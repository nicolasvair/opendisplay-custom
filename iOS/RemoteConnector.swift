import Foundation
import Network

// MARK: - Remote access: the dialing side (custom build)
//
// Outside the LAN the roles flip (Shared/RemoteTrust.swift): the Mac listens
// and this device dials it, because a phone on cellular sits behind carrier
// NAT. The connector:
//
// * dials each address the Mac gave (IPv6/IPv4 literal or DNS name) in order,
//   over TLS 1.2 with the pairing's PSK, unsealed by this device's Secure
//   Enclave identity;
// * once TLS is up, sends its channel-bound signature (RemoteAuth) and sends
//   nothing else until the Mac's own signature checks out against the key
//   pinned at USB pairing;
// * hands the authenticated connection to the StreamReceiver, which runs the
//   ordinary session on it (hello, video, input);
// * redials with backoff while the user wants remote mode and the app is in
//   the foreground.
//
// Main-thread API. The dialing state is confined to the receiver's session
// queue: connections are started there so the receiver can adopt them as is.

final class RemoteConnector: ObservableObject {
    enum Status: Equatable {
        case idle
        case connecting
        case connected
        case retrying(seconds: Int)   // no address answered
        case paused                   // app in the background or asleep
        case superseded               // a USB/WiFi session took over
        case refused                  // the Mac failed authentication
        case failed(String)

        var text: String {
            switch self {
            case .idle: return "Non connecté"
            case .connecting: return "Connexion…"
            case .connected: return "Connecté"
            case .retrying(let seconds): return "Mac injoignable — nouvel essai dans \(seconds) s"
            case .paused: return "En pause — reprend au retour dans l'app"
            case .superseded: return "Remplacée par une connexion USB ou WiFi"
            case .refused: return "Authentification refusée — réappaire ce Mac en USB"
            case .failed(let reason): return reason
            }
        }

        /// Remote mode is on for the shown Mac (the button offers "Déconnecter").
        var isEngaged: Bool {
            switch self {
            case .connecting, .connected, .retrying, .paused: return true
            default: return false
            }
        }
    }

    /// Macs paired for remote access (Keychain, RemoteStore).
    @Published private(set) var hosts: [RemoteHost] = RemoteStore.hosts()
    /// The Mac `status` is about; nil when there is nothing to show.
    @Published private(set) var activeHostID: String?
    @Published private(set) var status: Status = .idle

    var activeHost: RemoteHost? { hosts.first { $0.id == activeHostID } }

    private let receiver: StreamReceiver
    private let queue: DispatchQueue

    // Dialing state (session queue only).
    private var target: RemoteHost?          // non-nil = the user wants remote mode
    private var secret: Data?                // the target's unsealed PSK
    private var foreground = true
    private var generation = 0               // bumped to invalidate in-flight dials
    private var dialing: NWConnection?
    private var session: NWConnection?       // handed to the receiver
    private var retryWork: DispatchWorkItem?
    private var failures = 0

    private static let attemptTimeout: TimeInterval = 8
    private static let backoff: [TimeInterval] = [1, 2, 5, 10]

    init(receiver: StreamReceiver) {
        self.receiver = receiver
        queue = receiver.sessionQueue
    }

    // MARK: Main-thread API

    func connect(_ host: RemoteHost) {
        queue.async {
            guard SecureEnclaveIdentity.shared != nil else {
                self.publish(.failed("Secure Enclave indisponible sur cet appareil"), host: host.id)
                return
            }
            if self.session != nil {
                if self.target?.id == host.id { return }   // already there
                // Another Mac's session: forget it first so its end is not
                // taken for a drop to redial.
                self.session = nil
                self.receiver.dropRemoteSession()
            }
            self.stopDialing()
            self.target = host
            self.secret = nil
            self.failures = 0
            Log.info("remote: connecting to \(host.name)")
            self.dialCycle()
        }
    }

    func disconnect() {
        queue.async {
            Log.info("remote: disconnect requested")
            self.stopDialing()
            self.target = nil
            self.secret = nil
            if self.session != nil {
                self.session = nil
                self.receiver.dropRemoteSession()
            }
            self.publish(.idle, host: nil)
        }
    }

    /// Removes the Mac from the store and ends anything live with it.
    func forget(_ host: RemoteHost) {
        let remaining = RemoteStore.hosts().filter { $0.id != host.id }
        do { try RemoteStore.saveHosts(remaining) } catch {
            Log.info("remote: could not forget \(host.name): \(error)")
        }
        hosts = remaining
        queue.async {
            guard self.target?.id == host.id else { return }
            self.stopDialing()
            self.target = nil
            self.secret = nil
            self.session = nil
            self.publish(.idle, host: nil)
        }
        receiver.dropRemoteSession(hostID: host.id)
    }

    /// The store changed (a pairing completed): reload it.
    func reloadHosts() {
        let fresh = RemoteStore.hosts()
        hosts = fresh
        queue.async {
            guard let target = self.target else { return }
            if let updated = fresh.first(where: { $0.id == target.id }) {
                // Re-paired: new PSK identity and secret from the next dial.
                if updated.pskIdentity != target.pskIdentity { self.secret = nil }
                self.target = updated
            }
        }
    }

    /// A Mac sent its current addresses on an authenticated session
    /// (StreamReceiver, `remoteHost`). Updates a Mac already paired, never
    /// adds one.
    func applyHostUpdate(fingerprint: String, addresses: [String], port: UInt16) {
        guard !addresses.isEmpty else { return }
        var all = RemoteStore.hosts()
        guard let index = all.firstIndex(where: { $0.id == fingerprint }),
              all[index].addresses != addresses || all[index].port != port else { return }
        all[index].addresses = addresses
        all[index].port = port
        do { try RemoteStore.saveHosts(all) } catch {
            Log.info("remote: could not save new addresses: \(error)")
            return
        }
        Log.info("remote: \(all[index].name) now at \(addresses.count) address(es), port \(port)")
        hosts = all
        let updated = all[index]
        queue.async {
            if self.target?.id == updated.id { self.target = updated }
        }
    }

    /// The app left the foreground (switch, lock, quit): stop dialing. A live
    /// session is left to the receiver, as local ones are.
    func suspend() {
        queue.async {
            self.foreground = false
            guard self.target != nil else { return }
            self.stopDialing()
            if self.session == nil { self.publish(.paused) }
        }
    }

    /// Back in the foreground: dial again if remote mode is on and nothing
    /// is live or in flight.
    func resume() {
        queue.async {
            self.foreground = true
            guard self.target != nil, self.session == nil,
                  self.dialing == nil, self.retryWork == nil else { return }
            self.failures = 0
            self.dialCycle()
        }
    }

    // MARK: Dialing (session queue)

    private func publish(_ status: Status, host: String? = nil) {
        let hostID = host ?? target?.id
        DispatchQueue.main.async {
            self.status = status
            self.activeHostID = hostID
        }
    }

    private func stopDialing() {
        generation += 1
        retryWork?.cancel()
        retryWork = nil
        dialing?.stateUpdateHandler = nil
        dialing?.cancel()
        dialing = nil
    }

    /// Stop for good on this Mac (remote mode off) and say why.
    private func giveUp(_ status: Status) {
        let hostID = target?.id
        stopDialing()
        target = nil
        secret = nil
        publish(status, host: hostID)
    }

    private func dialCycle() {
        retryWork = nil
        guard let host = target, foreground, session == nil else { return }
        guard let identity = SecureEnclaveIdentity.shared else {
            return giveUp(.failed("Secure Enclave indisponible sur cet appareil"))
        }
        if secret == nil {
            do {
                secret = try identity.open(host.sealedSecret)
            } catch {
                Log.info("remote: cannot unseal the PSK for \(host.name): \(error)")
                return giveUp(.failed("Clé d'appairage illisible — réappaire ce Mac en USB"))
            }
        }
        generation += 1
        publish(.connecting)
        attempt(0, generation: generation, tlsRefused: false)
    }

    private func scheduleRetry() {
        guard target != nil else { return }
        guard foreground else { return publish(.paused) }
        let delay = Self.backoff[min(failures, Self.backoff.count - 1)]
        failures += 1
        publish(.retrying(seconds: Int(delay)))
        let work = DispatchWorkItem { [weak self] in self?.dialCycle() }
        retryWork = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    /// Dial `host.addresses[index]`; on failure, the next one. When none is
    /// left: refused if some address completed TCP but rejected our PSK,
    /// else unreachable (retry later).
    private func attempt(_ index: Int, generation gen: Int, tlsRefused: Bool) {
        guard gen == generation, let host = target, let secret else { return }
        guard index < host.addresses.count else {
            if tlsRefused {
                Log.info("remote: \(host.name) rejected our pre-shared key")
                return giveUp(.refused)
            }
            Log.info("remote: no address of \(host.name) answered")
            return scheduleRetry()
        }
        let address = host.addresses[index]
        guard let endpointHost = Self.endpointHost(address),
              let port = NWEndpoint.Port(rawValue: host.port) else {
            Log.info("remote: skipping unusable address \(address)")
            return attempt(index + 1, generation: gen, tlsRefused: tlsRefused)
        }
        let params = SecureTransport.parameters(keys: [(identity: host.pskIdentity, secret: secret)])
        params.serviceClass = .interactiveVideo
        let conn = NWConnection(host: endpointHost, port: port, using: params)
        dialing = conn
        Log.info("remote: dialing \(address) port \(host.port)")

        // Connect stage (TCP + TLS) of this attempt; settles exactly once.
        var settled = false
        let next: (Bool) -> Void = { [weak self] pskRejected in
            guard let self, !settled else { return }
            settled = true
            conn.stateUpdateHandler = nil
            conn.cancel()
            if self.dialing === conn { self.dialing = nil }
            guard gen == self.generation else { return }
            self.attempt(index + 1, generation: gen, tlsRefused: tlsRefused || pskRejected)
        }
        conn.stateUpdateHandler = { [weak self] state in
            guard let self, !settled else { return }
            guard gen == self.generation else { return next(false) }
            switch state {
            case .ready:
                settled = true
                self.authenticate(conn, host: host, generation: gen)
            case .waiting(let error), .failed(let error):
                Log.info("remote: \(address) failed: \(error)")
                next(Self.isTLSError(error))
            default:
                break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + Self.attemptTimeout) {
            guard !settled else { return }
            Log.info("remote: \(address) timed out")
            next(false)
        }
    }

    /// TLS is up: exchange the channel-bound signatures. Nothing but our
    /// auth frame leaves before the Mac's checks out.
    private func authenticate(_ conn: NWConnection, host: RemoteHost, generation gen: Int) {
        guard let identity = SecureEnclaveIdentity.shared,
              let exporter = RemoteAuth.exporter(of: conn),
              let message = try? RemoteAuth.message(.device, pskIdentity: host.pskIdentity,
                                                    exporter: exporter, identity: identity),
              let frame = RemoteAuth.frame(message) else {
            Log.info("remote: cannot build the authentication frame")
            conn.cancel()
            dialing = nil
            return giveUp(.failed("Authentification impossible sur cet appareil"))
        }
        var done = false
        let timeout = DispatchWorkItem { [weak self] in
            guard let self, !done else { return }
            done = true
            Log.info("remote: no authentication from the Mac within \(Int(RemoteWire.authTimeout))s")
            conn.cancel()
            if self.dialing === conn { self.dialing = nil }
            if gen == self.generation { self.scheduleRetry() }
        }
        queue.asyncAfter(deadline: .now() + RemoteWire.authTimeout, execute: timeout)
        conn.send(content: frame, completion: .contentProcessed { error in
            if let error { Log.info("remote: auth send failed: \(error)") }
        })
        RemoteAuth.receiveFrame(on: conn) { [weak self] reply in
            guard let self, !done else { return }
            done = true
            timeout.cancel()
            if self.dialing === conn { self.dialing = nil }
            guard gen == self.generation else { conn.cancel(); return }
            guard let reply else {
                // Closed or garbled before the Mac answered: network trouble
                // or a Mac that turned us away. Never streamed; retry later.
                Log.info("remote: connection closed during authentication")
                conn.cancel()
                return self.scheduleRetry()
            }
            guard RemoteAuth.verify(reply, from: .mac, pskIdentity: host.pskIdentity,
                                    exporter: exporter, peerKey: host.publicKey) else {
                // Whoever answered holds our PSK but not the Mac's Secure
                // Enclave key. Fail closed and stop: retrying cannot fix it.
                Log.info("remote: the Mac's authentication did not verify — refusing")
                conn.cancel()
                return self.giveUp(.refused)
            }
            Log.info("remote: \(host.name) authenticated — starting the session")
            conn.stateUpdateHandler = nil   // adoption installs the session's own
            self.session = conn
            self.failures = 0
            self.publish(.connected)
            self.receiver.adoptRemote(conn, hostID: host.id) { [weak self] reason in
                self?.sessionEnded(conn, reason)
            }
        }
    }

    /// The receiver ended the remote session (session queue).
    private func sessionEnded(_ conn: NWConnection, _ reason: StreamReceiver.RemoteSessionEnd) {
        guard session === conn else { return }   // already dropped on purpose
        session = nil
        switch reason {
        case .superseded:
            Log.info("remote: session replaced by a local one — remote mode off")
            giveUp(.superseded)
        case .dropped, .closed:
            if foreground {
                Log.info("remote: session ended (\(reason)) — redialing")
                scheduleRetry()
            } else {
                publish(.paused)
            }
        }
    }

    // MARK: Helpers

    /// An address as the Mac sent it: IPv6 literal (bracketed or not, with
    /// an optional %zone), IPv4 literal, or else a DNS name.
    static func endpointHost(_ address: String) -> NWEndpoint.Host? {
        var text = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("["), text.hasSuffix("]") { text = String(text.dropFirst().dropLast()) }
        guard !text.isEmpty, text.count <= 255 else { return nil }
        if let v6 = IPv6Address(text) { return .ipv6(v6) }
        if let v4 = IPv4Address(text) { return .ipv4(v4) }
        return .name(text, nil)
    }

    private static func isTLSError(_ error: NWError) -> Bool {
        if case .tls = error { return true }
        return false
    }
}
