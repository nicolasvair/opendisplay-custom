import SwiftUI
import Network
import CryptoKit
import SystemConfiguration
import UserNotifications
import Darwin

// MARK: - Remote access, Mac side (PROTOCOL.md 2.4)
//
// The Mac listens on an Internet-reachable port and the device dials it
// (Shared/RemoteTrust.swift explains why). Everything here is built so that
// a connection that has not authenticated reaches nothing:
//
// * The listener only runs while the user enabled the feature, this Mac has
//   a Secure Enclave identity, and at least one device was paired over USB
//   (RemotePairingInitiator). Not advertised over Bonjour.
// * TLS 1.2 PSK with every remote peer's key: a dialer without a pairing
//   secret fails the handshake.
// * Then exactly one frame of at most RemoteWire.maxAuthFrame bytes is read,
//   within RemoteWire.authTimeout, and must carry a signature over this TLS
//   session's exporter by the peer's pinned Secure Enclave key. Only then
//   does the connection reach a MacSender (hello, input, video).
// * At most `maxPending` unauthenticated connections at once (the oldest is
//   dropped to make room), a few per source address or prefix, and a source
//   that keeps failing is refused for a while.
// * A device the Mac would turn away anyway (disconnected by the user, or
//   connected locally) gets no signed answer: the refusal is decided before
//   the Mac signs anything for it.

/// Remote access settings, persisted in UserDefaults. Not actor-bound, so
/// stored property defaults and the listener can read them.
enum RemoteSettings {
    private static let enabledKey = "remoteAccessEnabled"
    private static let portKey = "remotePort"
    private static let publicHostKey = "remotePublicHost"

    /// Off by default: the port is reachable from the Internet.
    static var enabled: Bool {
        get { UserDefaults.standard.bool(forKey: enabledKey) }
        set { UserDefaults.standard.set(newValue, forKey: enabledKey) }
    }

    static var port: UInt16 {
        get {
            let value = UserDefaults.standard.integer(forKey: portKey)
            return (1...Int(UInt16.max)).contains(value) ? UInt16(value) : RemoteWire.defaultMacPort
        }
        set { UserDefaults.standard.set(Int(newValue), forKey: portKey) }
    }

    /// A DNS name or IP literal the user wants the device to try first
    /// (dynamic DNS, a Tailscale MagicDNS name…). nil when unset.
    static var publicHost: String? {
        get {
            let value = sanitizedHost(UserDefaults.standard.string(forKey: publicHostKey) ?? "")
            return value.isEmpty ? nil : value
        }
        set {
            let value = sanitizedHost(newValue ?? "")
            if value.isEmpty {
                UserDefaults.standard.removeObject(forKey: publicHostKey)
            } else {
                UserDefaults.standard.set(value, forKey: publicHostKey)
            }
        }
    }

    /// The form PROTOCOL.md 2.4.3 expects in `addrs`: no brackets, no
    /// whitespace, at most 255 characters.
    static func sanitizedHost(_ raw: String) -> String {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        guard !host.contains(where: { $0.isWhitespace || $0 == "/" }) else { return "" }
        return String(host.prefix(255))
    }
}

// MARK: - Address discovery

/// The hosts a remote device should dial, best first: the user's own name,
/// then this Mac's stable global IPv6 addresses, then Tailscale-style IPv4
/// (100.64.0.0/10). Link-local, ULA and loopback are never listed.
enum RemoteAddresses {
    // IN6_IFF_* (netinet6/in6_var.h). Not exported to Swift; the values are
    // part of the kernel ABI that SystemConfiguration reports below.
    private static let in6Tentative = 0x0002
    private static let in6Duplicated = 0x0004
    private static let in6Detached = 0x0008
    private static let in6Deprecated = 0x0010
    private static let in6Temporary = 0x0080

    static func current(publicHost: String?) -> [String] {
        var result: [String] = []
        func add(_ host: String) {
            guard !host.isEmpty,
                  !result.contains(where: { $0.caseInsensitiveCompare(host) == .orderedSame }) else { return }
            result.append(host)
        }
        if let publicHost { add(publicHost) }
        globalIPv6().forEach(add)
        tailscaleIPv4().forEach(add)
        // PROTOCOL.md 2.4.5: the device keeps at most 16.
        return Array(result.prefix(16))
    }

    /// Stable (non-temporary, non-deprecated) global IPv6 addresses. The
    /// per-address flags come from SystemConfiguration's dynamic store
    /// (State:/Network/Interface/<if>/IPv6 → Addresses + Flags), which needs
    /// no private ioctl. Temporary addresses rotate daily and a router's
    /// inbound rule rarely follows them, so they are listed only when no
    /// stable address exists. If the store gives nothing, getifaddrs is used
    /// and every global address is listed (flags unknown there).
    private static func globalIPv6() -> [String] {
        var stable: [String] = []
        var temporary: [String] = []
        if let store = SCDynamicStoreCreate(nil, "OpenDisplay remote access" as CFString, nil, nil),
           let keyList = SCDynamicStoreCopyKeyList(store, "State:/Network/Interface/[^/]+/IPv6" as CFString),
           let keys = keyList as NSArray as? [String] {
            for key in keys.sorted() {
                let parts = key.split(separator: "/")
                guard parts.count >= 4, !skippedInterface(String(parts[3])),
                      let value = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                      let addresses = value["Addresses"] as? [String] else { continue }
                let flags = value["Flags"] as? [Int] ?? []
                for (index, raw) in addresses.enumerated() {
                    guard let address = globalUnicast(raw) else { continue }
                    let flag = index < flags.count ? flags[index] : 0
                    if flag & (in6Tentative | in6Duplicated | in6Detached | in6Deprecated) != 0 { continue }
                    if flag & in6Temporary != 0 {
                        temporary.append(address)
                    } else {
                        stable.append(address)
                    }
                }
            }
        }
        if stable.isEmpty, temporary.isEmpty {
            stable = interfaceAddresses(family: AF_INET6).compactMap { globalUnicast($0.address) }
        }
        return stable.isEmpty ? temporary : stable
    }

    /// Tailscale (and other CGNAT-range overlays) hand out 100.64.0.0/10.
    private static func tailscaleIPv4() -> [String] {
        interfaceAddresses(family: AF_INET).compactMap { entry in
            let octets = entry.address.split(separator: ".").compactMap { UInt8($0) }
            guard octets.count == 4, octets[0] == 100, octets[1] & 0xC0 == 64 else { return nil }
            return entry.address
        }
    }

    /// Interfaces whose addresses are never useful to a remote device: Apple
    /// peer-to-peer links, tunnels (a VPN's address does not take inbound
    /// connections; Tailscale's IPv4 is picked up separately), 6to4.
    private static func skippedInterface(_ name: String) -> Bool {
        ["lo", "awdl", "llw", "utun", "gif", "stf", "anpi", "ipsec"].contains { name.hasPrefix($0) }
    }

    /// The canonical text of a global unicast IPv6 address (2000::/3, minus
    /// documentation and Teredo), nil for anything else.
    private static func globalUnicast(_ raw: String) -> String? {
        let text = String(raw.split(separator: "%", maxSplits: 1).first ?? "").lowercased()
        guard let address = IPv6Address(text) else { return nil }
        let bytes = [UInt8](address.rawValue)
        guard bytes.count == 16, bytes[0] & 0xE0 == 0x20 else { return nil }
        if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] == 0x0D, bytes[3] == 0xB8 { return nil }   // 2001:db8::/32
        if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] == 0x00, bytes[3] == 0x00 { return nil }   // Teredo
        return text
    }

    private static func interfaceAddresses(family: Int32) -> [(interface: String, address: String)] {
        var result: [(interface: String, address: String)] = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return result }
        defer { freeifaddrs(list) }
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = ptr.pointee
            let flags = Int32(ifa.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0,
                  let sa = ifa.ifa_addr, sa.pointee.sa_family == UInt8(family) else { continue }
            let name = String(cString: ifa.ifa_name)
            // Tailscale's address lives on a utun: only IPv6 skips tunnels.
            if family == AF_INET6, skippedInterface(name) { continue }
            let size = 64
            var buffer = [CChar](repeating: 0, count: size)
            let converted: Bool
            if family == AF_INET6 {
                converted = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    var address = sin6.pointee.sin6_addr
                    return inet_ntop(AF_INET6, &address, &buffer, socklen_t(size)) != nil
                }
            } else {
                converted = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var address = sin.pointee.sin_addr
                    return inet_ntop(AF_INET, &address, &buffer, socklen_t(size)) != nil
                }
            }
            guard converted else { continue }
            result.append((name, String(cString: buffer)))
        }
        return result
    }
}

// MARK: - Listener

/// The Internet-facing listener. Owns the pre-authentication phase only:
/// once a device has proven its identity, the connection goes to the
/// controller (`onAuthenticated`), which runs a MacSender over it.
///
/// All state is confined to `queue`. Remote MacSenders run on that same
/// queue: an NWConnection calls back on the queue it was started on, and the
/// connection is started here, before anyone knows which session it joins.
final class RemoteListener {
    static let queue = DispatchQueue(label: "remote.sessions", qos: .userInitiated)

    /// Main queue. Set once by the controller before the first `apply`.
    var onAuthenticated: ((NWConnection, RemotePeer) -> Void)?
    /// Main queue. Human-readable listener state for the settings screen.
    var onStatus: ((String) -> Void)?

    private var queue: DispatchQueue { Self.queue }
    private var listener: NWListener?
    private var generation = 0
    private var peers: [RemotePeer] = []
    // Peers (by id) the controller would turn away right now, and whether it
    // turns away everyone (feature off). Set through `setRefusals`.
    private var refused: Set<String> = []
    private var refuseAll = true

    private struct Pending {
        let connection: NWConnection
        let source: String        // IPv4 address or IPv6 /64
        let wideSource: String?   // IPv6 /48, nil for IPv4
        let acceptedAt: TimeInterval
    }
    // Connections accepted but not (yet) authenticated.
    private var pending: [ObjectIdentifier: Pending] = [:]
    // Failed attempts per source (IPv4 address or IPv6 /64), uptime clock.
    private var failures: [String: [TimeInterval]] = [:]
    private var blockedUntil: [String: TimeInterval] = [:]
    // Rejection log lines are rate-limited: a scan must not flood the log.
    private var lastRejectLog: TimeInterval = -.infinity
    private var suppressedRejectLogs = 0
    private var rejectSummaryScheduled = false

    private let maxPending = 32
    private let maxPendingPerSource = 2       // per IPv4 address or IPv6 /64
    private let maxPendingPerWideSource = 4   // per IPv6 /48
    private let maxTrackedSources = 4096
    private let maxFailures = 5
    private let failureWindow: TimeInterval = 600
    private let blockDuration: TimeInterval = 600
    // One deadline from accept covers the TLS handshake and the auth frame.
    private let authDeadline: TimeInterval = RemoteWire.authTimeout
    private var now: TimeInterval { ProcessInfo.processInfo.systemUptime }

    /// (Re)starts or stops the listener for the given settings and peers.
    /// Called whenever either changes; established sessions are untouched
    /// (the controller ends those it must).
    func apply(enabled: Bool, port: UInt16, peers: [RemotePeer]) {
        queue.async { [weak self] in
            self?.reconfigure(enabled: enabled, port: port, peers: peers)
        }
    }

    /// Main queue. Which peers the controller would refuse right now (user
    /// disconnected them, or they are connected locally), or everyone.
    /// Checked before the Mac signs its answer, so a refused device learns
    /// nothing signed. Takes effect for connections still authenticating.
    func setRefusals(all: Bool, peerIDs: Set<String>) {
        queue.async { [weak self] in
            self?.refuseAll = all
            self?.refused = peerIDs
        }
    }

    private func reconfigure(enabled: Bool, port: UInt16, peers: [RemotePeer]) {
        // Pending dialers are checked against the current list: a forgotten
        // peer cannot finish authenticating on a connection already open.
        self.peers = peers
        generation += 1
        if let listener {
            listener.stateUpdateHandler = nil
            listener.cancel()
            self.listener = nil
        }
        guard enabled else {
            publish("")
            return
        }
        guard let identity = SecureEnclaveIdentity.shared else {
            publish("Secure Enclave indisponible — rien n'écoute")
            return
        }
        var keys: [(identity: String, secret: Data)] = []
        for peer in peers {
            do {
                let secret = try identity.open(peer.sealedSecret)
                keys.append((identity: peer.pskIdentity, secret: secret))
            } catch {
                Log.info("remote: cannot unseal the key of \(peer.name) (\(peer.id.prefix(8))): \(error) — skipped")
            }
        }
        guard !keys.isEmpty else {
            Log.info("remote: no usable remote pairing — listener stays off")
            publish("Aucun appareil appairé — rien n'écoute")
            return
        }
        guard let nwPort = NWEndpoint.Port(rawValue: port), port != 0 else {
            publish("Port \(port) invalide")
            return
        }
        // No Bonjour service, no peer-to-peer: the port is not announced.
        let params = SecureTransport.parameters(keys: keys)
        params.includePeerToPeer = false
        let peerCount = keys.count
        keys.removeAll()
        let listener: NWListener
        do {
            listener = try NWListener(using: params, on: nwPort)
        } catch {
            Log.info("remote: cannot listen on port \(port): \(error)")
            publish("Port \(port) indisponible : \(error.localizedDescription)")
            return
        }
        let current = generation
        listener.newConnectionHandler = { [weak self, weak listener] conn in
            guard let self, let listener, self.listener === listener else {
                conn.cancel()
                return
            }
            self.accept(conn)
        }
        listener.stateUpdateHandler = { [weak self, weak listener] state in
            guard let self, let listener, self.listener === listener else { return }
            switch state {
            case .ready:
                Log.info("remote: listening on port \(port) for \(peerCount) paired device(s)")
                self.publish("En écoute sur le port \(port) · \(peerCount) appareil(s)")
            case .waiting(let error):
                Log.info("remote: listener waiting: \(error)")
            case .failed(let error):
                Log.info("remote: listener failed: \(error) — retrying in 30s")
                self.publish("Écoute impossible sur le port \(port) : \(error.localizedDescription)")
                listener.cancel()
                self.listener = nil
                // Usually a network transition; try again once it settles.
                self.queue.asyncAfter(deadline: .now() + 30) { [weak self] in
                    guard let self, self.generation == current, self.listener == nil else { return }
                    self.reconfigure(enabled: true, port: port, peers: self.peers)
                }
            default:
                break
            }
        }
        self.listener = listener
        listener.start(queue: queue)
    }

    // MARK: Accept path (pre-authentication)

    private func accept(_ conn: NWConnection) {
        let source = Self.sourceKey(of: conn.endpoint)
        let wideSource = Self.wideSourceKey(of: conn.endpoint)
        pruneFailures()
        if let until = blockedUntil[source], until > now {
            conn.cancel()   // not logged: a blocked scanner would flood the log
            return
        }
        // A few slots per source, so one host or prefix cannot hold them all.
        let fromSource = pending.values.filter { $0.source == source }.count
        let fromWideSource = wideSource.map { wide in pending.values.filter { $0.wideSource == wide }.count } ?? 0
        if fromSource >= maxPendingPerSource || fromWideSource >= maxPendingPerWideSource {
            logRejection("refused \(source) — too many unauthenticated connections from it")
            conn.cancel()
            return
        }
        // Full: drop the oldest instead of the newcomer, so slow or stalled
        // dialers cannot keep a legitimate device out for long.
        if pending.count >= maxPending,
           let oldest = pending.values.min(by: { $0.acceptedAt < $1.acceptedAt }) {
            reject(oldest.connection, "evicted: \(maxPending) unauthenticated connections open",
                   countsAsFailure: false)
        }
        let id = ObjectIdentifier(conn)
        pending[id] = Pending(connection: conn, source: source, wideSource: wideSource, acceptedAt: now)
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else {
                conn.cancel()
                return
            }
            switch state {
            case .ready:
                self.authenticate(conn)
            case .failed(let error):
                // A wrong or unknown PSK ends here (TLS handshake failure).
                self.reject(conn, "connection failed: \(error)")
            case .waiting(let error):
                self.reject(conn, "connection waiting: \(error)")
            case .cancelled:
                if self.pending[id]?.connection === conn { self.pending[id] = nil }
            default:
                break
            }
        }
        queue.asyncAfter(deadline: .now() + authDeadline) { [weak self] in
            guard let self, self.pending[id]?.connection === conn else { return }
            self.reject(conn, "not authenticated within \(Int(self.authDeadline))s of connecting")
        }
        conn.start(queue: queue)
    }

    private func authenticate(_ conn: NWConnection) {
        let id = ObjectIdentifier(conn)
        guard pending[id]?.connection === conn else { return }
        guard let exporter = RemoteAuth.exporter(of: conn) else {
            return reject(conn, "no TLS exporter on the connection")
        }
        // Exactly one bounded frame; nothing past it is read here.
        RemoteAuth.receiveFrame(on: conn) { [weak self] message in
            guard let self, self.pending[id]?.connection === conn else { return }
            self.verify(message, on: conn, exporter: exporter)
        }
    }

    private func verify(_ message: [String: Any]?, on conn: NWConnection, exporter: Data) {
        let id = ObjectIdentifier(conn)
        guard let source = pending[id]?.source else { return }
        guard let message else {
            return reject(conn, "malformed, oversized or missing authentication frame")
        }
        guard let pid = RemoteAuth.claimedPSKIdentity(message) else {
            return reject(conn, "authentication frame without a valid pairing identity")
        }
        guard let peer = peers.first(where: { $0.pskIdentity == pid }) else {
            return reject(conn, "unknown pairing identity")
        }
        guard RemoteAuth.verify(message, from: .device, pskIdentity: pid, exporter: exporter,
                                peerKey: peer.publicKey) else {
            return reject(conn, "signature for \(peer.name) (\(peer.id.prefix(8))) does not verify")
        }
        // The device proved who it is, but the Mac would turn it away: close
        // before signing anything for it. Not a failure of the source.
        if refuseAll || refused.contains(peer.id) {
            return reject(conn, "\(peer.name) (\(peer.id.prefix(8))) is not accepted right now",
                          countsAsFailure: false)
        }
        guard let identity = SecureEnclaveIdentity.shared,
              let reply = try? RemoteAuth.message(.mac, pskIdentity: pid, exporter: exporter,
                                                  identity: identity),
              let frame = RemoteAuth.frame(reply) else {
            return reject(conn, "could not sign the Mac's answer", countsAsFailure: false)
        }
        conn.send(content: frame, completion: .contentProcessed { [weak self] error in
            guard let self, self.pending[id]?.connection === conn else { return }
            if let error {
                return self.reject(conn, "answer not sent: \(error)", countsAsFailure: false)
            }
            self.pending[id] = nil
            self.failures[source] = nil
            Log.info("remote: \(peer.name) (\(peer.id.prefix(8))) authenticated from \(source)")
            let handler = self.onAuthenticated
            DispatchQueue.main.async {
                if let handler {
                    handler(conn, peer)
                } else {
                    conn.cancel()
                }
            }
        })
    }

    /// Ends a pending connection. A no-op once it has authenticated (the
    /// session layer owns it then) or was already rejected.
    private func reject(_ conn: NWConnection, _ reason: String, countsAsFailure: Bool = true) {
        let id = ObjectIdentifier(conn)
        guard let entry = pending[id], entry.connection === conn else { return }
        let source = entry.source
        pending[id] = nil
        conn.cancel()
        logRejection("rejected \(source) — \(reason)")
        guard countsAsFailure else { return }
        var recent = (failures[source] ?? []).filter { now - $0 < failureWindow }
        recent.append(now)
        if recent.count >= maxFailures {
            failures[source] = nil
            blockedUntil[source] = now + blockDuration
            logRejection("\(source) blocked for \(Int(blockDuration / 60)) min after \(maxFailures) failed attempts")
        } else {
            failures[source] = recent
        }
        pruneFailures()
    }

    /// At most one rejection line per second; the rest are counted and
    /// reported in a summary.
    private func logRejection(_ text: String) {
        let now = self.now
        guard now - lastRejectLog >= 1 else {
            suppressedRejectLogs += 1
            guard !rejectSummaryScheduled else { return }
            rejectSummaryScheduled = true
            queue.asyncAfter(deadline: .now() + 10) { [weak self] in
                guard let self else { return }
                self.rejectSummaryScheduled = false
                guard self.suppressedRejectLogs > 0 else { return }
                Log.info("remote: \(self.suppressedRejectLogs) more rejection(s) not logged individually")
                self.suppressedRejectLogs = 0
                self.lastRejectLog = self.now
            }
            return
        }
        lastRejectLog = now
        Log.info("remote: \(text)")
    }

    private func pruneFailures() {
        let now = self.now
        blockedUntil = blockedUntil.filter { $0.value > now }
        failures = failures.compactMapValues { list in
            let recent = list.filter { now - $0 < failureWindow }
            return recent.isEmpty ? nil : recent
        }
        // Bound the memory a scan from many sources can take: drop the
        // stalest entries (oldest last failure, soonest unblock), keeping
        // the recent ones that matter.
        if failures.count > maxTrackedSources {
            let stale = failures.sorted { ($0.value.last ?? 0) < ($1.value.last ?? 0) }
                .prefix(failures.count - maxTrackedSources * 3 / 4)
            for (key, _) in stale { failures[key] = nil }
        }
        if blockedUntil.count > maxTrackedSources {
            let stale = blockedUntil.sorted { $0.value < $1.value }
                .prefix(blockedUntil.count - maxTrackedSources * 3 / 4)
            for (key, _) in stale { blockedUntil[key] = nil }
        }
    }

    /// The unit failures are counted in: an IPv4 address, or an IPv6 /64
    /// (one subscriber's prefix — per-address counting would be trivial to
    /// evade inside it).
    static func sourceKey(of endpoint: NWEndpoint) -> String {
        guard case .hostPort(let host, _) = endpoint else { return "\(endpoint)" }
        switch host {
        case .ipv4(let address):
            return "\(address)"
        case .ipv6(let address):
            let b = [UInt8](address.rawValue)
            guard b.count == 16 else { return "\(address)" }
            if b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xFF, b[11] == 0xFF {
                return "\(b[12]).\(b[13]).\(b[14]).\(b[15])"   // IPv4-mapped
            }
            let groups = stride(from: 0, to: 8, by: 2).map {
                String(UInt16(b[$0]) << 8 | UInt16(b[$0 + 1]), radix: 16)
            }
            return groups.joined(separator: ":") + "::/64"
        case .name(let name, _):
            return name
        @unknown default:
            return "\(host)"
        }
    }

    /// The wider unit pending slots are also capped in: an IPv6 /48 (one
    /// site). nil for IPv4 and IPv4-mapped sources.
    static func wideSourceKey(of endpoint: NWEndpoint) -> String? {
        guard case .hostPort(let host, _) = endpoint, case .ipv6(let address) = host else { return nil }
        let b = [UInt8](address.rawValue)
        guard b.count == 16 else { return nil }
        if b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xFF, b[11] == 0xFF { return nil }
        let groups = stride(from: 0, to: 6, by: 2).map {
            String(UInt16(b[$0]) << 8 | UInt16(b[$0 + 1]), radix: 16)
        }
        return groups.joined(separator: ":") + "::/48"
    }

    private func publish(_ text: String) {
        let handler = onStatus
        DispatchQueue.main.async { handler?(text) }
    }
}

// MARK: - Notifications

/// Shows the "remote session opened" banner even while the app is frontmost
/// (the menu-bar panel open counts): without a delegate macOS drops it then.
final class RemoteNotificationPresenter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = RemoteNotificationPresenter()

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler:
                                    @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }

    /// Authorization is requested the first time it is needed, so users who
    /// never enable remote access are never asked.
    static func announceRemoteSession(from name: String) {
        let center = UNUserNotificationCenter.current()
        center.delegate = shared
        center.requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error { Log.info("remote: notification authorization failed: \(error)") }
            guard granted else {
                Log.info("remote: notifications not allowed — session from \(name) not announced")
                return
            }
            let content = UNMutableNotificationContent()
            content.title = "OpenDisplay"
            content.body = "Session distante ouverte par \(name)"
            content.sound = .default
            let request = UNNotificationRequest(identifier: "remote-session-\(UUID().uuidString)",
                                                content: content, trigger: nil)
            center.add(request) { error in
                if let error { Log.info("remote: notification not shown: \(error)") }
            }
        }
    }
}

// MARK: - Controller integration

extension SenderController {
    /// Why remote access cannot be used on this Mac, nil when it can. The
    /// Secure Enclave identity is only created once the feature is in use,
    /// so the Keychain is not touched for users who never turn it on.
    var remoteUnavailableReason: String? {
        guard SecureEnclave.isAvailable else {
            return "Ce Mac n'a pas de Secure Enclave (puce Apple ou puce T2) : l'accès à distance "
                + "est indisponible. Il n'existe volontairement pas de solution logicielle de repli."
        }
        if remoteAccessEnabled || !remotePeers.isEmpty, SecureEnclaveIdentity.shared == nil {
            return "Identité Secure Enclave indisponible (\(SecureEnclaveIdentity.lastError ?? "erreur inconnue")) : "
                + "l'accès à distance est désactivé."
        }
        return nil
    }

    func setUpRemoteAccess() {
        remoteListener.onAuthenticated = { [weak self] conn, peer in
            MainActor.assumeIsolated {
                guard let self else {
                    conn.cancel()
                    return
                }
                self.handleRemoteConnection(conn, peer: peer)
            }
        }
        remoteListener.onStatus = { [weak self] text in
            MainActor.assumeIsolated { self?.remoteListenerStatus = text }
        }
        reloadRemotePeers()
        updateRemoteRefusals()
        if remoteAccessEnabled || !remotePeers.isEmpty, SecureEnclaveIdentity.shared == nil {
            Log.info("remote: no Secure Enclave identity (\(SecureEnclaveIdentity.lastError ?? "unknown")) — remote access disabled")
        }
        refreshRemoteAddresses()
        applyRemoteListener()
        // Addresses follow the network (new IPv6 prefix, Tailscale up/down).
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] _ in
            MainActor.assumeIsolated { self?.remoteNetworkChanged() }
        }
        monitor.start(queue: .main)
        remotePathMonitor = monitor
    }

    /// The listener runs only while enabled, with an identity, for at least
    /// one peer (RemoteListener checks the last two).
    func applyRemoteListener() {
        let usable = remoteAccessEnabled && SecureEnclave.isAvailable
        remoteListener.apply(enabled: usable, port: RemoteSettings.port,
                             peers: usable ? remotePeers : [])
    }

    /// The toggle changed.
    func remoteSettingsChanged() {
        if remoteAccessEnabled {
            Log.info("remote: access enabled by the user")
        } else {
            Log.info("remote: access disabled by the user — ending remote sessions")
            for session in sessions where session.isRemote { end(session) }
        }
        updateRemoteRefusals()
        applyRemoteListener()
        refreshRemoteAddresses()
    }

    func commitRemotePort() {
        let trimmed = remotePortText.trimmingCharacters(in: .whitespaces)
        guard let value = UInt16(trimmed), value > 0 else {
            remotePortText = String(RemoteSettings.port)
            return
        }
        remotePortText = String(value)
        guard value != RemoteSettings.port else { return }
        RemoteSettings.port = value
        Log.info("remote: port set to \(value)")
        applyRemoteListener()
        pushRemoteHostUpdates()
    }

    func commitRemotePublicHost() {
        RemoteSettings.publicHost = remotePublicHost
        remotePublicHost = RemoteSettings.publicHost ?? ""
        refreshRemoteAddresses()
    }

    func remoteNetworkChanged() {
        refreshRemoteAddresses()
        // A fresh IPv6 address is tentative for a moment (duplicate address
        // detection) and is skipped until then: look again shortly.
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            self?.refreshRemoteAddresses()
        }
    }

    func refreshRemoteAddresses() {
        let addresses = RemoteAddresses.current(publicHost: RemoteSettings.publicHost)
        guard addresses != remoteAddresses else { return }
        Log.info("remote: advertised addresses now \(addresses)")
        remoteAddresses = addresses
        pushRemoteHostUpdates()
    }

    /// Reads the paired devices. A failed read leaves the last known list in
    /// place and shows an error: it never passes for "no device paired".
    func reloadRemotePeers() {
        do {
            remotePeers = try RemoteStore.peers()
            remotePeersError = nil
        } catch {
            Log.info("remote: cannot read the paired devices from the Keychain: \(error)")
            remotePeersError = "Lecture du trousseau impossible (\(error)) : la liste des appareils "
                + "appairés n'est pas disponible."
        }
    }

    /// Re-read the peers after a USB pairing completed.
    func remotePairingsChanged() {
        reloadRemotePeers()
        updateRemoteRefusals()
        applyRemoteListener()
        refreshRemoteAddresses()
    }

    /// Revocation (PROTOCOL.md 2.4.6): the key leaves the listener and any
    /// live session with the device ends now. If the Keychain cannot be
    /// updated the device stays listed (it is still stored), with an error,
    /// and is refused until this app quits.
    func forgetRemotePeer(_ peer: RemotePeer) {
        let sessionID = ConnectionTarget.remote(peerID: peer.id).sessionID
        for session in sessions where session.id == sessionID { end(session) }
        remoteSuppressedUntil[peer.id] = nil
        let remaining: [RemotePeer]
        do {
            remaining = try RemoteStore.peers().filter { $0.id != peer.id }
            try RemoteStore.savePeers(remaining)
        } catch {
            Log.info("remote: could not forget \(peer.name) (\(peer.id.prefix(8))): \(error) — still stored")
            remoteForgetFailed.insert(peer.id)
            remotePeersError = "Impossible d'oublier \(peer.name) (\(error)) : l'appairage est toujours "
                + "enregistré. Ses connexions sont refusées jusqu'à la fermeture de l'app ; réessaie."
            updateRemoteRefusals()
            return
        }
        remotePeers = remaining
        remotePeersError = nil
        remoteForgetFailed.remove(peer.id)
        updateRemoteRefusals()
        applyRemoteListener()
        Log.info("remote: forgot \(peer.name) (\(peer.id.prefix(8)))")
    }

    /// The user disconnected a remote session: its device redials on its
    /// own, so turn it away for a minute rather than reopen at once.
    func suppressRemote(_ peerID: String) {
        let delay: TimeInterval = 60
        remoteSuppressedUntil[peerID] = Date().addingTimeInterval(delay)
        updateRemoteRefusals()
        // Let it back in once the minute is over.
        DispatchQueue.main.asyncAfter(deadline: .now() + delay + 1) { [weak self] in
            self?.updateRemoteRefusals()
        }
    }

    /// The peers the listener must turn away before it signs anything:
    /// suppressed after a user disconnect, forgotten but not erased, or
    /// already connected locally. Everyone while the feature is off.
    /// Called whenever sessions, suppression, peers or the toggle change.
    func updateRemoteRefusals() {
        let now = Date()
        remoteSuppressedUntil = remoteSuppressedUntil.filter { $0.value > now }
        var refused = Set(remoteSuppressedUntil.keys).union(remoteForgetFailed)
        let localInstallIDs = Set(sessions.compactMap { s -> String? in
            guard !s.failed, !s.isRemote else { return nil }
            return s.deviceID
        })
        for peer in remotePeers {
            if let installID = peer.installID, localInstallIDs.contains(installID) { refused.insert(peer.id) }
        }
        remoteListener.setRefusals(all: !remoteAccessEnabled, peerIDs: refused)
    }

    /// A device passed RemoteListener's authentication. The listener already
    /// refused what was known to be refused; this is the second line, against
    /// the state as it is now on the main thread.
    func handleRemoteConnection(_ conn: NWConnection, peer: RemotePeer) {
        // Re-check against the current state: the user may have forgotten
        // the peer or turned the feature off while the hop was in flight.
        guard remoteAccessEnabled, !remoteForgetFailed.contains(peer.id),
              let current = remotePeers.first(where: { $0.id == peer.id && $0.pskIdentity == peer.pskIdentity })
        else {
            Log.info("remote: \(peer.name) is no longer allowed — closing its connection")
            conn.cancel()
            return
        }
        if let until = remoteSuppressedUntil[current.id], until > Date() {
            Log.info("remote: \(current.name) was disconnected by the user — refusing for now")
            conn.cancel()
            return
        }
        // One session per physical device: a local one wins.
        if let installID = current.installID,
           let local = sessions.first(where: { !$0.failed && !$0.isRemote && $0.deviceID == installID }) {
            Log.info("remote: \(current.name) already has a local session (\(local.id)) — refusing the remote connection")
            conn.cancel()
            return
        }
        let target = ConnectionTarget.remote(peerID: current.id)
        if let existing = session(for: target.sessionID), !existing.failed {
            // Reconnect within the grace (or a replacement): same display.
            // Logged, not announced: the user was told when it opened.
            Log.info("remote: \(current.name) reconnected — resuming its session")
            existing.sender.adoptInbound(conn)
            return
        }
        Log.info("remote: opening a session for \(current.name)")
        connect(to: target, userInitiated: true, inbound: conn)
        RemoteNotificationPresenter.announceRemoteSession(from: current.name)
    }

    /// A session's transport is the USB cable right now, dialed by this Mac
    /// through usbmuxd. Only such a session's install ID is backed by
    /// something stronger than the receiver's own word: a WiFi device (even
    /// a code-paired one) could claim any install ID in its hello.
    /// Set from the transport its last hello arrived through, so a WiFi
    /// session that migrated onto the cable counts once it says hello there.
    private func isCabled(_ session: DeviceSession) -> Bool {
        session.onUSB && session.usbUDID != nil && remoteCabledSessions.contains(session.id)
    }

    /// Every hello, on any transport.
    func remoteHelloReceived(_ info: PhoneInfo, session: DeviceSession, cabledUDID: String?) {
        if cabledUDID != nil {
            remoteCabledSessions.insert(session.id)
        } else {
            remoteCabledSessions.remove(session.id)
        }
        if let installID = info.id, isCabled(session) {
            // The device is on the cable now: the USB session wins, the
            // remote one for the same device ends. A WiFi session never
            // ends a remote one (its install ID is only claimed).
            let peerIDs = Set(remotePeers.filter { $0.installID == installID }.map(\.id))
            for twin in sessions where twin.isRemote {
                guard case .remote(let peerID) = twin.target,
                      twin.deviceID == installID || peerIDs.contains(peerID) else { continue }
                Log.info("remote: \(twin.name) is now connected over USB (\(session.id)) — ending its remote session")
                end(twin)
            }
        }
        updateRemoteRefusals()
        sendRemoteHostUpdate(to: session)
    }

    /// PROTOCOL.md 2.4.5: tell a paired device where to find this Mac. Only
    /// on remote sessions (authenticated by the device's key) and cabled
    /// sessions: never over WiFi, where the install ID is only claimed.
    private func sendRemoteHostUpdate(to session: DeviceSession) {
        // deviceID is set by the hello: nothing goes out before it.
        guard !session.failed, session.deviceID != nil, !remoteAddresses.isEmpty,
              SecureEnclave.isAvailable else { return }
        let isPeer: Bool
        if case .remote(let peerID) = session.target {
            isPeer = remotePeers.contains { $0.id == peerID }
        } else if isCabled(session), let installID = session.deviceID {
            isPeer = remotePeers.contains { $0.installID == installID }
        } else {
            isPeer = false
        }
        guard isPeer, let identity = SecureEnclaveIdentity.shared else { return }
        do {
            let update = try RemoteHostUpdate.message(identity: identity, addresses: remoteAddresses,
                                                      port: RemoteSettings.port)
            session.sender.sendControlMessage(update)
        } catch {
            Log.info("remote: cannot sign the address update for \(session.id): \(error)")
        }
    }

    /// Addresses or port changed: update every connected remote peer.
    func pushRemoteHostUpdates() {
        for session in sessions { sendRemoteHostUpdate(to: session) }
    }
}

// MARK: - Settings UI

struct RemoteAccessSection: View {
    @ObservedObject var controller: SenderController

    var body: some View {
        Section {
            if let reason = controller.remoteUnavailableReason {
                Label(reason, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            Toggle("Autoriser l'accès à distance", isOn: $controller.remoteAccessEnabled)
                // Turning it off always stays possible.
                .disabled(controller.remoteUnavailableReason != nil && !controller.remoteAccessEnabled)
            LabeledContent("Port") {
                TextField("Port", text: $controller.remotePortText)
                    .labelsHidden()
                    .multilineTextAlignment(.trailing)
                    .frame(width: 80)
                    .onSubmit { controller.commitRemotePort() }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Adresse publique ou nom DNS (optionnel)")
                TextField("mon-mac.example.net", text: $controller.remotePublicHost)
                    .labelsHidden()
                    .onSubmit { controller.commitRemotePublicHost() }
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text("Adresses détectées")
                    Spacer()
                    Button {
                        controller.refreshRemoteAddresses()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .controlSize(.small)
                    .help("Relire les adresses de ce Mac")
                }
                if controller.remoteAddresses.isEmpty {
                    Text("Aucune adresse IPv6 publique ni adresse Tailscale détectée.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                ForEach(controller.remoteAddresses, id: \.self) { address in
                    Text(address)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                if controller.remoteAccessEnabled, !controller.remoteListenerStatus.isEmpty {
                    Text(controller.remoteListenerStatus)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if let error = controller.remotePeersError {
                VStack(alignment: .leading, spacing: 4) {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                    Button("Relire") { controller.remotePairingsChanged() }
                        .controlSize(.small)
                }
            }
            ForEach(controller.remotePeers) { peer in
                HStack {
                    Image(systemName: "globe").foregroundStyle(.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(peer.name)
                        Text("Appairé en USB le \(peer.pairedAt.formatted(date: .abbreviated, time: .omitted))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Oublier") { controller.forgetRemotePeer(peer) }
                        .controlSize(.small)
                }
            }
            Button("Appairer en USB pour l'accès distant…") {
                RemotePairingWindow.show(controller: controller)
            }
            .controlSize(.small)
            .disabled(!SecureEnclave.isAvailable || controller.usbDevices.isEmpty)
            if SecureEnclave.isAvailable, controller.usbDevices.isEmpty {
                Text("Branche l'iPhone ou l'iPad en USB pour l'appairer.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Accès à distance")
        } footer: {
            Text("Seuls les appareils appairés par câble USB peuvent se connecter à distance. "
                 + "La box doit laisser entrer les connexions IPv6 vers ce Mac sur ce port, "
                 + "ou bien utilise Tailscale sur les deux appareils.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
