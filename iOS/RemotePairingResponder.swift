import Foundation
import Network
import CryptoKit
import SwiftUI

// MARK: - Remote access: USB pairing, device side (custom build)
//
// Runs this device's end of RemotePairing (Shared/RemoteTrust.swift) while
// the "Autoriser l'appairage USB" screen is open. The Mac reaches it only
// through the cable: usbmuxd delivers the Mac's dial from loopback to base
// port + 4, which listens on the loopback interface only, is never
// advertised, takes a single connection and closes after
// RemoteWire.pairingTimeout. The Mac is stored only once this user accepted
// AND the Mac's signed confirmation checked out.

final class RemotePairingResponder: ObservableObject {
    enum State: Equatable {
        case idle
        case unavailable(String)                       // no Secure Enclave
        case waiting                                   // listening, no Mac yet
        case showCode(code: String, mac: String)       // the user compares
        case waitingForMac(code: String, mac: String)  // accepted here, Mac pending
        case paired(mac: String)
        case failed(String)
    }

    @Published private(set) var state: State = .idle

    /// A Mac was stored (main thread).
    var onPaired: (() -> Void)?

    private let queue = DispatchQueue(label: "remote.pairing")
    private var listener: NWListener?
    private var channel: PairingChannel?
    private var timeout: DispatchWorkItem?
    private var currentState: State = .idle

    // Exchange state (queue only).
    private var identity: SecureEnclaveIdentity?
    private var deviceName = "Appareil"
    private var ephemeral = Curve25519.KeyAgreement.PrivateKey()
    private var macHello: RemotePairing.Hello?
    private var transcript: Data?
    private var secret: Data?
    private var macConfirm: (addresses: [String], port: UInt16)?
    private var userAccepted = false

    /// Opens the loopback-only pairing listener. `deviceName` is the name
    /// this device already advertises (Settings › Name).
    func start(deviceName: String, basePort: UInt16 = 9000) {
        queue.async {
            self.teardown()
            guard let identity = SecureEnclaveIdentity.shared else {
                let detail = SecureEnclaveIdentity.lastError.map { " (\($0))" } ?? ""
                Log.info("remote pairing: no Secure Enclave identity\(detail)")
                self.publish(.unavailable("Accès à distance indisponible : cet appareil n'a pas de Secure Enclave utilisable."))
                return
            }
            self.identity = identity
            self.deviceName = Self.helloName(deviceName)
            let params = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
            // The cable only: usbmuxd hands the Mac's dial over on loopback.
            params.requiredInterfaceType = .loopback
            params.includePeerToPeer = false
            params.allowLocalEndpointReuse = true
            guard let port = NWEndpoint.Port(rawValue: basePort &+ RemoteWire.usbPairingPortOffset),
                  let listener = try? NWListener(using: params, on: port) else {
                self.publish(.failed("Impossible d'ouvrir le port d'appairage USB"))
                return
            }
            listener.service = nil   // never advertised
            listener.newConnectionHandler = { [weak self] conn in
                guard let self, self.listener === listener else { conn.cancel(); return }
                self.accept(conn)
            }
            listener.stateUpdateHandler = { [weak self] state in
                guard let self, self.listener === listener else { return }
                if case .failed(let error) = state {
                    Log.info("remote pairing: listener failed: \(error)")
                    self.fail("Le port d'appairage USB a échoué")
                }
            }
            self.listener = listener
            listener.start(queue: self.queue)
            let timeout = DispatchWorkItem { [weak self] in self?.fail("Délai dépassé") }
            self.timeout = timeout
            self.queue.asyncAfter(deadline: .now() + RemoteWire.pairingTimeout, execute: timeout)
            Log.info("remote pairing: waiting for a Mac over USB on :\(port)")
            self.publish(.waiting)
        }
    }

    /// The screen closed: abort whatever is in progress.
    func cancel() {
        queue.async {
            if case .paired = self.currentState {} else {
                self.channel?.send(["type": RemoteWire.pairAbort])
            }
            self.teardown()
            self.publish(.idle)
        }
    }

    /// The codes match: accept the Mac on this device. It is stored once its
    /// own signed confirmation is in (now, or when it arrives).
    func approve() {
        queue.async {
            guard case .showCode(let code, let mac) = self.currentState else { return }
            self.userAccepted = true
            if self.macConfirm != nil {
                self.complete()
            } else {
                self.publish(.waitingForMac(code: code, mac: mac))
            }
        }
    }

    func reject() {
        queue.async { self.fail("Appairage refusé") }
    }

    // MARK: Private (queue only)

    private func publish(_ state: State) {
        currentState = state
        DispatchQueue.main.async { self.state = state }
    }

    private func accept(_ conn: NWConnection) {
        // Belt and braces on top of requiredInterfaceType: the peer must be
        // a loopback address, parsed (not a string prefix).
        guard StreamReceiver.isLoopback(conn.endpoint) else {
            Log.info("remote pairing: refused non-loopback connection from \(conn.endpoint)")
            conn.cancel()
            return
        }
        guard channel == nil, currentState == .waiting else { conn.cancel(); return }
        // One connection per opening: nobody else gets in, even if this
        // one fails. "Recommencer" opens a fresh listener.
        listener?.cancel()
        listener = nil
        Log.info("remote pairing: Mac connected over USB")
        let channel = PairingChannel(conn, queue: queue)
        channel.onMessage = { [weak self] msg in self?.handle(msg) }
        channel.onClosed = { [weak self] reason in
            guard let self, self.channel === channel else { return }
            self.channel = nil
            if case .paired = self.currentState { return }
            self.fail("Connexion interrompue (\(reason))")
        }
        self.channel = channel
        channel.start()
    }

    private func handle(_ msg: [String: Any]) {
        guard let type = msg["type"] as? String else { return fail("Message d'appairage invalide") }
        switch type {
        case RemoteWire.pairAbort:
            fail("Appairage annulé sur le Mac")
        case RemoteWire.pairHello:
            guard currentState == .waiting, macHello == nil, let identity else {
                return fail("Message d'appairage inattendu")
            }
            guard let mac = RemotePairing.parseHello(msg, from: .mac) else {
                return fail("Message d'appairage du Mac invalide")
            }
            ephemeral = Curve25519.KeyAgreement.PrivateKey()
            let own = RemotePairing.Hello(name: deviceName, signingKey: identity.publicKey,
                                          ephemeralKey: ephemeral.publicKey.rawRepresentation,
                                          pskIdentity: nil, installID: StreamReceiver.installID)
            let transcript = RemotePairing.transcript(mac: mac, device: own)
            guard let secret = try? RemotePairing.secret(ownEphemeral: ephemeral,
                                                         peerEphemeral: mac.ephemeralKey,
                                                         transcript: transcript) else {
                return fail("Clé du Mac invalide")
            }
            macHello = mac
            self.transcript = transcript
            self.secret = secret
            channel?.send(RemotePairing.helloMessage(own))
            publish(.showCode(code: RemotePairing.code(transcript: transcript), mac: mac.name))
        case RemoteWire.pairConfirm:
            guard let mac = macHello, let transcript, macConfirm == nil, awaitingConfirm else {
                return fail("Message d'appairage inattendu")
            }
            guard RemotePairing.verifyConfirm(msg, from: .mac, transcript: transcript,
                                              peerKey: mac.signingKey) else {
                return fail("La confirmation du Mac est invalide")
            }
            macConfirm = (Self.sanitizedAddresses(msg["addrs"]), Self.sanitizedPort(msg["port"]))
            if userAccepted { complete() }
        default:
            fail("Message d'appairage inattendu")
        }
    }

    private var awaitingConfirm: Bool {
        switch currentState {
        case .showCode, .waitingForMac: return true
        default: return false
        }
    }

    /// Both conditions hold (this user accepted, the Mac's confirmation
    /// verified): store the Mac, then send our own confirmation.
    private func complete() {
        guard userAccepted, let identity, let mac = macHello, let pid = mac.pskIdentity,
              let transcript, let secret, let confirm = macConfirm else { return }
        do {
            let reply = try RemotePairing.confirmMessage(.device, transcript: transcript,
                                                         identity: identity)
            let host = RemoteHost(id: RemoteCrypto.fingerprint(of: mac.signingKey),
                                  name: mac.name,
                                  publicKey: mac.signingKey,
                                  pskIdentity: pid,
                                  sealedSecret: try identity.seal(secret),
                                  addresses: confirm.addresses,
                                  port: confirm.port,
                                  pairedAt: Date())
            try RemoteStore.saveHosts(RemoteStore.merged(RemoteStore.hosts(), with: host))
            channel?.send(reply)
        } catch {
            Log.info("remote pairing: could not store the Mac: \(error)")
            return fail("Impossible d'enregistrer ce Mac")
        }
        Log.info("remote pairing: paired with \(mac.name) (\(confirm.addresses.count) address(es), port \(confirm.port))")
        timeout?.cancel()
        timeout = nil
        publish(.paired(mac: mac.name))
        // Let the confirmation leave before closing.
        let finished = channel
        queue.asyncAfter(deadline: .now() + 0.5) {
            finished?.close("done")
            if self.channel === finished { self.channel = nil }
        }
        macHello = nil
        self.transcript = nil
        self.secret = nil
        macConfirm = nil
        userAccepted = false
        DispatchQueue.main.async { self.onPaired?() }
    }

    private func fail(_ reason: String) {
        if case .paired = currentState { return }
        Log.info("remote pairing: failed — \(reason)")
        channel?.send(["type": RemoteWire.pairAbort])
        teardown()
        publish(.failed(reason))
    }

    private func teardown() {
        timeout?.cancel()
        timeout = nil
        listener?.cancel()
        listener = nil
        let channel = self.channel
        self.channel = nil
        channel?.close("done")
        macHello = nil
        transcript = nil
        secret = nil
        macConfirm = nil
        userAccepted = false
    }

    // MARK: Sanitizing

    /// The name in our hello exactly as the Mac will parse it (non-empty,
    /// at most 64 characters), so both transcripts hash the same bytes.
    private static func helloName(_ name: String) -> String {
        let trimmed = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
        return trimmed.isEmpty ? "Appareil" : trimmed
    }

    /// At most 16 non-empty strings of at most 255 characters; anything else
    /// is dropped.
    private static func sanitizedAddresses(_ value: Any?) -> [String] {
        guard let list = value as? [Any] else { return [] }
        let strings = list.compactMap { $0 as? String }
            .map { String($0.trimmingCharacters(in: .whitespacesAndNewlines).prefix(255)) }
            .filter { !$0.isEmpty }
        return Array(strings.prefix(16))
    }

    private static func sanitizedPort(_ value: Any?) -> UInt16 {
        guard let port = value as? Int, port > 0, port <= Int(UInt16.max) else {
            return RemoteWire.defaultMacPort
        }
        return UInt16(port)
    }
}

// MARK: - View

/// "Autoriser l'appairage USB": opens the pairing listener while shown,
/// shows the code to compare, then asks to accept the Mac.
struct RemotePairingView: View {
    @ObservedObject var responder: RemotePairingResponder
    let deviceName: String

    var body: some View {
        VStack(spacing: 18) {
            switch responder.state {
            case .idle, .waiting:
                ProgressView()
                Text("Branche ce \(deviceKind) au Mac avec le câble USB, puis lance l'appairage d'accès à distance dans OpenDisplay sur le Mac.")
                    .multilineTextAlignment(.center)
                Text("L'appairage n'est possible que par le câble, et seulement tant que cet écran est ouvert (2 minutes au plus).")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            case .showCode(let code, let mac):
                Text("Vérifie que « \(mac) » affiche le même code :")
                    .multilineTextAlignment(.center)
                Text(code.prefix(3) + " " + code.suffix(3))
                    .font(.system(size: 48, weight: .bold, design: .monospaced))
                Text("Ce \(deviceKind) pourra ensuite se connecter à ce Mac depuis n'importe quel réseau.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                HStack(spacing: 16) {
                    Button("Refuser", role: .cancel) { responder.reject() }
                    Button("Les codes correspondent") { responder.approve() }
                        .buttonStyle(.borderedProminent)
                }
            case .waitingForMac(let code, let mac):
                ProgressView()
                Text("En attente de la confirmation sur « \(mac) »…")
                    .multilineTextAlignment(.center)
                Text(code.prefix(3) + " " + code.suffix(3))
                    .font(.system(size: 28, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.secondary)
                Button("Annuler", role: .cancel) { responder.reject() }
            case .paired(let mac):
                Label("« \(mac) » est appairé pour l'accès à distance.", systemImage: "lock.fill")
                    .foregroundColor(.green)
                    .multilineTextAlignment(.center)
            case .unavailable(let reason):
                Label(reason, systemImage: "lock.slash")
                    .foregroundColor(.orange)
                    .multilineTextAlignment(.center)
            case .failed(let reason):
                Label(reason, systemImage: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
                    .multilineTextAlignment(.center)
                Button("Recommencer") { responder.start(deviceName: deviceName) }
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity)
        .onAppear { responder.start(deviceName: deviceName) }
        .onDisappear { responder.cancel() }
    }
}
