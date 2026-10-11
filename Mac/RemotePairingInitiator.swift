import SwiftUI
import Network
import CryptoKit

/// The Mac's end of the USB pairing that grants remote access (PROTOCOL.md
/// 2.4.3, RemotePairing in Shared/RemoteTrust.swift). The Mac dials the
/// device's loopback-only pairing listener through usbmuxd itself, so the
/// cable proves which device is on the other end; both screens then show a
/// code derived from the whole exchange and the user accepts on each.
///
/// This is the only path that creates a RemotePeer. The WiFi code pairing
/// (PairingInitiator) never grants remote access.
@MainActor
final class RemotePairingInitiator: ObservableObject {
    enum State: Equatable {
        case choosing                              // pick a USB device
        case connecting(String)                    // device name
        case compare(code: String, device: String)
        case waitingDevice(String)                 // accepted here, device not yet
        case paired(String)
        case failed(String)
    }

    @Published private(set) var state: State = .choosing

    /// Called on the main actor once the peer is stored.
    var onPaired: (() -> Void)?
    /// What the Mac's confirm announces (`addrs`, `port`). Read when the
    /// user accepts, so it reflects the current network.
    var endpoint: (() -> (addresses: [String], port: UInt16))?

    private let queue = DispatchQueue(label: "remote.pairing")
    private var channel: PairingChannel?
    // Bumped by every new attempt and every failure: callbacks of an older
    // attempt (late dial, timeout) find a different number and stand down.
    private var attempt = 0
    private var identity: SecureEnclaveIdentity?
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey?
    private var macHello: RemotePairing.Hello?
    private var deviceHello: RemotePairing.Hello?
    private var transcript: Data?
    private var secret: Data?
    // The peer is stored only when both hold (PROTOCOL.md 2.4.3).
    private var localAccepted = false
    private var deviceConfirmed = false

    private var inProgress: Bool {
        switch state {
        case .connecting, .compare, .waitingDevice: return true
        default: return false
        }
    }

    /// This Mac's name, already in the form the transcript covers.
    private static var macName: String {
        RemotePairing.normalizedName(Host.current().localizedName ?? "", role: .mac)
    }

    func pair(udid: String, name: String, basePort: UInt16) {
        if inProgress { fail("Remplacé par une nouvelle tentative") }
        clearExchange()
        attempt += 1
        let current = attempt
        guard let identity = SecureEnclaveIdentity.shared else {
            state = .failed("Ce Mac n'a pas d'identité Secure Enclave utilisable "
                            + "(\(SecureEnclaveIdentity.lastError ?? "erreur inconnue")) : "
                            + "l'accès à distance est indisponible.")
            return
        }
        guard basePort <= UInt16.max - RemoteWire.usbPairingPortOffset else {
            state = .failed("Port de base invalide")
            return
        }
        self.identity = identity
        state = .connecting(name)
        let port = basePort + RemoteWire.usbPairingPortOffset
        Log.info("remote pairing: dialing \(udid) port \(port) over USB")
        let queue = self.queue
        Task { [weak self] in
            do {
                let conn = try await Usbmux.dial(udid: udid, port: port, queue: queue)
                guard let self else {
                    conn.cancel()
                    return
                }
                self.connected(conn, attempt: current, name: name)
            } catch {
                guard let self, self.attempt == current else { return }
                let reason: String
                switch error as? Usbmux.Failure {
                case .noDevice:
                    reason = "\(name) n'est plus branché en USB."
                case .refused:
                    reason = "\(name) n'attend pas d'appairage. Sur l'appareil, ouvre OpenDisplay, "
                        + "lance l'appairage pour l'accès à distance dans ses réglages, puis réessaie."
                default:
                    reason = "Connexion USB impossible : \(error.localizedDescription)"
                }
                self.fail(reason, notifyDevice: false)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + RemoteWire.pairingTimeout) { [weak self] in
            guard let self, self.attempt == current, self.inProgress else { return }
            self.fail("Délai dépassé — recommence l'appairage.")
        }
    }

    /// The user checked that both screens show the same code.
    func accept() {
        guard case .compare(_, let device) = state, let identity, let transcript else { return }
        let info: (addresses: [String], port: UInt16) =
            endpoint?() ?? (addresses: [], port: RemoteWire.defaultMacPort)
        let confirm: [String: Any]
        do {
            confirm = try RemotePairing.confirmMessage(
                .mac, transcript: transcript, identity: identity,
                extra: ["addrs": info.addresses, "port": Int(info.port)])
        } catch {
            return fail("Signature impossible : \(error.localizedDescription)")
        }
        send(confirm)
        localAccepted = true
        Log.info("remote pairing: accepted on the Mac (\(info.addresses.count) address(es), port \(info.port))")
        if deviceConfirmed {
            complete()
        } else {
            state = .waitingDevice(device)
        }
    }

    /// The codes differ: someone else may be in the exchange.
    func reject() {
        guard case .compare = state else { return }
        fail("Les codes sont différents — appairage annulé. Rien n'a été enregistré.")
    }

    /// The window closed or the user chose to start over.
    func stop() {
        if inProgress || channel != nil { fail("Annulé sur le Mac") }
    }

    func reset() {
        stop()
        clearExchange()
        state = .choosing
    }

    // MARK: Private

    private func connected(_ conn: NWConnection, attempt current: Int, name: String) {
        guard attempt == current, case .connecting = state, let identity else {
            conn.cancel()
            return
        }
        let channel = PairingChannel(conn, queue: queue)
        channel.onMessage = { [weak self] msg in
            DispatchQueue.main.async { self?.handle(msg, attempt: current) }
        }
        channel.onClosed = { [weak self, weak channel] reason in
            DispatchQueue.main.async {
                guard let self, let channel, self.channel === channel else { return }
                self.channel = nil
                guard self.inProgress else { return }
                self.fail("Connexion interrompue (\(reason))", notifyDevice: false)
            }
        }
        self.channel = channel
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let hello = RemotePairing.Hello(name: Self.macName, signingKey: identity.publicKey,
                                        ephemeralKey: ephemeral.publicKey.rawRepresentation,
                                        pskIdentity: RemotePairing.newPSKIdentity(), installID: nil)
        self.ephemeral = ephemeral
        macHello = hello
        let message = RemotePairing.helloMessage(hello)
        // Usbmux hands the connection over already started on `queue`;
        // start() only installs the handlers and begins reading.
        queue.async {
            channel.start()
            channel.send(message)
        }
        Log.info("remote pairing: connected to \(name) over USB")
    }

    private func handle(_ msg: [String: Any], attempt current: Int) {
        guard attempt == current, channel != nil else { return }
        let type = msg["type"] as? String
        if type == RemoteWire.pairAbort {
            return fail("Appairage annulé sur l'appareil.", notifyDevice: false)
        }
        if type == RemoteWire.pairHello, case .connecting = state {
            guard let macHello, let ephemeral,
                  let device = RemotePairing.parseHello(msg, from: .device) else {
                return fail("Réponse de l'appareil invalide")
            }
            guard device.signingKey != macHello.signingKey else {
                return fail("L'appareil présente la clé de ce Mac")
            }
            let transcript = RemotePairing.transcript(mac: macHello, device: device)
            do {
                secret = try RemotePairing.secret(ownEphemeral: ephemeral,
                                                  peerEphemeral: device.ephemeralKey,
                                                  transcript: transcript)
            } catch {
                return fail("Échange de clés impossible")
            }
            self.ephemeral = nil   // used once, never kept
            deviceHello = device
            self.transcript = transcript
            state = .compare(code: RemotePairing.code(transcript: transcript), device: device.name)
            return
        }
        if type == RemoteWire.pairConfirm, !deviceConfirmed, let device = deviceHello, let transcript {
            switch state {
            case .compare, .waitingDevice: break
            default: return fail("Message d'appairage inattendu")
            }
            guard RemotePairing.verifyConfirm(msg, from: .device, transcript: transcript,
                                              peerKey: device.signingKey) else {
                return fail("La confirmation de l'appareil ne correspond pas — rien n'a été enregistré.")
            }
            // The official device answers only after our confirm, but the
            // protocol lets confirms cross: accept either order.
            deviceConfirmed = true
            Log.info("remote pairing: \(device.name) confirmed")
            if localAccepted { complete() }
            return
        }
        fail("Message d'appairage inattendu")
    }

    /// Both conditions hold: store the peer.
    private func complete() {
        guard localAccepted, deviceConfirmed, let identity, let device = deviceHello,
              let pid = macHello?.pskIdentity, let secret else { return }
        let peer: RemotePeer
        do {
            let sealed = try identity.seal(secret)
            peer = RemotePeer(id: RemoteCrypto.fingerprint(of: device.signingKey),
                              name: device.name,
                              publicKey: device.signingKey,
                              installID: device.installID,
                              pskIdentity: pid,
                              sealedSecret: sealed,
                              pairedAt: Date())
            try RemoteStore.savePeers(RemoteStore.merged(RemoteStore.peers(), with: peer))
        } catch {
            return fail("Impossible d'enregistrer l'appairage : \(error)")
        }
        Log.info("remote pairing: paired with \(peer.name) (\(peer.id.prefix(8)))")
        let channel = self.channel
        self.channel = nil
        clearExchange()
        state = .paired(peer.name)
        // Let our confirm leave before the connection closes.
        queue.asyncAfter(deadline: .now() + 0.5) { channel?.close("paired") }
        onPaired?()
    }

    private func send(_ message: [String: Any]) {
        guard let channel else { return }
        queue.async { channel.send(message) }
    }

    /// Ends the attempt, stores nothing. `notifyDevice`: send rpAbort first
    /// (pointless when the device aborted or the connection is gone).
    private func fail(_ reason: String, notifyDevice: Bool = true) {
        Log.info("remote pairing: failed — \(reason)")
        attempt += 1
        if let channel {
            self.channel = nil
            queue.async {
                if notifyDevice { channel.send(["type": RemoteWire.pairAbort]) }
                channel.close("failed")
            }
        }
        clearExchange()
        state = .failed(reason)
    }

    private func clearExchange() {
        identity = nil
        ephemeral = nil
        macHello = nil
        deviceHello = nil
        transcript = nil
        secret = nil
        localAccepted = false
        deviceConfirmed = false
    }
}

struct RemotePairingSheet: View {
    @ObservedObject var controller: SenderController
    @StateObject private var pairing = RemotePairingInitiator()
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Appairer pour l'accès à distance").font(.title3.bold())
            content
            HStack {
                Spacer()
                Button(isDone ? "Terminé" : "Annuler") { onClose() }
                    .keyboardShortcut(isDone ? .defaultAction : .cancelAction)
            }
        }
        .padding(20)
        .frame(width: 400)
        .onAppear {
            pairing.onPaired = { controller.remotePairingsChanged() }
            pairing.endpoint = {
                (addresses: controller.remoteAddresses, port: RemoteSettings.port)
            }
        }
        .onDisappear { pairing.stop() }
    }

    private var isDone: Bool {
        if case .paired = pairing.state { return true }
        return false
    }

    @ViewBuilder
    private var content: some View {
        switch pairing.state {
        case .choosing:
            Text("Sur l'iPhone ou l'iPad, ouvre OpenDisplay et lance l'appairage pour l'accès "
                 + "à distance dans ses réglages, puis choisis l'appareil branché ici.")
                .font(.callout).foregroundStyle(.secondary)
            if !SecureEnclave.isAvailable {
                Label("Ce Mac n'a pas de Secure Enclave : l'accès à distance est indisponible.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else if controller.usbDevices.isEmpty {
                Text("Aucun appareil branché en USB.").foregroundStyle(.secondary)
            }
            ForEach(controller.usbDevices) { device in
                HStack {
                    Image(systemName: "cable.connector")
                    Text(device.name ?? "iPhone / iPad")
                    Spacer()
                    Button("Appairer") {
                        pairing.pair(udid: device.udid, name: device.name ?? "iPhone / iPad",
                                     basePort: UInt16(controller.port) ?? 9000)
                    }
                    .disabled(!SecureEnclave.isAvailable)
                }
            }
        case .connecting(let name):
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Connexion à \(name) par USB…")
            }
        case .compare(let code, let device):
            Text("Vérifie que \(device) affiche exactement ce code :")
                .font(.callout)
            Text("\(String(code.prefix(3))) \(String(code.suffix(3)))")
                .font(.system(size: 34, weight: .semibold, design: .monospaced))
                .frame(maxWidth: .infinity)
            Text("Accepte aussi sur l'appareil. Si les codes diffèrent, refuse : rien ne sera enregistré.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Les codes sont différents") { pairing.reject() }
                Spacer()
                Button("Les codes correspondent") { pairing.accept() }
                    .keyboardShortcut(.defaultAction)
            }
        case .waitingDevice(let name):
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Accepte l'appairage sur \(name)…")
            }
        case .paired(let name):
            Label("\(name) peut maintenant se connecter à ce Mac à distance.",
                  systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        case .failed(let reason):
            Label(reason, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Button("Recommencer") { pairing.reset() }
        }
    }
}

/// Pairing runs in its own window: sheets on the menu-bar panel close with it.
@MainActor
enum RemotePairingWindow {
    private static var window: NSWindow?

    static func show(controller: SenderController) {
        window?.close()
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 400, height: 260),
                         styleMask: [.titled, .closable], backing: .buffered, defer: false)
        w.title = "Accès à distance"
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: RemotePairingSheet(
            controller: controller,
            onClose: { RemotePairingWindow.close() }))
        w.center()
        window = w
        w.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    static func close() {
        window?.close()
        window = nil
    }
}
