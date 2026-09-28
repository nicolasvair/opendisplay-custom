import SwiftUI
import Network
import CryptoKit

/// The Mac's end of pairing (see Shared/Pairing.swift): finds receivers whose
/// pairing screen is open, runs the key exchange, and checks the code the
/// user reads off the device before storing the shared secret.
@MainActor
final class PairingInitiator: ObservableObject {
    enum State: Equatable {
        case browsing
        case connecting(String)
        case enterCode(String)       // device name
        case waitingDevice(String)   // code matched — the device must accept
        case paired(String)
        case failed(String)
    }

    @Published private(set) var state: State = .browsing
    @Published private(set) var candidates: [NWBrowser.Result] = []
    @Published private(set) var attemptsLeft = 3

    /// Called on the main actor once a new key is stored.
    var onPaired: (() -> Void)?

    private let queue = DispatchQueue(label: "pairing.initiator")
    private var browser: NWBrowser?
    private var channel: PairingChannel?
    private let privateKey = Curve25519.KeyAgreement.PrivateKey()
    private var receiverID = ""
    private var receiverName = ""
    private var expectedCode = ""
    private var secret: Data?

    func start() {
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: PairingWire.serviceType,
                                                           domain: nil), using: .tcp)
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            let open = Array(results.filter { PairingWire.txtFlag($0, PairingWire.pairingTXTKey) })
            Log.info("pairing: browse found \(open.count) device(s) in pairing mode")
            Task { @MainActor in self?.candidates = open }
        }
        browser.stateUpdateHandler = { state in
            Log.info("pairing: browser \(state)")
        }
        Log.info("pairing: looking for devices in pairing mode")
        browser.start(queue: .main)
        self.browser = browser
    }

    func stop() {
        browser?.cancel()
        browser = nil
        channel?.close("closed by the Mac")
        channel = nil
    }

    static func name(of result: NWBrowser.Result) -> String {
        guard case .service(let name, _, _, _) = result.endpoint else { return "\(result.endpoint)" }
        return name.hasSuffix(PairingWire.pairingNameSuffix)
            ? String(name.dropLast(PairingWire.pairingNameSuffix.count)) : name
    }

    func pair(with result: NWBrowser.Result) {
        let name = Self.name(of: result)
        receiverName = name
        attemptsLeft = 3
        state = .connecting(name)
        // IPv4 only: a LAN device's IPv6 addresses (rotating link-local,
        // global) can be advertised yet unroutable, and the dial then sits
        // in `waiting` for good. The stream path redials; this one-shot
        // dialogue would just hang.
        let params = NWParameters.tcp
        (params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options)?.version = .v4
        let conn = NWConnection(to: result.endpoint, using: params)
        let channel = PairingChannel(conn, queue: queue)
        channel.onMessage = { [weak self] msg in
            Task { @MainActor in self?.handle(msg) }
        }
        channel.onClosed = { [weak self] reason in
            Task { @MainActor in
                guard let self, self.channel === channel else { return }
                self.channel = nil
                if case .paired = self.state { return }
                if case .failed = self.state { return }
                self.state = .failed("Connexion interrompue (\(reason))")
            }
        }
        self.channel = channel
        channel.start()
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.channel === channel, case .connecting = self.state else { return }
            self.fail("Impossible de joindre \(name) — vérifie que les deux appareils sont sur le même WiFi")
        }
        channel.send(["type": "pairHello",
                      "macID": PairingIdentity.macID,
                      "macName": Host.current().localizedName ?? "Mac",
                      "commit": PairingMath.commitment(to: privateKey.publicKey.rawRepresentation).base64])
    }

    /// Checks the code typed by the user against the one derived here.
    func submit(code typed: String) {
        guard case .enterCode = state, let secret else { return }
        let digits = typed.filter(\.isNumber)
        guard digits == expectedCode else {
            attemptsLeft -= 1
            if attemptsLeft <= 0 {
                channel?.send(["type": "pairAbort"])
                fail("Code incorrect — l'appairage a été annulé. Si le code était bien recopié, "
                     + "quelqu'un s'interpose peut-être sur le réseau.")
            }
            return
        }
        channel?.send(["type": "pairConfirm", "tag": PairingMath.tag(secret, "mac-confirm").base64])
        state = .waitingDevice(receiverName)
    }

    func reset() {
        channel?.close("reset")
        channel = nil
        secret = nil
        state = .browsing
    }

    private func handle(_ msg: [String: Any]) {
        switch (msg["type"] as? String, state) {
        case ("pairKey", .connecting):
            guard let id = msg["id"] as? String, !id.isEmpty,
                  let receiverKey = Data(base64: msg["pk"]),
                  let receiverPublic = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: receiverKey),
                  let shared = try? privateKey.sharedSecretFromKeyAgreement(with: receiverPublic) else {
                return fail("Réponse de l'appareil invalide")
            }
            let ownKey = privateKey.publicKey.rawRepresentation
            receiverID = id
            secret = PairingMath.secret(shared, macKey: ownKey, receiverKey: receiverKey)
            expectedCode = PairingMath.code(macKey: ownKey, receiverKey: receiverKey)
            // Only now reveal our key — the device already committed to its own.
            channel?.send(["type": "pairReveal", "pk": ownKey.base64])
            state = .enterCode(receiverName)
        case ("pairDone", .waitingDevice):
            guard let secret, let tag = Data(base64: msg["tag"]),
                  PairingMath.tagMatches(tag, secret, "receiver-confirm") else {
                return fail("L'appareil n'a pas confirmé l'appairage")
            }
            PairingStore.upsert(PairingKey(peerID: receiverID, peerName: receiverName,
                                           secret: secret), .sender)
            Log.info("pairing: paired with \(receiverName) (\(receiverID))")
            channel?.close("paired")
            state = .paired(receiverName)
            onPaired?()
        case ("pairAbort", _):
            fail("Appairage annulé sur l'appareil")
        default:
            fail("Message d'appairage inattendu")
        }
    }

    private func fail(_ reason: String) {
        Log.info("pairing: failed — \(reason)")
        channel?.close("failed")
        channel = nil
        secret = nil
        state = .failed(reason)
    }
}

struct PairingSheet: View {
    @StateObject private var pairing = PairingInitiator()
    @State private var code = ""
    let onPaired: () -> Void
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Appairer un appareil").font(.title3.bold())
            content
            HStack {
                Spacer()
                Button(isDone ? "Terminé" : "Annuler") { onClose() }
                    .keyboardShortcut(isDone ? .defaultAction : .cancelAction)
            }
        }
        .padding(20)
        .frame(width: 380)
        .onAppear {
            pairing.onPaired = onPaired
            pairing.start()
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
        case .browsing:
            Text("Sur l'iPad ou l'iPhone, ouvre OpenDisplay › Réglages › Appairer un Mac. Il apparaîtra ici.")
                .font(.callout).foregroundStyle(.secondary)
            if pairing.candidates.isEmpty {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Recherche…").foregroundStyle(.secondary)
                }
            }
            ForEach(pairing.candidates, id: \.endpoint) { result in
                HStack {
                    Image(systemName: "ipad.and.iphone")
                    Text(PairingInitiator.name(of: result))
                    Spacer()
                    Button("Appairer") { pairing.pair(with: result) }
                }
            }
        case .connecting(let name):
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Connexion à \(name)…")
            }
        case .enterCode(let name):
            Text("Tape le code à 6 chiffres affiché sur \(name).")
                .font(.callout)
            TextField("123456", text: $code)
                .font(.system(.title2, design: .monospaced))
                .textFieldStyle(.roundedBorder)
                .onSubmit { submit() }
            HStack {
                if pairing.attemptsLeft < 3 {
                    Text("Code incorrect — \(pairing.attemptsLeft) essai(s) restant(s)")
                        .font(.caption).foregroundStyle(.red)
                }
                Spacer()
                Button("Valider") { submit() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(code.filter(\.isNumber).count != 6)
            }
        case .waitingDevice(let name):
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Code correct — accepte l'appairage sur \(name).")
            }
        case .paired(let name):
            Label("\(name) est appairé. Les connexions WiFi sont maintenant chiffrées.",
                  systemImage: "lock.fill")
                .foregroundStyle(.green)
        case .failed(let reason):
            Label(reason, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Button("Recommencer") { code = ""; pairing.reset() }
        }
    }

    private func submit() {
        pairing.submit(code: code)
        code = ""
    }
}

/// Pairing runs in its own window: sheets on the menu-bar panel close with it.
@MainActor
enum PairingWindow {
    private static var window: NSWindow?

    static func show(controller: SenderController) {
        window?.close()
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 380, height: 220),
                         styleMask: [.titled, .closable], backing: .buffered, defer: false)
        w.title = "Appairage"
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: PairingSheet(
            onPaired: { controller.pairingsChanged() },
            onClose: { PairingWindow.close() }))
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
