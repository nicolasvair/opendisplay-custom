import Foundation
import Network
import CryptoKit
import Security

// MARK: - Encrypted pairing (custom build)
//
// The stock protocol is plaintext TCP with no authentication, so over WiFi
// anything advertising a receiver's name could be dialed by the Mac and be
// handed the screen. Pairing fixes that:
//
// * Once, the Mac and the receiver agree on a 256-bit secret over an
//   X25519 exchange. The receiver shows a 6-digit code derived from both
//   public keys; the user types it on the Mac. A man in the middle ends up
//   with a different code on each side (the Mac commits to its key before
//   seeing the receiver's, so the attacker cannot grind a match), and a
//   passive listener learns nothing from the exchange.
// * From then on WiFi sessions run over TLS 1.2 with that pre-shared key
//   (PSK identity = the Mac's pairing ID), on its own port and Bonjour type.
//   This build never streams plaintext over the network, paired or not:
//   receivers refuse it and the Mac never dials it. USB (usbmuxd, arriving
//   from loopback) stays plaintext.

enum PairingWire {
    /// Both listeners advertise under the stock service type and are told
    /// apart by a TXT key. macOS authorizes Bonjour browsing per service type
    /// and keeps the list an app had when Local Network access was granted,
    /// so new types would be refused (NoAuth) on an already-authorized Mac.
    static let serviceType = "_opensidecar._tcp"
    /// TLS-PSK stream listener: base port + 2, TXT `tls=1`.
    static let secureTXTKey = "tls"
    static let securePortOffset: UInt16 = 2
    /// Pairing listener, only up while the receiver's pairing screen is open:
    /// base port + 3, TXT `pair=1`, instance name + `pairingNameSuffix` (the
    /// stream service already holds the plain name).
    static let pairingTXTKey = "pair"
    static let pairingNameSuffix = " (appairage)"
    static let pairingPortOffset: UInt16 = 3

    static func txtFlag(_ result: NWBrowser.Result, _ key: String) -> Bool {
        if case .bonjour(let txt) = result.metadata { return txt[key] == "1" }
        return false
    }
    /// How long a pairing attempt may take end to end.
    static let pairingTimeout: TimeInterval = 120
}

/// One paired peer: who it is and the secret shared with it.
struct PairingKey: Codable, Equatable, Identifiable {
    var peerID: String
    var peerName: String
    var secret: Data
    var id: String { peerID }
}

/// Paired peers live in the Keychain. The receiver keeps one entry per paired
/// Mac, the sender one per paired receiver; `role` separates the two lists.
enum PairingStore {
    enum Role: String { case receiver, sender }

    private static let service = "OpenDisplay Custom pairing"

    static func load(_ role: Role) -> [PairingKey] {
        var query = baseQuery(role)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let keys = try? JSONDecoder().decode([PairingKey].self, from: data)
        else { return [] }
        return keys
    }

    static func save(_ keys: [PairingKey], _ role: Role) {
        let query = baseQuery(role)
        guard !keys.isEmpty, let data = try? JSONEncoder().encode(keys) else {
            SecItemDelete(query as CFDictionary)
            return
        }
        let update = [kSecValueData as String: data]
        if SecItemUpdate(query as CFDictionary, update as CFDictionary) == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let status = SecItemAdd(add as CFDictionary, nil)
            if status != errSecSuccess { Log.info("pairing: keychain add failed (\(status))") }
        }
    }

    /// Adds or replaces the entry for `key.peerID`.
    static func upsert(_ key: PairingKey, _ role: Role) {
        var keys = load(role).filter { $0.peerID != key.peerID }
        keys.append(key)
        save(keys, role)
    }

    static func remove(peerID: String, _ role: Role) {
        save(load(role).filter { $0.peerID != peerID }, role)
    }

    private static func baseQuery(_ role: Role) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: role.rawValue]
    }
}

/// This Mac's pairing identity: the TLS-PSK identity it presents.
enum PairingIdentity {
    static let macID: String = {
        if let existing = UserDefaults.standard.string(forKey: "pairingMacID") { return existing }
        let fresh = UUID().uuidString
        UserDefaults.standard.set(fresh, forKey: "pairingMacID")
        return fresh
    }()
}

enum SecureTransport {
    /// TCP (noDelay, as the plaintext paths) wrapped in TLS 1.2 with the
    /// given pre-shared keys. A client passes its single key; a server passes
    /// every paired peer's, matched on the identity the client presents.
    static func parameters(keys: [(identity: String, secret: Data)]) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        for key in keys {
            sec_protocol_options_add_pre_shared_key(sec, dispatchData(key.secret),
                                                    dispatchData(Data(key.identity.utf8)))
        }
        sec_protocol_options_append_tls_ciphersuite(
            sec, tls_ciphersuite_t(rawValue: UInt16(TLS_PSK_WITH_AES_128_GCM_SHA256))!)
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(sec, .TLSv12)
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        return NWParameters(tls: tls, tcp: tcp)
    }

    private static func dispatchData(_ data: Data) -> __DispatchData {
        data.withUnsafeBytes { DispatchData(bytes: $0) } as __DispatchData
    }
}

// MARK: - Pairing math

enum PairingMath {
    static func commitment(to publicKey: Data) -> Data {
        Data(SHA256.hash(data: publicKey))
    }

    /// The 6-digit code both sides display/compare, bound to both keys.
    static func code(macKey: Data, receiverKey: Data) -> String {
        var input = Data("opendisplay-pairing-code-v1".utf8)
        input.append(macKey)
        input.append(receiverKey)
        let digest = Array(SHA256.hash(data: input))
        let value = (UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16
                     | UInt32(digest[2]) << 8 | UInt32(digest[3])) % 1_000_000
        return String(format: "%06u", value)
    }

    static func secret(_ shared: SharedSecret, macKey: Data, receiverKey: Data) -> Data {
        var salt = macKey
        salt.append(receiverKey)
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                 sharedInfo: Data("opendisplay-psk-v1".utf8),
                                                 outputByteCount: 32)
        return key.withUnsafeBytes { Data($0) }
    }

    /// Key confirmation: proves the peer derived the same secret.
    static func tag(_ secret: Data, _ label: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(label.utf8), using: SymmetricKey(data: secret)))
    }

    static func tagMatches(_ tag: Data, _ secret: Data, _ label: String) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: Data(label.utf8),
                                               using: SymmetricKey(data: secret))
    }
}

// MARK: - Pairing channel

/// Newline-delimited JSON over a plain TCP connection, for the short pairing
/// dialogue. Callbacks arrive on the channel's queue.
final class PairingChannel {
    let connection: NWConnection
    private let queue: DispatchQueue
    private var buffer = Data()
    var onMessage: (([String: Any]) -> Void)?
    var onClosed: ((String) -> Void)?
    private var closed = false

    init(_ connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            Log.info("pairing: connection \(state)")
            switch state {
            case .failed(let error): self?.close("connection failed: \(error)")
            case .cancelled: self?.close("connection closed")
            default: break
            }
        }
        if connection.state == .setup { connection.start(queue: queue) }
        receive()
    }

    func send(_ message: [String: Any]) {
        guard !closed, var data = try? JSONSerialization.data(withJSONObject: message) else { return }
        data.append(0x0A)
        connection.send(content: data, completion: .contentProcessed { _ in })
    }

    func close(_ reason: String) {
        guard !closed else { return }
        closed = true
        connection.cancel()
        onClosed?(reason)
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            if let data { self.buffer.append(data) }
            while let newline = self.buffer.firstIndex(of: 0x0A) {
                let line = self.buffer[self.buffer.startIndex..<newline]
                self.buffer.removeSubrange(self.buffer.startIndex...newline)
                guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else {
                    self.close("malformed pairing message")
                    return
                }
                self.onMessage?(obj)
                if self.closed { return }
            }
            if self.buffer.count > 16_384 { self.close("pairing message too large"); return }
            if done || error != nil { self.close("peer closed the pairing connection"); return }
            self.receive()
        }
    }
}

extension Data {
    var base64: String { base64EncodedString() }
    init?(base64 value: Any?) {
        guard let string = value as? String else { return nil }
        self.init(base64Encoded: string)
    }
}

// MARK: - Receiver side

/// Runs the receiver's end of pairing while its pairing screen is open:
/// advertises `_opensidecar-pr._tcp`, shows the code, and asks the user to
/// accept the Mac before its key is stored.
final class PairingResponder: ObservableObject {
    enum State: Equatable {
        case idle
        case waiting                            // advertised, no Mac yet
        case showCode(code: String, mac: String)
        case confirm(mac: String)               // Mac typed the right code
        case paired(mac: String)
        case failed(String)
    }

    @Published private(set) var state: State = .idle
    @Published private(set) var pairedMacs: [PairingKey] = PairingStore.load(.receiver)

    /// Called after the list of paired Macs changed (paired or forgotten).
    var onPairingsChanged: (() -> Void)?

    private let queue = DispatchQueue(label: "pairing.responder")
    private var listener: NWListener?
    private var channel: PairingChannel?
    private var timeout: DispatchWorkItem?

    // Exchange state (queue-confined).
    private var macID = ""
    private var macName = ""
    private var macCommitment = Data()
    private var privateKey = Curve25519.KeyAgreement.PrivateKey()
    private var secret: Data?

    func start(serviceName: String, basePort: UInt16 = 9000) {
        queue.async {
            self.teardown()
            let tcp = NWProtocolTCP.Options()
            let params = NWParameters(tls: nil, tcp: tcp)
            params.allowLocalEndpointReuse = true
            let port = NWEndpoint.Port(rawValue: basePort + PairingWire.pairingPortOffset)!
            guard let listener = try? NWListener(using: params, on: port) else {
                self.publish(.failed("Impossible d'ouvrir le port d'appairage"))
                return
            }
            var txt = NWTXTRecord()
            txt["id"] = StreamReceiver.installID
            txt[PairingWire.pairingTXTKey] = "1"
            listener.service = NWListener.Service(name: serviceName + PairingWire.pairingNameSuffix,
                                                  type: PairingWire.serviceType,
                                                  domain: nil, txtRecord: txt)
            listener.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
            listener.stateUpdateHandler = { [weak self] state in
                if case .failed(let error) = state {
                    Log.info("pairing listener failed: \(error)")
                    self?.fail("Le port d'appairage a échoué")
                }
            }
            listener.start(queue: self.queue)
            self.listener = listener
            let timeout = DispatchWorkItem { [weak self] in self?.fail("Délai dépassé") }
            self.timeout = timeout
            self.queue.asyncAfter(deadline: .now() + PairingWire.pairingTimeout, execute: timeout)
            Log.info("pairing: waiting for a Mac")
            self.publish(.waiting)
        }
    }

    func cancel() {
        queue.async {
            self.channel?.send(["type": "pairAbort"])
            self.teardown()
            self.publish(.idle)
        }
    }

    /// The user accepted the Mac on this device: store the key, tell the Mac.
    func accept() {
        queue.async {
            guard case .confirm = self.currentState, let secret = self.secret else { return }
            PairingStore.upsert(PairingKey(peerID: self.macID, peerName: self.macName,
                                           secret: secret), .receiver)
            self.channel?.send(["type": "pairDone",
                                "tag": PairingMath.tag(secret, "receiver-confirm").base64])
            Log.info("pairing: paired with Mac \(self.macName)")
            let name = self.macName
            // Let the last message leave before the listener goes down.
            self.queue.asyncAfter(deadline: .now() + 0.5) { self.teardown() }
            self.publish(.paired(mac: name))
            self.reloadPairings()
        }
    }

    func reject() { fail("Appairage refusé") }

    func forget(_ key: PairingKey) {
        PairingStore.remove(peerID: key.peerID, .receiver)
        reloadPairings()
    }

    // MARK: Private

    private var currentState: State = .idle

    private func publish(_ state: State) {
        currentState = state
        DispatchQueue.main.async { self.state = state }
    }

    private func reloadPairings() {
        let keys = PairingStore.load(.receiver)
        DispatchQueue.main.async {
            self.pairedMacs = keys
            self.onPairingsChanged?()
        }
    }

    private func accept(_ conn: NWConnection) {
        // One Mac at a time; a second dialer is turned away.
        guard channel == nil, currentState == .waiting else { conn.cancel(); return }
        Log.info("pairing: Mac connected from \(conn.endpoint)")
        let channel = PairingChannel(conn, queue: queue)
        channel.onMessage = { [weak self] msg in self?.handle(msg) }
        channel.onClosed = { [weak self] reason in
            guard let self, self.channel === channel else { return }
            self.channel = nil
            if case .paired = self.currentState { return }
            self.fail("Connexion interrompue (\(reason))")
        }
        self.channel = channel
        privateKey = Curve25519.KeyAgreement.PrivateKey()
        secret = nil
        channel.start()
    }

    private func handle(_ msg: [String: Any]) {
        switch (msg["type"] as? String, currentState) {
        case ("pairHello", .waiting):
            guard let id = msg["macID"] as? String, !id.isEmpty,
                  let commitment = Data(base64: msg["commit"]), commitment.count == 32 else {
                return fail("Message d'appairage invalide")
            }
            macID = id
            macName = (msg["macName"] as? String).map { String($0.prefix(64)) } ?? "Mac"
            macCommitment = commitment
            channel?.send(["type": "pairKey", "id": StreamReceiver.installID,
                           "pk": privateKey.publicKey.rawRepresentation.base64])
        case ("pairReveal", .waiting):
            guard let macKey = Data(base64: msg["pk"]),
                  PairingMath.commitment(to: macKey) == macCommitment,
                  let macPublic = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: macKey),
                  let shared = try? privateKey.sharedSecretFromKeyAgreement(with: macPublic) else {
                return fail("Clé du Mac invalide")
            }
            let ownKey = privateKey.publicKey.rawRepresentation
            secret = PairingMath.secret(shared, macKey: macKey, receiverKey: ownKey)
            publish(.showCode(code: PairingMath.code(macKey: macKey, receiverKey: ownKey),
                              mac: macName))
        case ("pairConfirm", .showCode):
            guard let secret, let tag = Data(base64: msg["tag"]),
                  PairingMath.tagMatches(tag, secret, "mac-confirm") else {
                return fail("Le Mac n'a pas confirmé le code")
            }
            publish(.confirm(mac: macName))
        case ("pairAbort", _):
            fail("Code refusé sur le Mac")
        default:
            fail("Message d'appairage inattendu")
        }
    }

    private func fail(_ reason: String) {
        queue.async {
            if case .paired = self.currentState { return }
            Log.info("pairing: failed — \(reason)")
            self.channel?.send(["type": "pairAbort"])
            self.teardown()
            self.publish(.failed(reason))
        }
    }

    private func teardown() {
        timeout?.cancel()
        timeout = nil
        let channel = self.channel
        self.channel = nil
        channel?.close("done")
        listener?.cancel()
        listener = nil
        secret = nil
    }
}
