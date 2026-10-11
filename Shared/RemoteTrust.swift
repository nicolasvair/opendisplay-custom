import Foundation
import Network
import CryptoKit
import Security

// MARK: - Remote access (custom build)
//
// Lets a receiver (iPhone/iPad) reach its Mac from outside the local network.
// The usual roles flip for this path: the Mac listens (TCP, default 9010) and
// the device dials, because a phone on cellular sits behind carrier NAT and
// cannot be dialed.
//
// The listening port can be reached from the whole Internet, so the rules are
// strict:
//
// * Remote access exists only for peers paired over USB. The Mac dials the
//   cabled device through usbmuxd itself, and the device opens its
//   loopback-only pairing listener only after the user asks for it. A WiFi
//   (code) pairing never grants remote access.
// * Each device has a long-term P-256 signing identity in its Secure Enclave.
//   The private key cannot be exported, backed up or migrated, so a new
//   machine restored or migrated from a paired one has a different identity.
//   No Secure Enclave, no remote access: there is no software fallback.
// * Peers are stored under the fingerprint of their public key, never under
//   an ID they chose, so one pairing cannot overwrite another.
// * Each pairing has its own 256-bit secret, used as the TLS 1.2 PSK. At rest
//   it is sealed to a Secure Enclave key-agreement key, so copying the
//   Keychain item to another machine gives nothing usable.
// * Inside TLS, before any other message, both ends sign a value exported
//   from that TLS session (RFC 5705) with their Secure Enclave key. The other
//   end checks it against the public key pinned at USB pairing. The
//   signature is bound to the session, so it can be neither replayed nor
//   relayed. The Mac reads nothing but this one small frame until it checks out.
//
// This file stays free of app types (no Log, no StreamReceiver) so the unit
// test bundle can compile it on its own.

enum RemoteWire {
    /// Receiver-side USB pairing listener: base port + 4. Loopback only (it is
    /// reached through usbmuxd), never advertised, and up only while the user
    /// has the "remote access" pairing screen open.
    static let usbPairingPortOffset: UInt16 = 4
    /// The Mac's remote listener when the user has not chosen another port.
    static let defaultMacPort: UInt16 = 9010
    /// How long a USB pairing attempt may take end to end.
    static let pairingTimeout: TimeInterval = 120
    /// How long a dialer has, once TLS is up, to authenticate.
    static let authTimeout: TimeInterval = 5
    /// Largest authentication frame either end accepts (payload bytes).
    static let maxAuthFrame = 1024
    /// Version of the remote pairing + authentication scheme.
    static let version = 1

    // Pairing dialogue message types (newline-delimited JSON, PairingChannel).
    static let pairCommit = "rpCommit"
    static let pairHello = "rpHello"
    static let pairConfirm = "rpConfirm"
    static let pairAbort = "rpAbort"
    // Session message types (length-prefixed JSON, the main protocol framing).
    /// Both directions, first frame after TLS: the channel-bound signature.
    static let auth = "rauth"
    /// Mac -> device on any authenticated session (USB, paired WiFi, remote):
    /// the Mac's current remote addresses, so the device can follow a changed
    /// IPv6 prefix without re-pairing.
    static let hostUpdate = "remoteHost"
}

enum RemoteRole: String {
    case mac
    case device
}

enum RemoteTrustError: Error, Equatable {
    case secureEnclaveUnavailable
    case keychain(OSStatus)
    case malformed(String)
}

// MARK: - Identity

/// A device's long-term identity: signs with a P-256 key and seals secrets
/// at rest so that only this same identity can open them.
protocol RemoteIdentity: AnyObject {
    /// P-256 signing public key, X9.63 (65 bytes).
    var publicKey: Data { get }
    /// ECDSA P-256 / SHA-256 signature, raw r||s (64 bytes).
    func sign(_ message: Data) throws -> Data
    func seal(_ secret: Data) throws -> Data
    func open(_ sealed: Data) throws -> Data
}

extension RemoteIdentity {
    var fingerprint: String { RemoteCrypto.fingerprint(of: publicKey) }
}

/// The production identity: both keys live in the Secure Enclave. Only their
/// opaque handles (`dataRepresentation`) are stored. Those handles work only
/// on the Secure Enclave that created them, so a backup, a migration or a
/// copied Keychain carries nothing usable.
final class SecureEnclaveIdentity: RemoteIdentity {
    private let signingKey: SecureEnclave.P256.Signing.PrivateKey
    private let agreementKey: SecureEnclave.P256.KeyAgreement.PrivateKey

    /// This device's identity, created on first use. `nil` when the device
    /// has no usable Secure Enclave; remote access is unavailable then.
    static let shared: SecureEnclaveIdentity? = {
        do { return try SecureEnclaveIdentity.loadOrCreate() } catch {
            lastError = "\(error)"
            return nil
        }
    }()
    /// Why `shared` is nil, for logs and the settings screen.
    private(set) static var lastError: String?

    private init(signing: SecureEnclave.P256.Signing.PrivateKey,
                 agreement: SecureEnclave.P256.KeyAgreement.PrivateKey) {
        signingKey = signing
        agreementKey = agreement
    }

    private static let keychainService = "OpenDisplay Custom remote identity"

    static func loadOrCreate() throws -> SecureEnclaveIdentity {
        guard SecureEnclave.isAvailable else { throw RemoteTrustError.secureEnclaveUnavailable }
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil)!
        let signing: SecureEnclave.P256.Signing.PrivateKey
        // A handle copied from another machine (migration, backup) may load
        // but cannot sign; probe it and start over with a fresh key if so.
        // A failed read throws (fail closed) rather than passing for "no key
        // yet", which would replace this device's identity.
        if let blob = try KeychainBlob.load(service: keychainService, account: "signing"),
           let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob),
           (try? key.signature(for: Data("probe".utf8))) != nil {
            signing = key
        } else {
            signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            try KeychainBlob.save(signing.dataRepresentation, service: keychainService, account: "signing")
        }
        let agreement: SecureEnclave.P256.KeyAgreement.PrivateKey
        if let blob = try KeychainBlob.load(service: keychainService, account: "agreement"),
           let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob),
           (try? key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PrivateKey().publicKey)) != nil {
            agreement = key
        } else {
            agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            try KeychainBlob.save(agreement.dataRepresentation, service: keychainService, account: "agreement")
        }
        return SecureEnclaveIdentity(signing: signing, agreement: agreement)
    }

    var publicKey: Data { signingKey.publicKey.x963Representation }

    func sign(_ message: Data) throws -> Data {
        try signingKey.signature(for: message).rawRepresentation
    }

    func seal(_ secret: Data) throws -> Data {
        try RemoteCrypto.seal(secret, to: agreementKey.publicKey)
    }

    func open(_ sealed: Data) throws -> Data {
        try RemoteCrypto.open(sealed) { try agreementKey.sharedSecretFromKeyAgreement(with: $0) }
    }
}

/// Same contract with ordinary software keys. For unit tests only. The apps
/// never fall back to it: a software key could be copied, which is exactly
/// what remote access must rule out.
final class SoftwareIdentity: RemoteIdentity {
    private let signingKey = P256.Signing.PrivateKey()
    private let agreementKey = P256.KeyAgreement.PrivateKey()

    var publicKey: Data { signingKey.publicKey.x963Representation }

    func sign(_ message: Data) throws -> Data {
        try signingKey.signature(for: message).rawRepresentation
    }

    func seal(_ secret: Data) throws -> Data {
        try RemoteCrypto.seal(secret, to: agreementKey.publicKey)
    }

    func open(_ sealed: Data) throws -> Data {
        try RemoteCrypto.open(sealed) { try agreementKey.sharedSecretFromKeyAgreement(with: $0) }
    }
}

// MARK: - Primitives

enum RemoteCrypto {
    /// Short, stable identifier for a public key: hex of the first 16 bytes
    /// of its SHA-256. Derived, never claimed, so it cannot be chosen to
    /// collide with another peer's.
    static func fingerprint(of publicKey: Data) -> String {
        SHA256.hash(data: publicKey).prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    static func verify(signature: Data, message: Data, publicKey: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else { return false }
        return key.isValidSignature(sig, for: message)
    }

    static func randomBytes(_ count: Int) -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return bytes
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static let sealInfo = Data("opendisplay-remote-seal-v1".utf8)
    private static let ephemeralKeyLength = 65

    /// ECIES: an ephemeral P-256 agreement with `recipient`, HKDF-SHA256,
    /// AES-GCM. Output: ephemeral public key (65 bytes) || nonce || ciphertext || tag.
    static func seal(_ secret: Data, to recipient: P256.KeyAgreement.PublicKey) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let ephemeralKey = ephemeral.publicKey.x963Representation
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeralKey,
                                                 sharedInfo: sealInfo, outputByteCount: 32)
        guard let combined = try AES.GCM.seal(secret, using: key).combined else {
            throw RemoteTrustError.malformed("AES-GCM produced no combined box")
        }
        return ephemeralKey + combined
    }

    static func open(_ sealed: Data,
                     agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret) throws -> Data {
        let bytes = Data(sealed)   // re-base indices
        guard bytes.count > ephemeralKeyLength + 28 else { throw RemoteTrustError.malformed("sealed secret too short") }
        let ephemeralKey = Data(bytes.prefix(ephemeralKeyLength))
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralKey)
        let shared = try agree(peer)
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeralKey,
                                                 sharedInfo: sealInfo, outputByteCount: 32)
        let box = try AES.GCM.SealedBox(combined: Data(bytes.dropFirst(ephemeralKeyLength)))
        return try AES.GCM.open(box, using: key)
    }
}

// MARK: - USB pairing

/// The remote pairing dialogue. It runs over a usbmuxd tunnel the Mac opened
/// to the device's loopback-only listener, so the cable proves which two
/// devices are talking. Both screens show a code derived from the whole
/// exchange, and the user accepts on both devices.
///
///     Mac    -> device  rpCommit  {v, c: helloDigest(mac hello)}
///     device -> Mac     rpHello   {v, name, sk, ek, iid}
///     Mac    -> device  rpHello   {v, name, sk, ek, pid}   (device checks it against c)
///     (both show code(transcript), the user accepts on each device)
///     Mac    -> device  rpConfirm {sig: sign_mac(confirm(.mac, T)), addrs, port}
///     device -> Mac     rpConfirm {sig: sign_dev(confirm(.device, T))}
///
/// `sk` is the long-term Secure Enclave signing key, `ek` a fresh X25519 key
/// for this pairing only, `pid` the TLS-PSK identity the Mac assigns (random,
/// so it reveals nothing about either device), `iid` the device's install ID
/// (so the Mac can recognize the device when it later arrives over USB or WiFi).
/// The Mac commits to its hello before it sees the device's, and the device
/// sends its hello before it sees the Mac's. Neither side (nor a man in the
/// middle playing either role) can then try hello variants until the
/// 6-digit codes on the two screens match: the code is fixed before the
/// last party to speak learns what it will be.
/// Each side stores the peer only after both of these hold: its own user
/// accepted, and the peer's confirm signature checks out against the `sk`
/// from the transcript.
enum RemotePairing {
    struct Hello: Equatable {
        var name: String
        var signingKey: Data      // P-256 X9.63, 65 bytes
        var ephemeralKey: Data    // X25519 raw, 32 bytes
        /// Mac only: the PSK identity it assigns to this pairing.
        var pskIdentity: String?
        /// Device only: its install ID.
        var installID: String?
    }

    static func helloMessage(_ hello: Hello) -> [String: Any] {
        var msg: [String: Any] = [
            "type": RemoteWire.pairHello,
            "v": RemoteWire.version,
            "name": hello.name,
            "sk": hello.signingKey.base64EncodedString(),
            "ek": hello.ephemeralKey.base64EncodedString(),
        ]
        if let pid = hello.pskIdentity { msg["pid"] = pid }
        if let iid = hello.installID { msg["iid"] = iid }
        return msg
    }

    /// The Mac's commitment: a digest of its whole hello, sent before it sees
    /// the device's hello.
    static func helloDigest(_ hello: Hello, role: RemoteRole) -> Data {
        var input = Data("opendisplay-remote-commit-v1\0\(role.rawValue)".utf8)
        let fields: [Data] = [
            hello.signingKey, hello.ephemeralKey, Data(normalizedName(hello.name, role: role).utf8),
            Data((hello.pskIdentity ?? "").utf8), Data((hello.installID ?? "").utf8),
        ]
        for field in fields { appendLengthPrefixed(field, to: &input) }
        return Data(SHA256.hash(data: input))
    }

    static func commitMessage(_ hello: Hello) -> [String: Any] {
        ["type": RemoteWire.pairCommit, "v": RemoteWire.version,
         "c": helloDigest(hello, role: .mac).base64EncodedString()]
    }

    static func parseCommit(_ msg: [String: Any]) -> Data? {
        guard msg["type"] as? String == RemoteWire.pairCommit,
              msg["v"] as? Int == RemoteWire.version,
              let c = (msg["c"] as? String).flatMap({ Data(base64Encoded: $0) }), c.count == 32
        else { return nil }
        return c
    }

    /// Validates a peer's hello. `from` is the role of the peer that sent it.
    static func parseHello(_ msg: [String: Any], from role: RemoteRole) -> Hello? {
        guard msg["type"] as? String == RemoteWire.pairHello,
              msg["v"] as? Int == RemoteWire.version,
              let sk = (msg["sk"] as? String).flatMap({ Data(base64Encoded: $0) }),
              (try? P256.Signing.PublicKey(x963Representation: sk)) != nil,
              let ek = (msg["ek"] as? String).flatMap({ Data(base64Encoded: $0) }),
              (try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ek)) != nil
        else { return nil }
        let name = normalizedName(msg["name"] as? String ?? "", role: role)
        switch role {
        case .mac:
            guard let pid = msg["pid"] as? String, isValidPSKIdentity(pid) else { return nil }
            return Hello(name: name, signingKey: sk, ephemeralKey: ek, pskIdentity: pid, installID: nil)
        case .device:
            let iid = (msg["iid"] as? String).map { String($0.prefix(64)) }
            return Hello(name: name, signingKey: sk, ephemeralKey: ek, pskIdentity: nil, installID: iid)
        }
    }

    /// Display names as both sides hash them: trimmed, at most 64
    /// characters, never empty. `transcript` applies it too, so the sender's
    /// own `Hello` and the peer's parsed copy always hash alike.
    static func normalizedName(_ name: String, role: RemoteRole) -> String {
        // Control and format characters (bidi overrides included) could make
        // a name display as something else on the confirmation screens.
        let visible = String(name.unicodeScalars.filter {
            $0.properties.generalCategory != .control && $0.properties.generalCategory != .format
        })
        let trimmed = String(visible.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
        if !trimmed.isEmpty { return trimmed }
        return role == .mac ? "Mac" : "Appareil"
    }

    /// A fresh PSK identity: 16 random bytes, hex.
    static func newPSKIdentity() -> String { RemoteCrypto.hex(RemoteCrypto.randomBytes(16)) }

    static func isValidPSKIdentity(_ pid: String) -> Bool {
        pid.count == 32 && pid.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    /// Hash of everything both sides said, in a fixed order with every field
    /// length-prefixed. Any field changed in transit gives a different
    /// transcript, so a different code and signatures that fail.
    static func transcript(mac: Hello, device: Hello) -> Data {
        var input = Data("opendisplay-remote-pair-v1".utf8)
        let fields: [Data] = [
            mac.signingKey, mac.ephemeralKey, Data(normalizedName(mac.name, role: .mac).utf8),
            Data((mac.pskIdentity ?? "").utf8),
            device.signingKey, device.ephemeralKey, Data(normalizedName(device.name, role: .device).utf8),
            Data((device.installID ?? "").utf8),
        ]
        for field in fields { appendLengthPrefixed(field, to: &input) }
        return Data(SHA256.hash(data: input))
    }

    static func appendLengthPrefixed(_ field: Data, to input: inout Data) {
        var length = UInt32(field.count).bigEndian
        input.append(Data(bytes: &length, count: 4))
        input.append(field)
    }

    /// The 6-digit code both screens show.
    static func code(transcript: Data) -> String {
        var input = Data("opendisplay-remote-code-v1".utf8)
        input.append(transcript)
        let digest = Array(SHA256.hash(data: input))
        let value = (UInt32(digest[0]) << 24 | UInt32(digest[1]) << 16
                     | UInt32(digest[2]) << 8 | UInt32(digest[3])) % 1_000_000
        return String(format: "%06u", value)
    }

    /// The pairing's 256-bit secret (the TLS PSK), from the ephemeral X25519
    /// exchange, salted with the transcript.
    static func secret(ownEphemeral: Curve25519.KeyAgreement.PrivateKey,
                       peerEphemeral: Data, transcript: Data) throws -> Data {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerEphemeral)
        let shared = try ownEphemeral.sharedSecretFromKeyAgreement(with: peer)
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: transcript,
                                                 sharedInfo: Data("opendisplay-remote-psk-v1".utf8),
                                                 outputByteCount: 32)
        return key.withUnsafeBytes { Data($0) }
    }

    /// What each side signs to confirm the pairing.
    static func confirmPayload(_ role: RemoteRole, transcript: Data) -> Data {
        var payload = Data("opendisplay-remote-confirm-v1\0\(role.rawValue)\0".utf8)
        payload.append(transcript)
        return payload
    }

    static func confirmMessage(_ role: RemoteRole, transcript: Data, identity: RemoteIdentity,
                               extra: [String: Any] = [:]) throws -> [String: Any] {
        var msg = extra
        msg["type"] = RemoteWire.pairConfirm
        msg["sig"] = try identity.sign(confirmPayload(role, transcript: transcript)).base64EncodedString()
        return msg
    }

    /// Checks a peer's confirm. `from` is the role of the peer that sent it,
    /// `peerKey` the signing key from that peer's hello.
    static func verifyConfirm(_ msg: [String: Any], from role: RemoteRole,
                              transcript: Data, peerKey: Data) -> Bool {
        guard msg["type"] as? String == RemoteWire.pairConfirm,
              let sig = (msg["sig"] as? String).flatMap({ Data(base64Encoded: $0) }) else { return false }
        return RemoteCrypto.verify(signature: sig, message: confirmPayload(role, transcript: transcript),
                                   publicKey: peerKey)
    }
}

// MARK: - Session authentication

/// The first frame in each direction on a remote session, inside TLS. It
/// uses the main protocol's framing (4-byte big-endian length + JSON).
///
///     device -> Mac  {"type":"rauth","v":1,"pid":<psk identity>,"sig":<b64>}
///     Mac -> device  {"type":"rauth","v":1,"sig":<b64>}
///
/// sig = sign(payload(role, pid, exporter)), where exporter is 32 bytes
/// exported from this TLS session under `exporterLabel`. The device speaks
/// first. The Mac checks the signature against the key pinned for `pid`,
/// then answers. The device checks the Mac's answer before it sends `hello`.
enum RemoteAuth {
    static let exporterLabel = "EXPORTER-opendisplay-remote-auth-v1"
    static let exporterLength = 32

    /// The RFC 5705 exporter of an established TLS connection, or nil if the
    /// connection has no TLS metadata (not ready, or not TLS).
    static func exporter(of connection: NWConnection) -> Data? {
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition)
                as? NWProtocolTLS.Metadata else { return nil }
        let label = exporterLabel
        let secret: __DispatchData? = label.withCString { pointer in
            sec_protocol_metadata_create_secret(metadata.securityProtocolMetadata,
                                                label.utf8.count, pointer, exporterLength)
        }
        guard let secret else { return nil }
        let data = Data(secret as DispatchData)
        return data.count == exporterLength ? data : nil
    }

    static func payload(_ role: RemoteRole, pskIdentity: String, exporter: Data) -> Data {
        var payload = Data("opendisplay-remote-auth-v1\0\(role.rawValue)\0\(pskIdentity)\0".utf8)
        payload.append(exporter)
        return payload
    }

    static func message(_ role: RemoteRole, pskIdentity: String, exporter: Data,
                        identity: RemoteIdentity) throws -> [String: Any] {
        var msg: [String: Any] = [
            "type": RemoteWire.auth,
            "v": RemoteWire.version,
            "sig": try identity.sign(payload(role, pskIdentity: pskIdentity, exporter: exporter))
                .base64EncodedString(),
        ]
        if role == .device { msg["pid"] = pskIdentity }
        return msg
    }

    /// The PSK identity a device's auth frame claims. The Mac uses it only to
    /// pick which pinned key to verify against.
    static func claimedPSKIdentity(_ msg: [String: Any]) -> String? {
        guard msg["type"] as? String == RemoteWire.auth,
              let pid = msg["pid"] as? String, RemotePairing.isValidPSKIdentity(pid) else { return nil }
        return pid
    }

    /// Checks a peer's auth frame. `from` is the role of the peer that sent it.
    static func verify(_ msg: [String: Any], from role: RemoteRole, pskIdentity: String,
                       exporter: Data, peerKey: Data) -> Bool {
        guard msg["type"] as? String == RemoteWire.auth,
              msg["v"] as? Int == RemoteWire.version,
              let sig = (msg["sig"] as? String).flatMap({ Data(base64Encoded: $0) }) else { return false }
        if role == .device, msg["pid"] as? String != pskIdentity { return false }
        return RemoteCrypto.verify(signature: sig,
                                   message: payload(role, pskIdentity: pskIdentity, exporter: exporter),
                                   publicKey: peerKey)
    }

    // MARK: Framing

    /// `[4-byte big-endian length][JSON]`, as the main protocol frames
    /// control messages.
    static func frame(_ message: [String: Any]) -> Data? {
        guard let json = try? JSONSerialization.data(withJSONObject: message) else { return nil }
        var length = UInt32(json.count).bigEndian
        return Data(bytes: &length, count: 4) + json
    }

    /// Reads exactly one frame of at most `maxLength` payload bytes and
    /// parses it as a JSON object. Calls back with nil on anything else
    /// (oversize, malformed, closed). Reads nothing past that frame.
    static func receiveFrame(on connection: NWConnection, maxLength: Int = RemoteWire.maxAuthFrame,
                             completion: @escaping ([String: Any]?) -> Void) {
        connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { header, _, _, error in
            guard error == nil, let header, header.count == 4 else { return completion(nil) }
            let b = [UInt8](header)
            let length = Int(b[0]) << 24 | Int(b[1]) << 16 | Int(b[2]) << 8 | Int(b[3])
            guard length > 0, length <= maxLength else { return completion(nil) }
            connection.receive(minimumIncompleteLength: length, maximumLength: length) { body, _, _, error in
                guard error == nil, let body, body.count == length,
                      let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
                else { return completion(nil) }
                completion(obj)
            }
        }
    }
}

// MARK: - Address updates

enum RemoteHostUpdate {
    /// Mac -> device: `{"type":"remoteHost","fp","addrs","port","sig"}`. The
    /// Mac signs it with its Secure Enclave key, so a device accepts it only
    /// for the Mac whose pinned key verifies it, whatever session carried it.
    static func message(identity: RemoteIdentity, addresses: [String], port: UInt16) throws -> [String: Any] {
        let fp = identity.fingerprint
        let sig = try identity.sign(payload(fingerprint: fp, addresses: addresses, port: port))
        return ["type": RemoteWire.hostUpdate, "fp": fp, "addrs": addresses, "port": Int(port),
                "sig": sig.base64EncodedString()]
    }

    static func payload(fingerprint: String, addresses: [String], port: UInt16) -> Data {
        var input = Data("opendisplay-remote-host-v1\0\(fingerprint)\0\(port)".utf8)
        for address in addresses { RemotePairing.appendLengthPrefixed(Data(address.utf8), to: &input) }
        return input
    }

    struct Update: Equatable {
        var fingerprint: String
        var addresses: [String]
        var port: UInt16
        var signature: Data
    }

    /// Shape checks only; call `verify` against the stored host before use.
    static func parse(_ msg: [String: Any]) -> Update? {
        guard msg["type"] as? String == RemoteWire.hostUpdate,
              let fp = msg["fp"] as? String, fp.count == 32,
              let addrs = msg["addrs"] as? [String], addrs.count <= 16,
              let port = msg["port"] as? Int, port > 0, port <= Int(UInt16.max),
              let sig = (msg["sig"] as? String).flatMap({ Data(base64Encoded: $0) })
        else { return nil }
        guard addrs.allSatisfy({ !$0.isEmpty && $0.count <= 255 }) else { return nil }
        return Update(fingerprint: fp, addresses: addrs, port: UInt16(port), signature: sig)
    }

    static func verify(_ update: Update, against host: RemoteHost) -> Bool {
        update.fingerprint == host.id
            && RemoteCrypto.verify(signature: update.signature,
                                   message: payload(fingerprint: update.fingerprint,
                                                    addresses: update.addresses, port: update.port),
                                   publicKey: host.publicKey)
    }
}

// MARK: - Storage

/// A device paired for remote access, as the Mac stores it.
struct RemotePeer: Codable, Equatable, Identifiable {
    /// Fingerprint of `publicKey`.
    var id: String
    var name: String
    var publicKey: Data
    /// The device's install ID, to recognize it on USB/WiFi sessions.
    var installID: String?
    var pskIdentity: String
    /// The PSK, sealed to this Mac's Secure Enclave identity.
    var sealedSecret: Data
    var pairedAt: Date
}

/// A Mac paired for remote access, as the device stores it.
struct RemoteHost: Codable, Equatable, Identifiable {
    /// Fingerprint of `publicKey`.
    var id: String
    var name: String
    var publicKey: Data
    var pskIdentity: String
    /// The PSK, sealed to this device's Secure Enclave identity.
    var sealedSecret: Data
    /// Hosts to dial, in order: IPv6/IPv4 literals or DNS names.
    var addresses: [String]
    var port: UInt16
    var pairedAt: Date
}

protocol RemoteRecord: Codable, Identifiable where ID == String {
    var pskIdentity: String { get }
}
extension RemotePeer: RemoteRecord {}
extension RemoteHost: RemoteRecord {}

enum RemoteStore {
    private static let service = "OpenDisplay Custom remote pairing"

    // Reads throw on Keychain errors: callers must not mistake a failed read
    // for an empty list and then save over every existing pairing.
    static func peers() throws -> [RemotePeer] { try load(account: "mac") }
    static func savePeers(_ peers: [RemotePeer]) throws { try save(peers, account: "mac") }
    static func hosts() throws -> [RemoteHost] { try load(account: "device") }
    static func saveHosts(_ hosts: [RemoteHost]) throws { try save(hosts, account: "device") }

    /// Adds or replaces `record`. It replaces any entry with the same
    /// fingerprint (same peer, re-paired) or the same PSK identity.
    static func merged<T: RemoteRecord>(_ records: [T], with record: T) -> [T] {
        records.filter { $0.id != record.id && $0.pskIdentity != record.pskIdentity } + [record]
    }

    private static func load<T: Codable>(account: String) throws -> [T] {
        guard let data = try KeychainBlob.load(service: service, account: account) else { return [] }
        return try JSONDecoder().decode([T].self, from: data)
    }

    private static func save<T: Codable>(_ records: [T], account: String) throws {
        if records.isEmpty {
            guard KeychainBlob.delete(service: service, account: account) else {
                throw RemoteTrustError.keychain(errSecIO)
            }
            return
        }
        try KeychainBlob.save(try JSONEncoder().encode(records), service: service, account: account)
    }
}

/// Generic-password items, this device only.
enum KeychainBlob {
    /// nil only when there is no such item; any other failure throws.
    static func load(service: String, account: String) throws -> Data? {
        var query = baseQuery(service, account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw RemoteTrustError.keychain(status) }
        return item as? Data
    }

    static func save(_ data: Data, service: String, account: String) throws {
        let query = baseQuery(service, account)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return }
        // An item that cannot be updated in place (ACL, legacy keychain
        // quirks) is replaced, so a "forget" can never silently not stick.
        if status != errSecItemNotFound { SecItemDelete(query as CFDictionary) }
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw RemoteTrustError.keychain(addStatus) }
    }

    @discardableResult
    static func delete(service: String, account: String) -> Bool {
        let status = SecItemDelete(baseQuery(service, account) as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    private static func baseQuery(_ service: String, _ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }
}
