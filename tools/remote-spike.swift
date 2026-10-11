#!/usr/bin/env swift
// remote-spike.swift: checks, on a given Mac and macOS version, the platform
// pieces remote access (Shared/RemoteTrust.swift, PROTOCOL.md section 2.4)
// relies on. Standalone: Foundation, Network, CryptoKit and Security only,
// no app types.
//
// Run from the repository root:
//
//     swift tools/remote-spike.swift
//
// It prints one PASS / FAIL / INFO line per check and exits with status 1 if
// any check failed. Everything runs locally: the TLS checks use a listener
// bound to the loopback interface only, so nothing is exposed and no Local
// Network or firewall prompt should appear. Each step has a timeout, so the
// script always terminates.
//
// (a) Secure Enclave: available; a SecureEnclave.P256.Signing key (created
//     with the same access control as the app) signs and the signature
//     verifies; its dataRepresentation round-trips to the same key; a
//     SecureEnclave.P256.KeyAgreement key agrees with a software key, its
//     dataRepresentation round-trips, and the app's ECIES seal/open works.
// (b) TLS 1.2 PSK over loopback, with exactly the options of
//     Shared/Pairing.swift `SecureTransport` (TLS_PSK_WITH_AES_128_GCM_SHA256,
//     TLS 1.2 only): both ends reach .ready, both derive the RFC 5705
//     exporter labelled "EXPORTER-opendisplay-remote-auth-v1" (32 bytes) and,
//     after exchanging them over the connection, find them equal; two
//     sessions give different exporters; a wrong PSK and an unknown PSK
//     identity both fail the handshake.
// (c) Informational: TLS 1.3 with the same PSK (min/max TLS 1.3, no cipher
//     suite override). TLS 1.3 PSK would bring forward secrecy; whether
//     Network.framework accepts an external PSK there is what this records.
//
// Secure Enclave caveat: `swift file.swift` runs the code inside the
// toolchain's own (Apple-signed) process, not inside a signed app with the
// app's entitlements and Keychain access group. CryptoKit's Secure Enclave
// keys used here are not stored in the Keychain, so they normally work from a
// script; but if part (a) fails here, repeat it from the signed Debug app (or
// a signed unit-test host) before concluding the Mac cannot do remote access.
// Conversely, a PASS here does not prove that the app's Keychain storage of
// the key handles works: that is exercised by the app itself.

import Foundation
import Network
import CryptoKit
import Security

// MARK: - Reporting

final class Results: @unchecked Sendable {
    private let lock = NSLock()
    private var failed = 0

    func report(_ name: String, _ ok: Bool, _ detail: String = "") {
        lock.lock()
        if !ok { failed += 1 }
        lock.unlock()
        print("\(ok ? "PASS" : "FAIL")  \(name)\(detail.isEmpty ? "" : " — \(detail)")")
    }

    func info(_ name: String, _ detail: String) {
        print("INFO  \(name) — \(detail)")
    }

    var failures: Int {
        lock.lock(); defer { lock.unlock() }
        return failed
    }
}

let results = Results()

func section(_ title: String) {
    print("\n== \(title)")
}

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

// MARK: - (a) Secure Enclave

/// The app's ECIES (RemoteCrypto.seal/open): ephemeral P-256 agreement,
/// HKDF-SHA256, AES-GCM. Output: ephemeral public key (65) || nonce || ct || tag.
enum Seal {
    static let info = Data("opendisplay-remote-seal-v1".utf8)

    static func seal(_ secret: Data, to recipient: P256.KeyAgreement.PublicKey) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let ephemeralKey = ephemeral.publicKey.x963Representation
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeralKey,
                                                 sharedInfo: info, outputByteCount: 32)
        guard let combined = try AES.GCM.seal(secret, using: key).combined else {
            throw CocoaError(.coderInvalidValue)
        }
        return ephemeralKey + combined
    }

    static func open(_ sealed: Data, with key: SecureEnclave.P256.KeyAgreement.PrivateKey) throws -> Data {
        let bytes = Data(sealed)
        let ephemeralKey = Data(bytes.prefix(65))
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralKey)
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        let symmetric = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeralKey,
                                                       sharedInfo: info, outputByteCount: 32)
        let box = try AES.GCM.SealedBox(combined: Data(bytes.dropFirst(65)))
        return try AES.GCM.open(box, using: symmetric)
    }
}

func secureEnclaveChecks() {
    section("(a) Secure Enclave")
    let available = SecureEnclave.isAvailable
    results.report("SecureEnclave.isAvailable", available)
    guard available else {
        results.info("Secure Enclave", "skipping the key checks (no Secure Enclave: remote access unavailable on this Mac)")
        return
    }

    // Same access control as SecureEnclaveIdentity.loadOrCreate().
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil) else {
        results.report("SecAccessControlCreateWithFlags", false, "returned nil")
        return
    }

    let message = Data("opendisplay remote spike".utf8)

    // Signing key.
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        results.report("create SecureEnclave.P256.Signing key", true)
        let publicKey = key.publicKey.x963Representation
        results.report("public key is X9.63, 65 bytes", publicKey.count == 65, "\(publicKey.count) bytes")

        let signature = try key.signature(for: message)
        results.report("raw signature is 64 bytes", signature.rawRepresentation.count == 64,
                       "\(signature.rawRepresentation.count) bytes")
        // Verify the way the peer does (RemoteCrypto.verify): from the
        // X9.63 bytes and the raw signature, with software P-256.
        let verifies: Bool = {
            guard let pub = try? P256.Signing.PublicKey(x963Representation: publicKey),
                  let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature.rawRepresentation)
            else { return false }
            return pub.isValidSignature(sig, for: message)
        }()
        results.report("sign + verify (software verifier, X9.63 key, raw r||s)", verifies)
        let tampered = Data("opendisplay remote spikE".utf8)
        results.report("signature rejects a modified message",
                       !key.publicKey.isValidSignature(signature, for: tampered))

        let blob = key.dataRepresentation
        let restored = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        results.report("signing key dataRepresentation round-trip",
                       restored.publicKey.x963Representation == publicKey,
                       "handle is \(blob.count) bytes")
        let signature2 = try restored.signature(for: message)
        results.report("restored signing key signs verifiably",
                       key.publicKey.isValidSignature(signature2, for: message))
    } catch {
        results.report("Secure Enclave signing key", false, "\(error)")
    }

    // Key-agreement key (seals the PSK at rest).
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        results.report("create SecureEnclave.P256.KeyAgreement key", true)
        let software = P256.KeyAgreement.PrivateKey()
        let s1 = try key.sharedSecretFromKeyAgreement(with: software.publicKey)
        let s2 = try software.sharedSecretFromKeyAgreement(with: key.publicKey)
        let b1 = s1.withUnsafeBytes { Data($0) }
        let b2 = s2.withUnsafeBytes { Data($0) }
        results.report("key agreement matches a software peer", b1 == b2 && b1.count == 32)

        let restored = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: key.dataRepresentation)
        results.report("agreement key dataRepresentation round-trip",
                       restored.publicKey.x963Representation == key.publicKey.x963Representation)

        let secret = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let sealed = try Seal.seal(secret, to: key.publicKey)
        let opened = try Seal.open(sealed, with: restored)
        results.report("ECIES seal to SE key, open with restored handle", opened == secret,
                       "sealed blob \(sealed.count) bytes")
        let other = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let wrongOpen = (try? Seal.open(sealed, with: other)) != nil
        results.report("another SE key cannot open the sealed secret", !wrongOpen)
    } catch {
        results.report("Secure Enclave key-agreement key", false, "\(error)")
    }
}

// MARK: - (b)/(c) TLS PSK over loopback

let exporterLabel = "EXPORTER-opendisplay-remote-auth-v1"
let exporterLength = 32

struct PSK {
    var identity: String
    var secret: Data
}

func dispatchData(_ data: Data) -> __DispatchData {
    data.withUnsafeBytes { DispatchData(bytes: $0) } as __DispatchData
}

/// Mirrors SecureTransport.parameters(keys:) in Shared/Pairing.swift for
/// TLS 1.2; with `tls13` it pins TLS 1.3 and leaves the cipher suites alone.
func tlsParameters(_ keys: [PSK], tls13: Bool) -> NWParameters {
    let tls = NWProtocolTLS.Options()
    let sec = tls.securityProtocolOptions
    for key in keys {
        sec_protocol_options_add_pre_shared_key(sec, dispatchData(key.secret),
                                                dispatchData(Data(key.identity.utf8)))
    }
    if tls13 {
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(sec, .TLSv13)
    } else {
        sec_protocol_options_append_tls_ciphersuite(
            sec, tls_ciphersuite_t(rawValue: UInt16(TLS_PSK_WITH_AES_128_GCM_SHA256))!)
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(sec, .TLSv12)
    }
    let tcp = NWProtocolTCP.Options()
    tcp.noDelay = true
    return NWParameters(tls: tls, tcp: tcp)
}

/// Mirrors RemoteAuth.exporter(of:) in Shared/RemoteTrust.swift.
func exporter(of connection: NWConnection) -> Data? {
    guard let metadata = connection.metadata(definition: NWProtocolTLS.definition)
            as? NWProtocolTLS.Metadata else { return nil }
    let label = exporterLabel
    let secret: __DispatchData? = label.withCString { pointer in
        sec_protocol_metadata_create_secret(metadata.securityProtocolMetadata,
                                            label.utf8.count, pointer, exporterLength)
    }
    guard let secret else { return nil }
    return Data(secret as DispatchData)
}

/// Negotiated (protocol version, cipher suite) raw values.
func negotiated(_ connection: NWConnection) -> (version: UInt16, suite: UInt16)? {
    guard let metadata = connection.metadata(definition: NWProtocolTLS.definition)
            as? NWProtocolTLS.Metadata else { return nil }
    let m = metadata.securityProtocolMetadata
    return (sec_protocol_metadata_get_negotiated_tls_protocol_version(m).rawValue,
            sec_protocol_metadata_get_negotiated_tls_ciphersuite(m).rawValue)
}

func describe(_ n: (version: UInt16, suite: UInt16)?) -> String {
    guard let n else { return "no TLS metadata" }
    return "version 0x\(String(n.version, radix: 16)), suite 0x\(String(n.suite, radix: 16))"
}

/// State of one loopback handshake + exporter exchange. Touched from the
/// network queue and read on the main thread, always under the lock.
final class Trial: @unchecked Sendable {
    private let lock = NSLock()
    private let done = DispatchSemaphore(value: 0)
    private var finished = false

    var serverReady = false
    var clientReady = false
    var serverOwn: Data?
    var clientOwn: Data?
    var serverGot: Data?
    var clientGot: Data?
    var serverNegotiated: (version: UInt16, suite: UInt16)?
    var clientNegotiated: (version: UInt16, suite: UInt16)?
    var serverError: String?
    var clientError: String?
    var serverConnection: NWConnection?

    func update(_ body: (Trial) -> Void) {
        lock.lock(); body(self); lock.unlock()
    }

    func read<T>(_ body: (Trial) -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body(self)
    }

    func finish() {
        lock.lock()
        let first = !finished
        finished = true
        lock.unlock()
        if first { done.signal() }
    }

    func finishIfExchanged() {
        if read({ $0.serverGot != nil && $0.clientGot != nil }) { finish() }
    }

    /// true if finished before the timeout.
    func wait(seconds: Double) -> Bool {
        done.wait(timeout: .now() + seconds) == .success
    }
}

/// Each side sends its own exporter (32 zero bytes if it has none) and reads
/// exactly 32 bytes from the other.
func exchange(_ connection: NWConnection, own: Data?, trial: Trial, isServer: Bool) {
    let payload = own ?? Data(count: exporterLength)
    connection.send(content: payload, completion: .contentProcessed { error in
        if let error {
            trial.update { if isServer { $0.serverError = "send: \(error)" } else { $0.clientError = "send: \(error)" } }
            trial.finish()
        }
    })
    connection.receive(minimumIncompleteLength: exporterLength, maximumLength: exporterLength) { data, _, _, error in
        trial.update {
            let got = data ?? Data()
            if isServer { $0.serverGot = got } else { $0.clientGot = got }
            if let error {
                if isServer { $0.serverError = "receive: \(error)" } else { $0.clientError = "receive: \(error)" }
            }
        }
        if error != nil { trial.finish() } else { trial.finishIfExchanged() }
    }
}

/// One loopback session: a listener holding `serverKeys`, a client
/// presenting `clientKey`. Returns once both ends exchanged exporters, one
/// end failed, or `timeout` passed.
func runTrial(serverKeys: [PSK], clientKey: PSK, tls13: Bool, timeout: Double = 8) -> Trial {
    let trial = Trial()
    let queue = DispatchQueue(label: "remote-spike.tls")

    let serverParams = tlsParameters(serverKeys, tls13: tls13)
    serverParams.requiredInterfaceType = .loopback
    serverParams.allowLocalEndpointReuse = true
    let listener: NWListener
    do {
        listener = try NWListener(using: serverParams, on: .any)
    } catch {
        trial.update { $0.serverError = "NWListener: \(error)" }
        return trial
    }

    let listenerReady = DispatchSemaphore(value: 0)
    listener.stateUpdateHandler = { state in
        switch state {
        case .ready:
            listenerReady.signal()
        case .failed(let error):
            trial.update { $0.serverError = "listener failed: \(error)" }
            listenerReady.signal()
        default:
            break
        }
    }
    listener.newConnectionHandler = { connection in
        trial.update { $0.serverConnection = connection }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let own = exporter(of: connection)
                let n = negotiated(connection)
                trial.update { $0.serverReady = true; $0.serverOwn = own; $0.serverNegotiated = n }
                exchange(connection, own: own, trial: trial, isServer: true)
            case .failed(let error):
                trial.update { $0.serverError = "\(error)" }
                trial.finish()
            case .waiting(let error):
                trial.update { $0.serverError = "waiting: \(error)" }
                trial.finish()
            default:
                break
            }
        }
        connection.start(queue: queue)
    }
    listener.start(queue: queue)

    guard listenerReady.wait(timeout: .now() + 3) == .success,
          trial.read({ $0.serverError == nil }),
          let port = listener.port else {
        trial.update { if $0.serverError == nil { $0.serverError = "listener not ready within 3 s" } }
        listener.cancel()
        return trial
    }

    let client = NWConnection(host: "127.0.0.1", port: port,
                              using: tlsParameters([clientKey], tls13: tls13))
    client.stateUpdateHandler = { state in
        switch state {
        case .ready:
            let own = exporter(of: client)
            let n = negotiated(client)
            trial.update { $0.clientReady = true; $0.clientOwn = own; $0.clientNegotiated = n }
            exchange(client, own: own, trial: trial, isServer: false)
        case .failed(let error):
            trial.update { $0.clientError = "\(error)" }
            trial.finish()
        case .waiting(let error):
            trial.update { $0.clientError = "waiting: \(error)" }
            trial.finish()
        default:
            break
        }
    }
    client.start(queue: queue)

    if !trial.wait(seconds: timeout) {
        trial.update { if $0.clientError == nil { $0.clientError = "timed out after \(Int(timeout)) s" } }
    }
    // Give a failing peer's state a moment to settle before reading it.
    Thread.sleep(forTimeInterval: 0.3)
    client.cancel()
    trial.read { $0.serverConnection }?.cancel()
    listener.cancel()
    return trial
}

func randomSecret() -> Data {
    var bytes = Data(count: 32)
    let status = bytes.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
    }
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
    return bytes
}

func randomIdentity() -> String {
    hex(randomSecret().prefix(16))   // 32 lowercase hex characters, like a pid
}

/// Checks a trial that should have succeeded. Returns its exporter.
@discardableResult
func checkSuccess(_ trial: Trial, label: String, expectTLS12: Bool) -> Data? {
    let s = trial.read { t in
        (t.serverReady, t.clientReady, t.serverOwn, t.clientOwn, t.serverGot, t.clientGot,
         t.serverNegotiated, t.clientNegotiated, t.serverError, t.clientError)
    }
    let (serverReady, clientReady, serverOwn, clientOwn, serverGot, clientGot,
         serverNeg, clientNeg, serverError, clientError) = s
    let errors = [serverError.map { "server: \($0)" }, clientError.map { "client: \($0)" }]
        .compactMap { $0 }.joined(separator: "; ")

    results.report("\(label): both ends reach .ready", serverReady && clientReady,
                   errors.isEmpty ? "" : errors)
    guard serverReady && clientReady else { return nil }

    if expectTLS12 {
        let ok = serverNeg?.version == 0x0303 && clientNeg?.version == 0x0303
            && serverNeg?.suite == 0x00A8 && clientNeg?.suite == 0x00A8
        results.report("\(label): negotiated TLS 1.2 + TLS_PSK_WITH_AES_128_GCM_SHA256", ok,
                       "server \(describe(serverNeg)); client \(describe(clientNeg))")
    } else {
        results.info("\(label): negotiated", "server \(describe(serverNeg)); client \(describe(clientNeg))")
    }

    results.report("\(label): server exporter is \(exporterLength) bytes", serverOwn?.count == exporterLength,
                   serverOwn.map { "\($0.count) bytes" } ?? "sec_protocol_metadata_create_secret returned nil")
    results.report("\(label): client exporter is \(exporterLength) bytes", clientOwn?.count == exporterLength,
                   clientOwn.map { "\($0.count) bytes" } ?? "sec_protocol_metadata_create_secret returned nil")
    guard let serverOwn, let clientOwn else { return nil }
    results.report("\(label): exporter is not all zeros", serverOwn != Data(count: serverOwn.count))
    results.report("\(label): exporters exchanged over the connection",
                   serverGot?.count == exporterLength && clientGot?.count == exporterLength,
                   errors)
    results.report("\(label): both ends derive the same exporter",
                   serverOwn == clientOwn && serverGot == clientOwn && clientGot == serverOwn,
                   "server \(hex(serverOwn.prefix(8)))…, client \(hex(clientOwn.prefix(8)))…")
    return serverOwn == clientOwn ? serverOwn : nil
}

/// Checks a trial that must not have produced a session.
func checkRefused(_ trial: Trial, label: String) {
    let (serverReady, clientReady, serverError, clientError) = trial.read {
        ($0.serverReady, $0.clientReady, $0.serverError, $0.clientError)
    }
    let detail = [serverError.map { "server: \($0)" }, clientError.map { "client: \($0)" }]
        .compactMap { $0 }.joined(separator: "; ")
    results.report("\(label): handshake fails, neither end reaches .ready",
                   !serverReady && !clientReady, detail)
}

func tlsChecks() {
    section("(b) TLS 1.2 PSK over loopback")
    let key = PSK(identity: randomIdentity(), secret: randomSecret())
    let otherPeer = PSK(identity: randomIdentity(), secret: randomSecret())

    // The server holds several peers' keys, as the Mac's listener does.
    let first = checkSuccess(runTrial(serverKeys: [otherPeer, key], clientKey: key, tls13: false),
                             label: "TLS 1.2 PSK", expectTLS12: true)
    let second = checkSuccess(runTrial(serverKeys: [otherPeer, key], clientKey: key, tls13: false),
                              label: "TLS 1.2 PSK, second session", expectTLS12: true)
    if let first, let second {
        results.report("two sessions with the same PSK give different exporters", first != second)
    }

    let wrongSecret = PSK(identity: key.identity, secret: randomSecret())
    checkRefused(runTrial(serverKeys: [otherPeer, key], clientKey: wrongSecret, tls13: false),
                 label: "wrong PSK (right identity)")
    let unknownIdentity = PSK(identity: randomIdentity(), secret: key.secret)
    checkRefused(runTrial(serverKeys: [otherPeer, key], clientKey: unknownIdentity, tls13: false),
                 label: "unknown PSK identity")

    section("(c) TLS 1.3 PSK (informational)")
    let trial = runTrial(serverKeys: [key], clientKey: key, tls13: true)
    let (serverReady, clientReady, serverOwn, clientOwn, serverNeg, clientNeg, serverError, clientError) = trial.read {
        ($0.serverReady, $0.clientReady, $0.serverOwn, $0.clientOwn,
         $0.serverNegotiated, $0.clientNegotiated, $0.serverError, $0.clientError)
    }
    if serverReady && clientReady {
        results.info("TLS 1.3 PSK", "connects: server \(describe(serverNeg)); client \(describe(clientNeg))")
        let same = serverOwn != nil && serverOwn == clientOwn && serverOwn?.count == exporterLength
        results.info("TLS 1.3 PSK exporter", same ? "equal on both ends (\(exporterLength) bytes)"
                                                  : "missing or different")
    } else {
        let detail = [serverError.map { "server: \($0)" }, clientError.map { "client: \($0)" }]
            .compactMap { $0 }.joined(separator: "; ")
        results.info("TLS 1.3 PSK", "does not connect\(detail.isEmpty ? "" : " (\(detail))")")
    }
    let wrong = runTrial(serverKeys: [key], clientKey: wrongSecret, tls13: true)
    let wrongConnected = wrong.read { $0.serverReady && $0.clientReady }
    results.info("TLS 1.3 PSK, wrong PSK", wrongConnected ? "CONNECTED (unexpected, investigate)" : "refused")
}

// MARK: - Main

let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
print("remote-spike: macOS \(osVersion)")
secureEnclaveChecks()
tlsChecks()

let failures = results.failures
print("")
print(failures == 0 ? "All checks passed." : "\(failures) check(s) FAILED.")
exit(failures == 0 ? 0 : 1)
