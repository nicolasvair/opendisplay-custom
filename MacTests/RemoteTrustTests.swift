import XCTest
import CryptoKit

/// The remote pairing and authentication math, with software identities
/// standing in for the Secure Enclave (same contract, testable anywhere).
final class RemoteTrustTests: XCTestCase {
    private struct Side {
        let identity = SoftwareIdentity()
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
    }

    private func hellos(mac: Side, device: Side, pid: String = RemotePairing.newPSKIdentity())
        -> (RemotePairing.Hello, RemotePairing.Hello) {
        (RemotePairing.Hello(name: "MacBook", signingKey: mac.identity.publicKey,
                             ephemeralKey: mac.ephemeral.publicKey.rawRepresentation,
                             pskIdentity: pid, installID: nil),
         RemotePairing.Hello(name: "iPad", signingKey: device.identity.publicKey,
                             ephemeralKey: device.ephemeral.publicKey.rawRepresentation,
                             pskIdentity: nil, installID: "INSTALL-1"))
    }

    // MARK: Pairing

    func testHelloRoundTripsThroughJSON() throws {
        let (macHello, deviceHello) = hellos(mac: Side(), device: Side())
        let macWire = try roundTrip(RemotePairing.helloMessage(macHello))
        let deviceWire = try roundTrip(RemotePairing.helloMessage(deviceHello))
        XCTAssertEqual(RemotePairing.parseHello(macWire, from: .mac), macHello)
        XCTAssertEqual(RemotePairing.parseHello(deviceWire, from: .device), deviceHello)
    }

    func testMacHelloWithoutValidPSKIdentityIsRejected() throws {
        var (macHello, _) = hellos(mac: Side(), device: Side())
        macHello.pskIdentity = "not-hex"
        XCTAssertNil(RemotePairing.parseHello(try roundTrip(RemotePairing.helloMessage(macHello)), from: .mac))
        macHello.pskIdentity = nil
        XCTAssertNil(RemotePairing.parseHello(try roundTrip(RemotePairing.helloMessage(macHello)), from: .mac))
    }

    func testHelloWithBadKeysIsRejected() throws {
        var (_, deviceHello) = hellos(mac: Side(), device: Side())
        deviceHello.signingKey = Data(repeating: 4, count: 65)
        XCTAssertNil(RemotePairing.parseHello(RemotePairing.helloMessage(deviceHello), from: .device))
    }

    func testBothSidesDeriveTheSameCodeAndSecret() throws {
        let mac = Side(), device = Side()
        let (macHello, deviceHello) = hellos(mac: mac, device: device)
        let transcript = RemotePairing.transcript(mac: macHello, device: deviceHello)
        let macSecret = try RemotePairing.secret(ownEphemeral: mac.ephemeral,
                                                 peerEphemeral: deviceHello.ephemeralKey,
                                                 transcript: transcript)
        let deviceSecret = try RemotePairing.secret(ownEphemeral: device.ephemeral,
                                                    peerEphemeral: macHello.ephemeralKey,
                                                    transcript: transcript)
        XCTAssertEqual(macSecret, deviceSecret)
        XCTAssertEqual(macSecret.count, 32)
        XCTAssertEqual(RemotePairing.code(transcript: transcript).count, 6)
    }

    func testSubstitutedKeyChangesTranscriptAndCode() {
        let mac = Side(), device = Side(), attacker = Side()
        let (macHello, deviceHello) = hellos(mac: mac, device: device)
        var forged = deviceHello
        forged.signingKey = attacker.identity.publicKey
        forged.ephemeralKey = attacker.ephemeral.publicKey.rawRepresentation
        let honest = RemotePairing.transcript(mac: macHello, device: deviceHello)
        let tampered = RemotePairing.transcript(mac: macHello, device: forged)
        XCTAssertNotEqual(honest, tampered)
        var renamed = deviceHello
        renamed.name = "iPad 2"
        XCTAssertNotEqual(honest, RemotePairing.transcript(mac: macHello, device: renamed))
    }

    func testConfirmSignaturesVerifyOnlyForTheRightRoleKeyAndTranscript() throws {
        let mac = Side(), device = Side(), other = Side()
        let (macHello, deviceHello) = hellos(mac: mac, device: device)
        let transcript = RemotePairing.transcript(mac: macHello, device: deviceHello)
        let macConfirm = try roundTrip(
            RemotePairing.confirmMessage(.mac, transcript: transcript, identity: mac.identity))
        XCTAssertTrue(RemotePairing.verifyConfirm(macConfirm, from: .mac, transcript: transcript,
                                                  peerKey: mac.identity.publicKey))
        // Reflected back as if the device had signed it.
        XCTAssertFalse(RemotePairing.verifyConfirm(macConfirm, from: .device, transcript: transcript,
                                                   peerKey: mac.identity.publicKey))
        // Checked against a key that is not in the transcript.
        XCTAssertFalse(RemotePairing.verifyConfirm(macConfirm, from: .mac, transcript: transcript,
                                                   peerKey: other.identity.publicKey))
        // Replayed into another pairing.
        let (_, otherDevice) = hellos(mac: mac, device: other)
        let otherTranscript = RemotePairing.transcript(mac: macHello, device: otherDevice)
        XCTAssertFalse(RemotePairing.verifyConfirm(macConfirm, from: .mac, transcript: otherTranscript,
                                                   peerKey: mac.identity.publicKey))
    }

    // MARK: Session authentication

    func testAuthVerifiesForTheRightPeerOnly() throws {
        let mac = SoftwareIdentity(), device = SoftwareIdentity(), impostor = SoftwareIdentity()
        let pid = RemotePairing.newPSKIdentity()
        let exporter = RemoteCrypto.randomBytes(32)

        let deviceAuth = try roundTrip(RemoteAuth.message(.device, pskIdentity: pid, exporter: exporter,
                                                          identity: device))
        XCTAssertEqual(RemoteAuth.claimedPSKIdentity(deviceAuth), pid)
        XCTAssertTrue(RemoteAuth.verify(deviceAuth, from: .device, pskIdentity: pid, exporter: exporter,
                                        peerKey: device.publicKey))

        // A new machine with its own key cannot pass as the paired device.
        let forged = try roundTrip(RemoteAuth.message(.device, pskIdentity: pid, exporter: exporter,
                                                      identity: impostor))
        XCTAssertFalse(RemoteAuth.verify(forged, from: .device, pskIdentity: pid, exporter: exporter,
                                         peerKey: device.publicKey))

        // A signature from another TLS session (replay or relay) fails.
        XCTAssertFalse(RemoteAuth.verify(deviceAuth, from: .device, pskIdentity: pid,
                                         exporter: RemoteCrypto.randomBytes(32), peerKey: device.publicKey))

        // The Mac's answer cannot be reflected as the device's, or vice versa.
        let macAuth = try roundTrip(RemoteAuth.message(.mac, pskIdentity: pid, exporter: exporter,
                                                       identity: mac))
        XCTAssertTrue(RemoteAuth.verify(macAuth, from: .mac, pskIdentity: pid, exporter: exporter,
                                        peerKey: mac.publicKey))
        XCTAssertFalse(RemoteAuth.verify(deviceAuth, from: .mac, pskIdentity: pid, exporter: exporter,
                                         peerKey: device.publicKey))
    }

    func testAuthBoundToPSKIdentity() throws {
        let device = SoftwareIdentity()
        let pid = RemotePairing.newPSKIdentity(), otherPID = RemotePairing.newPSKIdentity()
        let exporter = RemoteCrypto.randomBytes(32)
        var auth = try RemoteAuth.message(.device, pskIdentity: pid, exporter: exporter, identity: device)
        auth["pid"] = otherPID
        XCTAssertFalse(RemoteAuth.verify(auth, from: .device, pskIdentity: otherPID, exporter: exporter,
                                         peerKey: device.publicKey))
    }

    func testAuthFrameFitsTheLimit() throws {
        let auth = try RemoteAuth.message(.device, pskIdentity: RemotePairing.newPSKIdentity(),
                                          exporter: RemoteCrypto.randomBytes(32), identity: SoftwareIdentity())
        let frame = try XCTUnwrap(RemoteAuth.frame(auth))
        XCTAssertLessThanOrEqual(frame.count - 4, RemoteWire.maxAuthFrame)
        let length = frame.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        XCTAssertEqual(length, frame.count - 4)
        XCTAssertEqual(frame[4], UInt8(ascii: "{"))
    }

    // MARK: Sealing

    func testSealedSecretOpensOnlyForItsIdentity() throws {
        let owner = SoftwareIdentity(), other = SoftwareIdentity()
        let secret = RemoteCrypto.randomBytes(32)
        let sealed = try owner.seal(secret)
        XCTAssertNotEqual(sealed, secret)
        XCTAssertEqual(try owner.open(sealed), secret)
        XCTAssertThrowsError(try other.open(sealed))
        var tampered = sealed
        tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try owner.open(tampered))
        XCTAssertThrowsError(try owner.open(Data(sealed.prefix(40))))
    }

    // MARK: Storage and identity

    func testFingerprintIsStableAndKeySpecific() {
        let a = SoftwareIdentity(), b = SoftwareIdentity()
        XCTAssertEqual(a.fingerprint, RemoteCrypto.fingerprint(of: a.publicKey))
        XCTAssertEqual(a.fingerprint.count, 32)
        XCTAssertNotEqual(a.fingerprint, b.fingerprint)
    }

    func testMergeReplacesSameKeyOrSamePSKIdentityOnly() {
        func peer(_ id: String, _ pid: String, _ name: String) -> RemotePeer {
            RemotePeer(id: id, name: name, publicKey: Data(), installID: nil, pskIdentity: pid,
                       sealedSecret: Data(), pairedAt: Date(timeIntervalSince1970: 0))
        }
        let a = peer("a", "p1", "A"), b = peer("b", "p2", "B")
        let rePairedA = peer("a", "p3", "A2")
        XCTAssertEqual(RemoteStore.merged([a, b], with: rePairedA), [b, rePairedA])
        let clash = peer("c", "p2", "C")
        XCTAssertEqual(RemoteStore.merged([a, b], with: clash), [a, clash])
    }

    func testHostUpdateVerifiesOnlyForTheSigningMac() throws {
        let mac = SoftwareIdentity(), other = SoftwareIdentity()
        func host(_ identity: SoftwareIdentity) -> RemoteHost {
            RemoteHost(id: identity.fingerprint, name: "Mac", publicKey: identity.publicKey,
                       pskIdentity: RemotePairing.newPSKIdentity(), sealedSecret: Data(),
                       addresses: [], port: 9010, pairedAt: Date())
        }
        let msg = try roundTrip(RemoteHostUpdate.message(identity: mac,
                                                         addresses: ["2a01:db8::1", "mac.example.net"],
                                                         port: 9011))
        let update = try XCTUnwrap(RemoteHostUpdate.parse(msg))
        XCTAssertEqual(update.fingerprint, mac.fingerprint)
        XCTAssertEqual(update.addresses, ["2a01:db8::1", "mac.example.net"])
        XCTAssertEqual(update.port, 9011)
        XCTAssertTrue(RemoteHostUpdate.verify(update, against: host(mac)))
        XCTAssertFalse(RemoteHostUpdate.verify(update, against: host(other)))
        var redirected = update
        redirected.addresses = ["attacker.example"]
        XCTAssertFalse(RemoteHostUpdate.verify(redirected, against: host(mac)))
        var unsigned = msg
        unsigned["sig"] = nil
        XCTAssertNil(RemoteHostUpdate.parse(unsigned))
    }

    func testCommitBindsTheMacHello() throws {
        let (macHello, _) = hellos(mac: Side(), device: Side())
        let commit = try XCTUnwrap(RemotePairing.parseCommit(try roundTrip(RemotePairing.commitMessage(macHello))))
        let revealed = try XCTUnwrap(RemotePairing.parseHello(try roundTrip(RemotePairing.helloMessage(macHello)),
                                                              from: .mac))
        XCTAssertEqual(RemotePairing.helloDigest(revealed, role: .mac), commit)
        var changed = revealed
        changed.ephemeralKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        XCTAssertNotEqual(RemotePairing.helloDigest(changed, role: .mac), commit)
        changed = revealed
        changed.name = "Other"
        XCTAssertNotEqual(RemotePairing.helloDigest(changed, role: .mac), commit)
    }

    func testNamesDropControlAndFormatCharacters() {
        XCTAssertEqual(RemotePairing.normalizedName("  iPad\u{202E}de Paul\n ", role: .device), "iPadde Paul")
        XCTAssertEqual(RemotePairing.normalizedName("\u{200F}\u{0007}", role: .mac), "Mac")
    }

    // MARK: Helpers

    private func roundTrip(_ message: [String: Any]) throws -> [String: Any] {
        let data = try JSONSerialization.data(withJSONObject: message)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}
