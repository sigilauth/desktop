import XCTest
import CryptoKit
@testable import SigilAuth

final class SessionPictogramTests: XCTestCase {

    func testSessionPictogramDerivation() throws {
        let serverPrivateKey = P256.KeyAgreement.PrivateKey()
        let serverPublicKey = serverPrivateKey.publicKey.compressedRepresentation

        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        let clientPublicKey = clientPrivateKey.publicKey.compressedRepresentation

        var serverNonce = Data(count: 32)
        _ = serverNonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let derivation = SessionPictogramDerivation()

        let pictogram = try derivation.derive(
            serverPublicKey: serverPublicKey,
            clientPublicKey: clientPublicKey,
            serverNonce: serverNonce
        )

        XCTAssertEqual(pictogram.emojis.count, 6)
        XCTAssertEqual(pictogram.names.count, 6)
        XCTAssertFalse(pictogram.speakable.isEmpty)

        print("Session pictogram: \(pictogram.emojis.joined(separator: " "))")
        print("Speakable: \(pictogram.speakable)")
    }

    func testDeterministicPictogram() throws {
        let serverPub = Data(repeating: 0x02, count: 33)
        let clientPub = Data(repeating: 0x03, count: 33)
        let nonce = Data(repeating: 0x01, count: 32)

        let derivation = SessionPictogramDerivation()

        let pictogram1 = try derivation.derive(
            serverPublicKey: serverPub,
            clientPublicKey: clientPub,
            serverNonce: nonce
        )

        let pictogram2 = try derivation.derive(
            serverPublicKey: serverPub,
            clientPublicKey: clientPub,
            serverNonce: nonce
        )

        XCTAssertEqual(pictogram1.emojis, pictogram2.emojis)
        XCTAssertEqual(pictogram1.speakable, pictogram2.speakable)
    }
}
