import XCTest
import CryptoKit
@testable import SigilAuth

final class EnvelopeTests: XCTestCase {


    func testEnvelopeCreation() throws {
        let ecies = DefaultECIESService()
        let envelope = DefaultEnvelopeService(ecies: ecies)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]

        var error: Unmanaged<CFError>?
        guard let clientPrivateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let serverPrivateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        guard let clientPublicKeyRef = SecKeyCopyPublicKey(clientPrivateKey),
              let serverPublicKeyRef = SecKeyCopyPublicKey(serverPrivateKey),
              let clientPublicKeyUncompressed = SecKeyCopyExternalRepresentation(clientPublicKeyRef, &error) as Data?,
              let serverPublicKeyUncompressed = SecKeyCopyExternalRepresentation(serverPublicKeyRef, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        let clientP256 = try P256.KeyAgreement.PublicKey(x963Representation: clientPublicKeyUncompressed)
        let serverP256 = try P256.KeyAgreement.PublicKey(x963Representation: serverPublicKeyUncompressed)
        let clientPublicKey = clientP256.compressedRepresentation
        let serverPublicKey = serverP256.compressedRepresentation

        let payload = EnvelopePayload(
            action: "test.action",
            body: ["data": "test"],
            timestamp: Int64(Date().timeIntervalSince1970),
            nonce: UUID().uuidString.replacingOccurrences(of: "-", with: ""),
            audience: serverPublicKey.sha256().hexString
        )

        let requestData = try envelope.createRequest(
            payload: payload,
            clientPrivateKey: clientPrivateKey,
            clientPublicKey: clientPublicKey,
            serverPublicKey: serverPublicKey
        )

        XCTAssertGreaterThan(requestData.count, 100)

        let outerDict = try JSONSerialization.jsonObject(with: requestData) as? [String: Any]
        XCTAssertNotNil(outerDict)
        XCTAssertNotNil(outerDict?["envelope"] as? String)
    }
}

extension Data {
    func sha256() -> Data {
        return Data(SHA256.hash(data: self))
    }

    var hexString: String {
        return map { String(format: "%02x", $0) }.joined()
    }
}
