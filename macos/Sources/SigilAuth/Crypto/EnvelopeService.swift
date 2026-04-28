import Foundation
import CryptoKit

public struct EnvelopePayload {
    public let action: String
    public let body: [String: Any]
    public let timestamp: Int64
    public let nonce: String
    public let audience: String?

    public init(action: String, body: [String: Any] = [:], timestamp: Int64, nonce: String, audience: String?) {
        self.action = action
        self.body = body
        self.timestamp = timestamp
        self.nonce = nonce
        self.audience = audience
    }

    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "action": action,
            "body": body,
            "timestamp": timestamp,
            "nonce": nonce
        ]
        if let audience = audience {
            dict["audience"] = audience
        }
        return dict
    }
}

public struct OuterEnvelope: Codable {
    public let envelope: String
}

public enum EnvelopeError: Error {
    case canonicalizationFailed
    case signingFailed
    case encryptionFailed
    case decryptionFailed
    case signatureVerificationFailed
    case timestampExpired
    case nonceReused
    case audienceMismatch
    case invalidFormat
}

public protocol EnvelopeService {
    func createRequest(
        payload: EnvelopePayload,
        clientPrivateKey: SecKey,
        clientPublicKey: Data,
        serverPublicKey: Data
    ) throws -> Data

    func verifyResponse(
        envelopeData: Data,
        serverPublicKey: Data,
        clientPrivateKey: SecKey
    ) throws -> [String: Any]
}

public struct DefaultEnvelopeService: EnvelopeService {

    private let ecies: ECIESService
    private let nonceStore: NonceStore

    public init(ecies: ECIESService = DefaultECIESService(), nonceStore: NonceStore = MemoryNonceStore()) {
        self.ecies = ecies
        self.nonceStore = nonceStore
    }

    public func createRequest(
        payload: EnvelopePayload,
        clientPrivateKey: SecKey,
        clientPublicKey: Data,
        serverPublicKey: Data
    ) throws -> Data {
        let payloadDict = payload.toDictionary()
        let canonicalPayload = try CanonicalJSON.encode(payloadDict)

        let signature = try signPayload(
            canonicalPayload,
            privateKey: clientPrivateKey,
            domain: DomainTag.conv
        )

        let innerDict: [String: Any] = [
            "client_public_key": clientPublicKey.base64EncodedString(),
            "payload": String(data: canonicalPayload, encoding: .utf8)!,
            "signature": signature.base64EncodedString()
        ]

        let innerJSON = try CanonicalJSON.encode(innerDict)

        let outerCiphertext = try ecies.encrypt(plaintext: innerJSON, recipientPublicKey: serverPublicKey)

        let outerDict: [String: Any] = [
            "envelope": outerCiphertext.base64EncodedString()
        ]

        return try JSONSerialization.data(withJSONObject: outerDict)
    }

    public func verifyResponse(
        envelopeData: Data,
        serverPublicKey: Data,
        clientPrivateKey: SecKey
    ) throws -> [String: Any] {
        guard let outerDict = try? JSONSerialization.jsonObject(with: envelopeData) as? [String: Any],
              let envelopeB64 = outerDict["envelope"] as? String,
              let outerCiphertext = Data(base64Encoded: envelopeB64) else {
            throw EnvelopeError.invalidFormat
        }

        let innerJSON = try ecies.decrypt(ciphertext: outerCiphertext, recipientPrivateKey: clientPrivateKey)

        guard let innerDict = try? JSONSerialization.jsonObject(with: innerJSON) as? [String: Any],
              let serverPubB64 = innerDict["server_public_key"] as? String,
              let payloadStr = innerDict["payload"] as? String,
              let signatureB64 = innerDict["signature"] as? String,
              let serverPubDecoded = Data(base64Encoded: serverPubB64),
              let payloadData = payloadStr.data(using: .utf8),
              let signature = Data(base64Encoded: signatureB64) else {
            throw EnvelopeError.invalidFormat
        }

        guard serverPubDecoded == serverPublicKey else {
            throw EnvelopeError.signatureVerificationFailed
        }

        let isValid = try verifySignature(
            signature,
            for: payloadData,
            domain: DomainTag.conv,
            publicKey: serverPublicKey
        )

        guard isValid else {
            throw EnvelopeError.signatureVerificationFailed
        }

        guard let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw EnvelopeError.invalidFormat
        }

        if let timestamp = payload["timestamp"] as? Int64 {
            let now = Int64(Date().timeIntervalSince1970)
            guard abs(now - timestamp) <= 300 else {
                throw EnvelopeError.timestampExpired
            }
        }

        // Check nonce for replay protection (per wire-protocol.md §6.2, §5.4)
        if let nonce = payload["nonce"] as? String {
            guard nonceStore.checkAndMarkNonce(nonce) else {
                throw EnvelopeError.nonceReused
            }
        }

        return payload
    }

    private func signPayload(_ payload: Data, privateKey: SecKey, domain: [UInt8]) throws -> Data {
        var tagged = Data(domain)
        tagged.append(payload)

        let digest = Data(SHA256.hash(data: tagged))

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            throw EnvelopeError.signingFailed
        }

        return try convertDERToRaw(signature)
    }

    private func verifySignature(
        _ signature: Data,
        for payload: Data,
        domain: [UInt8],
        publicKey: Data
    ) throws -> Bool {
        guard publicKey.count == 33 else {
            return false
        }

        guard signature.count == 64 else {
            return false
        }

        let s = signature[32..<64]
        let normalizedS = try normalizeLowS(Data(s))

        guard s == normalizedS else {
            return false
        }

        let p256PublicKey = try P256.Signing.PublicKey(compressedRepresentation: publicKey)

        var tagged = Data(domain)
        tagged.append(payload)

        let digest = Data(SHA256.hash(data: tagged))

        let derSignature = try convertRawToDER(signature)

        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: derSignature)

        return p256PublicKey.isValidSignature(ecdsaSignature, for: digest)
    }

    private func convertDERToRaw(_ der: Data) throws -> Data {
        guard der.count >= 8 else {
            throw EnvelopeError.signingFailed
        }

        var index = 0

        guard der[index] == 0x30 else {
            throw EnvelopeError.signingFailed
        }
        index += 1

        let _ = der[index]
        index += 1

        guard der[index] == 0x02 else {
            throw EnvelopeError.signingFailed
        }
        index += 1

        let rLength = Int(der[index])
        index += 1

        var r = der[index..<(index + rLength)]
        index += rLength

        while r.count > 32 && r.first == 0x00 {
            r = r.dropFirst()
        }
        while r.count < 32 {
            r = Data([0x00]) + r
        }

        guard der[index] == 0x02 else {
            throw EnvelopeError.signingFailed
        }
        index += 1

        let sLength = Int(der[index])
        index += 1

        var s = der[index..<(index + sLength)]

        while s.count > 32 && s.first == 0x00 {
            s = s.dropFirst()
        }
        while s.count < 32 {
            s = Data([0x00]) + s
        }

        let normalizedS = try normalizeLowS(Data(s))

        return r + normalizedS
    }

    private func normalizeLowS(_ s: Data) throws -> Data {
        guard s.count == 32 else {
            throw EnvelopeError.signingFailed
        }

        let curveOrder: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
        ]

        let halfOrder: [UInt8] = [
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
            0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8
        ]

        let sBytes = [UInt8](s)

        for i in 0..<32 {
            if sBytes[i] < halfOrder[i] {
                return s
            } else if sBytes[i] > halfOrder[i] {
                var result = [UInt8](repeating: 0, count: 32)
                var borrow: UInt16 = 0

                for j in stride(from: 31, through: 0, by: -1) {
                    let diff = UInt16(curveOrder[j]) - UInt16(sBytes[j]) - borrow
                    result[j] = UInt8(diff & 0xFF)
                    borrow = (diff >> 8) & 1
                }

                return Data(result)
            }
        }

        return s
    }

    private func convertRawToDER(_ raw: Data) throws -> Data {
        guard raw.count == 64 else {
            throw EnvelopeError.signatureVerificationFailed
        }

        var r = raw[0..<32]
        var s = raw[32..<64]

        while r.count > 1 && r.first == 0x00 && r[1] < 0x80 {
            r = r.dropFirst()
        }
        if r.first! >= 0x80 {
            r = Data([0x00]) + r
        }

        while s.count > 1 && s.first == 0x00 && s[1] < 0x80 {
            s = s.dropFirst()
        }
        if s.first! >= 0x80 {
            s = Data([0x00]) + s
        }

        var der = Data()
        der.append(0x30)
        der.append(UInt8(4 + r.count + s.count))
        der.append(0x02)
        der.append(UInt8(r.count))
        der.append(r)
        der.append(0x02)
        der.append(UInt8(s.count))
        der.append(s)

        return der
    }
}
