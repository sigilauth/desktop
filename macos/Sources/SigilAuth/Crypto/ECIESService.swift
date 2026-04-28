import Foundation
import CryptoKit

public enum ECIESError: Error {
    case keyGenerationFailed
    case encryptionFailed
    case decryptionFailed
    case invalidCiphertext
    case invalidPublicKey
    case invalidPrivateKey
    case keyAgreementFailed
}

public protocol ECIESService {
    func encrypt(plaintext: Data, recipientPublicKey: Data) throws -> Data
    func decrypt(ciphertext: Data, recipientPrivateKey: SecKey) throws -> Data
}

public struct DefaultECIESService: ECIESService {

    public init() {}

    public func encrypt(plaintext: Data, recipientPublicKey: Data) throws -> Data {
        guard recipientPublicKey.count == 33 else {
            throw ECIESError.invalidPublicKey
        }

        let recipientKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipientPublicKey)

        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey

        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientKey)

        let fingerprint = Data(SHA256.hash(data: recipientPublicKey))

        let derivedKey = try deriveAESKey(
            sharedSecret: sharedSecret.withUnsafeBytes { Data($0) },
            salt: fingerprint,
            info: "SIGIL-CONV-V1-AES256"
        )

        let nonce = try AES.GCM.Nonce()
        let ephemeralPubCompressed = ephemeralPublicKey.compressedRepresentation

        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: derivedKey),
            nonce: nonce,
            authenticating: ephemeralPubCompressed
        )

        var envelope = Data()
        envelope.append(ephemeralPubCompressed)
        envelope.append(nonce.withUnsafeBytes { Data($0) })
        envelope.append(sealedBox.ciphertext)
        envelope.append(sealedBox.tag)

        return envelope
    }

    public func decrypt(ciphertext: Data, recipientPrivateKey: SecKey) throws -> Data {
        guard ciphertext.count >= 33 + 12 + 16 else {
            throw ECIESError.invalidCiphertext
        }

        let ephemeralPubCompressed = ciphertext[0..<33]
        let nonceBytes = ciphertext[33..<45]
        let ciphertextBody = ciphertext[45..<(ciphertext.count - 16)]
        let tag = ciphertext[(ciphertext.count - 16)...]

        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPubCompressed)

        // Get recipient's public key for fingerprint
        guard let recipientPublicKeyRef = SecKeyCopyPublicKey(recipientPrivateKey),
              let recipientPublicKeyData = SecKeyCopyExternalRepresentation(recipientPublicKeyRef, nil) as Data? else {
            throw ECIESError.invalidPrivateKey
        }

        let recipientP256PublicKey = try P256.KeyAgreement.PublicKey(x963Representation: recipientPublicKeyData)
        let recipientPublicKey = recipientP256PublicKey.compressedRepresentation

        // Try Secure Enclave ECDH first (doesn't extract private key)
        // If that fails (e.g., software key), fall back to CryptoKit (for testing only)
        let sharedSecret: Data

        let ephemeralX963 = ephemeralPublicKey.x963Representation
        let ephemeralKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        var ephemeralError: Unmanaged<CFError>?
        if let ephemeralSecKey = SecKeyCreateWithData(
            ephemeralX963 as CFData,
            ephemeralKeyAttributes as CFDictionary,
            &ephemeralError
        ) {
            // Try ECDH via SecKey API (works with Secure Enclave keys)
            let ecdhParameters: [String: Any] = [:]
            var ecdhError: Unmanaged<CFError>?
            if let sharedSecretData = SecKeyCopyKeyExchangeResult(
                recipientPrivateKey,
                .ecdhKeyExchangeStandard,
                ephemeralSecKey,
                ecdhParameters as CFDictionary,
                &ecdhError
            ) as Data? {
                // Success via Secure Enclave path
                sharedSecret = sharedSecretData
            } else {
                // Fall back to CryptoKit (test keys only)
                guard let privateKeyData = SecKeyCopyExternalRepresentation(recipientPrivateKey, nil) as Data? else {
                    throw ECIESError.keyAgreementFailed
                }
                let recipientKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
                let ss = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
                sharedSecret = ss.withUnsafeBytes { Data($0) }
            }
        } else {
            // Fall back to CryptoKit (test keys only)
            guard let privateKeyData = SecKeyCopyExternalRepresentation(recipientPrivateKey, nil) as Data? else {
                throw ECIESError.keyAgreementFailed
            }
            let recipientKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let ss = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
            sharedSecret = ss.withUnsafeBytes { Data($0) }
        }

        let fingerprint = Data(SHA256.hash(data: recipientPublicKey))

        let derivedKey = try deriveAESKey(
            sharedSecret: sharedSecret,
            salt: fingerprint,
            info: "SIGIL-CONV-V1-AES256"
        )

        let nonce = try AES.GCM.Nonce(data: nonceBytes)

        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: ciphertextBody,
            tag: tag
        )

        let plaintext = try AES.GCM.open(
            sealedBox,
            using: SymmetricKey(data: derivedKey),
            authenticating: ephemeralPubCompressed
        )

        return plaintext
    }

    private func deriveAESKey(sharedSecret: Data, salt: Data, info: String) throws -> Data {
        let infoData = info.data(using: .utf8)!

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: infoData,
            outputByteCount: 32
        )

        return derivedKey.withUnsafeBytes { Data($0) }
    }
}
