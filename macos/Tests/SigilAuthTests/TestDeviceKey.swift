import Foundation
import CryptoKit
@testable import SigilAuth

/// Software-based device key for testing
///
/// Secure Enclave is not available in test environments, so tests use
/// a software P-256 key that implements the same interface.
final class TestDeviceKey: DeviceSigningKey {
    let privateKey: P256.Signing.PrivateKey
    let publicKey: Data
    let fingerprint: Data

    init() throws {
        privateKey = P256.Signing.PrivateKey()

        // Export public key in compressed format (33 bytes)
        let rawPublicKey = privateKey.publicKey.x963Representation
        guard rawPublicKey.count == 65, rawPublicKey.first == 0x04 else {
            throw TestKeyError.invalidPublicKey
        }

        let x = rawPublicKey[1...32]
        let y = rawPublicKey[33...64]

        // Compress: 0x02/0x03 prefix + X coordinate
        let prefix: UInt8 = (y.last! & 1) == 0 ? 0x02 : 0x03
        var compressed = Data([prefix])
        compressed.append(x)

        publicKey = compressed
        fingerprint = Data(SHA256.hash(data: publicKey))
    }

    func sign(_ data: Data, reason: String = "Test signing") async throws -> Data {
        let signature = try privateKey.signature(for: data)

        // Use raw representation (r || s, 64 bytes) instead of DER
        let rawSignature = signature.rawRepresentation

        // Apply low-S normalization per BIP-62 (same as SecureEnclaveKey)
        return try SecureEnclaveKey.normalizeLowS(rawSignature)
    }
}

enum TestKeyError: Error {
    case invalidPublicKey
}
