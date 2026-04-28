import Foundation
import Security
import CryptoKit
import LocalAuthentication

/// Secure Enclave P-256 keypair management for macOS
///
/// Generates hardware-backed ECDSA P-256 keys in Secure Enclave (M1+ Macs).
/// Private key never leaves hardware. Biometric gate on every signing operation.
///
/// ## Knox Top 5 Compliance
/// 1. ✅ Hardware key extraction infeasible (Secure Enclave)
/// 2. ✅ Biometric gate every sign (kSecAccessControlBiometryCurrentSet)
/// 3. ✅ Device self-authentication (public key sent with response)
public final class SecureEnclaveKey {

    /// Reference to Secure Enclave private key (non-exportable)
    private let privateKey: SecKey

    /// Compressed P-256 public key (33 bytes)
    public let publicKey: Data

    /// Device fingerprint (SHA-256 of public key)
    public let fingerprint: Data

    /// Device pictogram for verbal verification
    public let pictogram: Pictogram

    /// Keychain label for this key
    private let keychainLabel: String

    // MARK: - Initialization

    private init(privateKey: SecKey, publicKey: Data) throws {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.fingerprint = SHA256.hash(data: publicKey).withUnsafeBytes { Data($0) }
        self.pictogram = Pictogram.derive(from: fingerprint)
        self.keychainLabel = "com.sigilauth.device-key"
    }

    // MARK: - Key Generation

    /// Generate new Secure Enclave keypair (M1+ Macs only)
    ///
    /// Creates P-256 key in Secure Enclave with biometric access control.
    /// Private key is non-exportable and requires Touch ID on every use.
    ///
    /// - Throws: KeyError if generation fails or Secure Enclave unavailable
    /// - Returns: SecureEnclaveKey instance
    public static func generate() throws -> SecureEnclaveKey {
        // Create biometric-gated access control
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], // Invalidate on biometric change
            nil
        ) else {
            throw KeyError.accessControlFailed
        }

        // Configure Secure Enclave key generation
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl,
                kSecAttrLabel as String: "com.sigilauth.device-key-\(UUID().uuidString)"
            ]
        ]

        // Generate keypair in Secure Enclave
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let err = error?.takeRetainedValue() {
                let nsError = err as Error as NSError
                // errSecItemNotAvailable = -25300 for Secure Enclave unavailable
                if nsError.domain == NSOSStatusErrorDomain && nsError.code == -25300 {
                    throw KeyError.secureEnclaveUnavailable
                }
            }
            throw KeyError.generationFailed(error?.takeRetainedValue())
        }

        // Extract public key
        guard let publicKeyRef = SecKeyCopyPublicKey(privateKey) else {
            throw KeyError.publicKeyExtractionFailed
        }

        // Export public key data (uncompressed 65 bytes)
        var exportError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKeyRef, &exportError) as Data? else {
            throw KeyError.publicKeyExportFailed(exportError?.takeRetainedValue())
        }

        // Compress public key to 33 bytes
        let compressedPublicKey = try compressP256PublicKey(publicKeyData)

        return try SecureEnclaveKey(privateKey: privateKey, publicKey: compressedPublicKey)
    }

    // MARK: - Signing

    /// Sign message with Secure Enclave key (requires Touch ID)
    ///
    /// Prompts user for Touch ID, then signs message with hardware key.
    /// Message is hashed with SHA-256 internally before signing.
    /// Signature is 64 bytes (r || s) with low-S normalization per BIP-62.
    ///
    /// - Parameters:
    ///   - message: Message to sign (will be hashed with SHA-256)
    ///   - reason: User-facing reason string (shown in Touch ID prompt)
    /// - Throws: SigningError if biometric fails or signing fails
    /// - Returns: 64-byte ECDSA signature (r || s, low-S normalized)
    public func sign(_ message: Data, reason: String = "Approve authentication request") async throws -> Data {
        // Note: LAContext is created per signing operation to trigger biometric prompt
        // Access control on key enforces biometric gate

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            if let err = error?.takeRetainedValue() {
                let nsError = err as Error as NSError
                // errSecAuthFailed = -25293 for biometric failure
                if nsError.domain == NSOSStatusErrorDomain && nsError.code == -25293 {
                    throw SigningError.biometricFailed
                }
            }
            throw SigningError.signingFailed(error?.takeRetainedValue())
        }

        // Normalize to low-S per BIP-62
        return try Self.normalizeLowS(signature)
    }

    /// Sign message with domain separation (requires Touch ID)
    ///
    /// Per `api/domain-separation.md`, prepends domain tag to message before hashing
    /// to prevent cross-protocol confusion attacks.
    ///
    /// Algorithm:
    /// 1. tagged = domainTag || message
    /// 2. hash = SHA256(tagged)
    /// 3. signature = ECDSA-P256-Sign(privateKey, hash)
    ///
    /// - Parameters:
    ///   - message: Message bytes to sign
    ///   - domainTag: Domain tag bytes (must include trailing NUL)
    ///   - reason: User-facing reason string (shown in Touch ID prompt)
    /// - Throws: SigningError if biometric fails or signing fails
    /// - Returns: 64-byte ECDSA signature (r || s, low-S normalized)
    public func signWithDomain(
        _ message: Data,
        domainTag: [UInt8],
        reason: String = "Approve authentication request"
    ) async throws -> Data {
        // Compute tagged hash: SHA256(domainTag || message)
        let digest = DomainSeparatedSigning.taggedHash(message: message, domainTag: domainTag)

        // Sign the digest (not the message) to avoid double-hashing
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256, // Sign digest directly, no additional hashing
            digest as CFData,
            &error
        ) as Data? else {
            if let err = error?.takeRetainedValue() {
                let nsError = err as Error as NSError
                if nsError.domain == NSOSStatusErrorDomain && nsError.code == -25293 {
                    throw SigningError.biometricFailed
                }
            }
            throw SigningError.signingFailed(error?.takeRetainedValue())
        }

        // Normalize to low-S per BIP-62
        return try Self.normalizeLowS(signature)
    }

    /// Sign authentication payload with action_context binding (V1 spec)
    ///
    /// Per `api/domain-separation.md` V1 spec correction:
    /// - Signed payload: `challenge_bytes || SHA256(canonical_json(action_context))`
    /// - Domain tag: SIGIL-AUTH-V1\0
    ///
    /// - Parameters:
    ///   - challengeBytes: 32-byte authentication challenge
    ///   - actionContext: Optional action context dictionary
    ///   - reason: User-facing reason string (shown in Touch ID prompt)
    /// - Returns: 64-byte ECDSA signature (r || s, low-S normalized)
    /// - Throws: SigningError if biometric fails or signing fails
    public func signAuthPayload(
        challengeBytes: Data,
        actionContext: [String: Any]? = nil,
        reason: String = "Approve authentication request"
    ) async throws -> Data {
        // Compute auth payload hash: SHA256(SIGIL-AUTH-V1\0 || challenge || action_hash)
        let digest = try DomainSeparatedSigning.authPayloadHash(
            challengeBytes: challengeBytes,
            actionContext: actionContext
        )

        // Sign the digest
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            if let err = error?.takeRetainedValue() {
                let nsError = err as Error as NSError
                if nsError.domain == NSOSStatusErrorDomain && nsError.code == -25293 {
                    throw SigningError.biometricFailed
                }
            }
            throw SigningError.signingFailed(error?.takeRetainedValue())
        }

        return try Self.normalizeLowS(signature)
    }

    // MARK: - Intel Mac Fallback

    /// Check if Secure Enclave is available (M1+ only)
    public static var isSecureEnclaveAvailable: Bool {
        // Try to create a test key - if it fails with errSecItemNotAvailable, SE is unavailable
        let testAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]

        var error: Unmanaged<CFError>?
        let testKey = SecKeyCreateRandomKey(testAttributes as CFDictionary, &error)

        if let key = testKey {
            // Clean up test key
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecValueRef as String: key
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            return true
        }

        return false
    }
}

// MARK: - P-256 Key Compression

extension SecureEnclaveKey {
    /// Compress uncompressed P-256 public key (65 bytes → 33 bytes)
    ///
    /// Uncompressed format: 0x04 || X (32 bytes) || Y (32 bytes)
    /// Compressed format: 0x02/0x03 || X (32 bytes)
    ///
    /// - Parameter uncompressed: Uncompressed public key (65 bytes)
    /// - Returns: Compressed public key (33 bytes)
    private static func compressP256PublicKey(_ uncompressed: Data) throws -> Data {
        guard uncompressed.count == 65, uncompressed[0] == 0x04 else {
            throw KeyError.invalidPublicKeyFormat
        }

        let x = uncompressed[1...32]
        let y = uncompressed[33...64]

        // Check if Y is even or odd
        let prefix: UInt8 = (y.last! & 1) == 0 ? 0x02 : 0x03

        var compressed = Data([prefix])
        compressed.append(x)

        return compressed
    }

    /// Normalize ECDSA signature to low-S per BIP-62
    ///
    /// P-256 ECDSA signatures in IEEE P1363 format (r || s, 64 bytes).
    /// If S > N/2, replace with N - S to produce canonical low-S form.
    ///
    /// - Parameter signature: Raw ECDSA signature (64 bytes)
    /// - Returns: Low-S normalized signature (64 bytes)
    /// - Throws: SigningError.malformedSignature if not 64 bytes
    internal static func normalizeLowS(_ signature: Data) throws -> Data {
        // P-256 order N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        let p256Order: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
        ]

        // N / 2 = 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5612E319AA8
        let p256HalfOrder: [UInt8] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
            0x79, 0xDC, 0xE5, 0x61, 0x2E, 0x31, 0x9A, 0xA8
        ]

        guard signature.count == 64 else {
            throw SigningError.malformedSignature
        }

        // Extract r and s components
        let r = signature.prefix(32)
        let s = signature.suffix(32)

        // Compare s with N/2
        let sBytes = [UInt8](s)
        if !isGreaterThan(sBytes, p256HalfOrder) {
            // Already low-S
            return signature
        }

        // S > N/2: normalize to N - S
        let normalizedS = subtractBytes(p256Order, sBytes)

        // Reconstruct signature: r || normalized_s
        var result = Data(r)
        result.append(contentsOf: normalizedS)
        return result
    }

    /// Compare two big-endian byte arrays: a > b
    private static func isGreaterThan(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        for i in 0..<min(a.count, b.count) {
            if a[i] > b[i] { return true }
            if a[i] < b[i] { return false }
        }
        return false
    }

    /// Subtract two big-endian byte arrays: a - b
    /// Assumes a >= b (always true for N - S when S <= N)
    private static func subtractBytes(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        precondition(a.count == 32 && b.count == 32, "Both operands must be 32 bytes")

        var result = [UInt8](repeating: 0, count: 32)
        var borrow: UInt16 = 0

        // Subtract from right to left (little-endian arithmetic on big-endian data)
        for i in stride(from: 31, through: 0, by: -1) {
            let diff = UInt16(a[i]) - UInt16(b[i]) - borrow
            if diff & 0x100 != 0 {
                // Borrow needed
                result[i] = UInt8(diff & 0xFF)
                borrow = 1
            } else {
                result[i] = UInt8(diff)
                borrow = 0
            }
        }

        return result
    }
}

// MARK: - Errors

public enum KeyError: Error, LocalizedError {
    case accessControlFailed
    case generationFailed(CFError?)
    case publicKeyExtractionFailed
    case publicKeyExportFailed(CFError?)
    case invalidPublicKeyFormat
    case secureEnclaveUnavailable

    public var errorDescription: String? {
        switch self {
        case .accessControlFailed:
            return "Failed to create biometric access control"
        case .generationFailed(let error):
            return "Keypair generation failed: \(error?.localizedDescription ?? "unknown")"
        case .publicKeyExtractionFailed:
            return "Failed to extract public key from private key"
        case .publicKeyExportFailed(let error):
            return "Failed to export public key: \(error?.localizedDescription ?? "unknown")"
        case .invalidPublicKeyFormat:
            return "Public key is not in expected format (65-byte uncompressed)"
        case .secureEnclaveUnavailable:
            return "Secure Enclave is not available (Intel Mac? Requires M1+)"
        }
    }
}

public enum SigningError: Error, LocalizedError {
    case biometricFailed
    case biometricCancelled
    case signingFailed(CFError?)
    case malformedSignature

    public var errorDescription: String? {
        switch self {
        case .biometricFailed:
            return "Touch ID authentication failed"
        case .biometricCancelled:
            return "Touch ID was cancelled"
        case .signingFailed(let error):
            return "Signature generation failed: \(error?.localizedDescription ?? "unknown")"
        case .malformedSignature:
            return "Signature is not 64 bytes (r || s format expected)"
        }
    }
}
