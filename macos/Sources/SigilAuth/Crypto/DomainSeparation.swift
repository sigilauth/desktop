import Foundation
import CryptoKit

/// Domain separation tags for Sigil Auth signature operations
///
/// Per `api/domain-separation.md`, all signing operations MUST prepend a domain tag
/// to the message before hashing to prevent cross-protocol confusion attacks.
///
/// Each tag is a UTF-8 string with a trailing NUL byte (0x00).
public enum DomainTag {
    /// Authentication challenge/response signatures
    /// Tag: "SIGIL-AUTH-V1\0" (15 bytes)
    public static let auth: [UInt8] = Array("SIGIL-AUTH-V1\0".utf8)

    /// Multi-party authorization approval signatures
    /// Tag: "SIGIL-MPA-V1\0" (14 bytes)
    public static let mpa: [UInt8] = Array("SIGIL-MPA-V1\0".utf8)

    /// Secure decrypt envelope signatures
    /// Tag: "SIGIL-DECRYPT-V1\0" (18 bytes)
    public static let decrypt: [UInt8] = Array("SIGIL-DECRYPT-V1\0".utf8)

    /// Wire protocol conversation envelope signatures (SIGIL-CONV-V1)
    /// Tag: "SIGIL-CONV-V1\0" (14 bytes including NUL)
    /// Per api/wire-protocol.md §5.1 line 474
    public static let conv: [UInt8] = [
        0x53, 0x49, 0x47, 0x49, 0x4c, 0x2d, 0x43, 0x4f,
        0x4e, 0x56, 0x2d, 0x56, 0x31, 0x00
    ]

    /// Pair handshake session pictogram salt (SIGIL-PAIR-V1)
    /// Salt: "SIGIL-PAIR-V1\0\0\0" (16 bytes, zero-padded for Argon2id)
    /// Per api/wire-protocol.md §4.2
    public static let pairSalt: [UInt8] = [
        0x53, 0x49, 0x47, 0x49, 0x4c, 0x2d, 0x50, 0x41,
        0x49, 0x52, 0x2d, 0x56, 0x31, 0x00, 0x00, 0x00
    ]
}

/// Domain-separated signing and verification utilities
public enum DomainSeparatedSigning {
    /// Compute tagged message hash for domain-separated signatures
    ///
    /// - Parameters:
    ///   - message: Message bytes to sign
    ///   - domainTag: Domain tag bytes (must include trailing NUL)
    /// - Returns: SHA-256 hash of (domainTag || message)
    public static func taggedHash(message: Data, domainTag: [UInt8]) -> Data {
        var tagged = Data(domainTag)
        tagged.append(message)
        return Data(SHA256.hash(data: tagged))
    }

    /// Compute tagged hash for authentication flow (V1 with action_context binding)
    ///
    /// Per api/domain-separation.md V1 spec:
    /// - Signed payload: `challenge_bytes || SHA256(canonical_json(action_context))`
    /// - Domain tag: SIGIL-AUTH-V1\0
    ///
    /// - Parameters:
    ///   - challengeBytes: 32-byte authentication challenge
    ///   - actionContext: Optional action context dictionary (use nil for empty {})
    /// - Returns: SHA-256 hash of (SIGIL-AUTH-V1\0 || challenge || action_hash)
    /// - Throws: EncodingError if action_context is not encodable
    public static func authPayloadHash(challengeBytes: Data, actionContext: [String: Any]?) throws -> Data {
        // Compute action_context hash (or use fixed empty hash)
        let actionHash: Data
        if let context = actionContext, !context.isEmpty {
            actionHash = try CanonicalJSON.hash(context)
        } else {
            actionHash = CanonicalJSON.hashEmpty()
        }

        // Build auth payload: challenge_bytes || action_hash
        var payload = challengeBytes
        payload.append(actionHash)

        // Tag and hash: SHA256(SIGIL-AUTH-V1\0 || payload)
        return taggedHash(message: payload, domainTag: DomainTag.auth)
    }

    /// Verify that a tag is a recognized Sigil Auth domain tag
    ///
    /// - Parameter tag: Tag bytes to verify
    /// - Returns: True if tag is one of the normative tags
    public static func isValidTag(_ tag: [UInt8]) -> Bool {
        return tag == DomainTag.auth || tag == DomainTag.mpa || tag == DomainTag.decrypt || tag == DomainTag.conv
    }
}
