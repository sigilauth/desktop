import Foundation

/// RFC 8785 canonical JSON encoding
///
/// Produces deterministic byte-identical JSON representation:
/// - Sorted object keys
/// - No whitespace
/// - Minimal number encoding
/// - UTF-8 encoding
///
/// Used for cryptographic binding of action_context in signatures.
public enum CanonicalJSON {
    /// Encode dictionary to RFC 8785 canonical JSON
    ///
    /// - Parameter value: Dictionary to encode
    /// - Returns: Canonical JSON data
    /// - Throws: EncodingError if value is not encodable
    public static func encode(_ value: [String: Any]) throws -> Data {
        // Use JSONSerialization with sorted keys + no pretty print
        let options: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]
        return try JSONSerialization.data(withJSONObject: value, options: options)
    }

    /// Encode empty action context (canonical "{}")
    ///
    /// - Returns: Data containing exactly "{}" (2 bytes)
    public static func encodeEmpty() -> Data {
        return Data([0x7b, 0x7d]) // "{}"
    }

    /// Compute SHA-256 hash of canonical JSON
    ///
    /// - Parameter value: Dictionary to canonicalize and hash
    /// - Returns: 32-byte SHA-256 hash
    /// - Throws: EncodingError if value is not encodable
    public static func hash(_ value: [String: Any]) throws -> Data {
        let canonical = try encode(value)
        return Data(SHA256.hash(data: canonical))
    }

    /// Compute SHA-256 hash of empty action context
    ///
    /// Returns the fixed hash value: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
    ///
    /// - Returns: 32-byte SHA-256 hash of "{}"
    public static func hashEmpty() -> Data {
        return Data(SHA256.hash(data: encodeEmpty()))
    }
}

// MARK: - CryptoKit Import

import CryptoKit
