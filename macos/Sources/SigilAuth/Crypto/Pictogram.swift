import Foundation
import CryptoKit

/// Pictogram derived from device fingerprint for verbal verification
///
/// Per protocol-spec §3.6: Derives 5 emoji names from the first 30 bits of a SHA-256 fingerprint.
/// Uses 6-bit indexing (64 possible emojis) for each of 5 positions.
///
/// ## Decision D10 Compliance
/// - JSON field name: `pictogram_speakable`
/// - JSON format: space-separated (e.g., "apple banana plane car dog")
/// - URL query format: hyphen-separated (e.g., `pictogram=apple-banana-plane-car-dog`)
public struct Pictogram: Equatable, Codable {

    /// 5 indices into the emoji list (0-63)
    public let indices: [Int]

    /// 5 emoji names in order
    public let names: [String]

    /// Space-separated speakable form per D10 (for JSON payloads)
    public var speakable: String {
        names.joined(separator: " ")
    }

    /// Hyphen-separated URL-safe form per D10 (for query parameters)
    public var urlSafeForm: String {
        names.joined(separator: "-")
    }

    /// Canonical emoji name list (64 entries, 6-bit indexing)
    ///
    /// Order matches /api/test-vectors/pictogram.json
    /// Categories: fruits (0-7), vegetables (8-15), food (16-23), transport (24-31),
    ///             animals (32-39), nature (40-47), places (48-55), objects (56-63)
    public static let emojiNames: [String] = [
        // Fruits (0-7)
        "apple", "banana", "grapes", "orange", "lemon", "cherry", "strawberry", "kiwi",
        // Vegetables (8-15)
        "carrot", "corn", "broccoli", "mushroom", "pepper", "avocado", "onion", "peanut",
        // Food (16-23)
        "pizza", "burger", "taco", "donut", "cookie", "cake", "cupcake", "popcorn",
        // Transport (24-31)
        "car", "taxi", "bus", "rocket", "plane", "helicopter", "sailboat", "bicycle",
        // Animals (32-39)
        "dog", "cat", "fish", "butterfly", "bee", "fox", "lion", "elephant",
        // Nature (40-47)
        "tree", "sunflower", "cactus", "clover", "blossom", "rainbow", "star", "moon",
        // Places (48-55)
        "house", "mountain", "peak", "volcano", "island", "moai", "tent", "castle",
        // Objects (56-63)
        "key", "bell", "books", "guitar", "anchor", "crown", "diamond", "fire"
    ]

    // MARK: - Initialization

    private init(indices: [Int]) {
        precondition(indices.count == 5, "Pictogram must have exactly 5 indices")
        precondition(indices.allSatisfy { $0 >= 0 && $0 < 64 }, "Indices must be in range 0-63")

        self.indices = indices
        self.names = indices.map { Self.emojiNames[$0] }
    }

    // MARK: - Derivation

    /// Derive pictogram from device fingerprint
    ///
    /// Algorithm per protocol-spec §3.6:
    /// 1. Take first 4 bytes of fingerprint (SHA-256 hash of public key)
    /// 2. Extract 5 x 6-bit indices from first 30 bits
    /// 3. Map each index to emoji name
    ///
    /// - Parameter fingerprint: Device fingerprint (SHA-256 of compressed public key)
    /// - Returns: Pictogram with 5 emoji indices and names
    public static func derive(from fingerprint: Data) -> Pictogram {
        precondition(fingerprint.count >= 4, "Fingerprint must be at least 4 bytes")

        // Extract first 4 bytes
        let bytes = Array(fingerprint.prefix(4))

        // Combine into 32-bit value (big-endian)
        let value = UInt32(bytes[0]) << 24 |
                    UInt32(bytes[1]) << 16 |
                    UInt32(bytes[2]) << 8 |
                    UInt32(bytes[3])

        // Extract 5 x 6-bit indices from first 30 bits
        var indices: [Int] = []
        var remaining = value

        for _ in 0..<5 {
            // Extract top 6 bits
            let index = Int((remaining >> 26) & 0x3F) // 0x3F = 0b111111 (6 bits)
            indices.append(index)

            // Shift left 6 bits
            remaining <<= 6
        }

        return Pictogram(indices: indices)
    }

    /// Derive pictogram from device public key
    ///
    /// Convenience method: hashes public key to fingerprint then derives pictogram
    ///
    /// - Parameter publicKey: Compressed P-256 public key (33 bytes)
    /// - Returns: Pictogram derived from SHA-256(publicKey)
    public static func derive(fromPublicKey publicKey: Data) -> Pictogram {
        let fingerprint = SHA256.hash(data: publicKey)
        return derive(from: Data(fingerprint))
    }

    // MARK: - Codable

    enum CodingKeys: String, CodingKey {
        case pictogramSpeakable = "pictogram_speakable"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let speakableString = try container.decode(String.self, forKey: .pictogramSpeakable)

        let names = speakableString.split(separator: " ").map(String.init)
        guard names.count == 5 else {
            throw DecodingError.dataCorruptedError(
                forKey: .pictogramSpeakable,
                in: container,
                debugDescription: "Expected 5 space-separated emoji names, got \(names.count)"
            )
        }

        var indices: [Int] = []
        for name in names {
            guard let index = Self.emojiNames.firstIndex(of: name) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .pictogramSpeakable,
                    in: container,
                    debugDescription: "Unknown emoji name: \(name)"
                )
            }
            indices.append(index)
        }

        self.init(indices: indices)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(speakable, forKey: .pictogramSpeakable)
    }
}

// MARK: - CustomStringConvertible

extension Pictogram: CustomStringConvertible {
    public var description: String {
        "Pictogram(\(speakable))"
    }
}

// MARK: - Accessibility

extension Pictogram {
    /// VoiceOver-friendly description
    ///
    /// Per Aria §3.2: Screen reader announces as comma-separated list
    /// Example: "Device pictogram: apple, banana, plane, car, dog"
    public var accessibilityLabel: String {
        "Device pictogram: \(names.joined(separator: ", "))"
    }
}
