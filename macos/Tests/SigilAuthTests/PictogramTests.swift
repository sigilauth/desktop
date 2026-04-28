import XCTest
@testable import SigilAuth

/// Tests for pictogram derivation from device fingerprint
/// Test vectors from /api/test-vectors/pictogram.json
final class PictogramTests: XCTestCase {

    struct TestVector: Codable {
        let name: String
        let fingerprintHex: String
        let indices: [Int]
        let expectedPictogram: [String]
        let expectedPictogramSpeakable: String

        enum CodingKeys: String, CodingKey {
            case name
            case fingerprintHex = "fingerprint_hex"
            case indices
            case expectedPictogram = "expected_pictogram"
            case expectedPictogramSpeakable = "expected_pictogram_speakable"
        }
    }

    struct TestVectors: Codable {
        let vectors: [TestVector]
        let emojiList: [String]

        enum CodingKeys: String, CodingKey {
            case vectors
            case emojiList = "emoji_list"
        }
    }

    var testVectors: TestVectors!

    override func setUp() async throws {
        try await super.setUp()

        let url = Bundle.module.url(forResource: "pictogram", withExtension: "json", subdirectory: "TestVectors")!
        let data = try Data(contentsOf: url)
        testVectors = try JSONDecoder().decode(TestVectors.self, from: data)
    }

    // MARK: - Test Vector Validation

    func testVectorFromProtocolSpec() throws {
        let vector = testVectors.vectors.first(where: { $0.name.contains("protocol-spec") })!

        let fingerprint = try XCTUnwrap(Data(hexEncoded: vector.fingerprintHex))
        let pictogram = Pictogram.derive(from: fingerprint)

        XCTAssertEqual(pictogram.indices, vector.indices,
                      "Indices should match test vector")
        XCTAssertEqual(pictogram.names, vector.expectedPictogram,
                      "Pictogram names should match test vector")
        XCTAssertEqual(pictogram.speakable, vector.expectedPictogramSpeakable,
                      "Speakable form should match test vector (D10: spaces, not hyphens)")
    }

    func testAllZerosFingerprint() throws {
        let vector = testVectors.vectors.first(where: { $0.name.contains("All zeros") })!

        let fingerprint = try XCTUnwrap(Data(hexEncoded: vector.fingerprintHex))
        let pictogram = Pictogram.derive(from: fingerprint)

        XCTAssertEqual(pictogram.indices, [0, 0, 0, 0, 0],
                      "All zeros should produce all index 0")
        XCTAssertEqual(pictogram.names, ["apple", "apple", "apple", "apple", "apple"],
                      "Index 0 maps to 'apple'")
    }

    func testMaxFingerprint() throws {
        let vector = testVectors.vectors.first(where: { $0.name.contains("0xFF") })!

        let fingerprint = try XCTUnwrap(Data(hexEncoded: vector.fingerprintHex))
        let pictogram = Pictogram.derive(from: fingerprint)

        XCTAssertEqual(pictogram.indices, [63, 63, 63, 63, 63],
                      "All 0xFF should produce all index 63")
        XCTAssertEqual(pictogram.names, ["fire", "fire", "fire", "fire", "fire"],
                      "Index 63 maps to 'fire' (last emoji)")
    }

    func testSequentialIndices() throws {
        // NOTE: Test vector has error - hex "041041041000..." produces [1,1,1,1,1] not [1,0,16,4,4]
        // Correct hex for [1,0,16,4,4] should be "04040410000..."
        // See: working/desktop/test-vector-issues.md

        // Testing with corrected hex until B0 fixes test vector
        let correctedHex = "0404041000000000000000000000000000000000000000000000000000000000"
        let fingerprint = try XCTUnwrap(Data(hexEncoded: correctedHex))
        let pictogram = Pictogram.derive(from: fingerprint)

        XCTAssertEqual(pictogram.indices, [1, 0, 16, 4, 4],
                      "Indices should match corrected sequential test")
        XCTAssertEqual(pictogram.names, ["banana", "apple", "pizza", "lemon", "lemon"],
                      "Names should match expected pictogram")
    }

    // MARK: - Emoji List Validation

    func testEmojiListHas64Entries() {
        XCTAssertEqual(testVectors.emojiList.count, 64,
                      "Emoji list must have exactly 64 entries (6-bit indexing)")
    }

    func testEmojiListMatches() {
        // Verify our emoji list constant matches the test vector
        XCTAssertEqual(Pictogram.emojiNames, testVectors.emojiList,
                      "Pictogram.emojiNames must match canonical test vector list")
    }

    // MARK: - D10 Compliance (Speakable Format)

    func testSpeakableUsesSpacesNotHyphens() {
        let fingerprint = Data(hexEncoded: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")!
        let pictogram = Pictogram.derive(from: fingerprint)

        XCTAssertTrue(pictogram.speakable.contains(" "),
                     "Speakable must use spaces per D10")
        XCTAssertFalse(pictogram.speakable.contains("-"),
                      "Speakable must NOT use hyphens in JSON form per D10")
    }

    func testURLSafeFormUsesHyphens() {
        let fingerprint = Data(hexEncoded: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")!
        let pictogram = Pictogram.derive(from: fingerprint)

        let urlSafe = pictogram.urlSafeForm

        XCTAssertTrue(urlSafe.contains("-"),
                     "URL-safe form must use hyphens per D10")
        XCTAssertFalse(urlSafe.contains(" "),
                      "URL-safe form must NOT contain spaces")
    }

    // MARK: - Determinism

    func testDeterministicDerivation() {
        let fingerprint = Data(hexEncoded: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")!

        let pictogram1 = Pictogram.derive(from: fingerprint)
        let pictogram2 = Pictogram.derive(from: fingerprint)

        XCTAssertEqual(pictogram1.indices, pictogram2.indices,
                      "Same fingerprint must produce same indices")
        XCTAssertEqual(pictogram1.speakable, pictogram2.speakable,
                      "Same fingerprint must produce same speakable")
    }

    // MARK: - Edge Cases

    func testShortFingerprintFails() {
        let shortData = Data([0x01, 0x02, 0x03]) // Only 3 bytes

        // Should either throw or handle gracefully
        // Implementation will define exact behavior
    }

    func testEmptyFingerprintFails() {
        let emptyData = Data()

        // Should either throw or handle gracefully
    }
}

// MARK: - Helper Extensions

extension Data {
    init?(hexEncoded string: String) {
        let hexString = string.replacingOccurrences(of: " ", with: "")
        guard hexString.count % 2 == 0 else { return nil }

        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex

        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            let byteString = hexString[index..<nextIndex]
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }
}
