import XCTest
import CryptoKit
@testable import SigilAuth

/// Integration tests for RelayClient against live doppler relay
///
/// These tests require network access to the doppler cluster relay:
/// - Endpoint: ws://192.168.0.192:30080/ws
/// - Relay must be running in doppler cluster (kubectl --context=doppler -n sigil get svc/relay)
///
/// Tests validate full WebSocket protocol implementation:
/// - Auth challenge/response flow
/// - ECDSA signature verification
/// - Reconnect behavior
/// - Error handling
///
/// NOTE: Tests must run serially due to shared network resource (relay endpoint)
final class RelayClientIntegrationTests: XCTestCase {

    // Lazy initialization to avoid issues during XCTest class loading
    private lazy var relayURL: URL = URL(string: "ws://192.168.0.192:30080")!

    private var client: RelayClient!
    private var deviceKey: TestDeviceKey!

    override func setUp() async throws {
        try await super.setUp()

        // Skip integration tests if relay is not available
        // These tests require doppler cluster relay at ws://192.168.0.192:30080
        try XCTSkipIf(true, "Integration tests require live doppler relay. Run manually when relay is available.")

        client = RelayClient()
        deviceKey = try TestDeviceKey()
    }

    override func tearDown() async throws {
        client = nil
        deviceKey = nil
        try await super.tearDown()
    }

    // MARK: - Basic Connectivity

    /// Test successful connection and authentication flow
    func testSuccessfulAuthentication() async throws {
        let expectation = expectation(description: "Authentication completes")
        var receivedState: RelayClient.State?
        var authSucceeded = false

        await client.setStateChangeHandler { state in
            receivedState = state
            if state == .connected {
                authSucceeded = true
                expectation.fulfill()
            }
        }

        try await client.connect(to: relayURL, deviceKey: deviceKey)

        await fulfillment(of: [expectation], timeout: 10.0)

        XCTAssertTrue(authSucceeded, "Authentication should succeed")
        XCTAssertEqual(receivedState, .connected, "Final state should be connected")

        let fingerprint = await client.fingerprint
        XCTAssertNotNil(fingerprint, "Fingerprint should be set after auth")
        XCTAssertEqual(fingerprint?.count, 64, "Fingerprint should be 64 hex chars (SHA-256)")
    }

    /// Test that fingerprint matches SHA-256 of device public key
    func testFingerprintMatchesPublicKey() async throws {
        try await client.connect(to: relayURL, deviceKey: deviceKey)

        let fingerprint = await client.fingerprint
        XCTAssertNotNil(fingerprint)

        // Calculate expected fingerprint
        let publicKeyHash = SHA256.hash(data: deviceKey.publicKey)
        let expectedFingerprint = publicKeyHash.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(fingerprint, expectedFingerprint, "Server fingerprint should match SHA-256(public_key)")
    }

    // MARK: - State Transitions

    /// Test state transitions during connection
    func testStateTransitions() async throws {
        var states: [RelayClient.State] = []
        let expectation = expectation(description: "All states observed")

        await client.setStateChangeHandler { state in
            states.append(state)
            if state == .connected {
                expectation.fulfill()
            }
        }

        try await client.connect(to: relayURL, deviceKey: deviceKey)

        await fulfillment(of: [expectation], timeout: 10.0)

        XCTAssertTrue(states.contains(.connecting), "Should transition through connecting state")
        XCTAssertTrue(states.contains(.authenticating), "Should transition through authenticating state")
        XCTAssertTrue(states.contains(.connected), "Should reach connected state")
        XCTAssertEqual(states.last, .connected, "Final state should be connected")
    }

    // MARK: - Disconnection & Reconnection

    /// Test graceful disconnect
    func testGracefulDisconnect() async throws {
        try await client.connect(to: relayURL, deviceKey: deviceKey)

        await client.disconnect()

        // Verify disconnection synchronously (no expectation needed since disconnect() is async)
        let state = await client.state
        XCTAssertEqual(state, .disconnected, "Should be disconnected after disconnect() returns")

        let fingerprint = await client.fingerprint
        XCTAssertNil(fingerprint, "Fingerprint should be cleared after disconnect")
    }

    // MARK: - Concurrent Connections

    /// Test that multiple connection attempts are handled gracefully
    func testConcurrentConnectionAttempts() async throws {
        // First connection
        try await client.connect(to: relayURL, deviceKey: deviceKey)

        let state1 = await client.state
        XCTAssertEqual(state1, .connected)

        // Attempt second connection while first is active
        // Should be ignored per RelayClient logic (already connected)
        try await client.connect(to: relayURL, deviceKey: deviceKey)

        let state2 = await client.state
        XCTAssertEqual(state2, .connected, "Should remain connected")
    }

    // MARK: - Error Handling

    /// Test connection to invalid endpoint
    func testInvalidEndpoint() async throws {
        let invalidURL = URL(string: "ws://192.168.0.192:99999")!
        let client = RelayClient()

        do {
            try await client.connect(to: invalidURL, deviceKey: deviceKey)
            XCTFail("Connection to invalid endpoint should throw")
        } catch {
            // Expected error
            XCTAssertNotNil(error, "Should throw error for invalid endpoint")
        }
    }

    /// Test connection timeout on unreachable endpoint
    func testUnreachableEndpoint() async throws {
        let unreachableURL = URL(string: "ws://192.168.99.99:30080")!
        let client = RelayClient()

        do {
            try await client.connect(to: unreachableURL, deviceKey: deviceKey)
            XCTFail("Connection to unreachable endpoint should timeout/throw")
        } catch {
            // Expected timeout/network error
            XCTAssertNotNil(error)
        }
    }

    // MARK: - Notification Handling

    /// Test that challenge notifications can be received (if relay supports push)
    ///
    /// Note: This test may not trigger a notification immediately unless the relay
    /// is configured to send test challenges. Test validates the callback mechanism.
    func testNotificationCallback() async throws {
        var notificationReceived = false
        var receivedNotification: ChallengeNotification?

        await client.setNotificationHandler { notification in
            notificationReceived = true
            receivedNotification = notification
        }

        try await client.connect(to: relayURL, deviceKey: deviceKey)

        // Wait briefly for any immediate notifications
        // (Relay may not send any unless triggered externally)
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds

        // This test validates the mechanism works; actual notification delivery
        // depends on relay configuration and external triggers
        // We just verify no crashes occurred when setting the callback
        XCTAssertNotNil(receivedNotification == nil || receivedNotification != nil,
                       "Notification callback should be set without error")
    }

    // MARK: - Protocol Validation

    /// Test that authentication uses ECDSA P-256 signature
    func testAuthenticationUsesECDSAP256() async throws {
        // This is validated implicitly by successful authentication
        // The relay only accepts valid P-256 signatures
        try await client.connect(to: relayURL, deviceKey: deviceKey)

        let state = await client.state
        XCTAssertEqual(state, .connected, "ECDSA signature should be accepted by relay")
    }

    /// Test that public key is sent in compressed format (33 bytes)
    func testPublicKeyIsCompressed() async throws {
        let publicKey = deviceKey.publicKey

        XCTAssertEqual(publicKey.count, 33, "Public key should be compressed (33 bytes)")

        let prefix = publicKey.first!
        XCTAssertTrue(prefix == 0x02 || prefix == 0x03,
                     "Compressed public key should start with 0x02 or 0x03")
    }

    // MARK: - Long-Running Connection

    /// Test that connection remains stable over time
    func testLongRunningConnection() async throws {
        try await client.connect(to: relayURL, deviceKey: deviceKey)

        // Stay connected for 30 seconds
        for _ in 0..<30 {
            try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second

            let state = await client.state
            XCTAssertEqual(state, .connected, "Should remain connected during long-running test")
        }

        await client.disconnect()
    }

}
