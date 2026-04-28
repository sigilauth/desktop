import Foundation
import CryptoKit
import OSLog

/// Protocol for device keys that can sign relay authentication challenges
public protocol DeviceSigningKey {
    var publicKey: Data { get }
    func sign(_ data: Data, reason: String) async throws -> Data
}

/// Make SecureEnclaveKey conform to DeviceSigningKey
extension SecureEnclaveKey: DeviceSigningKey {}

/// WebSocket client for connecting to Sigil relay.
/// Handles authentication and listens for challenge notifications.
public actor RelayClient {
    private let logger = Logger(subsystem: "com.wagmilabs.sigil", category: "relay")

    private var webSocketTask: URLSessionWebSocketTask?
    private var session: URLSession?
    private var isConnected = false
    private var reconnectAttempts = 0
    private var reconnectTask: Task<Void, Never>?

    private let maxReconnectAttempts = 10
    private let baseReconnectDelay: TimeInterval = 1.0
    private let maxReconnectDelay: TimeInterval = 60.0

    public enum State {
        case disconnected
        case connecting
        case authenticating
        case connected
        case reconnecting
    }

    public private(set) var state: State = .disconnected
    public private(set) var fingerprint: String?

    public var onNotificationReceived: ((ChallengeNotification) -> Void)?
    public var onStateChanged: ((State) -> Void)?

    public init() {}

    /// Set callback for state changes
    public func setStateChangeHandler(_ handler: @escaping (State) -> Void) {
        onStateChanged = handler
    }

    /// Set callback for incoming notifications
    public func setNotificationHandler(_ handler: @escaping (ChallengeNotification) -> Void) {
        onNotificationReceived = handler
    }

    /// Connect to relay WebSocket endpoint
    public func connect(to relayURL: URL, deviceKey: some DeviceSigningKey) async throws {
        guard state == .disconnected || state == .reconnecting else {
            logger.warning("Already connected or connecting")
            return
        }

        setState(.connecting)

        // Construct WebSocket URL properly (append /ws path)
        var wsURL = relayURL
        if !wsURL.path.hasSuffix("/ws") {
            wsURL = wsURL.appendingPathComponent("ws")
        }
        logger.info("Connecting to relay: \(wsURL.absoluteString, privacy: .public)")

        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30

        session = URLSession(configuration: configuration)
        webSocketTask = session?.webSocketTask(with: wsURL)
        webSocketTask?.resume()

        do {
            try await authenticate(deviceKey: deviceKey)
            setState(.connected)
            isConnected = true
            reconnectAttempts = 0

            startReceiving()
        } catch {
            logger.error("Connection failed: \(error.localizedDescription)")
            setState(.disconnected)
            throw error
        }
    }

    /// Disconnect from relay
    public func disconnect() async {
        reconnectTask?.cancel()
        reconnectTask = nil

        if let task = webSocketTask {
            task.cancel(with: .normalClosure, reason: nil)
        }

        webSocketTask = nil
        session?.invalidateAndCancel()
        session = nil

        isConnected = false
        setState(.disconnected)
        fingerprint = nil
        reconnectAttempts = 0
    }

    private func authenticate(deviceKey: some DeviceSigningKey) async throws {
        setState(.authenticating)

        let message = try await receive()
        guard let authChallenge = try? JSONDecoder().decode(AuthChallengeMessage.self, from: message) else {
            throw RelayError.invalidAuthChallenge
        }

        logger.debug("Received auth challenge, expires: \(authChallenge.expires_at)")

        guard let challengeBytes = Data(base64Encoded: authChallenge.challenge) else {
            throw RelayError.invalidChallengeEncoding
        }

        let signature = try await deviceKey.sign(challengeBytes, reason: "Authenticate to Sigil relay")

        let authResponse = AuthResponseMessage(
            type: "auth_response",
            device_public_key: deviceKey.publicKey.base64EncodedString(),
            signature: signature.base64EncodedString(),
            timestamp: ISO8601DateFormatter().string(from: Date())
        )

        try await send(authResponse)

        let responseData = try await receive()

        if let authSuccess = try? JSONDecoder().decode(AuthSuccessMessage.self, from: responseData) {
            self.fingerprint = authSuccess.fingerprint
            logger.info("Authenticated successfully, fingerprint: \(authSuccess.fingerprint.prefix(16))...")
        } else if let authFailure = try? JSONDecoder().decode(AuthFailureMessage.self, from: responseData) {
            logger.error("Authentication failed: \(authFailure.error)")
            throw RelayError.authenticationFailed(authFailure.error)
        } else {
            throw RelayError.invalidAuthResponse
        }
    }

    private func startReceiving() {
        Task {
            do {
                while isConnected {
                    let data = try await receive()

                    if let notification = try? JSONDecoder().decode(ChallengeNotification.self, from: data) {
                        logger.debug("Received challenge notification")
                        onNotificationReceived?(notification)
                    } else {
                        logger.warning("Received unknown message type")
                    }
                }
            } catch {
                logger.error("Receive loop error: \(error.localizedDescription)")

                if isConnected {
                    await handleDisconnect()
                }
            }
        }
    }

    private func handleDisconnect() async {
        isConnected = false

        guard reconnectAttempts < maxReconnectAttempts else {
            logger.error("Max reconnect attempts reached, giving up")
            setState(.disconnected)
            return
        }

        reconnectAttempts += 1
        let delay = min(baseReconnectDelay * pow(2.0, Double(reconnectAttempts - 1)), maxReconnectDelay)

        logger.info("Reconnecting in \(delay)s (attempt \(self.reconnectAttempts)/\(self.maxReconnectAttempts))")
        setState(.reconnecting)

        reconnectTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))

            // TODO: Store device key to enable reconnect
            // try? await connect(to: lastRelayURL, deviceKey: lastDeviceKey)
        }
    }

    private func receive() async throws -> Data {
        guard let task = webSocketTask else {
            throw RelayError.notConnected
        }

        let message = try await task.receive()

        switch message {
        case .data(let data):
            return data
        case .string(let text):
            guard let data = text.data(using: .utf8) else {
                throw RelayError.invalidMessageEncoding
            }
            return data
        @unknown default:
            throw RelayError.unknownMessageType
        }
    }

    private func send<T: Encodable>(_ message: T) async throws {
        guard let task = webSocketTask else {
            throw RelayError.notConnected
        }

        let data = try JSONEncoder().encode(message)
        let message = URLSessionWebSocketTask.Message.data(data)

        try await task.send(message)
    }

    private func setState(_ newState: State) {
        state = newState
        onStateChanged?(newState)
    }
}

// MARK: - Message Types

private struct AuthChallengeMessage: Codable {
    let type: String
    let challenge: String
    let expires_at: String
}

private struct AuthResponseMessage: Codable {
    let type: String
    let device_public_key: String
    let signature: String
    let timestamp: String
}

private struct AuthSuccessMessage: Codable {
    let type: String
    let fingerprint: String
}

private struct AuthFailureMessage: Codable {
    let type: String
    let error: String
}

public struct ChallengeNotification: Codable {
    public let type: String
    public let challenge_id: String?
    public let server_name: String?
    public let server_id: String?
    public let server_pubkey: String?
    public let action: String?
    public let expires_at: String
    public let challenge: String
}

// MARK: - Errors

public enum RelayError: LocalizedError {
    case notConnected
    case invalidAuthChallenge
    case invalidChallengeEncoding
    case invalidAuthResponse
    case authenticationFailed(String)
    case invalidMessageEncoding
    case unknownMessageType

    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "Not connected to relay"
        case .invalidAuthChallenge:
            return "Received invalid auth challenge"
        case .invalidChallengeEncoding:
            return "Challenge encoding is invalid"
        case .invalidAuthResponse:
            return "Received invalid auth response"
        case .authenticationFailed(let reason):
            return "Authentication failed: \(reason)"
        case .invalidMessageEncoding:
            return "Message encoding is invalid"
        case .unknownMessageType:
            return "Unknown message type"
        }
    }
}
