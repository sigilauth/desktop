import Foundation

public struct PairInitResponse: Codable, Equatable, Sendable {
    public let serverId: String
    public let serverPublicKey: String
    public let serverNonce: String
    public let expiresAt: Date

    enum CodingKeys: String, CodingKey {
        case serverId = "server_id"
        case serverPublicKey = "server_public_key"
        case serverNonce = "server_nonce"
        case expiresAt = "expires_at"
    }
}

public struct PairCompleteRequest: Codable, Equatable, Sendable {
    public let serverNonce: String
    public let clientPublicKey: String
    public let deviceInfo: DeviceInfo

    public struct DeviceInfo: Codable, Equatable, Sendable {
        public let name: String
        public let platform: String
        public let osVersion: String

        enum CodingKeys: String, CodingKey {
            case name
            case platform
            case osVersion = "os_version"
        }
    }

    enum CodingKeys: String, CodingKey {
        case serverNonce = "server_nonce"
        case clientPublicKey = "client_public_key"
        case deviceInfo = "device_info"
    }

    public init(serverNonce: String, clientPublicKey: String, deviceInfo: DeviceInfo) {
        self.serverNonce = serverNonce
        self.clientPublicKey = clientPublicKey
        self.deviceInfo = deviceInfo
    }
}

public struct PairCompleteResponse: Codable, Equatable, Sendable {
    public let status: String
    public let serverPublicKey: String
    public let pairedAt: Date

    enum CodingKeys: String, CodingKey {
        case status
        case serverPublicKey = "server_public_key"
        case pairedAt = "paired_at"
    }
}

public struct TrustedServer: Codable, Equatable, Sendable {
    public let serverUrl: URL
    public let serverId: String
    public let serverPublicKey: String
    public let serverFingerprint: String
    public let pairedAt: Date

    public init(
        serverUrl: URL,
        serverId: String,
        serverPublicKey: String,
        serverFingerprint: String,
        pairedAt: Date
    ) {
        self.serverUrl = serverUrl
        self.serverId = serverId
        self.serverPublicKey = serverPublicKey
        self.serverFingerprint = serverFingerprint
        self.pairedAt = pairedAt
    }
}
