import Foundation
import Security

public protocol TrustStorageService: Sendable {
    func saveTrustedServer(_ server: TrustedServer) throws
    func loadTrustedServer(fingerprint: String) throws -> TrustedServer?
    func loadAllTrustedServers() throws -> [TrustedServer]
    func removeTrustedServer(fingerprint: String) throws
}

public enum TrustStorageError: Error {
    case encodingFailed
    case decodingFailed
    case keychainError(OSStatus)
    case notFound
}

public final class KeychainTrustStorage: TrustStorageService, @unchecked Sendable {
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let service = "com.wagmilabs.sigil.trusted-servers"

    public init() {
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    public func saveTrustedServer(_ server: TrustedServer) throws {
        guard let data = try? encoder.encode(server) else {
            throw TrustStorageError.encodingFailed
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: server.serverFingerprint,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: server.serverFingerprint
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw TrustStorageError.keychainError(status)
        }
    }

    public func loadTrustedServer(fingerprint: String) throws -> TrustedServer? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status != errSecItemNotFound else {
            return nil
        }

        guard status == errSecSuccess, let data = result as? Data else {
            throw TrustStorageError.keychainError(status)
        }

        guard let server = try? decoder.decode(TrustedServer.self, from: data) else {
            throw TrustStorageError.decodingFailed
        }

        return server
    }

    public func loadAllTrustedServers() throws -> [TrustedServer] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status != errSecItemNotFound else {
            return []
        }

        guard status == errSecSuccess, let dataArray = result as? [Data] else {
            if status == errSecItemNotFound {
                return []
            }
            throw TrustStorageError.keychainError(status)
        }

        return dataArray.compactMap { data in
            try? decoder.decode(TrustedServer.self, from: data)
        }
    }

    public func removeTrustedServer(fingerprint: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TrustStorageError.keychainError(status)
        }
    }
}
