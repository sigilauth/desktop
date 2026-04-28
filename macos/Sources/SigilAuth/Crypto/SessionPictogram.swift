import Foundation
import CryptoKit

public struct SessionPictogram: Equatable {
    public let emojis: [String]
    public let names: [String]
    public let speakable: String

    public init(emojis: [String], names: [String]) {
        self.emojis = emojis
        self.names = names
        self.speakable = names.joined(separator: " ")
    }
}

public struct SessionPictogramDerivation {
    private let argon2: Argon2Service
    private let pool: PictogramPool

    public init(argon2: Argon2Service = DefaultArgon2Service(), pool: PictogramPool = .shared) {
        self.argon2 = argon2
        self.pool = pool
    }

    public func derive(
        serverPublicKey: Data,
        clientPublicKey: Data,
        serverNonce: Data
    ) throws -> SessionPictogram {
        guard serverPublicKey.count == 33 else {
            throw SessionPictogramError.invalidPublicKeySize
        }
        guard clientPublicKey.count == 33 else {
            throw SessionPictogramError.invalidPublicKeySize
        }
        guard serverNonce.count == 32 else {
            throw SessionPictogramError.invalidNonceSize
        }

        var input = Data()
        input.append(serverPublicKey)
        input.append(clientPublicKey)
        input.append(serverNonce)

        let password = Data(SHA256.hash(data: input))

        let salt = Data(DomainTag.pairSalt)

        let derived = try argon2.deriveKey(
            password: password,
            salt: salt,
            memoryKiB: 65536,
            iterations: 10,
            parallelism: 1,
            outputLength: 32
        )

        var emojis: [String] = []
        var names: [String] = []

        for i in 0..<6 {
            let offset = i * 2
            let wordIndex = (UInt16(derived[offset]) << 8) | UInt16(derived[offset + 1])
            let poolIndex = Int(wordIndex) % pool.count

            guard let entry = pool.entry(at: poolIndex) else {
                throw SessionPictogramError.poolIndexOutOfBounds
            }

            emojis.append(entry.emoji)
            names.append(entry.name)
        }

        return SessionPictogram(emojis: emojis, names: names)
    }
}

public enum SessionPictogramError: Error {
    case invalidPublicKeySize
    case invalidNonceSize
    case poolIndexOutOfBounds
    case argon2Failed
}
