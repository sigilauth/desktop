import Foundation
import CArgon2

public enum Argon2Error: Error {
    case derivationFailed
    case invalidParameters
}

public protocol Argon2Service {
    func deriveKey(
        password: Data,
        salt: Data,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        outputLength: Int
    ) throws -> Data
}

public struct DefaultArgon2Service: Argon2Service {
    public init() {}

    public func deriveKey(
        password: Data,
        salt: Data,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        outputLength: Int
    ) throws -> Data {
        guard salt.count == 16 else {
            throw Argon2Error.invalidParameters
        }

        var output = [UInt8](repeating: 0, count: outputLength)

        let result = password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                argon2id_hash_raw(
                    UInt32(iterations),
                    UInt32(memoryKiB),
                    UInt32(parallelism),
                    passwordBytes.baseAddress,
                    password.count,
                    saltBytes.baseAddress,
                    salt.count,
                    &output,
                    output.count
                )
            }
        }

        guard result == Int32(ARGON2_OK.rawValue) else {
            throw Argon2Error.derivationFailed
        }

        return Data(output)
    }
}


