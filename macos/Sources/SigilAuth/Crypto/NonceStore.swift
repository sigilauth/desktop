import Foundation

/// Thread-safe nonce tracking for replay protection
///
/// Per wire-protocol.md §6.2 and §5.4, clients MUST track response nonces
/// to prevent replay attacks within the timestamp window (300s).
public protocol NonceStore {
    /// Check if nonce has been seen before, and mark as seen if not
    /// - Parameter nonce: Nonce string to check
    /// - Returns: True if nonce is fresh (not seen), false if replay detected
    func checkAndMarkNonce(_ nonce: String) -> Bool

    /// Remove expired entries (older than TTL)
    func cleanup()
}

/// In-memory nonce store with 300s TTL
public class MemoryNonceStore: NonceStore {
    private var seenNonces: [String: Date] = [:]
    private let lock = NSLock()
    private let ttl: TimeInterval

    public init(ttl: TimeInterval = 300) {
        self.ttl = ttl
    }

    public func checkAndMarkNonce(_ nonce: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        // Clean up expired entries first
        cleanupExpired()

        // Check if nonce exists
        if seenNonces[nonce] != nil {
            return false  // Replay detected
        }

        // Mark as seen
        seenNonces[nonce] = Date()
        return true  // Fresh nonce
    }

    public func cleanup() {
        lock.lock()
        defer { lock.unlock() }
        cleanupExpired()
    }

    private func cleanupExpired() {
        let now = Date()
        seenNonces = seenNonces.filter { _, timestamp in
            now.timeIntervalSince(timestamp) < ttl
        }
    }
}
