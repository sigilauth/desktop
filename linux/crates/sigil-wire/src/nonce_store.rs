//! Nonce tracking for replay protection.
//!
//! Per `/api/wire-protocol.md` §6.2: All requests and responses include a nonce field.
//! Server-side nonce store prevents replay attacks within the 300-second timestamp window.
//!
//! **Implementation:** Sliding window with 5-minute TTL. Rejects envelopes whose nonce
//! has been seen within the window.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

const NONCE_TTL: Duration = Duration::from_secs(300);

/// Errors from nonce tracking operations.
#[derive(Debug, Error)]
pub enum NonceError {
    /// Nonce has been used before (replay attack detected).
    #[error("nonce has been used before (replay attack)")]
    NonceReused,
}

/// Thread-safe nonce store with sliding window eviction.
///
/// Stores nonces with insertion timestamps and automatically evicts entries
/// older than 300 seconds on each check.
#[derive(Clone)]
pub struct NonceStore {
    inner: Arc<Mutex<NonceStoreInner>>,
}

struct NonceStoreInner {
    /// Map of nonce (hex string) to insertion timestamp.
    nonces: HashMap<String, Instant>,
}

impl NonceStore {
    /// Create a new empty nonce store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NonceStoreInner {
                nonces: HashMap::new(),
            })),
        }
    }

    /// Check if nonce has been seen, then mark it as seen.
    ///
    /// Returns `Ok(())` if nonce is fresh (not seen before).
    /// Returns `Err(NonceError::NonceReused)` if nonce was seen within the TTL window.
    ///
    /// Automatically evicts stale nonces (older than 300s) during each check.
    pub fn check_and_insert(&self, nonce: &str) -> Result<(), NonceError> {
        let mut inner = self.inner.lock().unwrap();

        self.evict_stale(&mut inner);

        if inner.nonces.contains_key(nonce) {
            return Err(NonceError::NonceReused);
        }

        inner.nonces.insert(nonce.to_string(), Instant::now());

        Ok(())
    }

    /// Evict nonces older than TTL.
    fn evict_stale(&self, inner: &mut NonceStoreInner) {
        let now = Instant::now();
        inner.nonces.retain(|_, &mut timestamp| {
            now.duration_since(timestamp) < NONCE_TTL
        });
    }

    /// Get current nonce count (for debugging/monitoring).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.nonces.len()
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn fresh_nonce_accepted() {
        let store = NonceStore::new();
        let result = store.check_and_insert("nonce-001");
        assert!(result.is_ok(), "Fresh nonce should be accepted");
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let store = NonceStore::new();
        store.check_and_insert("nonce-001").unwrap();
        let result = store.check_and_insert("nonce-001");
        assert!(
            matches!(result, Err(NonceError::NonceReused)),
            "Duplicate nonce should be rejected"
        );
    }

    #[test]
    fn different_nonces_accepted() {
        let store = NonceStore::new();
        store.check_and_insert("nonce-001").unwrap();
        let result = store.check_and_insert("nonce-002");
        assert!(result.is_ok(), "Different nonce should be accepted");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn eviction_removes_stale_nonces() {
        let store = NonceStore::new();

        {
            let mut inner = store.inner.lock().unwrap();
            inner.nonces.insert(
                "old-nonce".to_string(),
                Instant::now() - Duration::from_secs(400),
            );
            inner.nonces.insert("recent-nonce".to_string(), Instant::now());
        }

        store.check_and_insert("new-nonce").unwrap();

        let inner = store.inner.lock().unwrap();
        assert!(!inner.nonces.contains_key("old-nonce"), "Old nonce should be evicted");
        assert!(inner.nonces.contains_key("recent-nonce"), "Recent nonce should remain");
        assert!(inner.nonces.contains_key("new-nonce"), "New nonce should be inserted");
    }

    #[test]
    fn thread_safe_concurrent_access() {
        let store = NonceStore::new();
        let store_clone = store.clone();

        let handle = thread::spawn(move || {
            for i in 0..100 {
                store_clone.check_and_insert(&format!("nonce-{}", i)).unwrap();
            }
        });

        for i in 100..200 {
            store.check_and_insert(&format!("nonce-{}", i)).unwrap();
        }

        handle.join().unwrap();

        assert_eq!(store.len(), 200, "All nonces should be inserted without conflicts");
    }
}
