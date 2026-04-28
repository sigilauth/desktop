//! libsecret / freedesktop Secret Service wrapper for Sigil Auth.
//!
//! **Stores METADATA only.** Server URLs, pinned server public keys,
//! pictograms, user preferences. Private keys MUST remain in TPM /
//! YubiKey hardware per Knox threat model §11.1. This crate has no API
//! for storing keys.
//!
//! # Storage model
//!
//! Each server is a Secret Service *item* with attributes:
//! ```text
//! application  = "sigilauth"
//! kind         = "server_record"
//! fingerprint  = <hex fingerprint>
//! ```
//!
//! The secret (payload) is the JSON-encoded [`ServerRecord`]. The secret
//! itself is encrypted at rest by the Secret Service daemon (gnome-keyring
//! or KWallet with the compat bridge).
//!
//! # Async model
//!
//! All methods are async. Secret Service operations are D-Bus round-trips;
//! callers must not block the GTK main loop on them. The backend uses the
//! `secret-service` crate's tokio executor (`rt-tokio-crypto-rust`).
//!
//! # Tests
//!
//! Unit tests cover serde + attribute construction. Integration tests
//! (feature `integration-tests`) spin up `dbus-run-session` + `gnome-keyring-daemon`
//! in CI and exercise the full round-trip. Skipped when feature is off.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Errors from the Secret Service backend.
#[derive(Debug, Error)]
pub enum SecretError {
    /// The Secret Service daemon is not running or not reachable over D-Bus.
    #[error("secret service unavailable: {0}")]
    Unavailable(String),
    /// The default collection is locked and cannot be unlocked
    /// (typically because no `login` keyring exists).
    #[error("default collection is locked; user must unlock or create `login` keyring")]
    Locked,
    /// The requested item was not found.
    #[error("item not found")]
    NotFound,
    /// JSON encoding or decoding failed.
    #[error("record serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// The backend returned an error.
    #[error("backend error: {0}")]
    Backend(String),
}

/// Metadata about a Sigil server the user has paired with.
///
/// Serialised as JSON, stored as the Secret Service "secret" for an item.
/// The server public key is **pinned** — subsequent connections verify the
/// TLS certificate corresponds to the same key.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerRecord {
    /// `https://` URL.
    pub url: String,
    /// Base64 (standard alphabet, padded) 33-byte compressed SEC1 P-256 pubkey.
    pub server_public_key_b64: String,
    /// Five emoji-names derived per protocol §11 pictogram.
    pub pictogram: [String; 5],
    /// Space-separated speakable form per D8.
    pub pictogram_speakable: String,
    /// Human-assigned name (optional, user-editable).
    pub display_name: Option<String>,
    /// ISO-8601 timestamp of first pairing.
    pub paired_at: String,
    /// Optional TLS certificate SHA-256 hash (hex) for stronger pinning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_sha256_hex: Option<String>,
}

impl ServerRecord {
    /// The canonical Secret Service attribute set for this record.
    /// Stable across versions — changing it breaks migration.
    pub fn attributes(fingerprint_hex: &str) -> HashMap<&'static str, String> {
        let mut m = HashMap::new();
        m.insert("application", "sigilauth".to_string());
        m.insert("kind", "server_record".to_string());
        m.insert("fingerprint", fingerprint_hex.to_string());
        m
    }

    /// Canonicalised label shown in `seahorse` (GNOME Keyring GUI).
    pub fn label(&self) -> String {
        match &self.display_name {
            Some(name) => format!("Sigil server: {name}"),
            None => format!("Sigil server: {}", self.url),
        }
    }

    /// Encode to JSON bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SecretError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Decode from JSON bytes loaded from storage.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecretError> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// The Sigil metadata store. Constructed via [`MetadataStore::connect`].
///
/// Cloneable + thread-safe.
pub struct MetadataStore {
    #[cfg(target_os = "linux")]
    inner: linux_backend::Inner,
    #[cfg(not(target_os = "linux"))]
    _phantom: std::marker::PhantomData<()>,
}

impl MetadataStore {
    /// Connect to the session Secret Service and unlock the default collection.
    #[cfg(target_os = "linux")]
    pub async fn connect() -> Result<Self, SecretError> {
        let inner = linux_backend::Inner::connect().await?;
        Ok(MetadataStore { inner })
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(missing_docs)]
    pub async fn connect() -> Result<Self, SecretError> {
        Err(SecretError::Unavailable(
            "Secret Service is a Linux D-Bus service; not available on this platform".into(),
        ))
    }

    /// Persist a server record. Replaces any existing record with the same
    /// fingerprint.
    #[cfg(target_os = "linux")]
    pub async fn put_server(
        &self,
        fingerprint_hex: &str,
        record: &ServerRecord,
    ) -> Result<(), SecretError> {
        self.inner.put_server(fingerprint_hex, record).await
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(missing_docs)]
    pub async fn put_server(
        &self,
        _fingerprint_hex: &str,
        _record: &ServerRecord,
    ) -> Result<(), SecretError> {
        Err(SecretError::Unavailable("Linux only".into()))
    }

    /// Retrieve a server record by fingerprint.
    #[cfg(target_os = "linux")]
    pub async fn get_server(&self, fingerprint_hex: &str) -> Result<ServerRecord, SecretError> {
        self.inner.get_server(fingerprint_hex).await
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(missing_docs)]
    pub async fn get_server(&self, _fingerprint_hex: &str) -> Result<ServerRecord, SecretError> {
        Err(SecretError::Unavailable("Linux only".into()))
    }

    /// List all paired servers.
    #[cfg(target_os = "linux")]
    pub async fn list_servers(&self) -> Result<Vec<(String, ServerRecord)>, SecretError> {
        self.inner.list_servers().await
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(missing_docs)]
    pub async fn list_servers(&self) -> Result<Vec<(String, ServerRecord)>, SecretError> {
        Err(SecretError::Unavailable("Linux only".into()))
    }

    /// Delete a server record.
    #[cfg(target_os = "linux")]
    pub async fn delete_server(&self, fingerprint_hex: &str) -> Result<(), SecretError> {
        self.inner.delete_server(fingerprint_hex).await
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(missing_docs)]
    pub async fn delete_server(&self, _fingerprint_hex: &str) -> Result<(), SecretError> {
        Err(SecretError::Unavailable("Linux only".into()))
    }
}

// ---- Linux backend -----------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_backend {
    use secret_service::{EncryptionType, SecretService};
    use std::sync::Arc;

    use super::{SecretError, ServerRecord};

    pub(super) struct Inner {
        ss: Arc<SecretService<'static>>,
    }

    impl Inner {
        pub(super) async fn connect() -> Result<Self, SecretError> {
            let ss = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(|e| SecretError::Unavailable(e.to_string()))?;

            // Unlock default collection if present; callers rely on it.
            let collection = ss
                .get_default_collection()
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            let locked = collection
                .is_locked()
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            if locked {
                collection.unlock().await.map_err(|_| SecretError::Locked)?;
            }

            Ok(Inner { ss: Arc::new(ss) })
        }

        pub(super) async fn put_server(
            &self,
            fingerprint_hex: &str,
            record: &ServerRecord,
        ) -> Result<(), SecretError> {
            let collection = self
                .ss
                .get_default_collection()
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;

            let attrs_owned = ServerRecord::attributes(fingerprint_hex);
            let attrs: std::collections::HashMap<&str, &str> =
                attrs_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();

            let payload = record.to_bytes()?;
            collection
                .create_item(
                    &record.label(),
                    attrs,
                    &payload,
                    true, // replace existing
                    "application/json",
                )
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            Ok(())
        }

        pub(super) async fn get_server(
            &self,
            fingerprint_hex: &str,
        ) -> Result<ServerRecord, SecretError> {
            let attrs_owned = ServerRecord::attributes(fingerprint_hex);
            let attrs: std::collections::HashMap<&str, &str> =
                attrs_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();

            let items = self
                .ss
                .search_items(attrs)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;

            let item = items
                .unlocked
                .into_iter()
                .chain(items.locked)
                .next()
                .ok_or(SecretError::NotFound)?;

            // Unlock if necessary. `search_items` partitions by lock state; if
            // the item ended up in `locked` we must unlock.
            let locked = item
                .is_locked()
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            if locked {
                item.unlock().await.map_err(|_| SecretError::Locked)?;
            }

            let secret = item
                .get_secret()
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            ServerRecord::from_bytes(&secret)
        }

        pub(super) async fn list_servers(
            &self,
        ) -> Result<Vec<(String, ServerRecord)>, SecretError> {
            let mut seed = std::collections::HashMap::new();
            seed.insert("application", "sigilauth");
            seed.insert("kind", "server_record");

            let items = self
                .ss
                .search_items(seed)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;

            let mut out = Vec::new();
            for item in items.unlocked.into_iter().chain(items.locked) {
                let attributes = item
                    .get_attributes()
                    .await
                    .map_err(|e| SecretError::Backend(e.to_string()))?;
                let Some(fp) = attributes.get("fingerprint").cloned() else {
                    continue;
                };
                let locked = item
                    .is_locked()
                    .await
                    .map_err(|e| SecretError::Backend(e.to_string()))?;
                if locked && item.unlock().await.is_err() {
                    tracing::warn!(fingerprint = %fp, "skipping locked item");
                    continue;
                }
                let secret = item
                    .get_secret()
                    .await
                    .map_err(|e| SecretError::Backend(e.to_string()))?;
                match ServerRecord::from_bytes(&secret) {
                    Ok(record) => out.push((fp, record)),
                    Err(e) => {
                        tracing::warn!(error = %e, fingerprint = %fp, "skipping malformed record");
                    }
                }
            }
            Ok(out)
        }

        pub(super) async fn delete_server(&self, fingerprint_hex: &str) -> Result<(), SecretError> {
            let attrs_owned = ServerRecord::attributes(fingerprint_hex);
            let attrs: std::collections::HashMap<&str, &str> =
                attrs_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();

            let items = self
                .ss
                .search_items(attrs)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;

            let mut deleted_any = false;
            for item in items.unlocked.into_iter().chain(items.locked) {
                item.delete()
                    .await
                    .map_err(|e| SecretError::Backend(e.to_string()))?;
                deleted_any = true;
            }
            if deleted_any {
                Ok(())
            } else {
                Err(SecretError::NotFound)
            }
        }
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    fn sample_record() -> ServerRecord {
        ServerRecord {
            url: "https://sigil.example.com".into(),
            server_public_key_b64: "Ag8xYzI3ZWRkNDUzYmNlYzVmMTJjNmI5MzA4OGY0".into(),
            pictogram: [
                "tree".into(),
                "rocket".into(),
                "mushroom".into(),
                "orange".into(),
                "moai".into(),
            ],
            pictogram_speakable: "tree rocket mushroom orange moai".into(),
            display_name: Some("Acme Corp".into()),
            paired_at: "2026-04-23T10:00:00Z".into(),
            tls_cert_sha256_hex: None,
        }
    }

    #[test]
    fn attributes_are_stable_across_versions() {
        let a = ServerRecord::attributes("deadbeef");
        assert_eq!(a["application"], "sigilauth");
        assert_eq!(a["kind"], "server_record");
        assert_eq!(a["fingerprint"], "deadbeef");
    }

    #[test]
    fn record_round_trips_through_bytes() {
        let record = sample_record();
        let bytes = record.to_bytes().unwrap();
        let decoded = ServerRecord::from_bytes(&bytes).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn label_uses_display_name_when_present() {
        let record = sample_record();
        assert_eq!(record.label(), "Sigil server: Acme Corp");
    }

    #[test]
    fn label_falls_back_to_url() {
        let mut record = sample_record();
        record.display_name = None;
        assert_eq!(record.label(), "Sigil server: https://sigil.example.com");
    }

    #[test]
    fn malformed_bytes_rejected() {
        assert!(ServerRecord::from_bytes(b"not json").is_err());
        assert!(ServerRecord::from_bytes(b"{}").is_err());
    }

    #[test]
    fn tls_cert_hash_optional() {
        // Omit on serialise when None.
        let record = sample_record();
        let bytes = record.to_bytes().unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !json.contains("tls_cert_sha256_hex"),
            "None must be omitted per skip_serializing_if"
        );
    }

    #[test]
    fn tls_cert_hash_round_trips_when_set() {
        let mut record = sample_record();
        record.tls_cert_sha256_hex = Some("aa".repeat(32));
        let bytes = record.to_bytes().unwrap();
        let decoded = ServerRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.tls_cert_sha256_hex, Some("aa".repeat(32)));
    }

    #[test]
    fn missing_fields_rejected() {
        let partial = r#"{"url":"https://x","server_public_key_b64":"A"}"#;
        assert!(ServerRecord::from_bytes(partial.as_bytes()).is_err());
    }
}
