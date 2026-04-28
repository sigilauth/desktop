//! Hardware-backed signing keys for Sigil Auth on Linux.
//!
//! Exposes a single `HardwareKey` trait. Two backends, feature-gated:
//! - `tpm` — TPM 2.0 via `tss-esapi`. User presence = TPM auth (PIN).
//! - `yubikey` — YubiKey PIV applet. User presence = PIN + physical touch.
//!
//! Private keys NEVER leave hardware. The trait returns only signatures,
//! public keys, and attestation chains. Any backend that cannot enforce
//! hardware-bound keys is a bug — see Knox threat model §11.1.
//!
//! A third backend, `SoftwareTestKey`, is available behind the
//! `test-support` feature. It is for integration tests only — it holds the
//! private key in userspace memory and MUST NOT be compiled into release
//! builds. The release binary has `default-features = ["tpm", "yubikey"]`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use sigil_wire::Fingerprint;
use thiserror::Error;

// Modules compile on all platforms — pure helpers are platform-independent;
// `tss-esapi` / `yubikey` bindings are gated to `cfg(target_os = "linux")`
// inside each module's `linux_backend` submodule.
#[cfg(feature = "tpm")]
pub mod tpm;

#[cfg(feature = "yubikey")]
pub mod yubikey;

#[cfg(feature = "test-support")]
pub mod test_support;

/// Runtime backend selection: pick the first available hardware backend,
/// honouring user preference from GSettings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendPreference {
    /// Automatic: try TPM first, then YubiKey.
    Auto,
    /// Force TPM; fail if unavailable.
    Tpm,
    /// Force YubiKey; fail if unavailable.
    YubiKey,
}

impl BackendPreference {
    /// Parse from GSettings enum nick (`auto` | `tpm` | `yubikey`).
    pub fn from_nick(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(BackendPreference::Auto),
            "tpm" => Some(BackendPreference::Tpm),
            "yubikey" => Some(BackendPreference::YubiKey),
            _ => None,
        }
    }

    /// Serialise to GSettings nick.
    pub fn as_nick(&self) -> &'static str {
        match self {
            BackendPreference::Auto => "auto",
            BackendPreference::Tpm => "tpm",
            BackendPreference::YubiKey => "yubikey",
        }
    }
}

#[cfg(test)]
mod backend_pref_tests {
    use super::BackendPreference::*;
    use super::*;

    #[test]
    fn from_nick_round_trips_all_variants() {
        for pref in [Auto, Tpm, YubiKey] {
            assert_eq!(BackendPreference::from_nick(pref.as_nick()), Some(pref));
        }
    }

    #[test]
    fn from_nick_rejects_unknown_values() {
        assert_eq!(BackendPreference::from_nick(""), None);
        assert_eq!(BackendPreference::from_nick("AUTO"), None); // case-sensitive
        assert_eq!(BackendPreference::from_nick("secure-enclave"), None);
    }

    #[test]
    fn as_nick_matches_gschema_enum_values() {
        // GSettings schema at data/org.sigilauth.Desktop.gschema.xml.in pins
        // these exact strings. Changing them is a migration-break.
        assert_eq!(Auto.as_nick(), "auto");
        assert_eq!(Tpm.as_nick(), "tpm");
        assert_eq!(YubiKey.as_nick(), "yubikey");
    }
}

/// Compressed SEC1-encoded P-256 public key (33 bytes, leading 0x02 or 0x03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedPublicKey(pub [u8; 33]);

impl CompressedPublicKey {
    /// The 33 raw bytes.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

/// ECDSA P-256 signature (r || s, 64 bytes). Low-S normalised per BIP-62.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// The 64 raw bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Attestation chain proving the key is hardware-bound.
/// Structure depends on backend; consumer verifies per Knox §3.6.
#[derive(Clone, Debug)]
pub struct AttestationChain {
    /// DER-encoded certificate chain, leaf first.
    pub certs: Vec<Vec<u8>>,
    /// Backend-specific attestation blob (TPM quote / Yubico attestation).
    pub attestation_blob: Vec<u8>,
}

/// Errors returned by hardware-key backends.
#[derive(Debug, Error)]
pub enum KeyError {
    /// The backend is not available on this system (no TPM, no YubiKey, etc.).
    #[error("hardware backend unavailable: {0}")]
    Unavailable(String),
    /// User declined the biometric or touch prompt.
    #[error("user presence declined")]
    UserDeclined,
    /// The operation timed out waiting for user presence.
    #[error("user presence timed out")]
    Timeout,
    /// The backend returned an error. Backend-specific source attached.
    #[error("backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Hardware-backed signing key. Implementations MUST keep the private key
/// in hardware; returning it in any form is a contract violation.
pub trait HardwareKey: Send + Sync {
    /// Compressed SEC1 P-256 public key, 33 bytes.
    fn public_key(&self) -> CompressedPublicKey;

    /// Sign `payload` after obtaining user presence. Blocks until the user
    /// approves or declines. Callers must invoke from an async task or
    /// worker thread; never from the GTK main loop.
    fn sign(&self, payload: &[u8]) -> Result<Signature, KeyError>;

    /// Backend-specific attestation proving hardware binding.
    fn attestation(&self) -> Result<AttestationChain, KeyError>;

    /// SHA-256 of the compressed public key.
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_bytes(self.public_key().as_bytes())
    }
}
