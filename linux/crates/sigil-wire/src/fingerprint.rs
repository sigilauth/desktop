//! Fingerprint = SHA-256(compressed SEC1 public key), hex-encoded lowercase.
//!
//! Per protocol-spec §1.3 + Knox threat model §3.2. Schema pattern at
//! `/api/schemas/challenge.json#/definitions/Fingerprint`: `^[a-f0-9]{64}$`.

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

/// Errors parsing a hex fingerprint.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FingerprintParseError {
    /// Wrong length (not 64 chars).
    #[error("fingerprint must be 64 hex characters, got {0}")]
    WrongLength(usize),
    /// Contains a non-lowercase or non-hex character.
    #[error("fingerprint must be lowercase ASCII hex [a-f0-9] — found {0:?}")]
    InvalidCharacter(char),
}

/// 32-byte SHA-256 fingerprint of a compressed public key.
///
/// Opaque: the raw bytes are not public. Compare via `PartialEq` or inspect
/// via `to_hex`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Compute a fingerprint over arbitrary bytes. In production this input is
    /// always a 33-byte compressed SEC1 public key, but the type does not
    /// enforce that — the caller does.
    pub fn from_bytes(input: &[u8]) -> Self {
        let digest = Sha256::digest(input);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Fingerprint(out)
    }

    /// Parse a 64-char lowercase-hex string into a fingerprint.
    ///
    /// Enforces the schema pattern at parse time: lowercase only, exact length.
    pub fn from_hex(s: &str) -> Result<Self, FingerprintParseError> {
        if s.len() != 64 {
            return Err(FingerprintParseError::WrongLength(s.len()));
        }
        // Reject any character outside [0-9a-f]. Uppercase rejected per schema.
        if let Some(bad) = s.chars().find(|c| !matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(FingerprintParseError::InvalidCharacter(bad));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex_nibble(s.as_bytes()[i * 2]);
            let lo = hex_nibble(s.as_bytes()[i * 2 + 1]);
            *byte = (hi << 4) | lo;
        }
        Ok(Fingerprint(out))
    }

    /// Hex-encode the fingerprint using lowercase.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(nibble_hex(byte >> 4));
            out.push(nibble_hex(byte & 0x0F));
        }
        out
    }

    /// Borrow the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hex_nibble(c: u8) -> u8 {
    // c is guaranteed to be in [0-9a-f] at this point.
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => unreachable!("validated above"),
    }
}

fn nibble_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!("nibble must be 0-15"),
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Fingerprint::from_hex(&s).map_err(de::Error::custom)
    }
}
