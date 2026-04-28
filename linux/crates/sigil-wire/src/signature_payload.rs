//! Signature payload construction.
//!
//! Both sides hash *exactly* the same bytes before ECDSA-signing, or verification
//! fails. Every sign site in this codebase routes through these helpers; no
//! ad-hoc concatenation allowed elsewhere.
//!
//! # Server-signed challenge payload (Knox §3.3)
//!
//! `SHA-256(challenge_id_ascii || fingerprint_hex_ascii || challenge_bytes_raw
//!   || action_json_canonical || timestamp_ascii)`
//!
//! # Device-signed response payload
//!
//! `SHA-256(challenge_id_ascii || challenge_bytes_raw || timestamp_ascii)`
//!
//! # Canonical action JSON
//!
//! The `action` object is JSON-encoded with **sorted keys** and **no
//! whitespace** to guarantee bit-identical hashing across server and device.
//! Without canonicalisation, server and device libraries could choose
//! different key orders and every signature would be rejected.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::wire::{Action, ChallengeNotification};

/// Errors reconstructing a signature payload from wire data.
#[derive(Debug, Error)]
pub enum PayloadError {
    /// The `challenge_bytes` field was not valid base64.
    #[error("challenge_bytes not valid base64: {0}")]
    BadBase64(#[from] base64::DecodeError),
    /// The action object could not be re-serialised canonically.
    #[error("action JSON serialisation failed: {0}")]
    ActionSerde(#[from] serde_json::Error),
}

/// Build the server's signing payload from fully-decoded components.
///
/// Returns the 32-byte SHA-256 digest.
pub fn server_challenge_payload(
    challenge_id: &str,
    fingerprint_hex: &str,
    challenge_bytes: &[u8],
    action_canonical_json: &str,
    timestamp: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge_id.as_bytes());
    hasher.update(fingerprint_hex.as_bytes());
    hasher.update(challenge_bytes);
    hasher.update(action_canonical_json.as_bytes());
    hasher.update(timestamp.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Build the device's response signing payload.
pub fn device_response_payload(
    challenge_id: &str,
    challenge_bytes: &[u8],
    timestamp: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge_id.as_bytes());
    hasher.update(challenge_bytes);
    hasher.update(timestamp.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Canonicalise an `Action` to JSON with sorted keys and no whitespace.
///
/// Used for both signing (server) and signature-verification (device).
pub fn canonical_action_json(action: &Action) -> String {
    // serde_json sorts keys alphabetically when `preserve_order` is NOT enabled
    // (the default) and we go through a `Value` intermediate. Nested objects
    // are sorted recursively by walking the Value tree.
    let value: Value = serde_json::to_value(action).expect("Action always serialises");
    canonical_json(&value)
}

/// Canonical JSON: sorted object keys, arrays preserved, compact separators.
fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(&mut out, value);
    out
}

fn write_canonical(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).expect("string serialise"));
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("key serialise"));
                out.push(':');
                write_canonical(out, &map[*key]);
            }
            out.push('}');
        }
    }
}

impl ChallengeNotification {
    /// Reconstruct the 32-byte payload the server hashed when signing.
    /// The device calls this to verify `server_signature` before displaying
    /// action context to the user — Knox §8.2 "action context display".
    pub fn reconstruct_server_payload(
        &self,
        fingerprint_hex: &str,
    ) -> Result<[u8; 32], PayloadError> {
        let challenge_bytes_raw = STANDARD.decode(&self.challenge_bytes)?;
        let action_canonical = canonical_action_json(&self.action);
        Ok(server_challenge_payload(
            &self.challenge_id,
            fingerprint_hex,
            &challenge_bytes_raw,
            &action_canonical,
            &self.expires_at, // timestamp component; see §Open Question below
        ))
    }
}

// OPEN QUESTION (flagged to @beacon/@echo/@knox):
//
// Knox §3.3 specifies the server signs over `... || timestamp`. The wire
// notification contains `expires_at`, not `created_at` or a `timestamp` field.
// I'm using `expires_at` as the timestamp component in the reconstruction
// (they are typically `created_at + 5min`, and the server signs whichever it
// sent in the wire). But this needs explicit confirmation in the protocol
// spec — `expires_at` is the only ISO-8601 timestamp on the wire so it has to
// be it, but the spec text calls it "timestamp" ambiguously.
//
// If the canonical source is `expires_at` this is correct. If it's a separate
// `created_at` or `timestamp` field not yet on the wire, B0 needs amending.
