//! Sign-then-encrypt envelope construction and verification.
//!
//! Algorithm per `/api/wire-protocol.md` §5:
//! 1. Canonicalize payload (RFC 8785)
//! 2. Sign with ECDSA P-256 + domain tag "SIGIL-CONV-V1\x00"
//! 3. Build inner envelope: {client_public_key, payload, signature}
//! 4. Canonicalize inner envelope
//! 5. ECIES encrypt to recipient
//! 6. Base64-encode outer ciphertext
//!
//! **Request envelope:**
//! - Payload includes: action, body, timestamp, nonce, audience
//! - Client signs, encrypts to server
//!
//! **Response envelope:**
//! - Payload includes: status, body, timestamp, nonce (no audience)
//! - Server signs, encrypts to client

use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use p256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use base64::{Engine as _, engine::general_purpose};

use crate::crypto::{self, CryptoError, DOMAIN_CONV_V1};
use crate::nonce_store::{NonceStore, NonceError};

/// Envelope construction and verification errors.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// Canonical JSON serialization failed.
    #[error("canonical JSON serialization failed: {0}")]
    SerializationFailed(#[from] serde_json::Error),
    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    /// Base64 decode failed.
    #[error("base64 decode failed")]
    Base64DecodeFailed,
    /// Invalid envelope structure.
    #[error("invalid envelope structure")]
    InvalidStructure,
    /// Timestamp expired (window: 300s).
    #[error("timestamp expired (window: 300s)")]
    TimestampExpired,
    /// Audience mismatch.
    #[error("audience mismatch")]
    AudienceMismatch,
    /// Nonce reused (replay attack).
    #[error("nonce reused: {0}")]
    NonceReused(#[from] NonceError),
}

/// Request envelope payload structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPayload {
    /// Action type (e.g., "challenge.create").
    pub action: String,
    /// Action-specific body.
    pub body: serde_json::Value,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// 16-byte random nonce (hex-encoded).
    pub nonce: String,
    /// SHA256(server_public_key) in hex.
    pub audience: String,
}

/// Response envelope payload structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePayload {
    /// Status (e.g., "ok", "error").
    pub status: String,
    /// Response body.
    pub body: serde_json::Value,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// 16-byte random nonce (hex-encoded).
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InnerEnvelope {
    client_public_key: String,
    payload: String,
    signature: String,
}

/// Outer envelope wrapper for HTTP transport.
#[derive(Debug, Serialize, Deserialize)]
pub struct OuterEnvelope {
    /// Base64-encoded ciphertext.
    pub envelope: String,
}

/// Build and encrypt a request envelope.
///
/// Returns base64-encoded outer ciphertext ready for `POST /envelope`.
pub fn build_request(
    client_privkey: &SigningKey,
    server_pubkey: &VerifyingKey,
    payload: &RequestPayload,
) -> Result<String, EnvelopeError> {
    let canonical_payload = serde_jcs::to_string(payload)?;

    let signature = crypto::sign(client_privkey, canonical_payload.as_bytes(), DOMAIN_CONV_V1);

    let client_pubkey = VerifyingKey::from(client_privkey);
    let client_pubkey_compressed = client_pubkey.to_encoded_point(true);

    let inner = InnerEnvelope {
        client_public_key: general_purpose::STANDARD.encode(client_pubkey_compressed.as_bytes()),
        payload: canonical_payload,
        signature: general_purpose::STANDARD.encode(&signature),
    };

    let inner_json = serde_jcs::to_string(&inner)?;

    let outer_ciphertext = crypto::ecies_encrypt(server_pubkey, inner_json.as_bytes())?;

    Ok(general_purpose::STANDARD.encode(&outer_ciphertext))
}

/// Verify and decrypt a request envelope.
///
/// Returns (client_pubkey, payload) on success.
///
/// **Replay protection:** Checks nonce against `nonce_store`. Rejects if nonce seen within 300s window.
pub fn verify_request(
    server_privkey: &SigningKey,
    envelope_b64: &str,
    current_timestamp: i64,
    expected_audience: &str,
    nonce_store: &NonceStore,
) -> Result<(VerifyingKey, RequestPayload), EnvelopeError> {
    let outer_ciphertext = general_purpose::STANDARD.decode(envelope_b64)
        .map_err(|_| EnvelopeError::Base64DecodeFailed)?;

    let inner_json = crypto::ecies_decrypt(server_privkey, &outer_ciphertext)?;

    let inner: InnerEnvelope = serde_json::from_slice(&inner_json)?;

    let client_pubkey_bytes = general_purpose::STANDARD.decode(&inner.client_public_key)
        .map_err(|_| EnvelopeError::InvalidStructure)?;
    let client_pubkey_point = p256::EncodedPoint::from_bytes(&client_pubkey_bytes)
        .map_err(|_| EnvelopeError::InvalidStructure)?;
    let client_pubkey = PublicKey::from_encoded_point(&client_pubkey_point)
        .into_option()
        .ok_or(EnvelopeError::InvalidStructure)?;
    let client_verifying_key = VerifyingKey::from(&client_pubkey);

    let signature_bytes = general_purpose::STANDARD.decode(&inner.signature)
        .map_err(|_| EnvelopeError::InvalidStructure)?;
    let signature: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| EnvelopeError::InvalidStructure)?;

    crypto::verify(
        &client_verifying_key,
        inner.payload.as_bytes(),
        &signature,
        DOMAIN_CONV_V1,
    )?;

    let payload: RequestPayload = serde_json::from_str(&inner.payload)?;

    let time_delta = (current_timestamp - payload.timestamp).abs();
    if time_delta > 300 {
        return Err(EnvelopeError::TimestampExpired);
    }

    if payload.audience != expected_audience {
        return Err(EnvelopeError::AudienceMismatch);
    }

    nonce_store.check_and_insert(&payload.nonce)?;

    Ok((client_verifying_key, payload))
}

/// Build and encrypt a response envelope.
///
/// Returns base64-encoded outer ciphertext.
pub fn build_response(
    server_privkey: &SigningKey,
    client_pubkey: &VerifyingKey,
    payload: &ResponsePayload,
) -> Result<String, EnvelopeError> {
    let canonical_payload = serde_jcs::to_string(payload)?;

    let signature = crypto::sign(server_privkey, canonical_payload.as_bytes(), DOMAIN_CONV_V1);

    let server_pubkey = VerifyingKey::from(server_privkey);
    let server_pubkey_compressed = server_pubkey.to_encoded_point(true);

    let inner = InnerEnvelope {
        client_public_key: general_purpose::STANDARD.encode(server_pubkey_compressed.as_bytes()),
        payload: canonical_payload,
        signature: general_purpose::STANDARD.encode(&signature),
    };

    let inner_json = serde_jcs::to_string(&inner)?;

    let outer_ciphertext = crypto::ecies_encrypt(client_pubkey, inner_json.as_bytes())?;

    Ok(general_purpose::STANDARD.encode(&outer_ciphertext))
}

/// Verify and decrypt a response envelope.
///
/// Returns (server_pubkey, payload) on success.
///
/// **Replay protection:** Checks nonce against `nonce_store`. Rejects if nonce seen within 300s window.
pub fn verify_response(
    client_privkey: &SigningKey,
    envelope_b64: &str,
    current_timestamp: i64,
    expected_server_pubkey: &VerifyingKey,
    nonce_store: &NonceStore,
) -> Result<ResponsePayload, EnvelopeError> {
    let outer_ciphertext = general_purpose::STANDARD.decode(envelope_b64)
        .map_err(|_| EnvelopeError::Base64DecodeFailed)?;

    let inner_json = crypto::ecies_decrypt(client_privkey, &outer_ciphertext)?;

    let inner: InnerEnvelope = serde_json::from_slice(&inner_json)?;

    let server_pubkey_bytes = general_purpose::STANDARD.decode(&inner.client_public_key)
        .map_err(|_| EnvelopeError::InvalidStructure)?;
    let server_pubkey_point = p256::EncodedPoint::from_bytes(&server_pubkey_bytes)
        .map_err(|_| EnvelopeError::InvalidStructure)?;
    let server_pubkey = PublicKey::from_encoded_point(&server_pubkey_point)
        .into_option()
        .ok_or(EnvelopeError::InvalidStructure)?;
    let server_verifying_key = VerifyingKey::from(&server_pubkey);

    if server_verifying_key.to_encoded_point(true) != expected_server_pubkey.to_encoded_point(true) {
        return Err(EnvelopeError::InvalidStructure);
    }

    let signature_bytes = general_purpose::STANDARD.decode(&inner.signature)
        .map_err(|_| EnvelopeError::InvalidStructure)?;
    let signature: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| EnvelopeError::InvalidStructure)?;

    crypto::verify(
        &server_verifying_key,
        inner.payload.as_bytes(),
        &signature,
        DOMAIN_CONV_V1,
    )?;

    let payload: ResponsePayload = serde_json::from_str(&inner.payload)?;

    let time_delta = (current_timestamp - payload.timestamp).abs();
    if time_delta > 300 {
        return Err(EnvelopeError::TimestampExpired);
    }

    nonce_store.check_and_insert(&payload.nonce)?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;

    #[test]
    fn roundtrip_request() {
        let client_secret = SecretKey::random(&mut rand_core::OsRng);
        let client_privkey = SigningKey::from(&client_secret);
        let server_secret = SecretKey::random(&mut rand_core::OsRng);
        let server_privkey = SigningKey::from(&server_secret);
        let server_pubkey = VerifyingKey::from(&server_privkey);

        let server_pubkey_compressed = server_pubkey.to_encoded_point(true);
        let audience = format!("{:x}", Sha256::digest(server_pubkey_compressed.as_bytes()));

        let payload = RequestPayload {
            action: "challenge.create".to_string(),
            body: serde_json::json!({"test": "data"}),
            timestamp: 1714122000,
            nonce: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".to_string(),
            audience: audience.clone(),
        };

        let envelope_b64 = build_request(&client_privkey, &server_pubkey, &payload).unwrap();

        let nonce_store = NonceStore::new();
        let (recovered_client_pubkey, recovered_payload) =
            verify_request(&server_privkey, &envelope_b64, 1714122000, &audience, &nonce_store).unwrap();

        let client_pubkey = VerifyingKey::from(&client_privkey);
        assert_eq!(
            recovered_client_pubkey.to_encoded_point(true),
            client_pubkey.to_encoded_point(true)
        );
        assert_eq!(recovered_payload.action, payload.action);
        assert_eq!(recovered_payload.timestamp, payload.timestamp);
        assert_eq!(recovered_payload.nonce, payload.nonce);
    }

    #[test]
    fn roundtrip_response() {
        let server_secret = SecretKey::random(&mut rand_core::OsRng);
        let server_privkey = SigningKey::from(&server_secret);
        let server_pubkey = VerifyingKey::from(&server_privkey);
        let client_secret = SecretKey::random(&mut rand_core::OsRng);
        let client_privkey = SigningKey::from(&client_secret);
        let client_pubkey = VerifyingKey::from(&client_privkey);

        let payload = ResponsePayload {
            status: "ok".to_string(),
            body: serde_json::json!({"result": "success"}),
            timestamp: 1714122005,
            nonce: "f0e1d2c3b4a59687f1e2d3c4b5a69708".to_string(),
        };

        let envelope_b64 = build_response(&server_privkey, &client_pubkey, &payload).unwrap();

        let nonce_store = NonceStore::new();
        let recovered_payload =
            verify_response(&client_privkey, &envelope_b64, 1714122005, &server_pubkey, &nonce_store).unwrap();

        assert_eq!(recovered_payload.status, payload.status);
        assert_eq!(recovered_payload.timestamp, payload.timestamp);
        assert_eq!(recovered_payload.nonce, payload.nonce);
    }

    #[test]
    fn reject_expired_timestamp() {
        let client_secret = SecretKey::random(&mut rand_core::OsRng);
        let client_privkey = SigningKey::from(&client_secret);
        let server_secret = SecretKey::random(&mut rand_core::OsRng);
        let server_privkey = SigningKey::from(&server_secret);
        let server_pubkey = VerifyingKey::from(&server_privkey);

        let server_pubkey_compressed = server_pubkey.to_encoded_point(true);
        let audience = format!("{:x}", Sha256::digest(server_pubkey_compressed.as_bytes()));

        let payload = RequestPayload {
            action: "challenge.create".to_string(),
            body: serde_json::json!({}),
            timestamp: 1714122000,
            nonce: "test".to_string(),
            audience,
        };

        let envelope_b64 = build_request(&client_privkey, &server_pubkey, &payload).unwrap();

        let nonce_store = NonceStore::new();
        let result = verify_request(
            &server_privkey,
            &envelope_b64,
            1714122000 + 400,
            &payload.audience,
            &nonce_store,
        );

        assert!(matches!(result, Err(EnvelopeError::TimestampExpired)));
    }
}
