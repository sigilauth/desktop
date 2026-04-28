//! Domain-separated ECDSA P-256 signing and verification.
//!
//! Per `/api/domain-separation.md`: all signatures prepend a domain tag before
//! hashing to prevent cross-protocol confusion attacks.
//!
//! **Test vectors:** `/api/test-vectors/domain-separation/{auth,mpa,decrypt}-v1.json`
//! vendored to `tests/fixtures/domain-separation/` for standalone testing.

use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::{EncodedPoint, PublicKey, SecretKey};
use p256::elliptic_curve::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use sha2::{Digest, Sha256};
use thiserror::Error;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};

/// Authentication challenge/response domain tag (14 bytes including NUL).
pub const DOMAIN_AUTH: &[u8] = b"SIGIL-AUTH-V1\0";

/// Multi-party authorisation domain tag (13 bytes including NUL).
pub const DOMAIN_MPA: &[u8] = b"SIGIL-MPA-V1\0";

/// Secure decrypt envelope domain tag (17 bytes including NUL).
pub const DOMAIN_DECRYPT: &[u8] = b"SIGIL-DECRYPT-V1\0";

/// Conversation envelope domain tag (14 bytes including NUL).
pub const DOMAIN_CONV_V1: &[u8] = b"SIGIL-CONV-V1\0";

/// Pair handshake Argon2id salt domain tag (16 bytes, zero-padded).
pub const DOMAIN_PAIR_V1: &[u8] = b"SIGIL-PAIR-V1\0\0\0";

/// Errors from signing/verification operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,
    /// Invalid signature format.
    #[error("invalid signature format")]
    InvalidSignature,
    /// ECIES decryption failed.
    #[error("ECIES decryption failed")]
    DecryptionFailed,
    /// Invalid ciphertext format.
    #[error("invalid ciphertext format")]
    InvalidCiphertext,
}

/// Sign a message with domain separation.
///
/// Algorithm per `/api/domain-separation.md`:
/// 1. Concatenate `domain || message`
/// 2. Hash with SHA-256
/// 3. Sign the digest with ECDSA P-256
/// 4. Normalize S to low-S per BIP-62 (if S > N/2, replace with N - S)
/// 5. Return raw R||S bytes (64 bytes, low-S normalized)
///
/// Uses RFC 6979 deterministic signing (same key + message → same signature).
pub fn sign(key: &SigningKey, message: &[u8], domain: &[u8]) -> [u8; 64] {
    // Concatenate domain tag and message
    let mut tagged = Vec::with_capacity(domain.len() + message.len());
    tagged.extend_from_slice(domain);
    tagged.extend_from_slice(message);

    // Hash the tagged input
    let digest = Sha256::digest(&tagged);

    // Sign the digest (RFC 6979 deterministic)
    let signature: Signature = key.sign_prehash(&digest).expect("signing failed");

    // Normalize to low-S per BIP-62
    let normalized = signature.normalize_s().unwrap_or(signature);

    // Return raw R||S bytes (64 bytes)
    normalized.to_bytes().into()
}

/// Verify a signature with domain separation.
///
/// Returns `Ok(())` if signature is valid under the given domain tag.
/// Returns `Err(CryptoError::VerificationFailed)` if invalid.
///
/// **BIP-62 enforcement:** Rejects high-S signatures. Only low-S accepted per Knox §.
pub fn verify(
    pubkey: &VerifyingKey,
    message: &[u8],
    sig_bytes: &[u8; 64],
    domain: &[u8],
) -> Result<(), CryptoError> {
    // Parse signature from raw R||S bytes
    let signature =
        Signature::from_bytes(sig_bytes.into()).map_err(|_| CryptoError::InvalidSignature)?;

    // Reject high-S signatures (BIP-62 enforcement)
    // normalize_s() returns Some only if normalization is needed (high-S)
    if signature.normalize_s().is_some() {
        return Err(CryptoError::VerificationFailed);
    }

    // Concatenate domain tag and message (same as signing)
    let mut tagged = Vec::with_capacity(domain.len() + message.len());
    tagged.extend_from_slice(domain);
    tagged.extend_from_slice(message);

    // Hash the tagged input
    let digest = Sha256::digest(&tagged);

    // Verify the signature against the digest
    pubkey
        .verify_prehash(&digest, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// ECIES encrypt plaintext to a recipient's public key.
///
/// Algorithm per `/api/wire-protocol.md` §2.3:
/// 1. Generate fresh ephemeral P-256 keypair
/// 2. Perform ECDH with recipient static public key
/// 3. Derive AES-256 key via HKDF-SHA256(shared_secret, salt=fingerprint, info="SIGIL-CONV-V1-AES256")
/// 4. Encrypt with AES-256-GCM (96-bit nonce, ephemeral_public as AAD)
/// 5. Return: ephemeral_public (33) || nonce (12) || ciphertext || tag (16)
///
/// **CRITICAL:** Ephemeral keypair is generated fresh per call using platform CSPRNG.
/// Ephemeral key reuse breaks IND-CCA2 security.
pub fn ecies_encrypt(recipient_pubkey: &VerifyingKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();

    let recipient_pk = PublicKey::from(recipient_pubkey);
    let shared_secret = diffie_hellman(ephemeral_secret.to_nonzero_scalar(), recipient_pk.as_affine());

    let recipient_compressed = recipient_pk.to_encoded_point(true);
    let fingerprint = Sha256::digest(recipient_compressed.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(&fingerprint), shared_secret.raw_secret_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(b"SIGIL-CONV-V1-AES256", &mut aes_key)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let cipher = Aes256Gcm::new(&aes_key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ephemeral_compressed = ephemeral_public.to_encoded_point(true);
    let payload = Payload {
        msg: plaintext,
        aad: ephemeral_compressed.as_bytes(),
    };

    let ciphertext = cipher.encrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut envelope = Vec::with_capacity(33 + 12 + ciphertext.len());
    envelope.extend_from_slice(ephemeral_compressed.as_bytes());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

/// ECIES decrypt ciphertext with recipient's private key.
///
/// Wire format: ephemeral_public (33) || nonce (12) || ciphertext || tag (16)
///
/// Returns decrypted plaintext on success, or `CryptoError::DecryptionFailed` if:
/// - Invalid ciphertext format (wrong length)
/// - Invalid ephemeral public key encoding
/// - ECDH failure
/// - AES-GCM authentication tag verification failure
pub fn ecies_decrypt(recipient_privkey: &SigningKey, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if envelope.len() < 33 + 12 + 16 {
        return Err(CryptoError::InvalidCiphertext);
    }

    let ephemeral_pubkey_bytes = &envelope[0..33];
    let nonce_bytes = &envelope[33..45];
    let ciphertext_with_tag = &envelope[45..];

    let ephemeral_point = EncodedPoint::from_bytes(ephemeral_pubkey_bytes)
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    let ephemeral_pubkey = PublicKey::from_encoded_point(&ephemeral_point)
        .into_option()
        .ok_or(CryptoError::InvalidCiphertext)?;

    let recipient_secret = SecretKey::from(recipient_privkey);
    let shared_secret = diffie_hellman(recipient_secret.to_nonzero_scalar(), ephemeral_pubkey.as_affine());

    let recipient_public = recipient_secret.public_key();
    let recipient_compressed = recipient_public.to_encoded_point(true);
    let fingerprint = Sha256::digest(recipient_compressed.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(&fingerprint), shared_secret.raw_secret_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(b"SIGIL-CONV-V1-AES256", &mut aes_key)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let cipher = Aes256Gcm::new(&aes_key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext_with_tag,
        aad: ephemeral_pubkey_bytes,
    };

    cipher.decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{EncodedPoint, PublicKey, SecretKey};

    /// Test vector from auth-v1.json: sign challenge + action_context hash.
    #[test]
    fn auth_v1_vector_1_with_action_context() {
        use serde_json::json;

        // private_key_hex from test vector
        let privkey_bytes =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap();
        let secret_key = SecretKey::from_slice(&privkey_bytes).unwrap();
        let signing_key = SigningKey::from(secret_key);

        // challenge_bytes_hex: 32 random bytes
        let challenge_bytes = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        // action_context from test vector
        let action_context = json!({
            "type": "engine_login",
            "description": "Sign in to Engine Management",
            "user_id": "alice"
        });

        // Compute action_context hash
        let action_hash = action_context_hash(&action_context).unwrap();

        // Verify action_hash matches test vector
        let expected_action_hash =
            hex::decode("ae4c8d04ee09905ce0fbf5dd11c8733e92508ab00301b19d8e9da8f28b49b620")
                .unwrap();
        assert_eq!(
            action_hash.as_slice(),
            expected_action_hash.as_slice(),
            "action_context hash must match (RFC 8785 canonical JSON)"
        );

        // Build message: challenge_bytes || action_hash (64 bytes)
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(&challenge_bytes);
        message.extend_from_slice(&action_hash);

        // Sign with DOMAIN_AUTH
        let signature = sign(&signing_key, &message, DOMAIN_AUTH);

        // expected_signature_hex from test vector (updated for action_context binding)
        let expected_sig = hex::decode(
            "1500ac510b6b2cd7ed7400542d10ecf500a36e6f402b2f122afc15b8988e27c03a10c9d47aebcda59893507d3ad5bb75dd0fe5b94cecbbbb27c2522847cb1f02"
        ).unwrap();

        assert_eq!(
            signature.as_slice(),
            expected_sig.as_slice(),
            "Signature must match test vector byte-for-byte (RFC 6979 deterministic)"
        );
    }

    /// Test vector from auth-v1.json: verify signature with action_context.
    #[test]
    fn auth_v1_vector_1_verify() {
        // public_key_compressed_hex from test vector
        let pubkey_bytes =
            hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                .unwrap();
        let point = EncodedPoint::from_bytes(&pubkey_bytes).unwrap();
        let public_key = PublicKey::from_encoded_point(&point).unwrap();
        let verifying_key = VerifyingKey::from(&public_key);

        // message_hex: challenge_bytes || action_hash (64 bytes)
        let message = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefae4c8d04ee09905ce0fbf5dd11c8733e92508ab00301b19d8e9da8f28b49b620"
        )
        .unwrap();

        let signature = hex::decode(
            "1500ac510b6b2cd7ed7400542d10ecf500a36e6f402b2f122afc15b8988e27c03a10c9d47aebcda59893507d3ad5bb75dd0fe5b94cecbbbb27c2522847cb1f02"
        ).unwrap();
        let sig_array: [u8; 64] = signature.try_into().unwrap();

        // Verify with correct domain tag
        let result = verify(&verifying_key, &message, &sig_array, DOMAIN_AUTH);
        assert!(result.is_ok(), "Signature must verify with correct domain tag");
    }

    /// Test vector: empty action_context (canonical '{}').
    #[test]
    fn auth_v1_empty_action_context() {
        use serde_json::json;

        let privkey_bytes =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap();
        let secret_key = SecretKey::from_slice(&privkey_bytes).unwrap();
        let signing_key = SigningKey::from(secret_key);

        let challenge_bytes = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        // Empty action_context
        let empty_action = json!({});
        let action_hash = action_context_hash(&empty_action).unwrap();

        // Verify empty action hash matches the constant
        assert_eq!(
            action_hash, EMPTY_ACTION_HASH,
            "Empty action_context hash must match EMPTY_ACTION_HASH constant"
        );

        // Build message
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(&challenge_bytes);
        message.extend_from_slice(&action_hash);

        // Sign
        let signature = sign(&signing_key, &message, DOMAIN_AUTH);

        // Expected signature for empty action_context
        let expected_sig = hex::decode(
            "c8c48552aea9b31d6e1b14228598fc5db9c2ef23e31573c8957d96fc966347e4491183144065153ca605f0572fb655b54da99a92f7b7468ab22276e4ad36a6ea"
        ).unwrap();

        assert_eq!(
            signature.as_slice(),
            expected_sig.as_slice(),
            "Empty action_context signature must match test vector"
        );
    }

    /// Invalid case: signature with wrong domain tag must fail verification.
    #[test]
    fn auth_v1_wrong_domain_rejects() {
        let pubkey_bytes =
            hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                .unwrap();
        let point = EncodedPoint::from_bytes(&pubkey_bytes).unwrap();
        let public_key = PublicKey::from_encoded_point(&point).unwrap();
        let verifying_key = VerifyingKey::from(&public_key);

        // message_hex: challenge_bytes || action_hash (64 bytes)
        let message = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefae4c8d04ee09905ce0fbf5dd11c8733e92508ab00301b19d8e9da8f28b49b620"
        )
        .unwrap();

        let signature = hex::decode(
            "1500ac510b6b2cd7ed7400542d10ecf500a36e6f402b2f122afc15b8988e27c03a10c9d47aebcda59893507d3ad5bb75dd0fe5b94cecbbbb27c2522847cb1f02"
        ).unwrap();
        let sig_array: [u8; 64] = signature.try_into().unwrap();

        // Verify with WRONG domain tag (MPA instead of AUTH)
        let result = verify(&verifying_key, &message, &sig_array, DOMAIN_MPA);
        assert!(
            result.is_err(),
            "Signature produced with AUTH tag must NOT verify with MPA tag"
        );
    }

    /// Invalid case: signature without domain tag must fail verification.
    #[test]
    fn auth_v1_no_domain_rejects() {
        let pubkey_bytes =
            hex::decode("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
                .unwrap();
        let point = EncodedPoint::from_bytes(&pubkey_bytes).unwrap();
        let public_key = PublicKey::from_encoded_point(&point).unwrap();
        let verifying_key = VerifyingKey::from(&public_key);

        // message_hex: challenge_bytes || action_hash (64 bytes)
        let message = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefae4c8d04ee09905ce0fbf5dd11c8733e92508ab00301b19d8e9da8f28b49b620"
        )
        .unwrap();

        let signature = hex::decode(
            "1500ac510b6b2cd7ed7400542d10ecf500a36e6f402b2f122afc15b8988e27c03a10c9d47aebcda59893507d3ad5bb75dd0fe5b94cecbbbb27c2522847cb1f02"
        ).unwrap();
        let sig_array: [u8; 64] = signature.try_into().unwrap();

        // Verify with NO domain tag (empty slice)
        let result = verify(&verifying_key, &message, &sig_array, b"");
        assert!(
            result.is_err(),
            "Signature produced WITH domain tag must NOT verify WITHOUT domain tag"
        );
    }
}
