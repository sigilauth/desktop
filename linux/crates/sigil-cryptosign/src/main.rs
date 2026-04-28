//! CryptoSign CLI for SIGIL-CONV-V1 test harness.
//!
//! Provides byte-match validation for cross-implementation testing.
//! Used by Ava's test harness to verify Linux implementation matches
//! spec test vectors and other platform implementations.

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde::Deserialize;
use serde_json::json;
use sigil_wire::{crypto, envelope, nonce_store, session_pictogram};

#[derive(Parser)]
#[command(name = "sigil-cryptosign")]
#[command(about = "CryptoSign CLI for SIGIL-CONV-V1 test harness")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// ECIES encrypt plaintext to recipient public key
    EciesEncrypt {
        /// Recipient public key (hex, 33 bytes compressed)
        #[arg(long)]
        recipient_pubkey: String,
        /// Plaintext to encrypt (hex)
        #[arg(long)]
        plaintext: String,
    },
    /// ECIES decrypt ciphertext with private key
    EciesDecrypt {
        /// Recipient private key (hex, 32 bytes)
        #[arg(long)]
        privkey: String,
        /// Ciphertext (hex)
        #[arg(long)]
        ciphertext: String,
    },
    /// Derive session pictogram from pair handshake inputs
    SessionPictogram {
        /// Server public key (hex, 33 bytes compressed)
        #[arg(long)]
        server_pub: String,
        /// Client public key (hex, 33 bytes compressed)
        #[arg(long)]
        client_pub: String,
        /// Server nonce (hex, 32 bytes)
        #[arg(long)]
        server_nonce: String,
    },
    /// Sign message with domain tag
    Sign {
        /// Private key (hex, 32 bytes)
        #[arg(long)]
        privkey: String,
        /// Message to sign (hex)
        #[arg(long)]
        message: String,
        /// Domain tag
        #[arg(long)]
        domain: String,
    },
    /// Verify signature with domain tag
    Verify {
        /// Public key (hex, 33 bytes compressed)
        #[arg(long)]
        pubkey: String,
        /// Message (hex)
        #[arg(long)]
        message: String,
        /// Signature (hex, 64 bytes R||S)
        #[arg(long)]
        signature: String,
        /// Domain tag
        #[arg(long)]
        domain: String,
    },
    /// Build request envelope
    EnvelopeRequest {
        /// Client private key (hex, 32 bytes)
        #[arg(long)]
        client_privkey: String,
        /// Server public key (hex, 33 bytes compressed)
        #[arg(long)]
        server_pubkey: String,
        /// Request payload (JSON)
        #[arg(long)]
        payload: String,
    },
    /// Verify request envelope
    EnvelopeVerifyRequest {
        /// Server private key (hex, 32 bytes)
        #[arg(long)]
        server_privkey: String,
        /// Envelope (base64)
        #[arg(long)]
        envelope: String,
        /// Current timestamp (Unix seconds)
        #[arg(long)]
        timestamp: i64,
        /// Expected audience (hex SHA256)
        #[arg(long)]
        audience: String,
    },
    /// Build response envelope
    EnvelopeResponse {
        /// Server private key (hex, 32 bytes)
        #[arg(long)]
        server_privkey: String,
        /// Client public key (hex, 33 bytes compressed)
        #[arg(long)]
        client_pubkey: String,
        /// Response payload (JSON)
        #[arg(long)]
        payload: String,
    },
    /// Verify response envelope
    EnvelopeVerifyResponse {
        /// Client private key (hex, 32 bytes)
        #[arg(long)]
        client_privkey: String,
        /// Expected server public key (hex, 33 bytes compressed)
        #[arg(long)]
        server_pubkey: String,
        /// Envelope (base64)
        #[arg(long)]
        envelope: String,
        /// Current timestamp (Unix seconds)
        #[arg(long)]
        timestamp: i64,
    },
    /// Decrypt and verify generic ECIES envelope
    EnvelopeDecrypt {
        /// Recipient private key (hex, 32 bytes)
        #[arg(long)]
        recipient_priv_hex: String,
        /// ECIES envelope (base64)
        #[arg(long)]
        envelope_base64: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::EciesEncrypt { recipient_pubkey, plaintext } => {
            let pubkey_bytes = hex::decode(&recipient_pubkey)
                .context("Failed to decode recipient pubkey")?;
            let pubkey_point = p256::EncodedPoint::from_bytes(&pubkey_bytes)
                .context("Invalid public key encoding")?;
            let pubkey = PublicKey::from_encoded_point(&pubkey_point)
                .into_option()
                .context("Invalid public key")?;
            let verifying_key = VerifyingKey::from(&pubkey);

            let plaintext_bytes = hex::decode(&plaintext)
                .context("Failed to decode plaintext")?;

            let ciphertext = crypto::ecies_encrypt(&verifying_key, &plaintext_bytes)
                .context("ECIES encryption failed")?;

            println!("{}", json!({
                "ciphertext": hex::encode(&ciphertext),
                "length": ciphertext.len(),
            }));
        }

        Commands::EciesDecrypt { privkey, ciphertext } => {
            let privkey_bytes = hex::decode(&privkey)
                .context("Failed to decode private key")?;
            let secret_key = SecretKey::from_slice(&privkey_bytes)
                .context("Invalid private key")?;
            let signing_key = SigningKey::from(secret_key);

            let ciphertext_bytes = hex::decode(&ciphertext)
                .context("Failed to decode ciphertext")?;

            let plaintext = crypto::ecies_decrypt(&signing_key, &ciphertext_bytes)
                .context("ECIES decryption failed")?;

            println!("{}", json!({
                "plaintext": hex::encode(&plaintext),
                "length": plaintext.len(),
            }));
        }

        Commands::SessionPictogram { server_pub, client_pub, server_nonce } => {
            let server_pub_bytes: [u8; 33] = hex::decode(&server_pub)
                .context("Failed to decode server pubkey")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Server pubkey must be 33 bytes"))?;

            let client_pub_bytes: [u8; 33] = hex::decode(&client_pub)
                .context("Failed to decode client pubkey")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Client pubkey must be 33 bytes"))?;

            let server_nonce_bytes: [u8; 32] = hex::decode(&server_nonce)
                .context("Failed to decode server nonce")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Server nonce must be 32 bytes"))?;

            let pictogram = session_pictogram::derive(
                &server_pub_bytes,
                &client_pub_bytes,
                &server_nonce_bytes,
            )
            .context("Session pictogram derivation failed")?;

            let speakable = session_pictogram::speakable(&pictogram);

            println!("{}", json!({
                "pictogram": pictogram,
                "speakable": speakable,
            }));
        }

        Commands::Sign { privkey, message, domain } => {
            let privkey_bytes = hex::decode(&privkey)
                .context("Failed to decode private key")?;
            let secret_key = SecretKey::from_slice(&privkey_bytes)
                .context("Invalid private key")?;
            let signing_key = SigningKey::from(secret_key);

            let message_bytes = hex::decode(&message)
                .context("Failed to decode message")?;

            let domain_bytes = match domain.as_str() {
                "SIGIL-CONV-V1" => crypto::DOMAIN_CONV_V1,
                "SIGIL-PAIR-V1" => crypto::DOMAIN_PAIR_V1,
                "SIGIL-AUTH-V1" => crypto::DOMAIN_AUTH,
                "SIGIL-MPA-V1" => crypto::DOMAIN_MPA,
                "SIGIL-DECRYPT-V1" => crypto::DOMAIN_DECRYPT,
                _ => return Err(anyhow::anyhow!("Unknown domain tag: {}", domain)),
            };

            let signature = crypto::sign(&signing_key, &message_bytes, domain_bytes);

            println!("{}", json!({
                "signature": hex::encode(&signature),
            }));
        }

        Commands::Verify { pubkey, message, signature, domain } => {
            let pubkey_bytes = hex::decode(&pubkey)
                .context("Failed to decode public key")?;
            let pubkey_point = p256::EncodedPoint::from_bytes(&pubkey_bytes)
                .context("Invalid public key encoding")?;
            let pubkey_pk = PublicKey::from_encoded_point(&pubkey_point)
                .into_option()
                .context("Invalid public key")?;
            let verifying_key = VerifyingKey::from(&pubkey_pk);

            let message_bytes = hex::decode(&message)
                .context("Failed to decode message")?;

            let signature_bytes: [u8; 64] = hex::decode(&signature)
                .context("Failed to decode signature")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;

            let domain_bytes = match domain.as_str() {
                "SIGIL-CONV-V1" => crypto::DOMAIN_CONV_V1,
                "SIGIL-PAIR-V1" => crypto::DOMAIN_PAIR_V1,
                "SIGIL-AUTH-V1" => crypto::DOMAIN_AUTH,
                "SIGIL-MPA-V1" => crypto::DOMAIN_MPA,
                "SIGIL-DECRYPT-V1" => crypto::DOMAIN_DECRYPT,
                _ => return Err(anyhow::anyhow!("Unknown domain tag: {}", domain)),
            };

            let result = crypto::verify(&verifying_key, &message_bytes, &signature_bytes, domain_bytes);

            println!("{}", json!({
                "valid": result.is_ok(),
            }));
        }

        Commands::EnvelopeRequest { client_privkey, server_pubkey, payload } => {
            let client_privkey_bytes = hex::decode(&client_privkey)
                .context("Failed to decode client private key")?;
            let client_secret = SecretKey::from_slice(&client_privkey_bytes)
                .context("Invalid client private key")?;
            let client_signing_key = SigningKey::from(client_secret);

            let server_pubkey_bytes = hex::decode(&server_pubkey)
                .context("Failed to decode server public key")?;
            let server_pubkey_point = p256::EncodedPoint::from_bytes(&server_pubkey_bytes)
                .context("Invalid server public key encoding")?;
            let server_pk = PublicKey::from_encoded_point(&server_pubkey_point)
                .into_option()
                .context("Invalid server public key")?;
            let server_verifying_key = VerifyingKey::from(&server_pk);

            let request_payload: envelope::RequestPayload = serde_json::from_str(&payload)
                .context("Failed to parse request payload JSON")?;

            let envelope_b64 = envelope::build_request(&client_signing_key, &server_verifying_key, &request_payload)
                .context("Failed to build request envelope")?;

            println!("{}", json!({
                "envelope": envelope_b64,
            }));
        }

        Commands::EnvelopeVerifyRequest { server_privkey, envelope, timestamp, audience } => {
            let server_privkey_bytes = hex::decode(&server_privkey)
                .context("Failed to decode server private key")?;
            let server_secret = SecretKey::from_slice(&server_privkey_bytes)
                .context("Invalid server private key")?;
            let server_signing_key = SigningKey::from(server_secret);

            let nonce_store = nonce_store::NonceStore::new();
            let result = envelope::verify_request(&server_signing_key, &envelope, timestamp, &audience, &nonce_store);

            match result {
                Ok((client_pubkey, payload)) => {
                    let client_pubkey_compressed = client_pubkey.to_encoded_point(true);
                    println!("{}", json!({
                        "valid": true,
                        "client_pubkey": hex::encode(client_pubkey_compressed.as_bytes()),
                        "payload": payload,
                    }));
                }
                Err(e) => {
                    println!("{}", json!({
                        "valid": false,
                        "error": e.to_string(),
                    }));
                }
            }
        }

        Commands::EnvelopeResponse { server_privkey, client_pubkey, payload } => {
            let server_privkey_bytes = hex::decode(&server_privkey)
                .context("Failed to decode server private key")?;
            let server_secret = SecretKey::from_slice(&server_privkey_bytes)
                .context("Invalid server private key")?;
            let server_signing_key = SigningKey::from(server_secret);

            let client_pubkey_bytes = hex::decode(&client_pubkey)
                .context("Failed to decode client public key")?;
            let client_pubkey_point = p256::EncodedPoint::from_bytes(&client_pubkey_bytes)
                .context("Invalid client public key encoding")?;
            let client_pk = PublicKey::from_encoded_point(&client_pubkey_point)
                .into_option()
                .context("Invalid client public key")?;
            let client_verifying_key = VerifyingKey::from(&client_pk);

            let response_payload: envelope::ResponsePayload = serde_json::from_str(&payload)
                .context("Failed to parse response payload JSON")?;

            let envelope_b64 = envelope::build_response(&server_signing_key, &client_verifying_key, &response_payload)
                .context("Failed to build response envelope")?;

            println!("{}", json!({
                "envelope": envelope_b64,
            }));
        }

        Commands::EnvelopeVerifyResponse { client_privkey, server_pubkey, envelope, timestamp } => {
            let client_privkey_bytes = hex::decode(&client_privkey)
                .context("Failed to decode client private key")?;
            let client_secret = SecretKey::from_slice(&client_privkey_bytes)
                .context("Invalid client private key")?;
            let client_signing_key = SigningKey::from(client_secret);

            let server_pubkey_bytes = hex::decode(&server_pubkey)
                .context("Failed to decode server public key")?;
            let server_pubkey_point = p256::EncodedPoint::from_bytes(&server_pubkey_bytes)
                .context("Invalid server public key encoding")?;
            let server_pk = PublicKey::from_encoded_point(&server_pubkey_point)
                .into_option()
                .context("Invalid server public key")?;
            let server_verifying_key = VerifyingKey::from(&server_pk);

            let nonce_store = nonce_store::NonceStore::new();
            let result = envelope::verify_response(&client_signing_key, &envelope, timestamp, &server_verifying_key, &nonce_store);

            match result {
                Ok(payload) => {
                    println!("{}", json!({
                        "valid": true,
                        "payload": payload,
                    }));
                }
                Err(e) => {
                    println!("{}", json!({
                        "valid": false,
                        "error": e.to_string(),
                    }));
                }
            }
        }

        Commands::EnvelopeDecrypt { recipient_priv_hex, envelope_base64 } => {
            // Helper to exit with error code and message
            let exit_with_error = |code: i32, error_type: &str| -> ! {
                eprintln!("{}", error_type);
                std::process::exit(code);
            };

            // Decode recipient private key
            let privkey_bytes = match hex::decode(&recipient_priv_hex) {
                Ok(b) => b,
                Err(_) => exit_with_error(1, "ENVELOPE_INVALID"),
            };
            let secret_key = match SecretKey::from_slice(&privkey_bytes) {
                Ok(k) => k,
                Err(_) => exit_with_error(1, "ENVELOPE_INVALID"),
            };
            let signing_key = SigningKey::from(secret_key);

            // Decode envelope from base64
            let envelope_bytes = match base64::engine::general_purpose::STANDARD.decode(&envelope_base64) {
                Ok(b) => b,
                Err(_) => exit_with_error(1, "ENVELOPE_INVALID"),
            };

            // ECIES decrypt outer envelope
            let inner_json = match crypto::ecies_decrypt(&signing_key, &envelope_bytes) {
                Ok(j) => j,
                Err(_) => exit_with_error(2, "DECRYPTION_FAILED"),
            };

            // Parse inner JSON structure
            #[derive(Deserialize)]
            struct InnerEnvelope {
                client_public_key: String,
                payload: String,
                signature: String,
            }

            let inner: InnerEnvelope = match serde_json::from_slice(&inner_json) {
                Ok(i) => i,
                Err(_) => exit_with_error(1, "ENVELOPE_INVALID"),
            };

            // Decode client public key (base64 per spec line 1060)
            let client_pubkey_bytes = match base64::engine::general_purpose::STANDARD.decode(&inner.client_public_key) {
                Ok(b) => b,
                Err(_) => exit_with_error(1, "ENVELOPE_INVALID"),
            };
            let client_pubkey_point = match p256::EncodedPoint::from_bytes(&client_pubkey_bytes) {
                Ok(p) => p,
                Err(_) => exit_with_error(1, "ENVELOPE_INVALID"),
            };
            let client_pk = match PublicKey::from_encoded_point(&client_pubkey_point).into_option() {
                Some(k) => k,
                None => exit_with_error(1, "ENVELOPE_INVALID"),
            };
            let client_verifying_key = VerifyingKey::from(&client_pk);

            // Decode signature (base64 per spec line 1060)
            let signature_bytes: [u8; 64] = match base64::engine::general_purpose::STANDARD.decode(&inner.signature) {
                Ok(s) => match s.try_into() {
                    Ok(arr) => arr,
                    Err(_) => exit_with_error(2, "SIGNATURE_MALFORMED"),
                },
                Err(_) => exit_with_error(2, "SIGNATURE_MALFORMED"),
            };

            // Parse payload and validate required fields (ADV-07 protection)
            #[derive(Deserialize)]
            struct PayloadFields {
                action: Option<String>,
                nonce: Option<String>,
                timestamp: Option<i64>,
                audience: Option<String>,
                body: Option<serde_json::Value>,
            }

            let payload_parsed: PayloadFields = match serde_json::from_str(&inner.payload) {
                Ok(p) => p,
                Err(_) => exit_with_error(2, "ENVELOPE_INVALID"),
            };

            // Validate all required fields present (ADV-07)
            if payload_parsed.action.is_none() || payload_parsed.nonce.is_none()
                || payload_parsed.timestamp.is_none() || payload_parsed.audience.is_none()
                || payload_parsed.body.is_none() {
                exit_with_error(2, "ENVELOPE_INVALID");
            }

            // Re-canonicalize payload before signature verification (ADV-10 protection)
            let payload_canonical = match serde_jcs::to_vec(&serde_json::from_str::<serde_json::Value>(&inner.payload).unwrap()) {
                Ok(c) => c,
                Err(_) => exit_with_error(2, "ENVELOPE_INVALID"),
            };

            // Verify signature against canonical payload with SIGIL-CONV-V1 domain
            if let Err(_) = crypto::verify(&client_verifying_key, &payload_canonical, &signature_bytes, crypto::DOMAIN_CONV_V1) {
                exit_with_error(2, "INVALID_SIGNATURE");
            }

            // Output canonical JSON
            print!("{}", String::from_utf8_lossy(&payload_canonical));
            std::process::exit(0);
        }
    }

    Ok(())
}
