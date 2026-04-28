//! SIGIL-CONV-V1 pictogram pair flow orchestration.
//!
//! State machine: idle → fetch_server_pubkey → derive_pictogram → display →
//! confirm/deny → POST /pair/complete → persist to libsecret.
//!
//! Reference implementation: cli-device/cmd/sigil-device/cmd_pair.go:60-217

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sigil_wire::session_pictogram;

/// Pair init response from GET /pair/init?client_pub=<base64>
#[derive(Debug, Deserialize)]
struct PairInitResponse {
    server_public_key: String,
    server_nonce: String,
    session_pictogram_speakable: String,
    expires_at: String,
}

/// Pair complete request for POST /pair/complete
#[derive(Debug, Serialize)]
struct PairCompleteRequest {
    server_nonce: String,
    client_public_key: String,
    device_info: DeviceInfo,
}

#[derive(Debug, Serialize)]
struct DeviceInfo {
    name: String,
    platform: String,
    os_version: String,
}

/// Pair complete response
#[derive(Debug, Deserialize)]
struct PairCompleteResponse {
    status: String,
}

/// Pair flow session state.
///
/// Holds intermediate data between init and complete phases.
#[derive(Clone)]
pub struct PairFlowSession {
    pub server_url: String,
    pub server_nonce: String,
    pub server_public_key: String,
    pub device_public_key_b64: String,
    pub pictogram: [(String, String); 6],
}

/// Initialize pair handshake (phase 1).
///
/// Steps:
/// 1. GET /pair/init with device public key
/// 2. Derive session pictogram locally (Argon2id)
/// 3. Verify server's pictogram matches
///
/// Returns PairFlowSession with pictogram for UI display.
/// Caller should show SessionPictogramView and call complete_pair on confirmation.
pub async fn init_pair(
    server_url: &str,
    device_public_key_b64: &str,
) -> Result<PairFlowSession> {
    tracing::info!(server_url, "starting pair flow");

    // Step 1: GET /pair/init
    let init_url = format!("{}/pair/init?client_pub={}", server_url,
        urlencoding::encode(device_public_key_b64));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client")?;

    let resp = client.get(&init_url)
        .send()
        .await
        .context("failed to connect to server")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("server returned {}: {}", status, body);
    }

    let init_resp: PairInitResponse = resp.json()
        .await
        .context("failed to parse server response")?;

    // Validate response fields
    if init_resp.server_public_key.is_empty() {
        anyhow::bail!("server response missing server_public_key");
    }
    if init_resp.server_nonce.is_empty() {
        anyhow::bail!("server response missing server_nonce");
    }

    // Decode server public key
    let server_pubkey_bytes = base64::engine::general_purpose::STANDARD
        .decode(&init_resp.server_public_key)
        .context("invalid server public key format")?;

    if server_pubkey_bytes.len() != 33 {
        anyhow::bail!("server public key must be 33 bytes, got {}", server_pubkey_bytes.len());
    }

    // Decode server nonce
    let server_nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&init_resp.server_nonce)
        .context("invalid server nonce format")?;

    if server_nonce_bytes.len() != 32 {
        anyhow::bail!("server nonce must be 32 bytes, got {}", server_nonce_bytes.len());
    }

    // Decode client public key
    let client_pubkey_bytes = base64::engine::general_purpose::STANDARD
        .decode(device_public_key_b64)
        .context("invalid client public key format")?;

    if client_pubkey_bytes.len() != 33 {
        anyhow::bail!("client public key must be 33 bytes, got {}", client_pubkey_bytes.len());
    }

    // Step 2: Derive session pictogram locally (Argon2id per spec §4.2)
    let server_pub: [u8; 33] = server_pubkey_bytes.try_into().unwrap();
    let client_pub: [u8; 33] = client_pubkey_bytes.try_into().unwrap();
    let server_nonce: [u8; 32] = server_nonce_bytes.try_into().unwrap();

    let pictogram = session_pictogram::derive(&server_pub, &client_pub, &server_nonce)
        .context("failed to derive session pictogram")?;

    // Build pictogram array for SessionPictogramView
    let pictogram_array: [(String, String); 6] = [
        (pictogram[0].emoji.clone(), pictogram[0].word.clone()),
        (pictogram[1].emoji.clone(), pictogram[1].word.clone()),
        (pictogram[2].emoji.clone(), pictogram[2].word.clone()),
        (pictogram[3].emoji.clone(), pictogram[3].word.clone()),
        (pictogram[4].emoji.clone(), pictogram[4].word.clone()),
        (pictogram[5].emoji.clone(), pictogram[5].word.clone()),
    ];

    // Verify server's pictogram matches our derivation
    let local_speakable = pictogram.iter()
        .map(|p| p.word.as_str())
        .collect::<Vec<_>>()
        .join(" ");

    if init_resp.session_pictogram_speakable != local_speakable {
        tracing::error!(
            local = %local_speakable,
            server = %init_resp.session_pictogram_speakable,
            "PICTOGRAM MISMATCH - POSSIBLE MITM ATTACK"
        );
        anyhow::bail!("session pictogram mismatch — MITM attack detected");
    }

    tracing::info!("session pictogram verified");

    // Return session state for UI display + user confirmation
    Ok(PairFlowSession {
        server_url: server_url.to_string(),
        server_nonce: init_resp.server_nonce,
        server_public_key: init_resp.server_public_key,
        device_public_key_b64: device_public_key_b64.to_string(),
        pictogram: pictogram_array,
    })
}

/// Complete pair handshake (phase 2).
///
/// Steps:
/// 1. POST /pair/complete with server nonce
/// 2. Persist server record to libsecret
///
/// Call after user confirms pictogram via SessionPictogramView.
pub async fn complete_pair(session: PairFlowSession) -> Result<()> {
    tracing::info!(server_url = %session.server_url, "completing pair flow");

    let complete_url = format!("{}/pair/complete", session.server_url);

    let complete_req = PairCompleteRequest {
        server_nonce: session.server_nonce,
        client_public_key: session.device_public_key_b64,
        device_info: DeviceInfo {
            name: "Sigil Desktop".to_string(),
            platform: "linux".to_string(),
            os_version: "unknown".to_string(), // TODO: detect actual OS version
        },
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client")?;

    let complete_resp = client.post(&complete_url)
        .json(&complete_req)
        .send()
        .await
        .context("failed to complete pair handshake")?;

    if !complete_resp.status().is_success() {
        let status = complete_resp.status();
        let body = complete_resp.text().await.unwrap_or_default();
        anyhow::bail!("server returned {}: {}", status, body);
    }

    let complete_result: PairCompleteResponse = complete_resp.json()
        .await
        .context("failed to parse pair complete response")?;

    if complete_result.status != "paired" {
        anyhow::bail!("unexpected status: {}", complete_result.status);
    }

    tracing::info!("pair handshake complete");

    // TODO: Persist to libsecret
    // use sigil_secret::MetadataStore;
    // let metadata_store = MetadataStore::new()?;
    // metadata_store.put_server(
    //     &session.server_url,
    //     &session.server_public_key,
    //     /* ... */
    // )?;

    Ok(())
}
