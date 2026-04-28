//! HTTP client for Sigil Auth protocol endpoints.
//!
//! Mirrors cli-device `/internal/crypto/pair.go` + `/cmd/sigil-device/cmd_*.go`.
//! Uses reqwest async HTTP client with tokio runtime.

use base64::Engine;
use reqwest::Client;
use thiserror::Error;

use crate::fingerprint::Fingerprint;
use crate::wire::ServerInfo;

/// Errors from protocol client operations.
#[derive(Debug, Error)]
pub enum ClientError {
    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Server returned non-200 status.
    #[error("server returned {status}: {body}")]
    ServerError {
        /// HTTP status code
        status: u16,
        /// Response body
        body: String,
    },
    /// Invalid server response (missing required fields, wrong format).
    #[error("invalid server response: {0}")]
    InvalidResponse(String),
    /// Server fingerprint mismatch (possible MITM).
    #[error("server fingerprint mismatch - possible MITM attack")]
    FingerprintMismatch,
    /// Server pictogram mismatch (possible MITM).
    #[error("server pictogram mismatch - possible MITM attack")]
    PictogramMismatch,
}

/// Result type for client operations.
pub type ClientResult<T> = Result<T, ClientError>;

/// Pair with a Sigil Auth server by fetching `/info`.
///
/// Validates:
/// - Server public key is valid compressed P-256 (33 bytes)
/// - `server_id` matches fingerprint derived from public key
/// - `server_pictogram_speakable` matches pictogram derived from fingerprint
///
/// Returns `ServerInfo` on success.
pub async fn pair(server_url: &str) -> ClientResult<ServerInfo> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let info_url = format!("{}/info", server_url.trim_end_matches('/'));

    let resp = client.get(&info_url).send().await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ClientError::ServerError { status, body });
    }

    let server_info: ServerInfo = resp.json().await.map_err(|e| {
        ClientError::InvalidResponse(format!("failed to parse JSON: {}", e))
    })?;

    // Validate server_public_key field exists and is valid base64
    let server_pubkey_bytes = base64::engine::general_purpose::STANDARD
        .decode(&server_info.server_public_key)
        .map_err(|e| ClientError::InvalidResponse(format!("invalid server_public_key base64: {}", e)))?;

    if server_pubkey_bytes.len() != 33 {
        return Err(ClientError::InvalidResponse(format!(
            "server_public_key must be 33 bytes (compressed P-256), got {}",
            server_pubkey_bytes.len()
        )));
    }

    // Calculate fingerprint from server public key
    let server_fingerprint = Fingerprint::from_bytes(&server_pubkey_bytes);
    let expected_server_id = server_fingerprint.to_hex();

    // Verify server_id matches fingerprint
    if server_info.server_id != expected_server_id {
        return Err(ClientError::FingerprintMismatch);
    }

    // Verify server_pictogram matches fingerprint derivation
    let fingerprint_bytes = server_fingerprint.as_bytes();
    let expected_pictogram_names = crate::pictogram::names(fingerprint_bytes);
    let expected_speakable = crate::pictogram::speakable(fingerprint_bytes);

    // Convert &str array to String array for comparison
    let expected_pictogram: [String; 5] = [
        expected_pictogram_names[0].to_string(),
        expected_pictogram_names[1].to_string(),
        expected_pictogram_names[2].to_string(),
        expected_pictogram_names[3].to_string(),
        expected_pictogram_names[4].to_string(),
    ];
    if server_info.server_pictogram != expected_pictogram {
        return Err(ClientError::PictogramMismatch);
    }

    // Verify server_pictogram_speakable matches if provided
    if server_info.server_pictogram_speakable != expected_speakable {
        return Err(ClientError::PictogramMismatch);
    }

    Ok(server_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pair_validates_url_format() {
        // This will fail with connection error, but validates URL handling
        let result = pair("https://invalid.example.com:99999").await;
        assert!(result.is_err());
    }
}
