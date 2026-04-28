//! WebSocket relay client for Linux desktop.
//!
//! Connects to the Sigil push relay via WebSocket, authenticates with device
//! key, and listens for challenge notifications.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, info, warn};
use url::Url;

use sigil_hardware::HardwareKey;

type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum RelayMessage {
    #[serde(rename = "auth_challenge")]
    AuthChallenge {
        challenge: String,
        expires_at: String,
    },
    #[serde(rename = "auth_success")]
    AuthSuccess { fingerprint: String },
    #[serde(rename = "auth_failure")]
    AuthFailure { error: String },
    #[serde(rename = "challenge_notification")]
    ChallengeNotification(sigil_wire::wire::ChallengeNotification),
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    r#type: String,
    device_public_key: String,
    signature: String,
    timestamp: String,
}

/// Message sent from relay client to GTK main thread.
#[derive(Debug, Clone)]
pub enum RelayEvent {
    Connected { fingerprint: String },
    Disconnected,
    ChallengeReceived(sigil_wire::wire::ChallengeNotification),
    Error(String),
}

/// WebSocket relay client. Runs in background tokio runtime, sends events to
/// GTK main thread via channel.
pub struct RelayClient {
    relay_url: String,
    device_key: Arc<dyn HardwareKey>,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
}

impl RelayClient {
    /// Create a new relay client. Does not connect until `start()` is called.
    pub fn new(
        relay_url: String,
        device_key: Arc<dyn HardwareKey>,
    ) -> (Self, mpsc::UnboundedReceiver<RelayEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        (
            Self {
                relay_url,
                device_key,
                event_tx,
            },
            event_rx,
        )
    }

    /// Start the relay client in background. Connects, authenticates, and
    /// listens for messages. Reconnects with exponential backoff on disconnect.
    pub async fn start(self) {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);

        loop {
            match self.connect_and_run().await {
                Ok(()) => {
                    info!("Relay connection closed gracefully");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    error!(error = %e, "Relay connection failed");
                    let _ = self.event_tx.send(RelayEvent::Error(e.to_string()));
                    let _ = self.event_tx.send(RelayEvent::Disconnected);

                    warn!(backoff_secs = backoff.as_secs(), "Reconnecting after backoff");
                    sleep(backoff).await;

                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    async fn connect_and_run(&self) -> Result<()> {
        let ws_url = self.build_ws_url()?;
        debug!(url = %ws_url, "Connecting to relay WebSocket");

        let (ws_stream, _) = connect_async(ws_url)
            .await
            .context("Failed to connect to relay")?;

        info!("WebSocket connected, starting auth handshake");

        let (mut write, mut read) = ws_stream.split();

        let auth_challenge = read
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("Connection closed before auth challenge"))??;

        let challenge_msg: RelayMessage = serde_json::from_str(&auth_challenge.to_text()?)
            .context("Failed to parse auth challenge")?;

        let challenge_bytes = match challenge_msg {
            RelayMessage::AuthChallenge { challenge, .. } => {
                base64::engine::general_purpose::STANDARD
                    .decode(&challenge)
                    .context("Invalid challenge encoding")?
            }
            _ => anyhow::bail!("Expected auth_challenge, got {:?}", challenge_msg),
        };

        let signature = self
            .device_key
            .sign(&challenge_bytes)
            .context("Failed to sign auth challenge")?;

        let public_key = self.device_key.public_key();
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_bytes());

        let auth_response = AuthResponse {
            r#type: "auth_response".to_string(),
            device_public_key: public_key_b64,
            signature: signature_b64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let auth_json = serde_json::to_string(&auth_response)?;
        write
            .send(Message::Text(auth_json))
            .await
            .context("Failed to send auth response")?;

        let auth_result = read
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("Connection closed before auth result"))??;

        let result_msg: RelayMessage = serde_json::from_str(&auth_result.to_text()?)?;

        match result_msg {
            RelayMessage::AuthSuccess { fingerprint } => {
                info!(fingerprint_prefix = &fingerprint[..16], "Authenticated");
                let _ = self.event_tx.send(RelayEvent::Connected { fingerprint });
            }
            RelayMessage::AuthFailure { error } => {
                anyhow::bail!("Authentication failed: {}", error);
            }
            _ => anyhow::bail!("Unexpected auth response: {:?}", result_msg),
        }

        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Err(e) = self.handle_message(&text) {
                        error!(error = %e, "Failed to handle relay message");
                    }
                }
                Ok(Message::Ping(_)) => {
                    debug!("Received ping from relay");
                }
                Ok(Message::Pong(_)) => {
                    debug!("Received pong from relay");
                }
                Ok(Message::Close(_)) => {
                    info!("Relay closed connection");
                    break;
                }
                Ok(_) => {
                    debug!("Received non-text message, ignoring");
                }
                Err(e) => {
                    return Err(e).context("WebSocket read error");
                }
            }
        }

        Ok(())
    }

    fn handle_message(&self, text: &str) -> Result<()> {
        let msg: RelayMessage = serde_json::from_str(text)?;

        match msg {
            RelayMessage::ChallengeNotification(challenge) => {
                info!(
                    challenge_id = &challenge.challenge_id,
                    action = &challenge.action.description,
                    "Received challenge notification"
                );
                let _ = self.event_tx.send(RelayEvent::ChallengeReceived(challenge));
            }
            _ => {
                warn!("Unexpected message type after auth: {:?}", msg);
            }
        }

        Ok(())
    }

    fn build_ws_url(&self) -> Result<Url> {
        let base = Url::parse(&self.relay_url).context("Invalid relay URL")?;

        let (scheme, default_port) = if base.scheme() == "http" {
            ("ws", 80)
        } else if base.scheme() == "https" {
            ("wss", 443)
        } else {
            anyhow::bail!("Relay URL must be http or https")
        };

        let host = base.host_str().unwrap_or("localhost");
        let port = base.port().unwrap_or(default_port);

        let url = if port == default_port {
            format!("{}://{}/ws", scheme, host)
        } else {
            format!("{}://{}:{}/ws", scheme, host, port)
        };

        Url::parse(&url).context("Failed to build WebSocket URL")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ws_url_http() {
        let (client, _) = RelayClient::new(
            "http://localhost:8080".to_string(),
            Arc::new(sigil_hardware::test_support::SoftwareTestKey::generate(&mut rand::rngs::OsRng)),
        );

        let url = client.build_ws_url().unwrap();
        assert_eq!(url.as_str(), "ws://localhost:8080/ws");
    }

    #[test]
    fn test_build_ws_url_https() {
        let (client, _) = RelayClient::new(
            "https://relay.sigilauth.com".to_string(),
            Arc::new(sigil_hardware::test_support::SoftwareTestKey::generate(&mut rand::rngs::OsRng)),
        );

        let url = client.build_ws_url().unwrap();
        assert_eq!(url.as_str(), "wss://relay.sigilauth.com/ws");
    }
}
