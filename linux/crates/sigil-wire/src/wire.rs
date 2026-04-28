//! Wire-format types mirroring `/api/openapi.yaml` §components.schemas.
//!
//! Every struct deserialises from and serialises to JSON exactly matching the
//! schema. Round-trip tests in `tests/wire_serde.rs` pin this.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fingerprint::Fingerprint;

/// `ServerInfo` from `/info`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerInfo {
    /// Stable server identifier.
    pub server_id: String,
    /// Operator-visible name.
    pub server_name: String,
    /// Base64-encoded compressed SEC1 P-256 public key (33 bytes).
    pub server_public_key: String,
    /// 5-emoji pictogram.
    pub server_pictogram: [String; 5],
    /// Space-separated speakable names (D8).
    pub server_pictogram_speakable: String,
    /// Semver.
    pub version: String,
    /// Server lifecycle mode.
    pub mode: ServerMode,
    /// Push relay URL (operator-configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// Optional feature flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<ServerFeatures>,
}

/// Server lifecycle mode.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    /// Admin wizard in progress.
    Init,
    /// Ready to issue challenges.
    Operational,
}

/// Feature flags advertised by `/info`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerFeatures {
    /// Multi-party approval available.
    pub mpa: bool,
    /// Secure decrypt endpoint available.
    pub secure_decrypt: bool,
    /// Server can generate mnemonics on HW TRNG.
    pub mnemonic_generation: bool,
    /// Webhook dispatch configured.
    pub webhooks: bool,
}

/// `Action` — machine type + human description + optional params.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Action {
    /// Machine-readable action type (e.g., `step_up`, `transfer`).
    pub r#type: String,
    /// Human-readable description shown to the user pre-biometric.
    pub description: String,
    /// Optional action-specific parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// The push-notification payload the device receives (plaintext over TLS, D2).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeNotification {
    /// Discriminator — always `"challenge"`.
    pub r#type: String,
    /// UUID.
    pub challenge_id: String,
    /// Server ID from `/info`.
    pub server_id: String,
    /// Base64-encoded 32 random bytes.
    pub challenge_bytes: String,
    /// Action context.
    pub action: Action,
    /// Base64-encoded ECDSA P-256 signature (64 bytes, low-S).
    pub server_signature: String,
    /// ISO-8601 expiry.
    pub expires_at: String,
    /// HTTPS URL to POST the response to.
    pub respond_to: String,
}

/// Device response to a challenge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeResponse {
    /// UUID matching the notification.
    pub challenge_id: String,
    /// Base64-encoded compressed P-256 public key (33 bytes).
    pub device_public_key: String,
    /// Device's decision.
    pub decision: Decision,
    /// Base64-encoded ECDSA signature (64 bytes, low-S).
    pub signature: String,
    /// ISO-8601 timestamp of signing.
    pub timestamp: String,
}

/// Approval decision.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// User approved via hardware key.
    Approved,
    /// User rejected.
    Rejected,
}

/// Server-side verification result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeVerified {
    /// `true` if signature verified and challenge unconsumed.
    pub verified: bool,
    /// Device fingerprint.
    pub fingerprint: Fingerprint,
    /// Device pictogram (derived).
    pub pictogram: [String; 5],
    /// Space-separated speakable names.
    pub pictogram_speakable: String,
    /// Optional action context echoed back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
}

/// Device registration payload to the relay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRegister {
    /// Base64-encoded compressed P-256 public key.
    pub device_public_key: String,
    /// Push token issued by APNs/FCM.
    pub push_token: String,
    /// Push provider.
    pub push_platform: PushPlatform,
}

/// Push provider for a Linux device. For B9 MVP neither APNs nor FCM fit the
/// Linux desktop; `apns`/`fcm` are the only values accepted by the relay today.
/// **FLAG (spec gap):** the Linux desktop needs a WebSocket or long-poll
/// transport. Raised to @team-lead / @beacon / @kai-relay. Until resolved,
/// this enum exactly mirrors the OpenAPI contract and Linux desktop cannot
/// register for push.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    /// Apple Push Notification Service.
    Apns,
    /// Firebase Cloud Messaging.
    Fcm,
}
