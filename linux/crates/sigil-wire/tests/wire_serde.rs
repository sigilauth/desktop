//! Wire-format serde round-trip tests against the OpenAPI schemas.
//!
//! Sources:
//! - /api/openapi.yaml §components.schemas
//! - /api/schemas/challenge.json
//! - /api/schemas/mpa.json
//!
//! Contract pinning: the `sigil-wire` types must serialise to JSON that
//! conforms to the published schema and deserialise from the published
//! example bodies.

use serde_json::json;
use sigil_wire::wire::{
    Action, ChallengeNotification, ChallengeResponse, ChallengeVerified, Decision, DeviceRegister,
    PushPlatform, ServerInfo,
};

#[test]
fn server_info_example_round_trips() {
    // From openapi.yaml:50-72 example.
    let raw = json!({
        "server_id": "sigil-prod-001",
        "server_name": "Acme Corp Sigil Auth",
        "server_public_key": "Ag8xYzI3ZWRkNDUzYmNlYzVmMTJjNmI5MzA4OGY0",
        "server_pictogram": ["lock", "shield", "key", "oldkey", "lightning"],
        "server_pictogram_speakable": "lock shield key oldkey lightning",
        "version": "1.0.0",
        "mode": "operational",
        "relay_url": "https://relay.sigilauth.com",
        "features": {
            "mpa": true,
            "secure_decrypt": true,
            "mnemonic_generation": true,
            "webhooks": true
        }
    });

    let parsed: ServerInfo = serde_json::from_value(raw.clone()).expect("parse ok");
    assert_eq!(parsed.server_id, "sigil-prod-001");
    assert_eq!(parsed.mode, sigil_wire::wire::ServerMode::Operational);
    assert!(parsed.features.as_ref().unwrap().mpa);

    let reserialised = serde_json::to_value(&parsed).expect("serialise ok");
    assert_eq!(reserialised, raw, "round-trip must be byte-identical");
}

#[test]
fn challenge_notification_example_round_trips() {
    let raw = json!({
        "type": "challenge",
        "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
        "server_id": "sigil-prod-001",
        "challenge_bytes": "SGVsbG8gV29ybGQ=",
        "action": {
            "type": "step_up",
            "description": "Add WebAuthn key",
            "params": { "key_name": "Sarah's YubiKey" }
        },
        "server_signature": "AAAA",
        "expires_at": "2026-04-23T10:05:00Z",
        "respond_to": "https://sigil.example.com/respond"
    });

    let parsed: ChallengeNotification = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(parsed.r#type, "challenge");
    assert_eq!(parsed.action.r#type, "step_up");

    let reserialised = serde_json::to_value(&parsed).unwrap();
    assert_eq!(reserialised, raw);
}

#[test]
fn challenge_response_decision_enum_serialises_lowercase() {
    // openapi.yaml §ChallengeResponse.decision enum: [approved, rejected] (lowercase)
    let response = ChallengeResponse {
        challenge_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        device_public_key: "AAAA".into(),
        decision: Decision::Approved,
        signature: "SIGSIG".into(),
        timestamp: "2026-04-23T10:01:00Z".into(),
    };
    let json_out = serde_json::to_value(&response).unwrap();
    assert_eq!(json_out["decision"], "approved");

    let response_rej = ChallengeResponse {
        decision: Decision::Rejected,
        ..response
    };
    let json_rej = serde_json::to_value(&response_rej).unwrap();
    assert_eq!(json_rej["decision"], "rejected");
}

#[test]
fn challenge_response_rejects_unknown_decision() {
    let bad = json!({
        "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
        "device_public_key": "AAAA",
        "decision": "maybe",
        "signature": "SIGSIG",
        "timestamp": "2026-04-23T10:01:00Z"
    });
    let parsed: Result<ChallengeResponse, _> = serde_json::from_value(bad);
    assert!(parsed.is_err(), "decision must be one of approved|rejected");
}

#[test]
fn device_register_push_platform_serialises_lowercase() {
    let reg = DeviceRegister {
        device_public_key: "AAAA".into(),
        push_token: "token".into(),
        push_platform: PushPlatform::Fcm,
    };
    let out = serde_json::to_value(&reg).unwrap();
    assert_eq!(out["push_platform"], "fcm");

    let reg2 = DeviceRegister {
        push_platform: PushPlatform::Apns,
        ..reg
    };
    let out2 = serde_json::to_value(&reg2).unwrap();
    assert_eq!(out2["push_platform"], "apns");
}

#[test]
fn challenge_verified_action_optional() {
    // openapi §ChallengeVerified.action is optional.
    let without = json!({
        "verified": true,
        "fingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "pictogram": ["tree", "rocket", "mushroom", "orange", "moai"],
        "pictogram_speakable": "tree rocket mushroom orange moai"
    });
    let parsed: ChallengeVerified = serde_json::from_value(without).unwrap();
    assert!(parsed.action.is_none());
}

#[test]
fn action_params_arbitrary_object() {
    // openapi §Action.params: { type: object, additionalProperties: true }
    // Arbitrary JSON object accepted.
    let raw = json!({
        "type": "transfer",
        "description": "Transfer $1000 to account 1234",
        "params": {
            "amount": 1000,
            "currency": "USD",
            "recipient": { "account": "1234", "name": "Acme Co" },
            "tags": ["urgent", "approved-by-cfo"]
        }
    });
    let parsed: Action = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(parsed.r#type, "transfer");
    assert!(parsed.params.is_some());

    let re = serde_json::to_value(&parsed).unwrap();
    assert_eq!(re, raw);
}

#[test]
fn fingerprint_field_must_match_schema_pattern() {
    // Schema: "^[a-f0-9]{64}$". Deserialiser must accept lowercase 64-hex and
    // reject uppercase or wrong length. Enforced at the Fingerprint wrapper type.
    use sigil_wire::fingerprint::Fingerprint;

    let ok = serde_json::from_value::<Fingerprint>(json!(
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    ));
    assert!(ok.is_ok());

    let upper = serde_json::from_value::<Fingerprint>(json!(
        "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2"
    ));
    assert!(upper.is_err(), "uppercase hex violates schema pattern");

    let short = serde_json::from_value::<Fingerprint>(json!("abcd"));
    assert!(short.is_err(), "short input violates schema pattern");
}
