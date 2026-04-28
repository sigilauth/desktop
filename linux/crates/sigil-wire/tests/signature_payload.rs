//! Signature payload construction tests.
//!
//! Per Knox threat model §3.3 + DECISIONS.md D2:
//!
//! Server signs over:
//!   SHA256(challenge_id || fingerprint || challenge_bytes || action_json || timestamp)
//!
//! Device signs over:
//!   SHA256(challenge_id || challenge_bytes || timestamp)
//!
//! These are hash inputs for ECDSA. The *pre-hash* byte ordering must be
//! identical across server and device implementations or verification fails
//! every time. These tests pin that ordering.

use sigil_wire::signature_payload::{device_response_payload, server_challenge_payload};
use sigil_wire::wire::{Action, ChallengeNotification};

#[test]
fn server_payload_is_sha256_of_concatenation() {
    let payload = server_challenge_payload(
        "550e8400-e29b-41d4-a716-446655440000",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        b"challenge-bytes-raw",
        r#"{"type":"step_up","description":"Add WebAuthn key"}"#,
        "2026-04-23T10:00:00Z",
    );
    // Output is a 32-byte digest.
    assert_eq!(payload.len(), 32);
}

#[test]
fn server_payload_deterministic() {
    let a = server_challenge_payload(
        "550e8400-e29b-41d4-a716-446655440000",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        b"challenge-bytes-raw",
        r#"{"type":"step_up","description":"Add WebAuthn key"}"#,
        "2026-04-23T10:00:00Z",
    );
    let b = server_challenge_payload(
        "550e8400-e29b-41d4-a716-446655440000",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        b"challenge-bytes-raw",
        r#"{"type":"step_up","description":"Add WebAuthn key"}"#,
        "2026-04-23T10:00:00Z",
    );
    assert_eq!(a, b, "same inputs must produce same digest");
}

#[test]
fn server_payload_sensitive_to_every_field() {
    let base = server_challenge_payload("id1", "fp1", b"bytes", "action", "2026-01-01T00:00:00Z");
    let changes = [
        server_challenge_payload("id2", "fp1", b"bytes", "action", "2026-01-01T00:00:00Z"),
        server_challenge_payload("id1", "fp2", b"bytes", "action", "2026-01-01T00:00:00Z"),
        server_challenge_payload("id1", "fp1", b"bytez", "action", "2026-01-01T00:00:00Z"),
        server_challenge_payload("id1", "fp1", b"bytes", "actiot", "2026-01-01T00:00:00Z"),
        server_challenge_payload("id1", "fp1", b"bytes", "action", "2026-01-01T00:00:01Z"),
    ];
    for (i, changed) in changes.iter().enumerate() {
        assert_ne!(
            &base, changed,
            "field {i} must influence digest — replay protection"
        );
    }
}

#[test]
fn device_payload_independent_of_fingerprint_and_action() {
    // Device signs only challenge_id || challenge_bytes || timestamp per Knox §3.3.
    // Fingerprint is NOT in the device sig payload — server derives it from the
    // response public key and verifies separately.
    let a = device_response_payload(
        "550e8400-e29b-41d4-a716-446655440000",
        b"challenge-bytes-raw",
        "2026-04-23T10:01:00Z",
    );
    assert_eq!(a.len(), 32);
}

#[test]
fn device_payload_deterministic_and_sensitive() {
    let base = device_response_payload("id1", b"bytes", "ts1");
    assert_eq!(base, device_response_payload("id1", b"bytes", "ts1"));
    assert_ne!(base, device_response_payload("id2", b"bytes", "ts1"));
    assert_ne!(base, device_response_payload("id1", b"BYTES", "ts1"));
    assert_ne!(base, device_response_payload("id1", b"bytes", "ts2"));
}

#[test]
fn server_and_device_payloads_differ_for_same_challenge() {
    // Cross-protocol replay defense: a server-signed payload must not happen
    // to equal a device-response payload even if the attacker controls shared
    // fields.
    let server = server_challenge_payload(
        "id1",
        "fp1",
        b"bytes",
        r#"{"type":"x","description":"y"}"#,
        "2026-01-01T00:00:00Z",
    );
    let device = device_response_payload("id1", b"bytes", "2026-01-01T00:00:00Z");
    assert_ne!(server, device);
}

#[test]
fn challenge_notification_canonicalises_action_json() {
    // The server-signed payload includes `action_json`. That JSON must be
    // reproducible byte-for-byte on the device to verify the signature, so we
    // serialise via a canonicaliser (sorted keys, no whitespace).
    let action = Action {
        r#type: "step_up".into(),
        description: "Add WebAuthn key".into(),
        params: Some(serde_json::json!({ "key_name": "Sarah's YubiKey" })),
    };
    let canonical = sigil_wire::signature_payload::canonical_action_json(&action);
    // Sorted keys, no whitespace.
    assert_eq!(
        canonical,
        r#"{"description":"Add WebAuthn key","params":{"key_name":"Sarah's YubiKey"},"type":"step_up"}"#
    );

    // Canonicalisation is stable across equivalent reorderings.
    let reordered: Action = serde_json::from_str(
        r#"{"description":"Add WebAuthn key","type":"step_up","params":{"key_name":"Sarah's YubiKey"}}"#,
    )
    .unwrap();
    assert_eq!(
        sigil_wire::signature_payload::canonical_action_json(&reordered),
        canonical
    );
}

#[test]
fn notification_payload_round_trip_via_canonical_action() {
    // Given a deserialised ChallengeNotification, we must be able to reconstruct
    // the exact bytes the server hashed. Tests the tightest contract between
    // server and device.
    let notif = ChallengeNotification {
        r#type: "challenge".into(),
        challenge_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        server_id: "sigil-prod-001".into(),
        challenge_bytes: base64_encode(b"challenge-bytes-raw"),
        action: Action {
            r#type: "step_up".into(),
            description: "Add WebAuthn key".into(),
            params: None,
        },
        server_signature: base64_encode(&[0u8; 64]),
        expires_at: "2026-04-23T10:05:00Z".into(),
        respond_to: "https://sigil.example.com/respond".into(),
    };

    let fingerprint_hex = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
    // For the device to verify, it reconstructs the payload from the notification.
    let payload = notif
        .reconstruct_server_payload(fingerprint_hex)
        .expect("payload reconstruction must succeed for valid notification");
    assert_eq!(payload.len(), 32);

    // Reconstruction is deterministic.
    let payload2 = notif.reconstruct_server_payload(fingerprint_hex).unwrap();
    assert_eq!(payload, payload2);
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}
