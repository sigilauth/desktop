//! Trait contract tests.
//!
//! Uses `SoftwareTestKey` to prove the `HardwareKey` trait + signature
//! payload machinery work end-to-end. Real TPM / YubiKey backends must pass
//! the same tests once implemented (see `trait_contract_tpm.rs` etc).

#![cfg(feature = "test-support")]

use sigil_hardware::test_support::{verify, SoftwareTestKey};
use sigil_hardware::HardwareKey;
use sigil_wire::signature_payload::{device_response_payload, server_challenge_payload};

#[test]
fn public_key_is_33_bytes_compressed_sec1() {
    let mut rng = rand::thread_rng();
    let key = SoftwareTestKey::generate(&mut rng);
    let pk = key.public_key();
    assert_eq!(pk.as_bytes().len(), 33);
    // SEC1 compressed: leading byte is 0x02 or 0x03.
    assert!(matches!(pk.as_bytes()[0], 0x02 | 0x03));
}

#[test]
fn fingerprint_is_sha256_of_public_key() {
    let mut rng = rand::thread_rng();
    let key = SoftwareTestKey::generate(&mut rng);
    let pk = key.public_key();
    let expected = sigil_wire::Fingerprint::from_bytes(pk.as_bytes());
    assert_eq!(key.fingerprint(), expected);
}

#[test]
fn sign_verify_round_trip_on_device_response_payload() {
    let mut rng = rand::thread_rng();
    let key = SoftwareTestKey::generate(&mut rng);

    let payload = device_response_payload(
        "550e8400-e29b-41d4-a716-446655440000",
        b"some-challenge-bytes",
        "2026-04-23T10:01:00Z",
    );

    let sig = key.sign(&payload).expect("sign must succeed on test key");
    assert_eq!(sig.as_bytes().len(), 64);
    assert!(verify(&key.verifying_key(), &payload, &sig));
}

#[test]
fn signature_does_not_verify_on_different_payload() {
    let mut rng = rand::thread_rng();
    let key = SoftwareTestKey::generate(&mut rng);
    let sig = key.sign(b"original").unwrap();
    assert!(!verify(&key.verifying_key(), b"tampered", &sig));
}

#[test]
fn signature_does_not_verify_under_different_key() {
    let mut rng = rand::thread_rng();
    let key_a = SoftwareTestKey::generate(&mut rng);
    let key_b = SoftwareTestKey::generate(&mut rng);
    let sig = key_a.sign(b"payload").unwrap();
    assert!(!verify(&key_b.verifying_key(), b"payload", &sig));
}

#[test]
fn server_challenge_payload_signable() {
    // The device verifies this payload under the server's public key; the
    // server builds it when signing the challenge. Shape is symmetric. Here
    // we sign as if we were the server and verify with our own key.
    let mut rng = rand::thread_rng();
    let server_key = SoftwareTestKey::generate(&mut rng);

    let payload = server_challenge_payload(
        "550e8400-e29b-41d4-a716-446655440000",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        b"challenge-bytes",
        r#"{"description":"Add WebAuthn key","type":"step_up"}"#,
        "2026-04-23T10:00:00Z",
    );

    let sig = server_key.sign(&payload).unwrap();
    assert!(verify(&server_key.verifying_key(), &payload, &sig));
}

#[test]
fn attestation_required_backend_mismatch() {
    // The test backend MUST refuse attestation — production code distinguishes
    // "hardware-bound" from "test" by attempting this call.
    let mut rng = rand::thread_rng();
    let key = SoftwareTestKey::generate(&mut rng);
    assert!(key.attestation().is_err());
}
