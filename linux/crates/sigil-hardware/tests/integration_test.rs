//! Integration tests for hardware backends.
//!
//! Tests run with `test-support` feature enabled by default. Real hardware
//! tests gated by `#[ignore]` and feature flags `tpm` / `yubikey`.
//!
//! **Test coverage:**
//! - Key generation and public key extraction
//! - Signature generation and verification
//! - Fingerprint computation
//! - Deterministic signing (same key, same message → same signature where applicable)
//! - Cross-signature verification (different keys → verification fails)
//! - Attestation availability checks

#![cfg(feature = "test-support")]

use rand::rngs::OsRng;
use sigil_hardware::test_support::{verify, SoftwareTestKey};
use sigil_hardware::HardwareKey;

// ---- SoftwareTestKey Tests (always enabled with test-support) ----------

#[test]
fn software_key_generates_valid_public_key() {
    let key = SoftwareTestKey::generate(&mut OsRng);
    let pk = key.public_key();

    // Must be 33 bytes
    assert_eq!(pk.as_bytes().len(), 33);

    // Must be SEC1 compressed format (0x02 or 0x03 prefix)
    let prefix = pk.as_bytes()[0];
    assert!(
        prefix == 0x02 || prefix == 0x03,
        "Invalid SEC1 compressed prefix: {:#04x}",
        prefix
    );
}

#[test]
fn software_key_fingerprint_is_deterministic() {
    let key = SoftwareTestKey::generate(&mut OsRng);

    // Fingerprint should be consistent across multiple calls
    let fp1 = key.fingerprint();
    let fp2 = key.fingerprint();
    assert_eq!(fp1, fp2);

    // Fingerprint should match manual SHA-256 of public key
    let expected = sigil_wire::Fingerprint::from_bytes(key.public_key().as_bytes());
    assert_eq!(key.fingerprint(), expected);
}

#[test]
fn software_key_signs_32_byte_digest() {
    let key = SoftwareTestKey::generate(&mut OsRng);
    let digest = [0xAB; 32];

    let sig = key.sign(&digest).expect("sign should succeed");

    // Signature must be exactly 64 bytes (r || s)
    assert_eq!(sig.as_bytes().len(), 64);

    // Signature must verify under the same key
    assert!(verify(&key.verifying_key(), &digest, &sig));
}

#[test]
fn software_key_signs_different_payloads_differently() {
    let key = SoftwareTestKey::generate(&mut OsRng);

    let sig1 = key.sign(b"payload one").unwrap();
    let sig2 = key.sign(b"payload two").unwrap();

    // Different payloads should produce different signatures
    assert_ne!(sig1.as_bytes(), sig2.as_bytes());
}

#[test]
fn software_key_signature_verifies_only_under_correct_key() {
    let key1 = SoftwareTestKey::generate(&mut OsRng);
    let key2 = SoftwareTestKey::generate(&mut OsRng);

    let payload = b"test payload";
    let sig = key1.sign(payload).unwrap();

    // Should verify under key1
    assert!(verify(&key1.verifying_key(), payload, &sig));

    // Should NOT verify under key2
    assert!(!verify(&key2.verifying_key(), payload, &sig));
}

#[test]
fn software_key_signature_fails_on_tampered_payload() {
    let key = SoftwareTestKey::generate(&mut OsRng);

    let original = b"original payload";
    let tampered = b"tampered payload";

    let sig = key.sign(original).unwrap();

    // Should verify on original
    assert!(verify(&key.verifying_key(), original, &sig));

    // Should NOT verify on tampered
    assert!(!verify(&key.verifying_key(), tampered, &sig));
}

#[test]
fn software_key_multiple_signatures_all_verify() {
    let key = SoftwareTestKey::generate(&mut OsRng);

    // Sign multiple times to ensure consistency
    for i in 0..10 {
        let mut payload = [0u8; 32];
        payload[0] = i;

        let sig = key.sign(&payload).unwrap();

        // All signatures should be 64 bytes
        assert_eq!(sig.as_bytes().len(), 64);

        // All signatures should verify
        assert!(
            verify(&key.verifying_key(), &payload, &sig),
            "Signature {} should verify",
            i
        );
    }
}

#[test]
fn software_key_attestation_unavailable() {
    let key = SoftwareTestKey::generate(&mut OsRng);

    // Software test keys MUST refuse attestation (security requirement)
    assert!(
        key.attestation().is_err(),
        "SoftwareTestKey should not provide attestation"
    );
}

#[test]
fn software_key_different_keys_have_different_fingerprints() {
    let key1 = SoftwareTestKey::generate(&mut OsRng);
    let key2 = SoftwareTestKey::generate(&mut OsRng);

    assert_ne!(
        key1.fingerprint(),
        key2.fingerprint(),
        "Different keys must have different fingerprints"
    );
}

#[test]
fn software_key_signs_payload_with_null_bytes() {
    let key = SoftwareTestKey::generate(&mut OsRng);
    let payload = [0x00; 32];

    let sig = key.sign(&payload).expect("should sign all-zero payload");

    assert!(verify(&key.verifying_key(), &payload, &sig));
}

#[test]
fn software_key_signs_payload_with_max_bytes() {
    let key = SoftwareTestKey::generate(&mut OsRng);
    let payload = [0xFF; 32];

    let sig = key.sign(&payload).expect("should sign all-FF payload");

    assert!(verify(&key.verifying_key(), &payload, &sig));
}

#[test]
fn software_key_handles_boundary_payloads() {
    let key = SoftwareTestKey::generate(&mut OsRng);

    // Test various boundary patterns
    let patterns = vec![
        [0x00; 32],                                   // all zeros
        [0xFF; 32],                                   // all ones
        {
            let mut p = [0u8; 32];
            p[0] = 0x80;
            p
        }, // high bit set
        {
            let mut p = [0u8; 32];
            p[31] = 0x01;
            p
        }, // low bit set
    ];

    for (i, payload) in patterns.iter().enumerate() {
        let sig = key
            .sign(payload)
            .unwrap_or_else(|_| panic!("should sign pattern {}", i));

        assert!(
            verify(&key.verifying_key(), payload, &sig),
            "pattern {} should verify",
            i
        );
    }
}

// ---- TPM Backend Tests (Linux-only, requires swtpm or real TPM) --------

#[cfg(all(target_os = "linux", feature = "tpm"))]
mod tpm_tests {
    use super::*;
    use sigil_hardware::tpm::TpmKey;

    /// Test that requires a real TPM or swtpm. Ignored by default.
    /// Run with: cargo test --features tpm -- --ignored
    #[test]
    #[ignore]
    fn tpm_key_discovery_succeeds() {
        let key = TpmKey::discover().expect("TPM should be available");

        let pk = key.public_key();
        assert_eq!(pk.as_bytes().len(), 33);
        assert!(matches!(pk.as_bytes()[0], 0x02 | 0x03));
    }

    #[test]
    #[ignore]
    fn tpm_key_fingerprint_stable() {
        let key = TpmKey::discover().expect("TPM should be available");

        let fp1 = key.fingerprint();
        let fp2 = key.fingerprint();
        assert_eq!(fp1, fp2, "Fingerprint should be deterministic");
    }

    #[test]
    #[ignore]
    fn tpm_key_signs_32_byte_digest() {
        let key = TpmKey::discover().expect("TPM should be available");
        let digest = [0xAB; 32];

        let sig = key.sign(&digest).expect("TPM should sign successfully");
        assert_eq!(sig.as_bytes().len(), 64);
    }

    #[test]
    #[ignore]
    fn tpm_key_rejects_non_32_byte_payload() {
        let key = TpmKey::discover().expect("TPM should be available");

        // TPM backend requires exactly 32 bytes (pre-hashed)
        assert!(key.sign(&[0xAB; 31]).is_err());
        assert!(key.sign(&[0xAB; 33]).is_err());
        assert!(key.sign(&[]).is_err());
    }

    #[test]
    #[ignore]
    fn tpm_key_multiple_signatures() {
        let key = TpmKey::discover().expect("TPM should be available");

        // Sign multiple payloads to ensure consistency
        for i in 0..5 {
            let mut digest = [0u8; 32];
            digest[0] = i;

            let sig = key.sign(&digest).unwrap();

            // All signatures should be 64 bytes
            assert_eq!(
                sig.as_bytes().len(),
                64,
                "TPM signature {} should be 64 bytes",
                i
            );
        }
    }

    #[test]
    #[ignore]
    fn tpm_key_provides_attestation() {
        let key = TpmKey::discover().expect("TPM should be available");

        let attestation = key
            .attestation()
            .expect("TPM should provide attestation");

        // Should have at least EK certificate
        assert!(
            !attestation.certs.is_empty(),
            "Attestation should include EK cert"
        );

        // Should have attestation blob
        assert!(
            !attestation.attestation_blob.is_empty(),
            "Attestation should include public key blob"
        );
    }

    #[test]
    #[ignore]
    fn tpm_key_rediscovery_returns_same_key() {
        let key1 = TpmKey::discover().expect("TPM should be available");
        let fp1 = key1.fingerprint();

        // Discover again - should get the same persistent key
        let key2 = TpmKey::discover().expect("TPM should be available");
        let fp2 = key2.fingerprint();

        assert_eq!(
            fp1, fp2,
            "Rediscovered TPM key should have same fingerprint"
        );
    }
}

// ---- YubiKey Backend Tests (Linux-only, requires real YubiKey) ---------

#[cfg(all(target_os = "linux", feature = "yubikey"))]
mod yubikey_tests {
    use super::*;
    use sigil_hardware::yubikey::YubiKeyPivKey;

    /// Test that requires a real YubiKey plugged in. Ignored by default.
    /// Run with: cargo test --features yubikey -- --ignored
    #[test]
    #[ignore]
    fn yubikey_discovery_succeeds() {
        let key = YubiKeyPivKey::discover().expect("YubiKey should be available");

        let pk = key.public_key();
        assert_eq!(pk.as_bytes().len(), 33);
        assert!(matches!(pk.as_bytes()[0], 0x02 | 0x03));
    }

    #[test]
    #[ignore]
    fn yubikey_fingerprint_stable() {
        let key = YubiKeyPivKey::discover().expect("YubiKey should be available");

        let fp1 = key.fingerprint();
        let fp2 = key.fingerprint();
        assert_eq!(fp1, fp2, "Fingerprint should be deterministic");
    }

    #[test]
    #[ignore]
    fn yubikey_signs_32_byte_digest() {
        let key = YubiKeyPivKey::discover().expect("YubiKey should be available");
        let digest = [0xAB; 32];

        let sig = key
            .sign(&digest)
            .expect("YubiKey should sign successfully");
        assert_eq!(sig.as_bytes().len(), 64);
    }

    #[test]
    #[ignore]
    fn yubikey_rejects_non_32_byte_payload() {
        let key = YubiKeyPivKey::discover().expect("YubiKey should be available");

        // YubiKey backend requires exactly 32 bytes (pre-hashed)
        assert!(key.sign(&[0xAB; 31]).is_err());
        assert!(key.sign(&[0xAB; 33]).is_err());
        assert!(key.sign(&[]).is_err());
    }

    #[test]
    #[ignore]
    fn yubikey_multiple_signatures() {
        let key = YubiKeyPivKey::discover().expect("YubiKey should be available");

        // Sign multiple payloads to ensure consistency
        for i in 0..5 {
            let mut digest = [0u8; 32];
            digest[0] = i;

            let sig = key.sign(&digest).unwrap();

            // All signatures should be 64 bytes
            assert_eq!(
                sig.as_bytes().len(),
                64,
                "YubiKey signature {} should be 64 bytes",
                i
            );
        }
    }

    #[test]
    #[ignore]
    fn yubikey_provides_attestation() {
        let key = YubiKeyPivKey::discover().expect("YubiKey should be available");

        let attestation = key
            .attestation()
            .expect("YubiKey should provide attestation");

        // Should have attestation cert chain
        assert!(
            !attestation.certs.is_empty(),
            "Attestation should include cert chain"
        );

        // Should have attestation blob
        assert!(
            !attestation.attestation_blob.is_empty(),
            "Attestation should include attestation data"
        );
    }

    #[test]
    #[ignore]
    fn yubikey_rediscovery_returns_same_key() {
        let key1 = YubiKeyPivKey::discover().expect("YubiKey should be available");
        let fp1 = key1.fingerprint();

        // Discover again - should get the same PIV slot key
        let key2 = YubiKeyPivKey::discover().expect("YubiKey should be available");
        let fp2 = key2.fingerprint();

        assert_eq!(
            fp1, fp2,
            "Rediscovered YubiKey should have same fingerprint"
        );
    }
}

// ---- Cross-Backend Compatibility Tests ----------------------------------

#[test]
fn different_software_keys_produce_different_signatures() {
    let key1 = SoftwareTestKey::generate(&mut OsRng);
    let key2 = SoftwareTestKey::generate(&mut OsRng);

    let payload = b"same payload for both keys";

    let sig1 = key1.sign(payload).unwrap();
    let sig2 = key2.sign(payload).unwrap();

    // Same payload, different keys → different signatures
    assert_ne!(sig1.as_bytes(), sig2.as_bytes());

    // Each should verify under its own key
    assert!(verify(&key1.verifying_key(), payload, &sig1));
    assert!(verify(&key2.verifying_key(), payload, &sig2));

    // But not under the other key
    assert!(!verify(&key1.verifying_key(), payload, &sig2));
    assert!(!verify(&key2.verifying_key(), payload, &sig1));
}

#[test]
fn public_key_uniqueness() {
    // Generate multiple keys and ensure public keys are unique
    let keys: Vec<_> = (0..10)
        .map(|_| SoftwareTestKey::generate(&mut OsRng))
        .collect();

    for (i, key1) in keys.iter().enumerate() {
        for (j, key2) in keys.iter().enumerate() {
            if i != j {
                assert_ne!(
                    key1.public_key().as_bytes(),
                    key2.public_key().as_bytes(),
                    "Keys {} and {} should have different public keys",
                    i,
                    j
                );
            }
        }
    }
}
