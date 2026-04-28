//! Fingerprint derivation tests.
//!
//! `fingerprint = SHA256(compressed_public_key)` per protocol-spec §1.3 + Knox §3.2.
//! Must be hex-encoded 64 chars, all lowercase, when serialised to JSON
//! (schema pattern `^[a-f0-9]{64}$` in `/api/schemas/challenge.json`).

use sigil_wire::fingerprint::Fingerprint;

#[test]
fn fingerprint_is_sha256_of_input() {
    // Known SHA-256: SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let fp = Fingerprint::from_bytes(b"abc");
    assert_eq!(
        fp.to_hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn fingerprint_hex_is_lowercase_and_64_chars() {
    let fp = Fingerprint::from_bytes(&[0u8; 33]);
    let hex_str = fp.to_hex();
    assert_eq!(hex_str.len(), 64);
    // Schema regex at /api/schemas/challenge.json#Fingerprint: ^[a-f0-9]{64}$
    assert!(
        hex_str.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "must match schema pattern ^[a-f0-9]{{64}}$"
    );
}

#[test]
fn fingerprint_deterministic() {
    let a = Fingerprint::from_bytes(b"sigil");
    let b = Fingerprint::from_bytes(b"sigil");
    assert_eq!(a, b);
}

#[test]
fn fingerprint_sensitive_to_input() {
    let a = Fingerprint::from_bytes(b"sigil");
    let b = Fingerprint::from_bytes(b"Sigil");
    assert_ne!(a, b, "case change must produce different fingerprint");
}

#[test]
fn fingerprint_parse_rejects_invalid_hex() {
    assert!(Fingerprint::from_hex("not hex").is_err());
    assert!(Fingerprint::from_hex("").is_err());
    assert!(
        Fingerprint::from_hex("ab").is_err(),
        "must reject short input"
    );
    assert!(
        Fingerprint::from_hex(&"aa".repeat(33)).is_err(),
        "must reject long input"
    );
    assert!(
        Fingerprint::from_hex(&"A".repeat(64)).is_err(),
        "must reject uppercase (schema is lowercase only)"
    );
}

#[test]
fn fingerprint_parse_round_trip() {
    let hex_str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let fp = Fingerprint::from_hex(hex_str).unwrap();
    assert_eq!(fp.to_hex(), hex_str);
}
