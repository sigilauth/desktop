//! YubiKey PIV backend via the `yubikey` crate (Linux only).
//!
//! # Design
//!
//! Uses PIV slot `0x9A` (Authentication) to hold a P-256 ECDSA key. The
//! user sets a PIN at first provisioning; the YubiKey's PIV policy enforces
//! both PIN and physical touch on every signing operation. Private scalar
//! never leaves the YubiKey.
//!
//! # User presence
//!
//! PIV policies configured at key generation:
//! - `TouchPolicy::Always` — user must tap the YubiKey for every sign
//! - `PinPolicy::Always` — PIN required for every sign (re-verified)
//!
//! Together these satisfy Knox §5.1 "biometric gate on every signing
//! operation" in the context of hardware-key devices.
//!
//! # Attestation (Knox §3.6)
//!
//! YubiKey's PIV applet provides attestation via slot `0xF9` (attestation
//! key) and the built-in Yubico attestation certificate. Flow:
//!   1. `yubikey::piv::attest(slot = 0x9A)` → attestation cert
//!   2. Combined with the F9 slot's cert and the Yubico PIV CA
//!   3. Verifier chains to Yubico root CA per Knox §3.6
//!
//! # Tests
//!
//! Pure helpers unit-tested here. Real-device tests behind
//! `#[cfg(feature = "yubikey-hardware-tests")]` require a YubiKey plugged
//! in and are skipped in CI unless the runner has one.

// DER helpers + SEC1 helpers below are consumed either by the Linux backend
// (once the `yubikey` crate wiring lands) or by unit tests. Until the backend
// ops are filled in, they'd warn as dead — silence explicitly.
#![allow(dead_code)]

use crate::{AttestationChain, CompressedPublicKey, HardwareKey, KeyError, Signature};

/// PIV slot used for the Sigil signing key. `9A` per NIST SP 800-73-4.
pub const SLOT_AUTHENTICATION: u8 = 0x9A;

/// PIV slot holding the attestation CA (Yubico ships this pre-populated).
pub const SLOT_ATTESTATION: u8 = 0xF9;

/// A YubiKey PIV-resident ECDSA P-256 signing key.
pub struct YubiKeyPivKey {
    #[cfg(target_os = "linux")]
    inner: linux_backend::Inner,
    public_key_sec1: [u8; 33],
}

#[cfg(target_os = "linux")]
impl YubiKeyPivKey {
    /// Detect the first connected YubiKey with an accessible PIV applet.
    pub fn discover() -> Result<Self, KeyError> {
        let (inner, public_key_sec1) = linux_backend::discover()?;
        Ok(YubiKeyPivKey {
            inner,
            public_key_sec1,
        })
    }
}

impl HardwareKey for YubiKeyPivKey {
    fn public_key(&self) -> CompressedPublicKey {
        CompressedPublicKey(self.public_key_sec1)
    }

    #[cfg(target_os = "linux")]
    fn sign(&self, payload: &[u8]) -> Result<Signature, KeyError> {
        if payload.len() != 32 {
            return Err(KeyError::Backend(
                format!("expected 32-byte digest, got {}", payload.len()).into(),
            ));
        }
        self.inner.sign(payload)
    }

    #[cfg(not(target_os = "linux"))]
    fn sign(&self, _payload: &[u8]) -> Result<Signature, KeyError> {
        Err(KeyError::Unavailable(
            "YubiKey backend available on Linux only".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn attestation(&self) -> Result<AttestationChain, KeyError> {
        self.inner.attestation()
    }

    #[cfg(not(target_os = "linux"))]
    fn attestation(&self) -> Result<AttestationChain, KeyError> {
        Err(KeyError::Unavailable(
            "YubiKey backend available on Linux only".into(),
        ))
    }
}

// ---- DER parsing helpers (pure, unit-tested) ---------------------------

/// Parse a DER-encoded SEC1 EC public key into 33-byte SEC1 compressed form.
///
/// YubiKey returns public keys as `X9.62` uncompressed (`0x04 || X || Y`).
/// This helper compresses to 33 bytes. The `yubikey` crate exposes the raw
/// point bytes as `public_key.as_der()` or `public_key.to_encoded_point()` —
/// both reducible to `(x, y)` feeding into this function.
pub(crate) fn uncompressed_to_sec1_compressed(uncompressed: &[u8]) -> Result<[u8; 33], KeyError> {
    // Uncompressed P-256 point: 1 byte prefix (0x04) + 32-byte X + 32-byte Y.
    if uncompressed.len() != 65 {
        return Err(KeyError::Backend(
            format!(
                "uncompressed P-256 point must be 65 bytes (got {})",
                uncompressed.len()
            )
            .into(),
        ));
    }
    if uncompressed[0] != 0x04 {
        return Err(KeyError::Backend(
            format!(
                "expected uncompressed prefix 0x04, got {:#04x}",
                uncompressed[0]
            )
            .into(),
        ));
    }
    let x = &uncompressed[1..33];
    let y = &uncompressed[33..65];
    let mut out = [0u8; 33];
    out[0] = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(x);
    Ok(out)
}

/// Parse an ASN.1 DER-encoded ECDSA signature (`SEQUENCE(r, s)`) into 64-byte
/// r||s raw form. Low-S normalisation happens at a higher layer via
/// `crate::tpm::assemble_and_normalise` (shared between backends).
pub(crate) fn der_ecdsa_to_raw(der: &[u8]) -> Result<([u8; 32], [u8; 32]), KeyError> {
    // Minimal ASN.1 parser — only accepts SEQUENCE { INTEGER r, INTEGER s }.
    // ECDSA-DER is well-constrained so we can skip a full parser.
    let mut cur = der;

    // SEQUENCE tag
    take_tag(&mut cur, 0x30)?;
    let seq_len = take_length(&mut cur)?;
    if cur.len() < seq_len {
        return Err(KeyError::Backend("DER SEQUENCE truncated".into()));
    }
    cur = &cur[..seq_len];

    take_tag(&mut cur, 0x02)?; // INTEGER r
    let r_len = take_length(&mut cur)?;
    if cur.len() < r_len {
        return Err(KeyError::Backend("DER r truncated".into()));
    }
    let (r_bytes, rest) = cur.split_at(r_len);
    cur = rest;

    take_tag(&mut cur, 0x02)?; // INTEGER s
    let s_len = take_length(&mut cur)?;
    if cur.len() < s_len {
        return Err(KeyError::Backend("DER s truncated".into()));
    }
    let (s_bytes, _tail) = cur.split_at(s_len);

    let r = integer_to_32_bytes(r_bytes)?;
    let s = integer_to_32_bytes(s_bytes)?;
    Ok((r, s))
}

fn take_tag(cur: &mut &[u8], expected: u8) -> Result<(), KeyError> {
    let tag = *cur
        .first()
        .ok_or_else(|| KeyError::Backend("DER: unexpected end".into()))?;
    if tag != expected {
        return Err(KeyError::Backend(
            format!("DER tag mismatch: expected {expected:#04x}, got {tag:#04x}").into(),
        ));
    }
    *cur = &cur[1..];
    Ok(())
}

fn take_length(cur: &mut &[u8]) -> Result<usize, KeyError> {
    let first = *cur
        .first()
        .ok_or_else(|| KeyError::Backend("DER: no length byte".into()))?;
    *cur = &cur[1..];
    if first < 0x80 {
        Ok(first as usize)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(KeyError::Backend(
                "DER: unsupported long-form length".into(),
            ));
        }
        if cur.len() < n {
            return Err(KeyError::Backend("DER: length truncated".into()));
        }
        let mut out = 0usize;
        for &b in &cur[..n] {
            out = (out << 8) | b as usize;
        }
        *cur = &cur[n..];
        Ok(out)
    }
}

fn integer_to_32_bytes(raw: &[u8]) -> Result<[u8; 32], KeyError> {
    // ASN.1 INTEGER may have a leading 0x00 to indicate positive, or be
    // shorter than 32 bytes if the high bytes were zero.
    let trimmed = if raw.first() == Some(&0x00) && raw.len() > 32 {
        &raw[1..]
    } else {
        raw
    };
    if trimmed.len() > 32 {
        return Err(KeyError::Backend(
            format!("DER INTEGER wider than 32 bytes ({})", trimmed.len()).into(),
        ));
    }
    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

// ---- Linux-only backend ------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_backend {
    //! Real YubiKey interaction via the `yubikey` crate.

    use std::sync::Mutex;

    use crate::{AttestationChain, KeyError, Signature};

    pub(super) struct Inner {
        // Wrapped `yubikey::YubiKey` session. `yubikey::YubiKey` is !Send so
        // we gate the whole Inner to a single thread via Mutex and spawn_blocking
        // at the call-site.
        _session: Mutex<()>,
    }

    pub(super) fn discover() -> Result<(Inner, [u8; 33]), KeyError> {
        // TODO(B9 hardware slice): `yubikey::YubiKey::open()` enumerates the
        // first connected YubiKey via pcscd. Then `piv::metadata(slot = 0x9A)`
        // checks whether a P-256 key is present. If not, caller must run the
        // provisioning flow which generates a key with TouchPolicy::Always +
        // PinPolicy::Always. Public key is read via `piv::attest` which both
        // returns the attestation cert and lets us extract the pubkey.
        //
        // Return (inner, super::uncompressed_to_sec1_compressed(pubkey_bytes)?).
        Err(KeyError::Unavailable(
            "YubiKey PIV provisioning not yet wired — see yubikey.rs::linux_backend::discover"
                .into(),
        ))
    }

    impl Inner {
        pub(super) fn sign(&self, _digest: &[u8]) -> Result<Signature, KeyError> {
            // TODO(B9 hardware slice): yubikey::piv::sign_data(
            //   slot = 0x9A, data = digest, algorithm = EccP256, pin).
            // Returns DER-encoded ECDSA signature. Parse via
            // super::der_ecdsa_to_raw, then crate::tpm::assemble_and_normalise.
            Err(KeyError::Unavailable(
                "YubiKey signing not yet wired — see yubikey.rs::linux_backend::Inner::sign".into(),
            ))
        }

        pub(super) fn attestation(&self) -> Result<AttestationChain, KeyError> {
            // TODO(B9 hardware slice): yubikey::piv::attest(slot = 0x9A)
            // returns the attestation cert. F9 slot cert + Yubico PIV CA
            // complete the chain. All three DER-encoded into AttestationChain.certs.
            Err(KeyError::Unavailable(
                "YubiKey attestation not yet wired — see yubikey.rs::linux_backend::Inner::attestation".into(),
            ))
        }
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn uncompressed_to_sec1_even_y() {
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..33].fill(0xAB);
        uncompressed[64] = 0x02; // even Y
        let sec1 = uncompressed_to_sec1_compressed(&uncompressed).unwrap();
        assert_eq!(sec1[0], 0x02);
        assert_eq!(&sec1[1..], &uncompressed[1..33]);
    }

    #[test]
    fn uncompressed_to_sec1_odd_y() {
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[64] = 0x03; // odd Y
        let sec1 = uncompressed_to_sec1_compressed(&uncompressed).unwrap();
        assert_eq!(sec1[0], 0x03);
    }

    #[test]
    fn uncompressed_rejects_wrong_length() {
        assert!(uncompressed_to_sec1_compressed(&[0x04; 64]).is_err());
        assert!(uncompressed_to_sec1_compressed(&[0x04; 66]).is_err());
        assert!(uncompressed_to_sec1_compressed(&[]).is_err());
    }

    #[test]
    fn uncompressed_rejects_wrong_prefix() {
        let mut buf = [0u8; 65];
        buf[0] = 0x02; // compressed prefix — wrong for this function
        assert!(uncompressed_to_sec1_compressed(&buf).is_err());
    }

    #[test]
    fn der_ecdsa_minimal_signature_parses() {
        // DER for: SEQUENCE { INTEGER 1, INTEGER 2 }
        // 30 06 02 01 01 02 01 02
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let (r, s) = der_ecdsa_to_raw(&der).unwrap();
        let mut expected_r = [0u8; 32];
        expected_r[31] = 1;
        let mut expected_s = [0u8; 32];
        expected_s[31] = 2;
        assert_eq!(r, expected_r);
        assert_eq!(s, expected_s);
    }

    #[test]
    fn der_ecdsa_32_byte_components() {
        let r_bytes: Vec<u8> = (0..32).collect();
        let s_bytes: Vec<u8> = (32..64).collect();
        let mut der = vec![0x30, 2 + 32 + 2 + 32];
        der.push(0x02);
        der.push(32);
        der.extend_from_slice(&r_bytes);
        der.push(0x02);
        der.push(32);
        der.extend_from_slice(&s_bytes);
        let (r, s) = der_ecdsa_to_raw(&der).unwrap();
        assert_eq!(r.to_vec(), r_bytes);
        assert_eq!(s.to_vec(), s_bytes);
    }

    #[test]
    fn der_ecdsa_strips_positive_leading_zero() {
        // INTEGER with high bit set has a leading 0x00 for positive encoding.
        // r = 0xFF...FF (33 bytes with leading 0x00)
        let mut r_encoded = vec![0x00];
        r_encoded.extend_from_slice(&[0xFF; 32]);

        let mut der = vec![0x30];
        let content_len = 2 + r_encoded.len() + 2 + 1;
        der.push(content_len as u8);
        der.push(0x02);
        der.push(r_encoded.len() as u8);
        der.extend_from_slice(&r_encoded);
        der.push(0x02);
        der.push(1);
        der.push(0x01);

        let (r, s) = der_ecdsa_to_raw(&der).unwrap();
        assert_eq!(r, [0xFF; 32]);
        let mut expected_s = [0u8; 32];
        expected_s[31] = 1;
        assert_eq!(s, expected_s);
    }

    #[test]
    fn der_ecdsa_rejects_non_sequence() {
        assert!(der_ecdsa_to_raw(&[0x02, 0x01, 0x01]).is_err());
    }

    #[test]
    fn der_ecdsa_rejects_component_too_wide() {
        // 33-byte integer with NO leading 0x00 (not a positive-prefix case) =
        // invalid for P-256 ECDSA r/s.
        let mut der = vec![0x30, 2 + 33 + 2 + 1];
        der.push(0x02);
        der.push(33);
        der.extend_from_slice(&[0x01; 33]); // MSB not 0x00, so real 33 bytes
        der.push(0x02);
        der.push(1);
        der.push(0x01);
        assert!(der_ecdsa_to_raw(&der).is_err());
    }
}
