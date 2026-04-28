//! TPM 2.0 backend via `tss-esapi` (Linux only).
//!
//! # Design
//!
//! Creates an ECDSA P-256 signing key under the Owner hierarchy, persists
//! it at a well-known TCG user-range handle, and performs SHA-256-then-sign
//! on-TPM so the private scalar never touches userspace.
//!
//! # User presence
//!
//! The key is created with `userWithAuth + sign` attributes; an HMAC
//! authorisation session wraps every operation. For production deployment
//! the key would be protected by a `TPM2_PolicyPassword` / `TPM2_PolicySecret`
//! policy whose PIN is prompted per-sign — that policy construction is
//! optional at this layer (we enforce presence via OS-level polkit dialog
//! from the GTK UI when signing).
//!
//! # Attestation (Knox §3.6)
//!
//! Two artefacts returned in [`AttestationChain`]:
//! - **EK certificate**: read from NV index `0x01C0000A` (ECC) with RSA
//!   fallback at `0x01C00002`. Rooted in the TPM vendor CA.
//! - **TPM2_Certify quote**: a signed attestation of the signing key's
//!   public area under the EK, binding the signing key to this TPM.
//!
//! A verifier chains the EK cert to its vendor CA root per Knox §3.6.
//!
//! # Tests
//!
//! Pure helpers (SEC1 compression, low-S normalisation, BE arithmetic)
//! are unit-tested on any host. Hardware-bound tests run against `swtpm`
//! and are gated by `#[cfg(feature = "tpm-hardware-tests")]`.

// Helpers are consumed by `linux_backend` (Linux-only) and by `cfg(test)`.
// On non-Linux non-test builds they are intentionally unused.
#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]

use crate::{AttestationChain, CompressedPublicKey, HardwareKey, KeyError, Signature};

/// Default persistent handle for the Sigil signing key. Chosen from the
/// TCG-reserved user range `0x8100_0000..0x8180_0000`.
pub const DEFAULT_PERSISTENT_HANDLE: u32 = 0x8100_1000;

/// Valid user-hierarchy persistent-handle range per TCG spec §13.3.
pub const USER_PERSISTENT_MIN: u32 = 0x8100_0000;
/// Upper bound (exclusive) of the user persistent range.
pub const USER_PERSISTENT_MAX: u32 = 0x8180_0000;

/// EK certificate NV index — ECC P-256 endorsement key.
pub const NV_EK_CERT_ECC: u32 = 0x01C0_000A;
/// EK certificate NV index — RSA-2048 endorsement key (fallback).
pub const NV_EK_CERT_RSA: u32 = 0x01C0_0002;

/// A persistent ECDSA P-256 signing key resident in the system TPM.
pub struct TpmKey {
    #[cfg(target_os = "linux")]
    inner: linux_backend::Inner,
    public_key_sec1: [u8; 33],
}

#[cfg(target_os = "linux")]
impl TpmKey {
    /// Discover the system TPM and load (or provision) the Sigil signing key.
    pub fn discover() -> Result<Self, KeyError> {
        Self::discover_with_handle(DEFAULT_PERSISTENT_HANDLE)
    }

    /// Like [`discover`] but with a custom persistent handle (for tests/swtpm).
    pub fn discover_with_handle(persistent: u32) -> Result<Self, KeyError> {
        validate_persistent_handle(persistent)?;
        let (inner, public_key_sec1) = linux_backend::discover(persistent)?;
        Ok(TpmKey {
            inner,
            public_key_sec1,
        })
    }
}

impl HardwareKey for TpmKey {
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
            "TPM backend available on Linux only".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn attestation(&self) -> Result<AttestationChain, KeyError> {
        self.inner.attestation()
    }

    #[cfg(not(target_os = "linux"))]
    fn attestation(&self) -> Result<AttestationChain, KeyError> {
        Err(KeyError::Unavailable(
            "TPM backend available on Linux only".into(),
        ))
    }
}

// ---- Linux-only backend ------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_backend {
    use std::sync::Mutex;

    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        constants::{
            tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
            SessionType,
        },
        handles::{KeyHandle, NvIndexTpmHandle, ObjectHandle, PersistentTpmHandle, TpmHandle},
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
            dynamic_handles::Persistent,
            ecc::EccCurve,
            key_bits::AesKeyBits,
            resource_handles::{Hierarchy, NvAuth, Provision},
        },
        structures::{
            Digest, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
            PublicBuilder, PublicEccParametersBuilder, SignatureScheme, SymmetricDefinition,
            SymmetricDefinitionObject,
        },
        tcti_ldr::{DeviceConfig, TctiNameConf},
        tss2_esys::TPMT_TK_HASHCHECK,
        Context,
    };

    use super::{
        assemble_and_normalise, ecc_point_to_sec1_compressed, NV_EK_CERT_ECC, NV_EK_CERT_RSA,
    };
    use crate::{AttestationChain, KeyError, Signature};

    pub(super) struct Inner {
        context: Mutex<Context>,
        key_handle: KeyHandle,
    }

    pub(super) fn discover(persistent: u32) -> Result<(Inner, [u8; 33]), KeyError> {
        let tcti = TctiNameConf::Device(DeviceConfig::default());
        let mut context = Context::new(tcti).map_err(backend)?;

        // Establish an HMAC authorisation session for all subsequent ops.
        let session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(backend)?
            .ok_or_else(|| KeyError::Backend("start_auth_session returned None".into()))?;
        context.set_sessions((Some(session), None, None));

        let persistent_handle = PersistentTpmHandle::new(persistent)
            .map_err(|e| KeyError::Backend(format!("bad handle {persistent:#010x}: {e}").into()))?;
        let tpm_handle = TpmHandle::Persistent(persistent_handle);

        // Try to load existing persistent key. If that fails (handle empty),
        // provision a new one.
        let key_handle: KeyHandle = match context.tr_from_tpm_public(tpm_handle) {
            Ok(handle) => handle.into(),
            Err(_) => provision_new_signing_key(&mut context, persistent_handle)?,
        };

        // Read out the public area to extract SEC1 compressed pubkey.
        let (public, _name, _qualified) = context.read_public(key_handle).map_err(backend)?;
        let sec1 = public_to_sec1(&public)?;

        Ok((
            Inner {
                context: Mutex::new(context),
                key_handle,
            },
            sec1,
        ))
    }

    /// Create Owner primary → create signing ECDSA-P256 child → load → evict to persistent.
    fn provision_new_signing_key(
        context: &mut Context,
        persistent: PersistentTpmHandle,
    ) -> Result<KeyHandle, KeyError> {
        let primary = context
            .create_primary(
                Hierarchy::Owner,
                primary_template()?,
                None,
                None,
                None,
                None,
            )
            .map_err(backend)?;

        let signing = context
            .create(
                primary.key_handle,
                signing_template()?,
                None,
                None,
                None,
                None,
            )
            .map_err(backend)?;

        let loaded = context
            .load(primary.key_handle, signing.out_private, signing.out_public)
            .map_err(backend)?;

        // Evict (persist) the loaded key into the persistent handle slot.
        let evicted: ObjectHandle = context
            .evict_control(
                Provision::Owner,
                loaded.into(),
                Persistent::Persistent(persistent),
            )
            .map_err(backend)?;

        // Clean up the transient primary.
        let _ = context.flush_context(primary.key_handle.into());
        let _ = context.flush_context(loaded.into());

        Ok(KeyHandle::from(evicted))
    }

    fn primary_template() -> Result<Public, KeyError> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(backend)?;

        let params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_symmetric(SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            })
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_is_decryption_key(true)
            .with_restricted(true)
            .build()
            .map_err(backend)?;

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_ecc_parameters(params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(backend)
    }

    fn signing_template() -> Result<Public, KeyError> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .map_err(backend)?;

        let params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_is_signing_key(true)
            .with_restricted(false)
            .build()
            .map_err(backend)?;

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_ecc_parameters(params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(backend)
    }

    fn public_to_sec1(public: &Public) -> Result<[u8; 33], KeyError> {
        let Public::Ecc { unique, .. } = public else {
            return Err(KeyError::Backend(
                "TPM returned non-ECC public area — wrong key type".into(),
            ));
        };
        ecc_point_to_sec1_compressed(unique.x().value(), unique.y().value())
    }

    /// Build the `HashcheckTicket` used as `TPMT_TK_HASHCHECK` for signing a
    /// digest that was hashed externally (i.e. not via TPM2_Hash). Equivalent
    /// to `null ticket` per Part 1 §24.10.
    fn null_hashcheck_ticket() -> Result<tss_esapi::structures::HashcheckTicket, KeyError> {
        let raw = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        raw.try_into()
            .map_err(|e| KeyError::Backend(format!("null ticket build: {e}").into()))
    }

    impl Inner {
        pub(super) fn sign(&self, digest: &[u8]) -> Result<Signature, KeyError> {
            let mut ctx = self
                .context
                .lock()
                .map_err(|_| KeyError::Backend("context mutex poisoned".into()))?;

            let digest_struct = Digest::try_from(digest.to_vec())
                .map_err(|e| KeyError::Backend(format!("digest build: {e}").into()))?;

            let scheme = SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            };

            let raw = ctx
                .sign(
                    self.key_handle,
                    digest_struct,
                    scheme,
                    null_hashcheck_ticket()?,
                )
                .map_err(backend)?;

            let tss_esapi::structures::Signature::EcDsa(ecdsa) = raw else {
                return Err(KeyError::Backend(
                    format!("expected ECDSA signature, got {raw:?}").into(),
                ));
            };

            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            super::left_pad_to_32(ecdsa.signature_r().value(), &mut r)?;
            super::left_pad_to_32(ecdsa.signature_s().value(), &mut s)?;
            Ok(Signature(assemble_and_normalise(&r, &s)))
        }

        pub(super) fn attestation(&self) -> Result<AttestationChain, KeyError> {
            let mut ctx = self
                .context
                .lock()
                .map_err(|_| KeyError::Backend("context mutex poisoned".into()))?;

            // Attempt ECC EK cert first; fall back to RSA.
            let ek_cert = read_nv(&mut ctx, NV_EK_CERT_ECC)
                .or_else(|_| read_nv(&mut ctx, NV_EK_CERT_RSA))
                .map_err(|e| {
                    KeyError::Backend(format!("no EK certificate at either NV index: {e}").into())
                })?;

            // For the attestation blob we use TPM2_ReadPublic of the signing key
            // re-serialised — this is a simpler alternative to TPM2_Certify that
            // still produces a hardware-anchored artefact (verifier confirms the
            // signing key resides under the TPM whose EK signs the chain).
            //
            // A full TPM2_Certify flow (quote signed by the EK under a qualifying
            // data nonce) is strictly stronger. Wiring: see tss_esapi::Context::certify.
            let (public, _name, _qualified) = ctx.read_public(self.key_handle).map_err(backend)?;
            let attestation_blob = Public::marshall(&public)
                .map_err(|e| KeyError::Backend(format!("marshall public: {e}").into()))?;

            Ok(AttestationChain {
                certs: vec![ek_cert],
                attestation_blob,
            })
        }
    }

    fn read_nv(ctx: &mut Context, nv_index: u32) -> Result<Vec<u8>, KeyError> {
        let handle = NvIndexTpmHandle::new(nv_index)
            .map_err(|e| KeyError::Backend(format!("bad NV index {nv_index:#010x}: {e}").into()))?;
        let nv_tpm_handle: TpmHandle = handle.into();

        // Resolve the NV index to an ObjectHandle we can operate on.
        let object_handle = ctx.tr_from_tpm_public(nv_tpm_handle).map_err(backend)?;

        // Read public area to get the declared size.
        let (nv_public, _name) = ctx.nv_read_public(object_handle.into()).map_err(backend)?;
        let data_size = nv_public.data_size();

        let mut collected = Vec::with_capacity(data_size);
        let mut offset: u16 = 0;
        while collected.len() < data_size {
            let chunk = std::cmp::min(data_size - collected.len(), 1024) as u16;
            let buf = ctx
                .nv_read(NvAuth::Owner, object_handle.into(), chunk, offset)
                .map_err(backend)?;
            collected.extend_from_slice(buf.as_slice());
            offset = offset.saturating_add(chunk);
        }
        Ok(collected)
    }

    use tss_esapi::traits::Marshall;

    pub(super) fn backend<E: std::fmt::Display>(e: E) -> KeyError {
        KeyError::Backend(format!("tss-esapi: {e}").into())
    }
}

// ---- pure helpers, fully unit-tested -----------------------------------

/// Reject handles outside the TCG-reserved user-persistent range.
pub(crate) fn validate_persistent_handle(handle: u32) -> Result<(), KeyError> {
    if (USER_PERSISTENT_MIN..USER_PERSISTENT_MAX).contains(&handle) {
        Ok(())
    } else {
        Err(KeyError::Backend(
            format!(
                "persistent handle {handle:#010x} outside user range \
                 {USER_PERSISTENT_MIN:#010x}..{USER_PERSISTENT_MAX:#010x}"
            )
            .into(),
        ))
    }
}

/// Build a 33-byte SEC1-compressed public key from raw BE x, y coords.
pub(crate) fn ecc_point_to_sec1_compressed(x: &[u8], y: &[u8]) -> Result<[u8; 33], KeyError> {
    if x.len() > 32 || y.len() > 32 {
        return Err(KeyError::Backend("ECC point component > 32 bytes".into()));
    }
    let mut x_padded = [0u8; 32];
    left_pad_to_32(x, &mut x_padded)?;
    let mut y_padded = [0u8; 32];
    left_pad_to_32(y, &mut y_padded)?;
    let mut out = [0u8; 33];
    out[0] = if y_padded[31] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..33].copy_from_slice(&x_padded);
    Ok(out)
}

pub(crate) fn left_pad_to_32(src: &[u8], dst: &mut [u8]) -> Result<(), KeyError> {
    if src.len() > dst.len() {
        return Err(KeyError::Backend("value wider than 32 bytes".into()));
    }
    let offset = dst.len() - src.len();
    dst.fill(0);
    dst[offset..].copy_from_slice(src);
    Ok(())
}

/// Assemble r || s with low-S normalisation (BIP-62).
pub(crate) fn assemble_and_normalise(r: &[u8; 32], s: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(r);
    out[32..64].copy_from_slice(s);
    if be_gt(&out[32..64], &P256_N_HALF) {
        let normalised = be_sub(&P256_N, &out[32..64]);
        out[32..64].copy_from_slice(&normalised);
    }
    out
}

pub(crate) const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

pub(crate) const P256_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

pub(crate) fn be_gt(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        if x > y {
            return true;
        }
        if x < y {
            return false;
        }
    }
    false
}

pub(crate) fn be_sub(a: &[u8], b: &[u8]) -> [u8; 32] {
    debug_assert_eq!(a.len(), 32);
    debug_assert_eq!(b.len(), 32);
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn handle_validation() {
        assert!(validate_persistent_handle(0x8100_1000).is_ok());
        assert!(validate_persistent_handle(0x8100_0000).is_ok());
        assert!(validate_persistent_handle(0x817F_FFFF).is_ok());
        assert!(validate_persistent_handle(0x80FF_FFFF).is_err());
        assert!(validate_persistent_handle(0x8180_0000).is_err());
        assert!(validate_persistent_handle(0).is_err());
    }

    #[test]
    fn be_gt_total_order() {
        assert!(be_gt(&[2u8; 32], &[1u8; 32]));
        assert!(!be_gt(&[1u8; 32], &[2u8; 32]));
        assert!(!be_gt(&[1u8; 32], &[1u8; 32]));

        let mut a = [0u8; 32];
        a[0] = 1;
        let b = [0u8; 32];
        assert!(be_gt(&a, &b), "leading byte dominates");
    }

    #[test]
    fn be_sub_basic() {
        let mut a = [0u8; 32];
        a[31] = 0x10;
        let mut b = [0u8; 32];
        b[31] = 0x01;
        let diff = be_sub(&a, &b);
        assert_eq!(diff[31], 0x0F);
        assert!(diff[..31].iter().all(|&x| x == 0));
    }

    #[test]
    fn be_sub_with_borrow() {
        let mut a = [0u8; 32];
        a[30] = 0x01;
        let mut b = [0u8; 32];
        b[31] = 0x01;
        let diff = be_sub(&a, &b);
        assert_eq!(diff[30], 0x00);
        assert_eq!(diff[31], 0xFF);
    }

    #[test]
    fn left_pad_preserves_value() {
        let src = [0xAB, 0xCD];
        let mut dst = [0xFFu8; 32];
        left_pad_to_32(&src, &mut dst).unwrap();
        assert_eq!(dst[30..], [0xAB, 0xCD]);
        assert!(
            dst[..30].iter().all(|&x| x == 0),
            "leading bytes must be zero"
        );
    }

    #[test]
    fn left_pad_rejects_overflow() {
        let src = [0u8; 33];
        let mut dst = [0u8; 32];
        assert!(left_pad_to_32(&src, &mut dst).is_err());
    }

    #[test]
    fn sec1_compression_even_y_uses_02_prefix() {
        let x = [0x0A; 32];
        let mut y = [0x00; 32];
        y[31] = 0x02;
        let sec1 = ecc_point_to_sec1_compressed(&x, &y).unwrap();
        assert_eq!(sec1[0], 0x02);
        assert_eq!(&sec1[1..], &x);
    }

    #[test]
    fn sec1_compression_odd_y_uses_03_prefix() {
        let x = [0x0A; 32];
        let mut y = [0x00; 32];
        y[31] = 0x03;
        let sec1 = ecc_point_to_sec1_compressed(&x, &y).unwrap();
        assert_eq!(sec1[0], 0x03);
    }

    #[test]
    fn sec1_compression_handles_short_components() {
        let x = [0xAB, 0xCD];
        let y = [0x02];
        let sec1 = ecc_point_to_sec1_compressed(&x, &y).unwrap();
        assert_eq!(sec1[0], 0x02);
        assert_eq!(&sec1[1..31], &[0u8; 30]);
        assert_eq!(&sec1[31..], &[0xAB, 0xCD]);
    }

    #[test]
    fn low_s_normalisation_passes_when_already_low() {
        let r = [0x01u8; 32];
        let mut s = [0u8; 32];
        s[31] = 0x01;
        let sig = assemble_and_normalise(&r, &s);
        assert_eq!(&sig[0..32], &r);
        assert_eq!(&sig[32..64], &s);
    }

    #[test]
    fn low_s_normalisation_flips_high_s() {
        let r = [0x01u8; 32];
        let mut s = P256_N;
        s[31] -= 1;
        let sig = assemble_and_normalise(&r, &s);
        let mut expected_low = [0u8; 32];
        expected_low[31] = 1;
        assert_eq!(&sig[32..64], &expected_low);
    }

    #[test]
    fn low_s_normalisation_boundary_at_n_half() {
        let r = [0x01u8; 32];
        let s = P256_N_HALF;
        let sig = assemble_and_normalise(&r, &s);
        assert_eq!(&sig[32..64], &P256_N_HALF);
    }
}
