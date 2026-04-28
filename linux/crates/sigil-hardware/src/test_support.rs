//! Test-only software-backed `HardwareKey`.
//!
//! **Not for production use.** Private key lives in userspace memory.
//! Gated behind the `test-support` cargo feature so release builds cannot
//! pull this module even by accident.
//!
//! Purpose: prove the trait contract + signature-payload machinery hang
//! together end-to-end. TPM + YubiKey backends will satisfy the same tests
//! once wired — the only difference is where the key material lives.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};

use crate::{AttestationChain, CompressedPublicKey, HardwareKey, KeyError, Signature};

/// Software-backed signing key for integration tests.
pub struct SoftwareTestKey {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl SoftwareTestKey {
    /// Generate a fresh key using the supplied RNG.
    pub fn generate(rng: &mut impl rand::RngCore) -> Self {
        let signing = SigningKey::random(&mut RngAdapter(rng));
        let verifying = VerifyingKey::from(&signing);
        Self { signing, verifying }
    }

    /// Expose the verifying key so tests can verify the signatures produced.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying
    }
}

impl HardwareKey for SoftwareTestKey {
    fn public_key(&self) -> CompressedPublicKey {
        let encoded = self.verifying.to_encoded_point(true);
        let bytes = encoded.as_bytes();
        let mut out = [0u8; 33];
        out.copy_from_slice(bytes);
        CompressedPublicKey(out)
    }

    fn sign(&self, payload: &[u8]) -> Result<Signature, KeyError> {
        let sig: P256Signature = self.signing.sign(payload);
        // p256 ecdsa signatures are already low-S normalised by default in 0.13.
        let bytes = sig.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(Signature(out))
    }

    fn attestation(&self) -> Result<AttestationChain, KeyError> {
        // Test backend has no attestation story. Real TPM/YubiKey backends
        // return a cert chain rooted in vendor CA per Knox §3.6.
        Err(KeyError::Unavailable(
            "software test key has no attestation".into(),
        ))
    }
}

/// Verify a `Signature` produced by a `SoftwareTestKey` against its public key.
/// Helper for tests.
pub fn verify(verifying: &VerifyingKey, payload: &[u8], sig: &Signature) -> bool {
    let parsed = match P256Signature::from_slice(sig.as_bytes()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying.verify(payload, &parsed).is_ok()
}

/// Bridge a caller-supplied RNG to `p256`'s rand_core expectations. Both the
/// `rand` and `rand_core` `RngCore` traits share the same method signatures —
/// we just forward. `CryptoRng` is asserted here because tests pass either
/// `rand::thread_rng()` (OsRng-backed) or `ChaCha20Rng` (deterministic).
struct RngAdapter<'a, R: rand::RngCore>(&'a mut R);

impl<'a, R: rand::RngCore> rand_core::RngCore for RngAdapter<'a, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<'a, R: rand::RngCore> rand_core::CryptoRng for RngAdapter<'a, R> {}
