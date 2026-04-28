//! Sigil Auth protocol wire types + pure helpers.
//!
//! This crate is the foundation shared by the hardware-key abstraction, the
//! UI, and the networking layer. Everything here is deterministic, pure, and
//! contract-pinned to `/api/openapi.yaml` + `/api/schemas/*.json` +
//! `/api/test-vectors/*.json`.
//!
//! No GTK dependencies. No D-Bus. No I/O. Pure logic only.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod crypto;
pub mod envelope;
pub mod fingerprint;
pub mod nonce_store;
pub mod pictogram;
pub mod session_pictogram;
pub mod signature_payload;
pub mod wire;

/// Convenience re-export.
pub use fingerprint::Fingerprint;
