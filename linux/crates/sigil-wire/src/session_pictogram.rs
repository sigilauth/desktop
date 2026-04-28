//! Session pictogram derivation for pair handshake MITM detection.
//!
//! Algorithm per `/api/wire-protocol.md` §4.2:
//! 1. Hash inputs: password = SHA-256(server_pub || client_pub || server_nonce)
//! 2. Argon2id KDF with salt = "SIGIL-PAIR-V1\x00\x00\x00" (16 bytes, zero-padded)
//!    - m = 65536 (64 MiB memory)
//!    - t = 10 iterations
//!    - p = 1 (single-threaded)
//!    - dkLen = 32 bytes
//! 3. Extract 6 × 16-bit indices from derived key: (derived[2*i] << 8) | derived[2*i+1]
//! 4. Modulo 192 (pool size)
//! 5. Map to emoji-word pairs from 192-entry pool
//!
//! **Entropy:** 6 × log₂(192) ≈ 46 bits
//!
//! **Work factor:** Argon2id(m=64 MiB, t=10) ≈ 3s per derivation on attacker GPU
//!
//! **Collision resistance:** 10-second handshake window + rate limiting makes
//! real-time grinding cryptographically infeasible (§4.2).

use sha2::{Digest, Sha256};
use argon2::{Argon2, Version};
use thiserror::Error;

use crate::crypto::DOMAIN_PAIR_V1;

/// 192-entry pictogram pool from `/api/pictogram-pool-v1.json`.
/// Pinned order — reordering is a protocol break.
pub const SESSION_PICTOGRAM_POOL: [&str; 192] = [
    "apple", "banana", "grapes", "orange", "lemon", "cherry", "strawberry", "kiwi",
    "peach", "melon", "pineapple", "pear", "coconut", "honeydew",
    "carrot", "corn", "broccoli", "mushroom", "pepper", "avocado", "tomato", "peanut",
    "cucumber", "potato", "eggplant", "salad", "chestnut", "yam", "grain", "herb",
    "baguette", "egg",
    "pizza", "burger", "taco", "donut", "cookie", "cake", "bread", "popcorn",
    "icecream", "chocolate", "candy", "croissant", "pretzel", "pancake", "cheese", "bacon",
    "coffee", "tea", "soda", "bottle", "sake", "beer", "wine", "milk",
    "beers", "toast", "whiskey", "tropical", "martini", "champagne",
    "car", "taxi", "bus", "rocket", "plane", "helicopter", "sailboat", "bicycle",
    "train", "tram", "subway", "ambulance", "firetruck", "police", "scooter", "ferry",
    "dog", "cat", "mouse", "rabbit", "fox", "bear", "panda", "koala",
    "tiger", "lion", "cow", "pig", "frog", "monkey", "elephant", "giraffe",
    "bird", "eagle", "duck", "owl", "penguin", "chicken", "parrot", "rooster",
    "turkey", "fish", "reef", "blowfish", "shark", "octopus", "shell", "crab",
    "turtle", "snake",
    "tree", "pine", "palm", "cactus", "clover", "blossom", "hibiscus", "sunflower",
    "tulip", "rose", "maple", "leaf", "butterfly", "bee", "ladybug", "rainbow",
    "star", "moon", "sun", "sunny",
    "cloudy", "cloud", "rainy", "storm", "lightning", "snow", "snowman", "wind",
    "tornado", "fog", "droplet", "bolt",
    "house", "home", "castle", "temple", "tower", "moai", "tent", "mountain",
    "peak", "volcano", "island", "beach", "desert", "camping", "foggy", "bridge",
    "key", "bell", "books", "anchor", "crown", "diamond", "fire", "gift",
    "balloon", "ribbon", "hammer", "wrench", "target", "dice", "palette", "circus",
    "guitar", "piano", "trumpet", "sax", "drum", "violin", "soccer", "basketball",
    "football", "baseball", "tennis", "volleyball", "rugby", "pingpong", "badminton", "golf",
];

/// Session pictogram derivation errors.
#[derive(Debug, Error)]
pub enum SessionPictogramError {
    /// Argon2id derivation failed.
    #[error("Argon2id derivation failed")]
    Argon2Failed,
}

/// Derive 6-entry session pictogram from pair handshake inputs.
///
/// Inputs:
/// - `server_pub`: 33 bytes (compressed P-256 public key)
/// - `client_pub`: 33 bytes (compressed P-256 public key)
/// - `server_nonce`: 32 bytes (cryptographic random)
///
/// Returns: 6 emoji names from `SESSION_PICTOGRAM_POOL`.
pub fn derive(server_pub: &[u8; 33], client_pub: &[u8; 33], server_nonce: &[u8; 32]) -> Result<[&'static str; 6], SessionPictogramError> {
    let mut hasher = Sha256::new();
    hasher.update(server_pub);
    hasher.update(client_pub);
    hasher.update(server_nonce);
    let password = hasher.finalize();

    let params = argon2::Params::new(65536, 10, 1, Some(32))
        .map_err(|_| SessionPictogramError::Argon2Failed)?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    );

    let mut derived = [0u8; 32];
    argon2.hash_password_into(&password, DOMAIN_PAIR_V1, &mut derived)
        .map_err(|_| SessionPictogramError::Argon2Failed)?;

    let mut indices = [0usize; 6];
    for i in 0..6 {
        let word_index = u16::from_be_bytes([derived[2 * i], derived[2 * i + 1]]);
        indices[i] = (word_index % 192) as usize;
    }

    Ok([
        SESSION_PICTOGRAM_POOL[indices[0]],
        SESSION_PICTOGRAM_POOL[indices[1]],
        SESSION_PICTOGRAM_POOL[indices[2]],
        SESSION_PICTOGRAM_POOL[indices[3]],
        SESSION_PICTOGRAM_POOL[indices[4]],
        SESSION_PICTOGRAM_POOL[indices[5]],
    ])
}

/// Space-separated speakable form for JSON field `session_pictogram_speakable`.
pub fn speakable(session_pictogram: &[&str; 6]) -> String {
    session_pictogram.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_deterministic() {
        let server_pub = [0x02; 33];
        let client_pub = [0x03; 33];
        let server_nonce = [0x04; 32];

        let pictogram1 = derive(&server_pub, &client_pub, &server_nonce).unwrap();
        let pictogram2 = derive(&server_pub, &client_pub, &server_nonce).unwrap();

        assert_eq!(pictogram1, pictogram2, "Derivation must be deterministic");
    }

    #[test]
    fn derive_different_inputs() {
        let server_pub = [0x02; 33];
        let client_pub = [0x03; 33];
        let server_nonce1 = [0x04; 32];
        let mut server_nonce2 = [0x04; 32];
        server_nonce2[0] = 0x05;

        let pictogram1 = derive(&server_pub, &client_pub, &server_nonce1).unwrap();
        let pictogram2 = derive(&server_pub, &client_pub, &server_nonce2).unwrap();

        assert_ne!(pictogram1, pictogram2, "Different nonces must produce different pictograms");
    }

    #[test]
    fn all_indices_in_range() {
        let server_pub = [0x02; 33];
        let client_pub = [0x03; 33];
        let server_nonce = [0x04; 32];

        let pictogram = derive(&server_pub, &client_pub, &server_nonce).unwrap();

        for name in pictogram.iter() {
            assert!(
                SESSION_PICTOGRAM_POOL.contains(name),
                "Pictogram entry '{}' not in pool",
                name
            );
        }
    }
}
