//! Pictogram derivation from a 32-byte fingerprint.
//!
//! Algorithm per protocol-spec §3.6 / §11.4 and the test vectors at
//! `/api/test-vectors/pictogram.json`:
//!
//! 1. Take the first 4 fingerprint bytes, interpret as a big-endian `u32`.
//! 2. Extract 5 × 6-bit indices from **the top 30 bits**, grouped left-to-right.
//!    The bottom 2 bits of the 32-bit value are discarded.
//!    - `idx0 = (bits >> 26) & 0x3F`
//!    - `idx1 = (bits >> 20) & 0x3F`
//!    - `idx2 = (bits >> 14) & 0x3F`
//!    - `idx3 = (bits >> 8)  & 0x3F`
//!    - `idx4 = (bits >> 2)  & 0x3F`
//! 3. Look each index up in [`EMOJI_LIST`].
//!
//! Speakable output follows DECISIONS.md D8:
//! - JSON: space-separated (`speakable`).
//! - URL query: hyphen-separated (`speakable_url`).
//!
//! **Note to @beacon / @echo:** the plain-text `indices` description under
//! `/api/schemas/pictogram.json#/definitions/DerivationAlgorithm` gives shifts
//! of `(24, 18, 12, 6, 0)` — that recipe does not reproduce the three
//! internally-consistent test vectors. Only shifts `(26, 20, 14, 8, 2)`
//! reproduce vectors 0, 1, and 2. Schema needs correcting. Flagged via
//! `working/linux-desktop/violations-log.md`.

/// Canonical 64-entry emoji list. Pinned in `/api/schemas/pictogram.json`
/// and `/api/test-vectors/pictogram.json`. Reordering is a protocol-break.
pub const EMOJI_LIST: [&str; 64] = [
    "apple",
    "banana",
    "grapes",
    "orange",
    "lemon",
    "cherry",
    "strawberry",
    "kiwi",
    "carrot",
    "corn",
    "broccoli",
    "mushroom",
    "pepper",
    "avocado",
    "onion",
    "peanut",
    "pizza",
    "burger",
    "taco",
    "donut",
    "cookie",
    "cake",
    "cupcake",
    "popcorn",
    "car",
    "taxi",
    "bus",
    "rocket",
    "plane",
    "helicopter",
    "sailboat",
    "bicycle",
    "dog",
    "cat",
    "fish",
    "butterfly",
    "bee",
    "fox",
    "lion",
    "elephant",
    "tree",
    "sunflower",
    "cactus",
    "clover",
    "blossom",
    "rainbow",
    "star",
    "moon",
    "house",
    "mountain",
    "peak",
    "volcano",
    "island",
    "moai",
    "tent",
    "castle",
    "key",
    "bell",
    "books",
    "guitar",
    "anchor",
    "crown",
    "diamond",
    "fire",
];

/// Extract the 5 × 6-bit indices per the schema's `DerivationAlgorithm`.
///
/// Panics only if `fingerprint.len() < 4`, which the signature prevents.
pub fn indices(fingerprint: &[u8; 32]) -> [u8; 5] {
    let bits = u32::from_be_bytes([
        fingerprint[0],
        fingerprint[1],
        fingerprint[2],
        fingerprint[3],
    ]);
    [
        ((bits >> 26) & 0x3F) as u8,
        ((bits >> 20) & 0x3F) as u8,
        ((bits >> 14) & 0x3F) as u8,
        ((bits >> 8) & 0x3F) as u8,
        ((bits >> 2) & 0x3F) as u8,
    ]
}

/// Map indices to emoji names.
pub fn names(fingerprint: &[u8; 32]) -> [&'static str; 5] {
    let idx = indices(fingerprint);
    [
        EMOJI_LIST[idx[0] as usize],
        EMOJI_LIST[idx[1] as usize],
        EMOJI_LIST[idx[2] as usize],
        EMOJI_LIST[idx[3] as usize],
        EMOJI_LIST[idx[4] as usize],
    ]
}

/// Space-separated speakable form (JSON field `pictogram_speakable`).
///
/// Matches schema regex `^[a-z]+([ ][a-z]+){4}$`.
pub fn speakable(fingerprint: &[u8; 32]) -> String {
    names(fingerprint).join(" ")
}

/// Hyphen-separated form for URL query parameters per D8.
pub fn speakable_url(fingerprint: &[u8; 32]) -> String {
    names(fingerprint).join("-")
}
