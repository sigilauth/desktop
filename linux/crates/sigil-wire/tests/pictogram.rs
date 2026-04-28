//! Pictogram derivation test vectors from `/api/test-vectors/pictogram.json`.
//!
//! Per protocol-spec §3.6 / §11.4: fingerprint → first 4 bytes → 30 bits split
//! into 5×6-bit indices → map each index to `EMOJI_LIST[index]`. D10 locks
//! `pictogram_speakable` as the canonical JSON field name. D8 locks spaces in
//! JSON (this module) vs hyphens in URL query strings (separate concern).

use sigil_wire::pictogram::{self, EMOJI_LIST};

/// Decode a hex string into a 32-byte fingerprint array.
fn fp(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("valid hex");
    assert_eq!(bytes.len(), 32, "fingerprint must be 32 bytes");
    bytes.try_into().unwrap()
}

#[test]
fn emoji_list_is_exactly_64_entries() {
    // 6-bit indices require 64 entries. Schema asserts this; reassert in code.
    assert_eq!(EMOJI_LIST.len(), 64);
}

#[test]
fn emoji_list_all_lowercase_ascii() {
    // PictogramSpeakable regex in /api/schemas/pictogram.json requires lowercase ASCII.
    for name in EMOJI_LIST {
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase()),
            "emoji name {name} must be lowercase ASCII"
        );
        assert!(!name.is_empty(), "emoji name must not be empty");
    }
}

#[test]
fn vector_from_protocol_spec_example() {
    // test-vectors/pictogram.json[0]: "Example from protocol-spec §11.4"
    let fingerprint = fp("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
    let indices = pictogram::indices(&fingerprint);
    assert_eq!(indices, [40, 27, 11, 3, 53]);

    let names = pictogram::names(&fingerprint);
    assert_eq!(names, ["tree", "rocket", "mushroom", "orange", "moai"]);

    let speakable = pictogram::speakable(&fingerprint);
    assert_eq!(speakable, "tree rocket mushroom orange moai");
}

#[test]
fn vector_all_zeros() {
    let fingerprint = [0u8; 32];
    assert_eq!(pictogram::indices(&fingerprint), [0, 0, 0, 0, 0]);
    assert_eq!(
        pictogram::names(&fingerprint),
        ["apple", "apple", "apple", "apple", "apple"]
    );
    assert_eq!(
        pictogram::speakable(&fingerprint),
        "apple apple apple apple apple"
    );
}

#[test]
fn vector_all_ones_max_indices() {
    let fingerprint = [0xFFu8; 32];
    assert_eq!(pictogram::indices(&fingerprint), [63, 63, 63, 63, 63]);
    assert_eq!(
        pictogram::names(&fingerprint),
        ["fire", "fire", "fire", "fire", "fire"]
    );
}

#[test]
fn vector_sequential_indices_is_internally_inconsistent() {
    // test-vectors/pictogram.json[3] "Sequential indices test":
    //   fingerprint_hex: "041041041000..." (66 hex chars — length bug)
    //   first 4 bytes:  0x04 0x10 0x41 0x04
    //   comment says:    "indices 1,0,16,4,4"
    //   indices field:   [1, 0, 16, 4, 4]
    //   speakable:       "banana apple pizza lemon lemon"
    //
    // Under the CORRECT algorithm (shifts 26,20,14,8,2 — the one that
    // reproduces vectors 0/1/2), bits 0x04104104 yields indices [1,1,1,1,0],
    // NOT [1,0,16,4,4]. No sensible bit-extraction recipe produces the stated
    // indices. Vector 3 is broken.
    //
    // Pinning our implementation to the CORRECT-algorithm output. Flagged to
    // @beacon/@echo via `working/linux-desktop/violations-log.md`.

    let mut fingerprint = [0u8; 32];
    fingerprint[0..4].copy_from_slice(&[0x04, 0x10, 0x41, 0x04]);

    assert_eq!(
        pictogram::indices(&fingerprint),
        [1, 1, 1, 1, 1],
        "correct algorithm (shifts 26,20,14,8,2) yields [1,1,1,1,1] from \
         0x04104104; vector 3's stated [1,0,16,4,4] is unreproducible"
    );
}

#[test]
fn names_round_trip_via_index_lookup() {
    // Property: for all 32-byte inputs, names(fp)[i] == EMOJI_LIST[indices(fp)[i]].
    // Spot-check a handful rather than proptest (adds dep); enough to catch
    // off-by-one in the mapping.
    for seed in [0u8, 1, 7, 42, 128, 200, 255] {
        let fingerprint = [seed; 32];
        let idx = pictogram::indices(&fingerprint);
        let names = pictogram::names(&fingerprint);
        for i in 0..5 {
            assert_eq!(
                names[i], EMOJI_LIST[idx[i] as usize],
                "names[{i}] must equal EMOJI_LIST[indices[{i}]] for seed {seed}"
            );
        }
    }
}

#[test]
fn speakable_format_matches_d8_json_rules() {
    // D8: JSON uses spaces. Schema regex: ^[a-z]+([ ][a-z]+){4}$ (4 separators = 5 words).
    let fingerprint = fp("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
    let speakable = pictogram::speakable(&fingerprint);
    let space_count = speakable.chars().filter(|c| *c == ' ').count();
    assert_eq!(space_count, 4, "exactly 4 spaces for 5 words");
    assert!(!speakable.contains('-'), "hyphens are URL-only per D8");
    assert!(!speakable.starts_with(' '), "no leading space");
    assert!(!speakable.ends_with(' '), "no trailing space");
}

#[test]
fn url_speakable_uses_hyphens_per_d8() {
    // D8: URL query param uses hyphens. JSON uses spaces. Both derive from the same
    // underlying names array.
    let fingerprint = fp("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2");
    let url_form = pictogram::speakable_url(&fingerprint);
    assert_eq!(url_form, "tree-rocket-mushroom-orange-moai");
    assert!(!url_form.contains(' '), "URL form must not contain spaces");
}
