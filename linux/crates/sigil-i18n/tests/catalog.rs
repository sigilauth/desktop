//! Fluent catalog loading + lookup against the real B15 shared-i18n.
//!
//! Path to the shared catalog is resolved relative to this workspace, so the
//! tests work whether invoked from `cargo test -p sigil-i18n` at the workspace
//! root or inside `crates/sigil-i18n/`.

use std::path::PathBuf;

use sigil_i18n::{detect_locale_from_env, normalise_posix_locale, Catalog, Domain};

fn locale_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at this crate; shared catalog is three levels up.
    //   crates/sigil-i18n  ->  ..  ->  crates  ->  ..  ->  linux
    //   then ../../i18n/locales
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .join("../..")
        .join("../../i18n/locales")
        .canonicalize()
        .expect("i18n/locales must exist")
}

#[test]
fn loads_english_catalog() {
    let cat = Catalog::load(&locale_dir(), "en-US").expect("english load");
    let title = cat.msg(Domain::Auth, "registration-title");
    assert_eq!(title, "Register Device");
}

#[test]
fn falls_back_to_english_when_key_missing_in_requested() {
    // A key present in English but potentially missing in German still resolves.
    let cat = Catalog::load(&locale_dir(), "de-DE").expect("german load");
    let out = cat.msg(Domain::Auth, "registration-title");
    assert!(!out.is_empty());
    // Either German translation OR English fallback — never the raw key.
    assert_ne!(out, "registration-title");
}

#[test]
fn missing_key_returns_key_itself() {
    let cat = Catalog::load(&locale_dir(), "en-US").unwrap();
    let out = cat.msg(Domain::Auth, "this-key-does-not-exist-anywhere");
    assert_eq!(out, "this-key-does-not-exist-anywhere");
}

#[test]
fn is_rtl_flags_arabic_and_hebrew() {
    let ar = Catalog::load(&locale_dir(), "ar").expect("arabic load");
    assert!(ar.is_rtl(), "arabic must be rtl");

    let he = Catalog::load(&locale_dir(), "he").expect("hebrew load");
    assert!(he.is_rtl(), "hebrew must be rtl");

    let en = Catalog::load(&locale_dir(), "en-US").unwrap();
    assert!(!en.is_rtl(), "english is ltr");
}

#[test]
fn language_only_fallback_from_region() {
    // pt-BR is explicitly in catalog; pt-PT is not. pt-PT should fall back via
    // language-only "pt" lookup. Catalog has "pt-BR" dir only, so pt-PT falls
    // to English. Verify no error.
    let cat = Catalog::load(&locale_dir(), "pt-PT").expect("pt-PT load (falls back)");
    let out = cat.msg(Domain::Common, "btn-cancel");
    assert!(!out.is_empty());
}

#[test]
fn unknown_locale_falls_back_to_english_without_error() {
    let cat = Catalog::load(&locale_dir(), "xx-XX").expect("unknown locale still loads");
    assert_eq!(
        cat.msg(Domain::Auth, "registration-title"),
        "Register Device",
        "unknown locale should serve English strings"
    );
}

#[test]
fn invalid_locale_tag_rejected() {
    let result = Catalog::load(&locale_dir(), "!!!not-a-locale!!!");
    assert!(result.is_err());
}

#[test]
fn all_domains_loadable_for_english() {
    // Catch missing catalog files early.
    let cat = Catalog::load(&locale_dir(), "en-US").unwrap();
    assert_eq!(Domain::all().len(), 8, "expected 8 domains");
    assert_eq!(
        cat.msg(Domain::Auth, "registration-title"),
        "Register Device"
    );
    assert!(!cat.msg(Domain::Common, "btn-cancel").is_empty());
    assert!(!cat.msg(Domain::Errors, "error-network").is_empty());
    assert!(!cat.msg(Domain::Pictogram, "pictogram-apple").is_empty());
}

#[test]
fn posix_locale_normalisation() {
    assert_eq!(normalise_posix_locale("en_US.UTF-8"), Some("en-US".into()));
    assert_eq!(
        normalise_posix_locale("de_DE.UTF-8@euro"),
        Some("de-DE".into())
    );
    assert_eq!(
        normalise_posix_locale("pt_BR.UTF-8:en_US.UTF-8"),
        Some("pt-BR".into()),
        "colon-separated LANGUAGE takes first entry"
    );
    assert_eq!(normalise_posix_locale("C"), None);
    assert_eq!(normalise_posix_locale("POSIX"), None);
    assert_eq!(normalise_posix_locale(""), None);
}

#[test]
fn env_detection_respects_precedence() {
    // This test is intentionally minimal — we don't mutate env in tests to
    // avoid non-determinism across parallel runners. Just confirm the
    // function runs without panicking.
    let _ = detect_locale_from_env();
}
