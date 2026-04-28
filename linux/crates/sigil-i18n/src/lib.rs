//! Fluent-based i18n for Sigil Auth Linux desktop.
//!
//! Loads the B15 shared catalog (`i18n/locales/{locale}/*.ftl`) at
//! runtime, resolves user locale from standard POSIX env vars, and looks up
//! messages by key.
//!
//! **Fallback chain:** requested → English → key-as-string (logged).
//! English is always loaded; requested locale loaded on top as override.
//!
//! **Thread safety:** `Catalog` is `Send + Sync`; bundles are wrapped in
//! `Arc`. UI code calls `Catalog::msg(domain, key)` or
//! `Catalog::msg_args(domain, key, &args)` from any thread.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource};
use thiserror::Error;
use unic_langid::LanguageIdentifier;

/// Errors loading or using the Fluent catalog.
#[derive(Debug, Error)]
pub enum I18nError {
    /// The locale directory does not exist.
    #[error("locale dir not found: {0}")]
    LocaleDirNotFound(PathBuf),
    /// The English fallback locale failed to load.
    #[error("english fallback missing from {0}")]
    EnglishMissing(PathBuf),
    /// A `.ftl` file could not be read.
    #[error("read {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    /// A `.ftl` file failed to parse.
    #[error("parse {0}: {1:?}")]
    Parse(PathBuf, Vec<fluent::FluentError>),
    /// The requested locale tag is malformed.
    #[error("invalid locale tag {0:?}")]
    InvalidLocale(String),
}

/// Domains correspond 1:1 with B15 catalog files.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Domain {
    /// `auth.ftl` — registration, biometric, hardware-key prompts.
    Auth,
    /// `challenge.ftl` — approval flow.
    Challenge,
    /// `common.ftl` — buttons, a11y labels, time/countdown.
    Common,
    /// `devices.ftl` — device list, pairing metadata.
    Devices,
    /// `errors.ftl` — error messages (maps 1:1 to OpenAPI error codes).
    Errors,
    /// `mnemonic.ftl` — recovery phrase flow.
    Mnemonic,
    /// `mpa.ftl` — multi-party approval.
    Mpa,
    /// `pair-flow.ftl` — session pictogram verification flow.
    PairFlow,
    /// `pictogram.ftl` — emoji pictogram names.
    Pictogram,
}

impl Domain {
    /// Filename portion — e.g. `auth.ftl`.
    pub fn file_name(self) -> &'static str {
        match self {
            Domain::Auth => "auth.ftl",
            Domain::Challenge => "challenge.ftl",
            Domain::Common => "common.ftl",
            Domain::Devices => "devices.ftl",
            Domain::Errors => "errors.ftl",
            Domain::Mnemonic => "mnemonic.ftl",
            Domain::Mpa => "mpa.ftl",
            Domain::PairFlow => "pair-flow.ftl",
            Domain::Pictogram => "pictogram.ftl",
        }
    }

    /// Every domain. For catalog-load loops.
    pub fn all() -> &'static [Domain] {
        &[
            Domain::Auth,
            Domain::Challenge,
            Domain::Common,
            Domain::Devices,
            Domain::Errors,
            Domain::Mnemonic,
            Domain::Mpa,
            Domain::PairFlow,
            Domain::Pictogram,
        ]
    }
}

type Bundle = FluentBundle<FluentResource>;

/// Loaded Fluent catalog for one locale (with English fallback).
pub struct Catalog {
    /// Per-domain bundles for the requested locale.
    requested: HashMap<Domain, Arc<Bundle>>,
    /// Per-domain bundles for English, used when requested is missing a key.
    english: HashMap<Domain, Arc<Bundle>>,
    /// Canonical tag for the requested locale (after parsing).
    locale: LanguageIdentifier,
}

impl Catalog {
    /// Discover the locale from POSIX env vars (`LANGUAGE`, `LC_ALL`,
    /// `LC_MESSAGES`, `LANG`) and load it plus English from `locale_dir`.
    ///
    /// If discovery fails or the locale isn't available, falls back to `en-US`.
    pub fn load_from_env(locale_dir: &Path) -> Result<Self, I18nError> {
        let tag = detect_locale_from_env().unwrap_or_else(|| "en-US".into());
        Self::load(locale_dir, &tag)
    }

    /// Load a specific locale from `locale_dir`.
    pub fn load(locale_dir: &Path, locale_tag: &str) -> Result<Self, I18nError> {
        if !locale_dir.is_dir() {
            return Err(I18nError::LocaleDirNotFound(locale_dir.into()));
        }

        let locale: LanguageIdentifier = locale_tag
            .parse()
            .map_err(|_| I18nError::InvalidLocale(locale_tag.into()))?;

        let english = load_locale_bundles(locale_dir, &"en".parse().unwrap())?
            .ok_or_else(|| I18nError::EnglishMissing(locale_dir.into()))?;

        let requested = if locale.language.as_str() == "en" {
            english.clone()
        } else {
            load_locale_bundles(locale_dir, &locale)?.unwrap_or_else(|| english.clone())
        };

        Ok(Catalog {
            requested,
            english,
            locale,
        })
    }

    /// Active locale tag.
    pub fn locale(&self) -> &LanguageIdentifier {
        &self.locale
    }

    /// Look up a message key. Falls back to English, then to the key itself.
    pub fn msg(&self, domain: Domain, key: &str) -> String {
        self.msg_args(domain, key, None)
    }

    /// Look up a message key with arguments.
    pub fn msg_args(&self, domain: Domain, key: &str, args: Option<&FluentArgs>) -> String {
        if let Some(v) = try_format(&self.requested, domain, key, args) {
            return v;
        }
        if let Some(v) = try_format(&self.english, domain, key, args) {
            tracing::debug!(domain = ?domain, key, "falling back to english");
            return v;
        }
        tracing::warn!(domain = ?domain, key, "missing translation, returning key");
        key.to_string()
    }

    /// Returns `true` if the active locale is right-to-left (ar, he, fa, ur).
    /// Sets a flag for GTK layout direction.
    pub fn is_rtl(&self) -> bool {
        matches!(self.locale.language.as_str(), "ar" | "he" | "fa" | "ur")
    }
}

fn try_format(
    bundles: &HashMap<Domain, Arc<Bundle>>,
    domain: Domain,
    key: &str,
    args: Option<&FluentArgs>,
) -> Option<String> {
    let bundle = bundles.get(&domain)?;
    let msg = bundle.get_message(key)?;
    let pattern = msg.value()?;
    let mut errors = Vec::new();
    let formatted = bundle.format_pattern(pattern, args, &mut errors);
    if !errors.is_empty() {
        tracing::warn!(domain = ?domain, key, errors = ?errors, "fluent format errors");
    }
    Some(formatted.into_owned())
}

fn load_locale_bundles(
    locale_dir: &Path,
    locale: &LanguageIdentifier,
) -> Result<Option<HashMap<Domain, Arc<Bundle>>>, I18nError> {
    // Try canonical tag then language-only (e.g. "pt-BR" then "pt").
    let candidates = [locale.to_string(), locale.language.as_str().to_string()];

    for candidate in candidates {
        let dir = locale_dir.join(&candidate);
        if !dir.is_dir() {
            continue;
        }
        let mut bundles = HashMap::new();
        for domain in Domain::all() {
            let path = dir.join(domain.file_name());
            if !path.is_file() {
                continue;
            }
            let source =
                std::fs::read_to_string(&path).map_err(|e| I18nError::Io(path.clone(), e))?;
            let resource = FluentResource::try_new(source).map_err(|(_, errs)| {
                I18nError::Parse(
                    path.clone(),
                    errs.into_iter().map(fluent::FluentError::from).collect(),
                )
            })?;
            let mut bundle = FluentBundle::new_concurrent(vec![locale.clone()]);
            bundle.set_use_isolating(false); // avoid directional isolate chars in UI
            bundle
                .add_resource(resource)
                .map_err(|errs| I18nError::Parse(path.clone(), errs))?;
            bundles.insert(*domain, Arc::new(bundle));
        }
        if !bundles.is_empty() {
            return Ok(Some(bundles));
        }
    }
    Ok(None)
}

/// Return the first set POSIX locale env var, stripped of encoding/modifiers.
/// Precedence per POSIX: `LANGUAGE` > `LC_ALL` > `LC_MESSAGES` > `LANG`.
pub fn detect_locale_from_env() -> Option<String> {
    for var in ["LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            if let Some(clean) = normalise_posix_locale(&val) {
                return Some(clean);
            }
        }
    }
    None
}

/// Strip encoding + modifiers from a POSIX locale string and normalise
/// underscore to hyphen. Returns `None` for empty / C / POSIX.
pub fn normalise_posix_locale(raw: &str) -> Option<String> {
    // Take first entry from `LANGUAGE` colon list: "en_US:de_DE" -> "en_US".
    let first = raw.split(':').next()?;
    if first.is_empty() || first == "C" || first == "POSIX" {
        return None;
    }
    // Strip `.encoding` and `@modifier`: "en_US.UTF-8@euro" -> "en_US".
    let without_mod = first.split('@').next().unwrap_or(first);
    let without_enc = without_mod.split('.').next().unwrap_or(without_mod);
    // Normalise separator: underscore -> hyphen for BCP47.
    Some(without_enc.replace('_', "-"))
}
