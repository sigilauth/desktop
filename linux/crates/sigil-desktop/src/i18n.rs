//! Thin wrapper re-exporting `sigil-i18n` with an `empty()` constructor for
//! the fallback path when the catalog fails to load.

use std::path::Path;

use fluent_bundle::FluentArgs;
use sigil_i18n::{Catalog, Domain, I18nError};

/// Adapter exposing `Domain` + fallback behaviour to GTK widget code.
pub struct AppCatalog {
    inner: Option<Catalog>,
}

impl AppCatalog {
    /// Load from the user's POSIX locale, falling back to English.
    pub fn load_from_env(locale_dir: &Path) -> Result<Self, I18nError> {
        Catalog::load_from_env(locale_dir).map(|c| AppCatalog { inner: Some(c) })
    }

    /// Empty fallback: every lookup returns the key itself. Used when the
    /// catalog dir is missing — the app still starts but strings are raw.
    pub fn empty() -> Self {
        AppCatalog { inner: None }
    }

    /// Shorthand message lookup.
    pub fn msg(&self, domain: Domain, key: &str) -> String {
        match &self.inner {
            Some(c) => c.msg(domain, key),
            None => key.to_string(),
        }
    }

    /// Message lookup with arguments (for plurals, variables).
    pub fn msg_args(&self, domain: Domain, key: &str, args: Option<&FluentArgs>) -> String {
        match &self.inner {
            Some(c) => c.msg_args(domain, key, args),
            None => key.to_string(),
        }
    }

    /// `true` if the active locale is right-to-left.
    pub fn is_rtl(&self) -> bool {
        self.inner.as_ref().is_some_and(|c| c.is_rtl())
    }
}

/// Convenience macro: `tr!(catalog, Domain::Auth, "registration-title")`.
#[macro_export]
macro_rules! tr {
    ($cat:expr, $domain:expr, $key:literal) => {{
        $cat.msg($domain, $key)
    }};
}
