//! Sigil Auth desktop app entrypoint.
//!
//! Registers the app on the session bus with the reverse-DNS ID, parses
//! CLI args, starts the GTK main loop. Single-instance enforced via
//! `Gio.Application` D-Bus name acquisition.

use anyhow::Result;

// Platform-independent modules — unit-testable on any host.
mod pairing_code;

#[cfg(target_os = "linux")]
mod a11y;
#[cfg(target_os = "linux")]
mod app;
#[cfg(target_os = "linux")]
mod components;
#[cfg(target_os = "linux")]
mod i18n;
#[cfg(target_os = "linux")]
mod relay;
#[cfg(target_os = "linux")]
mod pair_flow;
#[cfg(target_os = "linux")]
mod tray;
#[cfg(target_os = "linux")]
mod views;

/// Reverse-DNS application ID. Matches `org.sigilauth.Desktop.desktop`,
/// `org.sigilauth.Desktop.metainfo.xml`, `org.sigilauth.Desktop.gschema.xml`,
/// and the D-Bus well-known name.
pub const APP_ID: &str = "org.sigilauth.Desktop";

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sigil_desktop=debug".into()),
        )
        .init();

    tracing::info!(
        app_id = APP_ID,
        version = env!("CARGO_PKG_VERSION"),
        "starting"
    );

    #[cfg(target_os = "linux")]
    {
        app::run()
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("sigil-desktop is a Linux-only app (GTK4 + D-Bus Secret Service)")
    }
}
