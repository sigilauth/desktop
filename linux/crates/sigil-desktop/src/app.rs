//! GTK4 + libadwaita application shell.

use std::path::PathBuf;
use std::sync::Arc;

use adw::prelude::*;
use anyhow::Result;
use gtk::{gio, glib};
use libadwaita as adw;
use tracing::{error, info};

use crate::i18n::AppCatalog;
use crate::relay::{RelayClient, RelayEvent};
use crate::tray::SigilTray;
use crate::views::MainWindow;
use crate::APP_ID;

/// Build and run the `AdwApplication`. Returns when the last window closes.
pub fn run() -> Result<()> {
    let application = adw::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::HANDLES_OPEN)
        .build();

    application.connect_startup(|_| {
        setup_style_manager();
        start_relay_client_if_configured();

        // Start system tray
        if let Err(e) = SigilTray::spawn() {
            error!(error = %e, "Failed to start system tray");
        } else {
            info!("System tray started");
        }
    });

    application.connect_activate(move |app| {
        // If window already exists, just present it
        if let Some(window) = app.active_window() {
            window.present();
            return;
        }

        // Otherwise create new window
        let catalog = Arc::new(load_catalog());
        if catalog.is_rtl() {
            gtk::Widget::set_default_direction(gtk::TextDirection::Rtl);
        }
        let window = MainWindow::new(app, catalog);
        window.present();
    });

    application.connect_open(move |app, files, _hint| {
        let catalog = Arc::new(load_catalog());
        let window = MainWindow::new(app, catalog);
        for file in files {
            let uri = file.uri();
            window.handle_deep_link(uri.as_str());
        }
        window.present();
    });

    let exit_code = application.run();
    if exit_code == glib::ExitCode::SUCCESS {
        Ok(())
    } else {
        anyhow::bail!("application exited with {exit_code:?}")
    }
}

fn setup_style_manager() {
    let style_manager = adw::StyleManager::default();
    style_manager.set_color_scheme(adw::ColorScheme::PreferDark);
    style_manager.connect_dark_notify(|sm| {
        tracing::debug!(dark = sm.is_dark(), "system color scheme changed");
    });

    // Load custom CSS with design system tokens
    load_custom_css();
}

fn load_custom_css() {
    let css = include_str!("../resources/style.css");
    let provider = gtk::CssProvider::new();
    provider.load_from_data(css);

    gtk::style_context_add_provider_for_display(
        &gtk::gdk::Display::default().expect("Failed to get default display"),
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    info!("Design system CSS loaded");
}

/// Start relay WebSocket client if SIGIL_RELAY_URL is set.
/// Uses test-support SoftwareTestKey for demo/development.
/// Production builds will load hardware key from TPM/YubiKey.
fn start_relay_client_if_configured() {
    let relay_url = match std::env::var("SIGIL_RELAY_URL") {
        Ok(url) => url,
        Err(_) => {
            info!("SIGIL_RELAY_URL not set, relay client disabled");
            return;
        }
    };

    info!(relay_url = %relay_url, "Starting relay WebSocket client");

    #[cfg(feature = "test-support")]
    {
        use rand::rngs::OsRng;
        use sigil_hardware::test_support::SoftwareTestKey;

        let device_key = Arc::new(SoftwareTestKey::generate(&mut OsRng));
        let (relay_client, mut event_rx) = RelayClient::new(relay_url, device_key);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                relay_client.start().await;
            });
        });

        let device_key_for_events = Arc::clone(&device_key);
        glib::spawn_future_local(async move {
            while let Some(event) = event_rx.recv().await {
                handle_relay_event(event, Arc::clone(&device_key_for_events));
            }
        });
    }

    #[cfg(not(feature = "test-support"))]
    {
        error!("Relay client requires test-support feature or hardware key integration");
    }
}

fn handle_relay_event(event: RelayEvent, device_key: Arc<dyn sigil_hardware::HardwareKey>) {
    match event {
        RelayEvent::Connected { fingerprint } => {
            info!(fingerprint_prefix = &fingerprint[..16], "Relay connected");
        }
        RelayEvent::Disconnected => {
            info!("Relay disconnected");
        }
        RelayEvent::ChallengeReceived(challenge) => {
            info!(
                challenge_id = &challenge.challenge_id,
                action = &challenge.action.description,
                "Challenge notification received"
            );

            // Show desktop notification
            #[cfg(target_os = "linux")]
            {
                use notify_rust::Notification;

                let body = format!(
                    "{}\n\nServer ID: {}",
                    challenge.action.description,
                    &challenge.server_id[..8.min(challenge.server_id.len())]
                );

                if let Err(e) = Notification::new()
                    .summary("Sigil Auth — approval needed")
                    .body(&body)
                    .icon("dialog-password")
                    .appname("Sigil Auth")
                    .timeout(0) // No auto-dismiss
                    .action("approve", "Approve")
                    .show()
                {
                    error!(error = %e, "Failed to show desktop notification");
                }
            }

            // Present approval dialog
            if let Some(app) = gio::Application::default() {
                if let Some(window) = app.active_window() {
                    let catalog = Arc::new(load_catalog());
                    crate::views::approval::present(&window, catalog, &challenge, device_key);
                } else {
                    error!("No active window to present approval dialog");
                }
            }
        }
        RelayEvent::Error(err) => {
            error!(error = %err, "Relay error");
        }
    }
}

fn load_catalog() -> AppCatalog {
    let locale_dir = find_locale_dir();
    match AppCatalog::load_from_env(&locale_dir) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, locale_dir = %locale_dir.display(),
                "failed to load locale catalog; falling back to key-strings");
            AppCatalog::empty()
        }
    }
}

/// Locate the Fluent catalog directory. In installed builds it's at
/// `$prefix/share/sigilauth-desktop/locales/`; in dev the shared catalog
/// lives at `../../../../i18n/locales/` relative to this crate.
fn find_locale_dir() -> PathBuf {
    if let Ok(dirs) = xdg::BaseDirectories::with_prefix("sigilauth-desktop") {
        for data_dir in dirs.get_data_dirs() {
            let candidate = data_dir.join("locales");
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../../../i18n/locales")
}
