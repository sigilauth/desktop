//! Main window + minimal view shells.
//!
//! This is deliberately thin — the full pairing / approval / MPA views live
//! behind a slice-9 follow-up. The shell is here to prove AdwApplication +
//! locale-aware strings + AT-SPI boilerplate + deep-link handling.

use std::sync::Arc;

use adw::prelude::*;
use gtk::glib;
use libadwaita as adw;
use sigil_i18n::Domain;

use crate::i18n::AppCatalog;

pub mod approval;
pub mod pairing;
pub mod servers;
pub mod session_pictogram;

/// Main application window.
pub struct MainWindow {
    window: adw::ApplicationWindow,
    view_stack: adw::ViewStack,
    toast_overlay: adw::ToastOverlay,
    catalog: Arc<AppCatalog>,
}

impl MainWindow {
    pub fn new(app: &adw::Application, catalog: Arc<AppCatalog>) -> Self {
        let toast_overlay = adw::ToastOverlay::new();

        let view_stack = adw::ViewStack::builder().vexpand(true).build();

        let switcher = adw::ViewSwitcher::builder()
            .policy(adw::ViewSwitcherPolicy::Wide)
            .stack(&view_stack)
            .build();

        let header = adw::HeaderBar::builder().title_widget(&switcher).build();

        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        content.append(&header);
        content.append(&view_stack);

        toast_overlay.set_child(Some(&content));

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title(catalog.msg(Domain::Common, "app-title"))
            .default_width(640)
            .default_height(480)
            .content(&toast_overlay)
            .build();

        view_stack.add_titled_with_icon(
            &pairing::build(&catalog),
            Some("pairing"),
            &catalog.msg(Domain::Common, "nav-pair"),
            "list-add-symbolic",
        );
        view_stack.add_titled_with_icon(
            &servers::build(&catalog),
            Some("servers"),
            &catalog.msg(Domain::Common, "nav-servers"),
            "network-server-symbolic",
        );
        view_stack.set_visible_child_name("pairing");

        MainWindow {
            window,
            view_stack,
            toast_overlay,
            catalog,
        }
    }

    pub fn present(&self) {
        self.window.present();
    }

    /// Handle `sigilauth://pair?code=XXXXXXXX&server=...` deep links.
    pub fn handle_deep_link(&self, uri: &str) {
        tracing::info!(uri, "deep link received");
        self.view_stack.set_visible_child_name("pairing");

        let msg = self.catalog.msg(Domain::Auth, "pairing-deep-link-received");
        self.toast_overlay
            .add_toast(adw::Toast::builder().title(msg).timeout(5).build());
        pairing::apply_deep_link(uri);
    }

    pub fn navigate_to(&self, view_name: &str) {
        self.view_stack.set_visible_child_name(view_name);
    }

    pub fn show_toast(&self, message: &str) {
        self.toast_overlay
            .add_toast(adw::Toast::builder().title(message).timeout(5).build());
    }

    pub fn window(&self) -> &adw::ApplicationWindow {
        &self.window
    }
}

// Silence unused-field warning where `glib` is pulled in via re-export elsewhere.
#[allow(dead_code)]
fn _glib_pin() -> Option<glib::ExitCode> {
    None
}
