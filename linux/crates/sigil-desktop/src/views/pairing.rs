//! Pairing view — SIGIL-CONV-V1 pictogram pair flow.
//!
//! Implements the full pair handshake: GET /pair/init → derive session
//! pictogram → display SessionPictogramView → POST /pair/complete → persist.

use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use glib::clone;
use libadwaita as adw;
use sigil_i18n::Domain;

use crate::i18n::AppCatalog;
use crate::pair_flow;
use crate::pairing_code::{parse_deep_link, validate_pairing_code};
use crate::views::session_pictogram::SessionPictogramView;

pub fn build(catalog: &Arc<AppCatalog>) -> gtk::Widget {
    let vbox = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .margin_top(32)
        .margin_bottom(32)
        .margin_start(24)
        .margin_end(24)
        .build();
    vbox.add_css_class("content-view");

    let heading = gtk::Label::builder()
        .label(catalog.msg(Domain::Auth, "registration-title"))
        .halign(gtk::Align::Start)
        .build();
    heading.add_css_class("title-1");
    vbox.append(&heading);

    let subtitle_label = gtk::Label::builder()
        .label(catalog.msg(Domain::Auth, "pairing-code-title"))
        .halign(gtk::Align::Start)
        .margin_bottom(12)
        .build();
    subtitle_label.add_css_class("subtitle");
    vbox.append(&subtitle_label);

    let group = adw::PreferencesGroup::builder()
        .build();
    group.add_css_class("card");

    let code_row = adw::EntryRow::builder()
        .title(catalog.msg(Domain::Auth, "pairing-code-placeholder"))
        .input_purpose(gtk::InputPurpose::Digits)
        .max_width_chars(8)
        .build();
    code_row.add_css_class("monospace");
    group.add(&code_row);

    let server_row = adw::EntryRow::builder()
        .title(catalog.msg(Domain::Common, "label-server-url"))
        .build();
    group.add(&server_row);

    vbox.append(&group);

    let submit = gtk::Button::builder()
        .label(catalog.msg(Domain::Auth, "pairing-code-submit"))
        .halign(gtk::Align::End)
        .build();
    submit.add_css_class("suggested-action");
    submit.add_css_class("pill");

    let server_row_clone = server_row.clone();
    let catalog_clone = Arc::clone(catalog);
    submit.connect_clicked(move |button| {
        let url = server_row_clone.text().to_string();

        if !url.starts_with("https://") {
            tracing::warn!(url = %url, "invalid server URL");
            return;
        }

        tracing::info!(url = %url, "starting SIGIL-CONV-V1 pair flow");

        // TODO: Get actual device public key from hardware (TPM/YubiKey)
        // For now, generate a temporary key for testing
        let device_pubkey_b64 = "AjYzODk5ODk5ODk5ODk5ODk5ODk5ODk5ODk5ODk5OTk5".to_string(); // Placeholder

        // Get toplevel window for modal dialog parent
        let Some(window) = button.root().and_then(|r| r.downcast::<gtk::Window>().ok()) else {
            tracing::error!("failed to get toplevel window");
            return;
        };

        let catalog = Arc::clone(&catalog_clone);
        glib::spawn_future_local(clone!(@strong url, @strong window => async move {
            // Phase 1: Init pair flow (GET /pair/init + derive pictogram)
            let session = match pair_flow::init_pair(&url, &device_pubkey_b64).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "pair init failed");
                    // TODO: Show error dialog to user
                    return;
                }
            };

            // Wrap session in Rc for shared ownership across closures
            let session_rc = Rc::new(session);

            // Phase 2: Show SessionPictogramView and wait for user confirmation
            let pictogram_view = SessionPictogramView::new(
                &window,
                catalog,
                &session_rc.pictogram,
                10, // 10 second timeout per spec
                clone!(@strong session_rc => move |confirmed| {
                    if !confirmed {
                        tracing::info!("user denied pair request");
                        return;
                    }

                    // Phase 3: Complete pair flow (POST /pair/complete)
                    let session_clone = Rc::clone(&session_rc);
                    glib::spawn_future_local(async move {
                        // Move session out of Rc (we're the last holder after dialog closes)
                        let session = Rc::try_unwrap(session_clone)
                            .unwrap_or_else(|rc| (*rc).clone());

                        match pair_flow::complete_pair(session).await {
                            Ok(()) => {
                                tracing::info!("pair flow completed successfully");
                                // TODO: Navigate to dashboard or show success message
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "pair complete failed");
                                // TODO: Show error dialog to user
                            }
                        }
                    });
                }),
            );

            pictogram_view.present();
        }));
    });

    vbox.append(&submit);

    let clamp = adw::Clamp::builder()
        .maximum_size(480)
        .tightening_threshold(400)
        .child(&vbox)
        .build();

    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&clamp)
        .build();

    scroller.upcast()
}

/// Apply a `sigilauth://pair?code=XXXXXXXX&server=https://...` deep link.
pub fn apply_deep_link(uri: &str) {
    let Some(link) = parse_deep_link(uri) else {
        tracing::warn!(uri, "ignoring non-sigilauth deep link");
        return;
    };
    tracing::info!(
        code = ?link.code.as_deref(),
        server = ?link.server.as_deref(),
        "deep-link parsed"
    );
    // TODO(slice 9): populate entries + auto-submit.
}
