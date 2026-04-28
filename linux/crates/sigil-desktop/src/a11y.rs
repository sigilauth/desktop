//! AT-SPI / Orca accessibility helpers.
//!
//! Per Aria §7.3, Orca does not reliably announce `aria-live` updates on
//! GTK. Defence in depth:
//!   1. Set `accessible-label` / `accessible-description` on interactive
//!      widgets so Orca reads them on focus.
//!   2. Show an `AdwToast` with a timeout that the user can dismiss.
//!   3. Shift keyboard focus to the widget whose description was updated
//!      so Orca re-reads the current focus.
//!
//! GTK 4.14 adds a direct `announce()` API on `AccessibleExt` with
//! priority levels; until our minimum is bumped we use the triple-path
//! above to guarantee announcement.

// Helpers are plumbed into views in slice 9; until then they're dead-code
// warnings. Silence explicitly rather than remove — the UI layer needs them.
#![allow(dead_code)]

use adw::prelude::*;
use gtk::prelude::AccessibleExtManual;
use libadwaita as adw;

/// Announce a message visually + via the AT-SPI focus-shift path.
pub fn announce(
    toast_overlay: &adw::ToastOverlay,
    status_widget: &(impl IsA<gtk::Widget> + AccessibleExtManual),
    message: &str,
) {
    tracing::debug!(message, "a11y announce");

    // 1. Update the accessible description so next focus/re-focus announces it.
    status_widget.update_property(&[gtk::accessible::Property::Description(message)]);

    // 2. Shift focus — forces Orca to read the widget's label + description.
    let _ = status_widget.grab_focus();

    // 3. Visual toast (respects `prefers-reduced-motion` via libadwaita).
    let toast = adw::Toast::builder()
        .title(message)
        .priority(adw::ToastPriority::Normal)
        .timeout(5)
        .build();
    toast_overlay.add_toast(toast);
}

/// Apply a consistent pictogram accessibility label. Pictograms are
/// image-like but carry security-critical info; screen readers MUST hear
/// the speakable form.
///
/// `speakable` follows D8 JSON convention: "apple banana airplane car dog".
pub fn label_pictogram(widget: &(impl IsA<gtk::Widget> + AccessibleExtManual), speakable: &str) {
    let label = format!("Device fingerprint: {speakable}");
    widget.update_property(&[
        gtk::accessible::Property::Label(&label),
        gtk::accessible::Property::Description(
            "Five-symbol pictogram uniquely identifying this device. \
             Verify it matches what your administrator showed you before continuing.",
        ),
    ]);
}

/// Expose action context as an accessible description on the approval
/// card. Screen reader users hear "what is being approved" before the
/// PIN / biometric prompt.
pub fn label_action_context(
    widget: &(impl IsA<gtk::Widget> + AccessibleExtManual),
    action_type: &str,
    description: &str,
) {
    let full = format!("Action type: {action_type}. {description}");
    widget.update_property(&[gtk::accessible::Property::Description(&full)]);
}
