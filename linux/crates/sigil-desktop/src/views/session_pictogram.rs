//! Session pictogram confirmation view for pair handshake.
//!
//! Displays 6-emoji pictogram in 2×3 grid for MITM detection via out-of-band verification.
//! Per `working/ui/session-pictogram-cross-platform-review.md` (Iris cross-platform standards).

use crate::i18n::AppCatalog;
use fluent_bundle::FluentArgs;
use gtk::prelude::*;
use gtk::{glib, Box, Button, Grid, Label, Orientation};
use libadwaita as adw;
use sigil_i18n::Domain;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

/// Session pictogram confirmation dialog.
///
/// Shows 6-emoji pictogram with countdown timer, Deny + Confirm buttons,
/// and accessibility labels per ATK standards.
pub struct SessionPictogramView {
    window: adw::Window,
    confirm_callback: Rc<dyn Fn(bool)>,
    timer_seconds_remaining: Rc<Cell<u64>>,
    catalog: Arc<AppCatalog>,
}

impl SessionPictogramView {
    /// Create new session pictogram confirmation view.
    ///
    /// `catalog`: Fluent i18n catalog for localized strings
    /// `pictogram`: 6-entry array of (emoji, word) tuples
    /// `ttl_seconds`: Time-to-live before auto-deny (10s per spec)
    /// `on_confirm`: Callback with true=confirmed, false=denied
    pub fn new(
        parent: &impl IsA<gtk::Window>,
        catalog: Arc<AppCatalog>,
        pictogram: &[(String, String); 6],
        ttl_seconds: u64,
        on_confirm: impl Fn(bool) + 'static,
    ) -> Self {
        let window = adw::Window::builder()
            .transient_for(parent)
            .modal(true)
            .default_width(600)
            .build();

        let confirm_callback = Rc::new(on_confirm);
        let timer_seconds_remaining = Rc::new(Cell::new(ttl_seconds));

        let content = Self::build_content(
            &catalog,
            pictogram,
            timer_seconds_remaining.clone(),
            confirm_callback.clone(),
            &window,
        );

        window.set_content(Some(&content));

        Self::start_timer(
            &catalog,
            timer_seconds_remaining.clone(),
            confirm_callback.clone(),
            &window,
        );

        Self::setup_keyboard_shortcuts(&window, confirm_callback.clone());

        Self {
            window,
            confirm_callback,
            timer_seconds_remaining,
            catalog,
        }
    }

    /// Build content layout per Iris specs.
    fn build_content(
        catalog: &Arc<AppCatalog>,
        pictogram: &[(String, String); 6],
        timer_remaining: Rc<Cell<u64>>,
        on_confirm: Rc<dyn Fn(bool)>,
        window: &adw::Window,
    ) -> Box {
        let container = Box::new(Orientation::Vertical, 24);
        container.set_margin_top(32);
        container.set_margin_bottom(32);
        container.set_margin_start(32);
        container.set_margin_end(32);

        let title_text = catalog.msg(Domain::PairFlow, "pair-flow-title");
        let title = Label::new(Some(&title_text));
        title.add_css_class("title-1");
        container.append(&title);

        let subtitle_text = catalog.msg(Domain::PairFlow, "pair-flow-subtitle");
        let subtitle = Label::new(Some(&subtitle_text));
        subtitle.add_css_class("dim-label");
        subtitle.set_wrap(true);
        subtitle.set_max_width_chars(50);
        container.append(&subtitle);

        let grid_container = Self::build_pictogram_grid(catalog, pictogram);
        container.append(&grid_container);

        let speakable_header_text = catalog.msg(Domain::PairFlow, "pair-flow-speakable-label");
        let speakable_header = Label::new(Some(&speakable_header_text));
        speakable_header.add_css_class("caption");
        speakable_header.set_margin_top(16);
        container.append(&speakable_header);

        let speakable = pictogram
            .iter()
            .map(|(_, word)| word.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let speakable_label = Label::new(Some(&speakable));
        speakable_label.set_selectable(true);
        speakable_label.add_css_class("monospace");
        speakable_label.set_margin_top(8);
        container.append(&speakable_label);

        let seconds = timer_remaining.get();
        let mut args = FluentArgs::new();
        args.set("seconds", seconds);
        let timer_text = catalog.msg_args(Domain::PairFlow, "pair-flow-countdown-seconds", Some(&args));
        let timer_label = Label::new(Some(&timer_text));
        timer_label.set_name("timer-label");
        timer_label.set_margin_top(16);
        container.append(&timer_label);

        let button_box = Self::build_buttons(catalog, on_confirm, window);
        container.append(&button_box);

        container
    }

    /// Build 2×3 emoji grid with accessibility labels.
    fn build_pictogram_grid(catalog: &Arc<AppCatalog>, pictogram: &[(String, String); 6]) -> Box {
        let grid = Grid::builder()
            .row_spacing(16)
            .column_spacing(24)
            .halign(gtk::Align::Center)
            .build();

        grid.add_css_class("pictogram-grid");
        grid.set_accessible_role(gtk::AccessibleRole::Group);
        let section_label = catalog.msg(Domain::PairFlow, "pair-flow-section-pictogram");
        grid.update_property(&[gtk::accessible::Property::Label(&section_label)]);

        for (idx, (emoji, word)) in pictogram.iter().enumerate() {
            let row = idx / 3;
            let col = idx % 3;

            let cell = Box::new(Orientation::Vertical, 8);
            cell.set_accessible_role(gtk::AccessibleRole::Group);
            cell.update_property(&[gtk::accessible::Property::Label(word)]);

            let emoji_label = Label::new(Some(emoji));
            emoji_label.add_css_class("pictogram-emoji");
            emoji_label.set_accessible_label(word);
            cell.append(&emoji_label);

            let word_label = Label::new(Some(word));
            word_label.add_css_class("caption");
            word_label.add_css_class("dim-label");
            cell.append(&word_label);

            grid.attach(&cell, col as i32, row as i32, 1, 1);
        }

        let container = Box::new(Orientation::Vertical, 0);
        container.append(&grid);
        container.set_margin_top(24);
        container.set_margin_bottom(24);
        container.add_css_class("pictogram-container");

        container
    }

    /// Build Deny + Confirm buttons.
    fn build_buttons(catalog: &Arc<AppCatalog>, on_confirm: Rc<dyn Fn(bool)>, window: &adw::Window) -> Box {
        let button_box = Box::new(Orientation::Horizontal, 12);
        button_box.set_halign(gtk::Align::Center);
        button_box.set_margin_top(24);

        let deny_text = catalog.msg(Domain::PairFlow, "pair-flow-deny-button");
        let deny_a11y = catalog.msg(Domain::PairFlow, "pair-flow-deny-a11y");
        let deny_button = Button::with_label(&deny_text);
        deny_button.set_name("deny-button");
        deny_button.set_accessible_label(&deny_a11y);
        let deny_callback = on_confirm.clone();
        let deny_window = window.clone();
        deny_button.connect_clicked(move |_| {
            deny_callback(false);
            deny_window.close();
        });
        button_box.append(&deny_button);

        let confirm_text = catalog.msg(Domain::PairFlow, "pair-flow-confirm-button");
        let confirm_a11y = catalog.msg(Domain::PairFlow, "pair-flow-confirm-a11y");
        let confirm_button = Button::with_label(&confirm_text);
        confirm_button.set_name("confirm-button");
        confirm_button.set_accessible_label(&confirm_a11y);
        confirm_button.add_css_class("suggested-action");
        let confirm_callback = on_confirm.clone();
        let confirm_window = window.clone();
        confirm_button.connect_clicked(move |_| {
            confirm_callback(true);
            confirm_window.close();
        });
        button_box.append(&confirm_button);

        button_box
    }

    /// Setup keyboard shortcuts (Escape = Deny, Enter = Confirm).
    fn setup_keyboard_shortcuts(window: &adw::Window, on_confirm: Rc<dyn Fn(bool)>) {
        let key_controller = gtk::EventControllerKey::new();
        let escape_callback = on_confirm.clone();
        let escape_window = window.clone();
        let enter_callback = on_confirm.clone();
        let enter_window = window.clone();

        key_controller.connect_key_pressed(move |_, key, _, _| {
            match key {
                gtk::gdk::Key::Escape => {
                    escape_callback(false);
                    escape_window.close();
                    glib::Propagation::Stop
                }
                gtk::gdk::Key::Return | gtk::gdk::Key::KP_Enter => {
                    enter_callback(true);
                    enter_window.close();
                    glib::Propagation::Stop
                }
                _ => glib::Propagation::Proceed,
            }
        });

        window.add_controller(key_controller);
    }

    /// Start countdown timer with red threshold at 5s.
    fn start_timer(
        catalog: &Arc<AppCatalog>,
        timer_remaining: Rc<Cell<u64>>,
        on_confirm: Rc<dyn Fn(bool)>,
        window: &adw::Window,
    ) {
        let timer_label_weak = window
            .first_child()
            .and_then(|c| Self::find_widget_by_name(&c, "timer-label"))
            .and_then(|w| w.downcast::<Label>().ok())
            .map(|l| l.downgrade());

        let deny_button_weak = window
            .first_child()
            .and_then(|c| Self::find_widget_by_name(&c, "deny-button"))
            .and_then(|w| w.downcast::<Button>().ok())
            .map(|b| b.downgrade());

        let confirm_button_weak = window
            .first_child()
            .and_then(|c| Self::find_widget_by_name(&c, "confirm-button"))
            .and_then(|w| w.downcast::<Button>().ok())
            .map(|b| b.downgrade());

        let window_weak = window.downgrade();
        let catalog = Arc::clone(catalog);

        glib::timeout_add_seconds_local(1, move || {
            let remaining = timer_remaining.get();
            let new_remaining = remaining.saturating_sub(1);
            timer_remaining.set(new_remaining);

            if let Some(timer_label) = timer_label_weak.as_ref().and_then(|w| w.upgrade()) {
                let mut args = FluentArgs::new();
                args.set("seconds", new_remaining);
                let timer_text = catalog.msg_args(
                    Domain::PairFlow,
                    "pair-flow-countdown-seconds",
                    Some(&args),
                );
                timer_label.set_text(&timer_text);

                if new_remaining <= 5 {
                    timer_label.add_css_class("error");
                }
            }

            if new_remaining == 0 {
                if let Some(deny) = deny_button_weak.as_ref().and_then(|w| w.upgrade()) {
                    deny.set_sensitive(false);
                }
                if let Some(confirm) = confirm_button_weak.as_ref().and_then(|w| w.upgrade()) {
                    confirm.set_sensitive(false);
                }
                on_confirm(false);
                if let Some(window) = window_weak.upgrade() {
                    window.close();
                }
                return glib::ControlFlow::Break;
            }

            glib::ControlFlow::Continue
        });
    }

    /// Helper to find widget by name in widget tree.
    fn find_widget_by_name(widget: &impl IsA<gtk::Widget>, name: &str) -> Option<gtk::Widget> {
        let widget = widget.as_ref();

        if widget.widget_name() == name {
            return Some(widget.clone());
        }

        let mut child = widget.first_child();
        while let Some(c) = child {
            if let Some(found) = Self::find_widget_by_name(&c, name) {
                return Some(found);
            }
            child = c.next_sibling();
        }

        None
    }

    /// Present the dialog.
    pub fn present(&self) {
        self.window.present();
    }
}
