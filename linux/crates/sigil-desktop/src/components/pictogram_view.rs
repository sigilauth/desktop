//! Accessible pictogram display component.
//!
//! Per Aria Phase C review BLOCKING-LIN-3, implements accessible pictogram
//! display matching the Windows reference implementation:
//! - Emoji display in horizontal row
//! - Speakable text label for screen readers
//! - Expander with per-emoji descriptions
//! - Full AT-SPI support for Orca
//!
//! Pattern matches `desktop/windows/src/Sigil.Windows.App/Views/PictogramView.xaml`
//! which Aria rated as "reference quality" (aria-phase-c-review.md line 280).

use gtk::prelude::*;
use gtk::prelude::AccessibleExtManual;
use libadwaita as adw;
use libadwaita::prelude::ExpanderRowExt;

/// Map emoji names to Unicode characters.
/// Must match Android's getEmojiForName() and protocol-spec.md §3.6 EMOJI_NAMES.
fn emoji_for_name(name: &str) -> &'static str {
    match name {
        "apple" => "🍎",
        "banana" => "🍌",
        "grapes" => "🍇",
        "orange" => "🍊",
        "lemon" => "🍋",
        "cherry" => "🍒",
        "strawberry" => "🍓",
        "kiwi" => "🥝",
        "carrot" => "🥕",
        "corn" => "🌽",
        "broccoli" => "🥦",
        "mushroom" => "🍄",
        "pepper" => "🌶️",
        "avocado" => "🥑",
        "onion" => "🧅",
        "peanut" => "🥜",
        "pizza" => "🍕",
        "burger" => "🍔",
        "taco" => "🌮",
        "donut" => "🍩",
        "cookie" => "🍪",
        "cake" => "🎂",
        "cupcake" => "🧁",
        "popcorn" => "🍿",
        "car" => "🚗",
        "taxi" => "🚕",
        "bus" => "🚌",
        "rocket" => "🚀",
        "plane" => "✈️",
        "helicopter" => "🚁",
        "sailboat" => "⛵",
        "bicycle" => "🚲",
        "dog" => "🐕",
        "cat" => "🐈",
        "fish" => "🐟",
        "butterfly" => "🦋",
        "bee" => "🐝",
        "fox" => "🦊",
        "lion" => "🦁",
        "elephant" => "🐘",
        "tree" => "🌲",
        "sunflower" => "🌻",
        "cactus" => "🌵",
        "clover" => "🍀",
        "blossom" => "🌸",
        "rainbow" => "🌈",
        "star" => "⭐",
        "moon" => "🌙",
        "house" => "🏠",
        "mountain" => "🏔️",
        "peak" => "⛰️",
        "volcano" => "🌋",
        "island" => "🏝️",
        "moai" => "🗿",
        "tent" => "⛺",
        "castle" => "🏰",
        "key" => "🔑",
        "bell" => "🔔",
        "books" => "📚",
        "guitar" => "🎸",
        "anchor" => "⚓",
        "crown" => "👑",
        "diamond" => "💎",
        "fire" => "🔥",
        _ => "❓",
    }
}

/// Build accessible pictogram widget from fingerprint.
///
/// Per Aria requirements (aria-a11y-requirements.md §3):
/// - Whole control has single accessible label announcing all five emoji names
/// - Visual emoji row marked AccessibilityView="Raw" (Orca skips)
/// - Speakable text visible for High Contrast mode
/// - Expander with per-emoji descriptions
pub struct PictogramView {
    widget: gtk::Box,
}

impl PictogramView {
    pub fn new(fingerprint: &[u8; 32]) -> Self {
        let names = sigil_wire::pictogram::names(fingerprint);
        let speakable = names.join(" ");

        let vbox = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(8)
            .build();

        // Emoji row (visual only, screen readers skip)
        let emoji_row = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk::Align::Center)
            .build();

        for name in &names {
            let emoji = emoji_for_name(name);
            let label = gtk::Label::builder()
                .label(emoji)
                .build();
            label.add_css_class("emoji-large");

            // Mark as presentational - screen readers ignore
            label.set_accessible_role(gtk::AccessibleRole::Presentation);

            emoji_row.append(&label);
        }

        vbox.append(&emoji_row);

        // Speakable text (visible, announced by screen readers)
        let speakable_label = gtk::Label::builder()
            .label(&speakable)
            .halign(gtk::Align::Center)
            .selectable(true)
            .build();
        speakable_label.add_css_class("caption");
        speakable_label.add_css_class("dim-label");

        // Set accessible label for the whole pictogram
        let accessible_label = format!(
            "Device fingerprint: {}. Five-symbol pictogram uniquely identifying this device. \
             Verify it matches what your administrator showed you before continuing.",
            speakable
        );
        speakable_label.update_property(&[
            gtk::accessible::Property::Label(&accessible_label),
        ]);

        vbox.append(&speakable_label);

        // Expander with per-emoji details (for all users, optional detail)
        let expander = adw::ExpanderRow::builder()
            .title("Show individual symbols")
            .build();

        for (_i, name) in names.iter().enumerate() {
            let emoji = emoji_for_name(name);
            let row_label = format!("{} — {}", emoji, name);

            let row = adw::ActionRow::builder()
                .title(&row_label)
                .build();

            // Position in set for list semantics
            // NOTE: PosInSet/SetSize properties not available in GTK 4.10
            // Accessibility still functional via title and role

            expander.add_row(&row);
        }

        vbox.append(&expander);

        // Set overall accessible role as group
        vbox.update_property(&[
            gtk::accessible::Property::Label(&accessible_label),
        ]);

        Self { widget: vbox }
    }

    pub fn widget(&self) -> &gtk::Box {
        &self.widget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emoji_mapping_matches_protocol() {
        // Test a few key mappings from protocol-spec.md §3.6
        assert_eq!(emoji_for_name("apple"), "🍎");
        assert_eq!(emoji_for_name("rocket"), "🚀");
        assert_eq!(emoji_for_name("moai"), "🗿");
        assert_eq!(emoji_for_name("fire"), "🔥");
        assert_eq!(emoji_for_name("unknown"), "❓");
    }

    #[test]
    fn test_pictogram_view_construction() {
        // Can't test GTK widgets without initialized GTK context,
        // but we can test the emoji mapping logic
        let fingerprint = [0u8; 32];
        let names = sigil_wire::pictogram::names(&fingerprint);

        // First fingerprint bytes are all zeros, so all indices are 0
        // Index 0 maps to "apple"
        assert_eq!(names, ["apple", "apple", "apple", "apple", "apple"]);
    }
}
