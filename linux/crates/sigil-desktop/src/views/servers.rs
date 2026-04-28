//! Servers list view — displays paired servers with pictogram preview.

use std::sync::Arc;

use adw::prelude::*;
use glib::clone;
use gtk::glib;
use libadwaita as adw;
use sigil_i18n::Domain;
use sigil_secret::{MetadataStore, ServerRecord};

use crate::i18n::AppCatalog;

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
        _ => "⭐",
    }
}

pub fn build(catalog: &Arc<AppCatalog>) -> gtk::Widget {
    let vbox = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();

    let header = adw::HeaderBar::builder().build();

    let add_button = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Add Server")
        .build();
    add_button.add_css_class("flat");

    let vbox_weak = vbox.downgrade();
    add_button.connect_clicked(move |_| {
        if let Some(vbox) = vbox_weak.upgrade() {
            if let Some(root) = vbox.root() {
                if let Some(window) = root.downcast_ref::<adw::ApplicationWindow>() {
                    if let Some(content) = window.content() {
                        if let Some(toast_overlay) = content.downcast_ref::<adw::ToastOverlay>() {
                            if let Some(child) = toast_overlay.child() {
                                if let Some(vbox_content) = child.downcast_ref::<gtk::Box>() {
                                    let mut current = vbox_content.first_child();
                                    while let Some(widget) = current {
                                        if let Some(view_stack) = widget.downcast_ref::<adw::ViewStack>() {
                                            view_stack.set_visible_child_name("pairing");
                                            break;
                                        }
                                        current = widget.next_sibling();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    header.pack_start(&add_button);

    let refresh_button = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh")
        .build();
    refresh_button.add_css_class("flat");
    header.pack_end(&refresh_button);

    vbox.append(&header);

    let stack = gtk::Stack::builder()
        .vexpand(true)
        .transition_type(gtk::StackTransitionType::Crossfade)
        .build();

    let loading_page = build_loading_page(catalog);
    stack.add_named(&loading_page, Some("loading"));

    let empty_page = build_empty_page(catalog);
    stack.add_named(&empty_page, Some("empty"));

    let list_page = build_list_page(catalog);
    stack.add_named(&list_page, Some("list"));

    stack.set_visible_child_name("loading");

    vbox.append(&stack);

    let catalog_clone = Arc::clone(catalog);
    let stack_weak = stack.downgrade();
    glib::spawn_future_local(async move {
        match MetadataStore::connect().await {
            Ok(store) => match store.list_servers().await {
                Ok(servers) => {
                    if let Some(stack) = stack_weak.upgrade() {
                        if servers.is_empty() {
                            stack.set_visible_child_name("empty");
                        } else {
                            populate_server_list(&stack, &catalog_clone, servers);
                            stack.set_visible_child_name("list");
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to list servers");
                    if let Some(stack) = stack_weak.upgrade() {
                        stack.set_visible_child_name("empty");
                    }
                }
            },
            Err(e) => {
                tracing::error!(error = %e, "failed to connect to secret service");
                if let Some(stack) = stack_weak.upgrade() {
                    stack.set_visible_child_name("empty");
                }
            }
        }
    });

    let catalog_clone = Arc::clone(catalog);
    let stack_weak = stack.downgrade();
    refresh_button.connect_clicked(move |_| {
        let catalog = Arc::clone(&catalog_clone);
        let stack_weak = stack_weak.clone();

        glib::spawn_future_local(async move {
            if let Some(stack) = stack_weak.upgrade() {
                stack.set_visible_child_name("loading");

                match MetadataStore::connect().await {
                    Ok(store) => match store.list_servers().await {
                        Ok(servers) => {
                            if servers.is_empty() {
                                stack.set_visible_child_name("empty");
                            } else {
                                populate_server_list(&stack, &catalog, servers);
                                stack.set_visible_child_name("list");
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to list servers");
                            stack.set_visible_child_name("empty");
                        }
                    },
                    Err(e) => {
                        tracing::error!(error = %e, "failed to connect to secret service");
                        stack.set_visible_child_name("empty");
                    }
                }
            }
        });
    });

    vbox.upcast()
}

fn build_loading_page(catalog: &Arc<AppCatalog>) -> gtk::Widget {
    let status = adw::StatusPage::builder()
        .icon_name("emblem-synchronizing-symbolic")
        .title(catalog.msg(Domain::Common, "loading"))
        .build();
    status.add_css_class("content-view");

    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .child(&status)
        .build();

    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&clamp)
        .build();

    scroller.upcast()
}

fn build_empty_page(catalog: &Arc<AppCatalog>) -> gtk::Widget {
    let vbox = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(20)
        .valign(gtk::Align::Center)
        .halign(gtk::Align::Center)
        .margin_top(32)
        .margin_bottom(32)
        .build();

    let icon = gtk::Label::builder()
        .label("🔑")
        .build();
    icon.add_css_class("title-1");
    icon.set_opacity(0.3);
    vbox.append(&icon);

    let title = gtk::Label::builder()
        .label("No Servers Paired")
        .build();
    title.add_css_class("title-2");
    vbox.append(&title);

    let description = gtk::Label::builder()
        .label("Pair your first server to start approving authentication requests.\nYou can pair via QR code, deep link, or manual server URL.")
        .justify(gtk::Justification::Center)
        .wrap(true)
        .max_width_chars(50)
        .build();
    description.add_css_class("dim-label");
    vbox.append(&description);

    let button = gtk::Button::builder()
        .label("Pair Your First Server")
        .margin_top(16)
        .build();
    button.add_css_class("suggested-action");
    button.add_css_class("pill");
    vbox.append(&button);

    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .child(&vbox)
        .build();

    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&clamp)
        .build();

    scroller.upcast()
}

fn build_list_page(_catalog: &Arc<AppCatalog>) -> gtk::Widget {
    let list_box = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list_box.add_css_class("boxed-list");
    list_box.set_name("server-list");

    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(12)
        .margin_end(12)
        .child(&list_box)
        .build();

    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&clamp)
        .build();

    scroller.upcast()
}

fn populate_server_list(
    stack: &gtk::Stack,
    _catalog: &Arc<AppCatalog>,
    servers: Vec<(String, ServerRecord)>,
) {
    let list_page = stack.child_by_name("list").expect("list page exists");
    let scroller = list_page.downcast::<gtk::ScrolledWindow>().unwrap();
    let clamp = scroller.child().unwrap().downcast::<adw::Clamp>().unwrap();
    let list_box = clamp.child().unwrap().downcast::<gtk::ListBox>().unwrap();

    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    for (_fingerprint, record) in servers {
        let row = build_server_row(&record);
        list_box.append(&row);
    }
}

fn build_server_row(record: &ServerRecord) -> gtk::Widget {
    let vbox = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(16)
        .margin_end(16)
        .build();

    let display_name = record
        .display_name
        .clone()
        .unwrap_or_else(|| record.url.clone());
    let title = gtk::Label::builder()
        .label(&display_name)
        .halign(gtk::Align::Start)
        .build();
    title.add_css_class("heading");
    vbox.append(&title);

    let emoji_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(4)
        .halign(gtk::Align::Start)
        .build();

    for name in &record.pictogram {
        let emoji = emoji_for_name(name);
        let emoji_label = gtk::Label::builder().label(emoji).build();
        emoji_label.add_css_class("title-3");
        emoji_box.append(&emoji_label);
    }

    vbox.append(&emoji_box);

    let speakable = gtk::Label::builder()
        .label(&record.pictogram_speakable)
        .halign(gtk::Align::Start)
        .selectable(true)
        .build();
    speakable.add_css_class("caption");
    speakable.add_css_class("dim-label");
    speakable.add_css_class("monospace");
    vbox.append(&speakable);

    vbox.upcast()
}
