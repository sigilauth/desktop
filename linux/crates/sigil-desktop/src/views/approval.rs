//! Approval dialog — full challenge approval flow.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use glib::clone;
use gtk::{glib, Box, Button, Label, Orientation};
use libadwaita as adw;
use sigil_i18n::Domain;
use sigil_secret::{MetadataStore, ServerRecord};
use sigil_wire::wire::{ChallengeNotification, ChallengeResponse, Decision};

use crate::i18n::AppCatalog;

/// Present the approval dialog against an incoming challenge notification.
pub fn present(
    parent: &impl IsA<gtk::Window>,
    catalog: Arc<AppCatalog>,
    challenge: &ChallengeNotification,
    device_key: Arc<dyn sigil_hardware::HardwareKey>,
) {
    let challenge_clone = challenge.clone();
    let catalog_clone = Arc::clone(&catalog);
    let parent_weak = parent.clone().upcast::<gtk::Window>().downgrade();
    let device_key_clone = Arc::clone(&device_key);

    glib::spawn_future_local(async move {
        let server_record = match load_server_for_challenge(&challenge_clone).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                tracing::warn!(server_id = %challenge_clone.server_id, "server not found in trust store");
                show_error_toast(&parent_weak, &catalog_clone, "Server not found in paired servers").await;
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to load server record");
                show_error_toast(&parent_weak, &catalog_clone, "Failed to load server information").await;
                return;
            }
        };

        if let Some(parent) = parent_weak.upgrade() {
            show_approval_dialog(
                &parent,
                catalog_clone,
                challenge_clone,
                server_record,
                device_key_clone,
            );
        }
    });
}

async fn load_server_for_challenge(
    challenge: &ChallengeNotification,
) -> Result<Option<ServerRecord>, sigil_secret::SecretError> {
    let store = MetadataStore::connect().await?;
    let servers = store.list_servers().await?;

    for (_fingerprint, record) in servers {
        if record.url.contains(&challenge.server_id) {
            return Ok(Some(record));
        }
    }

    Ok(None)
}

async fn show_error_toast(parent_weak: &glib::WeakRef<gtk::Window>, catalog: &AppCatalog, message: &str) {
    tracing::error!(message = %message, "approval flow error");
}

fn show_approval_dialog(
    parent: &gtk::Window,
    catalog: Arc<AppCatalog>,
    challenge: ChallengeNotification,
    server_record: ServerRecord,
    device_key: Arc<dyn sigil_hardware::HardwareKey>,
) {
    let window = adw::Window::builder()
        .transient_for(parent)
        .modal(true)
        .default_width(500)
        .default_height(550)
        .build();

    let expires_at = parse_iso8601_to_seconds(&challenge.expires_at);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let initial_remaining = expires_at.saturating_sub(now);

    let content = build_approval_content(
        &catalog,
        &challenge,
        &server_record,
        initial_remaining,
        Arc::clone(&device_key),
        &window,
    );

    window.set_content(Some(&content));
    window.present();
}

fn build_approval_content(
    catalog: &Arc<AppCatalog>,
    challenge: &ChallengeNotification,
    server_record: &ServerRecord,
    initial_remaining_seconds: u64,
    device_key: Arc<dyn sigil_hardware::HardwareKey>,
    window: &adw::Window,
) -> Box {
    let vbox = Box::new(Orientation::Vertical, 24);
    vbox.set_margin_top(32);
    vbox.set_margin_bottom(32);
    vbox.set_margin_start(32);
    vbox.set_margin_end(32);

    let title_text = catalog.msg(Domain::Challenge, "challenge-title");
    let title = Label::new(Some(&title_text));
    title.add_css_class("title-1");
    vbox.append(&title);

    let server_section = build_server_section(catalog, server_record);
    vbox.append(&server_section);

    let action_section = build_action_section(catalog, &challenge.action);
    vbox.append(&action_section);

    let timer_seconds_remaining = Rc::new(Cell::new(initial_remaining_seconds));
    let timer_label = Label::builder()
        .label(&format!("Expires in {} seconds", initial_remaining_seconds))
        .margin_top(16)
        .build();
    timer_label.set_name("timer-label");
    timer_label.add_css_class("caption");

    if initial_remaining_seconds <= 30 {
        timer_label.add_css_class("error");
    }

    vbox.append(&timer_label);

    let button_box = build_action_buttons(
        catalog,
        challenge.clone(),
        Arc::clone(&device_key),
        window,
    );
    vbox.append(&button_box);

    start_countdown_timer(
        catalog,
        timer_seconds_remaining,
        &timer_label,
        &button_box,
        window,
    );

    vbox
}

fn build_server_section(catalog: &Arc<AppCatalog>, server_record: &ServerRecord) -> Box {
    let vbox = Box::new(Orientation::Vertical, 8);

    let section_label = catalog.msg(Domain::Challenge, "challenge-service-label");
    let section_title = Label::new(Some(&section_label));
    section_title.add_css_class("caption");
    section_title.add_css_class("dim-label");
    section_title.set_halign(gtk::Align::Start);
    vbox.append(&section_title);

    let card = Box::new(Orientation::Vertical, 12);
    card.set_margin_top(8);
    card.set_margin_bottom(8);
    card.set_margin_start(16);
    card.set_margin_end(16);
    card.add_css_class("card");

    let server_name = server_record
        .display_name
        .clone()
        .unwrap_or_else(|| server_record.url.clone());
    let name_label = Label::new(Some(&server_name));
    name_label.add_css_class("heading");
    name_label.set_halign(gtk::Align::Start);
    card.append(&name_label);

    let emoji_box = Box::new(Orientation::Horizontal, 4);
    emoji_box.set_halign(gtk::Align::Start);

    for name in &server_record.pictogram {
        let emoji = emoji_for_name(name);
        let emoji_label = Label::builder().label(emoji).build();
        emoji_label.add_css_class("title-3");
        emoji_box.append(&emoji_label);
    }

    card.append(&emoji_box);

    let speakable = Label::new(Some(&server_record.pictogram_speakable));
    speakable.add_css_class("caption");
    speakable.add_css_class("dim-label");
    speakable.add_css_class("monospace");
    speakable.set_halign(gtk::Align::Start);
    speakable.set_selectable(true);
    card.append(&speakable);

    vbox.append(&card);
    vbox
}

fn build_action_section(catalog: &Arc<AppCatalog>, action: &sigil_wire::wire::Action) -> Box {
    let vbox = Box::new(Orientation::Vertical, 8);

    let section_label = catalog.msg(Domain::Challenge, "challenge-action-label");
    let section_title = Label::new(Some(&section_label));
    section_title.add_css_class("caption");
    section_title.add_css_class("dim-label");
    section_title.set_halign(gtk::Align::Start);
    vbox.append(&section_title);

    let card = Box::new(Orientation::Vertical, 8);
    card.set_margin_top(8);
    card.set_margin_bottom(8);
    card.set_margin_start(16);
    card.set_margin_end(16);
    card.add_css_class("card");

    let description = Label::new(Some(&action.description));
    description.add_css_class("body");
    description.set_halign(gtk::Align::Start);
    description.set_wrap(true);
    description.set_max_width_chars(50);
    card.append(&description);

    if let Some(params) = &action.params {
        let params_json = serde_json::to_string_pretty(params).unwrap_or_else(|_| "{}".to_string());
        let params_label = Label::new(Some(&params_json));
        params_label.add_css_class("caption");
        params_label.add_css_class("monospace");
        params_label.set_halign(gtk::Align::Start);
        params_label.set_selectable(true);
        params_label.set_wrap(true);
        params_label.set_max_width_chars(50);
        card.append(&params_label);
    }

    vbox.append(&card);
    vbox
}

fn build_action_buttons(
    catalog: &Arc<AppCatalog>,
    challenge: ChallengeNotification,
    device_key: Arc<dyn sigil_hardware::HardwareKey>,
    window: &adw::Window,
) -> Box {
    let button_box = Box::new(Orientation::Horizontal, 12);
    button_box.set_halign(gtk::Align::Center);
    button_box.set_margin_top(24);
    button_box.set_name("action-buttons");

    let deny_text = catalog.msg(Domain::Challenge, "challenge-deny");
    let deny_button = Button::with_label(&deny_text);
    deny_button.set_name("deny-button");

    let window_weak = window.downgrade();
    let challenge_clone = challenge.clone();
    let device_key_clone = Arc::clone(&device_key);
    deny_button.connect_clicked(move |_| {
        let challenge = challenge_clone.clone();
        let device_key = Arc::clone(&device_key_clone);
        let window_weak = window_weak.clone();

        glib::spawn_future_local(async move {
            handle_decision(challenge, device_key, Decision::Rejected).await;
            if let Some(window) = window_weak.upgrade() {
                window.close();
            }
        });
    });

    button_box.append(&deny_button);

    let approve_text = catalog.msg(Domain::Challenge, "challenge-approve");
    let approve_button = Button::with_label(&approve_text);
    approve_button.set_name("approve-button");
    approve_button.add_css_class("suggested-action");

    let window_weak = window.downgrade();
    let challenge_clone = challenge.clone();
    let device_key_clone = Arc::clone(&device_key);
    approve_button.connect_clicked(move |button| {
        button.set_sensitive(false);
        button.set_label("Approving...");

        let challenge = challenge_clone.clone();
        let device_key = Arc::clone(&device_key_clone);
        let window_weak = window_weak.clone();
        let button_weak = button.downgrade();

        glib::spawn_future_local(async move {
            handle_decision(challenge, device_key, Decision::Approved).await;
            if let Some(window) = window_weak.upgrade() {
                window.close();
            }
            if let Some(button) = button_weak.upgrade() {
                button.set_sensitive(true);
                button.set_label("Approve");
            }
        });
    });

    button_box.append(&approve_button);

    button_box
}

fn start_countdown_timer(
    catalog: &Arc<AppCatalog>,
    timer_remaining: Rc<Cell<u64>>,
    timer_label: &Label,
    button_box: &Box,
    window: &adw::Window,
) {
    let timer_label_weak = timer_label.downgrade();
    let button_box_weak = button_box.downgrade();
    let window_weak = window.downgrade();

    glib::timeout_add_seconds_local(1, move || {
        let remaining = timer_remaining.get();
        let new_remaining = remaining.saturating_sub(1);
        timer_remaining.set(new_remaining);

        if let Some(timer_label) = timer_label_weak.upgrade() {
            timer_label.set_text(&format!("Expires in {} seconds", new_remaining));

            if new_remaining <= 30 && !timer_label.has_css_class("error") {
                timer_label.add_css_class("error");
            }
        }

        if new_remaining == 0 {
            if let Some(button_box) = button_box_weak.upgrade() {
                if let Some(deny_button) = button_box.first_child() {
                    deny_button.set_sensitive(false);
                }
                if let Some(approve_button) = button_box.last_child() {
                    approve_button.set_sensitive(false);
                }
            }

            if let Some(window) = window_weak.upgrade() {
                window.close();
            }

            return glib::ControlFlow::Break;
        }

        glib::ControlFlow::Continue
    });
}

async fn handle_decision(
    challenge: ChallengeNotification,
    device_key: Arc<dyn sigil_hardware::HardwareKey>,
    decision: Decision,
) {
    tracing::info!(
        challenge_id = %challenge.challenge_id,
        decision = ?decision,
        "handling approval decision"
    );

    if matches!(decision, Decision::Rejected) {
        tracing::info!("user rejected challenge");
        return;
    }

    match construct_and_sign_response(&challenge, &device_key, decision).await {
        Ok(response) => {
            if let Err(e) = post_response(&challenge.respond_to, &response).await {
                tracing::error!(error = %e, "failed to post response");
            } else {
                tracing::info!("challenge response posted successfully");
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to construct response");
        }
    }
}

async fn construct_and_sign_response(
    challenge: &ChallengeNotification,
    device_key: &Arc<dyn sigil_hardware::HardwareKey>,
    decision: Decision,
) -> Result<ChallengeResponse, anyhow::Error> {
    let device_public_key = device_key.public_key();
    let device_public_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        device_public_key.as_bytes(),
    );

    let timestamp = chrono::Utc::now().to_rfc3339();

    let payload = sigil_wire::signature_payload::device_response_payload(
        &challenge.challenge_id,
        &challenge.challenge_bytes,
        decision,
        &timestamp,
    )?;

    let signature = device_key
        .sign(&payload)
        .map_err(|e| anyhow::anyhow!("hardware signing failed: {:?}", e))?;

    let signature_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.as_bytes(),
    );

    Ok(ChallengeResponse {
        challenge_id: challenge.challenge_id.clone(),
        device_public_key: device_public_key_b64,
        decision,
        signature: signature_b64,
        timestamp,
    })
}

async fn post_response(url: &str, response: &ChallengeResponse) -> Result<(), anyhow::Error> {
    let client = reqwest::Client::new();
    let res = client
        .post(url)
        .json(response)
        .send()
        .await?;

    if !res.status().is_success() {
        anyhow::bail!("server returned {}: {}", res.status(), res.text().await?);
    }

    Ok(())
}

fn parse_iso8601_to_seconds(iso: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|dt| dt.timestamp() as u64)
        .unwrap_or(0)
}

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
