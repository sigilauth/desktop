# Linux Desktop Patterns — Sigil Auth

Approved patterns for Sigil Auth Linux desktop implementation.

## SIGIL-CONV-V1 Wire Protocol

### Envelope Encryption (ECIES)

**Pattern:** P-256 ECDH + HKDF-SHA256 + AES-256-GCM

```rust
// Fresh ephemeral keypair per encryption (CRITICAL)
let ephemeral_secret = SecretKey::random(&mut OsRng);
let ephemeral_public = ephemeral_secret.public_key();

// ECDH with recipient static public key
let shared_secret = diffie_hellman(
    ephemeral_secret.to_nonzero_scalar(),
    recipient_pk.as_affine()
);

// HKDF with fingerprint as salt
let fingerprint = Sha256::digest(recipient_compressed.as_bytes());
let hkdf = Hkdf::<Sha256>::new(Some(&fingerprint), shared_secret.raw_secret_bytes());
let mut aes_key = [0u8; 32];
hkdf.expand(b"SIGIL-CONV-V1-AES256", &mut aes_key)?;

// AES-256-GCM with ephemeral_public as AAD
let cipher = Aes256Gcm::new(&aes_key.into());
let nonce = Nonce::from_slice(&nonce_bytes);
let payload = Payload { msg: plaintext, aad: ephemeral_compressed.as_bytes() };
let ciphertext = cipher.encrypt(nonce, payload)?;

// Wire format: ephemeral_public (33) || nonce (12) || ciphertext || tag (16)
```

**Why:** Spec-mandated construction (§2.3). Ephemeral key reuse breaks IND-CCA2 security.

### Session Pictogram Derivation

**Pattern:** Argon2id KDF for MITM detection

```rust
// Step 1: Hash inputs
let mut hasher = Sha256::new();
hasher.update(server_pub);
hasher.update(client_pub);
hasher.update(server_nonce);
let password = hasher.finalize();

// Step 2: Argon2id with fixed params
let params = argon2::Params::new(65536, 10, 1, Some(32))?;
let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

// Step 3: Derive with domain-separated salt
let mut derived = [0u8; 32];
argon2.hash_password_into(&password, DOMAIN_PAIR_V1, &mut derived)?;

// Step 4: Extract 6 × 16-bit indices modulo 192
for i in 0..6 {
    let word_index = u16::from_be_bytes([derived[2*i], derived[2*i+1]]);
    indices[i] = (word_index % 192) as usize;
}
```

**Why:** 10-second handshake window + Argon2id work factor + 46-bit entropy makes real-time grinding cryptographically infeasible (§4.2).

### Sign-Then-Encrypt Envelope

**Pattern:** RFC 8785 canonical JSON + ECDSA + ECIES

```rust
// 1. Canonicalize payload (sorted keys, no whitespace)
let canonical_payload = serde_jcs::to_string(payload)?;

// 2. Sign with domain tag
let signature = crypto::sign(privkey, canonical_payload.as_bytes(), DOMAIN_CONV_V1);

// 3. Build inner envelope
let inner = InnerEnvelope {
    client_public_key: base64::encode(pubkey_compressed),
    payload: canonical_payload,  // String, not nested object
    signature: base64::encode(&signature),
};

// 4. Canonicalize inner envelope
let inner_json = serde_jcs::to_string(&inner)?;

// 5. ECIES encrypt
let outer_ciphertext = crypto::ecies_encrypt(recipient_pubkey, inner_json.as_bytes())?;

// 6. Base64 for HTTP
base64::encode(&outer_ciphertext)
```

**Why:** Spec-mandated construction (§5). Canonical JSON ensures byte-identical signatures across implementations.

### Domain Separation

**Pattern:** Prepend domain tag before hashing

```rust
// Domain tags (NUL-terminated, fixed length)
pub const DOMAIN_CONV_V1: &[u8] = b"SIGIL-CONV-V1\0";    // 16 bytes
pub const DOMAIN_PAIR_V1: &[u8] = b"SIGIL-PAIR-V1\0\0\0"; // 16 bytes (zero-padded)

// Sign with domain tag
let mut tagged = Vec::with_capacity(domain.len() + message.len());
tagged.extend_from_slice(domain);
tagged.extend_from_slice(message);
let digest = Sha256::digest(&tagged);
let signature = key.sign_prehash(&digest)?;
```

**Why:** Prevents cross-protocol confusion attacks. Different operations (AUTH, MPA, CONV, PAIR) use different tags.

### BIP-62 Low-S Normalization

**Pattern:** Reject high-S signatures

```rust
// Sign: normalize to low-S
let signature = key.sign_prehash(&digest)?;
let normalized = signature.normalize_s().unwrap_or(signature);

// Verify: reject high-S
if signature.normalize_s().is_some() {
    return Err(CryptoError::VerificationFailed);
}
```

**Why:** Prevents signature malleability (SIG-2026-FINDING-5).

## GTK4 / libadwaida Patterns

### Pictogram Display with Accessibility

**Pattern:** AdwPreferencesRow with screen-reader labels

```rust
// 6-emoji pictogram display
let pictogram_row = adw::PreferencesRow::new();
pictogram_row.set_title("Session Pictogram");

let emoji_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
for (emoji, name) in session_pictogram.iter() {
    let label = gtk::Label::new(Some(emoji));
    label.add_css_class("pictogram-emoji");
    label.set_accessible_label(name);  // Screen reader reads name, not emoji
    emoji_box.append(&label);
}

pictogram_row.set_child(Some(&emoji_box));
```

**Why:** WCAG 2.2 AA compliance. Emoji are visual-only; screen readers need text labels.

### XDG Base Directories

**Pattern:** Use `xdg` crate for all paths

```rust
use xdg::BaseDirectories;

let xdg_dirs = BaseDirectories::new()?;
let config_path = xdg_dirs.place_config_file("sigil-auth/config.toml")?;
let data_path = xdg_dirs.place_data_file("sigil-auth/keys.db")?;
let cache_path = xdg_dirs.place_cache_file("sigil-auth/pictograms.cache")?;
```

**Why:** Violation #1 (HIGH). Never hardcode `/home/user/` paths. Fails on multi-user, Flatpak, immutable distros.

### Async I/O on Main Thread

**Pattern:** Use GLib async APIs

```rust
// WRONG: Blocking file I/O
let contents = std::fs::read_to_string(path)?;

// RIGHT: Async with GLib
use gio::prelude::*;
let file = gio::File::for_path(path);
file.load_contents_async(None::<&gio::Cancellable>, move |result| {
    match result {
        Ok((contents, _)) => { /* handle */ },
        Err(e) => { /* handle */ },
    }
});
```

**Why:** Violation #8 (HIGH). Blocking main thread = frozen UI = user kills app.

### D-Bus Signal Cleanup

**Pattern:** Store signal handler ID, disconnect in `dispose`

```rust
struct MyObject {
    signal_handler_id: Cell<Option<glib::SignalHandlerId>>,
}

impl MyObject {
    fn connect_signals(&self) {
        let id = some_object.connect_signal(|_| { /* handler */ });
        self.signal_handler_id.set(Some(id));
    }
}

impl Drop for MyObject {
    fn drop(&mut self) {
        if let Some(id) = self.signal_handler_id.take() {
            some_object.disconnect(id);
        }
    }
}
```

**Why:** Violation #9 (HIGH). Undisconnected signals leak memory. Alternatively, use `g_signal_connect_object` for automatic cleanup.

### Desktop Entry File

**Pattern:** Reverse-DNS app ID

```
[Desktop Entry]
Type=Application
Name=Sigil Auth
Exec=sigil-desktop
Icon=org.sigilauth.Desktop
Categories=Utility;Security;
MimeType=x-scheme-handler/sigil;
```

**Why:** Violation #5 (HIGH). `org.sigilauth.Desktop` matches Flatpak app ID, D-Bus service name, icon theme path.

### App Metadata (AppData)

**Pattern:** Provide `.metainfo.xml` for app stores

```xml
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>org.sigilauth.Desktop</id>
  <name>Sigil Auth</name>
  <summary>Hardware-backed strong authentication</summary>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>AGPL-3.0-or-later</project_license>
  <developer_name>Wagmi Labs</developer_name>
  <url type="homepage">https://sigilauth.com</url>
  <screenshots>
    <screenshot type="default">
      <image>https://sigilauth.com/screenshots/main.png</image>
    </screenshot>
  </screenshots>
  <releases>
    <release version="0.1.0" date="2026-04-26" />
  </releases>
  <content_rating type="oars-1.1" />
</component>
```

**Why:** Violation #10 (HIGH). Without metainfo, app doesn't appear in GNOME Software, KDE Discover, Flathub.

## Flatpak Patterns

### Portal File Access

**Pattern:** Use `org.freedesktop.portal.FileChooser` in sandbox

```rust
use zbus::Connection;

let connection = Connection::session().await?;
let proxy = zbus::Proxy::new(
    &connection,
    "org.freedesktop.portal.Desktop",
    "/org/freedesktop/portal/desktop",
    "org.freedesktop.portal.FileChooser",
).await?;

// Portal returns handle, not path
let result = proxy.call_method("OpenFile", &(parent_window, title, options)).await?;
```

**Why:** Violation #2 (HIGH). Direct file access fails in Flatpak strict sandbox. Portal provides UI + permission gate.

### Rate Limiting Configuration

**Pattern:** Configurable TTL + fixed handshake window

```rust
pub struct PairConfig {
    pub handshake_ttl_seconds: u64,        // Fixed: 10
    pub pending_approval_ttl_seconds: u64, // Configurable: 30s to 7 days
    pub max_concurrent_handshakes: usize,  // Rate limit: 3 per IP
    pub max_init_requests_per_minute: usize, // Rate limit: 10 per IP
}

impl Default for PairConfig {
    fn default() -> Self {
        Self {
            handshake_ttl_seconds: 10,
            pending_approval_ttl_seconds: 300,
            max_concurrent_handshakes: 3,
            max_init_requests_per_minute: 10,
        }
    }
}
```

**Why:** Spec requirement (§4.1). 10-second handshake window is cryptographic bound. Pending-approval TTL is operational choice (30s for live admin, 7 days for ticket workflow).

## Test Patterns

### Deterministic Test Vectors

**Pattern:** RFC 6979 deterministic ECDSA for reproducibility

```rust
#[test]
fn matches_test_vector() {
    let privkey_bytes = hex::decode("c9afa9d8...").unwrap();
    let secret_key = SecretKey::from_slice(&privkey_bytes).unwrap();
    let signing_key = SigningKey::from(secret_key);

    let message = hex::decode("0123456789abcdef...").unwrap();
    let signature = crypto::sign(&signing_key, &message, DOMAIN_CONV_V1);

    let expected = hex::decode("a68b6513...").unwrap();
    assert_eq!(signature.as_slice(), expected.as_slice(),
        "Signature must match test vector byte-for-byte (RFC 6979)");
}
```

**Why:** Test vectors at `api/test-vectors/wire-protocol/` ensure cross-implementation compatibility. Deterministic signatures make tests reproducible.

### Session Pictogram Test Vectors

**Pattern:** Known inputs → expected emoji sequence

```rust
#[test]
fn session_pictogram_vector_1() {
    let server_pub = hex::decode("02...").unwrap().try_into().unwrap();
    let client_pub = hex::decode("03...").unwrap().try_into().unwrap();
    let server_nonce = hex::decode("abcd...").unwrap().try_into().unwrap();

    let pictogram = session_pictogram::derive(&server_pub, &client_pub, &server_nonce).unwrap();

    assert_eq!(pictogram, ["apple", "rocket", "fox", "anchor", "moon", "house"],
        "Pictogram must match test vector exactly");
}
```

**Why:** Argon2id is deterministic with fixed inputs. Test vectors ensure derivation matches server implementation (Kai's Go reference).

## Approved Libraries

| Purpose | Crate | Version | Why |
|---------|-------|---------|-----|
| ECDSA | `p256` | 0.13 | NIST P-256, RFC 6979 deterministic signing |
| AES-GCM | `aes-gcm` | 0.10 | Constant-time, audited |
| HKDF | `hkdf` | 0.12 | RFC 5869 compliant |
| Argon2id | `argon2` | 0.5 | PHC winner, memory-hard KDF |
| Canonical JSON | `serde_jcs` | 0.1 | RFC 8785 implementation |
| Base64 | `base64` | 0.22 | Use `Engine` API (0.21+ deprecates old API) |
| XDG dirs | `xdg` | 2 | FreeDesktop base directory spec |
| D-Bus | `zbus` | 4 | Async, well-typed |
| Secret Service | `secret-service` | 4 | Keyring integration |
| GTK4 | `gtk4` | 0.8 | v4_10 features |
| libadwaita | `libadwaita` | 0.6 | v1_4 features |

**NO:** Custom crypto implementations. Use audited crates only.

### Replay Protection (Nonce Tracking)

**Pattern:** Thread-safe sliding window with TTL eviction

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct NonceStore {
    inner: Arc<Mutex<NonceStoreInner>>,
}

struct NonceStoreInner {
    nonces: HashMap<String, Instant>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NonceStoreInner {
                nonces: HashMap::new(),
            })),
        }
    }

    pub fn check_and_insert(&self, nonce: &str) -> Result<(), NonceError> {
        let mut inner = self.inner.lock().unwrap();
        
        // Evict stale entries (>300s old)
        let now = Instant::now();
        inner.nonces.retain(|_, &mut timestamp| {
            now.duration_since(timestamp) < Duration::from_secs(300)
        });
        
        // Check for replay
        if inner.nonces.contains_key(nonce) {
            return Err(NonceError::NonceReused);
        }
        
        // Mark as seen
        inner.nonces.insert(nonce.to_string(), Instant::now());
        Ok(())
    }
}
```

**Integration in envelope verification:**

```rust
pub fn verify_request(
    server_privkey: &SigningKey,
    envelope_b64: &str,
    current_timestamp: i64,
    expected_audience: &str,
    nonce_store: &NonceStore,
) -> Result<(VerifyingKey, RequestPayload), EnvelopeError> {
    // ... decrypt, verify signature, check timestamp, check audience ...
    
    // Replay protection (MUST be called before returning success)
    nonce_store.check_and_insert(&payload.nonce)?;
    
    Ok((client_verifying_key, payload))
}
```

**Why:** 
- Spec requirement (§6.2). Prevents replay attacks within 300-second timestamp window.
- `Arc<Mutex<>>` provides thread-safe cloning for multi-threaded verification contexts.
- Automatic TTL eviction prevents unbounded memory growth.
- Check-and-insert is atomic (Mutex held across both operations) → no TOCTOU race.

**Tests:** fresh_nonce_accepted, duplicate_nonce_rejected, eviction_removes_stale_nonces, thread_safe_concurrent_access

**Addressed:** Raven HIGH P7 finding (SIG-2026-RAVEN-P7)

