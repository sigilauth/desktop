# Sigil Auth — Linux Desktop

GTK4 + libadwaita client for Sigil Auth, written in Rust.

**Status:** pre-production scaffold. Blocked on B0 (OpenAPI) for crypto and wire-layer code.

## Requirements

| Package (Debian/Ubuntu) | Package (Fedora) | Purpose |
|---|---|---|
| `libgtk-4-dev` | `gtk4-devel` | UI toolkit |
| `libadwaita-1-dev` | `libadwaita-devel` | GNOME adaptive widgets |
| `libsecret-1-dev` | `libsecret-devel` | Server-config storage |
| `libtss2-dev` | `tpm2-tss-devel` | TPM 2.0 (`tss-esapi`) |
| `libpcsclite-dev` | `pcsc-lite-devel` | YubiKey detection |
| `meson` | `meson` | Build system |
| `cargo` `rustc` (≥ 1.75) | `cargo` `rust` | Rust toolchain |

## Build

```sh
meson setup build --prefix=/usr
meson compile -C build
meson install -C build   # system-wide install
```

## Design

- Hardware keys: TPM 2.0 (`tss-esapi`) or YubiKey PIV (`yubikey` crate).
  Private keys never leave hardware. See `working/linux-desktop/plan.md` §Hardware-Key Strategy.
- Metadata (server URLs, pinned server public keys, pictograms): libsecret
  via Secret Service D-Bus.
- i18n: Fluent (`fluent-rs`), shared catalog from B15.
- Accessibility: AT-SPI via GTK4; Orca-compatible state announcements.

See `working/linux-desktop/plan.md` for the full plan, `patterns.md` for
approved patterns, and `violations-log.md` for open cross-spec issues.

## License

AGPL-3.0-or-later. API specifications (separate repo) are Apache-2.0.
