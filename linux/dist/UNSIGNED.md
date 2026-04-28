# Package Signing Status

**Date:** 2026-04-26  
**Built by:** Terra via doppler SSH  

## Packages

All packages in this directory are **UNSIGNED**.

| Package | Size | Format | Architecture |
|---------|------|--------|--------------|
| sigilauth-desktop_0.1.0-1_amd64.deb | 576KB | Debian | x86_64 |
| sigilauth-desktop-0.1.0-1.x86_64.rpm | TBD | RPM | x86_64 |

## Why Unsigned?

Per team lead directive 2026-04-26: skip GPG repo signing for initial build. Kaity will sign with her GPG key before distribution.

## Build Environment

- **System:** CachyOS (Arch-based rolling)
- **Rust:** 1.95.0
- **GTK4:** 4.10+
- **libadwaita:** 1.4+
- **Build features:** `test-support` (for demo mode WebSocket client)

## To Sign

Debian:
```bash
debsigs --sign=origin -k <GPG_KEY_ID> sigilauth-desktop_0.1.0-1_amd64.deb
```

RPM:
```bash
rpm --addsign sigilauth-desktop-0.1.0-1.x86_64.rpm
```

## Installation (Unsigned)

**Warning:** Installing unsigned packages bypasses package verification. Only install from trusted sources.

Debian/Ubuntu:
```bash
sudo dpkg -i sigilauth-desktop_0.1.0-1_amd64.deb
sudo apt-get install -f  # Fix dependencies
```

Fedora/RHEL:
```bash
sudo rpm -i sigilauth-desktop-0.1.0-1.x86_64.rpm
```

## Dependencies

| Debian/Ubuntu | Fedora/RHEL |
|--------------|-------------|
| libgtk-4-1 >= 4.10 | gtk4 >= 4.10 |
| libadwaita-1-0 >= 1.4 | libadwaita >= 1.4 |
| libsecret-1-0 | libsecret |
| libtss2-esys-3.0.2-0 | tpm2-tss |
| libpcsclite1 | pcsc-lite |

## Binary Details

- **Path:** `/usr/bin/sigil-desktop`
- **Size:** 3.1MB (stripped)
- **Type:** ELF 64-bit LSB pie executable
- **Desktop entry:** `/usr/share/applications/org.sigilauth.Desktop.desktop`
- **Icons:** `/usr/share/icons/hicolor/{scalable,symbolic}/apps/org.sigilauth.Desktop*.svg`
- **Metainfo:** `/usr/share/metainfo/org.sigilauth.Desktop.metainfo.xml`
- **GSettings schema:** `/usr/share/glib-2.0/schemas/org.sigilauth.Desktop.gschema.xml`
