# Sigil Auth Desktop — Flathub Submission

Flatpak packaging for native Linux desktop app. Targets Flathub for universal distribution across all distros.

## Files

| File | Purpose |
|------|---------|
| `org.sigilauth.Desktop.yml` | Flatpak manifest (runtime, dependencies, build config) |
| `../data/org.sigilauth.Desktop.metainfo.xml` | AppStream metadata (description, screenshots, OARS rating) |
| `../data/org.sigilauth.Desktop.desktop` | Desktop entry file (launcher integration) |

## Submission Status

**🚧 BLOCKED — Submission not yet possible**

### Blockers

1. **App not functional** — Desktop views are minimal shells. Wire protocol client implementation incomplete in `sigil-wire` crate (needs HTTP client for pair/respond, WebSocket for listen, ECDSA P-256 signing, ECIES decrypt). OpenAPI spec exists at `/api/openapi.yaml`; cli-device (Go) is working reference implementation.
2. **Screenshots required** — Flathub requires 3-5 screenshots showing actual UI. Cannot capture until views implemented.
3. **Flathub account credentials** — Kaity holds credentials, manual step required.

### What's Ready

- ✅ Flatpak manifest with full dependency chain (TPM2-TSS, PC/SC Lite)
- ✅ AppStream metainfo XML with description, categories, keywords, OARS rating
- ✅ Desktop entry file
- ✅ Build system integration (Meson)
- ✅ Sandbox permissions configured (network, D-Bus, smart card, TPM access)

## Building Locally

Test the Flatpak build before submission:

```bash
# Install Flatpak + flatpak-builder
sudo apt install flatpak flatpak-builder  # Debian/Ubuntu
sudo dnf install flatpak flatpak-builder  # Fedora
sudo pacman -S flatpak flatpak-builder    # Arch

# Add Flathub runtime repository
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

# Install GNOME Platform 47 runtime + SDK
flatpak install flathub org.gnome.Platform//47 org.gnome.Sdk//47

# Build
cd /Volumes/Expansion/src/sigilauth/desktop/linux
flatpak-builder --force-clean build-dir flatpak/org.sigilauth.Desktop.yml

# Install locally
flatpak-builder --user --install --force-clean build-dir flatpak/org.sigilauth.Desktop.yml

# Run
flatpak run org.sigilauth.Desktop
```

## Testing Sandbox Permissions

Verify app can access required hardware:

```bash
# Check TPM device visibility (should show /dev/tpm0, /dev/tpmrm0)
flatpak run --command=sh org.sigilauth.Desktop -c "ls -l /dev/tpm*"

# Check PC/SC socket (should exist)
flatpak run --command=sh org.sigilauth.Desktop -c "ls -l /run/pcscd/pcscd.comm"

# Check D-Bus session access (should connect)
flatpak run --command=sh org.sigilauth.Desktop -c "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames"
```

## Flathub Submission Process (When Ready)

1. **Create screenshots** — Capture 3-5 PNG screenshots showing main UI, authentication flow, settings. 16:9 ratio preferred.
2. **Add screenshots to metainfo** — Update `data/org.sigilauth.Desktop.metainfo.xml`:
   ```xml
   <screenshots>
     <screenshot type="default">
       <image>https://sigilauth.com/screenshots/main-window.png</image>
       <caption>Main authentication view</caption>
     </screenshot>
     <screenshot>
       <image>https://sigilauth.com/screenshots/approval-flow.png</image>
       <caption>Push approval with action context</caption>
     </screenshot>
   </screenshots>
   ```
3. **Fork flathub/flathub** — Create GitHub fork of Flathub submissions repo
4. **Create submission PR** — Add `org.sigilauth.Desktop/` directory with:
   - `org.sigilauth.Desktop.yml` (this manifest)
   - `flathub.json` (metadata: `{"only-arches": ["x86_64", "aarch64"]}`)
5. **Pass automated checks** — Flathub CI validates:
   - AppStream metainfo (appstreamcli validate)
   - Desktop file (desktop-file-validate)
   - Manifest structure
   - Build succeeds on x86_64 + aarch64
6. **Manual review** — Flathub maintainers review permissions, dependencies, license
7. **Merge** — App goes live on Flathub within hours of merge

## Sandbox Permissions Justification

Flatpak enforces strict sandboxing. Permissions required:

| Permission | Justification |
|------------|---------------|
| `--share=network` | WebSocket connection to relay server for push auth |
| `--socket=session-bus` | D-Bus access for Secret Service (libsecret) + notifications |
| `--system-talk-name=org.freedesktop.fwupd` | TPM device detection via fwupd |
| `--socket=pcsc` | YubiKey PIV smart card access |
| `--device=all` | TPM character device access (/dev/tpm0, /dev/tpmrm0) — will narrow when Flatpak supports specific device filters |
| `--talk-name=org.freedesktop.secrets` | Server config storage in system keyring |
| `--filesystem=xdg-config/sigil:create` | App configuration files (~/.config/sigil) |
| `--filesystem=xdg-data/sigil:create` | App data files (~/.local/share/sigil) |

**Note:** `--device=all` is broader than ideal. Flatpak does not yet support filtering to specific `/dev/tpm*` devices. This permission does NOT grant filesystem access (covered separately by `--filesystem`).

## Dependencies

**TPM2-TSS** (v4.0.1) — TPM 2.0 Software Stack for hardware key support in TPM chips.

**PC/SC Lite** (v2.0.1) — Smart card middleware for YubiKey PIV applet access.

Both are built from source within the Flatpak sandbox. See manifest for build configuration.

## Maintenance

**Runtime updates** — GNOME Platform 47 receives updates via Flathub. App automatically picks up security patches.

**Dependency updates** — Monitor TPM2-TSS and PC/SC Lite releases. Update manifest URLs + SHA256 hashes when new versions ship.

**Flatpak manifest changes** — Test locally with `flatpak-builder` before submitting PR to Flathub.

## Further Reading

- **Flathub submission guide:** https://docs.flathub.org/docs/for-app-authors/submission/
- **Flatpak manifest reference:** https://docs.flatpak.org/en/latest/manifests.html
- **AppStream metainfo spec:** https://www.freedesktop.org/software/appstream/docs/chap-Metadata.html
- **Flathub requirements:** https://docs.flathub.org/docs/for-app-authors/requirements/

## License

Flatpak manifest and packaging: AGPL-3.0-or-later  
AppStream metadata: CC0-1.0 (per FreeDesktop convention)
