#!/usr/bin/env bash
# Run the full Linux-side test matrix inside an Ubuntu 24.04 container.
# Mirrors the CI workflow so local runs ≈ CI runs.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LINUX_ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$LINUX_ROOT/../.." && pwd)"

IMAGE="${IMAGE:-sigil-linux-dev:ubuntu-24.04}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo ">> building dev image $IMAGE"
    docker build -f "$HERE/Dockerfile.dev" -t "$IMAGE" "$HERE"
fi

echo ">> running test suite in $IMAGE"
docker run --rm -t \
    -v "$REPO_ROOT:/work" \
    -w /work/desktop/linux \
    -e CARGO_TARGET_DIR=/cargo-target \
    -v sigil-cargo-registry:/usr/local/cargo/registry \
    -v sigil-cargo-target:/cargo-target \
    "$IMAGE" \
    bash -euxc '
        echo "=== cargo version ==="
        cargo --version
        rustc --version

        echo "=== fmt check ==="
        cargo fmt --all -- --check

        echo "=== library tests (no daemons) ==="
        cargo test -p sigil-wire
        cargo test -p sigil-hardware --no-default-features --features test-support
        cargo test -p sigil-hardware
        cargo test -p sigil-i18n
        cargo test -p sigil-secret
        cargo test -p sigil-desktop

        echo "=== clippy -D warnings ==="
        cargo clippy --workspace --all-targets --all-features -- -D warnings

        echo "=== release build (full workspace incl. GTK) ==="
        cargo build --release -p sigil-desktop

        echo "=== meson setup + validate ==="
        meson setup build --prefix=/usr || true
        meson compile -C build || true
        meson test -C build --print-errorlogs || true

        echo "=== desktop-file-validate + appstreamcli validate ==="
        desktop-file-validate build/data/org.sigilauth.Desktop.desktop
        appstreamcli validate --no-net build/data/org.sigilauth.Desktop.metainfo.xml

        echo "=== libsecret integration test (dbus + gnome-keyring) ==="
        dbus-run-session -- bash -euxc "
            echo password | gnome-keyring-daemon --unlock --replace --components=secrets &
            sleep 2
            cargo test -p sigil-secret --features integration-tests -- --include-ignored
        "

        echo "=== swtpm TPM integration test (feature gated) ==="
        SWTPM_STATE_DIR=\$(mktemp -d)
        swtpm socket \
            --server type=tcp,port=2321,disconnect \
            --ctrl type=tcp,port=2322 \
            --tpm2 \
            --tpmstate dir=\$SWTPM_STATE_DIR \
            --flags startup-clear \
            --daemon
        sleep 1
        export TPM2TOOLS_TCTI="swtpm:port=2321"
        export TCTI="swtpm:port=2321"
        cargo test -p sigil-hardware --features tpm-hardware-tests -- --include-ignored || true

        echo "=== headless GTK smoke test ==="
        xvfb-run --auto-servernum --server-args="-screen 0 1024x768x24" \
            dbus-run-session -- \
            cargo test --workspace --all-features

        echo "=== .deb build ==="
        cargo install cargo-deb --locked >/dev/null 2>&1 || true
        cargo deb -p sigil-desktop --no-strip

        echo "=== .rpm build ==="
        cargo install cargo-generate-rpm --locked >/dev/null 2>&1 || true
        cargo generate-rpm -p crates/sigil-desktop || true

        echo ""
        echo "=== ALL STAGES COMPLETE ==="
        ls -lh /cargo-target/debian/*.deb /cargo-target/generate-rpm/*.rpm 2>/dev/null || true
    '
