#!/usr/bin/env bash
# Install the Rust toolchain this repo pins, with the clippy and rustfmt
# components and the host *-unknown-linux-musl target. Runs both standalone
# (as root on a Debian/Ubuntu host) and from
# examples/layers/rust-dev/Dockerfile, which passes the pin and the install
# locations as build args.
#
# Environment:
#   RUST_TOOLCHAIN  required; the exact channel (e.g. 1.98.1)
#   RUSTUP_HOME     default /opt/rustup
#   CARGO_HOME      default /opt/cargo
#
# The install is world-readable (contract C7): the guest may run as an
# arbitrary non-root uid.
set -euo pipefail

: "${RUST_TOOLCHAIN:?RUST_TOOLCHAIN must be set to the pinned toolchain (e.g. 1.98.1)}"
RUSTUP_HOME="${RUSTUP_HOME:-/opt/rustup}"
CARGO_HOME="${CARGO_HOME:-/opt/cargo}"
export RUSTUP_HOME CARGO_HOME

echo "==> install-rust: toolchain $RUST_TOOLCHAIN into $RUSTUP_HOME / $CARGO_HOME"

# The official installer, as macos-build.md does: only the toolchain version is
# part of the build identity, not the rustup version that installs it.
installer="$(mktemp)"
trap 'rm -f "$installer"' EXIT
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$installer"
sh "$installer" -y --no-modify-path --profile minimal \
    --default-toolchain "$RUST_TOOLCHAIN" \
    --component clippy,rustfmt

case "$(dpkg --print-architecture)" in
    amd64) musl_target=x86_64-unknown-linux-musl ;;
    arm64) musl_target=aarch64-unknown-linux-musl ;;
    *)
        echo "install-rust: unexpected architecture: $(dpkg --print-architecture)" >&2
        exit 1
        ;;
esac
"$CARGO_HOME/bin/rustup" target add "$musl_target"

chmod -R a+rX "$RUSTUP_HOME" "$CARGO_HOME"
echo "==> install-rust: done"
