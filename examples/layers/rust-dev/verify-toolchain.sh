#!/usr/bin/env bash
# Post-install sanity for the rust-dev tooling layer. Runs both standalone and
# from examples/layers/rust-dev/Dockerfile.
#
# It invokes every tool directly (not `command -v`), so a present-but-broken
# binary -- a truncated download, a missing libc symbol, an absent component --
# fails here instead of surfacing as command-not-found in the guest. On amd64
# the Verus check goes beyond `--version`: it verifies a trivial contract and
# requires the `N verified, 0 errors` line, so a Verus tree that cannot reach
# its bundled vstd + z3 -- or that exits 0 while verifying nothing (ADR-0018)
# -- fails the build.
#
# Environment:
#   RUST_TOOLCHAIN  required; the exact channel the layer installed
#   VERUS_DIR       default /opt/verus
set -euo pipefail

: "${RUST_TOOLCHAIN:?RUST_TOOLCHAIN must be set to the pinned toolchain}"
VERUS_DIR="${VERUS_DIR:-/opt/verus}"

test "$(rustc --version | cut -d' ' -f2)" = "$RUST_TOOLCHAIN"
cargo --version
cargo clippy --version
rustfmt --version

if [ "$(dpkg --print-architecture)" = amd64 ]; then
    verus="$VERUS_DIR/verus-x86-linux/verus"
    "$verus" --version
    "$VERUS_DIR/verus-x86-linux/z3" --version

    smoke="$(mktemp -d)"
    trap 'rm -rf "$smoke"' EXIT
    cat > "$smoke/smoke.rs" <<'RS'
use vstd::prelude::*;

verus! {
proof fn layer_smoke()
    ensures true,
{
}
}
RS
    smoke_out="$( (cd "$smoke" && "$verus" --crate-type=lib smoke.rs) 2>&1 )"
    printf '%s\n' "$smoke_out"
    printf '%s\n' "$smoke_out" |
        grep -Eq 'verification results:: [1-9][0-9]* verified, 0 errors'
fi

echo "== rust-dev layer sanity OK =="
