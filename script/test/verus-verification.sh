#!/usr/bin/env bash
# Guards for the Verus verification gate (.github/workflows/verus.yml).
#
#   --repo-gate  Verify this repo's contracts AND assert something was actually
#                verified. `cargo verus verify` exits 0 while verifying nothing
#                when [package.metadata.verus] is gone, when the verus! block is
#                gone, or when cargo's fingerprint is warm, so exit status alone
#                is not a gate. See docs/adr/0018-machine-checked-boundary-contracts.md.
#   --controls   Prove the verifier on PATH can both pass and fail, using two
#                throwaway fixture crates.
#
# With no argument, runs both.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
VSTD_PIN='=0.0.0-2026-09-16-0054'
RESULTS_OK='verification results:: [1-9][0-9]* verified, 0 errors'

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The fixture tree lives in a script-level variable so the EXIT trap can still
# read it: a `local` inside controls() is out of scope (and `set -u` would make
# the trap itself fail) by the time the trap runs.
FIXTURE_ROOT=""
cleanup() {
    if [[ -n "$FIXTURE_ROOT" ]]; then
        rm -rf "$FIXTURE_ROOT"
    fi
}
trap cleanup EXIT

require_cargo_verus() {
    command -v cargo-verus >/dev/null 2>&1 ||
        fail "cargo-verus is not on PATH; install the pinned Verus release (see CONTRIBUTING.md)"
}

repo_gate() {
    local target_dir output status region
    target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target/verus}"

    # cargo re-prints a crate's "verification results::" line only when it
    # re-checks the crate; with a warm target dir it prints nothing at all and
    # the assertion below would fail for the wrong reason. Cleaning just this
    # package keeps every dependency -- including vstd's 2059 proofs -- cached.
    (cd "$REPO_ROOT" && CARGO_TARGET_DIR="$target_dir" cargo clean -p agent-vm)

    set +e
    output="$(cd "$REPO_ROOT" && CARGO_TARGET_DIR="$target_dir" \
        cargo verus verify --locked -p agent-vm 2>&1)"
    status=$?
    set -e
    printf '%s\n' "$output"

    [[ $status -eq 0 ]] ||
        fail "cargo verus verify --locked -p agent-vm exited $status (expected 0)"

    # vstd's own results line is printed before this crate's, so read only the
    # output from cargo's "Checking agent-vm" line onward.
    region="$(printf '%s\n' "$output" |
        sed -n -E '/^[[:space:]]*(Checking|Compiling) agent-vm /,$p')"
    [[ -n "$region" ]] ||
        fail "cargo verus never checked the agent-vm crate: [package.metadata.verus] verify = true may have been removed from crates/agent-vm/Cargo.toml"

    printf '%s\n' "$region" | grep -Eq "$RESULTS_OK" ||
        fail "the verification gate verified 0 functions in agent-vm: [package.metadata.verus] verify = true or the verus! block may have been removed"

    echo "verus gate: agent-vm contracts verified"
}

# fixture <dir> <crate-name> <exec-body>
fixture() {
    local dir="$1" name="$2" body="$3"
    mkdir -p "$dir/src"
    cat >"$dir/Cargo.toml" <<EOF
[package]
name = "$name"
version = "0.0.0"
edition = "2024"

[package.metadata.verus]
verify = true

[dependencies]
vstd = "$VSTD_PIN"

[workspace]
EOF
    cat >"$dir/src/lib.rs" <<EOF
use vstd::prelude::*;

verus! {
pub fn double(x: u8) -> (r: u8)
    requires x < 128,
    ensures r == 2 * x,
{ $body }
}
EOF
}

controls() {
    local target out status
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/verus-verification.XXXXXX")"
    target="$FIXTURE_ROOT/target" # one target dir for both fixtures: vstd verifies once

    # Positive control: the contract holds.
    fixture "$FIXTURE_ROOT/positive" verus_control_positive 'x + x'
    set +e
    out="$(cd "$FIXTURE_ROOT/positive" && CARGO_TARGET_DIR="$target" cargo verus verify 2>&1)"
    status=$?
    set -e
    [[ $status -eq 0 ]] || {
        printf '%s\n' "$out"
        fail "positive control exited $status, expected 0"
    }
    grep -Eq "$RESULTS_OK" <<<"$out" || {
        printf '%s\n' "$out"
        fail "positive control printed no successful verification line"
    }

    # Negative control: the same function with a deliberately false postcondition.
    fixture "$FIXTURE_ROOT/negative" verus_control_negative 'x'
    set +e
    out="$(cd "$FIXTURE_ROOT/negative" && CARGO_TARGET_DIR="$target" cargo verus verify 2>&1)"
    status=$?
    set -e
    [[ $status -ne 0 ]] || {
        printf '%s\n' "$out"
        fail "negative control exited 0: the verifier accepted a false postcondition"
    }
    grep -q 'postcondition not satisfied' <<<"$out" || {
        printf '%s\n' "$out"
        fail "negative control failed, but not with 'postcondition not satisfied'"
    }
    grep -q 'verification results:: 0 verified, 1 errors' <<<"$out" || {
        printf '%s\n' "$out"
        fail "negative control did not report '0 verified, 1 errors'"
    }

    echo "verus controls: positive verified, negative failed as expected"
}

main() {
    require_cargo_verus
    case "${1-}" in
        --repo-gate) repo_gate ;;
        --controls) controls ;;
        "")
            repo_gate
            controls
            ;;
        *)
            echo "usage: ${0##*/} [--repo-gate | --controls]" >&2
            exit 2
            ;;
    esac
}

main "$@"
