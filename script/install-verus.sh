#!/usr/bin/env bash
# Install the Verus release this repository pins, for local contract
# verification (CONTRIBUTING.md -> "Verifying contracts locally").
#
# The release and its per-asset digests are read from
# .github/workflows/verus.yml, which declares them and performs the same install
# in CI. That file is the single source of truth, so a Verus bump is not
# mirrored here.
#
# Every asset this script can install has a pinned digest, because the point of
# installing a release by tag is defeated if the bytes behind the tag are taken
# on faith. CI only ever downloads the x86-linux asset; the arm64-macos pin
# exists so a local macOS install is verified too. A platform with no pinned
# asset is a deliberate failure rather than an unverified download.
#
# Usage: script/install-verus.sh [--prefix DIR] [--force]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/verus.yml"
PREFIX="$HOME/.verus"
FORCE=0

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    printf 'usage: script/install-verus.sh [--prefix DIR] [--force]\n'
    printf '\nInstalls the Verus release pinned in .github/workflows/verus.yml.\n'
    printf 'Default prefix: %s\n' "$HOME/.verus"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            [[ $# -ge 2 ]] || fail "--prefix needs a directory"
            PREFIX="$2"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "unknown argument: $1"
            ;;
    esac
done

# Same idiom as script/check-rust-toolchain.sh's check_verus_yml.
read_pin() {
    local key="$1" value
    value="$(sed -n "s/^[[:space:]]*${key}: \"\\(.*\\)\"\$/\\1/p" "$WORKFLOW")"
    [[ -n "$value" ]] || fail "no ${key} found in ${WORKFLOW#"$REPO_ROOT"/}"
    printf '%s' "$value"
}

RELEASE="$(read_pin VERUS_RELEASE)"

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)
        ASSET="verus-${RELEASE}-x86-linux.zip"
        EXPECTED="$(read_pin VERUS_SHA256)"
        ;;
    Darwin/arm64)
        ASSET="verus-${RELEASE}-arm64-macos.zip"
        EXPECTED="$(read_pin VERUS_SHA256_ARM64_MACOS)"
        ;;
    *)
        fail "no Verus asset is known for $(uname -s)/$(uname -m); see https://github.com/verus-lang/verus/releases"
        ;;
esac

if [[ "$FORCE" -eq 0 ]] && [[ -n "$(find "$PREFIX" -maxdepth 3 -type f -name cargo-verus 2>/dev/null | head -n1)" ]]; then
    printf 'already installed under %s (use --force to reinstall)\n' "$PREFIX"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

printf 'downloading %s\n' "$ASSET"
curl -fSL --retry 3 -o "$TMP/$ASSET" \
    "https://github.com/verus-lang/verus/releases/download/release/${RELEASE}/${ASSET}"

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)"
else
    ACTUAL="$(shasum -a 256 "$TMP/$ASSET" | cut -d' ' -f1)"
fi

[[ "$ACTUAL" == "$EXPECTED" ]] ||
    fail "sha256 mismatch for $ASSET: expected $EXPECTED, got $ACTUAL"
printf 'sha256 verified against .github/workflows/verus.yml\n'

mkdir -p "$PREFIX"
unzip -q "$TMP/$ASSET" -d "$PREFIX"

CARGO_VERUS="$(find "$PREFIX" -maxdepth 3 -type f -name cargo-verus | head -n1)"
[[ -n "$CARGO_VERUS" ]] || fail "cargo-verus not found under $PREFIX after unpacking $ASSET"

printf "\nVerus %s installed.\n\n    export PATH=\"%s:\$PATH\"\n\nThen: CARGO_TARGET_DIR=target/verus cargo verus verify -p agent-vm\n" \
    "$RELEASE" "$(dirname "$CARGO_VERUS")"
