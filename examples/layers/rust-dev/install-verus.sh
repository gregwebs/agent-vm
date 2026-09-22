#!/usr/bin/env bash
# Install the pinned Verus release (the SMT-backed verifier for the repo's
# verus! contracts, ADR-0018). Runs both standalone and from
# examples/layers/rust-dev/Dockerfile, which passes the pin and the install
# location as build args.
#
# Environment:
#   VERUS_RELEASE  required; the tagged release (e.g. 0.2026.09.20.aef82ed)
#   VERUS_SHA256   required; sha256 of the x86-linux asset for that release
#   VERUS_DIR      default /opt/verus
#
# Upstream publishes no linux-arm64 asset, so on any other architecture this is
# a clean no-op and the caller uses the host's arm64-macos Verus instead. The
# digest check is a hard failure, never soft-failable.
set -euo pipefail

: "${VERUS_RELEASE:?VERUS_RELEASE must be set to the pinned tagged release}"
: "${VERUS_SHA256:?VERUS_SHA256 must be set to the pinned asset digest}"
VERUS_DIR="${VERUS_DIR:-/opt/verus}"

arch="$(dpkg --print-architecture)"
if [ "$arch" != amd64 ]; then
    echo "==> install-verus: no Verus linux-${arch} release; run Verus on the host instead"
    exit 0
fi

asset="verus-${VERUS_RELEASE}-x86-linux.zip"
archive="/tmp/${asset}"
trap 'rm -f "$archive"' EXIT

echo "==> install-verus: $VERUS_RELEASE into $VERUS_DIR"
curl -fSL --retry 3 -o "$archive" \
    "https://github.com/verus-lang/verus/releases/download/release/${VERUS_RELEASE}/${asset}"
echo "${VERUS_SHA256}  ${archive}" | sha256sum -c -

mkdir -p "$VERUS_DIR"
unzip -q "$archive" -d "$VERUS_DIR"

# World-readable for the arbitrary-uid guest (contract C7).
chmod -R a+rX "$VERUS_DIR"
echo "==> install-verus: done"
