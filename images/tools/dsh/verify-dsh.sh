#!/bin/sh
# Build-time gate for the dsh tool layer. Bind-mounted into the layer's
# Dockerfile, not COPYed, so it never ships in the image.
#
# The version *string* is the assertion, not the exit code. dsh dispatches on
# `import.meta.main`, which Node only defines from 22.19 (and 24.x); on an
# older Node its bin.js loads, prints nothing and exits 0. A `dsh --version`
# exit-code check would therefore pass on an image that ships no working dsh —
# and `agent-vm setup`'s own `--version` probe would pass it too. dsh is
# deliberately never soft-failable: the Dockerfile's `npm ci` already hard-fails
# on an install error, so the only failure left here is a present-but-broken
# agent, which is worse than an absent one.
set -eu

# The manifest pins the expected version. `DSH_MANIFEST` is a test seam (the
# same shape as the pi installer's `AGENT_VM_PI_PREFIX`); production uses the
# default.
MANIFEST="${DSH_MANIFEST:-/opt/agent-vm/dsh/package.json}"
PIN=$(jq -r '.dependencies["@deepseek-ai/dsh"]' "$MANIFEST")

if ! command -v dsh >/dev/null 2>&1; then
    echo "  dsh: MISSING — hard sanity failure" >&2
    exit 1
fi

version=$(dsh --version 2>/dev/null || true)

if [ -z "$version" ]; then
    echo "  dsh: empty --version output — hard sanity failure" >&2
    echo "  dsh needs Node >=22.19 ('import.meta.main'); an older Node makes" >&2
    echo "  its CLI exit 0 with no output, so this must fail the build." >&2
    exit 1
fi

# The lockfile pins one exact app version; the running binary must be it.
if [ "$version" != "$PIN" ]; then
    echo "  dsh: installed $version but package.json pins $PIN" >&2
    exit 1
fi

# pnpm is in the same lock and is what `dsh plugin` execs.
if ! pnpm --version >/dev/null 2>&1; then
    echo "  pnpm: MISSING — hard sanity failure ('dsh plugin' would fail)" >&2
    exit 1
fi

echo "  dsh: $version (pnpm $(pnpm --version))"
