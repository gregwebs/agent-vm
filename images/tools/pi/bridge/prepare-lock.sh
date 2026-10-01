#!/bin/sh
# Prepare the pi-claude-bridge lock for an explicit version slot.
#
# Usage:
#   prepare-lock.sh PREFIX BRIDGE_VERSION [--refresh-lock]
#
# BRIDGE_VERSION is either an exact npm version or empty. Empty means "keep the
# committed pin"; a value equal to the committed pin is treated the same way. In
# that case this script only re-checks the local invariants and exits, leaving
# the committed manifest and lock byte-identical and making NO registry request.
#
# When the slot changes the bridge project is regenerated from its exact
# manifest with `--legacy-peer-deps` (the same flag the layer's `npm ci` passes:
# without it npm installs the bridge's @earendil-works peers, a second
# version-skewed Pi), then the pin/integrity/loader-alias invariants are
# validated before the committed files are replaced.
#
# `--refresh-lock` is the DEVELOPER-ONLY bump path. It keeps the committed lock
# as the starting point so only the changed root (and whatever npm genuinely
# has to move for it) is refreshed, exactly like the dsh recipe and the
# pre-#227 upgrade tool: a build-local override must not silently change the
# retained developer tool's dependency-refresh policy. The ordinary build path
# (no flag) regenerates the separate project from the manifest alone.
#
# PREFIX is the production installation prefix, or -- only in tests -- a
# canonical child of AGENT_VM_FIXTURE_ROOT.
set -eu

usage() {
    echo "usage: prepare-lock.sh PREFIX BRIDGE_VERSION [--refresh-lock]" >&2
}

if [ "$#" -lt 2 ]; then
    usage
    exit 2
fi

PREFIX=$1
BRIDGE_VERSION=$2
shift 2

refresh=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --refresh-lock) refresh=1 ;;
        *)
            usage
            exit 2
            ;;
    esac
    shift
done

PACKAGE=pi-claude-bridge

exact_version() {
    # Require one line first: `grep` is line-oriented, so a multi-line range
    # whose FIRST line (or any line) looks exact -- e.g. "0.7.0\n||\n>=..."
    # -- would otherwise be accepted and handed to npm as a range. Then require
    # the whole value to match the canonical semver grammar, which forbids
    # leading-zero numeric components AND leading-zero numeric prerelease ids.
    [ "$(printf '%s' "$1" | wc -l | tr -d ' ')" -eq 0 ] || return 1
    printf '%s' "$1" |
        grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
}

[ -n "$BRIDGE_VERSION" ] || BRIDGE_VERSION=
if [ -n "$BRIDGE_VERSION" ]; then
    exact_version "$BRIDGE_VERSION" || {
        echo "prepare-lock.sh: not an exact npm version: '$BRIDGE_VERSION'" >&2
        exit 1
    }
fi

[ -d "$PREFIX" ] || {
    echo "prepare-lock.sh: prefix is not a directory: $PREFIX" >&2
    exit 1
}
prefix_phys=$(cd "$PREFIX" && pwd -P)
production_prefix="/opt/agent-vm/pi-packages"
if [ "$prefix_phys" != "$production_prefix" ]; then
    fixture_root="${AGENT_VM_FIXTURE_ROOT:-}"
    [ -n "$fixture_root" ] || {
        echo "prepare-lock.sh: refusing non-production prefix $PREFIX without AGENT_VM_FIXTURE_ROOT" >&2
        exit 1
    }
    [ -d "$fixture_root" ] || {
        echo "prepare-lock.sh: AGENT_VM_FIXTURE_ROOT is not a directory: $fixture_root" >&2
        exit 1
    }
    root_phys=$(cd "$fixture_root" && pwd -P)
    case "$prefix_phys" in
        "$root_phys"/*) ;;
        *)
            echo "prepare-lock.sh: prefix $prefix_phys is outside the fixture root $root_phys" >&2
            exit 1
            ;;
    esac
fi

manifest="$PREFIX/package.json"
lock="$PREFIX/package-lock.json"
[ -f "$manifest" ] || {
    echo "prepare-lock.sh: no committed manifest at $manifest" >&2
    exit 1
}
[ -f "$lock" ] || {
    echo "prepare-lock.sh: no committed lock at $lock" >&2
    exit 1
}

committed=$(jq -r --arg p "$PACKAGE" '.dependencies[$p]' "$manifest")
effective=${BRIDGE_VERSION:-$committed}

# No shrinkwrap anywhere in this tree, so every tarball is npm-authenticated and
# nothing is refilled by hand. A regenerated lock must not install any package
# Pi's extension loader aliases to its own copies.
validate_lock() {
    jq -e --arg p "$PACKAGE" --arg v "$effective" '
        .packages as $pk
        | ($pk[""].dependencies[$p] == $v)
        and ($pk["node_modules/" + $p].version == $v)
        and ([$pk | to_entries[] | select(.key != "" and (.value.integrity | not))] | length == 0)
    ' "$1" >/dev/null || return 1
    aliased=$(jq -r '.packages | keys[]
        | select(test("@earendil-works|typebox|pi-agent-core|pi-tui|pi-ai"))' "$1")
    if [ -n "$aliased" ]; then
        echo "prepare-lock.sh: the lock installs packages Pi's extension loader aliases:" >&2
        printf '%s\n' "$aliased" | sed 's/^/                 /' >&2
        return 1
    fi
    return 0
}

if [ "$effective" = "$committed" ]; then
    validate_lock "$lock" || {
        echo "prepare-lock.sh: the committed bridge lock fails the pin/integrity/layout checks" >&2
        exit 1
    }
    echo "prepare-lock.sh: pi-claude-bridge ${effective} unchanged; committed lock reused"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM HUP

jq --arg p "$PACKAGE" --arg v "$effective" '.dependencies[$p] = $v' \
    "$manifest" >"$work/package.json"

# Developer refresh starts from the committed lock; a build override regenerates
# from the manifest alone.
if [ "$refresh" -eq 1 ]; then
    cp "$lock" "$work/package-lock.json"
fi

echo "prepare-lock.sh: pi-claude-bridge ${committed} -> ${effective}"
(cd "$work" && npm install --ignore-scripts --package-lock-only --no-audit --no-fund \
    --legacy-peer-deps --loglevel=error)

validate_lock "$work/package-lock.json" || {
    echo "prepare-lock.sh: the regenerated bridge lock fails the pin/integrity/layout checks" >&2
    exit 1
}

cp "$work/package.json" "$manifest"
cp "$work/package-lock.json" "$lock"
echo "prepare-lock.sh: wrote the prepared bridge lock"
