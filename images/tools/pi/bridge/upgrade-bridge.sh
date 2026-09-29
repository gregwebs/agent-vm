#!/usr/bin/env bash
# Bump the pinned pi-claude-bridge version: rewrite package.json's pin and
# update package-lock.json. See images/tools/README.md ("The bridge packages")
# and docs/adr/0023-image-owned-pi-extension-packages.md.
#
# Host-side only. The Dockerfile COPYs only package.json and package-lock.json
# from this directory, so this file never reaches the image. Run it as
# `bash upgrade-bridge.sh`: like every file under images/tools/ it is committed
# 0644 (tool_layer.rs's
# embedded_layer_sources_are_committed_without_the_execute_bit).
#
# The lock is updated INCREMENTALLY (the committed lock is the starting point)
# so unrelated transitive pins do not move, and with `--legacy-peer-deps`, which
# the layer's `npm ci` also passes: without it npm installs the bridge's
# @earendil-works peers, a second version-skewed Pi. The update runs in a
# scratch directory and is only copied over the committed files once every
# check below passes, so a failed run leaves the working tree untouched.

set -euo pipefail

PACKAGE=pi-claude-bridge

usage() {
    cat <<EOF
Usage: bash images/tools/pi/bridge/upgrade-bridge.sh [VERSION]

Pin ${PACKAGE} to VERSION, an exact version or a dist-tag (default: the
registry's \`latest\` dist-tag), and update package.json + package-lock.json
beside this script.
EOF
}

case "${1:-}" in
    -h | --help)
        usage
        exit 0
        ;;
esac
if [ $# -gt 1 ]; then
    usage >&2
    exit 2
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Shared prerequisite check and version resolution; see the helper's header for
# why the copy is not inlined. source=/dev/null: shellcheck cannot follow a path
# built from $DIR, and npm-pin.sh is linted on its own.
# shellcheck source=/dev/null
. "$DIR/../../../../script/build/npm-pin.sh"

require_tools jq npm

current=$(jq -r --arg p "$PACKAGE" '.dependencies[$p]' "$DIR/package.json")

version_arg="${1:-}"
version=$(resolve_npm_version "$PACKAGE" "$version_arg")
if [ -z "$version_arg" ]; then
    echo "==> latest ${PACKAGE} is ${version}"
fi

echo "==> pinning ${PACKAGE}: ${current} -> ${version}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Exact pin, never a range (the_bridge_pin_is_exact_and_the_lock_agrees).
jq --arg p "$PACKAGE" --arg v "$version" '.dependencies[$p] = $v' \
    "$DIR/package.json" >"$work/package.json"
cp "$DIR/package-lock.json" "$work/package-lock.json"

echo "==> updating package-lock.json"
(cd "$work" && npm install --ignore-scripts --package-lock-only --no-audit --no-fund \
    --legacy-peer-deps --loglevel=error)

# The tool_layer.rs cargo guards: pins agree, every entry carries integrity (no
# shrinkwrap in this tree, so nothing is refilled by hand), and no package Pi's
# extension loader aliases is installed.
jq -e --arg p "$PACKAGE" --arg v "$version" '
    .packages as $pk
    | ($pk[""].dependencies[$p] == $v)
    and ($pk["node_modules/" + $p].version == $v)
    and ([$pk | to_entries[] | select(.key != "" and (.value.integrity | not))] | length == 0)
' "$work/package-lock.json" >/dev/null || {
    echo "error: the updated lock fails the pin/integrity checks; not writing it" >&2
    exit 1
}
aliased=$(jq -r '.packages | keys[]
    | select(test("@earendil-works|typebox|pi-agent-core|pi-tui|pi-ai"))' "$work/package-lock.json")
if [ -n "$aliased" ]; then
    echo "error: the lock installs packages Pi's extension loader aliases:" >&2
    printf '%s\n' "$aliased" | sed 's/^/         /' >&2
    exit 1
fi

cp "$work/package.json" "$DIR/package.json"
cp "$work/package-lock.json" "$DIR/package-lock.json"

# The bridge declares the image's own Pi as a peer. --legacy-peer-deps is
# mandatory on the install and hides a mismatch, so surface the new range here
# for the reviewer -- information only: the range grammar is npm's, so we do not
# evaluate it, and a mismatch is not a failure.
pi_pin=$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' "$DIR/../package.json")
peer=$(jq -r '.packages["node_modules/pi-claude-bridge"].peerDependencies["@earendil-works/pi-coding-agent"] // empty' \
    "$DIR/package-lock.json")

cat <<EOF
==> pinned ${PACKAGE}@${version}
==> peer @earendil-works/pi-coding-agent: ${peer:-<none>} (image pins ${pi_pin}; check compatibility)
Next:
  cargo test -p agent-vm tool_layer   # lock guards + embedded snapshot
  then rebuild the tool layers -- see images/tools/README.md ("Upgrading a tool")
EOF
