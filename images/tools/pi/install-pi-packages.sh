#!/bin/sh
# Installs the pinned Pi extension packages into the Pi packages prefix from the
# committed (or prepared) lockfile. See images/tools/README.md and
# docs/adr/0023-image-owned-pi-extension-packages.md.
#
# Runs inside the recipe-contract envelope (run-install.sh), so
# AGENT_VM_TRANSPORT_RECEIPT names a fresh private receipt and the owning hook
# can soften only a positively classified `npm ci` transport failure. The result
# is recorded SEPARATELY from Pi's: a working Pi with a transport-absent bridge
# is a distinct degraded state (`/opt/agent-vm/install-status/pi-claude-bridge`
# = `absent-transport CODE`), never healthy and never `installed`.
#
# No bespoke integrity re-verification here, deliberately: install-pi.sh needs
# one ONLY because npm ignores our lock for Pi's shrinkwrapped subtree. This
# tree has no shrinkwrap anywhere in its chain, so `npm ci` authenticates every
# tarball itself -- and tests/image_sources.rs::every_bridge_locked_package_carries_integrity
# fails the build if a regenerated lock ever loses that property.
#
# `--legacy-peer-deps` is not optional, on this `npm ci` and on the committed
# lock that generated it: without it npm tries to solve the bridge's
# `@earendil-works`/`typebox` peer ranges and installs a SECOND, version-skewed
# Pi under this tree (Pi's own loader aliases those imports, so they must not be
# installed). `--omit=optional` drops the Claude Agent SDK's platform packages,
# each of which carries a whole second Claude Code binary -- the guest-platform
# size is in docs/adr/0023-image-owned-pi-extension-packages.md. The image
# already ships one at /opt/agent/.local/bin/claude. `--ignore-scripts` matches
# install-pi.sh: no upstream lifecycle script runs during the build.
set -eu

PREFIX="${AGENT_VM_PI_PACKAGES_PREFIX:-/opt/agent-vm/pi-packages}"
CONTRACT="${AGENT_VM_CONTRACT_DIR:-/tmp/recipe-contract}"
PREPARE_LOCK="${AGENT_VM_PREPARE_LOCK:-/tmp/prepare-bridge-lock.sh}"
BRIDGE_VERSION="${AGENT_VM_VERSION_PI_CLAUDE_BRIDGE:-}"
soft_fail="${AGENT_INSTALL_SOFT_FAIL:-}"
receipt="${AGENT_VM_TRANSPORT_RECEIPT:-}"
status_dir="${AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}"

# Validate the install root before the `rm -rf` below. In production it is the
# fixed path the wrapper loads the bridge from; in tests it must be a canonical
# child of the fixture root, so a bad seam cannot delete a real tree.
[ -d "$PREFIX" ] || {
    echo "install-pi-packages.sh: prefix is not a directory: $PREFIX" >&2
    exit 1
}
prefix_phys=$(cd "$PREFIX" && pwd -P)
production_prefix="/opt/agent-vm/pi-packages"
if [ "$prefix_phys" != "$production_prefix" ]; then
    fixture_root="${AGENT_VM_FIXTURE_ROOT:-}"
    [ -n "$fixture_root" ] || {
        echo "install-pi-packages.sh: refusing non-production prefix $PREFIX without AGENT_VM_FIXTURE_ROOT" >&2
        exit 1
    }
    [ -d "$fixture_root" ] || {
        echo "install-pi-packages.sh: AGENT_VM_FIXTURE_ROOT is not a directory: $fixture_root" >&2
        exit 1
    }
    root_phys=$(cd "$fixture_root" && pwd -P)
    case "$prefix_phys" in
        "$root_phys"/*) ;;
        *)
            echo "install-pi-packages.sh: prefix $prefix_phys is outside the fixture root $root_phys" >&2
            exit 1
            ;;
    esac
fi

[ -r "$PREPARE_LOCK" ] || {
    echo "install-pi-packages.sh: prepare-lock.sh not found at $PREPARE_LOCK" >&2
    exit 1
}
sh "$PREPARE_LOCK" "$PREFIX" "$BRIDGE_VERSION"

work=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$work'" EXIT INT TERM HUP

rc=0
(cd "$PREFIX" && sh "$CONTRACT/run-npm.sh" "$work/npm-ci.json" -- npm ci --ignore-scripts --omit=optional --legacy-peer-deps --no-audit --no-fund) || rc=$?
if [ "$rc" -ne 0 ]; then
    message="==> pi-packages: npm ci FAILED"
    if [ "$rc" -eq 75 ] && [ -n "$receipt" ] &&
        grep -Eq '^transport npm [A-Za-z0-9_]+$' "$receipt"; then
        if [ -n "$soft_fail" ]; then
            rm -rf "$PREFIX"
            mkdir -p "$status_dir"
            printf 'absent-transport %s\n' "$(awk '{print $3}' "$receipt")" >"$status_dir/pi-claude-bridge"
            echo "${message} (soft-fail mode; image will ship without pi-claude-bridge)"
            exit 0
        fi
    fi
    rm -rf "$PREFIX"
    echo "${message}" >&2
    exit 1
fi
rm -rf "${HOME:-/root}/.npm"
chmod -R a+rX "$PREFIX"
