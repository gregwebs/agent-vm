#!/usr/bin/env bash
# Launcher half of the Chrome DevTools capability contract (#293). The example
# image and its content checks belong to agent-vm-images
# (script/test/example-layers.sh); this only proves the launcher's paths agree.
# Usage: chrome-example-contract.sh [--root DIR]   (default: this checkout)
# Exit: 0 pass, 1 contract failure, 2 usage.
set -euo pipefail

usage() {
    echo 'usage: chrome-example-contract.sh [--root DIR]' >&2
    exit 2
}

fail() {
    echo "chrome example contract: $*" >&2
    exit 1
}

not_a_directory() { # ROOT_ARG
    echo "chrome example contract: --root $1 is not a directory" >&2
    exit 2
}

root_arg="${BASH_SOURCE[0]%/*}/../.."
if (($#)); then
    [[ $# -eq 2 && "$1" == --root ]] || usage
    root_arg="$2"
fi
# `cd ''` succeeds in bash, so test first. An inherited CDPATH would make cd
# search it and print the resolved directory into ROOT.
[[ -d "$root_arg" ]] || not_a_directory "$root_arg"
ROOT="$(CDPATH='' cd -- "$root_arg" 2>/dev/null && pwd)" || not_a_directory "$root_arg"
cd "$ROOT"

# Mirrored literals; agent-vm-images script/test/example-layers.sh owns the
# image side (CHROME_MARKER, CHROME_WRAPPER). Changing either path is a
# coordinated change in both repositories (agent-vm-images
# docs/image-source-ownership.md).
EXPECTED_MARKER=/etc/agent-vm-capabilities/chrome-devtools-mcp
EXPECTED_WRAPPER=/usr/local/bin/agent-vm-chrome-mcp
# The v0.1.3 image source predates the examples' move into agent-vm-images, so
# at this pin there is nothing to read. The read activates by itself once a
# standard-release adoption advances the gitlink (standard-release-pin.sh).
PRE_MOVE_GITLINK=087f8bad3de624a5dad38f1669e7dea96996371a
DEFAULTS=crates/agent-vm/src/defaults.rs
IMAGES=vendor/agent-vm-images
EXAMPLE="$IMAGES/examples/layers/chrome-devtools"

[[ -f "$DEFAULTS" ]] || fail "$DEFAULTS is missing"
# Guarded: under set -e sed's own status would escape, and GNU sed exits 2 (the
# usage code) on an unreadable file.
marker="$(sed -n 's/^pub const CHROME_MCP_CAPABILITY_PATH: &str = "\([^"]*\)";$/\1/p' "$DEFAULTS")" ||
    fail "cannot read $DEFAULTS"
wrapper="$(sed -n 's/^pub const CHROME_MCP_WRAPPER_PATH: &str = "\([^"]*\)";$/\1/p' "$DEFAULTS")" ||
    fail "cannot read $DEFAULTS"
[[ "$marker" == "$EXPECTED_MARKER" ]] ||
    fail "$DEFAULTS CHROME_MCP_CAPABILITY_PATH is '$marker', expected $EXPECTED_MARKER"
[[ "$wrapper" == "$EXPECTED_WRAPPER" ]] ||
    fail "$DEFAULTS CHROME_MCP_WRAPPER_PATH is '$wrapper', expected $EXPECTED_WRAPPER"

# A present example is checked before the pin is consulted, so a submodule
# checked out past the gitlink is read rather than waved through as deferred.
if [[ ! -e "$IMAGES/.git" ]]; then
    echo "notice: $IMAGES uninitialized; skipping the Chrome example read" >&2
    example_state='example read skipped'
elif [[ -f "$EXAMPLE/Dockerfile" ]]; then
    [[ "$(tail -n 1 "$EXAMPLE/Dockerfile")" == " && : > $marker" ]] ||
        fail "$EXAMPLE/Dockerfile must end with ' && : > $marker'"
    grep -Fxq "COPY --chmod=0755 agent-vm-chrome-mcp $wrapper" "$EXAMPLE/Dockerfile" ||
        fail "$EXAMPLE/Dockerfile lacks the line 'COPY --chmod=0755 agent-vm-chrome-mcp $wrapper'"
    [[ -f "$EXAMPLE/agent-vm-chrome-mcp" ]] || fail "$EXAMPLE/agent-vm-chrome-mcp is missing"
    example_state='submodule example agrees'
else
    entry="$(git ls-files --stage -- "$IMAGES")" || fail "cannot read the $IMAGES gitlink"
    gitlink="$(awk '$1 == "160000" {print $2}' <<<"$entry")"
    [[ "$gitlink" == "$PRE_MOVE_GITLINK" ]] ||
        fail "$IMAGES at ${gitlink:-<no gitlink>} lacks $EXAMPLE/Dockerfile and agent-vm-chrome-mcp"
    echo "notice: $IMAGES gitlink $gitlink (v0.1.3 source) predates the example move; Chrome example read deferred until the pin advances" >&2
    example_state='example read deferred'
fi
echo "Chrome launcher path contract passed ($example_state)"
