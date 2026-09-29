#!/usr/bin/env bash
# Sourced -- never executed -- by script/build/agent-versions.sh and the
# images/tools/*/upgrade-*.sh scripts, which all run `set -euo pipefail`, so
# every upgrade script accepts the same VERSION arguments.

# Exit with the standard message when any named tool is absent.
require_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null || {
            echo "error: $tool is required" >&2
            exit 1
        }
    done
}

# Print the exact version PACKAGE resolves to at WANTED. WANTED is an exact
# version or a dist-tag (`latest`, `next`, ...); empty means `latest`. One
# `npm view` fetch answers both questions, so a dist-tag and an exact version
# are decided locally from the same response: `dist-tags.<name>` first, else
# WANTED must appear in `versions`. (Asking npm for `PKG@WANTED` instead cannot
# tell an unpublished version from an unreachable registry: both exit 1.)
#
# A failed query (offline, DNS, HTTP 5xx, an unknown package) is reported as
# such, never as "not published"; npm's own stderr is left to flow through.
resolve_npm_version() {
    local package="$1" wanted="${2:-}" json out

    [ -n "$wanted" ] || wanted=latest

    if ! json=$(npm view "$package" dist-tags versions --json); then
        echo "error: npm could not query ${package} (registry unreachable?)" >&2
        return 1
    fi
    # npm emits `versions` as a bare string, not a one-element array, when the
    # package has published exactly one version; normalise before matching.
    out=$(printf '%s' "$json" | jq -r --arg w "$wanted" '
        (.versions | if type == "array" then . else [.] end) as $versions
        | .["dist-tags"][$w] // (if $versions | index($w) then $w else empty end)
    ')
    if [ -z "$out" ]; then
        echo "error: ${package}@${wanted} is not a published version" >&2
        return 1
    fi
    printf '%s\n' "$out"
}
