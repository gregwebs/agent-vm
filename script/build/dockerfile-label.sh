#!/usr/bin/env bash
# Shared host helper for the tool-layer bump scripts: rewrite exactly one
# `org.agent-vm.version.<key>` LABEL fallback in a recipe Dockerfile.
#
# The fallback is a generated mirror of the committed manifest pin (Docker
# cannot run jq inside a LABEL), so a developer bump has to move it in lockstep
# with the manifest and lock. Callers stage the Dockerfile in a scratch
# directory and publish it only after every check passes; this helper only
# rewrites the one value and fails loudly if the label is not found exactly once.
#
# Usage (source first):
#   set_version_label FILE KEY ARG VALUE
#     FILE   path to the Dockerfile to edit in place
#     KEY    the label suffix, e.g. dsh, pnpm, pi, pi-claude-bridge
#     ARG    the ARG name, e.g. AGENT_VERSION_DSH
#     VALUE  the new exact fallback value
#
# Rewrites `org.agent-vm.version.KEY="${ARG:-<old>}"` to use VALUE. The old
# value is not inspected: the label suffix plus ARG name already identify the
# one authoritative line, and the caller asserts the resulting mirrors against
# the new manifest pins afterwards.
#
# Host tools must work on macOS Bash 3.2: POSIX awk string functions only, no
# GNU-only sed/stat assumptions.
set -euo pipefail

set_version_label() {
    local file="$1" key="$2" arg="$3" value="$4"
    local tmp
    tmp="$(mktemp "${file}.XXXXXX")" || return 1
    if ! awk -v key="$key" -v arg="$arg" -v value="$value" '
        BEGIN {
            prefix = "org.agent-vm.version." key "=\"${" arg ":-"
        }
        {
            start = index($0, prefix)
            if (start > 0) {
                tail = substr($0, start + length(prefix))
                endpos = index(tail, "}\"")
                if (endpos == 0) {
                    print "set_version_label: malformed " key " label" > "/dev/stderr"
                    exit 2
                }
                seen++
                $0 = substr($0, 1, start + length(prefix) - 1) value substr(tail, endpos)
            }
            print
        }
        END {
            if (seen != 1) {
                print "set_version_label: expected exactly one " key " label in " FILENAME ", found " (seen + 0) > "/dev/stderr"
                exit 3
            }
        }
    ' "$file" >"$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$file"
}
