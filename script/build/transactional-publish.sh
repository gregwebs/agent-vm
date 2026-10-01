#!/usr/bin/env bash
# Shared host-only helper: publish staged files transactionally.
#
# Canonical source: script/build/transactional-publish.sh. Sourced by the
# developer bump tools (images/tools/dsh/upgrade-dsh.sh, images/tools/pi/
# upgrade-pi.sh, images/tools/pi/bridge/upgrade-bridge.sh); it never reaches the
# image.
#
# Usage: publish_transactional BACKUP_DIR SRC DEST [SRC DEST ...]
#
# Staging upstream prevents *preparation* failures, not a failure copying the
# final staged files. This helper backs up every existing DEST into BACKUP_DIR,
# then copies each SRC over its DEST. If any copy fails it restores every
# already-published DEST from its backup and returns nonzero, so a partial
# publication cannot leave the manifest, lock and Dockerfile LABEL out of sync.

publish_transactional() {
    local backup_dir=$1
    shift
    if [ "$#" -eq 0 ] || [ $(( $# % 2 )) -ne 0 ]; then
        echo "publish_transactional: usage: publish_transactional BACKUP_DIR SRC DEST [SRC DEST ...]" >&2
        return 2
    fi

    local -a srcs=()
    local -a dests=()
    while [ "$#" -gt 0 ]; do
        srcs+=("$1")
        dests+=("$2")
        shift 2
    done

    mkdir -p "$backup_dir" || return 1

    local i
    for i in "${!srcs[@]}"; do
        if [ -e "${dests[$i]}" ]; then
            cp -p "${dests[$i]}" "$backup_dir/$i" 2>/dev/null || return 1
        fi
    done

    for i in "${!srcs[@]}"; do
        if ! cp "${srcs[$i]}" "${dests[$i]}"; then
            echo "error: failed to publish ${dests[$i]}; restoring already-published files" >&2
            local j
            for ((j = i - 1; j >= 0; j--)); do
                if [ -e "$backup_dir/$j" ]; then
                    cp -p "$backup_dir/$j" "${dests[$j]}" 2>/dev/null || true
                fi
            done
            return 1
        fi
    done
    return 0
}
