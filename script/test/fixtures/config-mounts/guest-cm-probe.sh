#!/usr/bin/env bash
# Guest-side rows for the config-mounts probe (#394 / ADR-0046, #397 / ADR-0048).
#
# Always `bash`, never `bash -l`: a login shell sources /etc/profile and resets
# PATH (CONTRIBUTING.md). No `set -e` on purpose — one row must not hide the
# next — but every failure is printed as a CM_ line, so a silent pass is
# impossible: the driver compares the whole line.
#
# `CM_ROOT` prefixes every path so the boot-free companion runs these exact
# statements against a host-side layout. It is empty in the guest, where the
# declared guest paths are /cm/ro, /cm/rw and /cm/fork.
set -uo pipefail

root="${CM_ROOT:-}"
probe="$root/cm"

die() {
    printf 'CM_ERROR %s\n' "$*" >&2
    exit 1
}

marker() {
    if [[ -f "$1" ]]; then cat -- "$1"; else printf 'absent'; fi
}

# One write attempt in a subshell, so a refusal cannot abort this script.
attempt() {
    ( printf '%s' "$2" > "$1" ) 2>/dev/null
}

# Read-only must refuse both a new name and an existing file. Reporting one
# verdict keeps the row one line; reporting "allowed" at all is the failure a
# probe that always says "denied" cannot fake.
row_n1() {
    local read write=denied
    read="$(marker "$probe/ro/marker")"
    attempt "$probe/ro/new" x && write=allowed
    attempt "$probe/ro/marker" x && write=allowed
    printf 'CM-N1 read=%s write=%s\n' "$read" "$write"
}

row_n2() {
    local write
    write="$( ( printf '%s' guest-rw > "$probe/rw/marker" ) 2>/dev/null && printf wrote || printf denied )"
    printf 'CM-N2 %s\n' "$write"
}

row_n3a() {
    # Read before writing: the row proves the guest saw the host seed *and* that
    # its own write landed, which is what makes the independence check in
    # CM-N3b meaningful.
    local read write
    read="$(marker "$probe/fork/marker")"
    write="$( ( printf '%s' guest-fork > "$probe/fork/marker" ) 2>/dev/null && printf wrote || printf denied )"
    printf 'CM-N3a read=%s %s\n' "$read" "$write"
}

row_n3b() {
    printf 'CM-N3b read=%s\n' "$(marker "$probe/fork/marker")"
}

# One verdict per mounted tree: every config mount absent, and the project still
# visible. `project=present` is the positive control — the guest ran and could see
# its own project bind, so three "absent" values cannot be a dead guest. The label
# is a parameter so the same statements carry the named-set rows (CM-S1/CM-S3)
# without renaming the #394 row's bytes.
row_absent() {
    local label="$1" name state
    local -a out=()
    for name in ro rw fork; do
        if [[ -e "$probe/$name" ]]; then state=present; else state=absent; fi
        out+=("$name=$state")
    done
    if [[ -f ./project-marker ]]; then state=present; else state=absent; fi
    out+=("project=$state")
    printf '%s %s\n' "$label" "${out[*]}"
}

row_n4() {
    row_absent CM-N4
}

# The named-set row (#397): the same three trees, reached through one selected
# set, plus the concrete access a selection is supposed to grant. The read-only
# tree must refuse both a new name and its existing file, the writable leaf must
# write `set-rw` through to the host, and the fork leaf must read whatever the
# earlier launch left in the copy — never the host's later write.
row_sets() {
    local read write=denied rw fork project
    read="$(marker "$probe/ro/marker")"
    attempt "$probe/ro/new" x && write=allowed
    attempt "$probe/ro/marker" x && write=allowed
    rw="$( ( printf '%s' set-rw > "$probe/rw/marker" ) 2>/dev/null && printf wrote || printf denied )"
    fork="$(marker "$probe/fork/marker")"
    if [[ -f ./project-marker ]]; then project=present; else project=absent; fi
    printf 'CM-S access ro=%s ro-write=%s rw=%s fork=%s project=%s\n' \
        "$read" "$write" "$rw" "$fork" "$project"
}

row_n5() {
    printf 'CM-N5 read=%s\n' "$(marker "$probe/fork/marker")"
}

case "${1:-}" in
    n1) row_n1 ;;
    n2) row_n2 ;;
    n3a) row_n3a ;;
    n3b) row_n3b ;;
    n4) row_n4 ;;
    n5) row_n5 ;;
    # Named sets: the same absent row under its own label, and the access row.
    sets-absent) row_absent CM-S ;;
    sets) row_sets ;;
    # One launch covers the three rows that need the default selection, so the
    # rows share a boot instead of paying for three of them.
    all)
        row_n1
        row_n2
        row_n3a
        ;;
    *) die "usage: $0 all|n1|n2|n3a|n3b|n4|n5|sets|sets-absent" ;;
esac
