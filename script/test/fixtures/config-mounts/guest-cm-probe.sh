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
#
# The tool-mount rows (#396) add `CM_HOME`, which defaults to the real `$HOME`:
# in the guest the Pi fork is mounted at the actual `$HOME/.pi` (the compiled
# generic `.pi` guest link exists either way, so absence rows test that
# directory's *contents*), while the host-only companion points it at a synthetic
# home under its scratch layout.
set -uo pipefail

root="${CM_ROOT:-}"
probe="$root/cm"
cm_home="${CM_HOME:-$HOME}"
pi_home="$cm_home/.pi"

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


# The tool-mount rows (#396). Every one of them reads and writes the *same*
# fixtures as the N/S rows through a different selection route, and reports one
# whole line: a mounted-as-absent topology and a genuinely absent one must not
# print the same thing.

# `<path>` or `absent`, for a whole tree. A symlink counts even when its target
# does not resolve here: a provisioned guest-HOME link dangles on the host (its
# target is the guest's `/agent-vm-state`) and resolves in the guest, so `-e`
# alone would report the same link absent in the boot-free companion.
tree() {
    if [[ -e "$1" || -L "$1" ]]; then printf 'present'; else printf 'absent'; fi
}

# One verdict for a read-only tree: neither a new name nor its existing marker
# may be writable. Reporting "allowed" at all is what a probe that always says
# "denied" cannot fake.
ro_write() {
    local verdict=denied
    attempt "$1/new" x && verdict=allowed
    attempt "$1/marker" x && verdict=allowed
    printf '%s' "$verdict"
}

rw_write() {
    local verdict=denied
    attempt "$1/new" "$2" && verdict=wrote
    printf '%s' "$verdict"
}

# CM-T1: the `plain` tool declares nothing and references nothing.
row_tool_plain() {
    local project
    if [[ -f ./project-marker ]]; then project=present; else project=absent; fi
    printf 'CM-T1 agent=%s skills=%s readonly=%s pi=%s project=%s\n' \
        "$(tree "$probe/tool/agent")" "$(tree "$probe/tool/agent/skills")" \
        "$(tree "$probe/tool/readonly")" "$(marker "$pi_home/marker")" "$project"
}

# CM-T2: the launched `claude` tool's own set — parent writable, both read-only
# trees refusing — and no Pi fork.
row_tool_claude() {
    local agent=denied skills ro
    agent="$(rw_write "$probe/tool/agent" claude-note)"
    skills="$(ro_write "$probe/tool/agent/skills")"
    ro="$(ro_write "$probe/tool/readonly")"
    printf 'CM-T2 agent=%s agent-write=%s skills=%s skills-write=%s readonly=%s readonly-write=%s pi=%s\n' \
        "$(marker "$probe/tool/agent/marker")" "$agent" \
        "$(marker "$probe/tool/agent/skills/marker")" "$skills" \
        "$(marker "$probe/tool/readonly/marker")" "$ro" \
        "$(marker "$pi_home/marker")"
}

# CM-T3: the launched `pi` inherits the agent topology through `tools` and adds
# the fork. The Pi marker is read *before* the write, so `pi-seed` and the
# guest's own `pi-guest` are distinguishable; the protected synthetic files must
# be absent from the committed copy.
row_tool_pi() {
    local pi write auth models guest
    pi="$(marker "$pi_home/marker")"
    write="$( ( printf '%s' pi-guest > "$pi_home/marker" ) 2>/dev/null && printf wrote || printf denied )"
    guest="$( ( printf '%s' guest-only > "$pi_home/guest-only" ) 2>/dev/null && printf wrote || printf denied )"
    if [[ -f "$pi_home/agent/auth.json" ]]; then auth=present; else auth=absent; fi
    if [[ -f "$pi_home/agent/models.json" ]]; then models=present; else models=absent; fi
    printf 'CM-T3 agent=%s skills=%s readonly=%s pi=%s pi-write=%s auth=%s models=%s guest-file=%s\n' \
        "$(marker "$probe/tool/agent/marker")" \
        "$(marker "$probe/tool/agent/skills/marker")" \
        "$(marker "$probe/tool/readonly/marker")" \
        "$pi" "$write" "$auth" "$models" "$guest"
}

# CM-T4: after a host-only mutation of its source, the inherited fork still shows
# the guest's own write and its own file.
row_tool_bridge() {
    printf 'CM-T4 pi=%s guest-file=%s\n' \
        "$(marker "$pi_home/marker")" "$(tree "$pi_home/guest-only")"
}

# CM-T5: the declared `shell`'s omitted `tools` wildcard reaches the fork and the
# agent topology. It reads only, so the later rows observe the same fork content.
row_tool_shell() {
    local project
    if [[ -f ./project-marker ]]; then project=present; else project=absent; fi
    printf 'CM-T5 agent=%s skills=%s ro-write=%s pi=%s project=%s\n' \
        "$(marker "$probe/tool/agent/marker")" \
        "$(marker "$probe/tool/agent/skills/marker")" \
        "$(ro_write "$probe/tool/agent/skills")" \
        "$(marker "$pi_home/marker")" "$project"
}

# CM-T6: the same declared shell with `tools = []`. Only its own list and the
# user-wide default survive.
row_tool_shell_own() {
    printf 'CM-T6 agent=%s skills=%s readonly=%s pi=%s shell-own=%s shell-own-write=%s default=%s default-write=%s\n' \
        "$(tree "$probe/tool/agent")" "$(tree "$probe/tool/agent/skills")" \
        "$(tree "$probe/tool/readonly")" "$(marker "$pi_home/marker")" \
        "$(marker "$probe/tool/shell-own/marker")" "$(ro_write "$probe/tool/shell-own")" \
        "$(marker "$probe/tool/default/marker")" "$(ro_write "$probe/tool/default")"
}

# CM-T7: no declared shell at all, so the built-in fallback runs in its own scope:
# no user tool is referenced, but the user-wide default still applies.
row_tool_shell_fallback() {
    local project
    if [[ -f ./project-marker ]]; then project=present; else project=absent; fi
    printf 'CM-T7 agent=%s skills=%s pi=%s shell-own=%s default=%s default-write=%s project=%s\n' \
        "$(tree "$probe/tool/agent")" "$(tree "$probe/tool/agent/skills")" \
        "$(marker "$pi_home/marker")" "$(tree "$probe/tool/shell-own")" \
        "$(marker "$probe/tool/default/marker")" "$(ro_write "$probe/tool/default")" "$project"
}

# CM-T8: `--no-config-mounts` removes the defaults, the declaring tool's own list
# and every inherited list, on both a tool launch and the declared shell.
row_tool_optout() {
    local project
    if [[ -f ./project-marker ]]; then project=present; else project=absent; fi
    printf 'CM-T8 agent=%s skills=%s readonly=%s pi=%s shell-own=%s default=%s project=%s\n' \
        "$(tree "$probe/tool/agent")" "$(tree "$probe/tool/agent/skills")" \
        "$(tree "$probe/tool/readonly")" "$(marker "$pi_home/marker")" \
        "$(tree "$probe/tool/shell-own")" "$(tree "$probe/tool/default")" "$project"
}

# CM-T9: an explicit `--mount agent` returns exactly the agent topology — both
# read-only trees included, not only the nested one — and nothing about the other
# automatic sources. Selecting a set named like a tool provisions no tool: the
# same-named tool's own leaf and its `persist` link are read here, and CM-T9-control
# shows both present when that tool is the launch instead.
row_tool_set_explicit() {
    printf 'CM-T9 agent=%s agent-write=%s skills=%s ro-write=%s readonly=%s readonly-write=%s pi=%s default=%s agent-tool=%s agent-tool-state=%s\n' \
        "$(marker "$probe/tool/agent/marker")" \
        "$(rw_write "$probe/tool/agent" explicit-note)" \
        "$(marker "$probe/tool/agent/skills/marker")" \
        "$(ro_write "$probe/tool/agent/skills")" \
        "$(marker "$probe/tool/readonly/marker")" \
        "$(ro_write "$probe/tool/readonly")" \
        "$(marker "$pi_home/marker")" "$(tree "$probe/tool/default")" \
        "$(tree "$probe/tool/agent-tool")" "$(tree "$cm_home/agent-tool-state")"
}

# CM-T9-control: the positive control for the two observables above. The tool named
# exactly like the `agent` set *is* this launch, so its own read-only leaf and its
# declared `persist` link both have to appear; the same statements printing
# `absent` under `--mount agent` is then a real measurement.
row_tool_agent_name() {
    printf 'CM-T9-control agent-tool=%s agent-tool-state=%s\n' \
        "$(marker "$probe/tool/agent-tool/marker")" "$(tree "$cm_home/agent-tool-state")"
}

# CM-T10/CM-T11: the same Pi declaration selected explicitly, as a default and
# through a nested set reads the reused fork and nothing else.
row_tool_pi_only() {
    local label="$1"
    printf '%s pi=%s guest-file=%s agent=%s\n' "$label" \
        "$(marker "$pi_home/marker")" "$(tree "$pi_home/guest-only")" \
        "$(marker "$probe/tool/agent/marker")"
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
    # Tool mounts (#396): one phase per row, because each row is a different
    # selection route and its own launch.
    tool-plain) row_tool_plain ;;
    tool-claude) row_tool_claude ;;
    tool-pi) row_tool_pi ;;
    tool-bridge) row_tool_bridge ;;
    tool-shell) row_tool_shell ;;
    tool-shell-own) row_tool_shell_own ;;
    tool-shell-fallback) row_tool_shell_fallback ;;
    tool-optout) row_tool_optout ;;
    tool-set-explicit) row_tool_set_explicit ;;
    tool-agent-name) row_tool_agent_name ;;
    tool-pi-explicit) row_tool_pi_only CM-T10 ;;
    tool-fork) row_tool_pi_only CM-T11 ;;
    # One launch covers the three rows that need the default selection, so the
    # rows share a boot instead of paying for three of them.
    all)
        row_n1
        row_n2
        row_n3a
        ;;
    *) die "usage: $0 all|n1|n2|n3a|n3b|n4|n5|sets|sets-absent|tool-plain|tool-claude|tool-pi|tool-bridge|tool-shell|tool-shell-own|tool-shell-fallback|tool-optout|tool-set-explicit|tool-agent-name|tool-pi-explicit|tool-fork" ;;
esac
