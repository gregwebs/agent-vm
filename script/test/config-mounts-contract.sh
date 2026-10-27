#!/usr/bin/env bash
# Boot-free host controls for the config-mounts evidence (#394 / ADR-0046,
# #397 / ADR-0048).
#
# These are host-only controls, never native VM evidence: no VM, no agent-vm
# launch and no image. They run the *actual* guest probe the native harness
# copies into the owned project, against a synthetic layout on this filesystem,
# including negative controls that a probe which always answers the same way
# cannot pass. They then run the *actual* live wrapper through its preflight
# refusals and prove that no native scratch is allocated before provenance is
# accepted. Finally they prove the `ci-contracts.sh` guard entries are load
# bearing by removing each one in a throwaway copy.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT_DIR="$REPO_ROOT/script/test"
FIXTURES="$SCRIPT_DIR/fixtures/config-mounts"
PROBE="$FIXTURES/guest-cm-probe.sh"
LIVE="$SCRIPT_DIR/config-mounts-live.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/avm-cmctl.XXXXXX")"
# A read-only fixture directory cannot be removed until it is writable again.
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

# --- Probe rows against a host-side layout -----------------------------------
# The probe's CM_ROOT prefix is what makes the guest statements runnable here;
# in the guest it is empty and the paths are the declared /cm/* ones.
layout="$work/layout"
mkdir -p "$layout/cm/ro" "$layout/cm/rw" "$layout/cm/fork"
printf 'seed-ro' > "$layout/cm/ro/marker"
printf 'seed-rw' > "$layout/cm/rw/marker"
printf 'seed-fork' > "$layout/cm/fork/marker"
# A read-only bind is a read-only *filesystem*: neither the directory nor the
# file inside it accepts a write. 0555 alone would leave the existing marker
# writable at its own mode, which is not what the guest row measures.
chmod 0444 "$layout/cm/ro/marker"
chmod 0555 "$layout/cm/ro"
chmod 0755 "$layout/cm/rw" "$layout/cm/fork"

project="$work/proj"
mkdir -p "$project"
printf 'project\n' > "$project/project-marker"

run_probe() {
    local root="$1" phase="$2"
    shift 2
    ( cd "${PROBE_CWD:-$project}" && CM_ROOT="$root" bash "$PROBE" "$phase" "$@" )
}

is_root=false
if [[ "$(id -u)" -eq 0 ]]; then
    is_root=true
fi

if [[ "$is_root" == true ]]; then
    # Mode 0555 does not deny writes to uid 0, so the read-only row cannot be
    # exercised: say so instead of claiming it ran.
    echo 'NOT RUN CM-N1 read-only control: running as root, mode 0555 does not deny writes'
else
    out="$(run_probe "$layout" n1)"
    [[ "$out" == 'CM-N1 read=seed-ro write=denied' ]] ||
        fail "N1 probe did not report a refused write on a 0555 tree: $out"
    # Negative control: a probe that always says "denied" must fail here.
    chmod 0644 "$layout/cm/ro/marker"
    chmod 0755 "$layout/cm/ro"
    out="$(run_probe "$layout" n1)"
    [[ "$out" == 'CM-N1 read=seed-ro write=allowed' ]] ||
        fail "N1 probe did not report an allowed write on a writable tree: $out"
    # The control overwrote the marker; restore the fixture before the rows
    # that read it, and leave no file behind.
    rm -f "$layout/cm/ro/new"
    printf 'seed-ro' > "$layout/cm/ro/marker"
    chmod 0444 "$layout/cm/ro/marker"
    chmod 0555 "$layout/cm/ro"
fi

out="$(run_probe "$layout" n2)"
[[ "$out" == 'CM-N2 wrote' ]] || fail "N2 probe did not report its write: $out"
[[ "$(cat "$layout/cm/rw/marker")" == 'guest-rw' ]] ||
    fail 'N2 control did not change the writable fixture'

out="$(run_probe "$layout" n3a)"
[[ "$out" == 'CM-N3a read=seed-fork wrote' ]] || fail "N3a probe output: $out"
[[ "$(cat "$layout/cm/fork/marker")" == 'guest-fork' ]] ||
    fail 'N3a control did not write the fork fixture'
out="$(run_probe "$layout" n3b)"
[[ "$out" == 'CM-N3b read=guest-fork' ]] || fail "N3b probe output: $out"

# Negative control: a missing fork marker must never read as the seed.
rm "$layout/cm/fork/marker"
out="$(run_probe "$layout" n3b)"
[[ "$out" == 'CM-N3b read=absent' ]] ||
    fail "N3b probe invented a value for a missing marker: $out"

# The opt-out row: nothing mounted under the root, project still visible.
empty="$work/empty"
mkdir -p "$empty"
out="$(run_probe "$empty" n4)"
[[ "$out" == 'CM-N4 ro=absent rw=absent fork=absent project=present' ]] ||
    fail "N4 probe output: $out"
# Positive control for the same row: a layout that does hold the mounts.
mkdir -p "$work/full/cm/ro"
out="$(run_probe "$work/full" n4)"
[[ "$out" == 'CM-N4 ro=present rw=absent fork=absent project=present' ]] ||
    fail "N4 probe did not see a present mount: $out"

out="$(run_probe "$layout" n5)"
[[ "$out" == 'CM-N5 read=absent' ]] || fail "N5 probe output: $out"

# --- Named-mount-set rows (#397) --------------------------------------------
# The probe statements are the native ones; only the layout is synthetic. The
# N3a control above wrote `guest-fork` and the N3b negative control removed it, so
# restore the fork marker before the set rows read it.
printf 'guest-fork' > "$layout/cm/fork/marker"
chmod 0644 "$layout/cm/fork/marker"
# The probe's own write is what the rw assertion below checks, so start from the
# seed: a retained `set-rw` from an earlier run must not pass for a write.
printf 'seed-rw' > "$layout/cm/rw/marker"

# Two assertions for the row, so the permission-only half can be stated with the
# verdict this host can actually produce while the rest — the exact seed, the rw
# write reaching the host, the fork copy and the project control — is required in
# every case.
assert_sets_line() {
    local out="$1" ro_write="$2"
    [[ "$out" == "CM-S access ro=seed-ro ro-write=$ro_write rw=wrote fork=guest-fork project=present" ]] ||
        fail "S probe output (ro-write=$ro_write expected): $out"
}

assert_sets_rw() {
    [[ "$(cat "$layout/cm/rw/marker")" == 'set-rw' ]] ||
        fail 'S control did not write the set rw marker through'
}

# Restore the read-only fixture after a control that may have written through it:
# make the tree writable first (the directory has to accept a create/rename for
# the seed rewrite), reset the bytes, and put the modes back. `cm/ro/new` is the
# probe's own write target, so remove it under every uid.
restore_ro_fixture() {
    chmod 0755 "$layout/cm/ro"
    rm -f "$layout/cm/ro/new" "$layout/cm/ro/marker"
    printf 'seed-ro' > "$layout/cm/ro/marker"
    chmod 0444 "$layout/cm/ro/marker"
    chmod 0555 "$layout/cm/ro"
}

# Branch coverage for the assertion itself, so both uid paths run the same check:
# a line with the wrong verdict must be refused, whichever verdict this host can
# produce.
# (Each call is a subshell: `fail` exits, and this is the control for a refusal.)
if ! ( assert_sets_line 'CM-S access ro=seed-ro ro-write=denied rw=wrote fork=guest-fork project=present' denied >/dev/null 2>&1 ); then
    fail 'S row assertion rejected the denied line'
fi
if ! ( assert_sets_line 'CM-S access ro=seed-ro ro-write=allowed rw=wrote fork=guest-fork project=present' allowed >/dev/null 2>&1 ); then
    fail 'S row assertion rejected the allowed line'
fi
if ( assert_sets_line 'CM-S access ro=seed-ro ro-write=denied rw=wrote fork=guest-fork project=present' allowed >/dev/null 2>&1 ); then
    fail 'S row assertion accepted a line with the wrong read-only verdict'
fi

# The read-only verdict this host can actually produce, computed once from
# `is_root` so every row that reports it requires exactly that value — `denied` on
# a permission-enforcing uid, `allowed` under uid 0, where 0555 does not deny —
# and never "either".
if [[ "$is_root" == true ]]; then
    expected_ro_write=allowed
else
    expected_ro_write=denied
fi

if [[ "$is_root" == true ]]; then
    # uid 0 writes a 0555/0444 tree, so the permission-only half of this row
    # cannot be exercised: say so, and keep the rest of the row under test.
    echo 'NOT RUN CM-S read-only control: running as root, mode 0555 does not deny writes'
    out="$(run_probe "$layout" sets)"
    assert_sets_line "$out" "$expected_ro_write"
    assert_sets_rw
    # The allowed write may have replaced the marker; restore the seed bytes and
    # leave no new file, exactly as the nonroot branch does, so the later rows and
    # the "restored after every allowed-write control" claim both hold.
    restore_ro_fixture
else
    out="$(run_probe "$layout" sets)"
    assert_sets_line "$out" "$expected_ro_write"
    assert_sets_rw
    # Negative control for the read-only half: a *writable* "ro" tree must report
    # `allowed`, so a probe that always answers "denied" cannot pass this row.
    chmod 0755 "$layout/cm/ro"
    chmod 0644 "$layout/cm/ro/marker"
    out="$(run_probe "$layout" sets)"
    assert_sets_line "$out" allowed
    # Restore the fixture bytes the allowed write changed, and leave no new file.
    restore_ro_fixture
fi

# Negative control for the fork half: a missing marker must never read as a
# value, and the row must still render. A directory named `marker` is "not a
# regular file" under any uid, so this control runs everywhere. The read-only
# verdict is still required to be exactly this host's, not either of the two.
rm "$layout/cm/fork/marker"
mkdir "$layout/cm/fork/marker"
out="$(run_probe "$layout" sets)"
expected_missing_fork="CM-S access ro=seed-ro ro-write=$expected_ro_write rw=wrote fork=absent project=present"
[[ "$out" == "$expected_missing_fork" ]] ||
    fail "S probe invented a fork value for a missing marker: $out"
rmdir "$layout/cm/fork/marker"
printf 'guest-fork' > "$layout/cm/fork/marker"
# Under uid 0 that row's write was allowed too; restore it here as well so
# "restored after every allowed-write control" is true without exception.
restore_ro_fixture

# The definitions-only row reuses the absent verdict under its own label.
out="$(run_probe "$empty" sets-absent)"
[[ "$out" == 'CM-S ro=absent rw=absent fork=absent project=present' ]] ||
    fail "sets-absent probe output: $out"
out="$(run_probe "$work/full" sets-absent)"
[[ "$out" == 'CM-S ro=present rw=absent fork=absent project=present' ]] ||
    fail "sets-absent probe did not see a present mount: $out"

# An unknown phase must fail rather than print nothing (a silent pass).
if run_probe "$layout" bogus >/dev/null 2>&1; then
    fail 'the probe accepted an unknown phase'
fi
echo 'probe controls passed (rows, positive and negative controls; no VM)'

# --- Tool-mount probe rows (#396) -------------------------------------------
# The same actual probe statements against a synthetic tool-mount topology: an
# agent parent with a read-only child, a second read-only tree, a declared
# shell's own leaf, a user-wide default and a Pi home whose protected files are
# sentinels. No VM, no agent-vm launch and no image: these controls prove the
# probe can tell a mounted topology from an absent one, that a fork copy differs
# from its source, and that a wrong whole line is refused.
toolroot="$work/tool"
toolhome="$work/toolhome"
forkhome="$work/forkhome"
project="$work/proj"

# A read-only tree: a 0555 directory with a 0444 marker. `seed_ro` is also what
# restores one after a control that let a write through (uid 0, or the negative
# control that makes the tree writable on purpose).
seed_ro() {
    local path="$1" value="$2"
    mkdir -p "$path"
    chmod 0755 "$path"
    rm -f "$path/new" "$path/marker"
    printf '%s' "$value" > "$path/marker"
    chmod 0444 "$path/marker"
    chmod 0555 "$path"
}

# A writable tree with its marker.
seed_rw() {
    local path="$1" value="$2"
    mkdir -p "$path"
    chmod 0755 "$path"
    rm -f "$path/new" "$path/marker"
    printf '%s' "$value" > "$path/marker"
    chmod 0644 "$path/marker"
}

# The full agent topology: a writable parent with a read-only child, plus the
# separate read-only directory and the declared shell's own leaf and default.
seed_agent_topology() {
    local root="$1"
    seed_rw "$root/cm/tool/agent" 'agent-seed'
    seed_ro "$root/cm/tool/agent/skills" 'skills-seed'
    seed_ro "$root/cm/tool/readonly" 'readonly-seed'
}

# The host-side Pi *source* keeps its protected files; a fork *copy* has neither
# and carries its own marker, exactly like the committed directory.
mkdir -p "$toolhome/.pi/agent"
printf 'pi-seed' > "$toolhome/.pi/marker"
printf '{"synthetic": "pi-auth"}' > "$toolhome/.pi/agent/auth.json"
printf '{"synthetic": "pi-models"}' > "$toolhome/.pi/agent/models.json"
mkdir -p "$forkhome/.pi/agent"
printf 'pi-seed' > "$forkhome/.pi/marker"

# The verdict this host can actually produce for a 0555/0444 tree: `denied` on a
# permission-enforcing uid, `allowed` under uid 0, where mode bits do not deny
# writes. Never "either".
tool_ro_write=denied
if [[ "$is_root" == true ]]; then
    tool_ro_write=allowed
    echo 'NOT RUN CM-T2/CM-T5/CM-T6/CM-T7 write-denial controls: running as root, mode 0555 does not deny writes'
fi

run_tool_probe() {
    local root="$1" home="$2" phase="$3"
    ( cd "$project" && CM_ROOT="$root" CM_HOME="$home" bash "$PROBE" "$phase" )
}

expect_tool_line() {
    local label="$1" expected="$2" actual="$3"
    [[ "$actual" == "$expected" ]] || fail "$label probe output: $actual"
}

refuse_tool_line() {
    local label="$1" expected="$2" actual="$3"
    [[ "$actual" != "$expected" ]] || fail "$label control accepted a wrong line: $actual"
}

# T1: nothing selected. The positive twin runs the same statements against the
# topology, and the Pi half is proven selective by a home that has the marker.
empty="$work/empty"
mkdir -p "$empty"
seed_agent_topology "$toolroot"
expect_tool_line T1 'CM-T1 agent=absent skills=absent readonly=absent pi=absent project=present' \
    "$(run_tool_probe "$empty" "$empty" tool-plain)"
expect_tool_line T1-positive 'CM-T1 agent=present skills=present readonly=present pi=pi-seed project=present' \
    "$(run_tool_probe "$toolroot" "$toolhome" tool-plain)"

# T2: the writable parent accepts a write; both read-only trees refuse it.
seed_agent_topology "$toolroot"
t2="CM-T2 agent=agent-seed agent-write=wrote skills=skills-seed skills-write=$tool_ro_write readonly=readonly-seed readonly-write=$tool_ro_write pi=absent"
expect_tool_line T2 "$t2" "$(run_tool_probe "$toolroot" "$empty" tool-claude)"
[[ "$(cat "$toolroot/cm/tool/agent/new")" == 'claude-note' ]] ||
    fail 'T2 control: the writable parent write did not reach the host'
if [[ "$is_root" != true ]]; then
    # Negative control for the read-only half: a writable tree must report
    # `allowed`, so a probe that always answers "denied" cannot pass this row.
    chmod 0755 "$toolroot/cm/tool/agent/skills"
    chmod 0644 "$toolroot/cm/tool/agent/skills/marker"
    refuse_tool_line T2-readonly "$t2" \
        "$(run_tool_probe "$toolroot" "$empty" tool-claude)"
fi

# T3: the fork copy's own marker and guest-only file, protected files absent. The
# host source is the control: against it the sentinels are present.
seed_agent_topology "$toolroot"
t3="CM-T3 agent=agent-seed skills=skills-seed readonly=readonly-seed pi=pi-seed pi-write=wrote auth=absent models=absent guest-file=wrote"
expect_tool_line T3 "$t3" "$(run_tool_probe "$toolroot" "$forkhome" tool-pi)"
[[ "$(cat "$forkhome/.pi/marker")" == 'pi-guest' ]] ||
    fail 'T3 control: the guest write did not land in the fork copy'
[[ -f "$forkhome/.pi/guest-only" ]] ||
    fail 'T3 control: the guest-only file was not created'
[[ "$(cat "$toolhome/.pi/marker")" == 'pi-seed' ]] ||
    fail 'T3 control: the host Pi source was modified'
refuse_tool_line T3-sentinels "$t3" "$(run_tool_probe "$toolroot" "$toolhome" tool-pi)"

# T4: the inherited fork reads its own copy. A marker still holding the seed is a
# fork-read mismatch and must be refused.
printf 'pi-guest' > "$forkhome/.pi/marker"
printf 'guest-only' > "$forkhome/.pi/guest-only"
t4='CM-T4 pi=pi-guest guest-file=present'
expect_tool_line T4 "$t4" "$(run_tool_probe "$empty" "$forkhome" tool-bridge)"
printf 'pi-seed' > "$forkhome/.pi/marker"
refuse_tool_line T4-mismatch "$t4" "$(run_tool_probe "$empty" "$forkhome" tool-bridge)"
printf 'pi-guest' > "$forkhome/.pi/marker"

# T5: the declared shell's omitted `tools` wildcard.
seed_agent_topology "$toolroot"
expect_tool_line T5 "CM-T5 agent=agent-seed skills=skills-seed ro-write=$tool_ro_write pi=pi-guest project=present" \
    "$(run_tool_probe "$toolroot" "$forkhome" tool-shell)"

# T6: inheritance switched off; the shell's own leaf and the default remain. This
# root holds *only* those two, so the agent paths are genuinely absent.
t6root="$work/t6root"
seed_ro "$t6root/cm/tool/shell-own" 'shell-own'
seed_ro "$t6root/cm/tool/default" 'default'
t6="CM-T6 agent=absent skills=absent readonly=absent pi=absent shell-own=shell-own shell-own-write=$tool_ro_write default=default default-write=$tool_ro_write"
expect_tool_line T6 "$t6" "$(run_tool_probe "$t6root" "$empty" tool-shell-own)"
if [[ "$is_root" != true ]]; then
    chmod 0755 "$t6root/cm/tool/default"
    chmod 0644 "$t6root/cm/tool/default/marker"
    refuse_tool_line T6-default "$t6" "$(run_tool_probe "$t6root" "$empty" tool-shell-own)"
fi

# T7: the fallback sees no user tool, but the user-wide default stays.
t7root="$work/t7root"
seed_ro "$t7root/cm/tool/default" 'default'
expect_tool_line T7 "CM-T7 agent=absent skills=absent pi=absent shell-own=absent default=default default-write=$tool_ro_write project=present" \
    "$(run_tool_probe "$t7root" "$empty" tool-shell-fallback)"

# T8: the fully suppressed launch.
expect_tool_line T8 'CM-T8 agent=absent skills=absent readonly=absent pi=absent shell-own=absent default=absent project=present' \
    "$(run_tool_probe "$empty" "$empty" tool-optout)"

# T9: the explicit set returns the agent topology only — both read-only trees —
# and provisions no tool. This root holds none of the same-named tool's own
# observables, so both halves have to read `absent`.
t9root="$work/t9root"
seed_agent_topology "$t9root"
t9_prefix="CM-T9 agent=agent-seed agent-write=wrote skills=skills-seed ro-write=$tool_ro_write readonly=readonly-seed readonly-write=$tool_ro_write pi=absent default=absent"
t9="$t9_prefix agent-tool=absent agent-tool-state=absent"
expect_tool_line T9 "$t9" "$(run_tool_probe "$t9root" "$empty" tool-set-explicit)"
[[ "$(cat "$t9root/cm/tool/agent/new")" == 'explicit-note' ]] ||
    fail 'T9 control: the set selection did not write the parent through'

# Negative controls for the two same-named-tool observations. Each twin keeps the
# ordinary T9 topology, so all eight pre-existing fields still read exactly as T9
# requires and only the observation under test differs. A probe that hard-codes
# either `absent` therefore still prints the whole T9 line and is refused here.
t9leaf="$work/t9leaf"
seed_agent_topology "$t9leaf"
seed_ro "$t9leaf/cm/tool/agent-tool" 'agent-tool-seed'
mkdir -p "$t9leaf/home"
expect_tool_line T9-leaf-present "$t9_prefix agent-tool=present agent-tool-state=absent" \
    "$(run_tool_probe "$t9leaf" "$t9leaf/home" tool-set-explicit)"

t9link="$work/t9link"
seed_agent_topology "$t9link"
mkdir -p "$t9link/home"
ln -s /agent-vm-state/persist/agent-tool-state "$t9link/home/agent-tool-state"
expect_tool_line T9-link-present "$t9_prefix agent-tool=absent agent-tool-state=present" \
    "$(run_tool_probe "$t9link" "$t9link/home" tool-set-explicit)"

# Both observables present at once, on the root the CM-T9-control row below reuses.
t9control="$work/t9control"
seed_agent_topology "$t9control"
seed_ro "$t9control/cm/tool/agent-tool" 'agent-tool-seed'
mkdir -p "$t9control/home"
ln -s /agent-vm-state/persist/agent-tool-state "$t9control/home/agent-tool-state"
expect_tool_line T9-both-present "$t9_prefix agent-tool=present agent-tool-state=present" \
    "$(run_tool_probe "$t9control" "$t9control/home" tool-set-explicit)"

# T9-control: the positive control. The same-named tool is the launch here, so its
# own leaf and its persist link both have to read `present`; the same statements
# against a home without the link must be refused.
t9_control='CM-T9-control agent-tool=agent-tool-seed agent-tool-state=present'
expect_tool_line T9-control "$t9_control" \
    "$(run_tool_probe "$t9control" "$t9control/home" tool-agent-name)"
rm "$t9control/home/agent-tool-state"
refuse_tool_line T9-control-link "$t9_control" \
    "$(run_tool_probe "$t9control" "$t9control/home" tool-agent-name)"

# T10/T11: the Pi-only rows, whose only mount is the fork copy.
expect_tool_line T10 'CM-T10 pi=pi-guest guest-file=present agent=absent' \
    "$(run_tool_probe "$empty" "$forkhome" tool-pi-explicit)"
expect_tool_line T11 'CM-T11 pi=pi-guest guest-file=present agent=absent' \
    "$(run_tool_probe "$empty" "$forkhome" tool-fork)"
refuse_tool_line T11-reseed 'CM-T11 pi=pi-seed guest-file=present agent=absent' \
    "$(run_tool_probe "$empty" "$forkhome" tool-fork)"
printf 'pi-seed' > "$forkhome/.pi/marker"
refuse_tool_line T11-source 'CM-T11 pi=pi-guest guest-file=present agent=absent' \
    "$(run_tool_probe "$empty" "$forkhome" tool-fork)"
printf 'pi-guest' > "$forkhome/.pi/marker"

# The tool phases must not be silently accepted under an unrelated name.
if run_tool_probe "$toolroot" "$forkhome" tool-unknown >/dev/null 2>&1; then
    fail 'the probe accepted an unknown tool-mount phase'
fi
echo 'tool-mount probe controls passed (rows, positive/negative controls, fork-read and sentinel mismatches; no VM)'

# --- Wrapper preflight refusals ----------------------------------------------
# The fakes make the host gate deterministic, record every native scratch
# allocation, and keep CI (Linux) able to run these controls.
tools="$work/tools"
mkdir -p "$tools"
allocations="$work/allocations.log"
: > "$allocations"
real_mktemp="$(command -v mktemp)"
cat > "$tools/uname" <<'SH'
#!/bin/sh
case "${1:-}" in
    -s) echo "${FAKE_UNAME_S:-Darwin}" ;;
    -m) echo "${FAKE_UNAME_M:-arm64}" ;;
    *) echo "${FAKE_UNAME_S:-Darwin}" ;;
esac
SH
printf '#!/bin/sh\nexit 1\n' > "$tools/pgrep"
cat > "$tools/sysctl" <<'SH'
#!/bin/sh
echo 'fixture-model fixture-cpu'
SH
printf '#!/bin/sh\necho "ProductName:\t\tsynthetic fixture"\n' > "$tools/sw_vers"
printf '#!/bin/sh\necho "codesign: fixture unsigned"\n' > "$tools/codesign"
cat > "$tools/mktemp" <<SH
#!/bin/sh
out="\$("$real_mktemp" "\$@")" || exit \$?
case "\$out" in
    /tmp/avm-cm.*|/private/tmp/avm-cm.*) printf '%s\n' "\$out" >> "$allocations" ;;
esac
printf '%s\n' "\$out"
SH
chmod 0755 "$tools/uname" "$tools/pgrep" "$tools/sysctl" "$tools/sw_vers" \
    "$tools/codesign" "$tools/mktemp"

# A fake bundle is enough to reach the refusals below without a real candidate.
mkdir -p "$work/bundle/bin" "$work/bundle/lib"
printf '#!/bin/sh\nprintf "agent-vm 0.0.0 (deadbeef)\\n"\n' > "$work/bundle/bin/agent-vm"
printf '#!/bin/sh\necho "msb 0.0.0"\n' > "$work/bundle/bin/msb"
printf 'fixture firmware\n' > "$work/bundle/lib/libkrunfw.5.dylib"
chmod 0755 "$work/bundle/bin/agent-vm" "$work/bundle/bin/msb"

digest_image='registry.example.invalid/owner/image@sha256:0000000000000000000000000000000000000000000000000000000000000000'

run_live() {
    local name="$1"
    shift
    local evidence="$work/evidence-$name"
    mkdir -p "$evidence"
    : > "$allocations"
    set +e
    env PATH="$tools:$PATH" AGENT_VM_CM_EVIDENCE="$evidence" "$@" \
        bash "$LIVE" > "$work/$name.log" 2>&1
    local status=$?
    set -e
    [[ "$status" -ne 0 ]] || fail "$name: the wrapper accepted a host it must refuse"
    [[ ! -s "$allocations" ]] || fail "$name: native scratch was allocated before the refusal"
    printf '%s' "$evidence"
}

evidence="$(run_live relative-binary AGENT_VM_BIN=./relative AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -q 'AGENT_VM_BIN must be an absolute path to an executable' "$work/relative-binary.log" ||
    fail 'relative-binary: unexpected first error'

evidence="$(run_live tagged-image AGENT_VM_BIN="$work/bundle/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE='repo:tag')"
grep -q 'must be digest-pinned' "$work/tagged-image.log" ||
    fail 'tagged-image: unexpected first error'

evidence="$(run_live linux-host FAKE_UNAME_S=Linux AGENT_VM_BIN="$work/bundle/bin/agent-vm" \
    AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -q 'needs a macOS arm64 host' "$work/linux-host.log" ||
    fail 'linux-host: unexpected first error'

mv "$work/bundle/bin/msb" "$work/bundle/bin/msb.away"
evidence="$(run_live missing-msb AGENT_VM_BIN="$work/bundle/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -q 'no executable sibling msb' "$work/missing-msb.log" ||
    fail 'missing-msb: unexpected first error'
mv "$work/bundle/bin/msb.away" "$work/bundle/bin/msb"

# The full preflight reaches provenance, which must refuse this fixture binary
# and still leave no scratch: provenance precedes allocation.
#
# The refusal must be the *checker's*. Every `reject()` in the wrapper prints
# `provenance: …` too, so matching that prefix alone would pass on a run where
# `build-provenance.py` never executed. The fixture reports
# `agent-vm 0.0.0 (deadbeef)`, whose revision is not a 40/64-hex commit, so the
# checker's own reason is this exact sentence.
provenance_reason='provenance: not one agent-vm version line'
evidence="$(run_live provenance AGENT_VM_BIN="$work/bundle/bin/agent-vm" AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -qF "$provenance_reason" "$work/provenance.log" ||
    fail 'provenance: the refusal did not come from build-provenance.py'
[[ -s "$evidence/provenance-check.txt" ]] || fail 'provenance: no retained provenance-check.txt'

# Negative control for that guard, in the style of the ci-contract mutations
# below: break the checker's precondition and require the guard to fail for the
# exact reason it names. A bundle whose `--version` fails is refused by the
# wrapper's own `reject` before the checker runs — the weak prefix guard would
# still match it, so the specific assertion must not.
mv "$work/bundle/bin/agent-vm" "$work/bundle/bin/agent-vm.real"
printf '#!/bin/sh\nexit 1\n' > "$work/bundle/bin/agent-vm"
chmod 0755 "$work/bundle/bin/agent-vm"
run_live provenance-early-reject AGENT_VM_BIN="$work/bundle/bin/agent-vm" \
    AGENT_VM_LIVE_TEST_IMAGE="$digest_image" >/dev/null
mv "$work/bundle/bin/agent-vm.real" "$work/bundle/bin/agent-vm"
grep -q 'provenance: ' "$work/provenance-early-reject.log" ||
    fail 'provenance control: the early refusal was not receipted as provenance'
if grep -qF "$provenance_reason" "$work/provenance-early-reject.log"; then
    fail 'provenance control: the checker-specific guard accepted an early reject'
fi

# An unset prerequisite is the first refusal a caller can hit, and it must be
# receipted like the rest — the run is blocked, so it owes the reader a reason.
# Only the variable under test is unset; the other keeps its valid value so this
# control cannot pass because of a different refusal.
evidence="$(run_live unset-agent-vm-bin env -u AGENT_VM_BIN \
    AGENT_VM_LIVE_TEST_IMAGE="$digest_image")"
grep -q 'rejected: set AGENT_VM_BIN' "$work/unset-agent-vm-bin.log" ||
    fail 'unset-agent-vm-bin: an unset AGENT_VM_BIN was not refused by name'
grep -q 'rejected: ' "$evidence/rejection.txt" ||
    fail 'unset-agent-vm-bin: an unset prerequisite left no rejection.txt'
evidence="$(run_live unset-live-test-image env -u AGENT_VM_LIVE_TEST_IMAGE \
    AGENT_VM_BIN="$work/bundle/bin/agent-vm")"
grep -q 'rejected: set AGENT_VM_LIVE_TEST_IMAGE' "$work/unset-live-test-image.log" ||
    fail 'unset-live-test-image: an unset image was not refused by name'
grep -q 'rejected: ' "$evidence/rejection.txt" ||
    fail 'unset-live-test-image: an unset prerequisite left no rejection.txt'

# Each refusal is receipted for the reader, not only printed.
for name in relative-binary tagged-image linux-host missing-msb; do
    grep -q 'rejected: ' "$work/evidence-$name/rejection.txt" ||
        fail "$name: the refusal left no rejection.txt"
done
echo 'wrapper preflight controls passed (refusals receipted, zero scratch allocated)'

# --- The ci-contracts.sh guard entries are load bearing ----------------------
python3 - "$REPO_ROOT" <<'PY'
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
source = (root / "script/test/ci-contracts.sh").read_text()
files = ("script/test/config-mounts-live.sh",
         "script/test/config-mounts-contract.sh",
         "script/test/lib/config-mounts.py",
         "script/test/fixtures/config-mounts/guest-cm-probe.sh")
# The companion must actually run in CI, not merely be listed.
run_list = source.split("# --- Shell guard rail", 1)[0]
assert 'bash "$REPO_ROOT/script/test/config-mounts-contract.sh"' in run_list, \
    "ci-contracts.sh does not invoke the host controls"
for array, label in (("syntax_check", "bash -n"), ("shellcheck_files", "shellcheck")):
    for script in files:
        if script.endswith(".py"):
            # shellcheck and bash -n have nothing to say about a Python driver.
            continue
        start = source.index(array + "=(")
        end = source.index("\n)", start)
        block = source[start:end]
        entry = "    " + script + "\n"
        assert block.count(entry) == 1, (array, script)
        assert f"assert_listed '{label}' '{script}'" in source, \
            f"no explicit {label} membership assertion for {script}"
        mutated = source[:start] + block.replace(entry, "", 1) + source[end:]
        with tempfile.TemporaryDirectory(prefix="cm-control-mutation-") as tmp:
            path = Path(tmp) / "script/test/ci-contracts.sh"
            path.parent.mkdir(parents=True)
            path.write_text(mutated)
            result = subprocess.run(["bash", str(path), "--guard-only"],
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode == 1, result.stdout + result.stderr
            assert f"({script}) is missing from the {label} guard list" in result.stderr, result.stderr
        print(f"host-only removal mutation PASS: {array}: {script}")
PY

echo 'host-only config-mounts controls passed (probe rows including the named-set rows, preflight refusals, guard entries; no VM run)'
