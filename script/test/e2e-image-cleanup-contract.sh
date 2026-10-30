#!/usr/bin/env bash
# #455: an e2e run's own Docker refs are removed by its EXIT trap. No daemon and
# no VM here: a `docker` function stub records every argv line the shared lib
# issues, and C9 runs the production `cleanup_work` in a child under its own trap,
# so a regression in what cleanup removes is visible in CI, where the native
# `harness-negative` row cannot run (CONTRIBUTING.md, "What runs where").
set -euo pipefail
ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
# The audited path is overridable only so a hand probe can point C9's live-trap case
# at a mutated copy of the harness. CI never sets it: ci-contracts.sh's dispatch
# passes no environment.
E2E="${AGENT_VM_E2E_CONTRACT_E2E:-$ROOT/script/test/e2e.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-e2e-image-cleanup-contract.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/docker.log"
CALLS="$WORK/listing-calls"
# A synthetic id: no real daemon ref can carry it, and no case here touches one.
RUN_ID="ab12cd"
# shellcheck source=script/test/lib/e2e-image-cleanup.sh
. "$ROOT/script/test/lib/e2e-image-cleanup.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

# The lib's whole contract is two daemon calls and one receipt, so the stub models
# exactly those: a listing that differs before and after the batch (a survivor, a
# ref another client untagged, a failing daemon) and a batch status that is
# deliberately independent of what survived.
listing_before=""
listing_after=""
listing_status_before=0
listing_status_after=0
removal_status=0
removal_output=""
# shellcheck disable=SC2317,SC2329  # invoked indirectly by the sourced lib
docker() {
    local calls
    printf '%s\n' "$*" >>"$LOG"
    case "${1:-} ${2:-}" in
    'image ls')
        # The call count lives in a file: the lib reads each listing in a command
        # substitution, so a variable could never distinguish the two listings.
        calls="$(cat "$CALLS" 2>/dev/null || echo 0)"
        calls=$((calls + 1))
        printf '%s\n' "$calls" >"$CALLS"
        if [ "$calls" -gt 1 ]; then
            [ "$listing_status_after" -eq 0 ] || return "$listing_status_after"
            printf '%s\n' "$listing_after"
        else
            [ "$listing_status_before" -eq 0 ] || return "$listing_status_before"
            printf '%s\n' "$listing_before"
        fi
        ;;
    'image rm')
        printf '%s\n' "$removal_output"
        [ "$removal_status" -eq 0 ] || return "$removal_status"
        ;;
    *) return 1 ;;
    esac
}

stub_reset() {
    : >"$LOG"
    printf '0\n' >"$CALLS"
    listing_before=""
    listing_after=""
    listing_status_before=0
    listing_status_after=0
    removal_status=0
    removal_output=""
}

sweep_rc=0
sweep_out=""
run_sweep() {
    sweep_rc=0
    sweep_out="$(owned_images_cleanup "$1" 2>&1)" || sweep_rc=$?
}

assert_rc() {
    [ "$sweep_rc" -eq "$1" ] || fail "$case: expected status $1, got $sweep_rc (output: $sweep_out)"
}
# Whole-line comparison on both: `image rm probe:x` must not be satisfied by
# `image rm probe:x-gone`, and an extra call is a regression even when harmless.
assert_argv() {
    local want got
    want="$(printf '%s\n' "$@")"
    got="$(cat "$LOG")"
    [ "$got" = "$want" ] ||
        fail "$case: daemon calls differ
--- expected
$want
--- actual
$got"
}
assert_out_matches() {
    printf '%s\n' "$sweep_out" | grep -qE -- "$1" ||
        fail "$case: output does not match /$1/ (output: $sweep_out)"
}
assert_out_lacks() {
    if printf '%s\n' "$sweep_out" | grep -qF -- "$1"; then
        fail "$case: output unexpectedly has '$1' (output: $sweep_out)"
    fi
}
listing_line='image ls --format {{.Repository}}:{{.Tag}}'

# --- C1: exactly the run's own refs, in one batch, verified by re-listing ------
case=C1
stub_reset
listing_before="agent-vm-e2e-258-ab12cd:marker-free
localhost:1/e2e-259-ab12cd:selected
localhost:33917/agent-vm-base:cm396"
listing_after="localhost:33917/agent-vm-base:cm396"
run_sweep 0
assert_rc 0
assert_argv "$listing_line" \
    "image rm -- agent-vm-e2e-258-ab12cd:marker-free localhost:1/e2e-259-ab12cd:selected" \
    "$listing_line"
assert_out_matches '^ *owned images: 2 removed, 0 still present$'
echo "C1 exact-candidate-set: ok"

# --- C2: a foreign ref, a digest and a `<none>` line are never named ----------
case=C2
stub_reset
listing_before="agent-vm-e2e-258-cd34ef:marker-free
localhost:9/e2e-259-cd34ef:selected
agent-vm-e2e-258-base@sha256:0123456789abcdef
<none>:<none>
localhost:33917/agent-vm-base:<none>
agent-vm-e2e-258-ab12cd:only"
listing_after=""
run_sweep 0
assert_rc 0
assert_argv "$listing_line" "image rm -- agent-vm-e2e-258-ab12cd:only" "$listing_line"
for foreign in cd34ef '@sha256' '<none>'; do
    if grep -qF -- "$foreign" "$LOG"; then
        fail "$case: a ref this run does not own was named: $foreign (calls: $(cat "$LOG"))"
    fi
done
echo "C2 foreign-refs-never-named: ok"

# --- C3: nothing marked is not a removal -------------------------------------
case=C3
stub_reset
listing_before="localhost:33917/agent-vm-base:cm396"
run_sweep 0
assert_rc 0
assert_argv "$listing_line"
assert_out_lacks 'owned images:'
echo "C3 no-candidates-is-not-a-removal: ok"

# --- C4: a failed listing is a failure and issues no removal ------------------
case=C4
stub_reset
listing_status_before=3
run_sweep 0
assert_rc 1
assert_argv "$listing_line"
assert_out_matches 'FAIL: could not list local images'
echo "C4 listing-failure-fails-cleanup: ok"

# --- C5: a failed *after*-listing is a failure too ---------------------------
case=C5
stub_reset
listing_before="agent-vm-e2e-258-ab12cd:only"
listing_status_after=3
run_sweep 0
assert_rc 1
assert_argv "$listing_line" "image rm -- agent-vm-e2e-258-ab12cd:only" "$listing_line"
assert_out_matches 'FAIL: could not list local images after removing'
echo "C5 after-listing-failure-fails-cleanup: ok"

# --- C6: a survivor after the batch fails and is named, even on batch status 0 --
case=C6
stub_reset
listing_before="agent-vm-e2e-258-ab12cd:survivor
agent-vm-e2e-258-ab12cd:gone"
listing_after="agent-vm-e2e-258-ab12cd:survivor"
run_sweep 0
assert_rc 1
assert_argv "$listing_line" \
    "image rm -- agent-vm-e2e-258-ab12cd:survivor agent-vm-e2e-258-ab12cd:gone" \
    "$listing_line"
assert_out_matches '^ *agent-vm-e2e-258-ab12cd:survivor$'
assert_out_matches '^ *owned images: 1 removed, 1 still present$'
echo "C6 survivor-fails-and-is-named: ok"

# --- C7: the batch's exit status is not the verdict --------------------------
case=C7
stub_reset
listing_before="agent-vm-e2e-258-ab12cd:a
agent-vm-e2e-258-ab12cd:b"
listing_after=""
removal_status=1
removal_output="Error response from daemon: conflict: unable to delete (must be forced)"
run_sweep 0
assert_rc 0
assert_argv "$listing_line" "image rm -- agent-vm-e2e-258-ab12cd:a agent-vm-e2e-258-ab12cd:b" "$listing_line"
assert_out_matches '^ *owned images: 2 removed, 0 still present$'
echo "C7 batch-status-is-not-the-verdict: ok"

# --- C8: a second sweep of the same run attempts nothing ---------------------
case=C8
stub_reset
run_sweep 0
assert_rc 0
assert_argv "$listing_line"
assert_out_lacks 'owned images:'
echo "C8 second-sweep-attempts-nothing: ok"

# --- C9: the production trap, in a child, with a decoy `docker` --------------
# The one case that is not a stub of the *code*: `cleanup_work` and its helpers are
# extracted from the tracked harness and run under their own EXIT trap, so deleting
# the sweep's call from `cleanup_work` leaves the decoy with no `image rm` and this
# case fails for real, rather than by grepping a marker out of the source.
case=C9
extract_function() {
    local name="$1" text
    text="$(awk -v fn="$name" '$0 == fn "() {" { inside = 1 } inside { print } inside && /^}$/ { exit }' "$E2E")"
    [ -n "$text" ] || fail "$case: could not extract $name from $E2E"
    printf '%s\n' "$text"
}
trap_child() {
    local name="$1" status="$2" builder="$3" dir script
    dir="$WORK/trap-$name-work"
    script="$WORK/trap-$name.sh"
    rm -rf "$dir"
    mkdir -p "$dir"
    : >"$WORK/trap-docker.log"
    rm -f "$WORK/trap-removed"
    {
        # Decoy first: functions read the same either way, but a reader should see
        # the seam before the production code that uses it.
        cat <<'CHILD'
# The sweep's seam is the `docker` command. The listing names one ref this run
# owns and one it does not; after a removal the owned one is gone, which is what
# makes the sweep's re-listing succeed.
docker() {
    printf '%s\n' "$*" >>"$DECOY_LOG"
    case "$*" in
    'image ls --format {{.Repository}}:{{.Tag}}')
        if [ -e "$DECOY_REMOVED" ]; then
            printf '%s\n' 'localhost:33917/agent-vm-base:cm396'
        else
            printf '%s\n' 'agent-vm-e2e-258-ab12cd:marker-free' \
                'localhost:33917/agent-vm-base:cm396'
        fi
        ;;
    'image rm '*) : >"$DECOY_REMOVED" ;;
    # A builder teardown failure is the ordinary case the trap's ordering exists
    # for, so the decoy always fails it.
    'buildx rm '*) return 1 ;;
    *) return 1 ;;
    esac
}
CHILD
        extract_function cleanup_work
        extract_function cleanup_row_helpers
        # The sweep itself comes from the sourced lib: what this case guards is the
        # call site inside `cleanup_work`, and re-extracting the lib's text here
        # would be a second copy of the code under test.
        printf '%s\n' "$(declare -f owned_images_cleanup)"
        printf 'set -u\nRUN_ID="ab12cd"\nOWNED_BUILDER="%s"\ntrap cleanup_work EXIT\nexit %s\n' \
            "$builder" "$status"
    } >"$script"
    env WORK="$dir" DECOY_LOG="$WORK/trap-docker.log" \
        DECOY_REMOVED="$WORK/trap-removed" bash "$script" >"$WORK/trap-$name.out" 2>&1
}
green_rc=0
trap_child green 0 '' || green_rc=$?
[ "$green_rc" -eq 0 ] || fail "$case: a green run's live trap exited $green_rc (output: $(cat "$WORK/trap-green.out"))"
grep -qxF 'image rm -- agent-vm-e2e-258-ab12cd:marker-free' "$WORK/trap-docker.log" ||
    fail "$case: the live trap issued no removal for the ref the run owns (calls: $(cat "$WORK/trap-docker.log"))"
grep -qE '^ *owned images: 1 removed, 0 still present$' "$WORK/trap-green.out" ||
    fail "$case: the live trap's receipt is wrong (output: $(cat "$WORK/trap-green.out"))"
failed_rc=0
trap_child failed 7 '' || failed_rc=$?
[ "$failed_rc" -eq 7 ] || fail "$case: the live trap changed the failed run's status to $failed_rc"
if grep -q '^image rm ' "$WORK/trap-docker.log"; then
    fail "$case: the live trap removed refs for a failed run (calls: $(cat "$WORK/trap-docker.log"))"
fi
grep -qF "preserving this run's Docker refs" "$WORK/trap-failed.out" ||
    fail "$case: the failed run did not report the refs it kept (output: $(cat "$WORK/trap-failed.out"))"
grep -qF 'remove them with: docker image rm agent-vm-e2e-258-ab12cd:marker-free' \
    "$WORK/trap-failed.out" ||
    fail "$case: the failed run printed no copy-pasteable removal line (output: $(cat "$WORK/trap-failed.out"))"
echo "C9 live-trap-both-statuses: ok"

# --- C9b: the sweep runs before `docker buildx rm` --------------------------
# The invariant `cleanup_work`'s own comment states: a builder teardown that fails
# for unrelated reasons must not strand the run's refs. Every consumer that passes
# no `OWNED_BUILDER` reaches the same code either way, so this is the only case
# that can tell the two orders apart: teardown first sets status 1, the sweep then
# takes its keep-on-failure branch, and a *green* run's ref is preserved with no
# removal attempted at all.
case=C9b
builder_rc=0
trap_child builder 0 probe || builder_rc=$?
[ "$builder_rc" -eq 1 ] ||
    fail "$case: a failing builder teardown left the trap's exit status at $builder_rc, not 1 (output: $(cat "$WORK/trap-builder.out"))"
grep -qxF 'buildx rm probe' "$WORK/trap-docker.log" ||
    fail "$case: the trap never attempted the builder teardown (calls: $(cat "$WORK/trap-docker.log"))"
grep -qxF 'image rm -- agent-vm-e2e-258-ab12cd:marker-free' "$WORK/trap-docker.log" ||
    fail "$case: a failing builder teardown stranded the run's ref: no removal was issued (calls: $(cat "$WORK/trap-docker.log"))"
grep -qE '^ *owned images: 1 removed, 0 still present$' "$WORK/trap-builder.out" ||
    fail "$case: the receipt is not the sweep's removal receipt (output: $(cat "$WORK/trap-builder.out"))"
if grep -qF "preserving this run's Docker refs" "$WORK/trap-builder.out"; then
    fail "$case: the sweep read the builder's failure as the run's and preserved its refs (output: $(cat "$WORK/trap-builder.out"))"
fi
echo "C9b sweep-before-builder-teardown: ok"

# --- C10: the CI guard's memberships are themselves guarded ----------------
# `assert_listed` is assertion-based -- nothing scans `script/test/` -- so a new
# file nobody lists is silently unguarded. Each of this change's two memberships is
# dropped in turn from a copy in owned scratch (the working tree is never edited)
# and the copy must reject it: mutating only one would leave the other removable
# from `ci-contracts.sh` with this case still green.
case=C10
mkdir -p "$WORK/script/test"
guard_copy="$WORK/script/test/ci-contracts.sh"
guard_membership_dropped() {
    local entry="$1" members remaining rc=0 err
    # Only the list lines carry the four-space indent, so this counts memberships
    # and not the `assert_listed` calls that name the same path.
    members="    $entry"
    awk -v entry="$members" '
        /^shellcheck_files=\(/ { list = 1; print; next }
        list && /^\)/          { list = 0; print; next }
        list && $0 == entry    { next }
        { print }
    ' "$ROOT/script/test/ci-contracts.sh" >"$guard_copy"
    remaining="$(grep -cF -- "$members" "$guard_copy" || true)"
    [ "$remaining" -eq 1 ] ||
        fail "$case: the mutation left $remaining copies of $entry's membership, expected 1 (syntax_check only)"
    err="$(bash "$guard_copy" --guard-only 2>&1)" || rc=$?
    [ "$rc" -eq 1 ] ||
        fail "$case: dropping $entry from the shellcheck guard exited $rc, not 1 (output: $err)"
    printf '%s\n' "$err" | grep -qF \
        "($entry) is missing from the shellcheck guard list" ||
        fail "$case: the mutated guard did not name the missing $entry membership (output: $err)"
}
guard_membership_dropped script/test/lib/e2e-image-cleanup.sh
guard_membership_dropped script/test/e2e-image-cleanup-contract.sh
echo "C10 guard-membership-mutation: ok"

echo 'e2e image-cleanup contract passed (C1-C10 plus C9b; decoy docker, no daemon, no VM)'
