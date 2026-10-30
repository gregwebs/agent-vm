#!/usr/bin/env bash
# #473: reclaiming the build cache is an explicit operator step, never a run's.
#
# No daemon here: a `docker` shim on PATH records every argv line the reclaim
# script issues, and the shim's exit status and output stand in for a daemon that
# is unlistable, unreadable in a future format, or failing mid-prune. What the
# cases pin is the script's observable contract — that reporting touches nothing,
# that `--prune` is exactly one prune between two reads, and that a failed
# observation never reads as "there was nothing to reclaim".
set -euo pipefail
ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
# Overridable only so a hand probe can point the cases at a mutated copy. CI sets
# nothing: ci-contracts.sh's dispatch passes no environment.
SCRIPT="${AGENT_VM_RECLAIM_SCRIPT:-$ROOT/script/test/reclaim-docker-cache.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/av-reclaim-docker-cache-contract.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
CALLS="$WORK/docker.log"
BIN="$WORK/bin"
OUT="$WORK/out"
mkdir -p "$BIN"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The three states a real daemon can be in during this script's two calls: it
# answers, it cannot be reached, or the prune itself fails. The summary block is
# byte-for-byte the shape `docker buildx du` prints (tab-separated).
DU_SUMMARY="$(printf 'Shared:\t1.0GB\nPrivate:\t1.0GB\nReclaimable:\t1.0GB\nTotal:\t1.0GB')"
cat >"$BIN/docker" <<'SHIM'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$CALLS"
case "${1:-} ${2:-}" in
'buildx du')
    if [ -e "$DU_FAIL" ]; then
        echo "Cannot connect to the Docker daemon at unix:///probe.sock. Is the docker daemon running?" >&2
        exit 1
    fi
    if [ -e "$DU_JUNK" ]; then
        echo "ID RECLAIMABLE SIZE LAST ACCESSED"
        echo "abc123 true 1.0GB 1 day ago"
        exit 0
    fi
    if [ -e "$DU_PARTIAL" ]; then
        printf 'Total:\t1.0GB\n'
        exit 0
    fi
    if [ -e "$DU_GARBAGE" ]; then
        printf 'Reclaimable:\tgarbage\nTotal:\tgarbage\n'
        exit 0
    fi
    printf '%s\n' "ID                           RECLAIMABLE   SIZE       LAST ACCESSED" \
        "abc123                       true          1.0GB      1 day ago" \
        ""
    printf '%s\n' "$DU_SUMMARY"
    ;;
'buildx prune')
    if [ -e "$PRUNE_FAIL" ]; then
        echo "error: failed to prune: probe" >&2
        exit 1
    fi
    # Distinctive so the case proves the script surfaces the daemon's own
    # receipt rather than printing a summary of its own.
    printf 'prune-receipt: freed 1.0GB\nTotal:\t1.0GB\n'
    ;;
*) exit 1 ;;
esac
SHIM
chmod +x "$BIN/docker"

reset_marks() {
    rm -f "$WORK/du-fail" "$WORK/du-junk" "$WORK/du-partial" "$WORK/du-garbage" \
        "$WORK/prune-fail"
    : >"$CALLS"
}
mark() { : >"$WORK/$1"; }

rc=0
run() {
    rc=0
    PATH="$BIN:$PATH" CALLS="$CALLS" DU_FAIL="$WORK/du-fail" DU_JUNK="$WORK/du-junk" \
        DU_PARTIAL="$WORK/du-partial" DU_GARBAGE="$WORK/du-garbage" \
        PRUNE_FAIL="$WORK/prune-fail" DU_SUMMARY="$DU_SUMMARY" \
        bash "$SCRIPT" "$@" >"$OUT" 2>&1 || rc=$?
}

expect_rc() { [ "$rc" -eq "$1" ] || fail "$2: exit status $rc, expected $1 (output: $(cat "$OUT"))"; }

expect_calls() {
    local desc="$1" expected="$WORK/expected"
    shift
    if [ "$#" -eq 0 ]; then
        : >"$expected"
    else
        printf '%s\n' "$@" >"$expected"
    fi
    diff -u "$expected" "$CALLS" >"$WORK/calls.diff" || fail "$desc: daemon calls are not the contracted ones:
$(cat "$WORK/calls.diff")"
}

expect_out() { grep -qF -- "$2" "$OUT" || fail "$1: output does not contain '$2' (output: $(cat "$OUT"))"; }
reject_out() { ! grep -qF -- "$2" "$OUT" || fail "$1: output contains '$2', which it must not (output: $(cat "$OUT"))"; }

# --- D1: the default is a report -------------------------------------------
# A report that pruned would be the whole failure mode this ticket is about, so
# "removes nothing" is asserted as an argv fact, not as prose.
reset_marks
run
expect_rc 0 D1
expect_calls D1 'buildx du'
expect_out D1 '  Reclaimable:'
expect_out D1 'nothing was pruned; pass --prune'
reject_out D1 'build cache after'
echo "D1 report-removes-nothing: ok"

# --- D2: --prune is one prune between two reads ----------------------------
# Both reads are required: the before read is what makes the receipt a
# measurement, and the after read is what shows the operator the new total.
reset_marks
run --prune
expect_rc 0 D2
expect_calls D2 'buildx du' 'buildx prune --force' 'buildx du'
expect_out D2 'build cache before'
expect_out D2 'build cache after'
# The daemon's own prune receipt is what the operator sees.
expect_out D2 'prune-receipt: freed 1.0GB'
reject_out D2 'nothing was pruned'
echo "D2 prune-reads-before-and-after: ok"

# --- D3: an unreachable daemon is not "nothing to reclaim" -----------------
reset_marks
mark du-fail
run --prune
expect_rc 1 D3
expect_calls D3 'buildx du'
expect_out D3 'could not read the build cache'
expect_out D3 'nothing was pruned'
expect_out D3 'Cannot connect to the Docker daemon'
echo "D3 unlistable-daemon-fails-without-pruning: ok"

# --- D4: a failing prune is reported as a failure, not as a receipt ---------
reset_marks
mark prune-fail
run --prune
expect_rc 1 D4
expect_calls D4 'buildx du' 'buildx prune --force'
expect_out D4 'docker buildx prune failed'
expect_out D4 'cannot say what it already removed'
reject_out D4 'unchanged'
expect_out D4 'error: failed to prune: probe'
reject_out D4 'build cache after'
echo "D4 failed-prune-is-a-failure: ok"

# --- D5: an unknown cache format is refused, not read as an empty cache -----
# The regression that matters: a future `buildx du` that stopped printing the
# summary block would otherwise make every host report "nothing reclaimable".
reset_marks
mark du-junk
run --prune
expect_rc 1 D5
expect_calls D5 'buildx du'
expect_out D5 'no recognisable Reclaimable/Total sizes'
echo "D5 unknown-format-is-not-an-empty-cache: ok"

# --- D6: --builder reaches every call --------------------------------------
reset_marks
run --prune --builder probe
expect_rc 0 D6
expect_calls D6 'buildx du --builder probe' 'buildx prune --force --builder probe' 'buildx du --builder probe'
expect_out D6 '(probe)'
echo "D6 builder-reaches-every-call: ok"

# --- D7: a malformed invocation issues nothing -----------------------------
reset_marks
run --bogus
expect_rc 2 D7
expect_calls D7
expect_out D7 'unsupported argument: --bogus'
reset_marks
run --builder
expect_rc 2 D7
expect_calls D7
expect_out D7 '--builder needs a builder name'
# A trailing --builder must not silently prune the selected builder instead, and
# neither must an empty or flag-looking name: an unset shell variable expands to
# the first, and a mistyped one to the second.
reset_marks
run --prune --builder
expect_rc 2 D7
expect_calls D7
reset_marks
run --prune --builder ''
expect_rc 2 D7
expect_calls D7
expect_out D7 "needs a builder name, not ''"
reset_marks
run --prune --builder --prune
expect_rc 2 D7
expect_calls D7
expect_out D7 "needs a builder name, not '--prune'"
echo "D7 malformed-invocation-issues-nothing: ok"

# --- D8: --help is inert ---------------------------------------------------
reset_marks
run --help
expect_rc 0 D8
expect_calls D8
expect_out D8 'Usage: script/test/reclaim-docker-cache.sh'
echo "D8 help-is-inert: ok"

# --- D9: --builder on the report path removes nothing ----------------------
# D1 pins the report path with no builder and D6 pins `--prune` with one: a
# script that pruned whenever a builder was named would have passed both.
reset_marks
run --builder probe
expect_rc 0 D9
expect_calls D9 'buildx du --builder probe'
reject_out D9 'build cache after'
expect_out D9 'nothing was pruned; pass --prune'
echo "D9 report-with-builder-removes-nothing: ok"

# --- D10: a partial summary is refused too ---------------------------------
# A format that kept `Total:` but dropped `Reclaimable:` would print a number
# this script cannot interpret, and the report is the only thing standing
# between an operator and `--prune`.
reset_marks
mark du-partial
run --prune
expect_rc 1 D10
expect_calls D10 'buildx du'
expect_out D10 'no recognisable Reclaimable/Total sizes'
echo "D10 partial-summary-is-not-an-empty-cache: ok"

# --- D11: sizes this script cannot read are refused ------------------------
# Field names alone are not enough: `Reclaimable: garbage` printed as a reported
# size would be read by an operator as grounds to prune.
reset_marks
mark du-garbage
run --prune
expect_rc 1 D11
expect_calls D11 'buildx du'
expect_out D11 'no recognisable Reclaimable/Total sizes'
echo "D11 unreadable-sizes-are-refused: ok"

echo "reclaim-docker-cache contract: ok (D1-D11)"
