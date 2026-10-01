#!/usr/bin/env bash
# Black-box contract tests for the pi layer's build gate
# (images/tools/pi/verify-pi.sh).
#
# No Docker and no real Pi: the wrapper (`$WRAPPER`) and the installed entry
# point (`$PI_PREFIX/node_modules/.bin/pi`) are fakes under a case temp root, so
# every branch -- a missing installer with/without an absence record, the wrong
# version, the print-then-nonzero trap, a mismatching subcommand allowlist, the
# mandatory extension, a real (rpc) invocation that exits nonzero, the
# bridge's manifest/installed/probe gates, and the bridge-only degradation -- is
# exercised hermetically. jq, `timeout`, python3, the real run-report.sh/`jq`
# selectors and check-tool-access.py back the gate; both status records are
# written under the case temp root.
#
# The wrapper's `--help` subcommand list is compared against its own
# PI_SUBCOMMANDS line by the gate, so the fake keeps both in one place.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
GATE="$REPO_ROOT/images/tools/pi/verify-pi.sh"
CONTRACT="$REPO_ROOT/images/tools/pi/contract"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pi-verify-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT
# T5 (check-tool-access.py) audits every ancestor, so the fixture tree must be
# traversable by all.
chmod 0755 "$TEST_ROOT"

REAL_JQ="$(command -v jq || true)"
[[ -n "$REAL_JQ" ]] || { echo "FAIL: jq is required" >&2; exit 1; }
JQ_DIR="$(dirname "$REAL_JQ")"
REAL_TIMEOUT="$(command -v timeout || true)"
[[ -n "$REAL_TIMEOUT" ]] || { echo "FAIL: coreutils timeout is required" >&2; exit 1; }
TIMEOUT_DIR="$(dirname "$REAL_TIMEOUT")"
REAL_PYTHON="$(command -v python3 || true)"
[[ -n "$REAL_PYTHON" ]] || { echo "FAIL: python3 is required" >&2; exit 1; }
PYTHON_DIR="$(dirname "$REAL_PYTHON")"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2 (got: $1)"
}

CASE=""

# The fake wrapper. Its behaviour is env-driven so one template covers every
# case; PI_SUBCOMMANDS and the --help block agree unless FAKE_HELP_SUBS
# deliberately desyncs them.
write_wrapper() {
    cat >"$CASE/wrapper" <<'SH'
#!/bin/sh
PI_SUBCOMMANDS="list update uninstall"
case "${1:-}" in
    --version)
        printf '%s\n' "${FAKE_PI_REPORT:-0.87.1}"
        exit "${FAKE_PI_VERSION_STATUS:-0}"
        ;;
    --help)
        printf 'Usage: pi [options]\n\nCommands:\n'
        for c in ${FAKE_HELP_SUBS:-list update uninstall}; do
            printf '  pi %s description\n' "$c"
        done
        exit "${FAKE_PI_HELP_STATUS:-0}"
        ;;
esac
if [ "${1:-}" = "-e" ]; then
    printf '%s\n' "${FAKE_PROBE_OUT:-AGENT-VM-BRIDGE-REGISTERED models=12}"
    exit "${FAKE_PI_PROBE_STATUS:-0}"
fi
printf '%s\n' "${FAKE_RPC_OUT:-agent-vm: signing in here}"
exit "${FAKE_PI_RPC_STATUS:-0}"
SH
    chmod 0755 "$CASE/wrapper"
}

new_case() {
    unset FAKE_PI_REPORT FAKE_PI_VERSION_STATUS FAKE_HELP_SUBS \
        FAKE_PI_HELP_STATUS FAKE_PROBE_OUT FAKE_PI_PROBE_STATUS \
        FAKE_RPC_OUT FAKE_PI_RPC_STATUS SOFT \
        AGENT_VM_VERSION_PI AGENT_VM_VERSION_PI_CLAUDE_BRIDGE
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/prefix/node_modules/.bin" \
        "$CASE/ext" \
        "$CASE/packages/node_modules/pi-claude-bridge/src" \
        "$CASE/gate" "$CASE/status"
    printf '{"dependencies":{"@earendil-works/pi-coding-agent":"0.87.1"}}\n' \
        >"$CASE/prefix/package.json"
    printf '#!/bin/sh\nexit 0\n' >"$CASE/prefix/node_modules/.bin/pi"
    printf '// image-owned extension\n' >"$CASE/ext/guest-credential-warning.js"
    printf '{"dependencies":{"pi-claude-bridge":"0.8.0"}}\n' >"$CASE/packages/package.json"
    printf '{"name":"pi-claude-bridge","version":"0.8.0"}\n' \
        >"$CASE/packages/node_modules/pi-claude-bridge/package.json"
    printf 'export default function(){}\n' \
        >"$CASE/packages/node_modules/pi-claude-bridge/src/index.ts"
    write_wrapper
    # World-readable/executable everywhere T5 looks.
    chmod -R a+rX "$CASE"
    chmod 0755 "$CASE" "$CASE/prefix/node_modules/.bin/pi" "$CASE/wrapper"
}

# `drop_bridge` removes the bridge install tree (leaving the seed hook).
drop_bridge() { rm -rf "$CASE/packages"; }
# `drop_pi` removes the installed entry point.
drop_pi() { rm -f "$CASE/prefix/node_modules/.bin/pi"; }

write_status() { # $1 = slot, $2 = content
    printf '%s\n' "$2" >"$CASE/status/$1"
}

run_gate() {
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$TIMEOUT_DIR:$PYTHON_DIR:$JQ_DIR:/usr/bin:/bin" \
        "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
        "AGENT_VM_PI_PREFIX=$CASE/prefix" \
        "AGENT_VM_PI_WRAPPER=$CASE/wrapper" \
        "AGENT_VM_PI_PACKAGES_PREFIX=$CASE/packages" \
        "AGENT_VM_PI_EXTENSION_DIR=$CASE/ext" \
        "AGENT_VM_PI_GATE_WORK_DIR=$CASE/gate" \
        "AGENT_VM_PI_SEED_HOOK=$CASE/seed-hook" \
        "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
        "AGENT_VM_FIXTURE_ROOT=$CASE" \
        "AGENT_VM_VERSION_PI=${AGENT_VM_VERSION_PI-}" \
        "AGENT_VM_VERSION_PI_CLAUDE_BRIDGE=${AGENT_VM_VERSION_PI_CLAUDE_BRIDGE-}" \
        "FAKE_PI_REPORT=${FAKE_PI_REPORT-}" \
        "FAKE_PI_VERSION_STATUS=${FAKE_PI_VERSION_STATUS-0}" \
        "FAKE_HELP_SUBS=${FAKE_HELP_SUBS-}" \
        "FAKE_PI_HELP_STATUS=${FAKE_PI_HELP_STATUS-0}" \
        "FAKE_PROBE_OUT=${FAKE_PROBE_OUT-}" \
        "FAKE_PI_PROBE_STATUS=${FAKE_PI_PROBE_STATUS-0}" \
        "FAKE_RPC_OUT=${FAKE_RPC_OUT-}" \
        "FAKE_PI_RPC_STATUS=${FAKE_PI_RPC_STATUS-0}" \
        "AGENT_INSTALL_SOFT_FAIL=${SOFT-}" \
        sh "$GATE" 2>&1)"
    RUN_STATUS=$?
    set -e
}

# --- a missing install: hard unless a fresh absence record exists ------------

new_case missing-pi
drop_pi
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing pi install must be a hard failure"
assert_contains "$RUN_OUTPUT" "pi: MISSING with no absence record"

new_case missing-pi-stale-installed
drop_pi
write_status pi installed
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an inherited 'installed' record must not authorise absence"

new_case missing-pi-pending
drop_pi
write_status pi pending
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a 'pending' record must not authorise absence"

new_case missing-pi-absent
drop_pi
write_status pi 'absent-transport 7'
write_status pi-claude-bridge 'absent-transport 7'
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a recorded transport absence must be accepted: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "pi: ABSENT"
[[ ! -e "$CASE/wrapper" ]] || fail "the degraded image must not ship the wrapper"
[[ "$(cat "$CASE/status/pi-claude-bridge")" == "absent-pi" ]] \
    || fail "a removed pi tree must mark the bridge absent-pi"

# --- version: exact, status-checked on both sides ---------------------------

new_case version-mismatch
FAKE_PI_REPORT=9.9.9
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a version differing from the manifest must fail"
assert_contains "$RUN_OUTPUT" "reported '9.9.9', lockfile pins '0.87.1'"

new_case version-nonzero-after-print
FAKE_PI_VERSION_STATUS=1
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "printing the pin then exiting nonzero must fail"
assert_contains "$RUN_OUTPUT" "--version exited 1"

new_case supplied-version-mismatch
AGENT_VM_VERSION_PI=0.87.0
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a supplied slot disagreeing with the manifest must fail"
assert_contains "$RUN_OUTPUT" "asked for 0.87.0 but the manifest pins 0.87.1"

# --- subcommand allowlist ---------------------------------------------------

new_case help-mismatch
FAKE_HELP_SUBS="list update uninstall extra"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a wrapper/Pi subcommand mismatch must fail"
assert_contains "$RUN_OUTPUT" "wrapper subcommands"

new_case help-nonzero
FAKE_PI_HELP_STATUS=1
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a nonzero --help must fail before parsing"
assert_contains "$RUN_OUTPUT" "--help exited 1"

# --- the mandatory extension and the real invocation ------------------------

new_case extension-missing
rm -f "$CASE/ext/guest-credential-warning.js"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing mandatory extension must fail"
assert_contains "$RUN_OUTPUT" "the mandatory extension is missing"

new_case rpc-nonzero
FAKE_PI_RPC_STATUS=1
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an rpc run that exits nonzero must fail"
assert_contains "$RUN_OUTPUT" "a real invocation exited 1"

new_case rpc-no-warning
FAKE_RPC_OUT="something else"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a run without the warning must fail"
assert_contains "$RUN_OUTPUT" "does not load the mandatory extension"

# --- bridge: presence, version, probe ---------------------------------------

new_case bridge-missing-no-record
drop_bridge
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing bridge with no record must fail"
assert_contains "$RUN_OUTPUT" "pi-claude-bridge is missing with no absence record"

new_case bridge-missing-recorded
drop_bridge
write_status pi-claude-bridge 'absent-transport 6'
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a recorded bridge transport absence must be accepted: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "pi-claude-bridge ABSENT"
[[ "$(cat "$CASE/status/pi")" == "installed" ]] \
    || fail "a bridge-only degradation must still record pi installed"
[[ "$(cat "$CASE/status/pi-claude-bridge")" == "absent-transport 6" ]] \
    || fail "the bridge absence record must survive (never 'installed')"

new_case bridge-version-mismatch
printf '{"name":"pi-claude-bridge","version":"0.7.0"}\n' \
    >"$CASE/packages/node_modules/pi-claude-bridge/package.json"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an installed bridge version differing from the manifest must fail"
assert_contains "$RUN_OUTPUT" "installed 0.7.0 but the manifest pins 0.8.0"

new_case bridge-supplied-mismatch
AGENT_VM_VERSION_PI_CLAUDE_BRIDGE=0.7.0
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a supplied bridge slot disagreeing with the manifest must fail"
assert_contains "$RUN_OUTPUT" "asked for bridge 0.7.0 but the manifest pins 0.8.0"

new_case bridge-probe-missing
FAKE_PROBE_OUT="AGENT-VM-BRIDGE-MISSING"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a bridge that does not register must fail"
assert_contains "$RUN_OUTPUT" "did not register its provider"

new_case bridge-probe-empty-models
FAKE_PROBE_OUT="AGENT-VM-BRIDGE-REGISTERED models=0"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an empty model catalog must fail"
assert_contains "$RUN_OUTPUT" "model catalog is empty"

new_case bridge-probe-nonzero
FAKE_PROBE_OUT="AGENT-VM-BRIDGE-REGISTERED models=12"
FAKE_PI_PROBE_STATUS=1
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a probe that prints its marker then exits nonzero must fail"
assert_contains "$RUN_OUTPUT" "the bridge probe exited 1"

# Regression (surfaced by a real pi layer build): the real Pi RPC prints the
# registration marker inside a single-line JSON notification, so the count is
# followed immediately by `","notifyType":...}`. The gate must read the digits
# (12), not reject the trailing JSON as a non-numeric count.
new_case bridge-probe-json-embedded
FAKE_PROBE_OUT='{"type":"notification","message":"AGENT-VM-BRIDGE-REGISTERED models=12","notifyType":"warning"}'
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a JSON-wrapped registration marker must pass: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "pi-claude-bridge registered the claude-bridge provider"

# SP5: a zero-padded zero is not a positive canonical count.
new_case bridge-probe-zero-padded
FAKE_PROBE_OUT="AGENT-VM-BRIDGE-REGISTERED models=00"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a zero-padded zero model count must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "model catalog is empty"

# SP5: a plain line with trailing garbage is neither a complete marker line nor
# valid JSON; it must not be read as a positive count.
new_case bridge-probe-trailing-garbage
FAKE_PROBE_OUT='AGENT-VM-BRIDGE-REGISTERED models=12"garbage'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a marker with trailing garbage must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "non-numeric model count"

# SP5: a positive marker contradicted by a later MISSING is ambiguous.
new_case bridge-probe-contradictory
FAKE_PROBE_OUT=$(printf 'AGENT-VM-BRIDGE-REGISTERED models=12\nAGENT-VM-BRIDGE-MISSING')
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "conflicting registration results must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "conflicting registration results"

# SP5: a registration-bearing line whose JSON is malformed must be REJECTED, not
# erased. `jq ... || true` used to empty it, so a positive marker followed by a
# truncated `{"message":"AGENT-VM-BRIDGE-MISSING"` silently published
# `installed`; the contradictory marker must fail closed.
new_case bridge-probe-malformed-json-contradiction
FAKE_PROBE_OUT=$(printf 'AGENT-VM-BRIDGE-REGISTERED models=12\n{"message":"AGENT-VM-BRIDGE-MISSING"')
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a malformed JSON registration line must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "malformed registration line"

# SP5: the same malformed JSON must fail with the soft-fail input nonempty,
# including the literal `0` (bridge health is never a function of soft input).
new_case bridge-probe-malformed-json-contradiction-soft
SOFT=0
FAKE_PROBE_OUT=$(printf 'AGENT-VM-BRIDGE-REGISTERED models=12\n{"message":"AGENT-VM-BRIDGE-MISSING"')
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a malformed JSON registration line must fail with soft=0: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "malformed registration line"

# SP5: the same malformed/contradictory results must be rejected with the
# soft-fail input nonempty -- bridge health is never a function of soft input.
new_case bridge-probe-zero-padded-soft
SOFT=1
FAKE_PROBE_OUT="AGENT-VM-BRIDGE-REGISTERED models=00"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a zero-padded zero count must fail even with soft input: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "model catalog is empty"

# D2: a registration-bearing JSON line with an unexpected shape -- `.message` is
# null while the marker sits in another field -- must fail closed rather than be
# silently erased (`else empty` used to let a lone positive marker pass).
new_case bridge-probe-null-message
FAKE_PROBE_OUT=$(printf 'AGENT-VM-BRIDGE-REGISTERED models=12\n{"message":null,"marker":"AGENT-VM-BRIDGE-MISSING"}')
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a JSON line with a null message but a MISSING marker must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "malformed registration line"

# D2: unrelated RPC output that carries no marker is still accepted.
new_case bridge-probe-unrelated-json
FAKE_PROBE_OUT=$(printf 'AGENT-VM-BRIDGE-REGISTERED models=12\n{"type":"log","text":"unrelated rpc output"}')
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "unrelated RPC output must be accepted: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "pi-claude-bridge registered the claude-bridge provider"

new_case bridge-probe-contradictory-soft
SOFT=1
FAKE_PROBE_OUT=$(printf 'AGENT-VM-BRIDGE-REGISTERED models=12\nAGENT-VM-BRIDGE-MISSING')
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "conflicting results must fail even with soft input: $RUN_OUTPUT"

new_case bridge-probe-missing-soft
SOFT=1
FAKE_PROBE_OUT="AGENT-VM-BRIDGE-MISSING"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a non-registering bridge must fail even with soft input: $RUN_OUTPUT"

# --- happy path records BOTH slots installed --------------------------------

new_case happy
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the happy path must succeed: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "pi: 0.87.1 (pinned)"
assert_contains "$RUN_OUTPUT" "subcommand allowlist matches pi --help"
assert_contains "$RUN_OUTPUT" "mandatory extension loads and warns"
assert_contains "$RUN_OUTPUT" "pi-claude-bridge registered the claude-bridge provider"
assert_contains "$RUN_OUTPUT" "tool-access: ok"
assert_contains "$RUN_OUTPUT" "readable and executable by any uid"
[[ "$(cat "$CASE/status/pi")" == "installed" ]] || fail "the gate must record pi installed"
[[ "$(cat "$CASE/status/pi-claude-bridge")" == "installed" ]] \
    || fail "the gate must record the bridge installed"

# --- SP2: a present-but-unusable command must NOT be treated as absent -------

# A 0644 entry point with a valid absence record is a contract violation: the
# command is present, so the record cannot waive it, and its tree must survive.
new_case present-unusable-command
write_status pi 'absent-transport 6'
chmod 0644 "$CASE/prefix/node_modules/.bin/pi"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a present 0644 command must fail even with an absence record"
[[ -e "$CASE/prefix/node_modules/.bin/pi" ]] || fail "the present command must not be deleted"
[[ -e "$CASE/prefix" ]] || fail "the present prefix must not be deleted"

# A dangling symlink is present (lstat succeeds); the record must not waive it.
new_case dangling-command
write_status pi 'absent-transport 6'
rm -f "$CASE/prefix/node_modules/.bin/pi"
ln -s nowhere "$CASE/prefix/node_modules/.bin/pi"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a dangling command symlink must fail even with an absence record"

# A malformed multi-line record is not a valid absence.
new_case malformed-absence-record
drop_pi
printf 'absent-transport 6\njunk\n' >"$CASE/status/pi"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a multi-line absence record must not be accepted"

# An unknown transport code is not a valid absence.
new_case unknown-absence-code
drop_pi
printf 'absent-transport 99\n' >"$CASE/status/pi"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an unknown transport code must not be accepted"

# --- SP3: the real npm transport vocabulary is accepted ----------------------
# install-pi.sh writes `absent-transport EAI_AGAIN` (an npm code), never a curl
# number; the gate must accept the union of both classified vocabularies.
new_case missing-pi-npm-absent
drop_pi
write_status pi 'absent-transport EAI_AGAIN'
write_status pi-claude-bridge 'absent-transport EAI_AGAIN'
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a recorded npm transport absence must be accepted: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "pi: ABSENT"

new_case bridge-npm-absent
drop_bridge
write_status pi-claude-bridge 'absent-transport ENOTFOUND'
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a recorded npm bridge absence must be accepted: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "pi-claude-bridge ABSENT"

# --- SP5: ambiguous reports and non-positive model counts --------------------

# An extra version line must be rejected (a bare `while read` silently drops a
# final line with no trailing newline, letting the ambiguous report pass).
new_case extra-version-line
FAKE_PI_REPORT=$(printf '0.87.1\n9.9.9')
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an ambiguous multi-line Pi report must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "unexpected --version output"

new_case negative-model-count
FAKE_PROBE_OUT='AGENT-VM-BRIDGE-REGISTERED models=-1'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a negative model count must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "non-numeric model count"

# --- ST2: destructive seams cannot delete an unauthorised tree ---------------
# A seam pointing outside the fixture root must be refused and the target must
# survive untouched.
new_case destructive-outside-fixture
drop_pi
write_status pi 'absent-transport 6'
outside="$TEST_ROOT/outside-$RANDOM"
mkdir -p "$outside"
printf 'do not delete\n' >"$outside/marker"
set +e
RUN_OUTPUT="$(env -i \
    "PATH=$TIMEOUT_DIR:$PYTHON_DIR:$JQ_DIR:/usr/bin:/bin" \
    "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
    "AGENT_VM_PI_PREFIX=$outside" \
    "AGENT_VM_PI_WRAPPER=$CASE/wrapper" \
    "AGENT_VM_PI_PACKAGES_PREFIX=$CASE/packages" \
    "AGENT_VM_PI_EXTENSION_DIR=$CASE/ext" \
    "AGENT_VM_PI_GATE_WORK_DIR=$CASE/gate" \
    "AGENT_VM_PI_SEED_HOOK=$CASE/seed-hook" \
    "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
    "AGENT_VM_FIXTURE_ROOT=$CASE" \
    sh "$GATE" 2>&1)"
RUN_STATUS=$?
set -e
[[ $RUN_STATUS -ne 0 ]] || fail "a destructive seam outside the fixture root must be refused"
[[ -f "$outside/marker" ]] || fail "an unauthorised tree was deleted"

# --- D1: required extension content resolves symlinks -----------------------
# The tree walk uses `find`, which does not follow symlinks, so a required file
# symlinked into a 0700 directory (holding a 0600 source) passed it. `--content`
# resolves the link and audits the target ancestors.

new_case extension-private-target
rm -f "$CASE/ext/guest-credential-warning.js"
mkdir -p "$CASE/private-ext"
printf '// warning\n' >"$CASE/private-ext/warn.js"
chmod 0600 "$CASE/private-ext/warn.js"
chmod 0700 "$CASE/private-ext"
ln -s "$CASE/private-ext/warn.js" "$CASE/ext/guest-credential-warning.js"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a mandatory extension symlinked into a 0700 directory must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "private-ext"

new_case bridge-source-private-target
rm -f "$CASE/packages/node_modules/pi-claude-bridge/src/index.ts"
mkdir -p "$CASE/private-bridge"
printf 'export default function(){}\n' >"$CASE/private-bridge/index.ts"
chmod 0600 "$CASE/private-bridge/index.ts"
chmod 0700 "$CASE/private-bridge"
ln -s "$CASE/private-bridge/index.ts" \
    "$CASE/packages/node_modules/pi-claude-bridge/src/index.ts"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a bridge source symlinked into a 0700 directory must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "private-bridge"

# A symlink into a world-open directory is fine: the repair is opening the
# target ancestors, not forbidding symlinks.
new_case extension-repaired-symlink
rm -f "$CASE/ext/guest-credential-warning.js"
mkdir -p "$CASE/open-ext"
printf '// warning\n' >"$CASE/open-ext/warn.js"
chmod 0755 "$CASE/open-ext"
chmod 0644 "$CASE/open-ext/warn.js"
ln -s "$CASE/open-ext/warn.js" "$CASE/ext/guest-credential-warning.js"
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a repaired symlinked extension must pass: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "readable and executable by any uid"

# --- D6: the tree predicate is all-class, not other-only --------------------
# A file that is readable by owner and other but NOT group (0604) must be
# rejected by `! -perm -444`. Weakening the predicate to `! -perm -o+r` would
# accept it, so this case discriminates the two.
new_case all-class-unreadable-file
printf '// payload\n' >"$CASE/prefix/group-hidden.js"
chmod 0604 "$CASE/prefix/group-hidden.js"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a file unreadable by group must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "not world-readable"
chmod 0444 "$CASE/prefix/group-hidden.js"
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the repaired file must pass: $RUN_OUTPUT"

# A directory readable by all but searchable only by owner and other (0745) is
# accepted by `-perm -444` and must be rejected by `! -perm -111`; weakening the
# directory predicate to `! -perm -o+x` would accept it.
new_case all-class-unsearchable-dir
mkdir -p "$CASE/prefix/group-search-dir"
chmod 0745 "$CASE/prefix/group-search-dir"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a directory unsearchable by group must fail: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "not world-searchable"
chmod 0755 "$CASE/prefix/group-search-dir"
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the repaired directory must pass: $RUN_OUTPUT"

# --- the test seams cannot become production defaults -----------------------

# shellcheck disable=SC2016  # single quotes keep the literal grep patterns
grep -Fq 'AGENT_VM_PI_PREFIX:-/opt/agent-vm/pi}' "$GATE" \
    || fail "production default pi prefix is missing"
grep -Fq 'AGENT_VM_PI_WRAPPER:-/usr/local/bin/pi}' "$GATE" \
    || fail "production default wrapper path is missing"
grep -Fq 'AGENT_VM_PI_PACKAGES_PREFIX:-/opt/agent-vm/pi-packages}' "$GATE" \
    || fail "production default packages prefix is missing"
grep -Fq 'AGENT_VM_PI_EXTENSION_DIR:-/opt/agent-vm/pi-extensions}' "$GATE" \
    || fail "production default extension dir is missing"
grep -Fq 'AGENT_VM_PI_SEED_HOOK:-/opt/agent-vm/seed.d/20-pi-claude-bridge}' "$GATE" \
    || fail "production default seed hook path is missing"
grep -Fq 'AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}' "$GATE" \
    || fail "production default status dir is missing"

echo 'pi-verify black-box tests passed'
