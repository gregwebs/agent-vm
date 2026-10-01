#!/usr/bin/env bash
# Black-box contract tests for the dsh layer's build gate
# (images/tools/dsh/verify-dsh.sh).
#
# No Docker, no npm, no real dsh: `dsh` and `pnpm` are faked on PATH and the
# manifest is a fixture, so every branch -- missing binary, the exit-0-with-no-
# output trap an old Node produces, a version that differs from the pin, a
# missing pnpm, a matching report followed by a nonzero exit, an extra output
# line, a supplied slot that disagrees with the effective manifest, and the
# happy path -- is exercised hermetically. jq is the real one (reading the pins
# from the manifest is part of what is under test), the real run-report.sh and
# check-tool-access.py back the gate, and the status record is written under a
# case temp root.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
GATE="$REPO_ROOT/images/tools/dsh/verify-dsh.sh"
CONTRACT="$REPO_ROOT/images/tools/dsh/contract"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dsh-verify-test.XXXXXX")"
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

make_tool() {
    local name="$1"
    cat >"$CASE/bin/$name"
    chmod +x "$CASE/bin/$name"
}

new_case() {
    unset AGENT_INSTALL_SOFT_FAIL AGENT_VM_VERSION_DSH AGENT_VM_VERSION_PNPM
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/bin" "$CASE/status"
    chmod 0755 "$CASE" "$CASE/bin"
    printf '{"dependencies":{"@deepseek-ai/dsh":"0.0.0-fixture","pnpm":"11.7.0"}}\n' >"$CASE/package.json"
}

# `$1` = dsh script body (omitted entirely = no dsh on PATH).
write_dsh() {
    make_tool dsh <<SH
#!/usr/bin/env bash
$1
SH
}

# `$1` = pnpm script body (omitted entirely = no pnpm on PATH).
write_pnpm() {
    make_tool pnpm <<SH
#!/usr/bin/env bash
$1
SH
}

run_gate() {
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$CASE/bin:$TIMEOUT_DIR:$PYTHON_DIR:$JQ_DIR:/usr/bin:/bin" \
        "DSH_MANIFEST=$CASE/package.json" \
        "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
        "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
        "AGENT_VM_VERSION_DSH=${AGENT_VM_VERSION_DSH-}" \
        "AGENT_VM_VERSION_PNPM=${AGENT_VM_VERSION_PNPM-}" \
        "AGENT_INSTALL_SOFT_FAIL=${AGENT_INSTALL_SOFT_FAIL-}" \
        sh "$GATE" 2>&1)"
    RUN_STATUS=$?
    set -e
}

# --- missing binaries: hard failure -----------------------------------------

new_case missing-dsh
write_pnpm 'printf "11.7.0\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing dsh must be a hard failure"
assert_contains "$RUN_OUTPUT" "dsh: MISSING"

new_case missing-dsh-soft
write_pnpm 'printf "11.7.0\n"'
AGENT_INSTALL_SOFT_FAIL=1
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "dsh is never soft-failable"

new_case missing-pnpm
write_dsh 'printf "0.0.0-fixture\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing pnpm must be a hard failure"
assert_contains "$RUN_OUTPUT" "pnpm: MISSING"

# --- the old-Node trap: exit 0, no output -----------------------------------

new_case empty-version
write_dsh 'exit 0'
write_pnpm 'printf "11.7.0\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an empty --version must be a hard failure"
assert_contains "$RUN_OUTPUT" "empty --version output"

new_case empty-version-soft
write_dsh 'exit 0'
write_pnpm 'printf "11.7.0\n"'
AGENT_INSTALL_SOFT_FAIL=1
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an empty --version must fail even under soft-fail"

# --- version mismatch (each slot) -------------------------------------------

new_case wrong-dsh
write_dsh 'printf "9.9.9\n"'
write_pnpm 'printf "11.7.0\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a dsh version differing from the pin must fail"
assert_contains "$RUN_OUTPUT" "installed 9.9.9 but package.json pins 0.0.0-fixture"

new_case wrong-pnpm
write_dsh 'printf "0.0.0-fixture\n"'
write_pnpm 'printf "9.9.9\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a pnpm version differing from the pin must fail"
assert_contains "$RUN_OUTPUT" "installed 9.9.9 but package.json pins 11.7.0"

# --- status is checked BEFORE parsing ---------------------------------------

new_case nonzero-after-print
write_dsh 'printf "0.0.0-fixture\n"; exit 1'
write_pnpm 'printf "11.7.0\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "printing the pin then exiting nonzero must fail"
assert_contains "$RUN_OUTPUT" "--version exited 1"

new_case extra-line
write_dsh 'printf "0.0.0-fixture\nwarning: something\n"'
write_pnpm 'printf "11.7.0\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "extra --version output must fail"
assert_contains "$RUN_OUTPUT" "unexpected --version output"

# --- a supplied slot must agree with the effective manifest -----------------

new_case supplied-mismatch
write_dsh 'printf "0.0.0-fixture\n"'
write_pnpm 'printf "11.7.0\n"'
AGENT_VM_VERSION_DSH=9.9.9
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a supplied slot disagreeing with the manifest must fail"
assert_contains "$RUN_OUTPUT" "layer asked for 9.9.9 but the manifest pins 0.0.0-fixture"

# --- happy path: record installed -------------------------------------------

new_case happy
write_dsh 'printf "0.0.0-fixture\n"'
write_pnpm 'printf "11.7.0\n"'
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the happy path must succeed: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "dsh: 0.0.0-fixture (pnpm 11.7.0)"
assert_contains "$RUN_OUTPUT" "tool-access: ok"
[[ "$(cat "$CASE/status/dsh")" == "installed" ]] || fail "the gate must record installed"

# --- the test seam cannot become the production default ----------------------

# shellcheck disable=SC2016  # single quotes keep the literal grep pattern
grep -Fq 'DSH_MANIFEST:-$PREFIX/package.json}"' "$GATE" \
    || fail "production default manifest path is missing"
grep -Fq 'AGENT_VM_DSH_PREFIX:-/opt/agent-vm/dsh}' "$GATE" \
    || fail "production default prefix is missing"
grep -Fq 'AGENT_VM_INSTALL_STATUS_DIR:-/opt/agent-vm/install-status}' "$GATE" \
    || fail "production default status dir is missing"

echo 'dsh-verify black-box tests passed'
