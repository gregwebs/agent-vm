#!/usr/bin/env bash
# Black-box contract tests for the dsh layer's build gate
# (images/tools/dsh/verify-dsh.sh).
#
# No Docker, no npm, no real dsh: `dsh` and `pnpm` are faked on PATH and the
# manifest is a fixture, so every branch -- missing binary, the exit-0-with-no-
# output trap an old Node produces, a version that differs from the pin, a
# missing pnpm, and the happy path -- is exercised hermetically. jq is the real
# one, since reading the pin from the manifest is part of what is under test.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
GATE="$REPO_ROOT/images/tools/dsh/verify-dsh.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dsh-verify-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

REAL_JQ="$(command -v jq || true)"
[[ -n "$REAL_JQ" ]] || { echo "FAIL: jq is required" >&2; exit 1; }
JQ_DIR="$(dirname "$REAL_JQ")"

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
    unset AGENT_INSTALL_SOFT_FAIL
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/bin"
    printf '{"dependencies":{"@deepseek-ai/dsh":"0.0.0-fixture"}}\n' >"$CASE/package.json"
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
        "PATH=$CASE/bin:$JQ_DIR:/usr/bin:/bin" \
        "DSH_MANIFEST=$CASE/package.json" \
        "AGENT_INSTALL_SOFT_FAIL=${AGENT_INSTALL_SOFT_FAIL-}" \
        sh "$GATE" 2>&1)"
    RUN_STATUS=$?
    set -e
}

# --- missing binary: hard failure -------------------------------------------

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

# --- version mismatch -------------------------------------------------------

new_case wrong-version
write_dsh 'printf "9.9.9\n"'
write_pnpm 'printf "11.7.0\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a version differing from the pin must fail"
assert_contains "$RUN_OUTPUT" "package.json pins 0.0.0-fixture"

# --- pnpm missing -----------------------------------------------------------

new_case missing-pnpm
write_dsh 'printf "0.0.0-fixture\n"'
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing pnpm must be a hard failure"
assert_contains "$RUN_OUTPUT" "pnpm: MISSING"

# --- happy path -------------------------------------------------------------

new_case happy
write_dsh 'printf "0.0.0-fixture\n"'
write_pnpm 'printf "11.7.0\n"'
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the happy path must succeed: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "dsh: 0.0.0-fixture (pnpm 11.7.0)"

# --- the test seam cannot become the production default ----------------------

grep -Fq 'DSH_MANIFEST:-/opt/agent-vm/dsh/package.json}"' "$GATE" \
    || fail "production default manifest path is missing"

echo 'dsh-verify black-box tests passed'
