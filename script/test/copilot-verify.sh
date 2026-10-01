#!/usr/bin/env bash
# Black-box contract tests for the copilot layer's build gate
# (images/tools/copilot/verify-copilot.sh).
#
# No Docker, no npm, no real copilot: `copilot` is faked on PATH and the
# expected version is passed in, so every branch -- wrong version, an extra
# output line, a prefix match, a banner-shaped warning, a nonzero exit and a
# missing command -- is exercised hermetically. The real run-report.sh and
# check-tool-access.py are used, since status handling and the T5 audit are part
# of what is under test.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
GATE="$REPO_ROOT/images/tools/copilot/verify-copilot.sh"
CONTRACT="$REPO_ROOT/images/recipe-contract"

TEST_ROOT="$(mktemp -d /tmp/copilot-verify.XXXXXX)"
chmod 0755 "$TEST_ROOT"
trap 'rm -rf "$TEST_ROOT"' EXIT

PYTHON_DIR="$(dirname "$(command -v python3)")"
TIMEOUT_DIR="$(dirname "$(command -v timeout)")"
CASE=""

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
assert_contains() { [[ "$1" == *"$2"* ]] || fail "expected '$2' in: $1"; }

new_case() {
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/bin"
    chmod 0755 "$CASE"
}

# make_copilot <body>; omitted body = no copilot on PATH.
make_copilot() {
    cat >"$CASE/bin/copilot"
    chmod 0755 "$CASE/bin/copilot"
}

run_gate() {
    set +e
    RUN_OUTPUT="$(
        env -i \
            "PATH=$CASE/bin:$TIMEOUT_DIR:$PYTHON_DIR:/usr/bin:/bin" \
            "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
            "AGENT_VM_VERSION_COPILOT=${WANT-}" \
            "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
            sh "$GATE" 2>&1
    )"
    RUN_STATUS=$?
    set -e
}

# --- happy path --------------------------------------------------------------

WANT=1.0.90
new_case ok
make_copilot <<'SH'
#!/bin/sh
printf 'GitHub Copilot CLI 1.0.90.\n'
printf "Run 'copilot update' to check for updates.\n"
SH
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the pinned version must pass: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "copilot: 1.0.90 (pinned)"
# The healthy slot is recorded only after report/equality/T5 all pass; an
# external audit reads this record as necessary-but-insufficient evidence.
[[ -f "$CASE/status/copilot" ]] || fail "the gate must record the installed status"
[[ "$(cat "$CASE/status/copilot")" == installed ]] ||
    fail "the copilot status record must read 'installed'"

# --- version mismatch --------------------------------------------------------

new_case mismatch
make_copilot <<'SH'
#!/bin/sh
printf 'GitHub Copilot CLI 1.0.91.\n'
printf "Run 'copilot update' to check for updates.\n"
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a wrong installed version must fail"
assert_contains "$RUN_OUTPUT" "installed 1.0.91"

# --- 1.0.90 is not 1.0.900 ---------------------------------------------------

new_case prefix
make_copilot <<'SH'
#!/bin/sh
printf 'GitHub Copilot CLI 1.0.900.\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "1.0.900 must not satisfy a 1.0.90 pin"

# --- a version-shaped warning on the first line is not a banner --------------

new_case warning
make_copilot <<'SH'
#!/bin/sh
printf 'warning: expected 1.0.90\n'
printf 'GitHub Copilot CLI 1.0.90.\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a version-shaped warning must not be accepted"
assert_contains "$RUN_OUTPUT" "unrecognized"

# --- an extra unexpected line ------------------------------------------------

new_case extra-line
make_copilot <<'SH'
#!/bin/sh
printf 'GitHub Copilot CLI 1.0.90.\n'
printf 'Run '\''copilot update'\'' to check for updates.\n'
printf 'mystery\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an unexpected extra line must fail"
assert_contains "$RUN_OUTPUT" "unexpected"

# B1: a contradictory banner on stderr must not certify the slot.
new_case stderr-contradictory
make_copilot <<'SH'
#!/bin/sh
printf 'GitHub Copilot CLI 1.0.90.\n'
printf "Run 'copilot update' to check for updates.\n"
printf 'GitHub Copilot CLI 9.9.9.\n' >&2
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a contradictory banner on stderr must fail"

# C2: a NUL inside the report must be rejected, not erased by substitution.
new_case nul-in-report
make_copilot <<'SH'
#!/bin/sh
printf 'GitHub Copilot CLI 1.0.\00090.\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a NUL inside the report must fail"

# --- prints the expected version then exits nonzero --------------------------

new_case nonzero
make_copilot <<'SH'
#!/bin/sh
printf 'GitHub Copilot CLI 1.0.90.\n'
exit 3
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a nonzero exit must fail even with the right version"
assert_contains "$RUN_OUTPUT" "exited 3"

# --- empty output ------------------------------------------------------------

new_case empty
make_copilot <<'SH'
#!/bin/sh
exit 0
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "empty output must fail"
assert_contains "$RUN_OUTPUT" "unrecognized"

# --- missing command ---------------------------------------------------------

new_case missing
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing copilot must fail"

echo "copilot-verify black-box tests passed"
