#!/usr/bin/env bash
# Black-box tests for the claude layer's install hook and build gate
# (images/tools/claude/{install-claude.sh,verify-claude.sh}) and for the
# vendored installer patch reproduction.
#
# No Docker, no network: the vendored installer is faked on a temp prefix and
# the real run-install/report/download/check-tool-access helpers are used where
# they are part of what is under test. This exercises the exact-version
# validation, the classified transport softening (and every way it must NOT
# soften), and the report/T5 gate.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
VENDOR_SRC="$REPO_ROOT/images/tools/claude/vendor"
INSTALL="$REPO_ROOT/images/tools/claude/install-claude.sh"
VERIFY="$REPO_ROOT/images/tools/claude/verify-claude.sh"
CONTRACT="$REPO_ROOT/images/recipe-contract"

TEST_ROOT="$(mktemp -d /tmp/claude-installer.XXXXXX)"
chmod 0755 "$TEST_ROOT"
trap 'rm -rf "$TEST_ROOT"' EXIT

PYTHON_DIR="$(dirname "$(command -v python3)")"
TIMEOUT_DIR="$(dirname "$(command -v timeout)")"
CASE=""

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# --- 1. the patch reproduces the committed runnable installer ----------------

patch_case="$TEST_ROOT/patch"
mkdir -p "$patch_case"
chmod 0755 "$patch_case"
cp "$VENDOR_SRC/install.upstream.sh" "$patch_case/install.sh"
(
    cd "$patch_case"
    git apply -p1 <"$VENDOR_SRC/install.patch"
)
cmp "$patch_case/install.sh" "$VENDOR_SRC/install.sh" ||
    fail "install.patch does not reproduce vendor/install.sh byte-for-byte"

# --- 2. install-claude.sh black-box ------------------------------------------

new_case() {
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/vendor" "$CASE/prefix" "$CASE/status"
    chmod 0755 "$CASE" "$CASE/prefix" "$CASE/status"

    # Fake vendored installer. It honours FAKE_EXIT/FAKE_RECEIPT and records
    # that it ran, so exact-version rejections can prove the installer was
    # never invoked. It reads the receipt path the hook exports, like the real
    # patched installer's download.sh does.
    cat >"$CASE/vendor/install.sh" <<'SH'
#!/bin/sh
if [ -n "${FAKE_SENTINEL:-}" ]; then printf 'ran\n' >>"$FAKE_SENTINEL"; fi
if [ -n "${FAKE_RECEIPT:-}" ] && [ -n "${AGENT_VM_TRANSPORT_RECEIPT:-}" ]; then
    printf '%s\n' "$FAKE_RECEIPT" >"$AGENT_VM_TRANSPORT_RECEIPT"
fi
exit "${FAKE_EXIT:-0}"
SH
    chmod 0755 "$CASE/vendor/install.sh"
}

# run_install <version>; env: FAKE_EXIT, FAKE_RECEIPT, SOFT, NO_RECEIPT
run_install() {
    local version="$1"
    local receipt_val="$CASE/receipt"
    [[ "${NO_RECEIPT:-}" == 1 ]] && receipt_val=""
    set +e
    RUN_OUTPUT="$(
        env -i \
            "PATH=/usr/bin:/bin" \
            "AGENT_VM_VENDOR_DIR=$CASE/vendor" \
            "AGENT_VM_CLAUDE_PREFIX=$CASE/prefix" \
            "AGENT_VM_FIXTURE_ROOT=$CASE" \
            "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
            "AGENT_VM_VERSION_CLAUDE=$version" \
            "FAKE_SENTINEL=$CASE/ran" \
            "FAKE_EXIT=${FAKE_EXIT:-0}" \
            "FAKE_RECEIPT=${FAKE_RECEIPT:-}" \
            "AGENT_VM_TRANSPORT_RECEIPT=$receipt_val" \
            ${SOFT:+"AGENT_INSTALL_SOFT_FAIL=$SOFT"} \
            sh "$INSTALL" 2>&1
    )"
    RUN_STATUS=$?
    set -e
}

new_case success
SOFT=
run_install 2.1.286
[[ $RUN_STATUS -eq 0 ]] || fail "a clean install must pass: $RUN_OUTPUT"
[[ -f "$CASE/ran" ]] || fail "the vendored installer must run on a valid version"
[[ ! -e "$CASE/status/claude" ]] || fail "the hook must not write installed itself"

# floating / non-exact versions are rejected BEFORE the installer runs
for bad in latest stable '^1.0.0' '1.0' '1.0.0 2.0.0' 'https://x/2.1.286' '2.1.286 ' \
    '01.2.3' '1.02.3' '1.2.03' '1.2.3-01' '1.2.3-alpha.01'; do
    new_case "reject-$(printf '%s' "$bad" | tr -c 'A-Za-z0-9' '_')"
    SOFT=
    run_install "$bad"
    [[ $RUN_STATUS -ne 0 ]] || fail "version '$bad' must be rejected"
    [[ ! -f "$CASE/ran" ]] || fail "version '$bad' must be rejected before the installer runs"
done

# Canonical prerelease/build metadata the pinned installer supports is accepted.
for good in 1.2.3-rc.1 1.2.3-alpha; do
    new_case "accept-$(printf '%s' "$good" | tr -c 'A-Za-z0-9' '_')"
    SOFT=
    run_install "$good"
    [[ $RUN_STATUS -eq 0 ]] || fail "canonical version '$good' must be accepted: $RUN_OUTPUT"
    [[ -f "$CASE/ran" ]] || fail "canonical version '$good' must reach the vendor"
done

new_case empty
SOFT=
run_install ""
[[ $RUN_STATUS -ne 0 ]] || fail "an empty version must be rejected"

# a classified transport 75 with a fresh receipt softens when asked
new_case transport-soft
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=1
mkdir -p "$CASE/prefix/.claude/downloads" "$CASE/prefix/.local/bin"
touch "$CASE/prefix/.claude/downloads/partial" "$CASE/prefix/.local/bin/claude"
run_install 2.1.286
[[ $RUN_STATUS -eq 0 ]] || fail "a classified transport failure must soften: $RUN_OUTPUT"
[[ "$(cat "$CASE/status/claude")" == "absent-transport 6" ]] ||
    fail "softened install must write an absence record"
[[ ! -e "$CASE/prefix/.claude/downloads" ]] || fail "the download cache must be cleaned"
[[ ! -e "$CASE/prefix/.local/bin/claude" ]] || fail "the half-published command must be cleaned"
unset FAKE_EXIT FAKE_RECEIPT SOFT

# B6: an env-overridden prefix that is a symlink escaping the fixture root must
# not authorise deletion of another real tree. The marker outside must survive.
new_case transport-soft-symlink-escape
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=1
outside="$TEST_ROOT/other-tree-$RANDOM"
mkdir -p "$outside/.claude/downloads" "$outside/.local/bin"
printf 'do not delete\n' >"$outside/.claude/downloads/marker"
printf 'cmd\n' >"$outside/.local/bin/claude"
rm -rf "$CASE/prefix"
ln -s "$outside" "$CASE/prefix"
run_install 2.1.286
[[ $RUN_STATUS -ne 0 ]] || fail "a symlinked escaped prefix must be refused"
[[ -f "$outside/.claude/downloads/marker" ]] || fail "an unauthorised tree was deleted"
[[ -f "$outside/.local/bin/claude" ]] || fail "an unauthorised command was deleted"
rm -f "$CASE/prefix"
unset FAKE_EXIT FAKE_RECEIPT SOFT

# ...but not without AGENT_INSTALL_SOFT_FAIL
new_case transport-no-soft
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=
run_install 2.1.286
[[ $RUN_STATUS -ne 0 ]] || fail "a transport failure without soft-fail must be hard"
[[ ! -e "$CASE/status/claude" ]] || fail "a hard failure must not leave an absence record"
unset FAKE_EXIT FAKE_RECEIPT SOFT

# ...and only for a receipt with the right operation
new_case transport-wrong-op
FAKE_EXIT=75
FAKE_RECEIPT='transport npm 6'
SOFT=1
run_install 2.1.286
[[ $RUN_STATUS -ne 0 ]] || fail "an npm receipt must not soften a native install"
unset FAKE_EXIT FAKE_RECEIPT SOFT

# a bare 75 with no receipt is never classified
new_case bare-75
FAKE_EXIT=75
FAKE_RECEIPT=''
SOFT=1
run_install 2.1.286
[[ $RUN_STATUS -ne 0 ]] || fail "an arbitrary 75 must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT

# an unknown installer failure is hard even with soft input
new_case unknown-failure
FAKE_EXIT=3
FAKE_RECEIPT=''
SOFT=1
run_install 2.1.286
[[ $RUN_STATUS -ne 0 ]] || fail "an unknown installer exit must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT

# no receipt environment at all: a 75 cannot be classified
new_case no-receipt-env
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=1
NO_RECEIPT=1
run_install 2.1.286
[[ $RUN_STATUS -ne 0 ]] || fail "a 75 without a receipt path must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT NO_RECEIPT

# --- 3. verify-claude.sh black-box -------------------------------------------

new_gate_case() {
    CASE="$TEST_ROOT/gate-$1"
    mkdir -p "$CASE/prefix/.local/bin" "$CASE/status"
    chmod 0755 "$CASE" "$CASE/prefix" "$CASE/prefix/.local/bin" "$CASE/status"
    GATE_BIN="$CASE/prefix/.local/bin/claude"
}

make_claude() {
    cat >"$GATE_BIN"
    chmod 0755 "$GATE_BIN"
}

run_gate() {
    set +e
    RUN_OUTPUT="$(
        env -i \
            "PATH=$CASE/prefix/.local/bin:$TIMEOUT_DIR:$PYTHON_DIR:/usr/bin:/bin" \
            "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
            "AGENT_VM_CLAUDE_PREFIX=$CASE/prefix" \
            "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
            "AGENT_VM_VERSION_CLAUDE=${WANT-}" \
            sh "$VERIFY" 2>&1
    )"
    RUN_STATUS=$?
    set -e
}

WANT=2.1.286
new_gate_case ok
make_claude <<'SH'
#!/bin/sh
[ "$1" = --version ] || exit 2
printf '2.1.286 (Claude Code)\n'
SH
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the pinned version must pass: $RUN_OUTPUT"
[[ "$(cat "$CASE/status/claude")" == "installed" ]] ||
    fail "a passing gate must record installed"

WANT=2.1.286
new_gate_case mismatch
make_claude <<'SH'
#!/bin/sh
printf '2.1.285 (Claude Code)\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a wrong installed version must fail"
[[ ! -e "$CASE/status/claude" ]] || fail "a failed gate must not record installed"

WANT=2.1.286
new_gate_case prefix
make_claude <<'SH'
#!/bin/sh
printf '2.1.2860 (Claude Code)\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "2.1.2860 must not satisfy a 2.1.286 pin"

WANT=2.1.286
new_gate_case extra
make_claude <<'SH'
#!/bin/sh
printf '2.1.286 (Claude Code)\n'
printf 'warning: 2.1.286\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a warning on a later line must not be accepted"

# B1: a contradictory version banner on the captured stderr must not certify the
# slot; the gate must reject it rather than discard it on exit 0.
WANT=2.1.286
new_gate_case stderr-contradictory
make_claude <<'SH'
#!/bin/sh
printf '2.1.286 (Claude Code)\n'
printf '9.9.9 (Claude Code)\n' >&2
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a contradictory banner on stderr must fail"

# C2: a NUL byte inside the report is exact-byte corruption, not a report the
# shell may canonicalize by erasing the NUL during command substitution.
WANT=2.1.286
new_gate_case nul-in-report
make_claude <<'SH'
#!/bin/sh
printf '2.1.286\000 (Claude Code)\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a NUL inside the report must fail"

# SP5: an unterminated trailing report line (no final newline) must still fail;
# a bare `while read` drops it.
WANT=2.1.286
new_gate_case unterminated-trailing
make_claude <<'SH'
#!/bin/sh
printf '2.1.286 (Claude Code)\nUNRECOGNIZED TRAILING REPORT'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an unterminated trailing report line must be rejected"

WANT=2.1.286
new_gate_case leading-warning
make_claude <<'SH'
#!/bin/sh
printf 'warning: expected 2.1.286\n'
printf '2.1.286 (Claude Code)\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a leading warning line must not be accepted"

WANT=2.1.286
new_gate_case nonzero
make_claude <<'SH'
#!/bin/sh
printf '2.1.286 (Claude Code)\n'
exit 1
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "printing the expected version then exiting nonzero must fail"
assert_contains() { [[ "$1" == *"$2"* ]] || fail "expected '$2' in: $1"; }
assert_contains "$RUN_OUTPUT" "exited 1"

# absence with the exact record is accepted (raw developer build only)
WANT=2.1.286
new_gate_case absent
printf 'absent-transport 6\n' >"$CASE/status/claude"
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a recorded absence must be accepted: $RUN_OUTPUT"

# SP2: a dangling symlink is PRESENT (lstat succeeds), so an absence record must
# not waive it.
WANT=2.1.286
new_gate_case dangling
printf 'absent-transport 6\n' >"$CASE/status/claude"
ln -s nowhere "$GATE_BIN"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a dangling command symlink must fail despite the absence record"

# SP2/B2: a dangling ancestor symlink is a present, broken path, not an absence.
WANT=2.1.286
new_gate_case broken-ancestor-dangling
printf 'absent-transport 6\n' >"$CASE/status/claude"
rm -rf "$CASE/prefix/.local"
ln -s nowhere "$CASE/prefix/.local"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a dangling ancestor symlink must not authorise absence"

# SP2/B2: a non-directory ancestor (ENOTDIR) is the same kind of broken path.
WANT=2.1.286
new_gate_case broken-ancestor-notdir
printf 'absent-transport 6\n' >"$CASE/status/claude"
rm -rf "$CASE/prefix/.local"
printf 'not a directory\n' >"$CASE/prefix/.local"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a non-directory ancestor must not authorise absence"

# SP2: a present-but-unusable file is a contract violation, not an absence.
WANT=2.1.286
new_gate_case present-unusable
printf 'absent-transport 6\n' >"$CASE/status/claude"
printf '#!/bin/sh\nexit 0\n' >"$GATE_BIN"
chmod 0644 "$GATE_BIN"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a present 0644 command must fail despite the absence record"
[[ -e "$GATE_BIN" ]] || fail "the present command must not be deleted"

# SP2: an absence line inside a malformed multi-line record is not valid.
WANT=2.1.286
new_gate_case malformed-record
printf 'absent-transport 6\njunk\n' >"$CASE/status/claude"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a multi-line absence record must not be accepted"

# a missing command with no record is hard
WANT=2.1.286
new_gate_case missing
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing command with no record must fail"

# a pending/inherited record is not an absence
WANT=2.1.286
new_gate_case pending
printf 'pending\n' >"$CASE/status/claude"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a pending record must not be accepted as absence"

# T5: a private directory on the command's path fails the audit
WANT=2.1.286
new_gate_case private-path
make_claude <<'SH'
#!/bin/sh
printf '2.1.286 (Claude Code)\n'
SH
chmod 0700 "$CASE/prefix/.local/bin"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a 0700 directory on the command's path must fail T5"

# T5: an unreadable script target fails the audit
WANT=2.1.286
new_gate_case unreadable-target
make_claude <<'SH'
#!/bin/sh
printf '2.1.286 (Claude Code)\n'
SH
chmod 0111 "$GATE_BIN"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an unreadable script target must fail T5"

echo "claude-installer black-box tests passed"
