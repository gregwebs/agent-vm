#!/usr/bin/env bash
# Black-box tests for the codex layer's install hook and build gate
# (images/tools/codex/{install-codex.sh,verify-codex.sh}) and for the vendored
# installer patch reproduction.
#
# No Docker, no network: the vendored installer is faked on a temp prefix and
# the real run-install/report/check-tool-access helpers are used where they are
# part of what is under test. This exercises the exact `rust-v` validation, the
# classified transport softening (and every way it must NOT soften), and the
# report/T5 gate.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
VENDOR_SRC="$REPO_ROOT/images/tools/codex/vendor"
INSTALL="$REPO_ROOT/images/tools/codex/install-codex.sh"
VERIFY="$REPO_ROOT/images/tools/codex/verify-codex.sh"
CONTRACT="$REPO_ROOT/images/recipe-contract"

TEST_ROOT="$(mktemp -d /tmp/codex-installer.XXXXXX)"
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

# --- 2. install-codex.sh black-box -------------------------------------------

new_case() {
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/vendor" "$CASE/prefix" "$CASE/status"
    chmod 0755 "$CASE" "$CASE/prefix" "$CASE/status"

    cat >"$CASE/vendor/install.sh" <<'SH'
#!/bin/sh
if [ -n "${FAKE_OPLOG:-}" ]; then
    printf 'VENDOR-INVOKED CODEX_RELEASE=%s\n' "${CODEX_RELEASE:-}" >>"$FAKE_OPLOG"
fi
if [ -n "${FAKE_SENTINEL:-}" ]; then printf 'ran\n' >>"$FAKE_SENTINEL"; fi
if [ -n "${FAKE_RECEIPT:-}" ] && [ -n "${AGENT_VM_TRANSPORT_RECEIPT:-}" ]; then
    printf '%s\n' "$FAKE_RECEIPT" >"$AGENT_VM_TRANSPORT_RECEIPT"
fi
exit "${FAKE_EXIT:-0}"
SH
    chmod 0755 "$CASE/vendor/install.sh"
}

# run_install <slot>; env: FAKE_EXIT, FAKE_RECEIPT, SOFT, NO_RECEIPT
run_install() {
    local slot="$1"
    local receipt_val="$CASE/receipt"
    [[ "${NO_RECEIPT:-}" == 1 ]] && receipt_val=""
    set +e
    RUN_OUTPUT="$(
        env -i \
            "PATH=/usr/bin:/bin" \
            "AGENT_VM_VENDOR_DIR=$CASE/vendor" \
            "AGENT_VM_CODEX_PREFIX=$CASE/prefix" \
            "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
            "AGENT_VM_VERSION_CODEX=$slot" \
            "FAKE_SENTINEL=$CASE/ran" \
            "FAKE_OPLOG=$CASE/oplog" \
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
run_install rust-v0.159.3
[[ $RUN_STATUS -eq 0 ]] || fail "a clean install must pass: $RUN_OUTPUT"
[[ -f "$CASE/ran" ]] || fail "the vendored installer must run on a valid slot"
[[ ! -e "$CASE/status/codex" ]] || fail "the hook must not write installed itself"

for bad in latest rust-vlatest '0.159.3' 'v0.159.3' 'rust-v0.159' 'rust-v0.159.3 ' \
    'rust-v01.2.3' 'rust-v1.02.3' 'rust-v1.2.03' 'rust-v1.2.3-alpha.01' \
    'rust-v1.2.3-beta.02' 'rust-v1.2.3-alpha.1.2.3' \
    'rust-v1.x' 'rust-v1.2' 'rust-v1.2.3.4' 'rust-v^1.2.3' 'rust-v~1.2.3' \
    'rust-v>=1.2.3' 'rust-v1.2.3 || rust-v2.0.0' 'rust-vhttps://example.com/x'; do
    new_case "reject-$(printf '%s' "$bad" | tr -c 'A-Za-z0-9' '_')"
    SOFT=
    run_install "$bad"
    [[ $RUN_STATUS -ne 0 ]] || fail "slot '$bad' must be rejected"
    [[ ! -f "$CASE/ran" ]] || fail "slot '$bad' must be rejected before the installer runs"
    [[ ! -s "$CASE/oplog" ]] ||
        fail "slot '$bad' must not reach the vendor; operation log: $(cat "$CASE/oplog")"
done

# Canonical alpha/beta spellings the vendored installer supports are accepted
# (a leading-zero control would reject them too, so prove the seam kept them).
for good in rust-v1.2.3-alpha rust-v1.2.3-alpha.1 rust-v1.2.3-alpha.1.2 \
    rust-v1.2.3-beta rust-v1.2.3-beta.2; do
    new_case "accept-$(printf '%s' "$good" | tr -c 'A-Za-z0-9' '_')"
    SOFT=
    run_install "$good"
    [[ $RUN_STATUS -eq 0 ]] || fail "canonical slot '$good' must be accepted: $RUN_OUTPUT"
    [[ -s "$CASE/oplog" ]] || fail "canonical slot '$good' must reach the vendor"
done

new_case empty
SOFT=
run_install ""
[[ $RUN_STATUS -ne 0 ]] || fail "an empty slot must be rejected"

new_case transport-soft
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=1
mkdir -p "$CASE/prefix/.local/bin"
touch "$CASE/prefix/.local/bin/codex"
run_install rust-v0.159.3
[[ $RUN_STATUS -eq 0 ]] || fail "a classified transport failure must soften: $RUN_OUTPUT"
[[ "$(cat "$CASE/status/codex")" == "absent-transport 6" ]] ||
    fail "softened install must write an absence record"
[[ ! -e "$CASE/prefix/.local/bin/codex" ]] || fail "the half-published command must be cleaned"
unset FAKE_EXIT FAKE_RECEIPT SOFT

new_case transport-no-soft
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=
run_install rust-v0.159.3
[[ $RUN_STATUS -ne 0 ]] || fail "a transport failure without soft-fail must be hard"
[[ ! -e "$CASE/status/codex" ]] || fail "a hard failure must not leave an absence record"
unset FAKE_EXIT FAKE_RECEIPT SOFT

new_case bare-75
FAKE_EXIT=75
FAKE_RECEIPT=''
SOFT=1
run_install rust-v0.159.3
[[ $RUN_STATUS -ne 0 ]] || fail "an arbitrary 75 must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT

new_case unknown-failure
FAKE_EXIT=3
FAKE_RECEIPT=''
SOFT=1
run_install rust-v0.159.3
[[ $RUN_STATUS -ne 0 ]] || fail "an unknown installer exit must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT

new_case no-receipt-env
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=1
NO_RECEIPT=1
run_install rust-v0.159.3
[[ $RUN_STATUS -ne 0 ]] || fail "a 75 without a receipt path must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT NO_RECEIPT

# --- 3. verify-codex.sh black-box --------------------------------------------

new_gate_case() {
    CASE="$TEST_ROOT/gate-$1"
    mkdir -p "$CASE/prefix/.local/bin" "$CASE/status"
    chmod 0755 "$CASE" "$CASE/prefix" "$CASE/prefix/.local/bin" "$CASE/status"
    GATE_BIN="$CASE/prefix/.local/bin/codex"
}

make_codex() {
    cat >"$GATE_BIN"
    chmod 0755 "$GATE_BIN"
}

run_gate() {
    set +e
    RUN_OUTPUT="$(
        env -i \
            "PATH=$CASE/prefix/.local/bin:$TIMEOUT_DIR:$PYTHON_DIR:/usr/bin:/bin" \
            "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
            "AGENT_VM_CODEX_PREFIX=$CASE/prefix" \
            "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
            "AGENT_VM_VERSION_CODEX=${WANT-}" \
            sh "$VERIFY" 2>&1
    )"
    RUN_STATUS=$?
    set -e
}

WANT=rust-v0.159.3
new_gate_case ok
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.3\n'
SH
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the pinned version must pass: $RUN_OUTPUT"
[[ "$(cat "$CASE/status/codex")" == "installed" ]] ||
    fail "a passing gate must record installed"

WANT=rust-v0.159.3
new_gate_case mismatch
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.2\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a wrong installed version must fail"
[[ ! -e "$CASE/status/codex" ]] || fail "a failed gate must not record installed"

WANT=rust-v0.159.3
new_gate_case prefix
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.30\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "0.159.30 must not satisfy a 0.159.3 pin"

WANT=rust-v0.159.3
new_gate_case trailing
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.3\n'
printf 'warning: 0.159.3\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a warning on a later line must not be accepted"

# B1: a contradictory banner on the captured stderr must not certify the slot.
WANT=rust-v0.159.3
new_gate_case stderr-contradictory
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.3\n'
printf 'codex-cli 9.9.9\n' >&2
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a contradictory banner on stderr must fail"

# C2: a NUL inside the banner is exact-byte corruption; the gate must reject the
# raw bytes rather than let command substitution erase the NUL and accept it.
WANT=rust-v0.159.3
new_gate_case nul-in-report
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.\0003\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a NUL inside the report must fail"

# SP5: an unterminated trailing line (no final newline) must still fail.
WANT=rust-v0.159.3
new_gate_case unterminated-trailing
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.3\nUNRECOGNIZED TRAILING REPORT'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an unterminated trailing report line must be rejected"

WANT=rust-v0.159.3
new_gate_case leading-warning
make_codex <<'SH'
#!/bin/sh
printf 'warning: expected 0.159.3\n'
printf 'codex-cli 0.159.3\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a leading warning line must not be accepted"

WANT=rust-v0.159.3
new_gate_case nonzero
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.3\n'
exit 1
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "printing the expected version then exiting nonzero must fail"
assert_contains "$RUN_OUTPUT" "exited 1"

WANT=rust-v0.159.3
new_gate_case absent
printf 'absent-transport 6\n' >"$CASE/status/codex"
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a recorded absence must be accepted: $RUN_OUTPUT"

# SP2: a dangling symlink is PRESENT; an absence record must not waive it.
WANT=rust-v0.159.3
new_gate_case dangling
printf 'absent-transport 6\n' >"$CASE/status/codex"
ln -s nowhere "$GATE_BIN"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a dangling command symlink must fail despite the absence record"

# SP2: an absence line inside a malformed multi-line record is not valid.
WANT=rust-v0.159.3
new_gate_case malformed-record
printf 'absent-transport 6\njunk\n' >"$CASE/status/codex"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a multi-line absence record must not be accepted"

WANT=rust-v0.159.3
new_gate_case missing
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing command with no record must fail"

WANT=rust-v0.159.3
new_gate_case pending
printf 'pending\n' >"$CASE/status/codex"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a pending record must not be accepted as absence"

WANT=rust-v0.159.3
new_gate_case private-path
make_codex <<'SH'
#!/bin/sh
printf 'codex-cli 0.159.3\n'
SH
chmod 0700 "$CASE/prefix/.local/bin"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a 0700 directory on the command's path must fail T5"

echo "codex-installer black-box tests passed"
