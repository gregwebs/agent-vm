#!/usr/bin/env bash
# Black-box tests for the opencode layer's install hook and build gate
# (images/tools/opencode/{install-opencode.sh,verify-opencode.sh}) and for the
# vendored installer patch reproduction.
set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
VENDOR_SRC="$REPO_ROOT/images/tools/opencode/vendor"
INSTALL="$REPO_ROOT/images/tools/opencode/install-opencode.sh"
VERIFY="$REPO_ROOT/images/tools/opencode/verify-opencode.sh"
CONTRACT="$REPO_ROOT/images/recipe-contract"

TEST_ROOT="$(mktemp -d /tmp/opencode-installer.XXXXXX)"
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

# --- 2. install-opencode.sh black-box ----------------------------------------

new_case() {
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/vendor" "$CASE/prefix" "$CASE/status" "$CASE/link"
    chmod 0755 "$CASE" "$CASE/prefix" "$CASE/status" "$CASE/link"

    cat >"$CASE/vendor/install.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ -n "${FAKE_SENTINEL:-}" ]; then printf 'ran\n' >>"$FAKE_SENTINEL"; fi
if [ -n "${FAKE_RECEIPT:-}" ] && [ -n "${AGENT_VM_TRANSPORT_RECEIPT:-}" ]; then
    printf '%s\n' "$FAKE_RECEIPT" >"$AGENT_VM_TRANSPORT_RECEIPT"
fi
if [ "${FAKE_EXIT:-0}" -eq 0 ]; then
    mkdir -p "$HOME/.opencode/bin"
    printf '#!/bin/sh\nexit 0\n' >"$HOME/.opencode/bin/opencode"
    chmod 0755 "$HOME/.opencode/bin/opencode"
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
            "AGENT_VM_OPENCODE_PREFIX=$CASE/prefix" \
            "AGENT_VM_OPENCODE_LINK=$CASE/link/opencode" \
            "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
            "AGENT_VM_VERSION_OPENCODE=$slot" \
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
run_install v1.18.34
[[ $RUN_STATUS -eq 0 ]] || fail "a clean install must pass: $RUN_OUTPUT"
[[ -f "$CASE/ran" ]] || fail "the vendored installer must run on a valid slot"
[[ -L "$CASE/link/opencode" ]] || fail "the hook must publish the /usr/local/bin link"
[[ ! -e "$CASE/status/opencode" ]] || fail "the hook must not write installed itself"

for bad in latest '1.18.34' 'v1.18' 'v1.18.34 ' '^1.18.34'; do
    new_case "reject-$(printf '%s' "$bad" | tr -c 'A-Za-z0-9' '_')"
    SOFT=
    run_install "$bad"
    [[ $RUN_STATUS -ne 0 ]] || fail "slot '$bad' must be rejected"
    [[ ! -f "$CASE/ran" ]] || fail "slot '$bad' must be rejected before the installer runs"
done

new_case empty
SOFT=
run_install ""
[[ $RUN_STATUS -ne 0 ]] || fail "an empty slot must be rejected"

new_case transport-soft
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=1
run_install v1.18.34
[[ $RUN_STATUS -eq 0 ]] || fail "a classified transport failure must soften: $RUN_OUTPUT"
[[ "$(cat "$CASE/status/opencode")" == "absent-transport 6" ]] ||
    fail "softened install must write an absence record"
[[ ! -e "$CASE/prefix/.opencode" ]] || fail "the install dir must be cleaned"
[[ ! -e "$CASE/link/opencode" ]] || fail "a half-published link must be cleaned"
unset FAKE_EXIT FAKE_RECEIPT SOFT

new_case transport-no-soft
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=
run_install v1.18.34
[[ $RUN_STATUS -ne 0 ]] || fail "a transport failure without soft-fail must be hard"
[[ ! -e "$CASE/status/opencode" ]] || fail "a hard failure must not leave an absence record"
unset FAKE_EXIT FAKE_RECEIPT SOFT

new_case bare-75
FAKE_EXIT=75
FAKE_RECEIPT=''
SOFT=1
run_install v1.18.34
[[ $RUN_STATUS -ne 0 ]] || fail "an arbitrary 75 must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT

new_case unknown-failure
FAKE_EXIT=3
FAKE_RECEIPT=''
SOFT=1
run_install v1.18.34
[[ $RUN_STATUS -ne 0 ]] || fail "an unknown installer exit must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT

new_case no-receipt-env
FAKE_EXIT=75
FAKE_RECEIPT='transport download 6'
SOFT=1
NO_RECEIPT=1
run_install v1.18.34
[[ $RUN_STATUS -ne 0 ]] || fail "a 75 without a receipt path must be hard"
unset FAKE_EXIT FAKE_RECEIPT SOFT NO_RECEIPT

# --- 3. verify-opencode.sh black-box -----------------------------------------

new_gate_case() {
    CASE="$TEST_ROOT/gate-$1"
    mkdir -p "$CASE/prefix/.opencode/bin" "$CASE/status"
    chmod 0755 "$CASE" "$CASE/prefix" "$CASE/prefix/.opencode" "$CASE/prefix/.opencode/bin" "$CASE/status"
    GATE_BIN="$CASE/prefix/.opencode/bin/opencode"
}

make_opencode() {
    cat >"$GATE_BIN"
    chmod 0755 "$GATE_BIN"
}

run_gate() {
    set +e
    RUN_OUTPUT="$(
        env -i \
            "PATH=$CASE/prefix/.opencode/bin:$TIMEOUT_DIR:$PYTHON_DIR:/usr/bin:/bin" \
            "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
            "AGENT_VM_OPENCODE_PREFIX=$CASE/prefix" \
            "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status" \
            "AGENT_VM_VERSION_OPENCODE=${WANT-}" \
            sh "$VERIFY" 2>&1
    )"
    RUN_STATUS=$?
    set -e
}

WANT=v1.18.34
new_gate_case ok
make_opencode <<'SH'
#!/bin/sh
printf '1.18.34\n'
SH
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "the pinned version must pass: $RUN_OUTPUT"
[[ "$(cat "$CASE/status/opencode")" == "installed" ]] ||
    fail "a passing gate must record installed"

WANT=v1.18.34
new_gate_case mismatch
make_opencode <<'SH'
#!/bin/sh
printf '1.18.33\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a wrong installed version must fail"

WANT=v1.18.34
new_gate_case prefix
make_opencode <<'SH'
#!/bin/sh
printf '1.18.340\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "1.18.340 must not satisfy a 1.18.34 pin"

WANT=v1.18.34
new_gate_case leading-warning
make_opencode <<'SH'
#!/bin/sh
printf 'warning: expected 1.18.34\n'
printf '1.18.34\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a leading warning line must not be accepted"

# B1: a contradictory bare version on stderr must not certify the slot.
WANT=v1.18.34
new_gate_case stderr-contradictory
make_opencode <<'SH'
#!/bin/sh
printf '1.18.34\n'
printf '9.9.9\n' >&2
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a contradictory version on stderr must fail"

# C2: a NUL inside the report must be rejected, not erased by substitution.
WANT=v1.18.34
new_gate_case nul-in-report
make_opencode <<'SH'
#!/bin/sh
printf '1.18.\00034\n'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a NUL inside the report must fail"

# SP5: an unterminated trailing line (no final newline) must still fail.
WANT=v1.18.34
new_gate_case unterminated-trailing
make_opencode <<'SH'
#!/bin/sh
printf '1.18.34\nUNRECOGNIZED TRAILING REPORT'
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "an unterminated trailing report line must be rejected"

WANT=v1.18.34
new_gate_case nonzero
make_opencode <<'SH'
#!/bin/sh
printf '1.18.34\n'
exit 1
SH
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "printing the expected version then exiting nonzero must fail"
assert_contains "$RUN_OUTPUT" "exited 1"

WANT=v1.18.34
new_gate_case absent
printf 'absent-transport 6\n' >"$CASE/status/opencode"
run_gate
[[ $RUN_STATUS -eq 0 ]] || fail "a recorded absence must be accepted: $RUN_OUTPUT"

# SP2: a dangling symlink is PRESENT; an absence record must not waive it.
WANT=v1.18.34
new_gate_case dangling
printf 'absent-transport 6\n' >"$CASE/status/opencode"
ln -s nowhere "$GATE_BIN"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a dangling command symlink must fail despite the absence record"

# SP2: an absence line inside a malformed multi-line record is not valid.
WANT=v1.18.34
new_gate_case malformed-record
printf 'absent-transport 6\njunk\n' >"$CASE/status/opencode"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a multi-line absence record must not be accepted"

WANT=v1.18.34
new_gate_case missing
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a missing command with no record must fail"

WANT=v1.18.34
new_gate_case pending
printf 'pending\n' >"$CASE/status/opencode"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a pending record must not be accepted as absence"

WANT=v1.18.34
new_gate_case private-path
make_opencode <<'SH'
#!/bin/sh
printf '1.18.34\n'
SH
chmod 0700 "$CASE/prefix/.opencode/bin"
run_gate
[[ $RUN_STATUS -ne 0 ]] || fail "a 0700 directory on the command's path must fail T5"

echo "opencode-installer black-box tests passed"
