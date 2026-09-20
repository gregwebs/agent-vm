#!/usr/bin/env bash
# Black-box contract tests for the build-only Pi installer
# (images/tools/pi/install-pi.sh).
#
# No Docker, no npm registry, no real tarballs: `npm`, `curl`, `openssl`, `tar`
# and `diff` are faked on PATH, so every failure policy -- soft-fail at the
# failure, integrity mismatch never soft-failable, a count check that cannot read
# as success, no partial tree left behind -- is exercised hermetically and fast.
# The lockfile parser (the `jq` selector) is the REAL one, against a synthetic
# lock, so the selector itself is under test.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
INSTALLER="$REPO_ROOT/images/tools/pi/install-pi.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pi-install-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT" /tmp/pi-verify /tmp/pi-siblings.tsv' EXIT

REAL_JQ="$(command -v jq || true)"
[[ -n "$REAL_JQ" ]] || { echo "FAIL: jq is required" >&2; exit 1; }
JQ_DIR="$(dirname "$REAL_JQ")"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2"
}

CASE=""

make_tool() {
    local name="$1"
    cat >"$CASE/bin/$name"
    chmod +x "$CASE/bin/$name"
}

new_case() {
    unset NPM_FAIL CURL_FAIL FAKE_B64 DIFF_STATUS AGENT_INSTALL_SOFT_FAIL INTEGRITY
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/bin" "$CASE/prefix" "$CASE/home"
    : >"$CASE/log"

    make_tool npm <<'SH'
#!/usr/bin/env bash
printf 'npm <%s>\n' "$*" >>"$FAKE_LOG"
[[ "${NPM_FAIL:-}" == 1 ]] && exit 1
mkdir -p "$NESTED_DIR"
: >"$NESTED_DIR/.installed"
SH
    make_tool curl <<'SH'
#!/usr/bin/env bash
printf 'curl <%s>\n' "$*" >>"$FAKE_LOG"
[[ "${CURL_FAIL:-}" == 1 ]] && exit 1
: >"${@: -1}"
SH
    make_tool openssl <<'SH'
#!/usr/bin/env bash
# `dgst` reads its file argument (never stdin); `base64` reads the pipe from it.
# Keeping that split matters: a fake that slurps stdin on the `dgst` call would
# eat the installer's `while read` input and hide later iterations.
case "$1" in
    dgst) printf 'fake-digest' ;;
    base64) cat >/dev/null; printf '%s' "${FAKE_B64:-AAAA}" ;;
esac
SH
    make_tool tar <<'SH'
#!/usr/bin/env bash
printf 'tar <%s>\n' "$*" >>"$FAKE_LOG"
mkdir -p "${@: -1}/package"
: >"${@: -1}/package/file"
SH
    make_tool diff <<'SH'
#!/usr/bin/env bash
printf 'diff <%s>\n' "$*" >>"$FAKE_LOG"
exit "${DIFF_STATUS:-0}"
SH
}

# `$1` = number of sibling entries, `$2` = their integrity value.
write_lock() {
    local count="${1:-5}" integrity="${2-sha512-AAAA}" name emitted=0
    {
        printf '{\n  "name": "agent-vm-guest-pi",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n  "packages": {\n'
        for name in chord pi-agent-core pi-ai pi-telemetry pi-tui; do
            [[ $emitted -lt $count ]] || break
            printf '    "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/%s": {"version": "0.86.1", "resolved": "https://registry.example.test/%s.tgz", "integrity": "%s"},\n' \
                "$name" "$name" "$integrity"
            emitted=$((emitted + 1))
        done
        printf '    "node_modules/@earendil-works/pi-coding-agent": {"version": "0.86.1"}\n  }\n}\n'
    } >"$CASE/prefix/package-lock.json"
    printf '{"dependencies": {"@earendil-works/pi-coding-agent": "0.86.1"}}\n' >"$CASE/prefix/package.json"
}

run_installer() {
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$CASE/bin:$JQ_DIR:/usr/bin:/bin" \
        "HOME=$CASE/home" \
        "FAKE_LOG=$CASE/log" \
        "AGENT_VM_PI_PREFIX=$CASE/prefix" \
        "NESTED_DIR=$CASE/prefix/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works" \
        "AGENT_INSTALL_SOFT_FAIL=${AGENT_INSTALL_SOFT_FAIL-}" \
        "NPM_FAIL=${NPM_FAIL-}" \
        "CURL_FAIL=${CURL_FAIL-}" \
        "FAKE_B64=${FAKE_B64-AAAA}" \
        "DIFF_STATUS=${DIFF_STATUS-0}" \
        sh "$INSTALLER" 2>&1)"
    RUN_STATUS=$?
    set -e
}

# --- npm ci: hard by default, soft (and clean) under the flag ----------------

new_case npm-hard-failure
write_lock
NPM_FAIL=1
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "an npm ci failure must be a hard failure by default"
assert_contains "$RUN_OUTPUT" "npm ci FAILED"
assert_contains "$RUN_OUTPUT" "$CASE/prefix"

new_case npm-soft-failure
write_lock
NPM_FAIL=1
AGENT_INSTALL_SOFT_FAIL=1
run_installer
[[ $RUN_STATUS -eq 0 ]] || fail "soft npm failure must exit 0: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "soft-fail mode"
[[ ! -e "$CASE/prefix" ]] || fail "soft-failed npm left a partial tree behind"

# --- tarball fetch: same class as npm ---------------------------------------

new_case fetch-soft-failure
write_lock
CURL_FAIL=1
AGENT_INSTALL_SOFT_FAIL=1
run_installer
[[ $RUN_STATUS -eq 0 ]] || fail "soft fetch failure must exit 0: $RUN_OUTPUT"
[[ ! -e "$CASE/prefix" ]] || fail "soft-failed fetch left a partial tree behind"

new_case fetch-hard-failure
write_lock
CURL_FAIL=1
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "a fetch failure is a hard failure by default"
assert_contains "$RUN_OUTPUT" "could not fetch"

# --- integrity: NEVER soft-failable -----------------------------------------

new_case integrity-mismatch
write_lock 5 sha512-WRONG
FAKE_B64=AAAA # the installer will compute sha512-AAAA
AGENT_INSTALL_SOFT_FAIL=1
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "an integrity mismatch must fail even under soft-fail"
assert_contains "$RUN_OUTPUT" "INTEGRITY MISMATCH"
assert_contains "$RUN_OUTPUT" "sha512-WRONG"
assert_contains "$RUN_OUTPUT" "sha512-AAAA"

# --- installed tree diverging from the verified tarball ----------------------

new_case diff-mismatch
write_lock 5 sha512-AAAA
FAKE_B64=AAAA
DIFF_STATUS=1
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "a diff mismatch must be a hard failure"
assert_contains "$RUN_OUTPUT" "differs from its verified tarball"

# --- the selector cannot silently match fewer than five ----------------------

new_case selector-count
write_lock 4
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "a selector matching fewer than five must fail"
assert_contains "$RUN_OUTPUT" "expected 5"

# --- a null/empty integrity in the lock is refused before any fetch ----------

new_case missing-integrity
write_lock 5 ""
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "a sibling with no integrity must fail"
assert_contains "$RUN_OUTPUT" "has no integrity"

# --- happy path: 5/5 verified, prefix world-readable -------------------------

new_case happy
write_lock 5 sha512-AAAA
FAKE_B64=AAAA
run_installer
[[ $RUN_STATUS -eq 0 ]] || fail "the happy path must succeed: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "5/5 shrinkwrap-only tarballs verified"
[[ -z "$(find "$CASE/prefix" ! -perm -o+r -print -quit)" ]] \
    || fail "the installed prefix is not world-readable (C7)"

# --- the test seam cannot become the production default ----------------------

grep -Fq 'AGENT_VM_PI_PREFIX:-/opt/agent-vm/pi}"' "$INSTALLER" \
    || fail "production default install prefix is missing"

echo 'pi-install black-box tests passed'
