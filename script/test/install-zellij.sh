#!/usr/bin/env bash
# Black-box contract tests for the build-only Zellij installer.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
INSTALLER="$REPO_ROOT/images/install-zellij.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/install-zellij-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2"
}

assert_not_contains() {
    [[ "$1" != *"$2"* ]] || fail "expected output not to contain: $2"
}

assert_log_contains() {
    assert_contains "$(cat "$CASE/log")" "$1"
}

assert_log_not_contains() {
    assert_not_contains "$(cat "$CASE/log")" "$1"
}

assert_log_line_equals() {
    grep -Fxq -- "$1" "$CASE/log" || fail "expected exact log line: $1"
}

make_tool() {
    local name="$1"
    shift
    cat >"$CASE/bin/$name"
    chmod +x "$CASE/bin/$name"
}

new_case() {
    unset FAKE_ARCH CURL_FAIL CURL_SIGNAL SHA_FAIL_STATUS TAR_FIXTURE INSTALL_FAIL_STATUS VERSION_FAIL_STATUS AGENT_INSTALL_SOFT_FAIL MISSING_REQUIRED
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/bin" "$CASE/tmp"
    : >"$CASE/log"

    make_tool dpkg <<'SH'
#!/usr/bin/env bash
printf 'dpkg %s\n' "$*" >>"$FAKE_LOG"
printf '%s\n' "${FAKE_ARCH:-amd64}"
SH
    make_tool curl <<'SH'
#!/usr/bin/env bash
{
printf 'curl'
printf ' <%s>' "$@"
printf '\n'
} >>"$FAKE_LOG"
case "${CURL_SIGNAL:-}" in
    INT) kill -INT "$PPID"; sleep 1 ;;
    TERM) kill -TERM "$PPID"; sleep 1 ;;
esac
if [[ "${CURL_FAIL:-}" == 1 ]]; then
    exit 1
fi
touch "${@: -1}"
SH
    make_tool sha256sum <<'SH'
#!/usr/bin/env bash
input="$(cat)"
{
printf 'sha256sum'
printf ' <%s>' "$@"
printf ' stdin=<%s>\n' "$input"
} >>"$FAKE_LOG"
if [[ -n "${SHA_FAIL_STATUS:-}" ]]; then
    exit "$SHA_FAIL_STATUS"
fi
SH
    make_tool tar <<'SH'
#!/usr/bin/env bash
{
printf 'tar'
printf ' <%s>' "$@"
printf '\n'
} >>"$FAKE_LOG"
if [[ "${TAR_FIXTURE:-nested}" == nested ]]; then
    destination="${@: -1}"
    mkdir -p "$destination/release/deep"
    : >"$destination/release/deep/zellij"
fi
SH
    make_tool find <<'SH'
#!/usr/bin/env bash
{
printf 'find'
printf ' <%s>' "$@"
printf '\n'
} >>"$FAKE_LOG"
exec /usr/bin/find "$@"
SH
    make_tool install <<'SH'
#!/usr/bin/env bash
{
printf 'install'
printf ' <%s>' "$@"
printf '\n'
} >>"$FAKE_LOG"
if [[ -n "${INSTALL_FAIL_STATUS:-}" ]]; then
    exit "$INSTALL_FAIL_STATUS"
fi
destination="${@: -1}"
cat >"$destination" <<'BIN'
#!/usr/bin/env bash
if [[ -n "${VERSION_FAIL_STATUS:-}" ]]; then
    exit "$VERSION_FAIL_STATUS"
fi
printf 'version <%s> <%s>\n' "$0" "$*" >>"$FAKE_LOG"
printf 'zellij 0.45.0\n'
BIN
chmod +x "$destination"
SH
}

run_installer() {
    local output status
    local -a inputs=(
        "PATH=$CASE/bin:/usr/bin:/bin"
        "HOME=$HOME" "TMPDIR=$CASE/tmp" "FAKE_LOG=$CASE/log"
        "ZELLIJ_INSTALL_PATH=$CASE/zellij"
        "FAKE_ARCH=${FAKE_ARCH-amd64}" "CURL_FAIL=${CURL_FAIL-}"
        "CURL_SIGNAL=${CURL_SIGNAL-}" "SHA_FAIL_STATUS=${SHA_FAIL_STATUS-}"
        "TAR_FIXTURE=${TAR_FIXTURE-nested}" "INSTALL_FAIL_STATUS=${INSTALL_FAIL_STATUS-}"
        "VERSION_FAIL_STATUS=${VERSION_FAIL_STATUS-}" "AGENT_INSTALL_SOFT_FAIL=${AGENT_INSTALL_SOFT_FAIL-}"
    )
    [[ ${MISSING_REQUIRED-} != ZELLIJ_VERSION ]] && inputs+=("ZELLIJ_VERSION=${ZELLIJ_VERSION-0.45.0}")
    [[ ${MISSING_REQUIRED-} != ZELLIJ_SHA256_AMD64 ]] && inputs+=("ZELLIJ_SHA256_AMD64=${ZELLIJ_SHA256_AMD64-amd64-sum}")
    [[ ${MISSING_REQUIRED-} != ZELLIJ_SHA256_ARM64 ]] && inputs+=("ZELLIJ_SHA256_ARM64=${ZELLIJ_SHA256_ARM64-arm64-sum}")
    set +e
    output="$(env -i "${inputs[@]}" bash "$INSTALLER" 2>&1)"
    status=$?
    set -e
    RUN_OUTPUT="$output"
    RUN_STATUS=$status
}

assert_cleaned_up() {
    if compgen -G "$CASE/tmp/zellij.*" >/dev/null; then
        fail "installer temporary directory was not cleaned up"
    fi
}

# Required inputs fail before any external installer work.
for variable in ZELLIJ_VERSION ZELLIJ_SHA256_AMD64 ZELLIJ_SHA256_ARM64; do
    new_case "missing-$variable"
    MISSING_REQUIRED=$variable
    run_installer
    [[ $RUN_STATUS -ne 0 ]] || fail "missing $variable unexpectedly succeeded"
    assert_contains "$RUN_OUTPUT" "$variable"
    assert_log_not_contains 'dpkg '
    assert_log_not_contains 'curl'
    unset MISSING_REQUIRED
done

new_case amd64
run_installer
[[ $RUN_STATUS -eq 0 ]] || fail "amd64 install failed: $RUN_OUTPUT"
assert_log_contains 'dpkg --print-architecture'
archive="$(grep '^curl ' "$CASE/log" | sed -E 's/^.* <-o> <([^>]*)>$/\1/')"
temporary_directory="${archive%/z.tar.gz}"
[[ "$archive" == "$CASE/tmp/zellij."*'/z.tar.gz' ]] \
    || fail "curl archive path was not a generated private temporary path: $archive"
[[ "$temporary_directory" != "$archive" ]] || fail "could not derive temporary directory from archive path"
assert_log_line_equals "curl <-fsSL> <--retry> <5> <--retry-all-errors> <--http1.1> <https://github.com/zellij-org/zellij/releases/download/v0.45.0/zellij-x86_64-unknown-linux-musl.tar.gz> <-o> <$archive>"
assert_log_line_equals "sha256sum <--status> <-c> <-> stdin=<amd64-sum  $archive>"
assert_log_line_equals "tar <-xzf> <$archive> <-C> <$temporary_directory>"
assert_log_line_equals "find <$temporary_directory> <-type> <f> <-name> <zellij> <-print> <-quit>"
assert_log_line_equals "install <-m> <0755> <$temporary_directory/release/deep/zellij> <$CASE/zellij>"
assert_log_line_equals "version <$CASE/zellij> <--version>"
[[ "$RUN_OUTPUT" == 'zellij 0.45.0' ]] || fail "exact installed-path version smoke did not run"
assert_cleaned_up

new_case arm64
FAKE_ARCH=arm64
run_installer
[[ $RUN_STATUS -eq 0 ]] || fail "arm64 install failed: $RUN_OUTPUT"
assert_log_contains 'zellij-aarch64-unknown-linux-musl.tar.gz'
assert_log_contains 'sha256sum <--status> <-c> <-> stdin=<arm64-sum  '
assert_cleaned_up

new_case unsupported
FAKE_ARCH=i386
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "unsupported architecture unexpectedly succeeded"
assert_contains "$RUN_OUTPUT" 'i386'
assert_log_not_contains 'curl'

new_case curl-hard-failure
CURL_FAIL=1
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "hard download failure unexpectedly succeeded"
assert_contains "$RUN_OUTPUT" 'zellij DOWNLOAD FAILED'
assert_contains "$RUN_OUTPUT" 'zellij-x86_64-unknown-linux-musl.tar.gz'
assert_cleaned_up

new_case curl-soft-failure
CURL_FAIL=1
AGENT_INSTALL_SOFT_FAIL=1
run_installer
[[ $RUN_STATUS -eq 0 ]] || fail "soft download failure failed: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" 'soft-fail mode'
assert_log_not_contains 'install <'
assert_cleaned_up

for mode in hard soft; do
    new_case "checksum-$mode"
    SHA_FAIL_STATUS=47
    [[ $mode == soft ]] && AGENT_INSTALL_SOFT_FAIL=1 || true
    run_installer
    [[ $RUN_STATUS -ne 0 ]] || fail "checksum mismatch ($mode) unexpectedly succeeded"
    assert_contains "$RUN_OUTPUT" 'sha256 MISMATCH'
    assert_log_not_contains 'tar <'
    assert_log_not_contains 'install <'
    assert_cleaned_up
done

new_case no-binary
TAR_FIXTURE=missing
run_installer
[[ $RUN_STATUS -ne 0 ]] || fail "missing binary unexpectedly succeeded"
assert_contains "$RUN_OUTPUT" "no 'zellij' binary"
assert_log_not_contains 'install <'
assert_cleaned_up

new_case install-failure
INSTALL_FAIL_STATUS=73
run_installer
[[ $RUN_STATUS -eq 73 ]] || fail "install failure status was $RUN_STATUS, expected 73"
assert_log_contains 'install'
[[ "$RUN_OUTPUT" != *'zellij 0.45.0'* ]] || fail "version smoke ran after install failure"
assert_cleaned_up

new_case version-failure
VERSION_FAIL_STATUS=79
run_installer
[[ $RUN_STATUS -eq 79 ]] || fail "version failure status was $RUN_STATUS, expected 79"
assert_log_contains " <$CASE/zellij>"
assert_cleaned_up

for signal in INT TERM; do
    new_case "signal-$signal"
    CURL_SIGNAL=$signal
    run_installer
    case "$signal" in
        INT) expected_status=130 ;;
        TERM) expected_status=143 ;;
    esac
    [[ $RUN_STATUS -eq $expected_status ]] \
        || fail "$signal status was $RUN_STATUS, expected $expected_status"
    assert_cleaned_up
done

grep -Fq 'ZELLIJ_INSTALL_PATH:-/usr/local/bin/zellij' "$INSTALLER" \
    || fail 'production default install path is missing'

echo 'install-zellij black-box tests passed'
