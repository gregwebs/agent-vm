#!/usr/bin/env bash
# Black-box tests for script/build/agent-versions.sh, the EXPLICIT developer
# write tool that resolves each single-slot installer layer's current upstream
# release and stages the reviewed exact default in its Dockerfile.
#
# No network and no repository writes: a fake `curl` (GitHub + the claude
# channel) and a fake `npm` (copilot's dist-tag) answer from environment
# variables, and every run targets a `--repo-root` fixture tree of four
# Dockerfiles with one `ARG AGENT_VERSION_*=<old>` line each. The real `jq` is
# used, since the JSON extraction is part of what is under test.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
SCRIPT="$REPO_ROOT/script/build/agent-versions.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agent-versions-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

REAL_JQ="$(command -v jq || true)"
[[ -n "$REAL_JQ" ]] || { echo "FAIL: jq is required" >&2; exit 1; }
JQ_DIR="$(dirname "$REAL_JQ")"
REAL_MV="$(command -v mv || true)"
[[ -n "$REAL_MV" ]] || { echo "FAIL: mv is required" >&2; exit 1; }
BASH_BIN="${BASH:-/bin/bash}"

# Upstream responses the fake curl/npm serve by default. The fixture Dockerfile
# defaults below are different, so the happy path rewrites all four.
DEFAULT_CODEX='{"tag_name":"rust-v0.30.0"}'
DEFAULT_OPENCODE='{"tag_name":"v1.2.3"}'
DEFAULT_CLAUDE='1.0.100'
DEFAULT_COPILOT='0.1.30'

FIXTURE_OLD_CODEX='rust-v0.29.9'
FIXTURE_OLD_OPENCODE='v1.2.2'
FIXTURE_OLD_CLAUDE='1.0.99'
FIXTURE_OLD_COPILOT='0.1.29'

STUB_BIN="$TEST_ROOT/bin"
mkdir -p "$STUB_BIN"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2 (got: $1)"
}

assert_not_contains() {
    [[ "$1" != *"$2"* ]] || fail "expected output NOT to contain: $2 (got: $1)"
}

assert_status_fail() {
    [[ $RUN_STATUS -ne 0 ]] || fail "expected failure, got success: $RUN_OUTPUT"
}

assert_log_empty() {
    [[ ! -s "$CASE/log" ]] || fail "expected no network query, got: $(cat "$CASE/log")"
}

# The exact line count of PATTERN in FILE. grep -c prints 0 on no match; the
# `|| true` keeps set -e from aborting before we can read the count.
count_lines() {
    grep -c "$1" "$2" || true
}

cat >"$STUB_BIN/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
printf '%s\n' "$*" >>"${STUB_LOG:-/dev/null}"
[[ "${STUB_CURL_FAIL:-}" == 1 ]] && exit 1
case "$url" in
    *openai/codex*) printf '%s' "${STUB_CODEX-}" ;;
    *anomalyco/opencode*) printf '%s' "${STUB_OPENCODE-}" ;;
    *claude-code-releases/latest*) printf '%s' "${STUB_CLAUDE-}" ;;
    *) echo "stub curl: unexpected url: $url" >&2; exit 22 ;;
esac
SH
cat >"$STUB_BIN/npm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${STUB_LOG:-/dev/null}"
[[ "${STUB_NPM_FAIL:-}" == 1 ]] && exit 1
printf '%s\n' "${STUB_COPILOT-}"
SH
# A real `mv`, except it refuses a target that contains STUB_MV_FAIL_MATCH. This
# injects a mid-write failure so the staged-write/rollback contract is provable.
cat >"$STUB_BIN/mv" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'mv %s\n' "$*" >>"${STUB_LOG:-/dev/null}"
target="${@: -1}"
if [[ -n "${STUB_MV_FAIL_MATCH:-}" ]]; then
    case "$target" in
        *"$STUB_MV_FAIL_MATCH"*)
            echo "stub mv: refusing to move to $target" >&2
            exit 1
            ;;
    esac
fi
exec "$REAL_MV" "$@"
SH
chmod +x "$STUB_BIN/curl" "$STUB_BIN/npm" "$STUB_BIN/mv"

CASE=""
FIXTURE_ROOT=""

write_dockerfile() { # $1 = tool, remaining args = lines
    local tool="$1" dir line
    shift
    dir="$FIXTURE_ROOT/images/tools/$tool"
    mkdir -p "$dir"
    printf 'FROM scratch\n' >"$dir/Dockerfile"
    for line in "$@"; do
        printf '%s\n' "$line" >>"$dir/Dockerfile"
    done
}

reset_fixture() {
    FIXTURE_ROOT="$CASE/repo"
    rm -rf "$FIXTURE_ROOT"
    mkdir -p "$FIXTURE_ROOT"
    write_dockerfile codex "ARG AGENT_VERSION_CODEX=${FIXTURE_OLD_CODEX}"
    write_dockerfile opencode "ARG AGENT_VERSION_OPENCODE=${FIXTURE_OLD_OPENCODE}"
    write_dockerfile claude "ARG AGENT_VERSION_CLAUDE=${FIXTURE_OLD_CLAUDE}"
    write_dockerfile copilot "ARG AGENT_VERSION_COPILOT=${FIXTURE_OLD_COPILOT}"
}

new_case() {
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/home"
    STUB_CODEX="$DEFAULT_CODEX"
    STUB_OPENCODE="$DEFAULT_OPENCODE"
    STUB_CLAUDE="$DEFAULT_CLAUDE"
    STUB_COPILOT="$DEFAULT_COPILOT"
    unset STUB_CURL_FAIL STUB_NPM_FAIL GH_TOKEN GITHUB_ACTIONS GITHUB_OUTPUT STUB_MV_FAIL_MATCH
    : >"$CASE/log"
    : >"$CASE/stderr"
    reset_fixture
    ARGS=(--write --repo-root "$FIXTURE_ROOT")
}

ARGS=()
run_agent_versions() {
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$STUB_BIN:$JQ_DIR:/usr/bin:/bin" \
        "HOME=$CASE/home" \
        "REAL_MV=$REAL_MV" \
        "STUB_LOG=$CASE/log" \
        "STUB_CODEX=${STUB_CODEX-}" \
        "STUB_OPENCODE=${STUB_OPENCODE-}" \
        "STUB_CLAUDE=${STUB_CLAUDE-}" \
        "STUB_COPILOT=${STUB_COPILOT-}" \
        "STUB_CURL_FAIL=${STUB_CURL_FAIL-}" \
        "STUB_NPM_FAIL=${STUB_NPM_FAIL-}" \
        "STUB_MV_FAIL_MATCH=${STUB_MV_FAIL_MATCH-}" \
        "GH_TOKEN=${GH_TOKEN-}" \
        "GITHUB_ACTIONS=${GITHUB_ACTIONS-}" \
        "GITHUB_OUTPUT=${GITHUB_OUTPUT-}" \
        "$BASH_BIN" "$SCRIPT" ${ARGS[@]+"${ARGS[@]}"} 2>"$CASE/stderr")"
    RUN_STATUS=$?
    RUN_STDERR="$(cat "$CASE/stderr")"
    RUN_COMBINED="$RUN_OUTPUT
$RUN_STDERR"
    set -e
}

# --- usage / argument handling: no network, no writes -----------------------

new_case help
ARGS=(--help)
run_agent_versions
[[ $RUN_STATUS -eq 0 ]] || fail "--help must succeed: $RUN_STDERR"
assert_contains "$RUN_OUTPUT" "Usage:"
assert_log_empty
grep -q "^ARG AGENT_VERSION_CODEX=${FIXTURE_OLD_CODEX}$" "$FIXTURE_ROOT/images/tools/codex/Dockerfile" \
    || fail "--help must not touch the Dockerfiles"

new_case no-args
ARGS=()
run_agent_versions
[[ $RUN_STATUS -eq 2 ]] || fail "no args must exit 2, got $RUN_STATUS"
assert_contains "$RUN_STDERR" "Usage:"
assert_log_empty

new_case unknown-arg
ARGS=(--bogus)
run_agent_versions
[[ $RUN_STATUS -eq 2 ]] || fail "an unknown arg must exit 2, got $RUN_STATUS"
assert_contains "$RUN_STDERR" "unknown argument: --bogus"
assert_log_empty

new_case unknown-after-write
ARGS=(--write --bogus)
run_agent_versions
[[ $RUN_STATUS -eq 2 ]] || fail "an unknown arg after --write must exit 2, got $RUN_STATUS"
assert_contains "$RUN_STDERR" "unknown argument: --bogus"
assert_log_empty

new_case repo-root-without-write
ARGS=(--repo-root "$FIXTURE_ROOT")
run_agent_versions
[[ $RUN_STATUS -eq 2 ]] || fail "--repo-root without --write must exit 2, got $RUN_STATUS"
assert_contains "$RUN_STDERR" "Usage:"
assert_log_empty

new_case missing-repo-root-dir
ARGS=(--write --repo-root "$CASE/nope")
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "not a directory"
assert_log_empty

# --- GITHUB_ACTIONS refuses before any query or write -----------------------

new_case github-actions
GITHUB_ACTIONS=true
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "refusing to run under GitHub Actions"
assert_log_empty
grep -q "^ARG AGENT_VERSION_CODEX=${FIXTURE_OLD_CODEX}$" "$FIXTURE_ROOT/images/tools/codex/Dockerfile" \
    || fail "a refused CI run must not touch the Dockerfiles"

# --- happy path: four staged exact ARG edits --------------------------------

new_case happy
GITHUB_OUTPUT="$CASE/github_output"
run_agent_versions
[[ $RUN_STATUS -eq 0 ]] || fail "the happy path must succeed: $RUN_STDERR"
assert_contains "$RUN_OUTPUT" "codex ${FIXTURE_OLD_CODEX} -> rust-v0.30.0"
assert_contains "$RUN_OUTPUT" "opencode ${FIXTURE_OLD_OPENCODE} -> v1.2.3"
assert_contains "$RUN_OUTPUT" "claude ${FIXTURE_OLD_CLAUDE} -> 1.0.100"
assert_contains "$RUN_OUTPUT" "copilot ${FIXTURE_OLD_COPILOT} -> 0.1.30"
assert_contains "$RUN_OUTPUT" "images/tools/codex/Dockerfile"
assert_contains "$RUN_OUTPUT" "images/tools/opencode/Dockerfile"
assert_contains "$RUN_OUTPUT" "images/tools/claude/Dockerfile"
assert_contains "$RUN_OUTPUT" "images/tools/copilot/Dockerfile"
# The old interface's machine-adoptable `tool=version` lines are gone.
assert_not_contains "$RUN_OUTPUT" "codex="
assert_not_contains "$RUN_OUTPUT" "opencode="
# The write tool never emits GITHUB_OUTPUT.
[[ ! -e "$GITHUB_OUTPUT" ]] || fail "GITHUB_OUTPUT must not be written: $(cat "$GITHUB_OUTPUT")"

assert_arg_rewritten() { # $1 = tool, $2 = new value
    local file="$FIXTURE_ROOT/images/tools/$1/Dockerfile" count
    count="$(count_lines "^ARG AGENT_VERSION_$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')=$2\$" "$file")"
    [[ "$count" == 1 ]] || fail "$1: expected exactly one exact ARG line, found $count in $(cat "$file")"
}

# All four fixture Dockerfiles must still carry their original ARG default: a
# rejected fetched response must never stage a partial write.
assert_all_args_unchanged() {
    grep -q "^ARG AGENT_VERSION_CODEX=${FIXTURE_OLD_CODEX}$" "$FIXTURE_ROOT/images/tools/codex/Dockerfile" \
        || fail "codex Dockerfile changed on rejection: $(cat "$FIXTURE_ROOT/images/tools/codex/Dockerfile")"
    grep -q "^ARG AGENT_VERSION_OPENCODE=${FIXTURE_OLD_OPENCODE}$" "$FIXTURE_ROOT/images/tools/opencode/Dockerfile" \
        || fail "opencode Dockerfile changed on rejection"
    grep -q "^ARG AGENT_VERSION_CLAUDE=${FIXTURE_OLD_CLAUDE}$" "$FIXTURE_ROOT/images/tools/claude/Dockerfile" \
        || fail "claude Dockerfile changed on rejection"
    grep -q "^ARG AGENT_VERSION_COPILOT=${FIXTURE_OLD_COPILOT}$" "$FIXTURE_ROOT/images/tools/copilot/Dockerfile" \
        || fail "copilot Dockerfile changed on rejection"
}
assert_arg_rewritten codex rust-v0.30.0
assert_arg_rewritten opencode v1.2.3
assert_arg_rewritten claude 1.0.100
assert_arg_rewritten copilot 0.1.30
assert_not_contains "$(cat "$FIXTURE_ROOT/images/tools/codex/Dockerfile")" "$FIXTURE_OLD_CODEX"

# --- the authentication token never appears in diagnostics ------------------

new_case token-not-printed
GH_TOKEN=secret-token
run_agent_versions
[[ $RUN_STATUS -eq 0 ]] || fail "the authenticated path must succeed: $RUN_STDERR"
assert_not_contains "$RUN_COMBINED" "secret-token"
assert_contains "$(cat "$CASE/log")" "Authorization: Bearer secret-token"

# --- already-current defaults are a clean no-op -----------------------------

new_case already-current
STUB_CODEX='{"tag_name":"rust-v0.29.9"}'
STUB_OPENCODE='{"tag_name":"v1.2.2"}'
STUB_CLAUDE='1.0.99'
STUB_COPILOT='0.1.29'
run_agent_versions
[[ $RUN_STATUS -eq 0 ]] || fail "a no-op run must succeed: $RUN_STDERR"
assert_contains "$RUN_OUTPUT" "already current"
grep -q "^ARG AGENT_VERSION_CODEX=${FIXTURE_OLD_CODEX}$" "$FIXTURE_ROOT/images/tools/codex/Dockerfile" \
    || fail "a no-op run must not touch the Dockerfiles"

# --- HTTP-200-but-garbage / malformed values, per tool ----------------------

new_case codex-null
STUB_CODEX='{"tag_name":null}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version empty/null"

new_case codex-empty-string
STUB_CODEX='{"tag_name":""}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version empty/null"

new_case codex-html
STUB_CODEX='<html><body>error</body></html>'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version lookup failed"

new_case codex-multiline
STUB_CODEX='{"tag_name":"rust-v1.0.0\nrust-v1.0.1"}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version has unexpected characters"

new_case codex-metachar
STUB_CODEX='{"tag_name":"v1.2.3; rm -rf /"}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version has unexpected characters"

new_case codex-no-prefix
STUB_CODEX='{"tag_name":"1.2.3"}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex tag is not rust-v<semver>: '1.2.3'"

new_case codex-bad-semver
STUB_CODEX='{"tag_name":"rust-v1.2"}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version is not exact semver: 'rust-v1.2'"

new_case opencode-null
STUB_OPENCODE='{"tag_name":null}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "opencode version empty/null"

new_case opencode-empty
STUB_OPENCODE=''
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "opencode version empty/null"

new_case opencode-no-prefix
STUB_OPENCODE='{"tag_name":"1.2.3"}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "opencode tag is not v<semver>: '1.2.3'"

new_case claude-empty
STUB_CLAUDE=''
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version empty/null"

new_case claude-null
STUB_CLAUDE='null'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version empty/null"

new_case claude-html
STUB_CLAUDE='<html>'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version has unexpected characters"

new_case claude-whitespace
STUB_CLAUDE='1.2.3 '
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version has unexpected characters"

new_case claude-leading-zero
STUB_CLAUDE='01.2.3'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version is not exact semver: '01.2.3'"

new_case claude-bare-major-minor
STUB_CLAUDE='1.2'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version is not exact semver: '1.2'"

new_case copilot-empty
STUB_COPILOT=''
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "copilot version empty/null"

new_case copilot-garbage
STUB_COPILOT='not-a-version'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "copilot version is not exact semver: 'not-a-version'"

new_case copilot-metachar
# shellcheck disable=SC2016  # the literal `$(...)` is exactly the metachar input under test
STUB_COPILOT='1.2.3$(reboot)'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "copilot version has unexpected characters"

# --- canonical grammar: empty and leading-zero pre-release/build ids --------
# Each response below was accepted by the old `[0-9A-Za-z.-]+` body and would
# have been staged into the Dockerfile, where the owning installer rejects it.
# The binder must refuse it before any staging (review E1).

new_case claude-prerelease-leading-zero
STUB_CLAUDE='1.2.3-01'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version is not exact semver: '1.2.3-01'"
assert_all_args_unchanged

new_case claude-prerelease-empty-id
STUB_CLAUDE='1.2.3-a..b'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version is not exact semver: '1.2.3-a..b'"
assert_all_args_unchanged

new_case claude-prerelease-trailing-dot
STUB_CLAUDE='1.2.3-a.'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version is not exact semver: '1.2.3-a.'"
assert_all_args_unchanged

new_case claude-build-not-supported
# The claude owning hook has no `+build` alternative; the bumper must be no
# more permissive than the hook, so an empty or any build id is refused here.
STUB_CLAUDE='1.2.3+..'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version is not exact semver: '1.2.3+..'"
assert_all_args_unchanged

new_case copilot-build-empty-id
STUB_COPILOT='1.2.3+..'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "copilot version is not exact semver: '1.2.3+..'"
assert_all_args_unchanged

new_case copilot-build-leading-dot
STUB_COPILOT='1.2.3+.b'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "copilot version is not exact semver: '1.2.3+.b'"
assert_all_args_unchanged

new_case opencode-prerelease-leading-zero
STUB_OPENCODE='{"tag_name":"v1.2.3-01"}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "opencode version is not exact semver: 'v1.2.3-01'"
assert_all_args_unchanged

new_case codex-prerelease-leading-zero
STUB_CODEX='{"tag_name":"rust-v1.2.3-alpha.01"}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version is not exact semver: 'rust-v1.2.3-alpha.01'"
assert_all_args_unchanged

new_case codex-unsupported-prerelease
# codex's owning hook accepts only its alpha/beta subset, so a generic
# pre-release spelling must be refused at the bumper instead of staged.
STUB_CODEX='{"tag_name":"rust-v1.2.3-rc.1"}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version is not exact semver: 'rust-v1.2.3-rc.1'"
assert_all_args_unchanged

# --- canonical grammar: accepted ids are still staged (controls) ------------

new_case canonical-prerelease-build-accepted
STUB_CODEX='{"tag_name":"rust-v1.2.3-alpha.1.2"}'
STUB_OPENCODE='{"tag_name":"v1.2.3-rc.1+build.01"}'
STUB_CLAUDE='1.2.3-rc.1'
STUB_COPILOT='1.2.3+build.01'
run_agent_versions
[[ $RUN_STATUS -eq 0 ]] || fail "canonical version ids must be accepted: $RUN_STDERR"
assert_arg_rewritten codex rust-v1.2.3-alpha.1.2
assert_arg_rewritten opencode v1.2.3-rc.1+build.01
assert_arg_rewritten claude 1.2.3-rc.1
assert_arg_rewritten copilot 1.2.3+build.01

# --- lookup failures are hard and never partial-write -----------------------

new_case curl-fail
STUB_CURL_FAIL=1
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version lookup failed"
grep -q "^ARG AGENT_VERSION_CODEX=${FIXTURE_OLD_CODEX}$" "$FIXTURE_ROOT/images/tools/codex/Dockerfile" \
    || fail "a failed lookup must not touch the Dockerfiles"

new_case npm-fail
STUB_NPM_FAIL=1
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "copilot version lookup failed"

# --- Dockerfile guards: missing, duplicate and unwritable -------------------

new_case duplicate-arg
write_dockerfile codex "ARG AGENT_VERSION_CODEX=${FIXTURE_OLD_CODEX}" "ARG AGENT_VERSION_CODEX=rust-v0.1.0"
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "expected exactly one 'ARG AGENT_VERSION_CODEX='"
assert_contains "$RUN_COMBINED" "found 2"

new_case missing-arg
write_dockerfile codex "LABEL org.example=1"
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "expected exactly one 'ARG AGENT_VERSION_CODEX='"
assert_contains "$RUN_COMBINED" "found 0"

new_case missing-dockerfile
rm -f "$FIXTURE_ROOT/images/tools/claude/Dockerfile"
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "missing Dockerfile"

# --- staged-write contract: a mid-write failure leaves all four intact ------

new_case mid-write-failure
for tool in codex opencode claude copilot; do
    cp "$FIXTURE_ROOT/images/tools/$tool/Dockerfile" "$CASE/$tool.orig"
done
STUB_MV_FAIL_MATCH="/copilot/Dockerfile"
run_agent_versions
assert_status_fail
for tool in codex opencode claude copilot; do
    cmp -s "$FIXTURE_ROOT/images/tools/$tool/Dockerfile" "$CASE/$tool.orig" \
        || fail "a mid-write failure changed $tool/Dockerfile"
done

echo 'agent-versions black-box tests passed'
