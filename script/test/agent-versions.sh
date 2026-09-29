#!/usr/bin/env bash
# Black-box tests for script/build/agent-versions.sh, the one resolver CI and
# images/build.sh share for each installer layer's AGENT_VERSION_* cache key.
#
# No network: a fake `curl` (GitHub + the claude channel) and a fake `npm`
# (copilot's dist-tag) answer from environment variables, so every guard is
# exercised hermetically -- the four `tool=version` lines, GH_TOKEN
# authentication, HTTP-200-but-garbage bodies (`null`, empty, HTML), an
# implausible version, the up-front tool check, and the `::error::` annotation
# under GitHub Actions. `jq` is the real one, since the JSON extraction is part
# of what is under test.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
SCRIPT="$REPO_ROOT/script/build/agent-versions.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agent-versions-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

REAL_JQ="$(command -v jq || true)"
[[ -n "$REAL_JQ" ]] || { echo "FAIL: jq is required" >&2; exit 1; }
JQ_DIR="$(dirname "$REAL_JQ")"
BASH_BIN="${BASH:-/bin/bash}"

DEFAULT_CODEX='{"tag_name":"v0.30.0"}'
DEFAULT_OPENCODE='{"tag_name":"v1.2.3"}'
DEFAULT_CLAUDE='1.0.100'
DEFAULT_COPILOT='0.1.30'

STUB_BIN="$TEST_ROOT/bin"
mkdir -p "$STUB_BIN"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2 (got: $1)"
}

assert_status_fail() {
    [[ $RUN_STATUS -ne 0 ]] || fail "expected failure, got success: $RUN_OUTPUT"
}

assert_not_contains() {
    [[ "$1" != *"$2"* ]] || fail "expected output NOT to contain: $2 (got: $1)"
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
chmod +x "$STUB_BIN/curl" "$STUB_BIN/npm"

CASE=""

new_case() {
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/home"
    STUB_CODEX="$DEFAULT_CODEX"
    STUB_OPENCODE="$DEFAULT_OPENCODE"
    STUB_CLAUDE="$DEFAULT_CLAUDE"
    STUB_COPILOT="$DEFAULT_COPILOT"
    unset STUB_CURL_FAIL STUB_NPM_FAIL GH_TOKEN GITHUB_ACTIONS
    : >"$CASE/log"
    : >"$CASE/stderr"
}

run_agent_versions() {
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$STUB_BIN:$JQ_DIR:/usr/bin:/bin" \
        "HOME=$CASE/home" \
        "STUB_LOG=$CASE/log" \
        "STUB_CODEX=${STUB_CODEX-}" \
        "STUB_OPENCODE=${STUB_OPENCODE-}" \
        "STUB_CLAUDE=${STUB_CLAUDE-}" \
        "STUB_COPILOT=${STUB_COPILOT-}" \
        "STUB_CURL_FAIL=${STUB_CURL_FAIL-}" \
        "STUB_NPM_FAIL=${STUB_NPM_FAIL-}" \
        "GH_TOKEN=${GH_TOKEN-}" \
        "GITHUB_ACTIONS=${GITHUB_ACTIONS-}" \
        "$BASH_BIN" "$SCRIPT" 2>"$CASE/stderr")"
    RUN_STATUS=$?
    RUN_STDERR="$(cat "$CASE/stderr")"
    RUN_COMBINED="$RUN_OUTPUT
$RUN_STDERR"
    set -e
}

# --- happy path: exactly four tool=version lines ----------------------------

new_case happy
run_agent_versions
[[ $RUN_STATUS -eq 0 ]] || fail "the happy path must succeed: $RUN_STDERR"
expected="codex=v0.30.0
opencode=v1.2.3
claude=1.0.100
copilot=0.1.30"
[[ "$RUN_OUTPUT" == "$expected" ]] || fail "unexpected output: $RUN_OUTPUT"

# --- GH_TOKEN is passed to the GitHub API -----------------------------------

new_case gh-token
GH_TOKEN=secret-token
run_agent_versions
[[ $RUN_STATUS -eq 0 ]] || fail "the authenticated path must succeed: $RUN_STDERR"
grep -Fq 'Authorization: Bearer secret-token' "$CASE/log" \
    || fail "GH_TOKEN was not sent as an Authorization header"

# --- HTTP-200-but-garbage bodies -------------------------------------------

new_case html
STUB_CODEX='<html><body>error</body></html>'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version lookup failed"

new_case null
STUB_CODEX='{"tag_name":null}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version empty/null"

new_case empty
STUB_CODEX=''
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version empty/null"

# The same guard exists per tool; opencode's is not covered by codex's.
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

new_case curl-fail
STUB_CURL_FAIL=1
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "codex version lookup failed"

new_case npm-fail
STUB_NPM_FAIL=1
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "copilot version lookup failed"

# --- implausible version strings -------------------------------------------

new_case claude-implausible
STUB_CLAUDE='<html>'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "claude version implausible: '<html>'"

new_case copilot-implausible
STUB_COPILOT='not-a-version'
run_agent_versions
assert_status_fail
assert_contains "$RUN_COMBINED" "copilot version implausible: 'not-a-version'"

# --- GITHUB_ACTIONS: ::error:: annotation on stderr, clean stdout -----------

new_case github-annotation
STUB_CODEX='{"tag_name":null}'
GITHUB_ACTIONS=true
run_agent_versions
assert_status_fail
assert_contains "$RUN_STDERR" "::error::codex version empty/null"
[[ -z "$RUN_OUTPUT" ]] || fail "a failing run must not write to stdout: $RUN_OUTPUT"

# ...and without GITHUB_ACTIONS the annotation must NOT be emitted (a bare
# `::error::` in a developer's terminal is noise, and only Actions reads it).
new_case no-github-annotation
STUB_CODEX='{"tag_name":null}'
run_agent_versions
assert_status_fail
assert_contains "$RUN_STDERR" "codex version empty/null"
assert_not_contains "$RUN_STDERR" "::error::"

# --- T6: the up-front tool check fires before any lookup --------------------

new_case missing-npm
partial="$TEST_ROOT/bin-partial"
mkdir -p "$partial"
cp "$STUB_BIN/curl" "$partial/curl"
ln -sf "$REAL_JQ" "$partial/jq"
set +e
RUN_OUTPUT="$(env -i "PATH=$partial" "HOME=$CASE/home" "$BASH_BIN" "$SCRIPT" 2>&1)"
RUN_STATUS=$?
set -e
assert_status_fail
assert_contains "$RUN_OUTPUT" "npm is required"

echo 'agent-versions black-box tests passed'
