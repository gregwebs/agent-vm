#!/usr/bin/env bash
# Black-box contract tests for the stable `pi` wrapper (images/tools/pi/pi.sh).
#
# No Docker and no real Pi: a fake entry point on AGENT_VM_PI_ENTRY records its
# argv (one <token> per argument) and its stdin, so the wrapper's one decision --
# "inject the mandatory --extension, unless argv[1] is a subcommand" -- is pinned
# without a 150 MiB install or a microVM.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
WRAPPER="$REPO_ROOT/images/tools/pi/pi.sh"
MANDATORY_EXTENSION=/opt/agent-vm/pi-extensions/guest-credential-warning.js
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pi-wrapper-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

CASE=""

new_case() {
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE"
    : >"$CASE/log"
    : >"$CASE/stdin"
    FAKE_EXIT_STATUS=""
    cat >"$CASE/fake-pi" <<'SH'
#!/usr/bin/env bash
{
    printf 'pi'
    printf ' <%s>' "$@"
    printf '\n'
} >>"$FAKE_LOG"
cat >>"$CASE_STDIN"
if [[ -n "${FAKE_EXIT_STATUS:-}" ]]; then
    exit "$FAKE_EXIT_STATUS"
fi
SH
    chmod +x "$CASE/fake-pi"
}

# Run the wrapper through `sh` (it is committed 0644; the execute bit comes from
# the layer's `COPY --chmod=0755`, which this host test deliberately does not
# reproduce), with a clean environment, and capture its status.
run_wrapper() {
    local -a env_args=(
        "PATH=/usr/bin:/bin"
        "AGENT_VM_PI_ENTRY=$CASE/fake-pi"
        "FAKE_LOG=$CASE/log"
        "CASE_STDIN=$CASE/stdin"
        "FAKE_EXIT_STATUS=${FAKE_EXIT_STATUS-}"
    )
    set +e
    env -i "${env_args[@]}" sh "$WRAPPER" "$@" </dev/null
    RUN_STATUS=$?
    set -e
}

# The exact single log line the wrapper's argv must produce.
assert_argv_is() {
    local expected="pi"
    local token
    for token in "$@"; do
        expected+=" <$token>"
    done
    local actual
    actual="$(cat "$CASE/log")"
    [[ "$actual" == "$expected" ]] \
        || fail "argv mismatch: expected [$expected] got [$actual]"
}

# --- the extension is injected, and only when it should be -------------------

new_case bare
run_wrapper
[[ $RUN_STATUS -eq 0 ]] || fail "bare invocation failed: $RUN_STATUS"
assert_argv_is --extension "$MANDATORY_EXTENSION"

new_case prompt
run_wrapper "fix the tests"
assert_argv_is --extension "$MANDATORY_EXTENSION" "fix the tests"

new_case flags-preserved
run_wrapper -ne -p msg
assert_argv_is --extension "$MANDATORY_EXTENSION" -ne -p msg

# A subcommand is only a subcommand as argv[1]; forwarded verbatim (no -e).
for subcommand in auth config install list remove uninstall update; do
    new_case "subcommand-$subcommand"
    run_wrapper "$subcommand"
    assert_argv_is "$subcommand"
done

new_case subcommand-args-verbatim
run_wrapper auth check --provider x
assert_argv_is auth check --provider x

# The other side of the boundary: the word is a prompt/argument, not a
# subcommand, so the extension IS injected.
new_case leading-flag-then-subcommand-word
run_wrapper -p list
assert_argv_is --extension "$MANDATORY_EXTENSION" -p list

new_case subcommand-word-as-prompt
run_wrapper "list the files"
assert_argv_is --extension "$MANDATORY_EXTENSION" "list the files"

# Exact match, not a prefix match.
new_case lookalike-listen
run_wrapper listen
assert_argv_is --extension "$MANDATORY_EXTENSION" listen

new_case lookalike-auth-x
run_wrapper auth-x
assert_argv_is --extension "$MANDATORY_EXTENSION" auth-x

# --- argv fidelity: an unquoted `$@` would break every one of these ----------

new_case argv-fidelity
run_wrapper -- "-a b" "*" ""
assert_argv_is --extension "$MANDATORY_EXTENSION" -- "-a b" "*" ""

# --- exec, not a subshell: the entry's status is the wrapper's ---------------

new_case exit-status
FAKE_EXIT_STATUS=42
run_wrapper --version
[[ $RUN_STATUS -eq 42 ]] || fail "exit status was $RUN_STATUS, expected 42 (exec, not subshell?)"

# --- stdin reaches the entry point (RPC mode depends on it) ------------------

new_case stdin-passthrough
printf 'hello from stdin\n' | env -i \
    "PATH=/usr/bin:/bin" \
    "AGENT_VM_PI_ENTRY=$CASE/fake-pi" \
    "FAKE_LOG=$CASE/log" \
    "CASE_STDIN=$CASE/stdin" \
    "FAKE_EXIT_STATUS=" \
    sh "$WRAPPER" --mode rpc
[[ "$(cat "$CASE/stdin")" == 'hello from stdin' ]] \
    || fail "piped stdin did not reach the entry point"

# --- the test seam cannot become the production default ----------------------

grep -Fq 'AGENT_VM_PI_ENTRY:-/opt/agent-vm/pi/node_modules/.bin/pi}"' "$WRAPPER" \
    || fail "production default entry point is missing"
grep -Fq "MANDATORY_EXTENSION=$MANDATORY_EXTENSION" "$WRAPPER" \
    || fail "production mandatory-extension path is missing"
grep -Fq 'PI_SUBCOMMANDS="auth config install list remove uninstall update"' "$WRAPPER" \
    || fail "the subcommand allowlist literal changed (the image build checks drift against pi --help)"

echo 'pi-wrapper black-box tests passed'
