#!/usr/bin/env bash
# Black-box contract tests for the stable `pi` wrapper (images/tools/pi/pi.sh).
#
# No Docker and no real Pi: a fake entry point on AGENT_VM_PI_ENTRY records its
# argv (one <token> per argument), its environment, and its stdin, so the
# wrapper's decisions -- the PI_SKIP_VERSION_CHECK enforcement, subcommand
# dispatch, and "inject the mandatory --extension on the non-subcommand path" --
# are pinned without a 150 MiB install or a microVM.
#
# agent-vm only intervenes where agent-vm introduced the condition, so the
# wrapper injects NO --approve default and NO PI_TELEMETRY default: those, and
# --no-approve and --extension, are forwarded untouched. The cases below pin
# that forwarding exactly.

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
CASE_EXTRA_ENV=""

new_case() {
    CASE="$TEST_ROOT/$1"
    CASE_EXTRA_ENV=""
    mkdir -p "$CASE"
    : >"$CASE/log"
    : >"$CASE/stdin"
    : >"$CASE/env"
    FAKE_EXIT_STATUS=""
    cat >"$CASE/fake-pi" <<'SH'
#!/usr/bin/env bash
{
    printf 'pi'
    printf ' <%s>' "$@"
    printf '\n'
} >>"$FAKE_LOG"
printf 'PI_SKIP_VERSION_CHECK=%s\nPI_TELEMETRY=%s\n' \
    "${PI_SKIP_VERSION_CHECK-<unset>}" "${PI_TELEMETRY-<unset>}" >"$CASE_ENV"
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
        "CASE_ENV=$CASE/env"
        "FAKE_EXIT_STATUS=${FAKE_EXIT_STATUS-}"
    )
    if [[ -n "$CASE_EXTRA_ENV" ]]; then
        env_args+=("$CASE_EXTRA_ENV")
    fi
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

assert_env_line() {
    grep -Fqx "$1" "$CASE/env" \
        || fail "expected env line [$1]; got [$(tr '\n' ' ' <"$CASE/env")]"
}

# --- the extension is injected, and only when it should be -------------------

new_case bare
run_wrapper
[[ $RUN_STATUS -eq 0 ]] || fail "bare invocation failed: $RUN_STATUS"
# The wrapper injects only the mandatory extension: no --approve, no telemetry.
assert_argv_is --extension "$MANDATORY_EXTENSION"
assert_env_line 'PI_SKIP_VERSION_CHECK=1'
# Pi's telemetry policy is Pi's own, so an unset PI_TELEMETRY stays unset.
assert_env_line 'PI_TELEMETRY=<unset>'

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

# The env enforcement is exported before the dispatch, so a subcommand
# invocation gets it too (and still no --extension / --approve).
new_case subcommand-env
run_wrapper list
assert_argv_is list
assert_env_line 'PI_SKIP_VERSION_CHECK=1'
assert_env_line 'PI_TELEMETRY=<unset>'

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

# --- no trust default: an explicit approve flag is forwarded verbatim --------

# The wrapper injects no --approve/--no-approve of its own, so an explicit one
# reaches Pi exactly once -- never duplicated, never dropped. `assert_argv_is`
# is an exact whole-line match, so a duplicate would fail here too.
new_case approve-explicit
run_wrapper --approve
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve

new_case no-approve-explicit
run_wrapper --no-approve
assert_argv_is --extension "$MANDATORY_EXTENSION" --no-approve

new_case approve-short-explicit
run_wrapper -a
assert_argv_is --extension "$MANDATORY_EXTENSION" -a

new_case no-approve-short-explicit
run_wrapper -na
assert_argv_is --extension "$MANDATORY_EXTENSION" -na

# An approve flag among other args survives exactly once, in place.
new_case approve-among-args
run_wrapper --approve --mode rpc --no-session
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve --mode rpc --no-session

# The exact line verify-pi.sh and pi-layer-runtime.sh run: the explicit
# --no-approve is forwarded verbatim and never duplicated.
new_case rpc-no-approve
run_wrapper --mode rpc --no-session --no-approve
assert_argv_is --extension "$MANDATORY_EXTENSION" --mode rpc --no-session --no-approve

# `--` still terminates option forwarding unchanged: after it, `--no-approve`
# is a message passed through to Pi, not a wrapper concern.
new_case delimiter-terminates-forwarding
run_wrapper -- --no-approve
assert_argv_is --extension "$MANDATORY_EXTENSION" -- --no-approve

# The --extension injection happens after the subcommand check, so it never
# displaces argv[1]: a subcommand keeps its position, and an approve flag after
# it is just an argument.
new_case subcommand-argv-not-displaced
run_wrapper list --approve
assert_argv_is list --approve

# --- the wrapper's env decisions (#96) --------------------------------------

# An explicit PI_TELEMETRY passes through untouched; PI_SKIP_VERSION_CHECK stays
# enforced.
new_case telemetry-explicit
CASE_EXTRA_ENV="PI_TELEMETRY=1"
run_wrapper
assert_env_line 'PI_TELEMETRY=1'
assert_env_line 'PI_SKIP_VERSION_CHECK=1'

# An empty PI_TELEMETRY is also left alone (the wrapper no longer coerces it).
new_case telemetry-empty-passthrough
CASE_EXTRA_ENV="PI_TELEMETRY="
run_wrapper
assert_env_line 'PI_TELEMETRY='
assert_env_line 'PI_SKIP_VERSION_CHECK=1'

# PI_SKIP_VERSION_CHECK is enforced, not defaulted -- an empty value is
# overwritten.
new_case skip-version-check-empty
CASE_EXTRA_ENV="PI_SKIP_VERSION_CHECK="
run_wrapper
assert_env_line 'PI_SKIP_VERSION_CHECK=1'

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
    "CASE_ENV=$CASE/env" \
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
# The wrapper must not reintroduce a trust or telemetry default. Match the code
# (not the prose above it, which deliberately names the flags it forwards).
if grep -Fq 'PI_TELEMETRY:=' "$WRAPPER" || grep -Fq 'export PI_TELEMETRY' "$WRAPPER"; then
    fail "the wrapper must not default or export PI_TELEMETRY (no telemetry default)"
fi
if grep -Fq 'approve=' "$WRAPPER" || grep -Fq 'for argument in' "$WRAPPER"; then
    fail "the wrapper must not inject or scan for approve flags (no trust default)"
fi

echo 'pi-wrapper black-box tests passed'
