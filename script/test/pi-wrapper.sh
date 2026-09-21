#!/usr/bin/env bash
# Black-box contract tests for the stable `pi` wrapper (images/tools/pi/pi.sh).
#
# No Docker and no real Pi: a fake entry point on AGENT_VM_PI_ENTRY records its
# argv (one <token> per argument), its environment, and its stdin, so the
# wrapper's decisions -- the Pi env defaults, subcommand dispatch, and "inject
# the mandatory --extension plus --approve, unless argv[1] is a subcommand (or
# the user passed an approve-family flag)" -- are pinned without a 150 MiB
# install or a microVM.

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
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve
assert_env_line 'PI_SKIP_VERSION_CHECK=1'
assert_env_line 'PI_TELEMETRY=0'

new_case prompt
run_wrapper "fix the tests"
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve "fix the tests"

new_case flags-preserved
run_wrapper -ne -p msg
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve -ne -p msg

# A subcommand is only a subcommand as argv[1]; forwarded verbatim (no -e).
for subcommand in auth config install list remove uninstall update; do
    new_case "subcommand-$subcommand"
    run_wrapper "$subcommand"
    assert_argv_is "$subcommand"
done

new_case subcommand-args-verbatim
run_wrapper auth check --provider x
assert_argv_is auth check --provider x

# W12: the env defaults are exported before the dispatch, so a subcommand
# invocation gets them too (and still no -e/--approve).
new_case subcommand-env
run_wrapper list
assert_argv_is list
assert_env_line 'PI_SKIP_VERSION_CHECK=1'
assert_env_line 'PI_TELEMETRY=0'

# The other side of the boundary: the word is a prompt/argument, not a
# subcommand, so the extension IS injected.
new_case leading-flag-then-subcommand-word
run_wrapper -p list
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve -p list

new_case subcommand-word-as-prompt
run_wrapper "list the files"
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve "list the files"

# Exact match, not a prefix match.
new_case lookalike-listen
run_wrapper listen
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve listen

new_case lookalike-auth-x
run_wrapper auth-x
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve auth-x

# --- argv fidelity: an unquoted `$@` would break every one of these ----------

new_case argv-fidelity
run_wrapper -- "-a b" "*" ""
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve -- "-a b" "*" ""

# --- --approve by default, and how a user overrides it (#96) ----------------

# W3/W4/W5: an approve-family token before `--` suppresses the default, and an
# explicit approve token is not duplicated.
new_case no-approve
run_wrapper --no-approve
assert_argv_is --extension "$MANDATORY_EXTENSION" --no-approve

new_case no-approve-short
run_wrapper -na
assert_argv_is --extension "$MANDATORY_EXTENSION" -na

new_case approve-short
run_wrapper -a
assert_argv_is --extension "$MANDATORY_EXTENSION" -a

new_case approve-explicit
run_wrapper --approve
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve

# W6: the exact line verify-pi.sh and pi-layer-runtime.sh run.
new_case rpc-no-approve
run_wrapper --mode rpc --no-session --no-approve
assert_argv_is --extension "$MANDATORY_EXTENSION" --mode rpc --no-session --no-approve

# W8: the scan stops at `--`; after it `--no-approve` is a message, not a flag.
new_case approve-scan-stops-at-delimiter
run_wrapper -- --no-approve
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve -- --no-approve

# W14/W15: the two accepted argv-scan imprecisions -- the scan deliberately
# does not model option VALUES. W14 fails toward LESS trust; W15 still emits
# the pair, which Pi's last-wins resolves in the user's favour.
new_case name-then-approve-flag
run_wrapper --name -a
assert_argv_is --extension "$MANDATORY_EXTENSION" --name -a

new_case name-then-delimiter-no-approve
run_wrapper --name -- --no-approve
assert_argv_is --extension "$MANDATORY_EXTENSION" --approve --name -- --no-approve

# --- the wrapper's env decisions (#96) --------------------------------------

# W10: an explicit PI_TELEMETRY survives; PI_SKIP_VERSION_CHECK stays enforced.
new_case telemetry-explicit
CASE_EXTRA_ENV="PI_TELEMETRY=1"
run_wrapper
assert_env_line 'PI_TELEMETRY=1'
assert_env_line 'PI_SKIP_VERSION_CHECK=1'

# W11: PI_SKIP_VERSION_CHECK is enforced, not defaulted -- an empty value is
# overwritten.
new_case skip-version-check-empty
CASE_EXTRA_ENV="PI_SKIP_VERSION_CHECK="
run_wrapper
assert_env_line 'PI_SKIP_VERSION_CHECK=1'

# W11b: `:=` treats an empty PI_TELEMETRY as unset, so it becomes 0.
new_case telemetry-empty
CASE_EXTRA_ENV="PI_TELEMETRY="
run_wrapper
assert_env_line 'PI_TELEMETRY=0'

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

echo 'pi-wrapper black-box tests passed'
