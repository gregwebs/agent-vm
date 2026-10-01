#!/usr/bin/env bash
# Black-box tests for the Pi and bridge lock preparation
# (images/tools/pi/prepare-lock.sh, images/tools/pi/bridge/prepare-lock.sh) and
# the invariants they enforce.
#
# No registry and no network: a fake `npm` produces a pre-generated result pair
# (or fails on demand) for `install --package-lock-only` and answers
# `view <pkg>@<ver> dist.integrity` from a fixed value, so the REAL
# prepare-lock.sh scripts run end to end -- prefix validation, exact-slot
# syntax, the empty/equal no-op, the regeneration, the Pi sibling refill, the
# validation and the copy-back -- against compact synthetic locks. `jq` is the
# real one.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
PI_PREPARE="$REPO_ROOT/images/tools/pi/prepare-lock.sh"
BRIDGE_PREPARE="$REPO_ROOT/images/tools/pi/bridge/prepare-lock.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pi-prepare-lock-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT
chmod 0755 "$TEST_ROOT"

REAL_JQ="$(command -v jq || true)"
[[ -n "$REAL_JQ" ]] || { echo "FAIL: jq is required" >&2; exit 1; }
JQ_DIR="$(dirname "$REAL_JQ")"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2 (got: $1)"
}

assert_success() {
    [[ $RUN_STATUS -eq 0 ]] || fail "expected success, got $RUN_STATUS: $RUN_OUTPUT"
}

assert_failure() {
    [[ $RUN_STATUS -ne 0 ]] || fail "expected failure, got success: $RUN_OUTPUT"
}

STUB_BIN="$TEST_ROOT/bin"
mkdir -p "$STUB_BIN"
cat >"$STUB_BIN/npm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${STUB_LOG:-/dev/null}"
if [ "${STUB_FAIL:-}" = 1 ]; then
    echo "stub npm: simulated failure" >&2
    exit 7
fi
case "${1:-}" in
    install)
        [ -n "${STUB_RESULT:-}" ] || { echo "stub npm: STUB_RESULT unset" >&2; exit 4; }
        [ -d "$STUB_RESULT" ] || { echo "stub npm: STUB_RESULT missing" >&2; exit 5; }
        # Record whether a committed lock was seeded as the starting point, so a
        # developer `--refresh-lock` run can prove it is incremental.
        if [ -f package-lock.json ]; then
            printf 'had-committed-lock\n' >>"${STUB_LOG:-/dev/null}"
        else
            printf 'no-committed-lock\n' >>"${STUB_LOG:-/dev/null}"
        fi
        cp "$STUB_RESULT/package.json" package.json
        cp "$STUB_RESULT/package-lock.json" package-lock.json
        ;;
    view)
        # Only `view <spec> dist.integrity` is modelled.
        [ "${3:-}" = dist.integrity ] || { echo "stub npm: unhandled view: $*" >&2; exit 3; }
        printf 'sha512-REFILL\n'
        ;;
    *)
        echo "stub npm: unhandled invocation: $*" >&2
        exit 3
        ;;
esac
SH
chmod +x "$STUB_BIN/npm"

SIBLINGS=(chord pi-agent-core pi-ai pi-telemetry pi-tui)

# Compact committed Pi fixture modelling the real lock's shape: a root, the pi
# root, the five nested siblings, and one deeper pi-ai dependency.
write_committed_pi() {
    local dir="$1" name
    mkdir -p "$dir"
    printf '{"name":"agent-vm-guest-pi","version":"0.0.0","private":true,"dependencies":{"@earendil-works/pi-coding-agent":"0.86.1"}}\n' \
        >"$dir/package.json"
    {
        printf '{\n  "name": "agent-vm-guest-pi",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n  "packages": {\n'
        printf '    "": {"name": "agent-vm-guest-pi", "dependencies": {"@earendil-works/pi-coding-agent": "0.86.1"}},\n'
        printf '    "node_modules/@earendil-works/pi-coding-agent": {"version": "0.86.1", "resolved": "https://r/pi.tgz", "integrity": "sha512-PI"},\n'
        for name in "${SIBLINGS[@]}"; do
            printf '    "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/%s": {"version": "0.86.1", "resolved": "https://r/%s.tgz", "integrity": "sha512-%s"},\n' \
                "$name" "$name" "$name"
        done
        printf '    "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/node_modules/agent-base": {"version": "1.0.0", "resolved": "https://r/ab.tgz", "integrity": "sha512-AB"}\n'
        printf '  }\n}\n'
    } >"$dir/package-lock.json"
}

write_committed_bridge() {
    local dir="$1"
    mkdir -p "$dir"
    printf '{"name":"agent-vm-guest-pi-packages","version":"0.0.0","private":true,"dependencies":{"pi-claude-bridge":"0.5.0"}}\n' \
        >"$dir/package.json"
    cat >"$dir/package-lock.json" <<'JSON'
{
  "name": "agent-vm-guest-pi-packages",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "agent-vm-guest-pi-packages", "dependencies": { "pi-claude-bridge": "0.5.0" } },
    "node_modules/pi-claude-bridge": { "version": "0.5.0", "resolved": "https://r/bridge.tgz", "integrity": "sha512-BRIDGE" },
    "node_modules/@anthropic-ai/claude-agent-sdk": { "version": "1.0.0", "resolved": "https://r/sdk.tgz", "integrity": "sha512-SDK" }
  }
}
JSON
}

CASE=""

new_case() {
    unset STUB_FAIL STUB_RESULT NO_FIXTURE_ROOT FIXTURE_ROOT
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/result" "$CASE/expected"
    : >"$CASE/npm.log"
}

run_prepare() { # $1 = prepare script, $2 = prefix, rest = args
    local script="$1" prefix="$2"
    shift 2
    local fixture_env
    if [ "${NO_FIXTURE_ROOT:-}" = 1 ]; then
        fixture_env="AGENT_VM_FIXTURE_ROOT="
    else
        fixture_env="AGENT_VM_FIXTURE_ROOT=${FIXTURE_ROOT:-$CASE}"
    fi
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$STUB_BIN:$JQ_DIR:/usr/bin:/bin" \
        "STUB_LOG=$CASE/npm.log" \
        "STUB_FAIL=${STUB_FAIL:-}" \
        "STUB_RESULT=${STUB_RESULT:-}" \
        "$fixture_env" \
        sh "$script" "$prefix" "$@" 2>&1)"
    RUN_STATUS=$?
    set -e
}

npm_called() { [ -s "$CASE/npm.log" ] || fail "expected the fake npm to be invoked"; }
npm_not_called() { [ ! -s "$CASE/npm.log" ] || fail "expected NO npm invocation, log: $(cat "$CASE/npm.log")"; }
view_not_called() { ! grep -q '^view ' "$CASE/npm.log" || fail "expected NO npm view, log: $(cat "$CASE/npm.log")"; }

pi_case() {
    new_case "pi-$1"
    mkdir -p "$CASE/pi"
    write_committed_pi "$CASE/pi"
    cp "$CASE/pi/package.json" "$CASE/pi/package-lock.json" "$CASE/expected/"
}

bridge_case() {
    new_case "bridge-$1"
    mkdir -p "$CASE/bridge"
    write_committed_bridge "$CASE/bridge"
    cp "$CASE/bridge/package.json" "$CASE/bridge/package-lock.json" "$CASE/expected/"
}

assert_pi_unchanged() {
    cmp -s "$CASE/expected/package.json" "$CASE/pi/package.json" || fail "pi manifest changed"
    cmp -s "$CASE/expected/package-lock.json" "$CASE/pi/package-lock.json" || fail "pi lock changed"
}

assert_bridge_unchanged() {
    cmp -s "$CASE/expected/package.json" "$CASE/bridge/package.json" || fail "bridge manifest changed"
    cmp -s "$CASE/expected/package-lock.json" "$CASE/bridge/package-lock.json" || fail "bridge lock changed"
}

# --- pi: empty / equal no-op ------------------------------------------------

pi_case empty
run_prepare "$PI_PREPARE" "$CASE/pi" ""
assert_success
npm_not_called
assert_pi_unchanged
assert_contains "$RUN_OUTPUT" "unchanged; committed lock reused"

pi_case equal
run_prepare "$PI_PREPARE" "$CASE/pi" 0.86.1
assert_success
npm_not_called
assert_pi_unchanged

# --- pi: changed slot regenerates and refills the five siblings -------------

pi_case bump
jq '.dependencies["@earendil-works/pi-coding-agent"] = "0.86.2"' "$CASE/pi/package.json" \
    >"$CASE/result/package.json"
jq --arg v 0.86.2 '
    .packages[""].dependencies["@earendil-works/pi-coding-agent"] = $v
    | .packages["node_modules/@earendil-works/pi-coding-agent"].version = $v
    | reduce (["chord","pi-agent-core","pi-ai","pi-telemetry","pi-tui"][]) as $n (.;
        .packages["node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/" + $n]
        |= (.version = $v | del(.integrity)))' \
    "$CASE/pi/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$PI_PREPARE" "$CASE/pi" 0.86.2
assert_success
npm_called
[[ "$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' "$CASE/pi/package.json")" == "0.86.2" ]] \
    || fail "the pi pin was not updated"
for name in "${SIBLINGS[@]}"; do
    key="node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/$name"
    [[ "$(jq -r --arg k "$key" '.packages[$k].version' "$CASE/pi/package-lock.json")" == "0.86.2" ]] \
        || fail "$name version not updated"
    [[ "$(jq -r --arg k "$key" '.packages[$k].integrity' "$CASE/pi/package-lock.json")" == "sha512-REFILL" ]] \
        || fail "$name integrity not refilled"
done
assert_contains "$RUN_OUTPUT" "refilled @earendil-works/pi-ai@0.86.2"

# --- pi: refusals -----------------------------------------------------------

pi_case nonsibling
jq '.dependencies["@earendil-works/pi-coding-agent"] = "0.86.2"' "$CASE/pi/package.json" \
    >"$CASE/result/package.json"
jq --arg v 0.86.2 '
    .packages[""].dependencies["@earendil-works/pi-coding-agent"] = $v
    | .packages["node_modules/@earendil-works/pi-coding-agent"].version = $v
    | .packages["node_modules/leftpad"] = {"version": "1.0.0"}' \
    "$CASE/pi/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$PI_PREPARE" "$CASE/pi" 0.86.2
assert_failure
assert_contains "$RUN_OUTPUT" "has no integrity and is not one of the known"
assert_pi_unchanged

pi_case pin-mismatch
jq '.dependencies["@earendil-works/pi-coding-agent"] = "0.86.2"' "$CASE/pi/package.json" \
    >"$CASE/result/package.json"
jq '.packages[""].dependencies["@earendil-works/pi-coding-agent"] = "0.86.2"
    | .packages["node_modules/@earendil-works/pi-coding-agent"].version = "0.0.0"' \
    "$CASE/pi/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$PI_PREPARE" "$CASE/pi" 0.86.2
assert_failure
assert_contains "$RUN_OUTPUT" "fails the pin/integrity/sibling checks"
assert_pi_unchanged

pi_case sibling-missing
jq '.dependencies["@earendil-works/pi-coding-agent"] = "0.86.2"' "$CASE/pi/package.json" \
    >"$CASE/result/package.json"
jq --arg v 0.86.2 '
    .packages[""].dependencies["@earendil-works/pi-coding-agent"] = $v
    | .packages["node_modules/@earendil-works/pi-coding-agent"].version = $v
    | del(.packages["node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-tui"])' \
    "$CASE/pi/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$PI_PREPARE" "$CASE/pi" 0.86.2
assert_failure
assert_contains "$RUN_OUTPUT" "fails the pin/integrity/sibling checks"
assert_pi_unchanged

# D4: a sibling version read from the freshly generated lock must be a canonical
# exact version equal to the effective pin BEFORE it reaches `npm view`; a
# tag/range/newline must fail with no view query at all (otherwise npm would
# resolve `latest` on a malformed upstream layout).
pi_case sibling-bad-version
for bad in latest '^0.86.2' "$(printf '0.86.2\n||\n>=0.86.2')" '0.86.2-01'; do
    jq '.dependencies["@earendil-works/pi-coding-agent"] = "0.86.2"' "$CASE/pi/package.json" \
        >"$CASE/result/package.json"
    jq --arg v 0.86.2 --arg bad "$bad" '
        .packages[""].dependencies["@earendil-works/pi-coding-agent"] = $v
        | .packages["node_modules/@earendil-works/pi-coding-agent"].version = $v
        | reduce (["chord","pi-agent-core","pi-ai","pi-telemetry","pi-tui"][]) as $n (.;
            .packages["node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/" + $n]
            |= (.version = $bad | del(.integrity)))' \
        "$CASE/pi/package-lock.json" >"$CASE/result/package-lock.json"
    STUB_RESULT="$CASE/result"
    run_prepare "$PI_PREPARE" "$CASE/pi" 0.86.2
    assert_failure
    assert_contains "$RUN_OUTPUT" "non-canonical version"
    view_not_called
    assert_pi_unchanged
done

pi_case bad-version
# SP4: the whole value must be validated (not just one line), and the canonical
# grammar forbids leading-zero components/prerelease ids.
for bad in latest next '^0.87.1' '0.87' "$(printf '0.87.0\n||\n>=0.87.1')" \
    '00.87.0' '0.87.0-01'; do
    run_prepare "$PI_PREPARE" "$CASE/pi" "$bad"
    assert_failure
    assert_contains "$RUN_OUTPUT" "not an exact npm version"
    npm_not_called
done

pi_case outside-root
NO_FIXTURE_ROOT=1
run_prepare "$PI_PREPARE" "$CASE/pi" ""
assert_failure
assert_contains "$RUN_OUTPUT" "without AGENT_VM_FIXTURE_ROOT"
unset NO_FIXTURE_ROOT

# --- bridge: empty / equal no-op --------------------------------------------

bridge_case empty
run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" ""
assert_success
npm_not_called
assert_bridge_unchanged

bridge_case equal
run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" 0.5.0
assert_success
npm_not_called
assert_bridge_unchanged

# --- bridge: changed slot regenerates ---------------------------------------

bridge_case bump
jq '.dependencies["pi-claude-bridge"] = "0.6.0"' "$CASE/bridge/package.json" \
    >"$CASE/result/package.json"
jq '.packages[""].dependencies["pi-claude-bridge"] = "0.6.0"
    | .packages["node_modules/pi-claude-bridge"].version = "0.6.0"' \
    "$CASE/bridge/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" 0.6.0
assert_success
npm_called
[[ "$(jq -r '.dependencies["pi-claude-bridge"]' "$CASE/bridge/package.json")" == "0.6.0" ]] \
    || fail "the bridge pin was not updated"
assert_contains "$RUN_OUTPUT" "wrote the prepared bridge lock"

# SP4: whole-value validation and the canonical grammar for the bridge slot.
bridge_case bad-version
for bad in latest next '^0.5.0' '0.5' "$(printf '0.5.1\n||\n>=0.5.0')" \
    '00.5.0' '0.5.0-01'; do
    run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" "$bad"
    assert_failure
    assert_contains "$RUN_OUTPUT" "not an exact npm version"
    npm_not_called
done

# SP9: the developer `--refresh-lock` path must start from the committed lock so
# unrelated pinned dependencies do not silently move; the ordinary build path
# regenerates from the manifest alone.
bridge_case refresh-start-point
jq '.dependencies["pi-claude-bridge"] = "0.6.0"' "$CASE/bridge/package.json" \
    >"$CASE/result/package.json"
jq '.packages[""].dependencies["pi-claude-bridge"] = "0.6.0"
    | .packages["node_modules/pi-claude-bridge"].version = "0.6.0"' \
    "$CASE/bridge/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" 0.6.0 --refresh-lock
assert_success
grep -q '^had-committed-lock$' "$CASE/npm.log" \
    || fail "a --refresh-lock run must seed the committed lock: $(cat "$CASE/npm.log")"

bridge_case build-override-fresh
jq '.dependencies["pi-claude-bridge"] = "0.6.0"' "$CASE/bridge/package.json" \
    >"$CASE/result/package.json"
jq '.packages[""].dependencies["pi-claude-bridge"] = "0.6.0"
    | .packages["node_modules/pi-claude-bridge"].version = "0.6.0"' \
    "$CASE/bridge/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" 0.6.0
assert_success
grep -q '^no-committed-lock$' "$CASE/npm.log" \
    || fail "a build override must regenerate from the manifest alone: $(cat "$CASE/npm.log")"

# --- bridge: refusals -------------------------------------------------------

bridge_case aliased
jq '.dependencies["pi-claude-bridge"] = "0.6.0"' "$CASE/bridge/package.json" \
    >"$CASE/result/package.json"
jq '.packages[""].dependencies["pi-claude-bridge"] = "0.6.0"
    | .packages["node_modules/pi-claude-bridge"].version = "0.6.0"
    | .packages["node_modules/typebox"] = {"version": "1.0.0", "integrity": "sha512-T"}' \
    "$CASE/bridge/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" 0.6.0
assert_failure
assert_contains "$RUN_OUTPUT" "Pi's extension loader aliases"
assert_bridge_unchanged

bridge_case pin-mismatch
jq '.dependencies["pi-claude-bridge"] = "0.6.0"' "$CASE/bridge/package.json" \
    >"$CASE/result/package.json"
jq '.packages[""].dependencies["pi-claude-bridge"] = "0.6.0"
    | .packages["node_modules/pi-claude-bridge"].version = "0.0.0"' \
    "$CASE/bridge/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" 0.6.0
assert_failure
assert_contains "$RUN_OUTPUT" "fails the pin/integrity/layout checks"
assert_bridge_unchanged

bridge_case integrity
jq '.dependencies["pi-claude-bridge"] = "0.6.0"' "$CASE/bridge/package.json" \
    >"$CASE/result/package.json"
jq '.packages[""].dependencies["pi-claude-bridge"] = "0.6.0"
    | .packages["node_modules/pi-claude-bridge"].version = "0.6.0"
    | del(.packages["node_modules/pi-claude-bridge"].integrity)' \
    "$CASE/bridge/package-lock.json" >"$CASE/result/package-lock.json"
STUB_RESULT="$CASE/result"
run_prepare "$BRIDGE_PREPARE" "$CASE/bridge" 0.6.0
assert_failure
assert_contains "$RUN_OUTPUT" "fails the pin/integrity/layout checks"
assert_bridge_unchanged

echo 'pi prepare-lock black-box tests passed'
