#!/usr/bin/env bash
# Black-box tests for the dsh lock preparation
# (images/tools/dsh/prepare-lock.sh) and its build-mode location freeze
# (images/tools/dsh/check-lock-update.js).
#
# No registry and no network: a fake `npm` copies a pre-generated result pair
# (or fails on demand) into the scratch project, so the REAL prepare-lock.sh
# runs end to end -- prefix validation, exact-slot syntax, the empty/equal
# no-op, the incremental update, the check, and the copy-back -- against a
# compact synthetic lock that models the committed shape (a root, the two roots,
# a nested sandbox, a nested transitive and a hoisted shared record). The real
# check-lock-update.js (node) performs the freeze comparison. `jq` is the real
# one.
#
# The captured lock-prototype evidence (real dsh-only/pnpm-only/dsh-both locks)
# was validated against this same checker during implementation; those full
# locks are not committed (they are ~1MB) -- this fixture reproduces every
# structural case they exercise.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
PREPARE="$REPO_ROOT/images/tools/dsh/prepare-lock.sh"
CHECK="$REPO_ROOT/images/tools/dsh/check-lock-update.js"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dsh-prepare-lock-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT
# mktemp -d is 0700; a fixture prefix must be traversable for the later Docker
# T5 tiers, and prepare-lock resolves the physical path.
chmod 0755 "$TEST_ROOT"

REAL_JQ="$(command -v jq || true)"
[[ -n "$REAL_JQ" ]] || { echo "FAIL: jq is required" >&2; exit 1; }
JQ_DIR="$(dirname "$REAL_JQ")"
REAL_NODE="$(command -v node || true)"
[[ -n "$REAL_NODE" ]] || { echo "FAIL: node is required" >&2; exit 1; }
NODE_DIR="$(dirname "$REAL_NODE")"

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
        cp "$STUB_RESULT/package.json" package.json
        cp "$STUB_RESULT/package-lock.json" package-lock.json
        ;;
    *)
        echo "stub npm: unhandled invocation: $*" >&2
        exit 3
        ;;
esac
SH
chmod +x "$STUB_BIN/npm"

# The committed fixture, modelling the real dsh lock's shape.
write_committed() {
    local dir="$1"
    mkdir -p "$dir"
    cat >"$dir/package.json" <<'JSON'
{
  "name": "agent-vm-dsh-layer",
  "private": true,
  "description": "committed dsh pin fixture",
  "dependencies": { "@deepseek-ai/dsh": "1.2.3", "pnpm": "4.5.6" }
}
JSON
    cat >"$dir/package-lock.json" <<'JSON'
{
  "name": "agent-vm-dsh-layer",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "agent-vm-dsh-layer", "dependencies": { "@deepseek-ai/dsh": "1.2.3", "pnpm": "4.5.6" } },
    "node_modules/@deepseek-ai/dsh": { "version": "1.2.3", "resolved": "https://r/dsh.tgz", "integrity": "sha512-DSH", "dependencies": { "@deepseek-ai/dsh-base": "^1.2.3" } },
    "node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base": { "version": "1.2.3", "resolved": "https://r/base.tgz", "integrity": "sha512-BASE" },
    "node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-sandbox-local": { "version": "1.2.3", "resolved": "https://r/sandbox.tgz", "integrity": "sha512-SANDBOX" },
    "node_modules/pnpm": { "version": "4.5.6", "resolved": "https://r/pnpm.tgz", "integrity": "sha512-PNPM" },
    "node_modules/shared-lib": { "version": "9.9.9", "resolved": "https://r/shared.tgz", "integrity": "sha512-SHARED" }
  }
}
JSON
}

# Generate a "prepared by npm" result pair from the committed lock.
#   $1 result dir, $2 dsh pin, $3 pnpm pin, $4 extra jq filter (optional)
make_result() {
    local dir="$1" d="$2" p="$3" extra="${4:-.}"
    mkdir -p "$dir"
    jq --arg d "$d" --arg p "$p" '.dependencies["@deepseek-ai/dsh"] = $d | .dependencies.pnpm = $p' \
        "$CASE/prefix/dsh/package.json" >"$dir/package.json"
    jq --arg d "$d" --arg p "$p" --argjson want_dsh "$([[ "$d" = 1.2.3 ]] && echo true || echo false)" '
        .packages[""].dependencies["@deepseek-ai/dsh"] = $d
        | .packages[""].dependencies.pnpm = $p
        | .packages["node_modules/@deepseek-ai/dsh"].version = $d
        | .packages["node_modules/pnpm"].version = $p
        | (if $want_dsh then . else
              .packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base"].version = $d
              | .packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-sandbox-local"].version = $d
           end)
        | '"$extra" \
        "$CASE/prefix/dsh/package-lock.json" >"$dir/package-lock.json"
}

CASE=""

new_case() {
    unset STUB_FAIL STUB_RESULT NO_FIXTURE_ROOT FIXTURE_ROOT
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/prefix/dsh" "$CASE/result" "$CASE/expected"
    write_committed "$CASE/prefix/dsh"
    cp "$CASE/prefix/dsh/package.json" "$CASE/prefix/dsh/package-lock.json" "$CASE/expected/"
    : >"$CASE/npm.log"
}

run_prepare() { # args passed after the prefix
    local fixture_env
    if [ "${NO_FIXTURE_ROOT:-}" = 1 ]; then
        fixture_env="AGENT_VM_FIXTURE_ROOT="
    else
        fixture_env="AGENT_VM_FIXTURE_ROOT=${FIXTURE_ROOT:-$CASE/prefix}"
    fi
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$STUB_BIN:$NODE_DIR:$JQ_DIR:/usr/bin:/bin" \
        "STUB_LOG=$CASE/npm.log" \
        "STUB_FAIL=${STUB_FAIL:-}" \
        "STUB_RESULT=${STUB_RESULT:-}" \
        "$fixture_env" \
        sh "$PREPARE" "$CASE/prefix/dsh" "$@" 2>&1)"
    RUN_STATUS=$?
    set -e
}

npm_called() {
    [ -s "$CASE/npm.log" ] || fail "expected the fake npm to be invoked"
}

npm_not_called() {
    [ ! -s "$CASE/npm.log" ] || fail "expected NO npm invocation, log: $(cat "$CASE/npm.log")"
}

assert_prefix_unchanged() {
    cmp -s "$CASE/expected/package.json" "$CASE/prefix/dsh/package.json" \
        || fail "the manifest changed (expected byte-identical)"
    cmp -s "$CASE/expected/package-lock.json" "$CASE/prefix/dsh/package-lock.json" \
        || fail "the lock changed (expected byte-identical)"
}

# --- empty / equal slots: no npm, bytes untouched ---------------------------

new_case empty
run_prepare "" ""
assert_success
npm_not_called
assert_prefix_unchanged
assert_contains "$RUN_OUTPUT" "unchanged; committed lock reused"

new_case equal-explicit
run_prepare 1.2.3 4.5.6
assert_success
npm_not_called
assert_prefix_unchanged

# --- one changed slot, other empty ------------------------------------------

new_case dsh-only
make_result "$CASE/result" 1.2.4 4.5.6
STUB_RESULT="$CASE/result"
run_prepare 1.2.4 ""
assert_success
npm_called
[[ "$(jq -r '.dependencies["@deepseek-ai/dsh"]' "$CASE/prefix/dsh/package.json")" == "1.2.4" ]] \
    || fail "the dsh pin was not updated"
[[ "$(jq -r '.packages["node_modules/@deepseek-ai/dsh"].version' "$CASE/prefix/dsh/package-lock.json")" == "1.2.4" ]] \
    || fail "the lock did not follow"
[[ "$(jq -r '.packages["node_modules/pnpm"].version' "$CASE/prefix/dsh/package-lock.json")" == "4.5.6" ]] \
    || fail "the unselected pnpm slot moved"
assert_contains "$RUN_OUTPUT" "changed only"

new_case pnpm-only
make_result "$CASE/result" 1.2.3 4.6.0
STUB_RESULT="$CASE/result"
run_prepare "" 4.6.0
assert_success
npm_called
[[ "$(jq -r '.dependencies.pnpm' "$CASE/prefix/dsh/package.json")" == "4.6.0" ]] \
    || fail "the pnpm pin was not updated"
[[ "$(jq -r '.packages["node_modules/@deepseek-ai/dsh"].version' "$CASE/prefix/dsh/package-lock.json")" == "1.2.3" ]] \
    || fail "the unselected dsh slot moved"

new_case both
make_result "$CASE/result" 1.2.4 4.6.0
STUB_RESULT="$CASE/result"
run_prepare 1.2.4 4.6.0
assert_success
npm_called
assert_contains "$RUN_OUTPUT" '"@deepseek-ai/dsh", "pnpm"'

# --- prefix / input validation ----------------------------------------------

new_case no-fixture-root
NO_FIXTURE_ROOT=1
run_prepare "" ""
assert_failure
assert_contains "$RUN_OUTPUT" "without AGENT_VM_FIXTURE_ROOT"
unset NO_FIXTURE_ROOT

new_case outside-fixture-root
mkdir -p "$CASE/other"
FIXTURE_ROOT="$CASE/other"
run_prepare "" ""
assert_failure
assert_contains "$RUN_OUTPUT" "outside the fixture root"

new_case bad-version
# SP4: the whole value must be validated before npm. The multi-line range has
# an exact-looking FIRST line, which a line-oriented `grep -Eq` accepted; the
# leading-zero components/prerelease ids are outside the canonical grammar.
for bad in latest next '^1.2.3' '1.2' 'https://x' '1.2.3 beta' \
    "$(printf '1.2.4\n||\n>=1.2.3')" '01.2.3' '1.02.3' '1.2.03' '1.2.3-01'; do
    run_prepare "$bad" ""
    assert_failure
    assert_contains "$RUN_OUTPUT" "not an exact npm version"
    npm_not_called
    assert_prefix_unchanged
done

# --- npm failure and freeze rejection leave the committed files ------------

new_case npm-failure
STUB_FAIL=1
run_prepare 1.2.4 ""
assert_failure
npm_called
assert_prefix_unchanged

# A changed slot whose prepared lock moves a frozen (hoisted/shared) record is
# rejected by the build-mode freeze, and nothing is written.
new_case frozen-move
make_result "$CASE/result" 1.2.4 4.5.6 '.packages["node_modules/shared-lib"].version = "0.0.1"'
STUB_RESULT="$CASE/result"
run_prepare 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "node_modules/shared-lib (changed)"
assert_prefix_unchanged

# --- --refresh-lock: developer path skips the freeze ------------------------

new_case refresh
make_result "$CASE/result" 1.2.4 4.5.6 '.packages["node_modules/shared-lib"].version = "0.0.1"'
STUB_RESULT="$CASE/result"
run_prepare 1.2.4 "" --refresh-lock
assert_success
npm_called
[[ "$(jq -r '.packages["node_modules/shared-lib"].version' "$CASE/prefix/dsh/package-lock.json")" == "0.0.1" ]] \
    || fail "refresh-lock should have accepted the transitive refresh"

# --- check-lock-update.js: direct negatives ---------------------------------
# The negative locks are produced by hand and run through the checker with
# explicit requested slots, so every allowed/disallowed decision is pinned.

run_check() { # old-manifest old-lock new-manifest new-lock dsh pnpm
    set +e
    RUN_OUTPUT="$(env -i "PATH=$NODE_DIR:$JQ_DIR:/usr/bin:/bin" \
        node "$CHECK" "$@" 2>&1)"
    RUN_STATUS=$?
    set -e
}

check_case() {
    CASE="$TEST_ROOT/check-$1"
    mkdir -p "$CASE"
    write_committed "$CASE/old"
    cp "$CASE/old/package.json" "$CASE/new.json"
    cp "$CASE/old/package-lock.json" "$CASE/new-lock.json"
}

# A frozen record changed
check_case frozen-changed
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"
    | .packages["node_modules/shared-lib"].integrity = "sha512-OTHER"' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "shared-lib (changed)"

# A frozen record removed (hoisted relocation)
check_case frozen-removed
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"
    | del(.packages["node_modules/shared-lib"])' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "shared-lib (removed)"

# A frozen record added (shared/hoisted drift)
check_case frozen-added
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"
    | .packages["node_modules/shared-lib/node_modules/leftpad"] = { "version": "1.0.0", "integrity": "sha512-LP" }' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "leftpad (added)"

# A prefix-collision key (dsh-extra) is outside A, so adding it fails.
check_case prefix-collision
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh-extra"] = { "version": "1.0.0", "integrity": "sha512-X" }' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "dsh-extra (added)"

# The "" root record changed a non-dependency field.
check_case root-field
jq '.packages[""].name = "evil"
    | .packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "root record"

# The manifest changed a non-dependency field.
check_case manifest-field
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4" | .description = "evil"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "manifest changed fields"

# A top-level lock field changed.
check_case top-level
jq '.name = "evil"
    | .packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "top-level lock field"

# A record inside A lost its integrity.
check_case a-integrity
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"
    | del(.packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base"].integrity)' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "carries no integrity hash"

# dsh-sandbox-local relocated under dsh-base/node_modules.
check_case sandbox-relocated
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base/node_modules/@deepseek-ai/dsh-sandbox-local"] = .packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-sandbox-local"]' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "dsh-sandbox-local"

# No changed slot but the bytes differ.
check_case equal-bytes
jq '.packages["node_modules/shared-lib"].version = "0.0.1"' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" "" ""
assert_failure
assert_contains "$RUN_OUTPUT" "not identical to the committed"

# A link record is rejected.
check_case link-record
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"
    | .packages["node_modules/ws"] = { "link": true, "resolved": "../ws" }' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_failure
assert_contains "$RUN_OUTPUT" "link record"

# Positive control: a valid changed pair passes.
check_case positive
jq '.packages[""].dependencies["@deepseek-ai/dsh"] = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh"].version = "1.2.4"
    | .packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base"].version = "1.2.4"' \
    "$CASE/new-lock.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new-lock.json"
jq '.dependencies["@deepseek-ai/dsh"] = "1.2.4"' "$CASE/new.json" >"$CASE/t" && mv "$CASE/t" "$CASE/new.json"
run_check "$CASE/old/package.json" "$CASE/old/package-lock.json" "$CASE/new.json" "$CASE/new-lock.json" 1.2.4 ""
assert_success

echo 'dsh prepare-lock black-box tests passed'
