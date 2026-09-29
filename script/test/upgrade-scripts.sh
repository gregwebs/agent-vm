#!/usr/bin/env bash
# Black-box tests for the tool-layer upgrade scripts
# (images/tools/pi/upgrade-pi.sh, images/tools/dsh/upgrade-dsh.sh,
# images/tools/pi/bridge/upgrade-bridge.sh) and the shared resolver they source
# (script/build/npm-pin.sh).
#
# No registry and no network: a fake `npm` first on PATH answers `view` from a
# small fixture registry and, for `install --package-lock-only`, rewrites the
# lock in the working directory with a configurable jq filter. So the REAL
# scripts run end to end -- argument parsing, resolution, the scratch dir, and
# the copy-back -- against fixtures, and every failure policy (unpublished
# version, query failure, refused layout, unchanged files on failure) is
# exercised hermetically. `jq` is the real one.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/upgrade-scripts-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

REAL_JQ="$(command -v jq || true)"
[[ -n "$REAL_JQ" ]] || { echo "FAIL: jq is required" >&2; exit 1; }
JQ_DIR="$(dirname "$REAL_JQ")"

# The scripts under test are bash-only; run them under the same bash as this
# test, so `bash script/test/upgrade-scripts.sh` and `/bin/bash ...` each cover
# their own interpreter (bash 3.2 on macOS).
BASH_BIN="${BASH:-/bin/bash}"

# The committed pins the fixture registry resolves to, so a re-pin is a no-op.
PI_PIN="$(jq -r '.dependencies["@earendil-works/pi-coding-agent"]' "$REPO_ROOT/images/tools/pi/package.json")"
DSH_PIN="$(jq -r '.dependencies["@deepseek-ai/dsh"]' "$REPO_ROOT/images/tools/dsh/package.json")"
PNPM_PIN="$(jq -r '.dependencies.pnpm' "$REPO_ROOT/images/tools/dsh/package.json")"
BRIDGE_PIN="$(jq -r '.dependencies["pi-claude-bridge"]' "$REPO_ROOT/images/tools/pi/bridge/package.json")"
PNPM_BUMP=12.0.0

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

assert_status_ok() {
    [[ $RUN_STATUS -eq 0 ]] || fail "expected success, got $RUN_STATUS: $RUN_OUTPUT"
}

assert_status_fail() {
    [[ $RUN_STATUS -ne 0 ]] || fail "expected failure, got success: $RUN_OUTPUT"
}

# The fake `npm`. `view` answers only the two forms the scripts under test
# issue -- `view PKG dist-tags versions --json` (the resolver) and
# `view PKG@VERSION dist.integrity` (upgrade-pi.sh's sibling refill) -- from
# $STUB_REGISTRY (a JSON fixture); an unknown package or version is npm's E404
# (exit 1), STUB_VIEW_FAIL models an unreachable registry, and any *other* view
# form fails loudly so a test cannot pass against an unmodelled query. `install`
# copies $STUB_SEED_LOCK into the cwd when no lock is present (pi regenerates
# from nothing) and applies $STUB_INSTALL_JQ, modelling what the registry would
# produce.
cat >"$STUB_BIN/npm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${STUB_LOG:-/dev/null}"

npm_404() {
    echo "npm error code E404" >&2
    echo "npm error 404 Not Found - GET https://registry.npmjs.org/$1 - Not found" >&2
    echo "npm error 404  '$1@*' is not in this registry." >&2
    exit 1
}

case "${1:-}" in
    view)
        shift
        if [ "${STUB_VIEW_FAIL:-}" = 1 ]; then
            echo "npm error network request to the registry failed" >&2
            exit 1
        fi
        if [ "${2:-}" = dist-tags ] && [ "${3:-}" = versions ] && [ "${4:-}" = --json ]; then
            pkg=$1
            jq -e --arg p "$pkg" '.packages[$p]' "$STUB_REGISTRY" >/dev/null || npm_404 "$pkg"
            jq -c --arg p "$pkg" \
                '{ "dist-tags": .packages[$p]["dist-tags"], versions: .packages[$p].versions }' \
                "$STUB_REGISTRY"
        elif [ "${2:-}" = dist.integrity ]; then
            spec=$1
            pkg=${spec%@*}
            ver=${spec##*@}
            jq -e --arg p "$pkg" '.packages[$p]' "$STUB_REGISTRY" >/dev/null || npm_404 "$pkg"
            jq -e --arg p "$pkg" --arg v "$ver" \
                '(.packages[$p].versions // []) | index($v)' "$STUB_REGISTRY" >/dev/null \
                || npm_404 "${pkg}@${ver}"
            jq -r --arg p "$pkg" --arg v "$ver" '.packages[$p].integrity[$v] // empty' "$STUB_REGISTRY"
        else
            echo "stub npm: unhandled view form: $*" >&2
            exit 3
        fi
        ;;
    install)
        if [ -n "${STUB_SEED_LOCK:-}" ] && [ ! -f package-lock.json ]; then
            cp "$STUB_SEED_LOCK" package-lock.json
        fi
        [ -f package-lock.json ] || {
            echo "stub npm: no package-lock.json to update" >&2
            exit 4
        }
        jq "${STUB_INSTALL_JQ:-.}" package-lock.json >package-lock.json.tmp
        mv package-lock.json.tmp package-lock.json
        ;;
    *)
        echo "stub npm: unhandled invocation: $*" >&2
        exit 5
        ;;
esac
SH
chmod +x "$STUB_BIN/npm"

CASE=""

new_case() {
    unset STUB_VIEW_FAIL STUB_SEED_LOCK STUB_INSTALL_JQ PI_INTEGRITY
    CASE="$TEST_ROOT/$1"
    mkdir -p "$CASE/home" "$CASE/script/build" "$CASE/images/tools/pi/bridge" \
        "$CASE/images/tools/dsh" "$CASE/expected/pi" "$CASE/expected/dsh" \
        "$CASE/expected/bridge"
    cp "$REPO_ROOT/script/build/npm-pin.sh" "$CASE/script/build/"
    cp "$REPO_ROOT/images/tools/pi/upgrade-pi.sh" "$CASE/images/tools/pi/"
    cp "$REPO_ROOT/images/tools/pi/package.json" "$REPO_ROOT/images/tools/pi/package-lock.json" \
        "$CASE/images/tools/pi/"
    cp "$REPO_ROOT/images/tools/pi/bridge/upgrade-bridge.sh" \
        "$REPO_ROOT/images/tools/pi/bridge/package.json" "$REPO_ROOT/images/tools/pi/bridge/package-lock.json" \
        "$CASE/images/tools/pi/bridge/"
    cp "$REPO_ROOT/images/tools/dsh/upgrade-dsh.sh" \
        "$REPO_ROOT/images/tools/dsh/package.json" "$REPO_ROOT/images/tools/dsh/package-lock.json" \
        "$CASE/images/tools/dsh/"
    # Pristine snapshots: a failed run must leave the live files byte-identical.
    cp "$CASE/images/tools/pi/package.json" "$CASE/images/tools/pi/package-lock.json" "$CASE/expected/pi/"
    cp "$CASE/images/tools/pi/bridge/package.json" "$CASE/images/tools/pi/bridge/package-lock.json" "$CASE/expected/bridge/"
    cp "$CASE/images/tools/dsh/package.json" "$CASE/images/tools/dsh/package-lock.json" "$CASE/expected/dsh/"
    : >"$CASE/npm.log"
    write_registry
}

# The fixture registry, defaulting to the committed pins. Sibling integrity is
# copied from the committed pi lock unless PI_INTEGRITY overrides it, so a
# re-pin refills exactly the original bytes.
write_registry() {
    jq -n \
        --arg pi "$PI_PIN" --arg dsh "$DSH_PIN" --arg pnpm "$PNPM_PIN" \
        --arg pnb "$PNPM_BUMP" --arg bridge "$BRIDGE_PIN" \
        --arg override "${PI_INTEGRITY:-}" \
        --slurpfile pilock "$CASE/images/tools/pi/package-lock.json" '
        def sib($n): $pilock[0].packages
            ["node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/" + $n].integrity;
        def integ($n): if $override == "" then sib($n) else $override end;
        {
          packages: {
            "@earendil-works/pi-coding-agent": {"dist-tags": {latest: $pi, next: $pi}, "versions": [$pi]},
            "@deepseek-ai/dsh": {"dist-tags": {latest: $dsh, next: $dsh}, "versions": [$dsh]},
            "pnpm": {"dist-tags": {latest: $pnpm, next: $pnpm}, "versions": [$pnpm, $pnb]},
            "pi-claude-bridge": {"dist-tags": {latest: $bridge, next: $bridge}, "versions": [$bridge]},
            "@earendil-works/chord": {"versions": [$pi], "integrity": {($pi): integ("chord")}},
            "@earendil-works/pi-agent-core": {"versions": [$pi], "integrity": {($pi): integ("pi-agent-core")}},
            "@earendil-works/pi-ai": {"versions": [$pi], "integrity": {($pi): integ("pi-ai")}},
            "@earendil-works/pi-telemetry": {"versions": [$pi], "integrity": {($pi): integ("pi-telemetry")}},
            "@earendil-works/pi-tui": {"versions": [$pi], "integrity": {($pi): integ("pi-tui")}}
          }
        }' >"$CASE/registry.json"
}

# Add a publishable version for PACKAGE, optionally pointing dist-tag TAG at it.
registry_add_version() {
    local pkg="$1" ver="$2" tag="${3:-}"
    if [ -n "$tag" ]; then
        jq --arg p "$pkg" --arg v "$ver" --arg t "$tag" \
            '.packages[$p].versions += [$v] | .packages[$p]["dist-tags"][$t] = $v' \
            "$CASE/registry.json" >"$CASE/registry.json.tmp"
    else
        jq --arg p "$pkg" --arg v "$ver" '.packages[$p].versions += [$v]' \
            "$CASE/registry.json" >"$CASE/registry.json.tmp"
    fi
    mv "$CASE/registry.json.tmp" "$CASE/registry.json"
}

run_upgrade() {
    local script="$1"
    shift
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$STUB_BIN:$JQ_DIR:/usr/bin:/bin" \
        "HOME=$CASE/home" \
        "STUB_REGISTRY=$CASE/registry.json" \
        "STUB_LOG=$CASE/npm.log" \
        "STUB_VIEW_FAIL=${STUB_VIEW_FAIL:-}" \
        "STUB_SEED_LOCK=${STUB_SEED_LOCK:-}" \
        "STUB_INSTALL_JQ=${STUB_INSTALL_JQ:-.}" \
        "$BASH_BIN" "$script" "$@" 2>&1)"
    RUN_STATUS=$?
    set -e
}

# For pi the script regenerates from nothing, so the fake install must seed a
# lock (the committed one, which npm would rewrite) with the five sibling
# integrities npm's inherited shrinkwrap omits; the script refills them.
pi_install_fixture() {
    STUB_SEED_LOCK="$CASE/expected/pi/package-lock.json"
    # $n is a jq variable, not a shell one (SC2016).
    # shellcheck disable=SC2016
    STUB_INSTALL_JQ='reduce (["chord","pi-agent-core","pi-ai","pi-telemetry","pi-tui"][]) as $n (.; .packages["node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/" + $n] |= del(.integrity))'
}

assert_files_unchanged() {
    local which="$1" base exp
    case "$which" in
        pi) base=images/tools/pi ;;
        dsh) base=images/tools/dsh ;;
        bridge) base=images/tools/pi/bridge ;;
    esac
    for exp in package.json package-lock.json; do
        cmp -s "$CASE/expected/$which/$exp" "$CASE/$base/$exp" \
            || fail "$which/$exp changed (expected byte-identical)"
    done
}

# --- pi: re-pin, failure modes, dist-tag, integrity refill, refusal ---------

new_case pi-repin
pi_install_fixture
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh" "$PI_PIN"
assert_status_ok
assert_contains "$RUN_OUTPUT" "pinning @earendil-works/pi-coding-agent: $PI_PIN -> $PI_PIN"
assert_files_unchanged pi

new_case pi-latest-default
pi_install_fixture
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh"
assert_status_ok
assert_contains "$RUN_OUTPUT" "latest @earendil-works/pi-coding-agent is $PI_PIN"
assert_files_unchanged pi

new_case pi-disttag
pi_install_fixture
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh" next
assert_status_ok
assert_contains "$RUN_OUTPUT" "pinning @earendil-works/pi-coding-agent: $PI_PIN -> $PI_PIN"
assert_files_unchanged pi

new_case pi-unpublished
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh" 9.9.9
assert_status_fail
assert_contains "$RUN_OUTPUT" "@earendil-works/pi-coding-agent@9.9.9 is not a published version"
assert_not_contains "$RUN_OUTPUT" "could not query"
assert_files_unchanged pi

new_case pi-viewfail
STUB_VIEW_FAIL=1
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh" "$PI_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "npm could not query @earendil-works/pi-coding-agent"
assert_not_contains "$RUN_OUTPUT" "not a published version"
assert_files_unchanged pi

# The five siblings' `integrity` is refilled from the registry (npm's shrinkwrap
# omits it), immediately after `resolved` where npm writes it.
new_case pi-refill
PI_INTEGRITY=sha512-STUBVALUE
write_registry
pi_install_fixture
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh" "$PI_PIN"
assert_status_ok
sibling="node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai"
got="$(jq -r --arg k "$sibling" '.packages[$k].integrity' "$CASE/images/tools/pi/package-lock.json")"
[[ "$got" == "sha512-STUBVALUE" ]] \
    || fail "refilled integrity was '$got', expected sha512-STUBVALUE"
after="$(jq -r --arg k "$sibling" \
    '.packages[$k] | (keys_unsorted) as $ks | $ks[(($ks | index("resolved")) + 1)]' \
    "$CASE/images/tools/pi/package-lock.json")"
[[ "$after" == "integrity" ]] || fail "integrity was not placed after resolved (found '$after')"

# An integrity-less entry that is NOT one of the five known siblings is a layout
# change the build's own verification does not cover, so it is refused.
new_case pi-nonsibling
STUB_SEED_LOCK="$CASE/expected/pi/package-lock.json"
STUB_INSTALL_JQ='.packages["node_modules/leftpad"] = {"version": "1.0.0"}'
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh" "$PI_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "has no integrity and is not one of the known"
assert_files_unchanged pi

# The post-refill guard re-checks the same invariants cargo test does. A lock
# whose `node_modules/<pkg>.version` did not follow the pin (npm would never do
# it, but the guard must not be vacuous) is refused.
new_case pi-pin-mismatch
pi_install_fixture
STUB_INSTALL_JQ="${STUB_INSTALL_JQ} | .packages[\"node_modules/@earendil-works/pi-coding-agent\"].version = \"0.0.0\""
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh" "$PI_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "fails the pin/integrity/sibling checks"
assert_files_unchanged pi

# ...and one of the five shrinkwrap-only siblings missing entirely fails the
# sibling-set equality, even though every remaining entry still carries
# integrity (this is the guard tool_layer.rs's sibling test mirrors).
new_case pi-sibling-missing
pi_install_fixture
STUB_INSTALL_JQ="${STUB_INSTALL_JQ} | del(.packages[\"node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-tui\"])"
run_upgrade "$CASE/images/tools/pi/upgrade-pi.sh" "$PI_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "fails the pin/integrity/sibling checks"
assert_files_unchanged pi

# --- dsh: re-pin, failure modes, dist-tag bump, layout refusal, pnpm --------

new_case dsh-repin
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN"
assert_status_ok
assert_contains "$RUN_OUTPUT" "pinning @deepseek-ai/dsh: $DSH_PIN -> $DSH_PIN"
assert_files_unchanged dsh

new_case dsh-unpublished
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" 9.9.9
assert_status_fail
assert_contains "$RUN_OUTPUT" "@deepseek-ai/dsh@9.9.9 is not a published version"
assert_not_contains "$RUN_OUTPUT" "could not query"
assert_files_unchanged dsh

new_case dsh-viewfail
STUB_VIEW_FAIL=1
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "npm could not query @deepseek-ai/dsh"
assert_not_contains "$RUN_OUTPUT" "not a published version"
assert_files_unchanged dsh

new_case dsh-disttag-bump
registry_add_version @deepseek-ai/dsh 0.1.9-rc.1 next
STUB_INSTALL_JQ='.packages[""].dependencies["@deepseek-ai/dsh"] = "0.1.9-rc.1" | .packages["node_modules/@deepseek-ai/dsh"].version = "0.1.9-rc.1"'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" next
assert_status_ok
assert_contains "$RUN_OUTPUT" "pinning @deepseek-ai/dsh: $DSH_PIN -> 0.1.9-rc.1"
[[ "$(jq -r '.dependencies["@deepseek-ai/dsh"]' "$CASE/images/tools/dsh/package.json")" == "0.1.9-rc.1" ]] \
    || fail "the dsh pin was not updated"

# The layout the lock exists to freeze: a nested dsh-sandbox-local is a boot
# failure, so the script must refuse rather than commit it.
new_case dsh-sandbox
STUB_INSTALL_JQ='.packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base/node_modules/@deepseek-ai/dsh-sandbox-local"] = .packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-sandbox-local"]'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "dsh-sandbox-local is nested under dsh-base/node_modules"
assert_files_unchanged dsh

# The post-update pin/integrity guard (the same invariants cargo test checks)
# must not be vacuous: a stale node_modules version and a dropped integrity are
# each refused.
new_case dsh-pin-mismatch
STUB_INSTALL_JQ='.packages["node_modules/@deepseek-ai/dsh"].version = "0.0.0"'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "fails the pin/integrity checks"
assert_files_unchanged dsh

new_case dsh-integrity
STUB_INSTALL_JQ='del(.packages["node_modules/@deepseek-ai/dsh"].integrity)'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "fails the pin/integrity checks"
assert_files_unchanged dsh

# dsh-sandbox-local must exist where dsh resolves it: absent entirely, at a
# wrong-but-not-dsh-base path, and with a good copy *plus* a stray one (the
# per-line check must reject the whole set, not accept the good line).
new_case dsh-sandbox-absent
STUB_INSTALL_JQ='del(.packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-sandbox-local"])'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "dsh-sandbox-local is not installed where dsh resolves it"
assert_files_unchanged dsh

new_case dsh-sandbox-stray
STUB_INSTALL_JQ='.packages["node_modules/monorepo/node_modules/@deepseek-ai/dsh-sandbox-local"] = .packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-sandbox-local"] | del(.packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-sandbox-local"])'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "dsh-sandbox-local is not installed where dsh resolves it"
assert_files_unchanged dsh

new_case dsh-sandbox-two
STUB_INSTALL_JQ='.packages["node_modules/monorepo/node_modules/@deepseek-ai/dsh-sandbox-local"] = .packages["node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-sandbox-local"]'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "dsh-sandbox-local is not installed where dsh resolves it"
assert_files_unchanged dsh

# An exact version that is published but not any dist-tag resolves through the
# local `versions` membership test, not the dist-tag lookup.
new_case dsh-exact
registry_add_version @deepseek-ai/dsh 0.1.9-rc.1
STUB_INSTALL_JQ='.packages[""].dependencies["@deepseek-ai/dsh"] = "0.1.9-rc.1" | .packages["node_modules/@deepseek-ai/dsh"].version = "0.1.9-rc.1"'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" 0.1.9-rc.1
assert_status_ok
assert_contains "$RUN_OUTPUT" "pinning @deepseek-ai/dsh: $DSH_PIN -> 0.1.9-rc.1"
[[ "$(jq -r '.dependencies["@deepseek-ai/dsh"]' "$CASE/images/tools/dsh/package.json")" == "0.1.9-rc.1" ]] \
    || fail "the dsh pin was not updated to the exact version"

new_case dsh-pnpm
STUB_INSTALL_JQ='.packages[""].dependencies.pnpm = "12.0.0" | .packages["node_modules/pnpm"].version = "12.0.0"'
run_upgrade "$CASE/images/tools/dsh/upgrade-dsh.sh" "$DSH_PIN" --pnpm 12.0.0
assert_status_ok
assert_contains "$RUN_OUTPUT" "pinning pnpm: $PNPM_PIN -> 12.0.0"
[[ "$(jq -r '.dependencies.pnpm' "$CASE/images/tools/dsh/package.json")" == "12.0.0" ]] \
    || fail "the pnpm pin was not updated"

# --- bridge: re-pin, failure modes, dist-tag bump, peer line, refusal -------

new_case bridge-repin
run_upgrade "$CASE/images/tools/pi/bridge/upgrade-bridge.sh" "$BRIDGE_PIN"
assert_status_ok
assert_contains "$RUN_OUTPUT" "pinning pi-claude-bridge: $BRIDGE_PIN -> $BRIDGE_PIN"
assert_contains "$RUN_OUTPUT" "peer @earendil-works/pi-coding-agent: >=0.85.0 (image pins $PI_PIN; check compatibility)"
assert_files_unchanged bridge

new_case bridge-unpublished
run_upgrade "$CASE/images/tools/pi/bridge/upgrade-bridge.sh" 9.9.9
assert_status_fail
assert_contains "$RUN_OUTPUT" "pi-claude-bridge@9.9.9 is not a published version"
assert_not_contains "$RUN_OUTPUT" "could not query"
assert_files_unchanged bridge

new_case bridge-viewfail
STUB_VIEW_FAIL=1
run_upgrade "$CASE/images/tools/pi/bridge/upgrade-bridge.sh" "$BRIDGE_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "npm could not query pi-claude-bridge"
assert_not_contains "$RUN_OUTPUT" "not a published version"
assert_files_unchanged bridge

new_case bridge-disttag-bump
registry_add_version pi-claude-bridge 0.99.0 next
STUB_INSTALL_JQ='.packages[""].dependencies["pi-claude-bridge"] = "0.99.0" | .packages["node_modules/pi-claude-bridge"].version = "0.99.0"'
run_upgrade "$CASE/images/tools/pi/bridge/upgrade-bridge.sh" next
assert_status_ok
assert_contains "$RUN_OUTPUT" "pinning pi-claude-bridge: $BRIDGE_PIN -> 0.99.0"
[[ "$(jq -r '.dependencies["pi-claude-bridge"]' "$CASE/images/tools/pi/bridge/package.json")" == "0.99.0" ]] \
    || fail "the bridge pin was not updated"

# A lock that drags in a loader-aliased package would ship a second, skewed Pi;
# the script must reject it even though it carries integrity.
new_case bridge-typebox
STUB_INSTALL_JQ='.packages["node_modules/typebox"] = {"version": "1.3.27", "resolved": "https://registry.npmjs.org/typebox/-/typebox-1.3.27.tgz", "integrity": "sha512-AAAA"}'
run_upgrade "$CASE/images/tools/pi/bridge/upgrade-bridge.sh" "$BRIDGE_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "Pi's extension loader aliases"
assert_files_unchanged bridge

# The post-update pin/integrity guard must not be vacuous.
new_case bridge-pin-mismatch
STUB_INSTALL_JQ='.packages["node_modules/pi-claude-bridge"].version = "0.0.0"'
run_upgrade "$CASE/images/tools/pi/bridge/upgrade-bridge.sh" "$BRIDGE_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "fails the pin/integrity checks"
assert_files_unchanged bridge

new_case bridge-integrity
STUB_INSTALL_JQ='del(.packages["node_modules/pi-claude-bridge"].integrity)'
run_upgrade "$CASE/images/tools/pi/bridge/upgrade-bridge.sh" "$BRIDGE_PIN"
assert_status_fail
assert_contains "$RUN_OUTPUT" "fails the pin/integrity checks"
assert_files_unchanged bridge

# --- the resolver itself: exact-version membership, npm's one-version shape --
# The end-to-end cases above resolve the committed pin through the `latest`
# dist-tag and reject an unpublished version. These call resolve_npm_version
# directly, with a registry whose `versions` is npm's single-version shape (a
# bare string, not a one-element array), so the membership test and the shape
# normalisation each fail loudly when broken.
single_registry="$TEST_ROOT/single-registry.json"
jq -n '{packages: {"single-pkg": {versions: "1.2.3", "dist-tags": {latest: "1.2.3"}}}}' \
    >"$single_registry"
run_resolver() {
    set +e
    # The -c body is deliberately single-quoted: $1/$2 are the inner bash's
    # positional parameters, not this shell's (SC2016).
    # shellcheck disable=SC2016
    RUN_OUTPUT="$(env -i \
        "PATH=$STUB_BIN:$JQ_DIR:/usr/bin:/bin" \
        "STUB_REGISTRY=$single_registry" \
        "STUB_VIEW_FAIL=" \
        "$BASH_BIN" -c '. "$1"; resolve_npm_version single-pkg "$2"' _ \
        "$REPO_ROOT/script/build/npm-pin.sh" "$1" 2>&1)"
    RUN_STATUS=$?
    set -e
}
run_resolver 1.2.3
assert_status_ok
[[ "$RUN_OUTPUT" == "1.2.3" ]] || fail "resolver returned '$RUN_OUTPUT', expected 1.2.3"
run_resolver latest
assert_status_ok
[[ "$RUN_OUTPUT" == "1.2.3" ]] || fail "resolver returned '$RUN_OUTPUT', expected 1.2.3"
run_resolver 9.9.9
assert_status_fail
assert_contains "$RUN_OUTPUT" "single-pkg@9.9.9 is not a published version"

# --- the helpers cannot drift out of the scripts they are meant to back -----

for s in images/tools/pi/upgrade-pi.sh images/tools/dsh/upgrade-dsh.sh \
    images/tools/pi/bridge/upgrade-bridge.sh; do
    grep -Fq 'script/build/npm-pin.sh' "$REPO_ROOT/$s" \
        || fail "$s no longer sources the shared npm-pin.sh helper"
done

echo 'upgrade-script black-box tests passed'
