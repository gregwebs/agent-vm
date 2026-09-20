#!/usr/bin/env bash
# Black-box contract tests for the build-only Pi installer
# (images/tools/pi/install-pi.sh).
#
# No Docker, no npm registry, no real tarballs: `npm`, `curl`, `openssl`, `tar`
# and `diff` are faked on PATH, so every failure policy -- soft-fail at the
# failure, integrity mismatch never soft-failable, a count check that cannot read
# as success, no partial tree left behind -- is exercised hermetically and fast.
# The lockfile parser (the `jq` selector) is the REAL one, against a synthetic
# lock, so the selector itself is under test. The final section is the exception:
# it plants a real shadow package in a real installed tree and uses the real
# `tar` and `diff` (RQ1), so the bytes-comparison B1 turned on is covered by the
# production commands, not a stub.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
INSTALLER="$REPO_ROOT/images/tools/pi/install-pi.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pi-install-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT" /tmp/pi-verify /tmp/pi-siblings.tsv /tmp/pi-nested.tsv' EXIT

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

# --- RQ1: real-filesystem shadow-package regression --------------------------
#
# The cases above prove install-pi.sh's failure *policy* with a fake `diff`. The
# B1 finding was that the verification's `diff -x node_modules` never looked at
# the bytes that ship: a shadow package planted under a `node_modules` at any
# depth was silently excluded. These cases plant a real shadow in a real
# installed tree and use the REAL `tar` and `diff`, so the comparison under test
# is the production one. `npm`, `curl` and `openssl` stay faked (no registry, no
# network): npm's output is materialised directly, curl serves prebuilt tarballs,
# and the fake openssl returns the integrity the lock commits.

SIBLINGS=(chord pi-agent-core pi-ai pi-telemetry pi-tui)
REAL_BASE="node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works"

make_real_tool() {
    local name="$1"
    cat >"$CASE/bin/$name"
    chmod +x "$CASE/bin/$name"
}

new_realcase() {
    unset AGENT_INSTALL_SOFT_FAIL
    CASE="$TEST_ROOT/real-$1"
    rm -rf "$CASE"
    mkdir -p "$CASE/bin" "$CASE/prefix" "$CASE/home" "$CASE/tarballs" "$CASE/src"
    : >"$CASE/log"

    # Real tarballs (package/<name>.js) and the real extracted installed tree
    # npm would have produced: one file per sibling, plus pi-ai's two
    # lock-declared nested dependencies.
    local name
    for name in "${SIBLINGS[@]}"; do
        mkdir -p "$CASE/src/$name/package"
        printf 'sibling %s\n' "$name" >"$CASE/src/$name/package/$name.js"
        # pi-ai really ships a dist/ directory, and a shadow planted inside
        # pi-ai/dist/node_modules/<pkg> is what Node resolves from inside
        # pi-ai/dist. Ship dist/ in BOTH the tarball and the installed tree so
        # the shadow-dist case below isolates the nested exclusion -- without
        # it the diff would trip on the top-level `dist` alone (see F2).
        if [[ "$name" == pi-ai ]]; then
            mkdir -p "$CASE/src/$name/package/dist"
            printf 'pi-ai dist\n' >"$CASE/src/$name/package/dist/index.js"
        fi
        tar -czf "$CASE/tarballs/$name.tgz" -C "$CASE/src/$name" package
        mkdir -p "$CASE/prefix/$REAL_BASE/$name"
        printf 'sibling %s\n' "$name" >"$CASE/prefix/$REAL_BASE/$name/$name.js"
        if [[ "$name" == pi-ai ]]; then
            mkdir -p "$CASE/prefix/$REAL_BASE/$name/dist"
            printf 'pi-ai dist\n' >"$CASE/prefix/$REAL_BASE/$name/dist/index.js"
        fi
    done
    for name in agent-base https-proxy-agent; do
        mkdir -p "$CASE/prefix/$REAL_BASE/pi-ai/node_modules/$name"
        : >"$CASE/prefix/$REAL_BASE/pi-ai/node_modules/$name/index.js"
    done

    make_real_tool npm <<'SH'
#!/usr/bin/env bash
printf 'npm <%s>\n' "$*" >>"$FAKE_LOG"
exit 0
SH
    # `curl ... --http1.1 <resolved> -o <tarball>`; serve the matching real tgz.
    make_real_tool curl <<'SH'
#!/usr/bin/env bash
url="${@: -3}"
out="${@: -1}"
cp "$CASE_TARBALLS/$(basename "$url")" "$out"
SH
    # Mirror the real openssl split: `dgst` reads its file argument; `base64`
    # consumes the pipe. The lock commits sha512-AAAA and this returns it.
    make_real_tool openssl <<'SH'
#!/usr/bin/env bash
case "$1" in
    dgst) : ;;
    base64) cat >/dev/null; printf '%s' AAAA ;;
esac
SH
}

write_real_lock() {
    local name integrity=sha512-AAAA extra
    {
        printf '{\n  "name": "agent-vm-guest-pi",\n  "version": "0.0.0",\n  "lockfileVersion": 3,\n  "packages": {\n'
        for name in "${SIBLINGS[@]}"; do
            printf '    "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/%s": {"version": "0.86.1", "resolved": "https://registry.example.test/%s.tgz", "integrity": "%s"},\n' \
                "$name" "$name" "$integrity"
        done
        for name in agent-base https-proxy-agent; do
            printf '    "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/node_modules/%s": {"version": "0.0.0", "resolved": "https://registry.example.test/%s.tgz", "integrity": "%s"},\n' \
                "$name" "$name" "$integrity"
        done
        # Optional extra declared dirs, e.g. a dependency nested inside an
        # already-declared one (F1). $1 is its root-relative path under pi-ai.
        for extra in "$@"; do
            printf '    "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/node_modules/%s": {"version": "0.0.0", "resolved": "https://registry.example.test/%s.tgz", "integrity": "%s"},\n' \
                "$extra" "${extra##*/}" "$integrity"
        done
        printf '    "node_modules/@earendil-works/pi-coding-agent": {"version": "0.86.1"}\n  }\n}\n'
    } >"$CASE/prefix/package-lock.json"
    printf '{"dependencies": {"@earendil-works/pi-coding-agent": "0.86.1"}}\n' >"$CASE/prefix/package.json"
}

# PATH deliberately omits any fake `tar`/`diff`: the real ones run.
run_real_installer() {
    set +e
    RUN_OUTPUT="$(env -i \
        "PATH=$CASE/bin:$JQ_DIR:/usr/bin:/bin" \
        "HOME=$CASE/home" \
        "FAKE_LOG=$CASE/log" \
        "CASE_TARBALLS=$CASE/tarballs" \
        "AGENT_VM_PI_PREFIX=$CASE/prefix" \
        "AGENT_INSTALL_SOFT_FAIL=${AGENT_INSTALL_SOFT_FAIL-}" \
        sh "$INSTALLER" 2>&1)"
    RUN_STATUS=$?
    set -e
}

# (c) the legitimate tree passes, with real diff/tar and no
# basename exclusions.
new_realcase legit
write_real_lock
run_real_installer
[[ $RUN_STATUS -eq 0 ]] || fail "the legitimate tree must pass: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "5/5 shrinkwrap-only tarballs verified"

# (a) a shadow package one level below pi-ai's own node_modules.
for soft in "" 1; do
    new_realcase shadow-deep
    write_real_lock
    mkdir -p "$CASE/prefix/$REAL_BASE/pi-ai/node_modules/shadow"
    : >"$CASE/prefix/$REAL_BASE/pi-ai/node_modules/shadow/index.js"
    AGENT_INSTALL_SOFT_FAIL=$soft
    run_real_installer
    [[ $RUN_STATUS -ne 0 ]] || fail "a shadow under pi-ai/node_modules must fail (soft='${soft:-unset}')"
    assert_contains "$RUN_OUTPUT" "differs from its verified tarball"
done

# (b) a shadow planted in a node_modules nested under pi-ai/dist, which Node
# resolves from inside pi-ai/dist. pi-ai's tarball ships dist/index.js (see
# new_realcase), so the ONLY difference the diff sees is the nested shadow --
# this case fails against a reintroduced `-x node_modules` AND against `-x dist`.
for soft in "" 1; do
    new_realcase shadow-dist
    write_real_lock
    mkdir -p "$CASE/prefix/$REAL_BASE/pi-ai/dist/node_modules/agent-base"
    printf 'SHADOWED-DEEP\n' >"$CASE/prefix/$REAL_BASE/pi-ai/dist/node_modules/agent-base/index.js"
    AGENT_INSTALL_SOFT_FAIL=$soft
    run_real_installer
    [[ $RUN_STATUS -ne 0 ]] || fail "a shadow under pi-ai/dist/node_modules must fail (soft='${soft:-unset}')"
    assert_contains "$RUN_OUTPUT" "differs from its verified tarball"
done

# (d) a lock declaring a dependency nested inside an already-declared one must
# fold without the spurious "tarball already contains" error: the shallowest
# declared dir (agent-base) is copied wholesale, which covers agent-base's own
# declared child (F1).
new_realcase nested-declared
write_real_lock agent-base/node_modules/deep-dep
mkdir -p "$CASE/prefix/$REAL_BASE/pi-ai/node_modules/agent-base/node_modules/deep-dep"
: >"$CASE/prefix/$REAL_BASE/pi-ai/node_modules/agent-base/node_modules/deep-dep/index.js"
run_real_installer
[[ $RUN_STATUS -eq 0 ]] \
    || fail "a lock declaring a dep nested in another declared one must fold cleanly: $RUN_OUTPUT"
assert_contains "$RUN_OUTPUT" "5/5 shrinkwrap-only tarballs verified"

# ... while the genuine guard is intact: a verified tarball that itself ships a
# lock-declared path is still a hard failure, not something the fold masks.
new_realcase tarball-ships-declared
write_real_lock
mkdir -p "$CASE/src/pi-ai/package/node_modules/agent-base"
: >"$CASE/src/pi-ai/package/node_modules/agent-base/index.js"
tar -czf "$CASE/tarballs/pi-ai.tgz" -C "$CASE/src/pi-ai" package
run_real_installer
[[ $RUN_STATUS -ne 0 ]] || fail "a tarball shipping a lock-declared path must fail"
assert_contains "$RUN_OUTPUT" "already contains"

# --- the test seam cannot become the production default ----------------------

grep -Fq 'AGENT_VM_PI_PREFIX:-/opt/agent-vm/pi}"' "$INSTALLER" \
    || fail "production default install prefix is missing"

echo 'pi-install black-box tests passed'
