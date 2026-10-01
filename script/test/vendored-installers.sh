#!/usr/bin/env bash
# SP7 black-box execution tier for the vendored shipped installers (#227).
#
# The owning-hook suites (script/test/{codex,claude,opencode}-installer.sh) fake
# the vendored installer and record its inputs; that proves the envelope, not
# the installer. THIS suite executes the REAL patched vendored scripts
# (images/tools/{codex,opencode,claude}/vendor/install.sh) under the owning
# hooks through the shared run-install.sh envelope, with:
#
#   * a fake curl on PATH that serves exact, synthetic release metadata /
#     checksum manifests and genuinely-shaped synthetic archives whose sha256
#     sums are real, and DENIES every moving-channel (`latest`/dist-tag) URL;
#   * a fake uname that drives each Linux architecture branch;
#   * fixture "native" commands that succeed, fail, exit 75 or hang.
#
# It covers, for both Linux architecture branches where applicable: a clean
# install (parsing + hash verification + extraction + linking + native run), a
# checksum mismatch BEFORE the command is published, malformed metadata, a
# denied `latest` URL (via a mutation), transport receipt propagation and
# clearing, and native nonzero / exit-75 / hang under soft input (all hard).
#
# No Docker, no network. Boot-free; wired into script/test/ci-contracts.sh.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
CONTRACT="$REPO_ROOT/images/recipe-contract"
RUN_INSTALL="$CONTRACT/run-install.sh"
CODEX_VENDOR="$REPO_ROOT/images/tools/codex/vendor"
OPENCODE_VENDOR="$REPO_ROOT/images/tools/opencode/vendor"
CLAUDE_VENDOR="$REPO_ROOT/images/tools/claude/vendor"
WATCHDOG="$REPO_ROOT/script/test/host-watchdog.py"

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/vendored-installers.XXXXXX")"
chmod 0755 "$TEST_ROOT"
trap 'rm -rf "$TEST_ROOT"' EXIT

REAL_TIMEOUT="$(command -v timeout || true)"
[ -n "$REAL_TIMEOUT" ] || fail "timeout is required (macOS: brew install coreutils)"

CASE=""
CODEX_TARGET=""
OPENCODE_ARCH=""
RUN_OUT=""
RUN_RC=0
CURL_TRANSPORT_CODE=""
SOFT=""

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

note() { echo "  $*"; }

sha256_of() { # host-side hash, the same value the fake sha256sum must produce
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    fi
}

# --- shared fake executables -------------------------------------------------
SHARED="$TEST_ROOT/shared"
mkdir -p "$SHARED"

# Fake curl. Parses `-o OUTPUT` and the URL, logs every request, denies any
# moving-channel URL and any URL not explicitly routed, and otherwise copies a
# rooted fixture file to OUTPUT. A transport code (FAKE_CURL_TRANSPORT_CODE) is
# returned for every request to drive the classified 75 path.
cat >"$SHARED/curl" <<'SH'
#!/bin/sh
out=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out="${2:-}"; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
[ -n "${FAKE_CURL_LOG:-}" ] && printf '%s\n' "$url" >>"$FAKE_CURL_LOG"
# Any moving channel is an HTTP error. The vendored installers must select an
# exact version; a `latest`/dist-tag request is never an acceptable build step.
case "$url" in
    *latest* | */dist-tags/*)
        [ -n "${FAKE_CURL_LOG:-}" ] && printf 'DENIED %s\n' "$url" >>"$FAKE_CURL_LOG"
        exit 22
        ;;
esac
if [ -n "${FAKE_CURL_TRANSPORT_CODE:-}" ]; then
    exit "$FAKE_CURL_TRANSPORT_CODE"
fi
base="${url##*/}"
file="$(awk -F '\t' -v b="$base" '$1 == b { print $2; exit }' "${FAKE_CURL_ROUTES:-/dev/null}")"
if [ -z "$file" ] || [ ! -f "$file" ]; then
    [ -n "${FAKE_CURL_LOG:-}" ] && printf 'DENIED %s\n' "$url" >>"$FAKE_CURL_LOG"
    exit 22
fi
cp "$file" "$out"
SH

# Fake sha256sum: GNU-style "<hex>  <path>" regardless of host tooling, so the
# vendored scripts' own hash checks and this suite's expected hashes agree.
cat >"$SHARED/sha256sum" <<'SH'
#!/bin/sh
if [ -x /usr/bin/sha256sum ]; then exec /usr/bin/sha256sum "$@"; fi
for file in "$@"; do
    if command -v shasum >/dev/null 2>&1; then
        printf '%s  %s\n' "$(shasum -a 256 "$file" | awk '{print $1}')" "$file"
    else
        printf '%s  %s\n' "$(openssl dgst -sha256 "$file" | awk '{print $NF}')" "$file"
    fi
done
SH

# Fake timeout: records the bound the vendored script asked for, then enforces a
# small test cap so a hung native is bounded quickly. The requested bound is
# the script's own ("300"); the cap is this suite's. The shipped callers pass a
# leading --kill-after= option (TERM then SIGKILL); keep it, but the recorded
# value the suite asserts on is the duration.
cat >"$SHARED/timeout" <<'SH'
#!/bin/sh
kill_after=
case "${1:-}" in
    --kill-after=*) kill_after=$1; shift ;;
esac
bound="${1:-0}"
if [ -n "${FAKE_TIMEOUT_LOG:-}" ]; then
    printf '%s\n' "$bound" >>"$FAKE_TIMEOUT_LOG"
fi
shift
cap="${FAKE_TIMEOUT_CAP:-3}"
case "$bound" in
    '' | *[!0-9]*) ;;
    *) [ "$bound" -gt "$cap" ] && bound="$cap" ;;
esac
if [ -n "$kill_after" ]; then
    exec "$REAL_TIMEOUT" "$kill_after" "$bound" "$@"
fi
exec "$REAL_TIMEOUT" "$bound" "$@"
SH

chmod 0755 "$SHARED/curl" "$SHARED/sha256sum" "$SHARED/timeout"

route() { # $1 basename, $2 fixture file
    printf '%s\t%s\n' "$1" "$2" >>"$CASE/routes"
}

new_case() { # $1 name, $2 uname arch
    CASE="$TEST_ROOT/$1"
    rm -rf "$CASE"
    mkdir -p "$CASE/bin" "$CASE/prefix" "$CASE/status" "$CASE/assets" "$CASE/link"
    chmod 0755 "$CASE" "$CASE/bin" "$CASE/prefix" "$CASE/status" "$CASE/assets" "$CASE/link"
    cp "$SHARED/curl" "$SHARED/sha256sum" "$SHARED/timeout" "$CASE/bin/"
    # shellcheck disable=SC2016  # the generated uname script must keep ${1:-} literal
    printf '#!/bin/sh\ncase "${1:-}" in\n  -s) echo Linux ;;\n  -m) echo %s ;;\n  *) echo Linux ;;\nesac\n' \
        "$2" >"$CASE/bin/uname"
    chmod 0755 "$CASE/bin/uname"
    : >"$CASE/curl.log"
    : >"$CASE/routes"
    : >"$CASE/timeout.log"
}

# --- fixture native commands -------------------------------------------------
render_codex_native() { # $1 out, $2 version, $3 exit, $4 hang
    local body
    body="$(cat <<'SH'
#!/bin/sh
printf 'codex-cli @VERSION@\n'
if [ -n "${AGENT_VM_TRANSPORT_RECEIPT:-}" ]; then
  printf 'transport download 6\n' >"$AGENT_VM_TRANSPORT_RECEIPT"
fi
@HANG@exit @EXIT@
SH
)"
    body="${body//@VERSION@/$2}"
    body="${body//@EXIT@/$3}"
    if [ "$4" = 1 ]; then
        body="${body//@HANG@/sleep 300$'\n'}"
    else
        body="${body//@HANG@/}"
    fi
    printf '%s\n' "$body" >"$1"
    chmod 0755 "$1"
}

render_claude_native() { # $1 out, $2 version, $3 exit, $4 hang
    local body
    body="$(cat <<'SH'
#!/bin/sh
printf 'claude-native-ran\n' >>"$HOME/native-ran"
# Record and enforce the EXACT native dispatch: the production installer must
# invoke `install <requested-version>`, and must strip AGENT_VM_TRANSPORT_RECEIPT
# from the native environment. A dropped target, a wrong target, or a leaked
# receipt env fails hard here (review F3).
{
  printf 'argc=%s\n' "$#"
  for a in "$@"; do printf 'arg=%s\n' "$a"; done
} >"$HOME/native-argv"
if [ "$#" -ne 2 ] || [ "$1" != install ] || [ "$2" != "@VERSION@" ]; then
  printf 'claude-native: unexpected argv (%s): %s\n' "$#" "$*" >&2
  exit 90
fi
if [ -n "${AGENT_VM_TRANSPORT_RECEIPT:-}" ]; then
  printf 'claude-native: AGENT_VM_TRANSPORT_RECEIPT must not reach the native\n' >&2
  exit 91
fi
@HANG@if [ "@EXIT@" = 0 ]; then
  mkdir -p "$HOME/.local/bin"
  printf '#!/bin/sh\nprintf "@VERSION@ (Claude Code)\\n"\n' >"$HOME/.local/bin/claude"
  chmod 0755 "$HOME/.local/bin/claude"
fi
exit @EXIT@
SH
)"
    body="${body//@VERSION@/$2}"
    body="${body//@EXIT@/$3}"
    if [ "$4" = 1 ]; then
        body="${body//@HANG@/sleep 300$'\n'}"
    else
        body="${body//@HANG@/}"
    fi
    printf '%s\n' "$body" >"$1"
    chmod 0755 "$1"
}

# --- fixture archives / metadata ---------------------------------------------
build_codex_archive() { # $1 out, $2 version, $3 target, $4 exit, $5 hang
    local stage="$CASE/assets/stage-codex-$RANDOM"
    mkdir -p "$stage/bin" "$stage/codex-path" "$stage/codex-resources"
    render_codex_native "$stage/bin/codex" "$2" "$4" "$5"
    printf '#!/bin/sh\nexit 0\n' >"$stage/bin/codex-code-mode-host"
    printf '#!/bin/sh\nexit 0\n' >"$stage/codex-path/rg"
    printf '#!/bin/sh\nexit 0\n' >"$stage/codex-resources/bwrap"
    chmod 0755 "$stage/bin/codex-code-mode-host" "$stage/codex-path/rg" "$stage/codex-resources/bwrap"
    printf '{}\n' >"$stage/codex-package.json"
    (cd "$stage" && tar -czf "$1" .)
    rm -rf "$stage"
}

make_codex_case() { # $1 name, $2 arch, $3 version, $4 native exit, $5 hang, $6 corrupt
    new_case "$1" "$2"
    case "$2" in
        x86_64) CODEX_TARGET="x86_64-unknown-linux-musl" ;;
        aarch64) CODEX_TARGET="aarch64-unknown-linux-musl" ;;
        *) fail "unknown arch $2" ;;
    esac
    local asset="codex-package-$CODEX_TARGET.tar.gz"
    build_codex_archive "$CASE/assets/archive.tgz" "$3" "$CODEX_TARGET" "$4" "$5"
    # $6: 0 = intact, 1 = invalid bytes served, 2 = a VALID archive whose
    # manifest digest differs.
    local ahash served sum_hash
    ahash="$(sha256_of "$CASE/assets/archive.tgz")"
    sum_hash="$ahash"
    served="$CASE/assets/archive.tgz"
    case "$6" in
        1)
            printf 'this is not the archive\n' >"$CASE/assets/corrupt.tgz"
            served="$CASE/assets/corrupt.tgz" ;;
        2)
            sum_hash="0000000000000000000000000000000000000000000000000000000000000000" ;;
    esac
    printf '%s  %s\n' "$sum_hash" "$asset" >"$CASE/assets/codex-package_SHA256SUMS"
    local shash
    shash="$(sha256_of "$CASE/assets/codex-package_SHA256SUMS")"
    printf '{"tag_name":"rust-v%s","assets":[{"name":"%s","digest":"sha256:%s"},{"name":"codex-package_SHA256SUMS","digest":"sha256:%s"}]}\n' \
        "$3" "$asset" "$ahash" "$shash" >"$CASE/assets/meta.json"
    route "rust-v$3" "$CASE/assets/meta.json"
    route "$asset" "$served"
    route "codex-package_SHA256SUMS" "$CASE/assets/codex-package_SHA256SUMS"
}

make_opencode_case() { # $1 name, $2 arch, $3 version
    new_case "$1" "$2"
    case "$2" in
        x86_64) OPENCODE_ARCH=x64 ;;
        aarch64) OPENCODE_ARCH=arm64 ;;
        *) fail "unknown arch $2" ;;
    esac
    local stage="$CASE/assets/stage-oc-$RANDOM" body
    mkdir -p "$stage"
    body="$(cat <<'SH'
#!/bin/sh
printf '%s\n' "@VERSION@"
SH
)"
    body="${body//@VERSION@/$3}"
    printf '%s\n' "$body" >"$stage/opencode"
    chmod 0755 "$stage/opencode"
    (cd "$stage" && tar -czf "$CASE/assets/opencode.tgz" opencode)
    rm -rf "$stage"
    # Route every filename the installer may compute on a glibc or musl host,
    # with or without the AVX2-baseline suffix, to the same synthetic archive.
    local variant
    for variant in \
        "opencode-linux-$OPENCODE_ARCH" \
        "opencode-linux-$OPENCODE_ARCH-baseline" \
        "opencode-linux-$OPENCODE_ARCH-musl" \
        "opencode-linux-$OPENCODE_ARCH-baseline-musl"; do
        route "$variant.tar.gz" "$CASE/assets/opencode.tgz"
    done
}

make_claude_case() { # $1 name, $2 arch, $3 version, $4 native exit, $5 hang, $6 corrupt, $7 malformed
    new_case "$1" "$2"
    local platform hash
    case "$2" in
        x86_64) platform=linux-x64 ;;
        aarch64) platform=linux-arm64 ;;
        *) fail "unknown arch $2" ;;
    esac
    render_claude_native "$CASE/assets/claude-native" "$3" "$4" "$5"
    hash="$(sha256_of "$CASE/assets/claude-native")"
    served="$CASE/assets/claude-native"
    # $6: 0 = intact, 1 = valid asset with a mismatched manifest digest,
    # 2 = invalid bytes served with the real digest.
    case "$6" in
        1) hash="0000000000000000000000000000000000000000000000000000000000000000" ;;
        2)
            printf 'not a real binary\n' >"$CASE/assets/claude-corrupt"
            served="$CASE/assets/claude-corrupt" ;;
    esac
    if [ "$7" = 1 ]; then
        printf '{ this is not json\n' >"$CASE/assets/manifest.json"
    else
        printf '{"platforms":{"%s":{"checksum":"%s","size":1234}}}\n' "$platform" "$hash" \
            >"$CASE/assets/manifest.json"
    fi
    route "manifest.json" "$CASE/assets/manifest.json"
    route "claude" "$served"
}

# --- envelope runners --------------------------------------------------------
# All run the real run-install.sh envelope with the owning hook and the real
# vendored installer. The fake curl/sha256sum/uname/timeout live in $CASE/bin.
run_codex() { # $1 slot, $2 vendor dir
    local -a e=(
        "PATH=$CASE/bin:/usr/bin:/bin"
        "HOME=$CASE"
        "AGENT_VM_CONTRACT_DIR=$CONTRACT"
        "AGENT_VM_VENDOR_DIR=$2"
        "AGENT_VM_CODEX_PREFIX=$CASE/prefix"
        "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status"
        "AGENT_VM_VERSION_CODEX=$1"
        "FAKE_CURL_LOG=$CASE/curl.log"
        "FAKE_CURL_ROUTES=$CASE/routes"
        "FAKE_TIMEOUT_LOG=$CASE/timeout.log"
        "REAL_TIMEOUT=$REAL_TIMEOUT"
        "FAKE_TIMEOUT_CAP=3"
    )
    if [ -n "$CURL_TRANSPORT_CODE" ]; then e+=("FAKE_CURL_TRANSPORT_CODE=$CURL_TRANSPORT_CODE"); fi
    if [ -n "$SOFT" ]; then e+=("AGENT_INSTALL_SOFT_FAIL=$SOFT"); fi
    set +e
    RUN_OUT="$(env -i "${e[@]}" sh "$RUN_INSTALL" codex "$CASE/status/codex" sh "$REPO_ROOT/images/tools/codex/install-codex.sh" 2>&1)"
    RUN_RC=$?
    set -e
}

run_opencode() { # $1 slot, $2 vendor dir
    mkdir -p "$CASE/tmp"
    local -a e=(
        "PATH=$CASE/bin:/usr/bin:/bin"
        "HOME=$CASE"
        "TMPDIR=$CASE/tmp"
        "AGENT_VM_CONTRACT_DIR=$CONTRACT"
        "AGENT_VM_VENDOR_DIR=$2"
        "AGENT_VM_OPENCODE_PREFIX=$CASE/prefix"
        "AGENT_VM_OPENCODE_LINK=$CASE/link/opencode"
        "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status"
        "AGENT_VM_VERSION_OPENCODE=$1"
        "FAKE_CURL_LOG=$CASE/curl.log"
        "FAKE_CURL_ROUTES=$CASE/routes"
    )
    if [ -n "$CURL_TRANSPORT_CODE" ]; then e+=("FAKE_CURL_TRANSPORT_CODE=$CURL_TRANSPORT_CODE"); fi
    if [ -n "$SOFT" ]; then e+=("AGENT_INSTALL_SOFT_FAIL=$SOFT"); fi
    set +e
    RUN_OUT="$(env -i "${e[@]}" sh "$RUN_INSTALL" opencode "$CASE/status/opencode" sh "$REPO_ROOT/images/tools/opencode/install-opencode.sh" 2>&1)"
    RUN_RC=$?
    set -e
}

run_claude() { # $1 slot, $2 vendor dir
    local -a e=(
        "PATH=$CASE/bin:/usr/bin:/bin"
        "HOME=$CASE"
        "AGENT_VM_CONTRACT_DIR=$CONTRACT"
        "AGENT_VM_VENDOR_DIR=$2"
        "AGENT_VM_CLAUDE_PREFIX=$CASE/prefix"
        "AGENT_VM_FIXTURE_ROOT=$CASE"
        "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status"
        "AGENT_VM_VERSION_CLAUDE=$1"
        "FAKE_CURL_LOG=$CASE/curl.log"
        "FAKE_CURL_ROUTES=$CASE/routes"
        "FAKE_TIMEOUT_LOG=$CASE/timeout.log"
        "REAL_TIMEOUT=$REAL_TIMEOUT"
        "FAKE_TIMEOUT_CAP=3"
    )
    if [ -n "$CURL_TRANSPORT_CODE" ]; then e+=("FAKE_CURL_TRANSPORT_CODE=$CURL_TRANSPORT_CODE"); fi
    if [ -n "$SOFT" ]; then e+=("AGENT_INSTALL_SOFT_FAIL=$SOFT"); fi
    set +e
    RUN_OUT="$(env -i "${e[@]}" sh "$RUN_INSTALL" claude "$CASE/status/claude" sh "$REPO_ROOT/images/tools/claude/install-claude.sh" 2>&1)"
    RUN_RC=$?
    set -e
}

status_of() { # $1 tool
    cat "$CASE/status/$1" 2>/dev/null || echo MISSING
}

expect_ok() { [ "$RUN_RC" -eq 0 ] || fail "$1: expected success, got rc=$RUN_RC: $RUN_OUT"; }
expect_hard() { [ "$RUN_RC" -ne 0 ] || fail "$1: expected a hard failure, got success: $RUN_OUT"; }
expect_no_denied() { ! grep -q '^DENIED ' "$CASE/curl.log" || fail "$1: a request was denied: $(cat "$CASE/curl.log")"; }
expect_denied() {
    grep -q '^DENIED ' "$CASE/curl.log" || fail "$1: no denied URL was logged: $(cat "$CASE/curl.log")"
    grep -q 'latest' "$CASE/curl.log" || fail "$1: the mutation never requested a latest URL"
}

mutate_vendor() { # $1 src dir, $2 out dir, $3 sed expr
    mkdir -p "$2"
    chmod 0755 "$2"
    sed "$3" "$1/install.sh" >"$2/install.sh"
    chmod 0644 "$2/install.sh"
}

# =============================================================================
# codex
# =============================================================================
echo "== codex (real vendored install.sh) =="
for arch in x86_64 aarch64; do
    V=0.159.3

    make_codex_case "codex-$arch-ok" "$arch" "$V" 0 0 0
    run_codex "rust-v$V" "$CODEX_VENDOR"
    expect_ok "codex $arch clean install"
    expect_no_denied "codex $arch clean install"
    "$CASE/prefix/.local/bin/codex" --version >"$CASE/out" 2>&1 ||
        fail "codex $arch: published command failed"
    [ "$(cat "$CASE/out")" = "codex-cli $V" ] ||
        fail "codex $arch: report '$(cat "$CASE/out")' != 'codex-cli $V'"
    [ "$(status_of codex)" = pending ] || fail "codex $arch: status is $(status_of codex)"
    note "codex $arch: clean install published codex-cli $V (target $CODEX_TARGET)"

    # Checksum corruption BEFORE publication, under every nonempty soft input
    # (including the literal "0"), for invalid bytes AND a valid-but-mismatched
    # archive. The old suite ran this only with SOFT empty, so a mutation that
    # softened a checksum mismatch under soft input survived the whole suite.
    for soft in "" 1 0; do
        for mode in 1 2; do
            kind=invalid-bytes
            [ "$mode" = 2 ] && kind=valid-digest-mismatch
            make_codex_case "codex-$arch-checksum-$kind-soft-${soft:-none}" "$arch" "$V" 0 0 "$mode"
            SOFT="$soft"
            run_codex "rust-v$V" "$CODEX_VENDOR"
            expect_hard "codex $arch $kind checksum (soft='$soft')"
            case "$(status_of codex)" in
                absent-transport*) fail "codex $arch $kind (soft='$soft'): checksum softened to $(status_of codex)" ;;
            esac
            [ ! -e "$CASE/prefix/.local/bin/codex" ] ||
                fail "codex $arch $kind (soft='$soft'): a checksum mismatch must not publish the command"
            printf '%s' "$RUN_OUT" | grep -q 'checksum did not match' ||
                fail "codex $arch $kind (soft='$soft'): expected a checksum diagnostic, got: $RUN_OUT"
            SOFT=""
        done
    done
    note "codex $arch: checksum corruption (invalid bytes + digest mismatch) is HARD under empty/1/0 soft input"

    for soft in "" 1 0; do
        make_codex_case "codex-$arch-malformed-soft-${soft:-none}" "$arch" "$V" 0 0 0
        printf '{ not valid release metadata\n' >"$CASE/assets/meta.json"
        SOFT="$soft"
        run_codex "rust-v$V" "$CODEX_VENDOR"
        expect_hard "codex $arch malformed metadata (soft='$soft')"
        case "$(status_of codex)" in
            absent-transport*) fail "codex $arch malformed (soft='$soft'): metadata failure softened to $(status_of codex)" ;;
        esac
        [ ! -e "$CASE/prefix/.local/bin/codex" ] ||
            fail "codex $arch malformed (soft='$soft'): malformed metadata must not publish the command"
        SOFT=""
    done
    note "codex $arch: malformed metadata is HARD under empty/1/0 soft input"

    # C1: the inherited hand-written scanner accepted missing commas, trailing
    # garbage, a duplicate tag_name and contradictory per-asset digests. Each of
    # these must now be a HARD metadata failure before any value is used.
    for variant in missing-comma trailing-garbage duplicate-tag duplicate-digest; do
        make_codex_case "codex-$arch-meta-$variant" "$arch" "$V" 0 0 0
        python3 - "$CASE/assets/meta.json" "$variant" <<'PY'
import json
import sys

path, variant = sys.argv[1], sys.argv[2]
text = open(path).read()
if variant == "missing-comma":
    text = text.replace(',"assets"', ' "assets"', 1)
elif variant == "trailing-garbage":
    text = text + "this is not JSON\n"
elif variant == "duplicate-tag":
    text = text.replace('"assets":', '"tag_name":"rust-v9.9.9","assets":', 1)
elif variant == "duplicate-digest":
    document = json.loads(text)
    document["assets"].append({"name": document["assets"][0]["name"], "digest": "sha256:" + "0" * 64})
    text = json.dumps(document) + "\n"
open(path, "w").write(text)
PY
        SOFT=1
        run_codex "rust-v$V" "$CODEX_VENDOR"
        expect_hard "codex $arch metadata $variant"
        case "$(status_of codex)" in
            absent-transport*) fail "codex $arch metadata $variant: softened to $(status_of codex)" ;;
        esac
        [ ! -e "$CASE/prefix/.local/bin/codex" ] ||
            fail "codex $arch metadata $variant: a bad metadata document must not publish the command"
        SOFT=""
    done
    note "codex $arch: missing-comma/trailing-garbage/duplicate-tag/duplicate-digest metadata is HARD"

    make_codex_case "codex-$arch-latest" "$arch" "$V" 0 0 0
    mutate_vendor "$CODEX_VENDOR" "$CASE/mutant" 's#releases/tags/rust-v%s#releases/latest#'
    run_codex "rust-v$V" "$CASE/mutant"
    expect_hard "codex $arch latest mutation"
    expect_denied "codex $arch latest mutation"
    note "codex $arch: a reintroduced /latest request is denied and fails"

    make_codex_case "codex-$arch-transport-soft" "$arch" "$V" 0 0 0
    CURL_TRANSPORT_CODE=7
    SOFT=1
    run_codex "rust-v$V" "$CODEX_VENDOR"
    expect_ok "codex $arch transport-soft"
    [ "$(status_of codex)" = "absent-transport 7" ] ||
        fail "codex $arch: softened transport must record absence, got $(status_of codex)"
    [ ! -e "$CASE/prefix/.local/bin/codex" ] ||
        fail "codex $arch: a softened transport failure must not leave a command"
    note "codex $arch: transport 7 propagates as a receipt and softens to an absence record"
    CURL_TRANSPORT_CODE=""
    SOFT=""

    make_codex_case "codex-$arch-transport-hard" "$arch" "$V" 0 0 0
    CURL_TRANSPORT_CODE=7
    run_codex "rust-v$V" "$CODEX_VENDOR"
    expect_hard "codex $arch transport without soft"
    [ "$(status_of codex)" != "absent-transport 7" ] ||
        fail "codex $arch: a transport failure without soft input must not record absence"
    CURL_TRANSPORT_CODE=""
    note "codex $arch: the same transport failure is hard without soft input"

    make_codex_case "codex-$arch-native-nonzero" "$arch" "$V" 1 0 0
    SOFT=1
    run_codex "rust-v$V" "$CODEX_VENDOR"
    expect_hard "codex $arch native nonzero under soft input"
    [ "$(status_of codex)" != installed ] || fail "codex $arch: native nonzero recorded installed"
    SOFT=""
    note "codex $arch: a native that exits nonzero is hard even with soft input"

    make_codex_case "codex-$arch-native-75" "$arch" "$V" 75 0 0
    SOFT=1
    run_codex "rust-v$V" "$CODEX_VENDOR"
    expect_hard "codex $arch native 75 under soft input"
    case "$(status_of codex)" in
        absent-transport*)
            fail "codex $arch: a native exit 75 was misclassified as transport ($(status_of codex))" ;;
    esac
    note "codex $arch: a native exit 75 (and a native that writes the receipt) stays hard"
    SOFT=""

    echo "  (codex $arch hang)"
    make_codex_case "codex-$arch-hang" "$arch" "$V" 0 1 0
    SOFT=1
    local_env=(
        "PATH=$CASE/bin:/usr/bin:/bin"
        "HOME=$CASE"
        "AGENT_VM_CONTRACT_DIR=$CONTRACT"
        "AGENT_VM_VENDOR_DIR=$CODEX_VENDOR"
        "AGENT_VM_CODEX_PREFIX=$CASE/prefix"
        "AGENT_VM_INSTALL_STATUS_DIR=$CASE/status"
        "AGENT_VM_VERSION_CODEX=rust-v$V"
        "AGENT_INSTALL_SOFT_FAIL=1"
        "FAKE_CURL_LOG=$CASE/curl.log"
        "FAKE_CURL_ROUTES=$CASE/routes"
        "FAKE_TIMEOUT_LOG=$CASE/timeout.log"
        "REAL_TIMEOUT=$REAL_TIMEOUT"
        "FAKE_TIMEOUT_CAP=3"
    )
    set +e
    RUN_OUT="$(python3 "$WATCHDOG" 8 env -i "${local_env[@]}" \
        sh "$RUN_INSTALL" codex "$CASE/status/codex" sh "$REPO_ROOT/images/tools/codex/install-codex.sh" 2>&1)"
    RUN_RC=$?
    set -e
    # C3: the production installer must bound its own native --version probe and
    # fail hard BEFORE the external watchdog fires (rc 124 means it did not).
    [ "$RUN_RC" -ne 124 ] ||
        fail "codex $arch: the installer did not bound the hung native probe itself (watchdog fired): $RUN_OUT"
    [ "$RUN_RC" -ne 0 ] || fail "codex $arch: a hung native must fail hard: $RUN_OUT"
    [ "$(status_of codex)" != installed ] || fail "codex $arch: a hung native recorded installed"
    grep -q '^60$' "$CASE/timeout.log" ||
        fail "codex $arch: the installer did not route the native probe through timeout 60"
    note "codex $arch: the installer bounds its native probe (timeout 60) and fails hard before the watchdog"
    SOFT=""
done

# =============================================================================
# opencode
# =============================================================================
echo "== opencode (real vendored install.sh) =="
for arch in x86_64 aarch64; do
    V=1.18.34

    make_opencode_case "opencode-$arch-ok" "$arch" "$V"
    run_opencode "v$V" "$OPENCODE_VENDOR"
    expect_ok "opencode $arch clean install"
    expect_no_denied "opencode $arch clean install"
    [ -x "$CASE/prefix/.opencode/bin/opencode" ] ||
        fail "opencode $arch: the binary was not installed"
    [ -L "$CASE/link/opencode" ] || fail "opencode $arch: the PATH link was not published"
    [ "$("$CASE/link/opencode")" = "$V" ] || fail "opencode $arch: installed binary reports wrong version"
    [ "$(status_of opencode)" = pending ] || fail "opencode $arch: status is $(status_of opencode)"
    note "opencode $arch: clean install extracted the exact asset and linked the command"

    make_opencode_case "opencode-$arch-latest" "$arch" "$V"
    mutate_vendor "$OPENCODE_VENDOR" "$CASE/mutant" 's#releases/download/v#releases/download/latest/#'
    run_opencode "v$V" "$CASE/mutant"
    expect_hard "opencode $arch latest mutation"
    expect_denied "opencode $arch latest mutation"
    note "opencode $arch: a reintroduced /latest request is denied and fails"

    make_opencode_case "opencode-$arch-transport-soft" "$arch" "$V"
    CURL_TRANSPORT_CODE=6
    SOFT=1
    run_opencode "v$V" "$OPENCODE_VENDOR"
    expect_ok "opencode $arch transport-soft"
    [ "$(status_of opencode)" = "absent-transport 6" ] ||
        fail "opencode $arch: softened transport must record absence, got $(status_of opencode)"
    [ ! -e "$CASE/prefix/.opencode" ] || fail "opencode $arch: softened install left the install dir"
    [ ! -e "$CASE/link/opencode" ] || fail "opencode $arch: softened install left the link"
    # C5: the private download scratch must be removed on a softened transport
    # failure, not left for the degraded image to ship.
    [ -z "$(ls -A "$CASE/tmp")" ] ||
        fail "opencode $arch: softened transport left scratch: $(ls -A "$CASE/tmp")"
    CURL_TRANSPORT_CODE=""
    SOFT=""
    note "opencode $arch: transport 6 softens to an absence record and cleans partial artifacts"

    make_opencode_case "opencode-$arch-transport-hard" "$arch" "$V"
    CURL_TRANSPORT_CODE=6
    run_opencode "v$V" "$OPENCODE_VENDOR"
    expect_hard "opencode $arch transport without soft"
    CURL_TRANSPORT_CODE=""
    note "opencode $arch: the same transport failure is hard without soft input"
done

# =============================================================================
# claude
# =============================================================================
echo "== claude (real vendored install.sh) =="
for arch in x86_64 aarch64; do
    V=2.1.286

    make_claude_case "claude-$arch-ok" "$arch" "$V" 0 0 0 0
    run_claude "$V" "$CLAUDE_VENDOR"
    expect_ok "claude $arch clean install"
    expect_no_denied "claude $arch clean install"
    [ -f "$CASE/prefix/native-ran" ] || fail "claude $arch: the native installer never ran"
    [ "$(cat "$CASE/prefix/native-argv")" = "$(printf 'argc=2\narg=install\narg=%s' "$V")" ] ||
        fail "claude $arch: the native installer received unexpected argv: $(cat "$CASE/prefix/native-argv")"
    [ -x "$CASE/prefix/.local/bin/claude" ] || fail "claude $arch: native install did not publish the command"
    [ "$("$CASE/prefix/.local/bin/claude")" = "$V (Claude Code)" ] ||
        fail "claude $arch: native command reports the wrong version"
    [ "$(status_of claude)" = pending ] || fail "claude $arch: status is $(status_of claude)"
    note "claude $arch: clean install verified the exact asset then ran the native installer"

    # Checksum corruption BEFORE native publication, under every nonempty soft
    # input, for a valid asset with a mismatched manifest digest AND invalid
    # bytes.
    for soft in "" 1 0; do
        for mode in 1 2; do
            kind=valid-digest-mismatch
            [ "$mode" = 2 ] && kind=invalid-bytes
            make_claude_case "claude-$arch-checksum-$kind-soft-${soft:-none}" "$arch" "$V" 0 0 "$mode" 0
            SOFT="$soft"
            run_claude "$V" "$CLAUDE_VENDOR"
            expect_hard "claude $arch $kind checksum (soft='$soft')"
            case "$(status_of claude)" in
                absent-transport*) fail "claude $arch $kind (soft='$soft'): checksum softened to $(status_of claude)" ;;
            esac
            [ ! -e "$CASE/prefix/native-ran" ] ||
                fail "claude $arch $kind (soft='$soft'): a checksum mismatch must fail before the native installer runs"
            [ ! -e "$CASE/prefix/.local/bin/claude" ] ||
                fail "claude $arch $kind (soft='$soft'): a checksum mismatch must not publish a command"
            SOFT=""
        done
    done
    note "claude $arch: checksum corruption (digest mismatch + invalid bytes) is HARD under empty/1/0 soft input"

    for soft in "" 1 0; do
        make_claude_case "claude-$arch-malformed-soft-${soft:-none}" "$arch" "$V" 0 0 0 1
        SOFT="$soft"
        run_claude "$V" "$CLAUDE_VENDOR"
        expect_hard "claude $arch malformed manifest (soft='$soft')"
        case "$(status_of claude)" in
            absent-transport*) fail "claude $arch malformed (soft='$soft'): manifest failure softened to $(status_of claude)" ;;
        esac
        [ ! -e "$CASE/prefix/native-ran" ] ||
            fail "claude $arch malformed (soft='$soft'): a malformed manifest must not reach the native installer"
        SOFT=""
    done
    note "claude $arch: malformed manifest is HARD under empty/1/0 soft input"

    make_claude_case "claude-$arch-latest" "$arch" "$V" 0 0 0 0
    mutate_vendor "$CLAUDE_VENDOR" "$CASE/mutant" 's#/manifest.json#/latest/manifest.json#'
    run_claude "$V" "$CASE/mutant"
    expect_hard "claude $arch latest mutation"
    expect_denied "claude $arch latest mutation"
    note "claude $arch: a reintroduced /latest request is denied and fails"

    make_claude_case "claude-$arch-transport-soft" "$arch" "$V" 0 0 0 0
    CURL_TRANSPORT_CODE=28
    SOFT=1
    run_claude "$V" "$CLAUDE_VENDOR"
    expect_ok "claude $arch transport-soft"
    [ "$(status_of claude)" = "absent-transport 28" ] ||
        fail "claude $arch: softened transport must record absence, got $(status_of claude)"
    [ ! -e "$CASE/prefix/.local/bin/claude" ] ||
        fail "claude $arch: softened transport must not leave a command"
    CURL_TRANSPORT_CODE=""
    SOFT=""
    note "claude $arch: transport 28 propagates as a receipt and softens to an absence record"

    make_claude_case "claude-$arch-transport-hard" "$arch" "$V" 0 0 0 0
    CURL_TRANSPORT_CODE=28
    run_claude "$V" "$CLAUDE_VENDOR"
    expect_hard "claude $arch transport without soft"
    CURL_TRANSPORT_CODE=""
    note "claude $arch: the same transport failure is hard without soft input"

    make_claude_case "claude-$arch-native-nonzero" "$arch" "$V" 1 0 0 0
    SOFT=1
    run_claude "$V" "$CLAUDE_VENDOR"
    expect_hard "claude $arch native nonzero under soft input"
    [ "$(status_of claude)" != installed ] || fail "claude $arch: native nonzero recorded installed"
    SOFT=""
    note "claude $arch: a native non-zero install is hard even with soft input"

    make_claude_case "claude-$arch-native-75" "$arch" "$V" 75 0 0 0
    SOFT=1
    run_claude "$V" "$CLAUDE_VENDOR"
    expect_hard "claude $arch native 75 under soft input"
    case "$(status_of claude)" in
        absent-transport*)
            fail "claude $arch: a native exit 75 was misclassified as transport ($(status_of claude))" ;;
    esac
    SOFT=""
    note "claude $arch: a native exit 75 stays hard (the native never sees the receipt env)"

    make_claude_case "claude-$arch-hang" "$arch" "$V" 0 1 0 0
    SOFT=1
    run_claude "$V" "$CLAUDE_VENDOR"
    expect_hard "claude $arch native hang under soft input"
    [ "$(status_of claude)" != installed ] || fail "claude $arch: a hung native recorded installed"
    grep -q '^300$' "$CASE/timeout.log" ||
        fail "claude $arch: the vendored installer did not bound the native install with timeout 300"
    SOFT=""
    note "claude $arch: the native install is bounded by 'timeout 300' and a hang fails"
done

# =============================================================================
# transport receipt clearing (images/recipe-contract/download.sh)
# =============================================================================
echo "== transport receipt clearing =="
new_case "receipt-clearing" x86_64
receipt="$CASE/receipt"
download_url="https://example.invalid/asset"
route "asset" "$CASE/assets/payload"
printf 'payload\n' >"$CASE/assets/payload"

# A stale receipt must be cleared before a successful attempt, not carried.
printf 'transport download 6\n' >"$receipt"
CURL_TRANSPORT_CODE=""
set +e
RECEIPT_OUT="$(env -i \
    "PATH=$CASE/bin:/usr/bin:/bin" \
    "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
    "AGENT_VM_TRANSPORT_RECEIPT=$receipt" \
    "FAKE_CURL_LOG=$CASE/curl.log" \
    "FAKE_CURL_ROUTES=$CASE/routes" \
    sh "$CONTRACT/download.sh" "$download_url" "$CASE/out.bin" 2>&1)"
RECEIPT_RC=$?
set -e
[ "$RECEIPT_RC" -eq 0 ] || fail "clearing: a routed download must succeed: $RECEIPT_OUT"
[ ! -s "$receipt" ] || fail "clearing: a successful attempt must clear the stale receipt (got '$(cat "$receipt")')"
note "clearing: a stale receipt is cleared before a successful download"

# A hard (non-transport) failure must not leave a stale receipt behind either,
# so an unrelated 75 can never consume an earlier attempt's classification.
printf 'transport download 6\n' >"$receipt"
CURL_TRANSPORT_CODE=""
set +e
RECEIPT_OUT="$(env -i \
    "PATH=$CASE/bin:/usr/bin:/bin" \
    "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
    "AGENT_VM_TRANSPORT_RECEIPT=$receipt" \
    "FAKE_CURL_LOG=$CASE/curl.log" \
    "FAKE_CURL_ROUTES=$CASE/routes" \
    sh "$CONTRACT/download.sh" "https://example.invalid/not-routed" "$CASE/out.bin" 2>&1)"
RECEIPT_RC=$?
set -e
[ "$RECEIPT_RC" -ne 0 ] || fail "clearing: an unrouted (HTTP error) download must fail hard"
[ ! -s "$receipt" ] || fail "clearing: a hard failure must not leave the stale receipt"

# A classified transport failure writes exactly one receipt line and exits 75.
printf 'stale\n' >"$receipt"
CURL_TRANSPORT_CODE=7
set +e
RECEIPT_OUT="$(env -i \
    "PATH=$CASE/bin:/usr/bin:/bin" \
    "AGENT_VM_CONTRACT_DIR=$CONTRACT" \
    "AGENT_VM_TRANSPORT_RECEIPT=$receipt" \
    "FAKE_CURL_LOG=$CASE/curl.log" \
    "FAKE_CURL_ROUTES=$CASE/routes" \
    "FAKE_CURL_TRANSPORT_CODE=$CURL_TRANSPORT_CODE" \
    sh "$CONTRACT/download.sh" "$download_url" "$CASE/out.bin" 2>&1)"
RECEIPT_RC=$?
set -e
CURL_TRANSPORT_CODE=""
[ "$RECEIPT_RC" -eq 75 ] || fail "clearing: a transport failure must exit 75, got $RECEIPT_RC"
[ "$(cat "$receipt")" = "transport download 7" ] ||
    fail "clearing: the receipt must be exactly 'transport download 7', got '$(cat "$receipt")'"
note "clearing: a classified transport writes one exact receipt line and exits 75"

echo "vendored-installer black-box tests passed"
