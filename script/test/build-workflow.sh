#!/usr/bin/env bash
# Exercise the public macOS build scripts with deterministic fake tools.

set -euo pipefail

REPO_ROOT="$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agent-vm-build-workflow.XXXXXX")"
# macOS's TMPDIR ends in a trailing slash, so the mktemp template above embeds
# a doubled slash (".../T//agent-vm-..."). macos.sh derives its own REPO_ROOT
# via `cd ... && pwd`, which bash normalizes to a single slash -- re-normalize
# TEST_ROOT the same way so path assertions below compare like with like.
TEST_ROOT="$(cd "$TEST_ROOT" && pwd)"
trap 'rm -rf "$TEST_ROOT"' EXIT

# Every fixture build runs with a private HOME, so the shared firmware store (see
# "Firmware reuse" below) is private to this run: the tests assert both a hit and
# a miss, and a real ~/.cache would leak state between runs.
FIXTURE_HOME="$TEST_ROOT/home"
mkdir -p "$FIXTURE_HOME"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    case "$1" in
        *"$2"*) ;;
        *) fail "expected output to contain: $2" ;;
    esac
}

assert_not_contains() {
    case "$1" in
        *"$2"*) fail "expected output not to contain: $2" ;;
        *) ;;
    esac
}

assert_file_contains() {
    local contents
    contents="$(cat "$1")"
    assert_contains "$contents" "$2"
}

assert_mode() {
    local expected="$1" path="$2" actual
    if actual="$(stat -f '%Lp' "$path" 2>/dev/null)"; then
        :
    else
        actual="$(stat -c '%a' "$path")"
    fi
    [[ "$actual" == "$expected" ]] || fail "$path mode was $actual, expected $expected"
}

# BSD stat spells the inode query `-f %i` and GNU spells it `-c %i`, and on Linux
# the BSD form exits 1 *after* writing a whole filesystem dump to stdout -- so the
# probe has to be an `if`, not an `||`, or the dump is what gets compared.
file_inode() {
    local inode
    if inode="$(stat -f '%i' "$1" 2>/dev/null)"; then
        printf '%s\n' "$inode"
    else
        stat -c '%i' "$1"
    fi
}

make_tool() {
    local path="$1" body="$2"
    printf '#!/bin/bash\nset -euo pipefail\n%s\n' "$body" >"$path"
    chmod +x "$path"
}

# The single-quoted bodies are expanded only after being written as fake tools.
# shellcheck disable=SC2016
make_fixture() {
    local name="$1" tool
    fixture="$TEST_ROOT/$name"
    fakebin="$TEST_ROOT/$name-bin"
    mkdir -p "$fixture/script/build" "$fixture/vendor/microsandbox/vendor/libkrunfw" "$fakebin"
    cp "$REPO_ROOT/script/build/macos.sh" "$fixture/script/build/"
    chmod +x "$fixture/script/build/"*.sh
    : >"$fixture/vendor/microsandbox/Cargo.toml"
    : >"$fixture/vendor/microsandbox/msb-entitlements.plist"
    : >"$fixture/vendor/microsandbox/vendor/libkrunfw/kernel.c"
    cat >"$fixture/vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh" <<'SH'
#!/bin/bash
set -euo pipefail
printf '%s\n' 'firmware docker build' >>"$FAKE_LOG"
SH
    chmod +x "$fixture/vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh"
    ln -s /bin/bash "$fakebin/bash"
    for tool in mkdir rm mv cp cat chmod touch awk date cmp mktemp; do
        ln -s "$(command -v "$tool")" "$fakebin/$tool"
    done

    make_tool "$fakebin/uname" '
case "${1:-}" in
    -s) printf "%s\n" "${FAKE_UNAME_S:-Darwin}" ;;
    -m) printf "%s\n" "${FAKE_UNAME_M:-arm64}" ;;
    *) exit 2 ;;
esac'
    make_tool "$fakebin/rustc" '
if [[ "${FAKE_RUSTUP_PINNED:-}" == 1 ]]; then
    printf "%s\n" "${FAKE_PINNED_RUST_VERSION:-rustc 1.98.1 (fake)}"
else
    printf "%s\n" "${FAKE_ACTIVE_RUST_VERSION:-rustc 1.98.1 (fake)}"
fi'
    make_tool "$fakebin/cargo" '
printf "cargo cwd=%s target=%s args=%s embed_msb=%s embed_lib=%s\n" "$PWD" "${CARGO_TARGET_DIR:-}" "$*" "${AGENT_VM_EMBED_MSB:-}" "${AGENT_VM_EMBED_LIBKRUNFW:-}" >>"$FAKE_LOG"
subdir=debug
case "$*" in *"--release"*) subdir=release ;; esac
case "$*" in
    --version)
        printf "%s\n" "cargo 1.98.1 (fake)"
        ;;
    *"-p microsandbox-cli"*)
        mkdir -p "$CARGO_TARGET_DIR/$subdir"
        cat >"$CARGO_TARGET_DIR/$subdir/msb" <<"BIN"
#!/bin/bash
[[ "${1:-}" == --version ]] || exit 40
if [[ "${FAKE_MSB_VERSION_FAIL:-}" == 1 ]]; then exit 41; fi
printf "%s\n" "msb fake-fresh"
BIN
        chmod +x "$CARGO_TARGET_DIR/$subdir/msb"
        ;;
    *"--features embedded-runtime"*"-p agent-vm"*)
        [[ -f "$AGENT_VM_EMBED_MSB" && -f "$AGENT_VM_EMBED_LIBKRUNFW" ]] || exit 4
        mkdir -p "$CARGO_TARGET_DIR/$subdir"
        {
            printf "#!/bin/bash\nmsb=%q\nlib=%q\n" "$AGENT_VM_EMBED_MSB" "$AGENT_VM_EMBED_LIBKRUNFW"
            cat <<"BIN"
if [[ "${1:-}" == --version ]]; then
    [[ "${FAKE_AGENT_VM_VERSION_FAIL:-}" != 1 ]] || exit 42
    printf "%s\n" "agent-vm fake-single"
elif [[ "$*" == "msb --version" ]]; then
    [[ "${FAKE_SINGLE_SMOKE_FAIL:-}" != 1 ]] || exit 43
    [[ -z "${MSB_PATH:-}" ]] || exit 44
    [[ -z "${XDG_CACHE_HOME:-}" ]] || exit 45
    mkdir -p "$HOME/.cache/agent-vm/runtime/fake/"{bin,lib}
    cp "$msb" "$HOME/.cache/agent-vm/runtime/fake/bin/msb"
    cp "$lib" "$HOME/.cache/agent-vm/runtime/fake/lib/libkrunfw.5.dylib"
    printf "%s\n" "msb fake-fresh"
else
    exit 40
fi
BIN
        } >"$CARGO_TARGET_DIR/$subdir/agent-vm"
        chmod +x "$CARGO_TARGET_DIR/$subdir/agent-vm"
        ;;
    *"-p agent-vm"*)
        mkdir -p "$CARGO_TARGET_DIR/$subdir"
        cat >"$CARGO_TARGET_DIR/$subdir/agent-vm" <<"BIN"
#!/bin/bash
[[ "${1:-}" == --version ]] || exit 40
if [[ "${FAKE_AGENT_VM_VERSION_FAIL:-}" == 1 ]]; then exit 42; fi
printf "%s\n" "agent-vm fake-fresh"
BIN
        chmod +x "$CARGO_TARGET_DIR/$subdir/agent-vm"
        ;;
    *) exit 3 ;;
esac'
    make_tool "$fakebin/rustup" '
printf "rustup auto_install=%s args=%s\n" "${RUSTUP_AUTO_INSTALL:-}" "$*" >>"$FAKE_LOG"
if [[ "${RUSTUP_AUTO_INSTALL:-}" != 0 ]]; then
    printf "%s\n" "fake rustup refused an auto-install-capable invocation" >&2
    exit 90
fi
if [[ "${1:-}" != run || "${2:-}" != 1.98.1 ]]; then
    exit 3
fi
shift 2
tool="${1:-}"
shift
case "$tool" in
    rustc | cargo) ;;
    *) exit 3 ;;
esac
if [[ "${FAKE_RUSTUP_TOOLCHAIN_MISSING:-}" == 1 ]]; then
    printf "%s\n" "error: toolchain 1.98.1 is not installed" >&2
    exit 1
fi
if [[ "$tool" == cargo && "${FAKE_RUSTUP_CARGO_MISSING:-}" == 1 ]]; then
    printf "%s\n" "error: cargo is not installed for toolchain 1.98.1" >&2
    exit 1
fi
FAKE_RUSTUP_PINNED=1 "$tool" "$@"'
    make_tool "$fakebin/docker" '
printf "docker %s\n" "$*" >>"$FAKE_LOG"
case "${1:-}" in
    info) [[ "${FAKE_DOCKER_DOWN:-}" != 1 ]] ;;
    build) exit 0 ;;
    create) printf "%s\n" fake-container ;;
    cp)
        mkdir -p "${3%/*}"
        printf "%s\n" agentd >"$3"
        ;;
    rm) exit 0 ;;
    *) exit 3 ;;
esac'
    make_tool "$fakebin/codesign" '
printf "codesign %s\n" "$*" >>"$FAKE_LOG"
if [[ "${1:-}" == --verify ]]; then
    [[ "${FAKE_SIGNATURE_INVALID:-}" != 1 ]]
elif [[ "${1:-}" == -d ]]; then
    printf "%s\n" "<plist><dict/></plist>"
fi'
    make_tool "$fakebin/xcode-select" '[[ "${FAKE_XCODE_MISSING:-}" != 1 ]]'
    # `file` is the only probe that distinguishes a firmware dylib from an arm64
    # executable, so it has to answer both, and to answer per path: a test can make
    # just the shared-store copy look like an executable.
    make_tool "$fakebin/file" '
kind=shared
if [[ "${FAKE_FILE_KIND:-}" == executable ]]; then kind=executable; fi
if [[ -n "${FAKE_FILE_PATH_KIND:-}" ]]; then
    case "$1" in
        *"${FAKE_FILE_PATH_KIND%%:*}"*) kind="${FAKE_FILE_PATH_KIND#*:}" ;;
    esac
fi
if [[ "$kind" == executable ]]; then
    printf "%s: Mach-O 64-bit executable arm64\n" "$1"
else
    printf "%s: Mach-O 64-bit dynamically linked shared library arm64\n" "$1"
fi'
    make_tool "$fakebin/lipo" '
[[ "${1:-}" == -archs ]] || exit 2
case "${FAKE_BAD_ARCH_PATH:-}" in
    "") printf "%s\n" arm64 ;;
    *)
        case "$2" in
            *"$FAKE_BAD_ARCH_PATH"*) printf "%s\n" "x86_64 arm64" ;;
            *) printf "%s\n" arm64 ;;
        esac
        ;;
esac'
    make_tool "$fakebin/otool" '
[[ "${1:-}" == -L ]] || exit 2
if [[ "${FAKE_OTOOL_INVALID:-}" == 1 && "$2" != *.next ]]; then exit 1; fi
if [[ "${FAKE_OTOOL_INVALID_ONCE:-}" == 1 && "$2" != *.next && ! -e "${FAKE_LOG}.otool-invalid-once" ]]; then
    touch "${FAKE_LOG}.otool-invalid-once"
    exit 1
fi
printf "%s\n" "$2:"
'
    # Fake `plutil` entitlement queries for macos.sh. Checked in as a fixture rather than
    # an inline heredoc so shellcheck analyzes it; see
    # script/test/fixtures/fake-plutil.sh for the portability contract.
    cp "$REPO_ROOT/script/test/fixtures/fake-plutil.sh" "$fakebin/plutil"
    chmod +x "$fakebin/plutil"
    make_tool "$fakebin/install" '
mode=; if [[ "${1:-}" == -m ]]; then mode="$2"; shift 2; fi
/bin/cp "$1" "$2"
/bin/chmod "$mode" "$2"'
    make_tool "$fakebin/cc" '
printf "cc %s\n" "$*" >>"$FAKE_LOG"
out=
while (($#)); do
    if [[ "$1" == -o ]]; then out="$2"; break; fi
    shift
done
[[ -n "$out" ]]
case "$out" in */*) mkdir -p "${out%/*}" ;; esac
printf "%s\n" firmware >"$out"'
    make_tool "$fakebin/git" '
case "${3:-}" in
    ls-tree) printf "%s\\n" "160000 commit ${FAKE_FIRMWARE_SHA:-c51f0146f9fe836e4fe1bf2c061c70bedfad058c} vendor/libkrunfw" ;;
    rev-parse) printf "%s\\n" "${FAKE_FIRMWARE_HEAD:-c51f0146f9fe836e4fe1bf2c061c70bedfad058c}" ;;
    status)
        [[ "${FAKE_FIRMWARE_STATUS_FAIL:-}" != 1 ]] || exit 1
        [[ "${FAKE_FIRMWARE_DIRTY:-}" != 1 ]] || printf "%s\\n" " M kernel.c"
        ;;
    *) exit 3 ;;
esac'

    :
}

run_fixture_script() {
    local fixture="$1" fakebin="$2" script="$3"
    shift 3
    local -a env_args=() script_args=()

    if [[ "${1:-}" == env ]]; then
        shift
        while (($#)) && [[ "$1" != -- ]]; do
            env_args+=("$1")
            shift
        done
        if [[ "${1:-}" == -- ]]; then
            shift
        fi
        script_args=("$@")
    elif [[ "${1:-}" == -- ]]; then
        shift
        script_args=("$@")
    elif (($#)); then
        script_args=("$@")
    fi

    (
        cd "$TEST_ROOT"
        set +u
        # HOME first so a test can override it with `env HOME= ...`.
        /usr/bin/env HOME="$FIXTURE_HOME" XDG_CACHE_HOME= "${env_args[@]}" PATH="$fakebin" \
            FAKE_LOG="$fixture/calls.log" \
            "$fixture/$script" "${script_args[@]}"
    )
}

run_build() {
    local fixture="$1" fakebin="$2"
    shift 2
    run_fixture_script "$fixture" "$fakebin" script/build/macos.sh "$@"
}

expect_build_failure() {
    local expected="$1" fixture="$2" fakebin="$3"
    shift 3
    local output status
    set +e
    output="$(run_build "$fixture" "$fakebin" "$@" 2>&1)"
    status=$?
    set -e
    [[ $status -ne 0 ]] || fail "build unexpectedly succeeded: $expected. output:\n\n$output"
    assert_contains "$output" "$expected"
}

# Public build script must exist.
[[ -f "$REPO_ROOT/script/build/macos.sh" ]] || fail "missing script/build/macos.sh"

# All Rust-toolchain pin literals (rust-toolchain.toml, Cargo.toml, ci.yml,
# release-npm.yml, this script's own RUST_TOOLCHAIN copy, and
# macos-build.md) are asserted consistent by one shared checker -- see its
# header for the full consumer list and why the pin is duplicated at all.
# Running it here, in a macOS-native test, also gives it BSD-sed/BSD-grep
# coverage: this is the checker's only run on macOS.
"$REPO_ROOT/script/check-rust-toolchain.sh" ||
    fail "script/check-rust-toolchain.sh reported a Rust-toolchain pin mismatch (see output above)"

# A complete fake build works without just, from outside the repository.
make_fixture success
if PATH="$fakebin" command -v just >/dev/null 2>&1; then fail "fake PATH unexpectedly contains just"; fi
run_build "$fixture" "$fakebin"
[[ -x "$fixture/target/macos/bin/agent-vm" ]]
[[ -x "$fixture/target/macos/bin/msb" ]]
[[ -f "$fixture/target/macos/lib/libkrunfw.5.dylib" ]]
assert_mode 755 "$fixture/target/macos/bin/agent-vm"
assert_mode 755 "$fixture/target/macos/bin/msb"
assert_mode 644 "$fixture/target/macos/lib/libkrunfw.5.dylib"
assert_file_contains "$fixture/calls.log" "docker build -f Dockerfile.agentd -t microsandbox-agentd-build ."
assert_file_contains "$fixture/calls.log" "docker cp fake-container:/agentd build/.agentd.next"
assert_file_contains "$fixture/calls.log" "docker rm fake-container"
assert_file_contains "$fixture/calls.log" "--release --no-default-features --features embed-binaries,net,ssh -p microsandbox-cli"
assert_file_contains "$fixture/calls.log" "codesign --entitlements msb-entitlements.plist --force -s - build/msb"
assert_file_contains "$fixture/calls.log" "firmware docker build"
assert_file_contains "$fixture/calls.log" "-DABI_VERSION=5"
assert_file_contains "$fixture/calls.log" "--release -p agent-vm"
assert_file_contains "$fixture/calls.log" "target=$fixture/vendor/microsandbox/target"
assert_file_contains "$fixture/calls.log" "target=$fixture/target"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 rustc --version"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 cargo --version"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 cargo build --release --no-default-features --features embed-binaries,net,ssh -p microsandbox-cli"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 cargo build --release -p agent-vm"

# A present firmware output is reused on the next build.
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin"
if [[ -s "$fixture/calls.log" ]]; then
    calls="$(cat "$fixture/calls.log")"
    case "$calls" in *"firmware docker build"*) fail "existing firmware was rebuilt" ;; esac
fi

# Firmware reuse is tied to the clean nested-source gitlink, not merely a file
# left in build/. The same identity keys the shared store every checkout on the
# host reads, so a build publishes what it made and a checkout that lost its own
# copy takes that one back instead of rebuilding. Without it, the second worktree
# of a pin paid the whole Docker kernel build again (983 s of a 1297 s cold build).
SHARED_FIRMWARE="$FIXTURE_HOME/.cache/agent-vm/firmware/libkrunfw-5-c51f0146f9fe836e4fe1bf2c061c70bedfad058c.dylib"
FIRMWARE_STAMP="c51f0146f9fe836e4fe1bf2c061c70bedfad058c"
firmware_built() {
    case "$(cat "$1/calls.log")" in
        *"firmware docker build"*) return 0 ;;
        *) return 1 ;;
    esac
}
[[ -f "$SHARED_FIRMWARE" ]] || fail "the build did not publish the shared firmware store"
[[ "$(cat "$SHARED_FIRMWARE")" == firmware ]]
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha")" == "$FIRMWARE_STAMP" ]]
rm "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin"
if firmware_built "$fixture"; then
    fail "a dropped stamp rebuilt firmware instead of restoring it from the shared store"
fi
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha")" == "$FIRMWARE_STAMP" ]]

# The case this exists for: a second checkout of the same pin copies the
# published artifact, stamp included, and never runs the Docker build. A copy
# taken from the store is not written back, so the entry keeps its identity.
make_fixture second-worktree
shared_inode="$(file_inode "$SHARED_FIRMWARE")"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin"
if firmware_built "$fixture"; then
    fail "a sibling checkout rebuilt firmware the shared store already had"
fi
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib")" == firmware ]]
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha")" == "$FIRMWARE_STAMP" ]]
[[ "$(file_inode "$SHARED_FIRMWARE")" == "$shared_inode" ]] ||
    fail "a shared-cache hit rewrote the entry it copied"

# A changed gitlink is a different key: build, never borrow a neighbour's bytes,
# and a dirty or unreadable source refuses rather than claiming an identity it
# cannot verify.
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env FAKE_FIRMWARE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa FAKE_FIRMWARE_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
firmware_built "$fixture" || fail "a changed gitlink reused another pin's firmware"
expect_build_failure "nested libkrunfw source is dirty" "$fixture" "$fakebin" env FAKE_FIRMWARE_DIRTY=1
expect_build_failure "cannot read the nested libkrunfw status" "$fixture" "$fakebin" env FAKE_FIRMWARE_STATUS_FAIL=1

# Force mode rebuilds even when the local artifact matches, or the check would
# only prove that a stale stamp is stale. Start from a matching pair by building
# with the store emptied (removing only the local artifact would be restored).
rm -f "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib"*
rm -f "$SHARED_FIRMWARE"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin"
firmware_built "$fixture" || fail "a build with neither copy did not build the firmware"
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha")" == "$FIRMWARE_STAMP" ]]
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin"
if firmware_built "$fixture"; then fail "a matching local artifact was rebuilt"; fi
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env MSB_FORCE_FIRMWARE_REBUILD=1
firmware_built "$fixture" || fail "forced rebuild reused a matching local artifact"

# An entry that is not a loadable arm64 dylib -- wrong architecture, or an
# executable at the firmware key -- is rebuilt and replaced; a local artifact that
# is no longer loadable is restored from the store instead.
rm -f "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib"*
printf 'truncated\n' >"$SHARED_FIRMWARE"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env FAKE_BAD_ARCH_PATH=firmware/libkrunfw-5-
firmware_built "$fixture" || fail "an invalid shared firmware entry was reused"
[[ "$(cat "$SHARED_FIRMWARE")" == firmware ]]
rm -f "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib"*
printf 'executable\n' >"$SHARED_FIRMWARE"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env FAKE_FILE_PATH_KIND=firmware/libkrunfw-5-:executable
firmware_built "$fixture" || fail "an executable in the shared store stood in for the firmware"
[[ "$(cat "$SHARED_FIRMWARE")" == firmware ]]
rm -f "$fixture/calls.log.otool-invalid-once"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env FAKE_OTOOL_INVALID_ONCE=1
if firmware_built "$fixture"; then
    fail "a local artifact that no longer loads rebuilt instead of restoring from the store"
fi
rm -f "$SHARED_FIRMWARE"
rm -f "$fixture/calls.log.otool-invalid-once"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env FAKE_OTOOL_INVALID_ONCE=1
firmware_built "$fixture" || fail "an invalid local artifact with no shared copy was reused"

# A rejected forced-rebuild candidate must not replace the local artifact or the
# shared entry it would have published to.
printf published-firmware >"$fixture/vendor/microsandbox/build/libkrunfw.5.dylib"
printf '%s\n' "$FIRMWARE_STAMP" >"$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha"
expect_build_failure "arm64-only loadable macOS dynamic library" "$fixture" "$fakebin" env \
    MSB_FORCE_FIRMWARE_REBUILD=1 FAKE_BAD_ARCH_PATH=libkrunfw.5.dylib.next
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib")" == published-firmware ]]
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha")" == "$FIRMWARE_STAMP" ]]
[[ "$(cat "$SHARED_FIRMWARE")" == firmware ]]
[[ ! -e "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.next" ]]
[[ ! -e "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha.next" ]]
[[ ! -e "$SHARED_FIRMWARE.next" ]]

# No usable cache root is a slow build, never a wrong one.
rm -f "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib"*
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env HOME= XDG_CACHE_HOME=
firmware_built "$fixture" || fail "a build without a cache root reused something"

# --dev builds unoptimized binaries into a separate bundle dir and never
# touches the release bundle already published above.
run_build "$fixture" "$fakebin" -- --dev
[[ -x "$fixture/target/macos-dev/bin/agent-vm" ]]
[[ -x "$fixture/target/macos-dev/bin/msb" ]]
[[ -f "$fixture/target/macos-dev/lib/libkrunfw.5.dylib" ]]
assert_file_contains "$fixture/target/macos-dev/bin/agent-vm" "fake-fresh"
assert_file_contains "$fixture/target/macos-dev/bin/msb" "fake-fresh"
assert_file_contains "$fixture/calls.log" "cargo build --no-default-features --features embed-binaries,net,ssh -p microsandbox-cli"
assert_file_contains "$fixture/calls.log" "cargo build -p agent-vm"
assert_file_contains "$fixture/calls.log" "codesign --entitlements msb-entitlements.plist --force -s - build/msb-dev"
[[ -f "$fixture/vendor/microsandbox/build/msb-dev" ]]
[[ -f "$fixture/vendor/microsandbox/build/msb" ]]
assert_file_contains "$fixture/target/macos/bin/agent-vm" "fake-fresh"
assert_file_contains "$fixture/target/macos/bin/msb" "fake-fresh"

: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" -- --single-binary
assert_mode 755 "$fixture/target/macos-single/agent-vm"
assert_file_contains "$fixture/target/macos-single/agent-vm" "fake-single"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 cargo build --release --features embedded-runtime -p agent-vm"
assert_file_contains "$fixture/calls.log" "embed_msb=$fixture/vendor/microsandbox/build/msb"
assert_file_contains "$fixture/calls.log" "embed_lib=$fixture/vendor/microsandbox/build/libkrunfw.5.dylib"
assert_file_contains "$fixture/calls.log" "codesign --verify --strict $fixture/target/macos-single/.smoke/home/.cache/agent-vm/runtime/fake/bin/msb"
case "$(cat "$fixture/calls.log")" in *"cargo build --release -p agent-vm"*) fail "single build invoked bundle build" ;; esac
for bundle in macos macos-dev; do
    assert_file_contains "$fixture/target/$bundle/bin/agent-vm" "fake-fresh"
    assert_file_contains "$fixture/target/$bundle/bin/msb" "fake-fresh"
done
for staging in .agent-vm.next .smoke .msb-entitlements.plist; do [[ ! -e "$fixture/target/macos-single/$staging" ]]; done
expect_build_failure "--single-binary cannot be combined with --dev" "$fixture" "$fakebin" -- --dev --single-binary

# Argument and preflight failures are early and actionable.
output="$(PATH="$fakebin" "$fixture/script/build/macos.sh" --help)"
assert_contains "$output" "Usage:"
expect_build_failure "Usage:" "$fixture" "$fakebin" -- "extra"
make_fixture old-active-rust
run_build "$fixture" "$fakebin" env \
    FAKE_ACTIVE_RUST_VERSION='rustc 1.87.0 (fake)' \
    FAKE_PINNED_RUST_VERSION='rustc 1.98.1 (fake)'
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 rustc --version"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 cargo --version"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 cargo build --release --no-default-features --features embed-binaries,net,ssh -p microsandbox-cli"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.98.1 cargo build --release -p agent-vm"
make_fixture old-pinned-rust
# Open-coded rather than expect_build_failure so this case's own captured
# output is asserted below: expect_build_failure's output/status are `local`,
# so a trailing assert against a global $output would test the previous
# unrelated capture. Mirrors the missing-rust-toolchain case below.
set +e
output="$(run_build "$fixture" "$fakebin" env FAKE_PINNED_RUST_VERSION='rustc 1.90.0 (fake)' 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "build unexpectedly succeeded with a too-old pinned Rust"
assert_contains "$output" "Rust 1.98.1 or newer is required"
# The pin is three-component; a one-step ${VAR#*.} parse yields "98.1" and makes
# the (( )) guard fail open with a bash arithmetic error instead of rejecting.
assert_not_contains "$output" "syntax error"
make_fixture missing-rust-toolchain
set +e
output="$(run_build "$fixture" "$fakebin" env FAKE_RUSTUP_TOOLCHAIN_MISSING=1 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "build unexpectedly succeeded with missing Rust toolchain"
assert_contains "$output" "Rust toolchain 1.98.1 is not installed or usable"
assert_contains "$output" "rustc"
assert_contains "$output" "rustup toolchain install 1.98.1"
assert_contains "$output" "RUSTUP_USE_CURL=1 rustup toolchain install 1.98.1"
calls="$(cat "$fixture/calls.log")"
assert_not_contains "$calls" "docker info"
assert_not_contains "$calls" "cargo cwd="
make_fixture incomplete-rust-toolchain
set +e
output="$(run_build "$fixture" "$fakebin" env FAKE_RUSTUP_CARGO_MISSING=1 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "build unexpectedly succeeded with unusable pinned Cargo"
assert_contains "$output" "Cargo component for Rust toolchain 1.98.1 is not installed or usable"
assert_contains "$output" "rustup component add cargo --toolchain 1.98.1"
assert_contains "$output" "RUSTUP_USE_CURL=1 rustup component add cargo --toolchain 1.98.1"
assert_not_contains "$output" "rustup toolchain install 1.98.1"
calls="$(cat "$fixture/calls.log")"
assert_not_contains "$calls" "docker info"
assert_not_contains "$calls" "cargo cwd="
make_fixture linux
expect_build_failure "supports macOS only" "$fixture" "$fakebin" env FAKE_UNAME_S=Linux
make_fixture intel
expect_build_failure "supports Apple Silicon (arm64) only" "$fixture" "$fakebin" env FAKE_UNAME_M=x86_64
make_fixture no-git
mv "$fakebin/git" "$fakebin/git.disabled"
expect_build_failure "required tool 'git' was not found on PATH" "$fixture" "$fakebin"
make_fixture no-rustup
mv "$fakebin/rustup" "$fakebin/rustup.disabled"
expect_build_failure "required tool 'rustup' was not found on PATH" "$fixture" "$fakebin"
make_fixture no-submodule
rm "$fixture/vendor/microsandbox/Cargo.toml"
expect_build_failure "vendor/microsandbox is not initialized" "$fixture" "$fakebin"
make_fixture docker-down
expect_build_failure "daemon is unavailable" "$fixture" "$fakebin" env FAKE_DOCKER_DOWN=1
make_fixture bad-arch
expect_build_failure "must be arm64-only" "$fixture" "$fakebin" env FAKE_BAD_ARCH_PATH=.msb.next
make_fixture bad-signature
expect_build_failure "does not have a valid code signature" "$fixture" "$fakebin" env FAKE_SIGNATURE_INVALID=1
make_fixture missing-entitlement
expect_build_failure "missing the boolean com.apple.security.hypervisor entitlement" "$fixture" "$fakebin" env FAKE_HYPERVISOR_ENTITLEMENT=missing
make_fixture false-entitlement
expect_build_failure "must set com.apple.security.cs.disable-library-validation to true" "$fixture" "$fakebin" env FAKE_LIBRARY_ENTITLEMENT=false

# Late validation failures preserve the prior published bundle and clean staging.
for failure in signature agent-version msb-version; do
    make_fixture "late-$failure"
    mkdir -p "$fixture/target/macos/bin" "$fixture/target/macos/lib"
    printf old-agent >"$fixture/target/macos/bin/agent-vm"
    printf old-msb >"$fixture/target/macos/bin/msb"
    printf old-fw >"$fixture/target/macos/lib/libkrunfw.5.dylib"
    case "$failure" in
        signature)
            expect_build_failure "valid code signature" "$fixture" "$fakebin" env FAKE_SIGNATURE_INVALID=1
            ;;
        agent-version)
            expect_build_failure "staged agent-vm failed to run" "$fixture" "$fakebin" env FAKE_AGENT_VM_VERSION_FAIL=1
            ;;
        msb-version)
            expect_build_failure "staged msb failed to run" "$fixture" "$fakebin" env FAKE_MSB_VERSION_FAIL=1
            ;;
    esac
    [[ "$(cat "$fixture/target/macos/bin/agent-vm")" == old-agent ]]
    [[ "$(cat "$fixture/target/macos/bin/msb")" == old-msb ]]
    [[ "$(cat "$fixture/target/macos/lib/libkrunfw.5.dylib")" == old-fw ]]
    [[ ! -e "$fixture/target/macos/bin/.agent-vm.next" ]]
    [[ ! -e "$fixture/target/macos/bin/.msb.next" ]]
    [[ ! -e "$fixture/target/macos/lib/.libkrunfw.5.dylib.next" ]]
    [[ ! -e "$fixture/target/macos/.msb-entitlements.plist" ]]
done

for failure in smoke entitlement arch arch-unpacked version; do
    make_fixture "single-$failure"
    mkdir -p "$fixture/target/macos-single"
    printf old-single >"$fixture/target/macos-single/agent-vm"
    case "$failure" in
        smoke) expect_build_failure "failed to start from an empty directory" "$fixture" "$fakebin" env FAKE_SINGLE_SMOKE_FAIL=1 -- --single-binary ;;
        entitlement) expect_build_failure "missing the boolean com.apple.security.hypervisor entitlement" "$fixture" "$fakebin" env FAKE_HYPERVISOR_ENTITLEMENT=missing -- --single-binary ;;
        arch) expect_build_failure "must be arm64-only" "$fixture" "$fakebin" env FAKE_BAD_ARCH_PATH=.agent-vm.next -- --single-binary ;;
        arch-unpacked) expect_build_failure "must be arm64-only" "$fixture" "$fakebin" env FAKE_BAD_ARCH_PATH=.smoke/home/.cache -- --single-binary ;;
        version) expect_build_failure "staged single-binary agent-vm failed to run with --version" "$fixture" "$fakebin" env FAKE_AGENT_VM_VERSION_FAIL=1 -- --single-binary ;;
    esac
    [[ "$(cat "$fixture/target/macos-single/agent-vm")" == old-single ]]
    for staging in .agent-vm.next .smoke .msb-entitlements.plist; do [[ ! -e "$fixture/target/macos-single/$staging" ]]; done
done

# Repository-scoped target directories override inherited Cargo output paths.
make_fixture cargo-target
mkdir -p "$fixture/target/release" "$fixture/vendor/microsandbox/target/release"
printf '#!/bin/bash\necho stale-agent\n' >"$fixture/target/release/agent-vm"
printf '#!/bin/bash\necho stale-msb\n' >"$fixture/vendor/microsandbox/target/release/msb"
chmod +x "$fixture/target/release/agent-vm" "$fixture/vendor/microsandbox/target/release/msb"
run_build "$fixture" "$fakebin" env CARGO_TARGET_DIR="$TEST_ROOT/alternate-target"
assert_file_contains "$fixture/target/macos/bin/agent-vm" "fake-fresh"
assert_file_contains "$fixture/target/macos/bin/msb" "fake-fresh"

# Help requires neither platform nor build tools.
make_fixture help
help_fixture="$fixture"
helpbin="$TEST_ROOT/help-only-bin"
mkdir -p "$helpbin"
ln -s /bin/bash "$helpbin/bash"
ln -s "$(command -v cat)" "$helpbin/cat"
PATH="$helpbin" "$help_fixture/script/build/macos.sh" --help >/dev/null

echo "macOS build workflow seam tests passed"
