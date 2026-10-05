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
    for tool in mkdir rm mv cp cat chmod touch awk date cmp; do
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
printf "cargo cwd=%s target=%s args=%s\n" "$PWD" "${CARGO_TARGET_DIR:-}" "$*" >>"$FAKE_LOG"
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
    make_tool "$fakebin/file" 'printf "%s: Mach-O 64-bit executable arm64\n" "$1"'
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
    status) [[ "${FAKE_FIRMWARE_DIRTY:-}" != 1 ]] || printf "%s\\n" " M kernel.c" ;;
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
        /usr/bin/env "${env_args[@]}" PATH="$fakebin" FAKE_LOG="$fixture/calls.log" \
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

# Firmware reuse is tied to the clean nested-source gitlink, not merely a
# file left in build/. Missing stamps, a changed gitlink, force mode, and an
# invalid cache all rebuild; a dirty source refuses rather than stamping an
# artifact whose source identity cannot be claimed.
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha")" == c51f0146f9fe836e4fe1bf2c061c70bedfad058c ]]
rm "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin"
assert_file_contains "$fixture/calls.log" "firmware docker build"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env MSB_FORCE_FIRMWARE_REBUILD=1
assert_file_contains "$fixture/calls.log" "firmware docker build"
: >"$fixture/calls.log"
run_build "$fixture" "$fakebin" env FAKE_FIRMWARE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa FAKE_FIRMWARE_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
assert_file_contains "$fixture/calls.log" "firmware docker build"
expect_build_failure "nested libkrunfw source is dirty" "$fixture" "$fakebin" env FAKE_FIRMWARE_DIRTY=1
: >"$fixture/calls.log"
printf '%s\n' c51f0146f9fe836e4fe1bf2c061c70bedfad058c >"$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha"
rm -f "$fixture/calls.log.otool-invalid-once"
run_build "$fixture" "$fakebin" env FAKE_OTOOL_INVALID_ONCE=1
assert_file_contains "$fixture/calls.log" "firmware docker build"

# A rejected forced-rebuild candidate must not replace or leave a reusable
# source-stamped firmware cache entry.
printf published-firmware >"$fixture/vendor/microsandbox/build/libkrunfw.5.dylib"
printf '%s\n' c51f0146f9fe836e4fe1bf2c061c70bedfad058c >"$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha"
expect_build_failure "arm64-only loadable macOS dynamic library" "$fixture" "$fakebin" env \
    MSB_FORCE_FIRMWARE_REBUILD=1 FAKE_BAD_ARCH_PATH=libkrunfw.5.dylib.next
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib")" == published-firmware ]]
[[ "$(cat "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha")" == c51f0146f9fe836e4fe1bf2c061c70bedfad058c ]]
[[ ! -e "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.next" ]]
[[ ! -e "$fixture/vendor/microsandbox/build/libkrunfw.5.dylib.source-sha.next" ]]

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

# --- images/build.sh: the real entry point, no version resolution -----------
# Execute an UNMODIFIED copy of images/build.sh through its real `main "$@"`
# entry point with capturing docker/curl stubs, so the whole driver runs:
# buildx version, driver check, registry recovery, the tool-free base build,
# the six `--load`ed tool layers, and the final registry-output template build.
# A poison `agent-versions.sh` (fixture-relative and on PATH) records any
# invocation; an ordinary build must never resolve agent versions. The docker
# stub logs argv boundaries and fails any unknown call, so nothing reaches the
# network and a re-added resolver call is a hard failure.
build_fixture="$TEST_ROOT/build-image-full"
build_bin="$build_fixture/bin"
mkdir -p "$build_fixture/images" "$build_fixture/script/build" "$build_bin"
cp "$REPO_ROOT/images/build.sh" "$build_fixture/images/build.sh"

# Poison resolvers: any invocation records INVOKED (so the test fails).
# shellcheck disable=SC2016  # stub bodies are expanded only once written out
make_tool "$build_bin/agent-versions.sh" '
printf "INVOKED\n" >>"${POISON_LOG:?}"; exit 1'
# shellcheck disable=SC2016
make_tool "$build_fixture/script/build/agent-versions.sh" '
printf "INVOKED\n" >>"${POISON_LOG:?}"; exit 1'

# shellcheck disable=SC2016
make_tool "$build_bin/docker" '
{ printf "docker"; printf " <%s>" "$@"; printf "\n"; } >>"${FAKE_LOG:?}"
case "${1:-}" in
    buildx)
        case "${2:-}" in
            version) [[ "${FAKE_BUILDX_MISSING:-}" != 1 ]] ;;
            inspect) printf "Driver: %s\n" "${FAKE_DOCKER_DRIVER:-docker}" ;;
            build) exit 0 ;;
            *) exit 3 ;;
        esac
        ;;
    inspect) printf "%s\n" "${FAKE_REGISTRY_STATE:-}" ;;
    run | start | rm | ps | logs) exit 0 ;;
    *) exit 3 ;;
esac'

# shellcheck disable=SC2016
make_tool "$build_bin/curl" '
{ printf "curl"; printf " <%s>" "$@"; printf "\n"; } >>"${FAKE_LOG:?}"
url="${@: -1}"
case "$url" in
    http://127.0.0.1:*/v2/)
        count_file="${FAKE_REGISTRY_COUNTER:?}"
        n=0
        if [[ -f "$count_file" ]]; then n="$(cat "$count_file")"; fi
        n=$((n + 1))
        printf "%s" "$n" >"$count_file"
        if (( n <= ${FAKE_REGISTRY_POLL_FAILS:-0} )); then exit 7; fi
        exit 0
        ;;
    *)
        printf "stub curl: unexpected url: %s\n" "$url" >&2
        exit 22
        ;;
esac'

# `stat -c %Y` is GNU-only; images/build.sh uses it only for the host-CA seam,
# which no CI host here exercises. Stub it so the CA case runs on macOS too.
# shellcheck disable=SC2016
make_tool "$build_bin/stat" '
if [[ "${1:-}" == -c && "${2:-}" == %Y ]]; then
    printf "%s\n" "${FAKE_STAT_MTIME:-1700000000}"
    exit 0
fi
exec /usr/bin/stat "$@"'

image_case_dir=""
image_build_output=""
image_build_status=0
image_calls=
BASH_BIN="${BASH:-/bin/bash}"
run_image_build() {
    image_case_dir="$1"
    mkdir -p "$image_case_dir/home"
    rm -f "$image_case_dir/calls.log" "$image_case_dir/registry.count" "$image_case_dir/poison"
    set +e
    image_build_output="$(
        cd "$TEST_ROOT" || exit 1
        env -i \
            "PATH=$build_bin:/usr/bin:/bin" \
            "HOME=$image_case_dir/home" \
            "FAKE_LOG=$image_case_dir/calls.log" \
            "POISON_LOG=$image_case_dir/poison" \
            "FAKE_REGISTRY_COUNTER=$image_case_dir/registry.count" \
            "FAKE_REGISTRY_STATE=${FAKE_REGISTRY_STATE-}" \
            "FAKE_DOCKER_DRIVER=${FAKE_DOCKER_DRIVER-docker}" \
            "FAKE_BUILDX_MISSING=${FAKE_BUILDX_MISSING-}" \
            "FAKE_REGISTRY_POLL_FAILS=${FAKE_REGISTRY_POLL_FAILS-0}" \
            "FAKE_STAT_MTIME=${FAKE_STAT_MTIME-1700000000}" \
            "AGENT_VM_BUILD_HOST_CA=${AGENT_VM_BUILD_HOST_CA-$TEST_ROOT/absent-host-ca}" \
            "AGENT_VM_BUILD_SOFT_FAIL_AGENTS=${AGENT_VM_BUILD_SOFT_FAIL_AGENTS-}" \
            "AGENT_VM_REGISTRY_PORT=${AGENT_VM_REGISTRY_PORT-5999}" \
            "AGENT_VM_REGISTRY_NAME=${AGENT_VM_REGISTRY_NAME-agent-vm-registry-test}" \
            "$BASH_BIN" "$build_fixture/images/build.sh" 2>&1
    )"
    image_build_status=$?
    set -e
    image_calls="$(cat "$image_case_dir/calls.log" 2>/dev/null || true)"
}

assert_no_poison() {
    [[ ! -e "$image_case_dir/poison" ]] \
        || fail "images/build.sh invoked the version resolver: $(cat "$image_case_dir/poison")"
}

# The single logged docker buildx build line for `-t TAG`, or empty.
build_line() { # $1 tag
    grep -F -- "docker <buildx> <build> <-t> <$1>" "$image_case_dir/calls.log" | head -n 1
}

# Assert the build for TAG carries EVERY required argv fragment. This inspects
# each build's OWN argv, not membership in the concatenated call log, so
# dropping EXTRA from one intermediate build fails (review F7).
assert_build_args() { # $1 tag, rest required fragments
    local tag="$1" line fragment
    shift
    line="$(build_line "$tag")"
    [[ -n "$line" ]] || fail "no docker buildx build call for $tag"
    for fragment in "$@"; do
        [[ "$line" == *"$fragment"* ]] ||
            fail "build $tag is missing '$fragment': $line"
    done
}

# Assert the build for TAG does NOT carry a fragment.
assert_build_excludes() { # $1 tag, $2 fragment
    local line
    line="$(build_line "$1")"
    [[ -n "$line" ]] || fail "no docker buildx build call for $1"
    [[ "$line" != *"$2"* ]] || fail "build $1 unexpectedly contains '$2': $line"
}

# The base plus the six tool builds (five unpublished intermediates + the
# composed template) that images/build.sh produces.
BUILD_TAGS=(
    localhost:5999/agent-vm-base:latest
    agent-vm-dsh-build:latest
    agent-vm-pi-build:latest
    agent-vm-codex-build:latest
    agent-vm-opencode-build:latest
    agent-vm-claude-build:latest
    localhost:5999/agent-vm-template:latest
)

# Ordinary/default build: no host CA, hard-fail policy, missing registry.
unset FAKE_REGISTRY_STATE FAKE_DOCKER_DRIVER FAKE_BUILDX_MISSING \
    FAKE_REGISTRY_POLL_FAILS AGENT_VM_BUILD_HOST_CA AGENT_VM_BUILD_SOFT_FAIL_AGENTS
run_image_build "$TEST_ROOT/build-default"
[[ $image_build_status -eq 0 ]] || fail "the ordinary build must succeed: $image_build_output"
assert_no_poison
assert_contains "$image_build_output" "localhost:5999/agent-vm-base:latest and localhost:5999/agent-vm-template:latest ready"
# No lookup warning and no version annotation survive from the old resolver.
assert_not_contains "$image_build_output" "agent version lookup failed"
assert_not_contains "$image_build_output" "Agent versions:"
# The driver check runs first (buildx version, then inspect).
assert_contains "$image_calls" "docker <buildx> <version>"
assert_contains "$image_calls" "docker <buildx> <inspect>"
# A missing registry is inspected, created, then polled.
assert_contains "$image_calls" "docker <inspect> <--type> <container> <-f> <{{.State.Status}}>"
assert_contains "$image_calls" "docker <run> <-d> <--name> <agent-vm-registry-test>"
assert_contains "$image_calls" "curl <-fsS> <http://127.0.0.1:5999/v2/>"
# The tool-free base is built with the zstd registry output.
assert_contains "$image_calls" "docker <buildx> <build> <-t> <localhost:5999/agent-vm-base:latest> <--output> <type=registry,push=true,"
assert_contains "$image_calls" "<-f> <$build_fixture/images/Dockerfile> <$build_fixture/images>"
# The six tool layers chain FROM the previous step, in declaration order.
assert_contains "$image_calls" "<-t> <agent-vm-dsh-build:latest> <--build-arg> <BASE_IMAGE=localhost:5999/agent-vm-base:latest> <--load> <$build_fixture/images/tools/dsh>"
assert_contains "$image_calls" "<-t> <agent-vm-pi-build:latest> <--build-arg> <BASE_IMAGE=agent-vm-dsh-build:latest> <--load> <$build_fixture/images/tools/pi>"
assert_contains "$image_calls" "<-t> <agent-vm-codex-build:latest> <--build-arg> <BASE_IMAGE=agent-vm-pi-build:latest> <--load> <$build_fixture/images/tools/codex>"
assert_contains "$image_calls" "<-t> <agent-vm-opencode-build:latest> <--build-arg> <BASE_IMAGE=agent-vm-codex-build:latest> <--load> <$build_fixture/images/tools/opencode>"
assert_contains "$image_calls" "<-t> <agent-vm-claude-build:latest> <--build-arg> <BASE_IMAGE=agent-vm-opencode-build:latest> <--load> <$build_fixture/images/tools/claude>"
assert_contains "$image_calls" "<-t> <localhost:5999/agent-vm-template:latest> <--build-arg> <BASE_IMAGE=agent-vm-claude-build:latest> <--output> <type=registry,push=true,"
assert_contains "$image_calls" "<$build_fixture/images/tools/copilot>"
# No synthesized version build args, not even empty ones.
assert_not_contains "$image_calls" "AGENT_VERSION"

# Soft-fail is an independent input, threaded to every layer and nothing else.
AGENT_VM_BUILD_SOFT_FAIL_AGENTS=1 run_image_build "$TEST_ROOT/build-soft"
[[ $image_build_status -eq 0 ]] || fail "the soft build must succeed: $image_build_output"
assert_no_poison
assert_contains "$image_build_output" "Soft-fail mode enabled for agent installers"
# Every build's OWN argv must carry the soft-fail arg, so dropping EXTRA from a
# single intermediate build (which a global membership check misses) fails.
for tag in "${BUILD_TAGS[@]}"; do
    assert_build_args "$tag" "--build-arg> <AGENT_INSTALL_SOFT_FAIL=1"
done
assert_not_contains "$image_calls" "AGENT_VERSION"

# Host-CA shim: secret, cache-bust, host network; MITM implies soft-fail.
host_ca="$TEST_ROOT/host-ca.crt"
printf 'fake-ca\n' >"$host_ca"
AGENT_VM_BUILD_HOST_CA="$host_ca" AGENT_VM_BUILD_SOFT_FAIL_AGENTS="" run_image_build "$TEST_ROOT/build-ca"
[[ $image_build_status -eq 0 ]] || fail "the host-CA build must succeed: $image_build_output"
assert_no_poison
assert_contains "$image_build_output" "Including host CA $host_ca as buildx secret"
# Each build's OWN argv must carry the CA secret, cache-bust, host-network and
# (MITM-implied) soft-fail args.
for tag in "${BUILD_TAGS[@]}"; do
    assert_build_args "$tag" \
        "--secret> <id=hostca,src=$host_ca" \
        "--build-arg> <CA_SHIM_CACHEBUST=1700000000" \
        "--allow> <network.host" \
        "--network> <host" \
        "--build-arg> <AGENT_INSTALL_SOFT_FAIL=1"
done
# ...but a host-CA build can still force hard-fail explicitly.
AGENT_VM_BUILD_HOST_CA="$host_ca" AGENT_VM_BUILD_SOFT_FAIL_AGENTS=0 run_image_build "$TEST_ROOT/build-ca-hard"
[[ $image_build_status -eq 0 ]] || fail "the explicit hard host-CA build must succeed: $image_build_output"
for tag in "${BUILD_TAGS[@]}"; do
    assert_build_args "$tag" \
        "--secret> <id=hostca,src=$host_ca" \
        "--build-arg> <CA_SHIM_CACHEBUST=1700000000" \
        "--allow> <network.host" \
        "--network> <host"
    assert_build_excludes "$tag" "AGENT_INSTALL_SOFT_FAIL"
done

# Registry recovery: a running-but-unresponsive registry is recreated.
FAKE_REGISTRY_STATE=running FAKE_REGISTRY_POLL_FAILS=5 run_image_build "$TEST_ROOT/build-registry-recovery"
[[ $image_build_status -eq 0 ]] || fail "registry recovery must succeed: $image_build_output"
assert_contains "$image_build_output" "is running but 127.0.0.1:5999 is unresponsive"
assert_contains "$image_calls" "docker <rm> <-f> <agent-vm-registry-test>"
assert_contains "$image_calls" "docker <run> <-d> <--name> <agent-vm-registry-test>"

# Registry restart: a stopped registry is started, not recreated.
FAKE_REGISTRY_STATE=exited run_image_build "$TEST_ROOT/build-registry-start"
[[ $image_build_status -eq 0 ]] || fail "registry restart must succeed: $image_build_output"
assert_contains "$image_build_output" "Starting existing registry container agent-vm-registry-test"
assert_contains "$image_calls" "docker <start> <agent-vm-registry-test>"
assert_not_contains "$image_calls" "docker <run> <-d>"

# A non-docker driver fails fast with the actionable message.
FAKE_DOCKER_DRIVER=docker-container run_image_build "$TEST_ROOT/build-bad-driver"
[[ $image_build_status -ne 0 ]] || fail "a non-docker driver must fail"
assert_contains "$image_build_output" "uses the 'docker-container' driver, not 'docker'"

# A missing buildx fails before any image work.
FAKE_BUILDX_MISSING=1 run_image_build "$TEST_ROOT/build-no-buildx"
[[ $image_build_status -ne 0 ]] || fail "a missing buildx must fail"
assert_contains "$image_build_output" "docker buildx not available"

# The static sources carry no resolver invocation or steps.ver wiring.
if grep -q 'resolve_agent_versions\|AGENT_VERSIONS\|agent_version(' "$REPO_ROOT/images/build.sh"; then
    fail "images/build.sh still contains the version resolver"
fi
if grep -nE 'agent-versions\.sh' "$REPO_ROOT/images/build.sh" | grep -qvE ':[[:space:]]*#'; then
    fail "images/build.sh still invokes the resolver"
fi
if grep -q 'steps\.ver' "$REPO_ROOT/.github/workflows/build-image.yml"; then
    fail "build-image.yml still references steps.ver"
fi
if grep -nE 'agent-versions\.sh' "$REPO_ROOT/.github/workflows/build-image.yml" | grep -qvE ':[[:space:]]*#'; then
    fail "build-image.yml still invokes the resolver"
fi

echo "build workflow seam tests passed"
