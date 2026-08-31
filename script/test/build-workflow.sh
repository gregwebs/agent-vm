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
    cp "$REPO_ROOT/script/build/macos.sh" "$REPO_ROOT/script/build/import-image.sh" "$fixture/script/build/"
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
    for tool in mkdir rm mv cp cat chmod touch awk; do
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
    printf "%s\n" "${FAKE_PINNED_RUST_VERSION:-rustc 1.94.0 (fake)}"
else
    printf "%s\n" "${FAKE_ACTIVE_RUST_VERSION:-rustc 1.94.0 (fake)}"
fi'
    make_tool "$fakebin/cargo" '
printf "cargo cwd=%s target=%s args=%s\n" "$PWD" "${CARGO_TARGET_DIR:-}" "$*" >>"$FAKE_LOG"
subdir=debug
case "$*" in *"--release"*) subdir=release ;; esac
case "$*" in
    --version)
        printf "%s\n" "cargo 1.94.0 (fake)"
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
if [[ "${1:-}" != run || "${2:-}" != 1.94 ]]; then
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
    printf "%s\n" "error: toolchain 1.94 is not installed" >&2
    exit 1
fi
if [[ "$tool" == cargo && "${FAKE_RUSTUP_CARGO_MISSING:-}" == 1 ]]; then
    printf "%s\n" "error: cargo is not installed for toolchain 1.94" >&2
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
        mkdir -p "${2%/*}"
        printf "%s\n" agentd >"$2"
        ;;
    rm) exit 0 ;;
    image)
        [[ "${2:-}" == inspect ]] || exit 3
        [[ "${FAKE_IMAGE_MISSING:-}" != 1 ]] || exit 1
        printf "%s\n" "${FAKE_IMAGE_PLATFORM:-linux/arm64}"
        ;;
    save)
        [[ "${FAKE_SAVE_FAIL:-}" != 1 ]] || exit 29
        printf "%s" fake-archive
        ;;
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
    make_tool "$fakebin/plutil" '
key="${2:-}"
case "$key" in
    *hypervisor*) value="${FAKE_HYPERVISOR_ENTITLEMENT:-true}" ;;
    *disable-library-validation*) value="${FAKE_LIBRARY_ENTITLEMENT:-true}" ;;
    *) exit 3 ;;
esac
[[ "$value" != missing ]] || exit 1
printf "%s\n" "$value"'
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
    [[ $status -ne 0 ]] || fail "build unexpectedly succeeded: $expected"
    assert_contains "$output" "$expected"
}

install_import_msb() {
    local fixture="$1"
    mkdir -p "$fixture/target/macos/bin"
    cat >"$fixture/target/macos/bin/msb" <<'SH'
#!/bin/bash
set -euo pipefail
payload="$(cat)"
printf 'MSB_HOME=%s args=%s payload=%s\n' "$MSB_HOME" "$*" "$payload" >>"$FAKE_LOG"
SH
    chmod +x "$fixture/target/macos/bin/msb"
}

run_import() {
    local fixture="$1" fakebin="$2"
    shift 2
    run_fixture_script "$fixture" "$fakebin" script/build/import-image.sh "$@"
}

expect_import_failure() {
    local expected="$1" fixture="$2" fakebin="$3"
    shift 3
    local output status
    set +e
    output="$(run_import "$fixture" "$fakebin" "$@" 2>&1)"
    status=$?
    set -e
    [[ $status -ne 0 ]] || fail "import unexpectedly succeeded: $expected"
    assert_contains "$output" "$expected"
    if [[ -f "$fixture/calls.log" ]]; then
        case "$(cat "$fixture/calls.log")" in
            *"MSB_HOME="*) fail "failed import reached image load" ;;
        esac
    fi
}

# Public scripts must exist before the fake contract can run.
[[ -f "$REPO_ROOT/script/build/macos.sh" ]] || fail "missing script/build/macos.sh"
[[ -f "$REPO_ROOT/script/build/import-image.sh" ]] || fail "missing script/build/import-image.sh"

# macos.sh's RUST_TOOLCHAIN literal is a deliberate second copy of the pin (it
# must not auto-select via rust-toolchain.toml, so the build script never
# depends on or changes the caller's global default toolchain — see its own
# comment). Assert the two agree so a future bump can't touch one and forget
# the other.
toolchain_toml_channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$REPO_ROOT/rust-toolchain.toml")"
macos_sh_pin="$(sed -n 's/^RUST_TOOLCHAIN=\(.*\)$/\1/p' "$REPO_ROOT/script/build/macos.sh")"
[[ -n "$toolchain_toml_channel" ]] || fail "could not read channel from rust-toolchain.toml"
[[ "$macos_sh_pin" == "$toolchain_toml_channel" ]] ||
    fail "script/build/macos.sh RUST_TOOLCHAIN ($macos_sh_pin) drifted from rust-toolchain.toml channel ($toolchain_toml_channel)"

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
assert_file_contains "$fixture/calls.log" "docker cp fake-container:/agentd build/agentd"
assert_file_contains "$fixture/calls.log" "docker rm fake-container"
assert_file_contains "$fixture/calls.log" "--release --no-default-features --features net,ssh -p microsandbox-cli"
assert_file_contains "$fixture/calls.log" "codesign --entitlements msb-entitlements.plist --force -s - build/msb"
assert_file_contains "$fixture/calls.log" "firmware docker build"
assert_file_contains "$fixture/calls.log" "-DABI_VERSION=5"
assert_file_contains "$fixture/calls.log" "--release -p agent-vm"
assert_file_contains "$fixture/calls.log" "target=$fixture/vendor/microsandbox/target"
assert_file_contains "$fixture/calls.log" "target=$fixture/target"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.94 rustc --version"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.94 cargo --version"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.94 cargo build --release --no-default-features --features net,ssh -p microsandbox-cli"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.94 cargo build --release -p agent-vm"

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
assert_file_contains "$fixture/calls.log" "cargo build --no-default-features --features net,ssh -p microsandbox-cli"
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
    FAKE_PINNED_RUST_VERSION='rustc 1.94.0 (fake)'
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.94 rustc --version"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.94 cargo --version"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.94 cargo build --release --no-default-features --features net,ssh -p microsandbox-cli"
assert_file_contains "$fixture/calls.log" "rustup auto_install=0 args=run 1.94 cargo build --release -p agent-vm"
make_fixture old-pinned-rust
expect_build_failure "Rust 1.94 or newer is required" "$fixture" "$fakebin" env FAKE_PINNED_RUST_VERSION='rustc 1.90.0 (fake)'
make_fixture missing-rust-toolchain
set +e
output="$(run_build "$fixture" "$fakebin" env FAKE_RUSTUP_TOOLCHAIN_MISSING=1 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "build unexpectedly succeeded with missing Rust toolchain"
assert_contains "$output" "Rust toolchain 1.94 is not installed or usable"
assert_contains "$output" "rustc"
assert_contains "$output" "rustup toolchain install 1.94"
assert_contains "$output" "RUSTUP_USE_CURL=1 rustup toolchain install 1.94"
calls="$(cat "$fixture/calls.log")"
assert_not_contains "$calls" "docker info"
assert_not_contains "$calls" "cargo cwd="
make_fixture incomplete-rust-toolchain
set +e
output="$(run_build "$fixture" "$fakebin" env FAKE_RUSTUP_CARGO_MISSING=1 2>&1)"
status=$?
set -e
[[ $status -ne 0 ]] || fail "build unexpectedly succeeded with unusable pinned Cargo"
assert_contains "$output" "Cargo component for Rust toolchain 1.94 is not installed or usable"
assert_contains "$output" "rustup component add cargo --toolchain 1.94"
assert_contains "$output" "RUSTUP_USE_CURL=1 rustup component add cargo --toolchain 1.94"
assert_not_contains "$output" "rustup toolchain install 1.94"
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

# Import argument defaults, cache placement, and direct streaming.
check_import() {
    local name="$1" expected_home="$2" expected_image="$3" expected_tag="$4"
    local output expected_agent_vm expected_shell_tag
    shift 4
    make_fixture "$name"
    install_import_msb "$fixture"
    output="$(run_import "$fixture" "$fakebin" "$@")"
    assert_file_contains "$fixture/calls.log" "docker image inspect --format {{.Os}}/{{.Architecture}} $expected_image"
    assert_file_contains "$fixture/calls.log" "docker save $expected_image"
    assert_file_contains "$fixture/calls.log" "MSB_HOME=$expected_home args=image load --tag $expected_tag payload=fake-archive"
    printf -v expected_agent_vm '%q' "$fixture/target/macos/bin/agent-vm"
    printf -v expected_shell_tag '%q' "$expected_tag"
    assert_contains "$output" "  $expected_agent_vm shell --image $expected_shell_tag -- uname -m"
    set -- "$fixture"/*.tar
    [[ ! -e "$1" ]] || fail "import created a caller-managed tar"
}
check_import import-default "/tmp/state/agent-vm/msb-home" agent-vm-template:latest agent-vm-template:latest env -u AGENT_VM_STATE_DIR XDG_STATE_HOME=/tmp/state
check_import import-one /tmp/custom/msb-home local:dev local:dev env AGENT_VM_STATE_DIR=/tmp/custom -- local:dev
check_import import-two /tmp/custom/msb-home source:dev destination:dev env AGENT_VM_STATE_DIR=/tmp/custom -- source:dev destination:dev
check_import import-empty-agent "$TEST_ROOT/msb-home" image:one image:one env AGENT_VM_STATE_DIR= -- image:one
check_import import-empty-xdg "$TEST_ROOT/agent-vm/msb-home" image:two image:two env -u AGENT_VM_STATE_DIR XDG_STATE_HOME= -- image:two
check_import import-empty-home "$TEST_ROOT/.local/state/agent-vm/msb-home" image:three image:three env -u AGENT_VM_STATE_DIR -u XDG_STATE_HOME HOME= -- image:three
check_import import-relative-agent "$TEST_ROOT/custom-state/msb-home" image:four image:four env AGENT_VM_STATE_DIR=custom-state -- image:four
check_import import-relative-xdg "$TEST_ROOT/xdg-state/agent-vm/msb-home" image:five image:five env -u AGENT_VM_STATE_DIR XDG_STATE_HOME=xdg-state -- image:five
check_import import-relative-home "$TEST_ROOT/home/.local/state/agent-vm/msb-home" image:six image:six env -u AGENT_VM_STATE_DIR -u XDG_STATE_HOME HOME=home -- image:six
check_import "import hint escaping" /tmp/custom/msb-home source:dev "destination tag" env AGENT_VM_STATE_DIR=/tmp/custom -- source:dev "destination tag"

# Import failures stop before loading.
make_fixture import-no-bundle
expect_import_failure "run './script/build/macos.sh' first" "$fixture" "$fakebin"
make_fixture import-no-docker
install_import_msb "$fixture"
mv "$fakebin/docker" "$fakebin/docker.disabled"
expect_import_failure "docker is required" "$fixture" "$fakebin"
make_fixture import-daemon
install_import_msb "$fixture"
expect_import_failure "daemon is unavailable" "$fixture" "$fakebin" env FAKE_DOCKER_DOWN=1
make_fixture import-missing-image
install_import_msb "$fixture"
expect_import_failure "was not found" "$fixture" "$fakebin" env FAKE_IMAGE_MISSING=1
make_fixture import-wrong-platform
install_import_msb "$fixture"
expect_import_failure "must be linux/arm64" "$fixture" "$fakebin" env FAKE_IMAGE_PLATFORM=linux/amd64
make_fixture import-no-home
install_import_msb "$fixture"
expect_import_failure "HOME is unset" "$fixture" "$fakebin" env -u AGENT_VM_STATE_DIR -u XDG_STATE_HOME -u HOME
make_fixture import-extra
install_import_msb "$fixture"
expect_import_failure "Usage:" "$fixture" "$fakebin" -- one two three

# Help requires neither platform nor build tools.
make_fixture help
help_fixture="$fixture"
helpbin="$TEST_ROOT/help-only-bin"
mkdir -p "$helpbin"
ln -s /bin/bash "$helpbin/bash"
ln -s "$(command -v cat)" "$helpbin/cat"
PATH="$helpbin" "$help_fixture/script/build/macos.sh" --help >/dev/null
PATH="$helpbin" "$help_fixture/script/build/import-image.sh" --help >/dev/null

echo "build workflow seam tests passed"
