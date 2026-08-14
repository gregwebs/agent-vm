#!/usr/bin/env bash
# Build and publish the signed Apple Silicon macOS agent-vm bundle.
# Usage: ./script/build/macos.sh

set -euo pipefail

case "${BASH_SOURCE[0]}" in
    */*) script_dir_path="${BASH_SOURCE[0]%/*}" ;;
    *) script_dir_path=. ;;
esac
SCRIPT_DIR="$(cd "$script_dir_path" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

RUST_TOOLCHAIN=1.92

usage() {
    cat <<'EOF'
Usage: ./script/build/macos.sh

Build and verify the Apple Silicon macOS bundle under target/macos.
EOF
}

run_rust_tool() {
    RUSTUP_AUTO_INSTALL=0 rustup run "$RUST_TOOLCHAIN" "$@"
}

rust_toolchain_error() {
    local tool="$1"

    echo "error: Rust toolchain $RUST_TOOLCHAIN is not installed or usable: failed to run '$tool'" >&2
    echo "Install the complete known-good toolchain with 'rustup toolchain install $RUST_TOOLCHAIN'." >&2
    echo "If rustup 1.29 fails on macOS with 'OSStatus -26276', retry once with its TLS-verifying curl backend:" >&2
    echo "  RUSTUP_USE_CURL=1 rustup toolchain install $RUST_TOOLCHAIN" >&2
}

cargo_component_error() {
    echo "error: Cargo component for Rust toolchain $RUST_TOOLCHAIN is not installed or usable" >&2
    echo "Install or repair Cargo with 'rustup component add cargo --toolchain $RUST_TOOLCHAIN'." >&2
    echo "If rustup 1.29 fails on macOS with 'OSStatus -26276', retry once with its TLS-verifying curl backend:" >&2
    echo "  RUSTUP_USE_CURL=1 rustup component add cargo --toolchain $RUST_TOOLCHAIN" >&2
}

preflight() {
    local tool rust_version version major remainder minor

    if [[ "$(uname -s)" != Darwin ]]; then
        echo "error: ./script/build/macos.sh supports macOS only" >&2
        exit 1
    fi
    if [[ "$(uname -m)" != arm64 ]]; then
        echo "error: ./script/build/macos.sh supports Apple Silicon (arm64) only" >&2
        exit 1
    fi

    for tool in rustup git docker codesign xcode-select file lipo plutil install cc; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "error: required tool '$tool' was not found on PATH" >&2
            exit 1
        }
    done

    if ! rust_version="$(run_rust_tool rustc --version)"; then
        rust_toolchain_error rustc
        exit 1
    fi
    version="${rust_version#rustc }"
    version="${version%% *}"
    major="${version%%.*}"
    remainder="${version#*.}"
    minor="${remainder%%.*}"
    if [[ ! "$major" =~ ^[0-9]+$ || ! "$minor" =~ ^[0-9]+$ ]]; then
        echo "error: could not parse Rust version from: $rust_version" >&2
        exit 1
    fi
    if ((major < 1 || (major == 1 && minor < 91))); then
        echo "error: Rust 1.91 or newer is required; found $version" >&2
        echo "Install the known-good toolchain with 'rustup toolchain install 1.92'." >&2
        exit 1
    fi
    if ! run_rust_tool cargo --version >/dev/null; then
        cargo_component_error
        exit 1
    fi

    xcode-select -p >/dev/null 2>&1 || {
        echo "error: Xcode Command Line Tools are unavailable; run 'xcode-select --install'" >&2
        exit 1
    }
    docker info >/dev/null 2>&1 || {
        echo "error: Docker is installed but its daemon is unavailable; start Docker Desktop" >&2
        exit 1
    }

    test -f vendor/microsandbox/Cargo.toml || {
        echo "error: vendor/microsandbox is not initialized; run 'git submodule update --init --recursive'" >&2
        exit 1
    }
    test -f vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh || {
        echo "error: vendor/microsandbox/vendor/libkrunfw is not initialized; run 'git submodule update --init --recursive'" >&2
        exit 1
    }
}

# This mirrors the pinned vendor/microsandbox macOS build-agentd and
# build-msb recipes. Re-check the sequence whenever the submodule pin changes.
build_agentd() (
    cd vendor/microsandbox
    mkdir -p build

    local container_id=
    # Invoked indirectly by the subshell's EXIT trap.
    # shellcheck disable=SC2329
    cleanup_container() {
        if [[ -n "$container_id" ]]; then
            docker rm "$container_id" >/dev/null 2>&1 || true
        fi
    }
    trap cleanup_container EXIT

    docker build -f Dockerfile.agentd -t microsandbox-agentd-build .
    container_id="$(docker create microsandbox-agentd-build /dev/null)"
    docker cp "$container_id:/agentd" build/agentd
    touch build/agentd
)

build_and_sign_msb() {
    (
        cd vendor/microsandbox
        CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}" \
            CARGO_TARGET_DIR="$REPO_ROOT/vendor/microsandbox/target" \
            run_rust_tool cargo build --release --no-default-features --features net,ssh -p microsandbox-cli
        mkdir -p build
        install -m 0755 target/release/msb build/msb
        codesign --entitlements msb-entitlements.plist --force -s - build/msb
    )
}

build_firmware_if_missing() {
    local firmware=vendor/microsandbox/build/libkrunfw.5.dylib
    if [[ -f "$firmware" ]]; then
        return
    fi

    echo "==> Restoring missing vendored firmware output"
    (
        cd vendor/microsandbox/vendor/libkrunfw
        ./build_in_docker.sh
        cc -fPIC -DABI_VERSION=5 -shared -o libkrunfw.5.dylib kernel.c
    )
    mkdir -p vendor/microsandbox/build
    install -m 0644 \
        vendor/microsandbox/vendor/libkrunfw/libkrunfw.5.dylib \
        "$firmware"
}

build_microsandbox_runtime() {
    echo "==> Building vendored microsandbox runtime"
    build_agentd
    build_and_sign_msb
    build_firmware_if_missing
}

require_build_outputs() {
    test -f vendor/microsandbox/build/msb || {
        echo "error: vendored build did not produce vendor/microsandbox/build/msb" >&2
        exit 1
    }
    test -f vendor/microsandbox/build/libkrunfw.5.dylib || {
        echo "error: vendored build did not produce vendor/microsandbox/build/libkrunfw.5.dylib" >&2
        exit 1
    }
}

build_agent_vm() {
    echo "==> Building agent-vm"
    CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}" \
        CARGO_TARGET_DIR="$REPO_ROOT/target" \
        run_rust_tool cargo build --release -p agent-vm
    test -f target/release/agent-vm || {
        echo "error: Cargo did not produce target/release/agent-vm" >&2
        exit 1
    }
}

verify_arm64_only() {
    local path="$1" archs
    file "$path"
    archs="$(lipo -archs "$path")"
    if [[ "$archs" != arm64 ]]; then
        echo "error: $path must be arm64-only; found: $archs" >&2
        exit 1
    fi
}

verify_msb() {
    local path="$1" entitlements="$2" hypervisor library_validation

    codesign --verify --strict "$path" || {
        echo "error: $path does not have a valid code signature" >&2
        exit 1
    }
    codesign -d --entitlements - --xml "$path" >"$entitlements" || {
        echo "error: could not read entitlements from $path" >&2
        exit 1
    }

    hypervisor="$(plutil -extract 'com\.apple\.security\.hypervisor' raw -expect bool "$entitlements")" || {
        echo "error: $path is missing the boolean com.apple.security.hypervisor entitlement" >&2
        exit 1
    }
    if [[ "$hypervisor" != true ]]; then
        echo "error: $path must set com.apple.security.hypervisor to true" >&2
        exit 1
    fi

    library_validation="$(plutil -extract 'com\.apple\.security\.cs\.disable-library-validation' raw -expect bool "$entitlements")" || {
        echo "error: $path is missing the boolean com.apple.security.cs.disable-library-validation entitlement" >&2
        exit 1
    }
    if [[ "$library_validation" != true ]]; then
        echo "error: $path must set com.apple.security.cs.disable-library-validation to true" >&2
        exit 1
    fi
}

publish_bundle() {
    local staged_agent_vm=target/macos/bin/.agent-vm.next
    local staged_msb=target/macos/bin/.msb.next
    local staged_firmware=target/macos/lib/.libkrunfw.5.dylib.next
    local entitlements=target/macos/.msb-entitlements.plist
    local agent_vm_version msb_version

    mkdir -p target/macos/bin target/macos/lib
    cleanup_staging() {
        rm -f "$staged_agent_vm" "$staged_msb" "$staged_firmware" "$entitlements"
    }
    trap cleanup_staging EXIT

    install -m 0755 target/release/agent-vm "$staged_agent_vm"
    install -m 0755 vendor/microsandbox/build/msb "$staged_msb"
    install -m 0644 vendor/microsandbox/build/libkrunfw.5.dylib "$staged_firmware"

    verify_arm64_only "$staged_agent_vm"
    verify_arm64_only "$staged_msb"
    verify_arm64_only "$staged_firmware"
    verify_msb "$staged_msb" "$entitlements"
    rm -f "$entitlements"

    agent_vm_version="$("$staged_agent_vm" --version)" || {
        echo "error: staged agent-vm failed to run with --version" >&2
        exit 1
    }
    msb_version="$("$staged_msb" --version)" || {
        echo "error: staged msb failed to run with --version" >&2
        exit 1
    }

    mv -f "$staged_agent_vm" target/macos/bin/agent-vm
    mv -f "$staged_msb" target/macos/bin/msb
    mv -f "$staged_firmware" target/macos/lib/libkrunfw.5.dylib
    trap - EXIT

    echo "==> macOS bundle ready"
    printf '%s\n' "$agent_vm_version" "$msb_version"
    printf '  %s\n' \
        target/macos/bin/agent-vm \
        target/macos/bin/msb \
        target/macos/lib/libkrunfw.5.dylib
}

main() {
    case "${1:-}" in
        -h | --help)
            [[ $# -eq 1 ]] || {
                usage >&2
                exit 2
            }
            usage
            return
            ;;
    esac
    if (($# != 0)); then
        usage >&2
        exit 2
    fi

    preflight
    build_microsandbox_runtime
    require_build_outputs
    build_agent_vm
    publish_bundle
}

main "$@"
