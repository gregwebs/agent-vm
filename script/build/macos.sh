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

RUST_TOOLCHAIN=1.94

usage() {
    cat <<'EOF'
Usage: ./script/build/macos.sh [--dev]

Build and verify the Apple Silicon macOS bundle under target/macos.

  --dev  Build agent-vm and msb unoptimized (cargo's debug profile,
         skipping the release profile's thin-LTO and 16-codegen-unit
         settings) for a much faster edit/build/run loop. Publishes to
         target/macos-dev instead, so it never overwrites the
         optimized target/macos bundle. Not for distribution: the
         binaries are larger, unstripped, and slower at runtime. See
         "Fast development build" in macos-build.md.
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

    for tool in rustup git docker codesign xcode-select file lipo otool plutil install cc; do
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
    if ((major < 1 || (major == 1 && minor < 94))); then
        echo "error: Rust 1.94 or newer is required; found $version" >&2
        echo "Install the known-good toolchain with 'rustup toolchain install 1.94'." >&2
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
    # shellcheck disable=SC2317,SC2329
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

msb_build_name() {
    if [[ "$1" == true ]]; then
        printf '%s\n' msb-dev
    else
        printf '%s\n' msb
    fi
}

build_and_sign_msb() {
    # A bare `local x=()` on macOS's shipped bash 3.2 leaves $x unset rather
    # than an empty array, which trips `set -u` the moment it's expanded
    # ("x[@]: unbound variable") -- so cargo's optional --release flag is
    # threaded through as a scalar, expanded unquoted, instead of an array.
    local dev="$1" cargo_release_flag=--release cargo_subdir=release msb_name

    if [[ "$dev" == true ]]; then
        cargo_release_flag=
        cargo_subdir=debug
    fi
    msb_name="$(msb_build_name "$dev")"

    (
        cd vendor/microsandbox
        # shellcheck disable=SC2086
        CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}" \
            CARGO_TARGET_DIR="$REPO_ROOT/vendor/microsandbox/target" \
            run_rust_tool cargo build $cargo_release_flag --no-default-features --features net,ssh -p microsandbox-cli
        mkdir -p build
        install -m 0755 "target/$cargo_subdir/msb" "build/$msb_name"
        codesign --entitlements msb-entitlements.plist --force -s - "build/$msb_name"
    )
}

firmware_gitlink() {
    local gitlink
    gitlink="$(git -C vendor/microsandbox ls-tree HEAD vendor/libkrunfw | awk '{print $3}')"
    [[ "$gitlink" =~ ^[0-9a-f]{40}$ ]] || {
        echo "error: could not resolve the nested libkrunfw gitlink; initialize recursive submodules" >&2
        exit 1
    }
    printf '%s\n' "$gitlink"
}

require_clean_firmware_source() {
    local firmware_source=vendor/microsandbox/vendor/libkrunfw
    [[ "$(git -C "$firmware_source" rev-parse HEAD)" == "$(firmware_gitlink)" ]] || {
        echo "error: nested libkrunfw checkout does not match its gitlink; run git submodule update --init --recursive" >&2
        exit 1
    }
    [[ -z "$(git -C "$firmware_source" status --porcelain --untracked-files=normal)" ]] || {
        echo "error: nested libkrunfw source is dirty; restore it before building or reusing firmware" >&2
        exit 1
    }
}

firmware_artifact_is_valid() {
    local path="$1" archs

    file "$path" >&2
    archs="$(lipo -archs "$path")" || return 1
    [[ "$archs" == arm64 ]] || return 1
    otool -L "$path" >/dev/null
}

require_valid_firmware_artifact() {
    local path="$1"

    firmware_artifact_is_valid "$path" || {
        echo "error: $path must be an arm64-only loadable macOS dynamic library" >&2
        exit 1
    }
}

build_firmware_if_missing() {
    local firmware=vendor/microsandbox/build/libkrunfw.5.dylib
    local stamp="${firmware}.source-sha"
    local source_firmware=vendor/microsandbox/vendor/libkrunfw/libkrunfw.5.dylib
    local staged_firmware="${firmware}.next"
    local staged_stamp="${stamp}.next"
    local gitlink expected_stamp

    require_clean_firmware_source
    gitlink="$(firmware_gitlink)"
    expected_stamp="$gitlink"
    if [[ "${MSB_FORCE_FIRMWARE_REBUILD:-}" != 1 && -f "$firmware" && -f "$stamp" && "$(cat "$stamp")" == "$expected_stamp" ]]; then
        if firmware_artifact_is_valid "$firmware" >/dev/null 2>&1; then
            return
        fi
        echo "==> Rebuilding invalid cached vendored firmware"
    else
        echo "==> Building vendored firmware from pinned source"
    fi

    (
        # shellcheck disable=SC2317,SC2329 # This cleanup is invoked by the EXIT trap below.
        cleanup_firmware_staging() {
            rm -f "$staged_firmware" "$staged_stamp"
        }
        trap cleanup_firmware_staging EXIT

        rm -f "$staged_firmware" "$staged_stamp"
        (
            cd vendor/microsandbox/vendor/libkrunfw
            ./build_in_docker.sh
            cc -fPIC -DABI_VERSION=5 -shared -o libkrunfw.5.dylib kernel.c
        )
        mkdir -p vendor/microsandbox/build
        install -m 0644 "$source_firmware" "$staged_firmware"
        require_valid_firmware_artifact "$staged_firmware"
        printf '%s\n' "$expected_stamp" >"$staged_stamp"
        mv -f "$staged_firmware" "$firmware"
        mv -f "$staged_stamp" "$stamp"
        trap - EXIT
    )
}

build_microsandbox_runtime() {
    local dev="$1"
    echo "==> Building vendored microsandbox runtime"
    build_agentd
    build_and_sign_msb "$dev"
    build_firmware_if_missing
}

require_build_outputs() {
    local dev="$1" msb_name
    msb_name="$(msb_build_name "$dev")"

    test -f "vendor/microsandbox/build/$msb_name" || {
        echo "error: vendored build did not produce vendor/microsandbox/build/$msb_name" >&2
        exit 1
    }
    test -f vendor/microsandbox/build/libkrunfw.5.dylib || {
        echo "error: vendored build did not produce vendor/microsandbox/build/libkrunfw.5.dylib" >&2
        exit 1
    }
    require_clean_firmware_source
    [[ -f vendor/microsandbox/build/libkrunfw.5.dylib.source-sha && "$(cat vendor/microsandbox/build/libkrunfw.5.dylib.source-sha)" == "$(firmware_gitlink)" ]] || {
        echo "error: vendored firmware is missing a matching source identity stamp" >&2
        exit 1
    }
    require_valid_firmware_artifact vendor/microsandbox/build/libkrunfw.5.dylib
}

build_agent_vm() {
    local dev="$1" cargo_release_flag=--release cargo_subdir=release

    if [[ "$dev" == true ]]; then
        cargo_release_flag=
        cargo_subdir=debug
        echo "==> Building agent-vm (dev, unoptimized)"
    else
        echo "==> Building agent-vm"
    fi

    # shellcheck disable=SC2086
    CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}" \
        CARGO_TARGET_DIR="$REPO_ROOT/target" \
        run_rust_tool cargo build $cargo_release_flag -p agent-vm
    test -f "target/$cargo_subdir/agent-vm" || {
        echo "error: Cargo did not produce target/$cargo_subdir/agent-vm" >&2
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
    local dev="$1" bundle_dir=target/macos agent_vm_src=target/release/agent-vm
    local msb_src="vendor/microsandbox/build/msb"

    if [[ "$dev" == true ]]; then
        bundle_dir=target/macos-dev
        agent_vm_src=target/debug/agent-vm
        msb_src="vendor/microsandbox/build/$(msb_build_name true)"
    fi

    local staged_agent_vm="$bundle_dir/bin/.agent-vm.next"
    local staged_msb="$bundle_dir/bin/.msb.next"
    local staged_firmware="$bundle_dir/lib/.libkrunfw.5.dylib.next"
    local entitlements="$bundle_dir/.msb-entitlements.plist"
    local agent_vm_version msb_version

    mkdir -p "$bundle_dir/bin" "$bundle_dir/lib"
    cleanup_staging() {
        rm -f "$staged_agent_vm" "$staged_msb" "$staged_firmware" "$entitlements"
    }
    trap cleanup_staging EXIT

    install -m 0755 "$agent_vm_src" "$staged_agent_vm"
    install -m 0755 "$msb_src" "$staged_msb"
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

    mv -f "$staged_agent_vm" "$bundle_dir/bin/agent-vm"
    mv -f "$staged_msb" "$bundle_dir/bin/msb"
    mv -f "$staged_firmware" "$bundle_dir/lib/libkrunfw.5.dylib"
    trap - EXIT

    if [[ "$dev" == true ]]; then
        echo "==> macOS dev bundle ready (unoptimized; not for distribution)"
    else
        echo "==> macOS bundle ready"
    fi
    printf '%s\n' "$agent_vm_version" "$msb_version"
    printf '  %s\n' \
        "$bundle_dir/bin/agent-vm" \
        "$bundle_dir/bin/msb" \
        "$bundle_dir/lib/libkrunfw.5.dylib"
}

main() {
    local dev=false

    while (($#)); do
        case "$1" in
            -h | --help)
                usage
                return
                ;;
            --dev)
                dev=true
                shift
                ;;
            *)
                usage >&2
                exit 2
                ;;
        esac
    done

    preflight
    build_microsandbox_runtime "$dev"
    require_build_outputs "$dev"
    build_agent_vm "$dev"
    publish_bundle "$dev"
}

main "$@"
