docker_platform_format := "{{.Os}}/{{.Architecture}}"

# Build and assemble the signed Apple Silicon macOS bundle.
build-macos: _preflight-macos
    #!/usr/bin/env bash
    set -euo pipefail

    export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"

    echo "==> Building vendored microsandbox runtime"
    (cd vendor/microsandbox && just build release)
    if [[ ! -f vendor/microsandbox/build/libkrunfw.5.dylib ]]; then
        echo "==> Restoring missing vendored firmware output"
        (cd vendor/microsandbox && just build-libkrunfw)
    fi

    test -f vendor/microsandbox/build/msb || {
        echo "error: vendored build did not produce vendor/microsandbox/build/msb" >&2
        exit 1
    }
    test -f vendor/microsandbox/build/libkrunfw.5.dylib || {
        echo "error: vendored build did not produce vendor/microsandbox/build/libkrunfw.5.dylib" >&2
        exit 1
    }

    echo "==> Building agent-vm"
    cargo build --release -p agent-vm
    test -f target/release/agent-vm || {
        echo "error: Cargo did not produce target/release/agent-vm" >&2
        exit 1
    }

    mkdir -p target/macos/bin target/macos/lib
    staged_agent_vm=target/macos/bin/.agent-vm.next
    staged_msb=target/macos/bin/.msb.next
    staged_firmware=target/macos/lib/.libkrunfw.5.dylib.next
    trap 'rm -f "$staged_agent_vm" "$staged_msb" "$staged_firmware"' EXIT

    install -m 0755 target/release/agent-vm "$staged_agent_vm"
    install -m 0755 vendor/microsandbox/build/msb "$staged_msb"
    install -m 0644 vendor/microsandbox/build/libkrunfw.5.dylib "$staged_firmware"

    verify_arm64_only() {
        local path="$1" archs
        file "$path"
        archs="$(lipo -archs "$path")"
        if [[ "$archs" != "arm64" ]]; then
            echo "error: $path must be arm64-only; found: $archs" >&2
            exit 1
        fi
    }

    verify_arm64_only "$staged_agent_vm"
    verify_arm64_only "$staged_msb"
    verify_arm64_only "$staged_firmware"
    just _verify-macos-msb "$staged_msb"

    mv -f "$staged_agent_vm" target/macos/bin/agent-vm
    mv -f "$staged_msb" target/macos/bin/msb
    mv -f "$staged_firmware" target/macos/lib/libkrunfw.5.dylib
    trap - EXIT

    echo "==> macOS bundle ready"
    target/macos/bin/agent-vm --version
    target/macos/bin/msb --version
    printf '  %s\n' \
        target/macos/bin/agent-vm \
        target/macos/bin/msb \
        target/macos/lib/libkrunfw.5.dylib

# Import a local Docker arm64 image into agent-vm's private cache.
import-image image="agent-vm-template:latest" tag=image:
    #!/usr/bin/env bash
    set -euo pipefail

    image={{ quote(image) }}
    tag={{ quote(tag) }}

    if [[ ! -x target/macos/bin/msb ]]; then
        echo "error: target/macos/bin/msb is missing; run 'just build-macos' first" >&2
        exit 1
    fi
    command -v docker >/dev/null 2>&1 || {
        echo "error: docker is required; install and start Docker Desktop" >&2
        exit 1
    }
    docker info >/dev/null 2>&1 || {
        echo "error: Docker is installed but its daemon is unavailable; start Docker Desktop" >&2
        exit 1
    }

    platform="$(docker image inspect "$image" --format {{ quote(docker_platform_format) }})" || {
        echo "error: local Docker image '$image' was not found" >&2
        exit 1
    }
    if [[ "$platform" != "linux/arm64" ]]; then
        echo "error: local Docker image '$image' must be linux/arm64; found: $platform" >&2
        exit 1
    fi

    if [[ -n "${AGENT_VM_STATE_DIR+x}" ]]; then
        state_root="$AGENT_VM_STATE_DIR"
    elif [[ -n "${XDG_STATE_HOME+x}" ]]; then
        state_root="$XDG_STATE_HOME/agent-vm"
    elif [[ -n "${HOME+x}" ]]; then
        state_root="$HOME/.local/state/agent-vm"
    else
        echo "error: cannot resolve agent-vm state root because HOME is unset" >&2
        exit 1
    fi
    if [[ -n "$state_root" ]]; then
        msb_home="$state_root/msb-home"
    else
        msb_home=msb-home
    fi
    mkdir -p "$msb_home"

    echo "==> Importing $image as $tag into agent-vm's private cache"
    docker save "$image" | MSB_HOME="$msb_home" \
        target/macos/bin/msb image load --tag "$tag"

    echo "==> Imported $tag"
    printf 'Verify offline with:\n  ./target/macos/bin/agent-vm shell --image %q --no-update-check -- uname -m\n' "$tag"
    echo "Note: msb stages the incoming archive in temporary storage, so keep roughly one archive's worth of disk free."

_preflight-macos:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ "$(uname -s)" != "Darwin" ]]; then
        echo "error: just build-macos supports macOS only" >&2
        exit 1
    fi
    if [[ "$(uname -m)" != "arm64" ]]; then
        echo "error: just build-macos supports Apple Silicon (arm64) only" >&2
        exit 1
    fi

    for tool in rustc cargo just docker codesign xcode-select file lipo plutil install; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "error: required tool '$tool' was not found on PATH" >&2
            exit 1
        }
    done
    xcode-select -p >/dev/null 2>&1 || {
        echo "error: Xcode Command Line Tools are unavailable; run 'xcode-select --install'" >&2
        exit 1
    }
    docker info >/dev/null 2>&1 || {
        echo "error: Docker is installed but its daemon is unavailable; start Docker Desktop" >&2
        exit 1
    }

    rust_version="$(rustc --version)"
    version="${rust_version#rustc }"
    version="${version%% *}"
    major="${version%%.*}"
    remainder="${version#*.}"
    minor="${remainder%%.*}"
    if [[ ! "$major" =~ ^[0-9]+$ || ! "$minor" =~ ^[0-9]+$ ]]; then
        echo "error: could not parse Rust version from: $rust_version" >&2
        exit 1
    fi
    if (( major < 1 || (major == 1 && minor < 91) )); then
        echo "error: Rust 1.91 or newer is required; found $version" >&2
        echo "Install the known-good toolchain with 'rustup toolchain install 1.92'." >&2
        exit 1
    fi

    test -f vendor/microsandbox/Cargo.toml || {
        echo "error: vendor/microsandbox is not initialized; run 'git submodule update --init --recursive'" >&2
        exit 1
    }
    test -f vendor/microsandbox/vendor/libkrunfw/build_in_docker.sh || {
        echo "error: vendor/microsandbox/vendor/libkrunfw is not initialized; run 'git submodule update --init --recursive'" >&2
        exit 1
    }

_verify-macos-msb path:
    #!/usr/bin/env bash
    set -euo pipefail

    path={{ quote(path) }}
    entitlements=target/macos/.msb-entitlements.plist
    mkdir -p target/macos
    trap 'rm -f "$entitlements"' EXIT

    codesign --verify --strict "$path" || {
        echo "error: $path does not have a valid code signature" >&2
        exit 1
    }
    codesign -d --entitlements - --xml "$path" >"$entitlements"
    hypervisor="$(plutil -extract 'com\.apple\.security\.hypervisor' raw -expect bool "$entitlements")" || {
        echo "error: $path is missing the boolean com.apple.security.hypervisor entitlement" >&2
        exit 1
    }
    if [[ "$hypervisor" != "true" ]]; then
        echo "error: $path must set com.apple.security.hypervisor to true" >&2
        exit 1
    fi
