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

RUST_TOOLCHAIN=1.98.1

usage() {
    cat <<'EOF'
Usage: ./script/build/macos.sh [--dev | --single-binary]

Build and verify the Apple Silicon macOS bundle under target/macos.

  --dev  Build agent-vm and msb unoptimized (cargo's debug profile,
         skipping the release profile's thin-LTO and 16-codegen-unit
         settings) for a much faster edit/build/run loop. Publishes to
         target/macos-dev instead, so it never overwrites the
         optimized target/macos bundle. Not for distribution: the
         binaries are larger, unstripped, and slower at runtime. See
         "Fast development build" in macos-build.md.

  --single-binary  Build release agent-vm with embedded-runtime and publish only
                   target/macos-single/agent-vm. Existing bundles are untouched.
                   Cannot be combined with --dev.
EOF
}

run_rust_tool() {
    RUSTUP_AUTO_INSTALL=0 rustup run "$RUST_TOOLCHAIN" "$@"
}

rust_toolchain_error() {
    local tool="$1"

    echo "error: Rust toolchain $RUST_TOOLCHAIN is not installed or usable: failed to run '$tool'" >&2
    echo "Install the complete known-good toolchain with 'rustup toolchain install $RUST_TOOLCHAIN'." >&2
    echo "If rustup $RUST_TOOLCHAIN fails on macOS with 'OSStatus -26276', retry once with its TLS-verifying curl backend:" >&2
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
    local needed_major needed_remainder needed_minor

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
    # The floor guard compares MAJOR.MINOR only: the patch component is
    # intentionally ignored because run_rust_tool already pins the exact
    # toolchain via `rustup run "$RUST_TOOLCHAIN"` with RUSTUP_AUTO_INSTALL=0,
    # so this is only a coarse "grossly old toolchain" backstop. The
    # `major != needed_major` arm deliberately rejects a *newer* major too
    # (rustc 2.0.0 against a 1.98.1 pin reads "Rust 1.98.1 or newer is
    # required"); an edition/major jump is not something this script waves
    # through.
    needed_major="${RUST_TOOLCHAIN%%.*}"
    needed_remainder="${RUST_TOOLCHAIN#*.}"
    needed_minor="${needed_remainder%%.*}"
    if ((major != needed_major)) || ((minor < needed_minor)); then
        echo "error: Rust $RUST_TOOLCHAIN or newer is required; found $version" >&2
        echo "Install the known-good toolchain with 'rustup toolchain install $RUST_TOOLCHAIN'." >&2
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

    local container_id='' staged=build/.agentd.next
    # Invoked indirectly by the subshell's EXIT trap.
    # shellcheck disable=SC2317,SC2329
    cleanup_container() {
        rm -f "$staged"
        if [[ -n "$container_id" ]]; then
            docker rm "$container_id" >/dev/null 2>&1 || true
        fi
    }
    trap cleanup_container EXIT

    docker build -f Dockerfile.agentd -t microsandbox-agentd-build .
    container_id="$(docker create microsandbox-agentd-build /dev/null)"
    docker cp "$container_id:/agentd" "$staged"

    # microsandbox-filesystem's build.rs declares
    # `cargo:rerun-if-changed=build/agentd`, so bumping this file's mtime on
    # every invocation -- even a full Docker layer-cache hit -- forces a full
    # rebuild of microsandbox-filesystem/runtime/sdk/cli (and, transitively,
    # agent-vm) on every run regardless of whether anything changed. Only
    # replace build/agentd, and thus only touch its mtime, when the built
    # binary's content actually differs.
    if [[ -f build/agentd ]] && cmp -s "$staged" build/agentd; then
        rm -f "$staged"
    else
        mv -f "$staged" build/agentd
    fi
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
            run_rust_tool cargo build $cargo_release_flag --no-default-features --features embed-binaries,net,ssh -p microsandbox-cli
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
    local firmware_source=vendor/microsandbox/vendor/libkrunfw head status

    head="$(git -C "$firmware_source" rev-parse HEAD)" || {
        echo "error: cannot read the nested libkrunfw commit; run git submodule update --init --recursive" >&2
        exit 1
    }
    [[ "$head" == "$(firmware_gitlink)" ]] || {
        echo "error: nested libkrunfw checkout does not match its gitlink; run git submodule update --init --recursive" >&2
        exit 1
    }
    # A failing status probe prints nothing, and "nothing" must not read as clean.
    status="$(git -C "$firmware_source" status --porcelain --untracked-files=normal)" || {
        echo "error: cannot read the nested libkrunfw status; restore it before building or reusing firmware" >&2
        exit 1
    }
    [[ -z "$status" ]] || {
        echo "error: nested libkrunfw source is dirty; restore it before building or reusing firmware" >&2
        exit 1
    }
}

firmware_artifact_is_valid() {
    local path="$1" archs kind

    # `file` names the Mach-O flavour: an arm64 *executable* is not a firmware
    # library, and the shared store hands this function artifacts no build of
    # this checkout produced.
    kind="$(file "$path" 2>/dev/null)" || return 1
    case "$kind" in
        *"shared library"*) ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$kind" >&2
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

# Where a firmware dylib for one pinned source is kept for every checkout on this
# host. The artifact and its stamp live inside the checkout, so reuse was
# per-worktree: a second checkout of the same pin paid the whole Docker kernel
# build again (983 s of a 1297 s cold build here). The stamp that already guards
# the local artifact names this entry, so a sibling worktree copies instead of
# rebuilding.
#
# The root matches host_paths::cache_root: an absolute $XDG_CACHE_HOME, else
# $HOME/.cache. Neither usable means no shared cache -- a slow build, never a
# wrong one.
shared_firmware_path() {
    local gitlink="$1" root="${XDG_CACHE_HOME:-}"

    if [[ "$root" != /* ]]; then
        root="${HOME:-}"
        [[ "$root" == /* ]] || return 1
        root="$root/.cache"
    fi
    printf '%s\n' "$root/agent-vm/firmware/libkrunfw-5-$gitlink.dylib"
}

# The path names the pinned source, so a hit still has to be a loadable arm64
# dylib before it is allowed to become this checkout's artifact: a truncated or
# hand-copied file rebuilds.
shared_firmware_is_reusable() {
    local path="$1"

    [[ -n "$path" && -f "$path" ]] || return 1
    firmware_artifact_is_valid "$path" >/dev/null 2>&1
}

# Best-effort by design: a cache that cannot be written costs the next worktree a
# rebuild, never this build, so nothing here may fail a build that already
# produced a verified artifact. Every failure says so, because silence here looks
# like a cache that is simply not helping.
#
# The staged copy is uniquely named: concurrent checkouts of one pin publish the
# same entry, and a shared staging name would let one rename another's
# half-written file into place.
publish_shared_firmware() {
    local artifact="$1" gitlink="$2" entry dir staged

    entry="$(shared_firmware_path "$gitlink")" || return 0
    dir="${entry%/*}"
    mkdir -p "$dir" 2>/dev/null || {
        echo "warning: cannot create the shared firmware cache $dir; the next worktree rebuilds" >&2
        return 0
    }
    staged="$(mktemp "$dir/.libkrunfw.XXXXXX" 2>/dev/null)" || {
        echo "warning: cannot stage a copy in the shared firmware cache $dir; the next worktree rebuilds" >&2
        return 0
    }
    if ! install -m 0644 "$artifact" "$staged" 2>/dev/null; then
        rm -f "$staged" || true
        echo "warning: cannot write the shared firmware cache $entry; the next worktree rebuilds" >&2
        return 0
    fi
    if ! mv -f "$staged" "$entry" 2>/dev/null; then
        rm -f "$staged" || true
        echo "warning: cannot publish the shared firmware cache $entry; the next worktree rebuilds" >&2
    fi
    return 0
}

build_firmware_if_missing() {
    local firmware=vendor/microsandbox/build/libkrunfw.5.dylib
    local stamp="${firmware}.source-sha"
    local source_firmware=vendor/microsandbox/vendor/libkrunfw/libkrunfw.5.dylib
    local staged_firmware="${firmware}.next"
    local staged_stamp="${stamp}.next"
    local gitlink expected_stamp shared_firmware=''

    require_clean_firmware_source
    gitlink="$(firmware_gitlink)"
    expected_stamp="$gitlink"
    if [[ "${MSB_FORCE_FIRMWARE_REBUILD:-}" != 1 && -f "$firmware" && -f "$stamp" && "$(cat "$stamp")" == "$expected_stamp" ]]; then
        if firmware_artifact_is_valid "$firmware" >/dev/null 2>&1; then
            # Seed the shared copy from a checkout that already has one, so the
            # store converges without a second build anywhere.
            shared_firmware="$(shared_firmware_path "$expected_stamp")" || shared_firmware=''
            shared_firmware_is_reusable "$shared_firmware" ||
                publish_shared_firmware "$firmware" "$expected_stamp"
            return
        fi
        echo "==> Rebuilding invalid cached vendored firmware"
    fi
    # A shared entry becomes this checkout's artifact by a copy, so it is keyed and
    # validated exactly like the local one. Force mode ignores it too.
    if [[ "${MSB_FORCE_FIRMWARE_REBUILD:-}" != 1 ]]; then
        shared_firmware="$(shared_firmware_path "$expected_stamp")" || shared_firmware=''
    fi

    (
        local built
        # shellcheck disable=SC2317,SC2329 # This cleanup is invoked by the EXIT trap below.
        cleanup_firmware_staging() {
            rm -f "$staged_firmware" "$staged_stamp"
        }
        trap cleanup_firmware_staging EXIT

        rm -f "$staged_firmware" "$staged_stamp"
        built=1
        if shared_firmware_is_reusable "$shared_firmware"; then
            echo "==> Reusing shared vendored firmware for $expected_stamp from $shared_firmware"
            install -m 0644 "$shared_firmware" "$staged_firmware"
            built=0
        else
            echo "==> Building vendored firmware from pinned source"
            (
                cd vendor/microsandbox/vendor/libkrunfw
                export LIBKRUNFW_BUILD_BACKEND=docker
                ./build_in_docker.sh
                cc -fPIC -DABI_VERSION=5 -shared -o libkrunfw.5.dylib kernel.c
            )
            mkdir -p vendor/microsandbox/build
            install -m 0644 "$source_firmware" "$staged_firmware"
        fi
        require_valid_firmware_artifact "$staged_firmware"
        # A build can run for 16 minutes, which is long enough for the pin to move
        # under it. This artifact may stand for $expected_stamp locally and in
        # every other checkout, so prove the source is still that pin first.
        require_clean_firmware_source
        gitlink="$(firmware_gitlink)"
        [[ "$gitlink" == "$expected_stamp" ]] || {
            echo "error: the nested libkrunfw gitlink changed during the build; nothing was published" >&2
            exit 1
        }
        printf '%s\n' "$expected_stamp" >"$staged_stamp"
        # A copy taken from the store must not be written back to it.
        if ((built)); then
            publish_shared_firmware "$staged_firmware" "$expected_stamp"
        fi
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

build_single_binary_agent_vm() {
    CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}" \
        CARGO_TARGET_DIR="$REPO_ROOT/target" \
        AGENT_VM_EMBED_MSB="$REPO_ROOT/vendor/microsandbox/build/msb" \
        AGENT_VM_EMBED_LIBKRUNFW="$REPO_ROOT/vendor/microsandbox/build/libkrunfw.5.dylib" \
        run_rust_tool cargo build --release --features embedded-runtime -p agent-vm
    test -f "$REPO_ROOT/target/release/agent-vm" || {
        echo "error: Cargo did not produce target/release/agent-vm" >&2
        exit 1
    }
}

publish_single_binary() {
    local out="$REPO_ROOT/target/macos-single"
    local staged="$out/.agent-vm.next" smoke="$out/.smoke" entitlements="$out/.msb-entitlements.plist"
    local agent_vm_version msb_version candidate extracted='' count=0

    mkdir -p "$out"
    rm -rf "$smoke"
    # Expanded now: the trap must not read locals after this function returns.
    # shellcheck disable=SC2064
    trap "rm -rf $(printf '%q ' "$staged" "$smoke" "$entitlements")" EXIT

    install -m 0755 "$REPO_ROOT/target/release/agent-vm" "$staged"
    verify_arm64_only "$staged"
    agent_vm_version="$("$staged" --version)" || {
        echo "error: staged single-binary agent-vm failed to run with --version" >&2; exit 1; }

    mkdir -p "$smoke/bin" "$smoke/home" "$smoke/state" "$smoke/work"
    install -m 0755 "$staged" "$smoke/bin/agent-vm"
    msb_version="$(cd "$smoke/work" &&
        unset MSB_PATH MSB_LIBKRUNFW_PATH XDG_CACHE_HOME XDG_STATE_HOME AGENT_VM_SHARE_MSB_CACHE AGENT_VM_MSB_CACHE_DIR &&
        HOME="$smoke/home" AGENT_VM_STATE_DIR="$smoke/state" "$smoke/bin/agent-vm" msb --version)" || {
        echo "error: single-binary agent-vm failed to start from an empty directory" >&2; exit 1; }

    for candidate in "$smoke"/home/.cache/agent-vm/runtime/*/bin/msb; do
        [[ -f "$candidate" ]] || continue
        extracted="$candidate"; count=$((count + 1))
    done
    if ((count == 0)); then
        echo "error: single-binary agent-vm did not unpack msb under $smoke/home/.cache/agent-vm/runtime" >&2; exit 1
    elif ((count > 1)); then
        echo "error: single-binary smoke unpacked more than one runtime" >&2; exit 1
    fi
    verify_arm64_only "$extracted"
    verify_arm64_only "${extracted%/bin/msb}/lib/libkrunfw.5.dylib"
    verify_msb "$extracted" "$entitlements"   # verbatim unpack kept signature + both entitlements

    mv -f "$staged" "$out/agent-vm"
    rm -rf "$smoke" "$entitlements"
    trap - EXIT
    echo "==> macOS single binary ready"
    printf '%s\n' "$agent_vm_version" "$msb_version"
    printf '  %s\n' "$out/agent-vm"
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
    # Invoked indirectly by the trap below.
    # shellcheck disable=SC2317,SC2329
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
    local dev=false single=false

    while (($#)); do
        case "$1" in
            -h | --help)
                usage
                return
                ;;
            --single-binary)
                single=true
                shift
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

    if [[ "$dev" == true && "$single" == true ]]; then
        echo "error: --single-binary cannot be combined with --dev" >&2
        usage >&2
        exit 2
    fi

    preflight
    build_microsandbox_runtime "$dev"
    require_build_outputs "$dev"
    if [[ "$single" == true ]]; then
        build_single_binary_agent_vm
        publish_single_binary
    else
        build_agent_vm "$dev"
        publish_bundle "$dev"
    fi
}

main "$@"
