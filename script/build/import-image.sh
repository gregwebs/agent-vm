#!/usr/bin/env bash
# Import a local Docker image into agent-vm's private microsandbox cache.
# Usage: ./script/build/import-image.sh [SOURCE_IMAGE [DESTINATION_TAG]]

set -euo pipefail
CALLER_PWD="$PWD"

case "${BASH_SOURCE[0]}" in
    */*) script_dir_path="${BASH_SOURCE[0]%/*}" ;;
    *) script_dir_path=. ;;
esac
SCRIPT_DIR="$(cd "$script_dir_path" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

usage() {
    cat <<'EOF'
Usage: ./script/build/import-image.sh [SOURCE_IMAGE [DESTINATION_TAG]]

Import a local linux/arm64 Docker image into agent-vm's private cache.
SOURCE_IMAGE defaults to agent-vm-template:latest. DESTINATION_TAG defaults
to SOURCE_IMAGE.
EOF
}

join_path() {
    local base="$1" component="$2"
    if [[ -n "$base" ]]; then
        printf '%s/%s\n' "${base%/}" "$component"
    else
        printf '%s\n' "$component"
    fi
}
resolve_from_caller() {
    local path="$1"
    case "$path" in
        /*) printf '%s\n' "$path" ;;
        *) join_path "$CALLER_PWD" "$path" ;;
    esac
}


resolve_msb_home() {
    local state_root
    if [[ -n "${AGENT_VM_STATE_DIR+x}" ]]; then
        state_root="$AGENT_VM_STATE_DIR"
    elif [[ -n "${XDG_STATE_HOME+x}" ]]; then
        state_root="$(join_path "$XDG_STATE_HOME" agent-vm)"
    elif [[ -n "${HOME+x}" ]]; then
        state_root="$(join_path "$HOME" .local/state/agent-vm)"
    else
        echo "error: cannot resolve agent-vm state root because HOME is unset" >&2
        return 1
    fi
    state_root="$(resolve_from_caller "$state_root")"
    join_path "$state_root" msb-home
}

main() {
    local image tag platform msb_home inspect_json digest base_link

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
    if (($# > 2)); then
        usage >&2
        exit 2
    fi

    image="${1:-agent-vm-template:latest}"
    tag="${2:-$image}"

    if [[ ! -x target/macos/bin/msb ]]; then
        echo "error: target/macos/bin/msb is missing; run './script/build/macos.sh' first" >&2
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
    # `plutil` reads the loaded image's top-level manifest digest out of the
    # msb inspect JSON below (a structured root-key extract, because the JSON
    # also carries a nested config.digest). It is a macOS system binary; fail
    # here with a clear message rather than misreporting its absence later as
    # "could not extract its manifest digest".
    command -v plutil >/dev/null 2>&1 || {
        echo "error: plutil is required to extract the imported image's manifest digest; it ships with macOS" >&2
        exit 1
    }

    platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")" || {
        echo "error: local Docker image '$image' was not found" >&2
        exit 1
    }
    if [[ "$platform" != linux/arm64 ]]; then
        echo "error: local Docker image '$image' must be linux/arm64; found: $platform" >&2
        exit 1
    fi

    msb_home="$(resolve_msb_home)"
    mkdir -p "$msb_home"

    # Shared-cache consistency (agent-vm #84 verification). This load runs with
    # *this* process's environment, but `agent-vm`'s later boot calls
    # `ensure_msb_home`, which — when AGENT_VM_SHARE_MSB_CACHE is enabled —
    # merge-writes msb-home/config.json to point `paths.cache` at the shared
    # ${AGENT_VM_MSB_CACHE_DIR:-$HOME/.microsandbox/cache}. This script does not
    # apply that redirect, so on a *fresh* state dir the blobs land in the
    # private msb-home/cache, the first boot then repoints `paths.cache` at the
    # shared cache, and msb — finding the image in its db but not its layers
    # there — falls through to a registry pull of a local tag and fails with
    # `Not authorized … index.docker.io/...`. Import and boot must agree on the
    # cache: use a state dir whose config.json already matches, or keep
    # AGENT_VM_SHARE_MSB_CACHE consistent across both. See CONTRIBUTING.md's
    # "End-to-end (VM-boot) tests". Follow-up: apply the redirect here.
    echo "==> Importing $image as $tag into agent-vm's private cache"
    docker save "$image" | MSB_HOME="$msb_home" \
        target/macos/bin/msb image load --tag "$tag"

    echo "==> Imported $tag"

    # Link the base into Docker under its msb manifest digest so a project
    # tooling-layer build can resolve step 0's FROM locally (issue #98).
    # Import time is the one moment Docker's source image and msb's cached
    # copy are guaranteed to be the same bytes. The digest is read back
    # structurally with plutil: real inspect output also carries a nested
    # config.digest, so a regex/textual extraction could pick the wrong value
    # (the root manifest digest is the layer-hash anchor).
    inspect_json="$(MSB_HOME="$msb_home" \
        target/macos/bin/msb image inspect --format json "$tag")" || {
        echo "error: imported $tag into msb, but 'msb image inspect' failed; the Docker base link was not created. Rerun to retry." >&2
        exit 1
    }
    digest="$(printf '%s' "$inspect_json" | \
        plutil -extract digest raw -expect string -o - -)" || {
        echo "error: imported $tag into msb, but could not extract its manifest digest from inspect output; the Docker base link was not created. Rerun to retry." >&2
        exit 1
    }
    if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "error: msb reported a malformed manifest digest for $tag ('$digest'); expected sha256:<64 lowercase hex>. The Docker base link was not created." >&2
        exit 1
    fi
    # The Docker-local repository below must match `layer::BASE_REPO` in
    # `crates/agent-vm/src/layer.rs` (a Rust const a shell script can't
    # import); `layer::tests::base_repo_constant_matches_the_import_script_literal`
    # guards the tie. See issue #98's ADR-0003 amendment.
    base_link="agent-vm-base:${digest#sha256:}"
    docker tag "$image" "$base_link" || {
        echo "error: imported $tag into msb, but 'docker tag $image $base_link' failed; the Docker base link is missing. Rerun to retry." >&2
        exit 1
    }
    echo "==> Linked $image into Docker as $base_link (tooling-layer base)"
    printf 'Verify offline with:\n  %q shell --image %q -- uname -m\n' \
        "$REPO_ROOT/target/macos/bin/agent-vm" "$tag"
    echo "Note: msb stages the incoming archive in temporary storage, so keep roughly one archive's worth of disk free."
}

main "$@"
