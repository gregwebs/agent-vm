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
    local image tag platform msb_home

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

    echo "==> Importing $image as $tag into agent-vm's private cache"
    docker save "$image" | MSB_HOME="$msb_home" \
        target/macos/bin/msb image load --tag "$tag"

    echo "==> Imported $tag"
    printf 'Verify offline with:\n  %q shell --image %q -- uname -m\n' \
        "$REPO_ROOT/target/macos/bin/agent-vm" "$tag"
    echo "Note: msb stages the incoming archive in temporary storage, so keep roughly one archive's worth of disk free."
}

main "$@"
