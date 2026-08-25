#!/usr/bin/env bash
# Import a local Docker image into agent-vm's private microsandbox cache.
# Usage: ./script/build/import-image.sh [SOURCE_IMAGE [DESTINATION_TAG]]

set -euo pipefail
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

main() {
    local image tag platform

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

    if [[ ! -x target/macos/bin/agent-vm ]]; then
        echo "error: target/macos/bin/agent-vm is missing; run './script/build/macos.sh' first" >&2
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

    echo "==> Importing $image as $tag into agent-vm's private cache"
    docker save "$image" | target/macos/bin/agent-vm msb image load --tag "$tag"

    echo "==> Imported $tag"
    printf 'Verify offline with:\n  %q shell --image %q -- uname -m\n' \
        "$REPO_ROOT/target/macos/bin/agent-vm" "$tag"
    echo "Note: msb stages the incoming archive in temporary storage, so keep roughly one archive's worth of disk free."
}

main "$@"
