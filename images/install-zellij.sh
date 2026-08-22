#!/usr/bin/env bash
# The musl release asset remains usable across Debian base-library changes.
# Hashes are for the distributed archive (not upstream's extracted-binary
# sidecars), so an unavailable download may be soft-failed for development
# hosts while an integrity mismatch must always stop the image build.

set -euo pipefail

require_env() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        echo "==> zellij: $name is required" >&2
        exit 1
    fi
}

require_env ZELLIJ_VERSION
require_env ZELLIJ_SHA256_AMD64
require_env ZELLIJ_SHA256_ARM64

install_path="${ZELLIJ_INSTALL_PATH:-/usr/local/bin/zellij}"
soft_fail="${AGENT_INSTALL_SOFT_FAIL:-}"
arch="$(dpkg --print-architecture)"
case "$arch" in
    amd64)
        target=x86_64-unknown-linux-musl
        sum="$ZELLIJ_SHA256_AMD64"
        ;;
    arm64)
        target=aarch64-unknown-linux-musl
        sum="$ZELLIJ_SHA256_ARM64"
        ;;
    *)
        echo "==> zellij: no upstream release asset for dpkg arch '$arch'" >&2
        exit 1
        ;;
esac

url="https://github.com/zellij-org/zellij/releases/download/v${ZELLIJ_VERSION}/zellij-${target}.tar.gz"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/zellij.XXXXXX")"
cleanup() {
    local status=$?
    rm -rf "$temporary_directory"
    return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

archive="$temporary_directory/z.tar.gz"
if ! curl -fsSL --retry 5 --retry-all-errors --http1.1 "$url" -o "$archive"; then
    message="==> zellij DOWNLOAD FAILED (${url}) — install in-VM with: curl -fsSL ${url} | tar -xz -C /usr/local/bin"
    if [[ -n "$soft_fail" ]]; then
        echo "$message (soft-fail mode; image will ship without zellij)"
        exit 0
    fi
    echo "$message" >&2
    exit 1
fi

if ! echo "${sum}  $archive" | sha256sum --status -c -; then
    echo "==> zellij: sha256 MISMATCH for ${url} (expected ${sum}) — refusing to install" >&2
    exit 1
fi

tar -xzf "$archive" -C "$temporary_directory"
binary="$(find "$temporary_directory" -type f -name zellij -print -quit)"
if [[ -z "$binary" ]]; then
    echo "==> zellij: no 'zellij' binary inside ${url}" >&2
    exit 1
fi

install -m 0755 "$binary" "$install_path"
"$install_path" --version
