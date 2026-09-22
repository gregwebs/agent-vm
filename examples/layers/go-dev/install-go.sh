#!/usr/bin/env bash
# Install the pinned Go toolchain from go.dev, verifying the per-architecture
# SHA-256 before extracting. Runs both standalone (as root on a Debian/Ubuntu
# host) and from examples/layers/go-dev/Dockerfile, which passes the pin, the
# per-architecture digests and the install prefix as build args.
#
# Environment:
#   GO_VERSION       required; the exact release without the "go" prefix (e.g. 1.27.1)
#   GO_AMD64_SHA256  required on amd64; sha256 of go<version>.linux-amd64.tar.gz
#   GO_ARM64_SHA256  required on arm64; sha256 of go<version>.linux-arm64.tar.gz
#   GO_PREFIX        default /opt/go
#
# The install is world-readable (contract C7): the guest may run as an
# arbitrary non-root uid. GOROOT is not set here or exported by the Dockerfile:
# the toolchain's own layout is self-locating, and unsetting it keeps a
# project-level `toolchain` directive from colliding with the environment.
set -euo pipefail

: "${GO_VERSION:?GO_VERSION must be set to the pinned release (e.g. 1.27.1)}"
GO_PREFIX="${GO_PREFIX:-/opt/go}"

arch="$(dpkg --print-architecture)"
case "$arch" in
    amd64) checksum="${GO_AMD64_SHA256:?GO_AMD64_SHA256 must be set on amd64}" ;;
    arm64) checksum="${GO_ARM64_SHA256:?GO_ARM64_SHA256 must be set on arm64}" ;;
    *)
        echo "install-go: unexpected architecture: $arch" >&2
        exit 1
        ;;
esac

asset="go${GO_VERSION}.linux-${arch}.tar.gz"
# mktemp, not a fixed /tmp path: a predictable name in a world-writable
# directory is a pre-planted symlink waiting for curl -o to follow it, and it
# also lets two builds share a host without colliding.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
archive="$work/$asset"

echo "==> install-go: go${GO_VERSION} into $GO_PREFIX"
curl -fSL --retry 3 -o "$archive" "https://go.dev/dl/${asset}"
echo "${checksum}  ${archive}" | sha256sum -c -

# The archive's single top-level directory is named `go`, so extracting it
# under the prefix's parent both creates $GO_PREFIX and makes $GO_PREFIX/bin/go
# resolve its own root without GOROOT being set.
parent="$(dirname "$GO_PREFIX")"
mkdir -p "$parent"
tar -C "$parent" -xzf "$archive"

chmod -R a+rX "$GO_PREFIX"
echo "==> install-go: done"
