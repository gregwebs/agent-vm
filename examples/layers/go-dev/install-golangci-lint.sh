#!/usr/bin/env bash
# Install the pinned golangci-lint release from its GitHub release tarball,
# verifying the per-architecture SHA-256 before extracting. Runs both
# standalone (as root on a Debian/Ubuntu host) and from
# examples/layers/go-dev/Dockerfile, which passes the pin, the digests and the
# install directory as build args.
#
# Environment:
#   GOLANGCI_LINT_VERSION        required; the release tag without "v" (e.g. 2.13.2)
#   GOLANGCI_LINT_AMD64_SHA256   required on amd64
#   GOLANGCI_LINT_ARM64_SHA256   required on arm64
#   GO_TOOLS_BIN                 default /opt/go-tools/bin
#
# The install is world-readable (contract C7): the guest may run as an
# arbitrary non-root uid.
set -euo pipefail

: "${GOLANGCI_LINT_VERSION:?GOLANGCI_LINT_VERSION must be set to the pinned release (e.g. 2.13.2)}"
GO_TOOLS_BIN="${GO_TOOLS_BIN:-/opt/go-tools/bin}"

arch="$(dpkg --print-architecture)"
case "$arch" in
    amd64) checksum="${GOLANGCI_LINT_AMD64_SHA256:?GOLANGCI_LINT_AMD64_SHA256 must be set on amd64}" ;;
    arm64) checksum="${GOLANGCI_LINT_ARM64_SHA256:?GOLANGCI_LINT_ARM64_SHA256 must be set on arm64}" ;;
    *)
        echo "install-golangci-lint: unexpected architecture: $arch" >&2
        exit 1
        ;;
esac

asset="golangci-lint-${GOLANGCI_LINT_VERSION}-linux-${arch}.tar.gz"
archive="/tmp/${asset}"
unpacked="/tmp/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-${arch}"
trap 'rm -f "$archive"; rm -rf "$unpacked"' EXIT

echo "==> install-golangci-lint: ${GOLANGCI_LINT_VERSION} into $GO_TOOLS_BIN"
curl -fSL --retry 3 -o "$archive" \
    "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/${asset}"
echo "${checksum}  ${archive}" | sha256sum -c -

tar -xzf "$archive" -C /tmp
mkdir -p "$GO_TOOLS_BIN"
install -m 0755 "${unpacked}/golangci-lint" "${GO_TOOLS_BIN}/golangci-lint"

chmod -R a+rX "$GO_TOOLS_BIN"
echo "==> install-golangci-lint: done"
