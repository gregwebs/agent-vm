#!/usr/bin/env bash
# Install the pinned gopls (the Go language server) with `go install`. Runs
# both standalone (as root on a Debian/Ubuntu host with the Go toolchain
# installed) and from examples/layers/go-dev/Dockerfile, which passes the pin
# and the install locations as build args.
#
# Environment:
#   GOPLS_VERSION  required; the module version (e.g. v0.23.0)
#   GO_PREFIX      default /opt/go
#   GO_TOOLS_BIN   default /opt/go-tools/bin
#
# Integrity: upstream publishes no gopls binary, so it is compiled from its
# module source. `go install pkg@version` resolves that exact version and the
# go command verifies every downloaded module zip against sum.golang.org's
# signed checksum database (GOSUMDB is pinned explicitly rather than inherited
# from the environment); that is the Go ecosystem's signature check for a
# module at a version, so there is no separate digest to pin beyond the
# version itself. GOTOOLCHAIN=local keeps the layer's toolchain the compiler
# instead of letting a gopls go.mod pull another one.
#
# The module and build caches are a temporary tree removed with the script:
# only the compiled binary belongs in the image, and a Go build cache is
# hundreds of megabytes. `-trimpath` keeps build-host paths out of the binary.
set -euo pipefail

: "${GOPLS_VERSION:?GOPLS_VERSION must be set to the pinned module version (e.g. v0.23.0)}"
GO_PREFIX="${GO_PREFIX:-/opt/go}"
GO_TOOLS_BIN="${GO_TOOLS_BIN:-/opt/go-tools/bin}"

build_home="$(mktemp -d)"
trap 'rm -rf "$build_home"' EXIT

echo "==> install-gopls: gopls@${GOPLS_VERSION} into $GO_TOOLS_BIN"
mkdir -p "$GO_TOOLS_BIN"
env \
    HOME="$build_home" \
    GOCACHE="$build_home/go-build" \
    GOPATH="$build_home/gopath" \
    GOBIN="$GO_TOOLS_BIN" \
    GOSUMDB=sum.golang.org \
    GOTOOLCHAIN=local \
    "$GO_PREFIX/bin/go" install -trimpath "golang.org/x/tools/gopls@${GOPLS_VERSION}"

chmod -R a+rX "$GO_TOOLS_BIN"
echo "==> install-gopls: done"
