# examples/layers/go-dev — Go development toolchain tooling layer.
#
# Install it into a project's chain, or try it directly, to build, test, lint
# and navigate a Go code base inside the microVM:
#
#   cp -r examples/layers/go-dev .agent-vm/layers/10-go-dev
#   agent-vm claude --yes
#   # or, without copying:
#   agent-vm shell --layer examples/layers/go-dev --yes
#
# It provides the pinned Go toolchain (go, gofmt, go vet, ...) plus the two
# tools a Go project's edit/CI loop expects beyond it: golangci-lint and the
# gopls language server. See examples/layers/README.md and
# docs/adr/0003-project-tooling-layers.md.
#
# The four steps that need real shell live as standalone, independently
# runnable scripts beside this file and are bind-mounted in at build time:
# install-go.sh, install-golangci-lint.sh, install-gopls.sh and
# verify-toolchain.sh. This file only wires the pins and locations into them.
#
# Layer image contract: C1 is the two lines below; C2 is satisfied because
# every ENV writes PATH=<new>:${PATH}; C3 by staying root; C7 by installing
# under world-readable /opt rather than a mode-0700 home.

ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest
FROM ${BASE_IMAGE}

# A C toolchain, for the two things the Go distribution itself defers to the
# host: cgo (a project that imports "C", or a dependency that does) and
# `go test -race`, which the Go command refuses to run without cgo. With no
# gcc present Go silently defaults CGO_ENABLED=0, and the failure only
# surfaces deep into a test run as "-race requires cgo; enable cgo by setting
# CGO_ENABLED=1". rust-dev installs the same package for its native build
# dependencies.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

# Pins. There is no second copy of these in the repo (this layer is the only
# place agent-vm pins a Go toolchain), so the pin and its verification sitting
# together is the whole lockstep rule: install-go.sh and
# install-golangci-lint.sh each check their prebuilt tarball against the digest
# declared here, so a bumped version left beside a stale digest fails the build
# instead of shipping a different tool. gopls has no tarball to digest;
# install-gopls.sh pins its module version and the go command verifies it
# against the checksum database. Bump a version and its digests together.
ARG GO_VERSION=1.27.1
ARG GO_AMD64_SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
ARG GO_ARM64_SHA256=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
ARG GOLANGCI_LINT_VERSION=2.13.2
ARG GOLANGCI_LINT_AMD64_SHA256=2277d43b98ec0054280f2ac26b53268bae97682444678a59a657dd565da021d6
ARG GOLANGCI_LINT_ARM64_SHA256=a2a4e0065aa41be71f7c5ac90f271b61751331e5d04314e62afe4027855f0893
ARG GOPLS_VERSION=v0.23.0

# Where the toolchain and the two extra tools live. Both are under /opt so the
# arbitrary-uid guest (ADR-0001) can read them. GOROOT is deliberately *not*
# exported: /opt/go/bin/go locates its own root, and leaving the variable
# unset keeps a project-level `toolchain` directive from colliding with it.
ARG GO_PREFIX=/opt/go
ARG GO_TOOLS_BIN=/opt/go-tools/bin

RUN --mount=type=bind,source=install-go.sh,target=/tmp/install-go.sh,ro \
    bash /tmp/install-go.sh

RUN --mount=type=bind,source=install-golangci-lint.sh,target=/tmp/install-golangci-lint.sh,ro \
    bash /tmp/install-golangci-lint.sh

RUN --mount=type=bind,source=install-gopls.sh,target=/tmp/install-gopls.sh,ro \
    bash /tmp/install-gopls.sh

# PATH stays additive (contract C2): the base's entries are preserved via
# ${PATH}. GOTOOLCHAIN=local makes the layer's pin the toolchain that actually
# runs: by default `go` would silently download a *different* toolchain
# through the module proxy whenever a go.mod asks for a newer one, which both
# defeats the pin and fails confusingly under the guest's network allow list.
# The error for an out-of-range go.mod names both versions, so the fix (bump
# GO_VERSION here and rebuild the layer) is discoverable. See the README.
ENV PATH=${GO_PREFIX}/bin:${GO_TOOLS_BIN}:${PATH}
ENV GOTOOLCHAIN=local

# Post-install sanity: every tool is invoked directly, and the Go, lint and
# language-server checks analyse a real module built from scratch, so a
# present-but-broken binary fails the build here instead of surfacing as
# command-not-found in the guest.
RUN --mount=type=bind,source=verify-toolchain.sh,target=/tmp/verify-toolchain.sh,ro \
    bash /tmp/verify-toolchain.sh
