#!/usr/bin/env bash
# Post-install sanity for the go-dev tooling layer. Runs both standalone and
# from examples/layers/go-dev/Dockerfile.
#
# It invokes every tool as the guest PATH resolves it (bare name, not an
# absolute path), so a tool missing from the Dockerfile's ENV PATH fails the
# build here rather than surfacing as command-not-found in the guest. Beyond
# the versions, each tool analyses a real throwaway module: `go` builds, vets
# and race-tests it (the race run is also what proves the C toolchain is
# usable, since `-race` needs cgo), `gofmt` must report it formatted,
# `golangci-lint` lints it, and `gopls check` reports its diagnostics. A binary
# that prints a version but cannot analyse code -- a truncated download, a
# missing shared library, a module-cache misconfiguration -- fails the build.
#
# HOME/GOCACHE/GOPATH point at a temporary tree so the smoke module's build
# cache is not baked into the image (the guest gets its own, under its own
# persistent home).
#
# Environment:
#   GO_VERSION              required; the exact channel the layer installed
#   GOLANGCI_LINT_VERSION   required; the release the layer installed
#   GOPLS_VERSION           required; the module version the layer installed
set -euo pipefail

: "${GO_VERSION:?GO_VERSION must be set to the pinned toolchain}"
: "${GOLANGCI_LINT_VERSION:?GOLANGCI_LINT_VERSION must be set to the pinned release}"
: "${GOPLS_VERSION:?GOPLS_VERSION must be set to the pinned module version}"

test "$(go version | cut -d' ' -f3)" = "go${GO_VERSION}"

# Each tool's output is captured before it is matched, never piped into
# `grep -q`: grep exits at the first match, the tool's remaining writes get
# SIGPIPE, and `pipefail` would turn that into a failed build -- a false
# failure whose rate depends only on how much the tool prints (gofmt's help is
# long enough to hit it reliably).
gofmt_help="$(gofmt -h 2>&1 || true)"
grep -q 'usage: gofmt' <<<"$gofmt_help"
golangci_lint_version="$(golangci-lint version)"
grep -q "golangci-lint has version ${GOLANGCI_LINT_VERSION} " <<<"$golangci_lint_version"
gopls_version="$(gopls version)"
grep -q "gopls ${GOPLS_VERSION}" <<<"$gopls_version"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

export HOME="$work/home"
export GOCACHE="$work/go-build"
export GOPATH="$work/gopath"
mkdir -p "$HOME"

cat > "$work/go.mod" <<EOF
module agent-vm-go-dev-smoke

go ${GO_VERSION}
EOF

cat > "$work/main.go" <<'GO'
package main

import "fmt"

func greeting() string { return "go-dev layer smoke OK" }

func main() {
	fmt.Println(greeting())
}
GO

cat > "$work/main_test.go" <<'GO'
package main

import "testing"

func TestGreeting(t *testing.T) {
	if got := greeting(); got != "go-dev layer smoke OK" {
		t.Fatalf("greeting() = %q", got)
	}
}
GO

(
    cd "$work"
    go vet ./...
    go run .
    # `-race` needs cgo, so this also proves the C toolchain is present and
    # usable rather than silently defaulted off with CGO_ENABLED=0.
    go test -race ./...
    test -z "$(gofmt -l .)"
    golangci-lint run
    # `gopls check` exits non-zero only on reported diagnostics, so a clean
    # file proves the language server started and loaded the module.
    gopls check ./main.go
)

echo "== go-dev layer sanity OK =="
