# Example Dockerfiles that extend a boot image

These directories are worked examples of building a **custom boot image** with
ordinary Docker. Each is a `Dockerfile` that starts `FROM ${BASE_IMAGE}` and
adds tools the default image does not carry — compilers, cross-toolchains,
Chromium, and so on. The explicit `agent-vm build` operation builds and imports one; launches never
build or compose these directories. Select the finished result separately. See
[Selecting the boot image](../../USAGE.md#selecting-the-boot-image) and
[ADR-0035](../../docs/adr/0035-consume-user-owned-boot-images.md).

The directories under `examples/layers/` are examples, not activated by
default. Maintained installers and standard-image sources live in the independent
[image repository](https://github.com/gregwebs/agent-vm-images), which also has a
[tool-free base extension example](https://github.com/gregwebs/agent-vm-images/tree/main/examples/base-extension).
These examples require the Debian-based standard image's apt/Node facilities;
the minimal boot contract alone is insufficient. Their default parent is the
immutable v0.1.3 index, overrideable with `--build-arg BASE_IMAGE=…`.

Build an example and select its finished result:

```sh
agent-vm build --builder native-oci \
  --build-arg BASE_IMAGE=ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de \
  --tag my-image:dev examples/layers/rust-dev
agent-vm shell --image my-image:dev                # or: image = "my-image:dev"
```

Every example needs the two lines below; the `ARG` is what
`--build-arg BASE_IMAGE=…` overrides:

```dockerfile
ARG BASE_IMAGE=ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de
FROM ${BASE_IMAGE}
```

Two conventions: expose environment through `ENV` (agent-vm reads the image's
OCI `ENV`), and leave `ENTRYPOINT`/`CMD` inert — agentd execs the agent
directly. These Debian-based examples are not portable to every minimal boot image.

## Index

| Example | Adds |
|---|---|
| [`wirenboard-cpp`](wirenboard-cpp/) | WB C/C++ build-essentials (debhelper, clang-format/clang-tidy, libcurl/libgtest/libmodbus/libsystemd-dev, cmake/ninja, ...) plus the armhf/arm64 cross toolchains, qemu-user-static, and the sbuild/schroot/debootstrap path. |
| [`rust-dev`](rust-dev/) | The Rust toolchain this repo pins (via `rust-toolchain.toml`, with clippy and rustfmt), the host musl target, the native build libraries `ci.yml` installs, shellcheck, and the pinned Verus release — enough to build, test, lint and verify agent-vm's Rust code in the guest. |
| [`go-dev`](go-dev/) | The pinned Go toolchain (go, gofmt, go vet) plus the two tools a Go project's editor and CI loop expect beyond it, `golangci-lint` and the `gopls` language server — enough to build, test, lint and navigate a Go code base in the guest. |
| [`chrome-devtools`](chrome-devtools/) | Chromium, Chrome DevTools MCP wrapper, scoped NSS CA trust, and the Chrome capability marker. |

## Rust development

`rust-dev` is the layer that lets an in-VM agent iterate on agent-vm's own
Rust code. It installs, all under the world-readable `/opt`:

- the **pinned Rust toolchain** from `rust-toolchain.toml` (`1.98.1` at the
time of writing) with the `clippy` and `rustfmt` components, plus the host
`*-unknown-linux-musl` target the guest `agentd` build needs when building
the vendored `msb` (agent-vm's own gates do not);
- the native libraries `ci.yml` installs — `build-essential`, `pkg-config`,
`libcap-ng-dev`, `libdbus-1-dev` — plus `musl-tools` for that musl target, and
`shellcheck` for `script/test/ci-contracts.sh`;
- the **pinned Verus release** CI verifies with, on `linux/amd64` (see the
Apple Silicon note below).

Build it on top of the default boot image and select it:

```sh
agent-vm build --builder native-oci \
  --build-arg BASE_IMAGE=ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de \
  --tag agent-vm-rust-dev:dev examples/layers/rust-dev
agent-vm claude --image agent-vm-rust-dev:dev
```

Once booted, the guest can run the repo's Rust gates the way CI does. These
gates need no guest `agentd` build first: agent-vm drives an external `msb`,
and only `msb` embeds `agentd`.

```sh
cargo build --release -p agent-vm
cargo test -p agent-vm
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/test/ci-contracts.sh
CARGO_TARGET_DIR=target/verus cargo verus verify --locked -p agent-vm
```

The toolchain lives under `RUSTUP_HOME=/opt/rustup` and the shims under
`/opt/cargo/bin`; both are read-only and shared by every guest uid. `cargo`'s
registry and build cache still land in the guest's own writable
`$HOME/.cargo`, so what the layer shares is only the toolchain. Because
`RUSTUP_HOME` is read-only, `rustup component add` and toolchain installs are
not available in the guest — the layer pre-provisions exactly the pinned
toolchain instead.

### Apple Silicon (no Verus asset)

Upstream publishes Verus for `linux/amd64` and `macos/arm64`, but **not**
`linux/arm64`. On an Apple Silicon host the guest is `linux/arm64`, so the
layer skips Verus; run the host's `arm64-macos` Verus there instead
(`CONTRIBUTING.md` § *Verifying contracts locally*). Everything else in the
layer works on both architectures.

### Keeping the pins in lockstep

The Dockerfile's `ARG RUST_TOOLCHAIN` is checked against
`rust-toolchain.toml`'s canonical channel, and its `ARG VERUS_RELEASE` /
`ARG VERUS_SHA256` against `.github/workflows/verus.yml`, by
`script/check-rust-toolchain.sh` — the same check that enforces the repo's
toolchain copies elsewhere. The checker also refuses a build whose Verus
install script stopped verifying the digest. A pin bump edits the source of
truth, then this directory, then runs the checker.

The layer's build steps are committed as standalone scripts beside the
Dockerfile — `install-rust.sh`, `install-verus.sh` and `verify-toolchain.sh`
— and bind-mounted in at build time, so each can be read, reviewed and run on
its own. They are covered by the CI shell guard in `script/test/ci-contracts.sh`.

## Go development

`go-dev` is the layer that lets an in-VM agent iterate on a Go code base. It
installs, under the world-readable `/opt`:

- the **pinned Go toolchain** from go.dev (`1.27.1` at the time of writing),
  verified against its per-architecture SHA-256 — `go`, `gofmt`, `go vet`,
  `go test`, and the rest of the standard distribution;
- **`build-essential`**, so cgo and `go test -race` work: with no C compiler
  present the Go command silently defaults `CGO_ENABLED=0`, and `-race` then
  fails with "requires cgo";
- the **pinned golangci-lint release** from its GitHub release tarball,
  likewise digest-verified;
- the **pinned `gopls` language server**, compiled from its module at build
  time (upstream ships no binary) with the go command verifying every module
  against the signed `sum.golang.org` checksum database.

Build it on top of the default boot image and select it:

```sh
agent-vm build --builder native-oci \
  --build-arg BASE_IMAGE=ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de \
  --tag agent-vm-go-dev:dev examples/layers/go-dev
agent-vm claude --image agent-vm-go-dev:dev
```

Once booted, the usual Go loop works:

```sh
go version
go build ./...
go test ./...
go test -race ./...
golangci-lint run
gofmt -l .
gopls check main.go      # or just point your editor's LSP at `gopls`
```

The toolchain lives under `/opt/go` and the two extra tools in
`/opt/go-tools/bin`; both are on `PATH` and read-only for every guest uid.
Module downloads and build output stay in the guest's own writable, persistent
home (`$HOME/go/pkg/mod` and `$HOME/.cache/go-build`), so a second launch
reuses them — the layer shares only the toolchain, never a cache.

### `GOTOOLCHAIN=local`, and module downloads

The image sets `GOTOOLCHAIN=local`, so `go` never silently downloads a second
toolchain when a project's `go.mod` asks for a newer one: it fails with a
message naming both versions. Bump `GO_VERSION` (and its two digests) in
the layer's `Dockerfile` and rebuild the layer. To opt out for one command
where the network permits it, run `GOTOOLCHAIN=auto go …`.

Module and checksum downloads need no extra flags: the default network policy
already reaches the public internet, which covers `proxy.golang.org` and
`sum.golang.org`. (`--allow-host` is unrelated — despite the name it opens the
*host's* loopback gateway for reaching a dev server, not a hostname allow
list.) A project that must not depend on the network can `go mod vendor` and
build with `-mod=vendor`.

### Keeping the pins in lockstep

This layer is the *only* place agent-vm pins a Go toolchain, so there is
nothing to cross-check. The version and, for the two prebuilt downloads, the
per-architecture digest are declared together in `Dockerfile`, and each
installer verifies its tarball against that digest, so a bumped version left
beside a stale digest fails the build. `gopls` is pinned by module version and
verified against the signed checksum database.

## Chrome DevTools

Build it on top of the default boot image and select it:

```sh
agent-vm build --builder native-oci \
  --build-arg BASE_IMAGE=ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de \
  --tag agent-vm-chrome:dev examples/layers/chrome-devtools
agent-vm claude --image agent-vm-chrome:dev
```

It installs Chromium and the Chrome DevTools MCP integration; see
[USAGE.md](../../USAGE.md#chrome-devtools-mcp) for the runtime behavior. The
Dockerfile pre-warms the npm cache for root mode only: arbitrary non-root guest
homes remain persistent but download on first use.

### Manual Chrome runtime check

Static capability/wrapper agreement runs in launcher CI, but the former Chrome
runtime workflow is retired. On a native Docker host, build this ordinary
Dockerfile with `docker build -t av-chrome-check examples/layers/chrome-devtools`,
then check the dedicated account, sudo scope and headless browser:

```bash
docker run --rm av-chrome-check bash -c 'set -e; test "$(id -u chrome)" = 9999; visudo -cf /etc/sudoers.d/agent-vm-chrome; sudo -n -u chrome -H -- test -w /home/chrome/.pki/nssdb; sudo -n -u chrome -H -- chromium --headless --disable-gpu --dump-dom about:blank'
```

Also test an arbitrary numeric UID with writable HOME and the wrapper's NSS/CA
handling before changing this example. Docker checks are not VM MCP integration
proof; the custom-image native suite owns the launcher-side capability join.

## Combining examples

To combine two examples, build one `FROM` the other with ordinary Docker (a
multistage or chained `docker build`), or copy the steps you need into one
Dockerfile. There is no launcher-side layering: the finished image is the one
you select.
