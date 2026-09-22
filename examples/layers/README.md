# Example tooling layers

A **tooling layer** is a project-owned `Dockerfile` (plus its build context)
that adds project-specific tools on top of the previous step in the
project's **layer chain** — compilers, cross-toolchains, anything the base
doesn't carry. A project's chain lives under `.agent-vm/layers/`, one
numbered subdirectory per step, built in order. See
`docs/adr/0003-project-tooling-layers.md` and the "Tooling layer" / "Layer
chain" / "Derived image" entries in `CONTEXT.md` for the full mechanism.

The directories under `examples/layers/` are worked examples, not activated
by default. The five shipped tool layers under `images/tools/`
(`pi`, `codex`, `opencode`, `claude`, `copilot`) are the repo's other worked examples —
and the ones agent-vm composes first: a launch's chain is the catalog's tool
layers, then the project's own `.agent-vm/layers/*` steps, then `--layer` flags,
so a project layer always builds on top of them. Copy one into place as a
numbered step to use it every time:

```sh
cp -r examples/layers/wirenboard-cpp .agent-vm/layers/10-wirenboard-cpp
```

Or try one without copying it, via the repeatable `--layer DIR` flag — it
appends after whatever the project already declares under
`.agent-vm/layers/` (or forms the whole chain by itself, if the project
declares none):

```sh
agent-vm shell --layer examples/layers/wirenboard-cpp --yes
```

`--layer` can be given more than once, and combines with the project's own
`.agent-vm/layers/*` steps rather than replacing them — see "Composing
several layers" below. There is deliberately no environment variable for it
(`$AGENT_VM_LAYER` is rejected outright if set).

The first launch after a chain is declared (or a step is edited) prompts to
build it: `Build project tooling layer '<tag>'? [y/N]` for a single-step
chain, or a multi-line prompt listing every step for a longer one. Pass
`--yes` (or set `AGENT_VM_YES=1`) for non-interactive/CI use. A later launch
with an unchanged chain reuses the already-built derived image with no
rebuild and no prompt.

## Writing your own layer

The **layer image contract** is normative in
`docs/adr/0003-project-tooling-layers.md` ("The layer image contract"). Every
step needs these two lines:

```dockerfile
ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest
FROM ${BASE_IMAGE}
```

Four clauses are **enforced at build time** (a violation is a hard error):
C1 build on the previous step; C2 keep `PATH` additive (never drop a
directory the previous step had); C3 end the chain's last step as root
(`USER root`, or no trailing `USER` at all); C4 don't pin `--platform` on
your final `FROM`.

C5–C8 are documented-only — see the ADR for all eight. Keep `/bin/bash` and
`/etc/passwd`/`/etc/group` appendable, install tools world-readable (`a+rX`),
don't touch `/etc/agent-vm-image-version` or `/opt/agent/**`, and write
`/etc/agent-vm-capabilities/<name>` only after your own build-time checks
pass. Two conventions: expose environment through `ENV` (not an `env.d`-style
file the base does not read), and leave `ENTRYPOINT`/`CMD` inert — agentd
execs the agent directly. Every shipped example satisfies all eight; the C1
lint half is kept true by
`layer::contract::tests::shipped_example_layers_pass_the_dockerfile_lint`.

## Index

| Example | Adds |
|---|---|
| [`wirenboard-cpp`](wirenboard-cpp/) | WB C/C++ build-essentials (debhelper, clang-format/clang-tidy, libcurl/libgtest/libmodbus/libsystemd-dev, cmake/ninja, ...) plus the armhf/arm64 cross toolchains, qemu-user-static, and the sbuild/schroot/debootstrap path. |
| [`rust-dev`](rust-dev/) | The Rust toolchain this repo pins (via `rust-toolchain.toml`, with clippy and rustfmt), the host musl target, the native build libraries `ci.yml` installs, shellcheck, and the pinned Verus release — enough to build, test, lint and verify agent-vm's Rust code in the guest. |
| [`go-dev`](go-dev/) | The pinned Go toolchain (go, gofmt, go vet) plus the two tools a Go project's editor and CI loop expect beyond it, `golangci-lint` and the `gopls` language server — enough to build, test, lint and navigate a Go code base in the guest. |
| [`chrome-devtools`](chrome-devtools/) | Chromium, Chrome DevTools MCP wrapper, scoped NSS CA trust, and the Chrome capability marker. |

## Rust development

`rust-dev` is the layer that lets an in-VM agent iterate on agent-vm's own
Rust code. It installs, all under the world-readable `/opt` (contract C7):

- the **pinned Rust toolchain** from `rust-toolchain.toml` (`1.98.1` at the
time of writing) with the `clippy` and `rustfmt` components, plus the host
`*-unknown-linux-musl` target the guest `agentd` cross-build needs;
- the native libraries `ci.yml` installs — `build-essential`, `pkg-config`,
`libcap-ng-dev`, `libdbus-1-dev`, `musl-tools` — and `shellcheck` for
`script/test/ci-contracts.sh`;
- the **pinned Verus release** CI verifies with, on `linux/amd64` (see the
Apple Silicon note below).

Copy it into a numbered step and launch, or try it first without copying:

```sh
cp -r examples/layers/rust-dev .agent-vm/layers/10-rust-dev
agent-vm claude --yes
# or:
agent-vm shell --layer examples/layers/rust-dev --yes
```

Once booted, the guest can run the repo's Rust gates the way CI does. The
guest `agentd` has to be built first — the microsandbox SDK's build script
embeds it, and a host (macOS) copy is not a Linux binary:

```sh
# Build the guest agentd the SDK embeds. The musl target is derived from the
# active host triple, so this works on x86_64 and aarch64 alike:
musl="$(rustc -vV | sed -n 's/^host: \(.*\)-unknown-linux-gnu$/\1/p')-unknown-linux-musl"
cargo build --release \
  --manifest-path vendor/microsandbox/crates/agentd/Cargo.toml \
  --target-dir vendor/microsandbox/target \
  --target "$musl"
mkdir -p vendor/microsandbox/build
cp "vendor/microsandbox/target/$musl/release/agentd" \
   vendor/microsandbox/build/agentd
touch vendor/microsandbox/build/agentd

# Then the workspace gates:
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
installs, under the world-readable `/opt` (contract C7):

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

Copy it into a numbered step and launch, or try it first without copying:

```sh
cp -r examples/layers/go-dev .agent-vm/layers/10-go-dev
agent-vm claude --yes
# or:
agent-vm shell --layer examples/layers/go-dev --yes
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

### `GOTOOLCHAIN=local`, and the module proxy

The image sets `GOTOOLCHAIN=local`, so `go` never silently downloads a second
toolchain when a project's `go.mod` asks for a newer one: it fails with a
message naming both versions. Bump `GO_VERSION` (and its two digests) in
the layer's `Dockerfile` and rebuild the layer. To opt out for one command
where the guest's allow list permits it, run `GOTOOLCHAIN=auto go …`.

Resolving modules needs the guest network allow list to include the Go module
proxy and checksum database:

```sh
agent-vm claude \
  --allow-host proxy.golang.org \
  --allow-host sum.golang.org \
  --allow-host storage.googleapis.com \
  --yes
```

(`storage.googleapis.com` is where `proxy.golang.org` redirects module
blobs.) Add the source host too when a module is fetched directly —
`--allow-host github.com`, for example, for `GOPROXY=direct` or a private
module. The layer *build* itself runs with unrestricted network access; the
allow list governs only what the guest does at runtime.

### Keeping the pins in lockstep

Unlike `rust-dev`'s toolchain pin — which is checked against
`rust-toolchain.toml` and `verus.yml` by `script/check-rust-toolchain.sh`
because those are the repo's elsewhere sources of truth — this layer is the
*only* place agent-vm pins a Go toolchain, so there is nothing to
cross-check. Instead each `install-*.sh` script verifies its download against
the digest declared beside the version in `Dockerfile`, so a bumped version
left beside a stale digest fails the build rather than shipping.

## Chrome DevTools

Copy `examples/layers/chrome-devtools` to `.agent-vm/layers/10-chrome-devtools`
(or any numbered step) and run `agent-vm claude --yes` — or skip the copy and
try it directly: `agent-vm claude --layer examples/layers/chrome-devtools
--yes`. It installs Chromium and the Chrome DevTools MCP integration. Root
guests use the dedicated `chrome` account; non-root guests run Chromium as
their guest user. The layer pre-warms the npm cache for root mode only:
arbitrary non-root guest homes remain persistent but download on first use.

## Composing several layers

A chain can combine `chrome-devtools` with a project's own toolchain — the
motivating case for the chain in the first place — two ways, which also
combine with each other:

**Both as project steps.** Copy both examples into numbered steps, choosing
the order that matches what each depends on (neither of these two depends on
the other, so either order works):

```sh
cp -r examples/layers/wirenboard-cpp   .agent-vm/layers/10-wirenboard-cpp
cp -r examples/layers/chrome-devtools  .agent-vm/layers/20-chrome-devtools
```

The `NN-` numbering is what fixes the build order — steps are sorted
byte-lexicographically by directory name, so `10-` always builds before
`20-`. Number with gaps (`10`, `20`, `30`, ...) so a step can be inserted
later without renaming its neighbors. Each step's `Dockerfile` must still
start `ARG BASE_IMAGE=...` / `FROM ${BASE_IMAGE}` — the launcher rewrites
`BASE_IMAGE` per step (the base image for the first step, the previous
step's built image for every step after it), so a step's own Dockerfile
never names a fixed base or its neighbors directly.

**Project steps plus `--layer`.** A project's own `.agent-vm/layers/*` steps
build first, in the usual sorted order; every `--layer DIR` given on the
command line is appended after them, in the order given:

```sh
agent-vm claude \
  --layer examples/layers/wirenboard-cpp \
  --layer examples/layers/chrome-devtools \
  --yes
```

`--layer` only ever appends — it can't reorder or replace a project's own
steps, which is why project steps keep their cached images whether or not
any `--layer` is passed on a given launch.
