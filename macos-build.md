# Building `agent-vm` on macOS

These instructions support Apple Silicon Macs (`arm64`, M1 or newer). Intel macOS is not supported.

## Prerequisites

Install the Xcode Command Line Tools, rustup with the known-good Rust 1.98.1 toolchain, and Docker Desktop. Docker is required to compile the guest agent, not for installed default launches; Apple's `container` CLI is additionally supported for the firmware kernel bundle:

```bash
xcode-select --install
brew install rustup
brew install --cask docker
rustup-init -y
source "$HOME/.cargo/env"
rustup toolchain install 1.98.1
```

Start Docker Desktop, initialize the recursive submodules, and check the exact toolchain used by the build:

```bash
docker info
git submodule update --init --recursive vendor/microsandbox
RUSTUP_AUTO_INSTALL=0 rustup run 1.98.1 rustc --version
RUSTUP_AUTO_INSTALL=0 rustup run 1.98.1 cargo --version
```

The guarded checks do not download a missing toolchain. The canonical build selects installed Rust 1.98.1 locally through rustup; it neither depends on nor changes your global default toolchain.

The vendored build compiles the Linux guest helper through Docker. Its firmware helper accepts `LIBKRUNFW_BUILD_BACKEND=auto|container|docker`: `auto` prefers Apple's `container` CLI, then Docker. Both backends upload a filtered source snapshot to container-native `/work`, build there, and copy only `kernel.c` back. Keep enough container and temporary disk space for those outputs and for one staged Docker image archive during local image import. The helper inherits runtime DNS by default; if Apple's Container runtime cannot resolve Fedora mirrors, explicitly provide the resolver chosen for your network, for example `LIBKRUNFW_BUILD_BACKEND=container LIBKRUNFW_BUILD_DNS=1.1.1.1 ./script/build/macos.sh`. It never selects a public resolver itself; the override accepts one IPv4 address and applies only to the firmware builder.

## Build the macOS bundle

From the repository root, run the canonical build command:

```bash
./script/build/macos.sh
```

The script checks the host, the pinned Rust compiler and Cargo, Xcode tools, Docker, and submodules; builds the vendored signed runtime and release `agent-vm`; and verifies each artifact's architecture, code signature, and Hypervisor.framework entitlements. It assembles:

```text
target/macos/
├── bin/
│   ├── agent-vm
│   └── msb
└── lib/
    └── libkrunfw.5.dylib
```

Re-running `./script/build/macos.sh` is safe. It retains Cargo and Docker incremental output and atomically replaces the verified bundle files without requiring manual copying, signing, or environment setup. Firmware reuse also requires a clean recursive checkout, a validated dylib, and a matching `vendor/microsandbox/build/libkrunfw.5.dylib.source-sha` value for the nested firmware gitlink; a missing, stale, dirty, invalid, or force-rebuild (`MSB_FORCE_FIRMWARE_REBUILD=1`) case rebuilds into staged files and publishes the dylib before its matching stamp. The stamp guards this local cache only; it is not release provenance. The macOS workflow does not require `just`.

## Fast development build

`./script/build/macos.sh` always builds `agent-vm` and `msb` with cargo's
`release` profile (this project's `[profile.release]` sets `codegen-units =
16` and `lto = "thin"`), which is the right tradeoff for a bundle you'll
actually run VMs from, but it makes the inner edit/build/run loop slow while
iterating on `agent-vm`'s Rust source. For that loop, add `--dev`:

```bash
./script/build/macos.sh --dev
```

This builds `agent-vm` and `msb` with cargo's unoptimized `debug` profile
instead of `--release`, then verifies and publishes the pair the same way as
the default build (arch check, code signature, and the
`com.apple.security.hypervisor` / `com.apple.security.cs.disable-library-validation`
entitlements) to a **separate** bundle directory, `target/macos-dev/`, so it
never overwrites your verified `target/macos/` release bundle:

```text
target/macos-dev/
├── bin/
│   ├── agent-vm
│   └── msb
└── lib/
    └── libkrunfw.5.dylib
```

Run it directly, the same way you'd run the release bundle:

```bash
./target/macos-dev/bin/agent-vm shell --no-git -- uname -m
```

The Docker-built `agentd` and container-built firmware outputs are unaffected
by `--dev` and are cached exactly as in the default build (see the note below
on re-running the build), so after the first `--dev` build, editing
`crates/agent-vm/src/**` and re-running `--dev` only pays for an incremental
debug-profile `cargo build`, not a fresh dependency build or a release-profile
compile.

The dev bundle is for local iteration only: it is unstripped, unoptimized,
and meaningfully larger and slower at runtime than the release bundle.
Never ship or benchmark from `target/macos-dev/`; use the default
`./script/build/macos.sh` (no `--dev`) for that.

## Import and boot a local image without a registry

Build or identify a finished native `linux/arm64` image using your Dockerfile.
For maintained base/standard source builds, follow the independent
[image repository](https://github.com/gregwebs/agent-vm-images). Optionally initialize
its contributor pin with `git submodule update --init vendor/agent-vm-images`;
Cargo and macOS runtime builds require only `vendor/microsandbox`.

### Building a standard/custom image locally

Source rebuilds are image-authoring operations and need not equal the published
digest. Once your build produces `my-image:dev`, import and select it explicitly:

```bash
docker image save --output image.tar my-image:dev &&
  ./target/macos-dev/bin/agent-vm msb image load --input image.tar --tag my-image:dev
./target/macos-dev/bin/agent-vm shell --no-git --image my-image:dev -- uname -m
```

Or explicitly build/import a user Dockerfile with an OCI-capable builder:

```bash
./target/macos-dev/bin/agent-vm build --tag my-image:dev --builder native-oci .
./target/macos-dev/bin/agent-vm shell --image my-image:dev -- my-program
```

See [Explicit builds and archive import](USAGE.md#explicit-builds-and-archive-import)
for driver/local-FROM restrictions, disk space and host-build trust. Cache references
are exact: importing `my-image:dev` does not populate a registry-qualified ref.
The guest should print `aarch64` and stop cleanly. `setup` is not a local-cache
check: it deliberately pulls its selected image with `PullPolicy::Always`.

## Verify the registry-backed workflow

Run the registry-backed setup from a normal macOS Terminal, not through `sudo` or a sandbox wrapper:

```bash
./target/macos/bin/agent-vm setup
```

A restrictive coding-agent Seatbelt profile can deny access to `com.apple.trustd.agent`, causing certificate verification to fail with `OSStatus -26276` even when the registry is reachable. Do not report registry-backed setup as successful unless it was observed from a normal Terminal.

## Troubleshooting and low-level reference

### Inspect the bundle

The build script performs these checks automatically. To inspect them independently:

```bash
file \
  target/macos/bin/agent-vm \
  target/macos/bin/msb \
  target/macos/lib/libkrunfw.5.dylib

lipo -archs target/macos/bin/agent-vm
lipo -archs target/macos/bin/msb
lipo -archs target/macos/lib/libkrunfw.5.dylib

codesign --verify --strict target/macos/bin/msb
codesign -d --entitlements - --xml target/macos/bin/msb | plutil -p -
```

All three `lipo` commands must print only `arm64`. The entitlements must include boolean `true` values for `com.apple.security.hypervisor` and `com.apple.security.cs.disable-library-validation`.

Without `--xml`, newer `codesign` versions may print a human-oriented raw `[Dict]` representation that `plutil` cannot parse. The root build script extracts XML to a file before validating the entitlements.

### VM creation fails with `VmSetup(VmCreate)`

This usually means macOS denied `hv_vm_create` because the running `msb` lacks
the Hypervisor.framework entitlement. Cargo's raw
`vendor/microsandbox/target/release/msb` is not a runnable source artifact on
macOS. The supported runtime binary is `vendor/microsandbox/build/msb`,
produced and signed as part of:

```bash
./script/build/macos.sh
```

The script verifies the signature and both required entitlements before
publishing the bundle. Run runtime smoke tests from a normal Terminal without
`sudo` or a sandbox wrapper.

### Boot fails with `Not authorized` against `index.docker.io`

```text
Error: creating sandbox
Caused by:
    image error: registry error: Not authorized: url https://index.docker.io/v2/library/my-image/manifests/dev
```

This is **not** a registry-credentials problem, and there is nothing to log in
to. `index.docker.io/v2/library/...` means the requested reference was
**unqualified**, so `msb` resolved it against Docker Hub instead of GHCR — where
no image of that name exists, so the lookup is reported as unauthorized. Check
both `--image` and the `AGENT_VM_IMAGE_TAG` environment variable: a value
exported from a shell profile acts as `--image` whenever no flag is passed, so
it can silently select the wrong reference. (An explicit `--image` still wins
over `AGENT_VM_IMAGE_TAG` — see `USAGE.md`.)

- an unqualified `my-image:dev` resolves to
  `index.docker.io/library/my-image` — **not** to the local image cache
  and **not** to `ghcr.io/gregwebs/agent-vm-standard`
- use the fully qualified `ghcr.io/gregwebs/agent-vm-standard:v0.1.3`, or an
  imported local tag — see [Import and boot a local image without a
  registry](#import-and-boot-a-local-image-without-a-registry)

A `Not authorized` here can also mean the image is simply absent from whichever
cache `msb` is configured to use, which is expected when the shared-cache opt-in
points at a cache that does not have it — see [Sharing the OCI image cache with
a Homebrew `msb`](#sharing-the-oci-image-cache-with-a-homebrew-msb) and, in
`USAGE.md`, *Reverting is a manual step*. In both cases the error text points at
the registry, not at the actual cause.

### Supported source rebuild

For a complete source rebuild, use the root script:

```bash
container system status || container system start
LIBKRUNFW_BUILD_BACKEND=container MSB_FORCE_FIRMWARE_REBUILD=1 \
  CARGO_NET_GIT_FETCH_WITH_CLI=true ./script/build/macos.sh
```

It drives the pinned vendored agentd, firmware, and `microsandbox-cli` build
sequence directly, then builds `agent-vm`. The vendored build produces
`build/msb` and `build/libkrunfw.5.dylib`. Never assemble a macOS bundle from
the raw `vendor/microsandbox/target/release/msb`; only the fresh-inode copy
under `build/` receives `msb-entitlements.plist`. If the repository-local
firmware output is missing, the same script rebuilds and restores it
automatically.

### Rust 1.98.1 or its Cargo component is missing or unusable

The build uses the installed Rust 1.98.1 toolchain through rustup with automatic installation disabled. If the toolchain is absent or corrupted, install or repair it without changing the global default:

```bash
rustup toolchain install 1.98.1
```

If the toolchain's compiler works but Cargo is missing or unusable, restore only the Cargo component:

```bash
rustup component add cargo --toolchain 1.98.1
```

On rustup 1.29 for macOS, either bootstrap command can fail during channel synchronization with `invalid peer certificate ... OSStatus -26276`. For that specific failure, retry the applicable command once with rustup's official curl backend:

```bash
RUSTUP_USE_CURL=1 rustup toolchain install 1.98.1
# Or, for a missing Cargo component:
RUSTUP_USE_CURL=1 rustup component add cargo --toolchain 1.98.1
```

This selects a TLS-verifying HTTPS backend; it does not disable certificate verification. The curl backend is deprecated, so use the variable only for this targeted rustup 1.29 recovery and do not export it permanently. The build script never sets it or downloads a toolchain. This rustup bootstrap failure is separate from the later registry/`agent-vm setup` trust-service failure.

If Cargo's built-in Git transport reports an SSL handshake failure, keep using the root build script or set:

```bash
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release -p agent-vm
```

### Registry TLS fails with `OSStatus -26276`

Run `agent-vm setup` from a normal Terminal. The Rust registry client delegates certificate verification to macOS Security.framework, which requires access to `com.apple.trustd.agent`; restrictive Seatbelt profiles commonly block that service. `SSL_CERT_FILE`, `--ca-certs`, and `--insecure` do not safely bypass this platform verification for GHCR.

### Docker certificate failures

Verify Docker can pull the vendored build images using the system CA bundle:

```bash
SSL_CERT_FILE=/etc/ssl/cert.pem docker pull rust:alpine
SSL_CERT_FILE=/etc/ssl/cert.pem docker pull fedora:latest
SSL_CERT_FILE=/etc/ssl/cert.pem ./script/build/macos.sh
```

### Firmware backend is unavailable

The firmware helper does not extract Linux on a macOS bind mount, so changing
VirtioFS implementations is not a supported workaround. Start the selected
backend instead:

```bash
container system start
LIBKRUNFW_BUILD_BACKEND=container ./script/build/macos.sh
# Docker remains an explicit compatible fallback for the firmware helper.
LIBKRUNFW_BUILD_BACKEND=docker ./script/build/macos.sh
```

An explicit selector never falls back to another backend. Docker must still be
running for the separate agentd image build.

### Sharing the OCI image cache with a Homebrew `msb`

This is not macOS-specific — see [Shared microsandbox image cache](USAGE.md#shared-microsandbox-image-cache)
in the usage guide, which covers agent-vm on any platform alongside any
separately-installed `msb` (Homebrew, a distro package, `cargo install`,
etc.).
