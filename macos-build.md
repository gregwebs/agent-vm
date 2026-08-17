# Building `agent-vm` on macOS

These instructions support Apple Silicon Macs (`arm64`, M1 or newer). Intel macOS is not supported.

## Prerequisites

Install the Xcode Command Line Tools, rustup with the known-good Rust 1.92 toolchain, and Docker Desktop:

```bash
xcode-select --install
brew install rustup
brew install --cask docker
rustup-init -y
source "$HOME/.cargo/env"
rustup toolchain install 1.92
```

Start Docker Desktop, initialize the recursive submodules, and check the exact toolchain used by the build:

```bash
docker info
git submodule update --init --recursive
RUSTUP_AUTO_INSTALL=0 rustup run 1.92 rustc --version
RUSTUP_AUTO_INSTALL=0 rustup run 1.92 cargo --version
```

The guarded checks do not download a missing toolchain. The canonical build selects installed Rust 1.92 locally through rustup; it neither depends on nor changes your global default toolchain.

The vendored build compiles a Linux guest helper and firmware through Docker. Keep enough Docker and temporary disk space for those outputs and for one staged Docker image archive during local image import.

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

Re-running `./script/build/macos.sh` is safe. It retains Cargo and Docker incremental output and atomically replaces the verified bundle files without requiring manual copying, signing, or environment setup. The macOS workflow does not require `just`.

## Import and boot a local image without a registry

Build or identify a local native `linux/arm64` Docker image. For example:

```bash
docker buildx build \
  --platform linux/arm64 \
  --load \
  -t agent-vm-template:latest \
  -f images/Dockerfile images
```

Import it directly into agent-vm's private microsandbox cache:

```bash
./script/build/import-image.sh agent-vm-template:latest
```

To use a different cache tag, pass both the Docker source and destination tag:

```bash
./script/build/import-image.sh my-local-image:dev agent-vm-template:dev
```

The script accepts zero to two positional arguments. The Docker source defaults to `agent-vm-template:latest`, and the destination tag defaults to the source. It verifies the Docker image is exactly `linux/arm64`, resolves agent-vm's state directory, and pipes `docker save` into `msb image load`. It does not run a registry or create a caller-managed tar archive. `msb` currently stages stdin in a temporary file before ingesting it, so temporary free space roughly equal to the Docker archive is still required.

Cache references are exact. Importing `agent-vm-template:latest` does not populate `ghcr.io/wirenboard/agent-vm-template:latest`.

From a disposable project directory, verify the cached image without a registry update check:

```bash
/path/to/agent-vm/target/macos/bin/agent-vm shell \
  --image agent-vm-template:latest \
  -- uname -m
```

The guest should print `aarch64`, the command should exit successfully, and the sandbox should stop cleanly. `agent-vm setup` is not a local-cache check: setup deliberately pulls its selected image with `PullPolicy::Always`.

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

### Supported source rebuild

For a complete source rebuild, use the root script:

```bash
CARGO_NET_GIT_FETCH_WITH_CLI=true ./script/build/macos.sh
```

It drives the pinned vendored agentd, firmware, and `microsandbox-cli` build
sequence directly, then builds `agent-vm`. The vendored build produces
`build/msb` and `build/libkrunfw.5.dylib`. Never assemble a macOS bundle from
the raw `vendor/microsandbox/target/release/msb`; only the fresh-inode copy
under `build/` receives `msb-entitlements.plist`. If the repository-local
firmware output is missing, the same script rebuilds and restores it
automatically.

### Rust 1.92 or its Cargo component is missing or unusable

The build uses the installed Rust 1.92 toolchain through rustup with automatic installation disabled. If the toolchain is absent or corrupted, install or repair it without changing the global default:

```bash
rustup toolchain install 1.92
```

If the toolchain's compiler works but Cargo is missing or unusable, restore only the Cargo component:

```bash
rustup component add cargo --toolchain 1.92
```

On rustup 1.29 for macOS, either bootstrap command can fail during channel synchronization with `invalid peer certificate ... OSStatus -26276`. For that specific failure, retry the applicable command once with rustup's official curl backend:

```bash
RUSTUP_USE_CURL=1 rustup toolchain install 1.92
# Or, for a missing Cargo component:
RUSTUP_USE_CURL=1 rustup component add cargo --toolchain 1.92
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

### Kernel extraction fails under Colima

Some Colima VirtioFS configurations reject symlinks while extracting the Linux kernel. Use Docker Desktop for the firmware build; its file sharing handles the vendored libkrunfw source layout reliably.

### Sharing the OCI image cache with a Homebrew `msb`

This is not macOS-specific — see [Shared microsandbox image cache](README.md#shared-microsandbox-image-cache)
in the main README, which covers agent-vm on any platform alongside any
separately-installed `msb` (Homebrew, a distro package, `cargo install`,
etc.).
