# Building `agent-vm` on macOS

These instructions support Apple Silicon Macs (`arm64`, M1 or newer). Intel macOS is not supported.

## Prerequisites

Install the Xcode Command Line Tools, Rust 1.91 or newer (1.92 is known good), and Docker Desktop:

```bash
xcode-select --install
brew install rustup
brew install --cask docker
rustup-init -y
source "$HOME/.cargo/env"
rustup toolchain install 1.92
```

Start Docker Desktop, initialize the recursive submodules, and check the toolchain:

```bash
docker info
git submodule update --init --recursive
rustc --version
```

The vendored build compiles a Linux guest helper and firmware through Docker. Keep enough Docker and temporary disk space for those outputs and for one staged Docker image archive during local image import.

## Build the macOS bundle

From the repository root, run the canonical build command:

```bash
./script/build/macos.sh
```

The script checks the host, Rust version, Xcode tools, Docker, and submodules; builds the vendored signed runtime and release `agent-vm`; and verifies each artifact's architecture, code signature, and Hypervisor.framework entitlements. It assembles:

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
  --no-update-check -- uname -m
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

### Rust compiler is too old

The build rejects Rust older than 1.91. Install the known-good toolchain without changing an unrelated project's build output:

```bash
rustup toolchain install 1.92
rustup default 1.92
```

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
