# agent-vm

Run inside a per-project [microsandbox](https://docs.microsandbox.dev/) (libkrun microVM), booting in ~2 seconds.

- **Filesystem protection.**
  The working directory is bind-mounted at its host path and you can mount other directories.
  Choose read-only, write, or fork (copied) mounts, per launch or as verified
  user-wide defaults.
- **Default-deny egress.**
  Opt in to the public internet, LAN, host, or specific IPs/CIDRs (with protocol/port).
- **Dropped User or root**
  The guest runs as your host user uid without sudo (--root is available when needed).
  Provide your own Dockerfile and configuration files to specify whats in your VM.
- **Credential shielding.**
  A TLS-intercept proxy in
  [microsandbox](https://github.com/gregwebs/microsandbox) adds
  the real credential on the way out- the guest doesn't see it.
  Supports standard API key usage and Claude/Codex Oauth with refresh.
- **Built-in support for common AI harnesses**
  Claude Code / Codex / OpenCode / Copilot / Pi / DeepSeek Harness (`dsh`)
  Run with `--yolo`, `--dangerously-skip-permissions`, etc- agent-vm instead provides the security.
- **Per-launch GitHub repo allow-list.** Auto-detected from
  `git remote -v`; extend with `--repo OWNER/NAME`. `gh pr create`,
  `git push` etc. are filtered at the proxy — off-list calls get a 403
  before they reach GitHub.

Missing planned features:

* MCP gateway
* SSH agent socket

## Similar tools

Docker Sandbox is designed with the same security guarantees in mind.
This project adopted some of the Docker Sandbox configuration schema.

The main reasons someone might prefer this project is:

* open source
* no login required
* doesn't run its own daemon
* integrates with existing host VM systems via microsandbox (libkrun)

The features of agent-vm differ in serveral ways:
* fork mounts instead of a clone mode
* shell / run usage
* no shared skills repository
* docker engine is only in the VM image if you put it there
* doesn't write secrets to plain files in headless CI mode

OpenShell from NVidia is an enterprise ready sandboxing tool.
I found it difficult to use. It has a gateway-based design which I couldn't get working locally on my Mac.
It seems more geared to datacenter/cloud usage. It has multiple backends and does support vm=libkrun.

## Status

Although this is architected for security, mostly relies on the microsandbox project for security, and every change is inspected for security, further security review is still needed.
This will happen afer completing testing of a few major features that have just landed.
If you are currently not sandboxing, then using this tool would be much more secure than that.
Please try out the project and give feedback or star it but don't rely on it for untrusted workloads yet.

## Requirements

- Linux with `/dev/kvm` (rw) and membership in the `kvm` group, or an
  Apple Silicon Mac for the [supported source-build workflow](macos-build.md).
- Linux: Node 18+ for the npm distribution. macOS: a signed source-built bundle, or a source-built single binary from `./script/build/macos.sh --single-binary`.
- Installed launches need native VM support and network on first acquisition,
  not Docker or image-source files. Docker is needed only for explicit image builds.

## Quick start

```bash
# Clone to build from source
git clone https://github.com/gregwebs/agent-vm
cd agent-vm
git submodule update --init --recursive vendor/microsandbox

# build from source
cargo build --release

# Acquire the selected OCI image; optionally verify it in a guest
agent-vm image refresh    # acquisition only, no guest
agent-vm setup            # acquisition plus boot/tool verification

cd ~/your-project
agent-vm --allow-internet-egress claude
```

Run a guest executable directly — no catalog entry, defaults, environment or
credential provisioning. Piped stdin is forwarded to the program and host EOF
closes it; `-t`/`-T` choose a PTY or streaming I/O explicitly (signal forwarding
is still tracked in #401):

```sh
agent-vm run make test
agent-vm -- make test        # the same, with the top-level separator
printf hello | agent-vm run cat   # streams stdin; prints hello
agent-vm -T run build.sh >out.log # streaming even from a terminal
```

Selection rules, forced-PTY constraints, merged PTY output and the absence of a
detach mode are in **[USAGE.md](USAGE.md#direct-commands)**.

Full flag, subcommand, networking, and troubleshooting reference:
**[USAGE.md](USAGE.md)** — direct commands are in
[Direct commands](USAGE.md#direct-commands), with the approved contract in
[docs/specs/direct-command-launch.md](docs/specs/direct-command-launch.md).

Build and select your own finished image; launches never run Docker:

```sh
agent-vm image build --tag my-image:dev --builder native-oci .
# Or: agent-vm image import --docker my-image:dev
agent-vm --image my-image:dev shell my-program
```

See [Explicit builds and archive import](USAGE.md#explicit-builds-and-archive-import)
for builder prerequisites and host-build trust.

## Documentation

- [USAGE.md](USAGE.md) — running agent-vm: subcommands, flags, explicit image builds, networking, credentials, troubleshooting.
- [CONTRIBUTING.md](CONTRIBUTING.md) — building from source, the release
  version-bump, and repo conventions.
- [macos-build.md](macos-build.md) — the Apple Silicon source-build guide.
- [Open issues](https://github.com/gregwebs/agent-vm/issues?q=is%3Aissue%20is%3Aopen) —
  outstanding work and known limitations.
- [Credential shielding specification](docs/specs/credential-shielding.md) —
  agreed user contract and Docker-shaped YAML/CLI design (not yet implemented).
- [Named mount sets and tier-local tool references](docs/adr/0048-named-mount-sets-and-tier-local-tool-references.md) —
  tool references resolve inside their own config file, user-config mount sets
  are selectable by name with `--mount NAME`, and a full user `[[tools]]` may
  declare `mounts` that a launch of it, or of a tool referencing it, selects (all
  implemented). See [Named mount sets](USAGE.md#named-mount-sets-user-config) and
  [Tool-specific config mounts](USAGE.md#tool-specific-config-mounts).
- [Tool references are local to their file](USAGE.md#tool-references-are-local-to-their-file) —
  the breaking change and how to migrate a config.
- [ARCHITECTURE.md](ARCHITECTURE.md) — design notes; why things look
  the way they do.
- [Host-wide OCI image approval](docs/adr/0047-host-wide-oci-image-approval.md) —
  why every selected image is pinned per host platform and how a digest change is
  approved.
- [CODING_STANDARDS.md](CODING_STANDARDS.md) — repo coding standards.
