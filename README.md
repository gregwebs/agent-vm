# agent-vm

Run inside a per-project [microsandbox](https://docs.microsandbox.dev/) (libkrun microVM), booting in ~2 seconds.

- **Filesystem protection.**
  The working directory is bind-mounted at its host path and you can mount other directories.
  Choose read-only, write, or fork (copied) mounts.
- **Network allow list**
  Disable or enable networking, enforce allow lists 
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
* local port publishing

## Similar tools

Docker Sandbox is designed with the same security guarantees in mind.
This project adopted some of the Docker Sandbox configuration schema.

The main reasons someone might prefer this project is:

* open source
* no login required
* doesn't run its own daemon
* integrates with existing host VM systems via microsandbox (libkrun)

The features differ in serveral ways:
* fork mounts instead of a clone mode
* shell / run usage
* no shared skills repository
* docker engine is only in the VM image if you put it there
* doesn't write secrets to plain files in headless CI mode

OpenShell from NVidia is an enterprise ready sandboxing tool.
I found it difficult to use. It has a gateway-based design which I couldn't get working locally on my Mac.
It seems more geared to datacenter/cloud usage. It has multiple backends and does support vm=libkrun.

## Status

Although this is architected for security and every change is inspected for security, further security review is still needed.
Currently a few major features are being worked on before intensive security review begins.
If you are currently not sandboxing, then using this tool would be much more secure than that.
Please try out the project and give feedback or star it and and come back to it in a month.

## Requirements

- Linux with `/dev/kvm` (rw) and membership in the `kvm` group, or an
  Apple Silicon Mac for the [supported source-build workflow](macos-build.md).
- Cargo for building (will produce releases soon)

## Quick start

```bash
cargo build

agent-vm setup            # pulls the image this config boots from and verifies it boots

cd ~/your-project
agent-vm claude           # a configured launch verb; see `agent-vm --help`
```

The launch verbs come from your tool configuration (two tiers, user-wins), so
`agent-vm --help` lists exactly the tools you have configured; `agent-vm doctor`
shows which config files were found and what they resolved to.

Full flag, subcommand, networking, and troubleshooting reference:
**[USAGE.md](USAGE.md)**.

## Documentation

- [USAGE.md](USAGE.md) — running agent-vm: subcommands, flags, tooling
  layers, networking, credentials, troubleshooting.
- [CONTRIBUTING.md](CONTRIBUTING.md) — building from source, the release
  version-bump, and repo conventions.
- [macos-build.md](macos-build.md) — the Apple Silicon source-build guide.
- [PLAN.md](PLAN.md) — what is left to do for v1.
- [Credential shielding specification](docs/specs/credential-shielding.md) —
  agreed user contract and Docker-shaped YAML/CLI design (not yet implemented).
- [ARCHITECTURE.md](ARCHITECTURE.md) — design notes; why things look
  the way they do.
- [ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md) —
  file-backed credential-injection and refresh boundary.
- [CODING_STANDARDS.md](CODING_STANDARDS.md) — repo coding standards.
