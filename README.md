# agent-vm

Run inside a per-project [microsandbox](https://docs.microsandbox.dev/) (libkrun microVM), booting in ~2 seconds.

- **Secure sandbox with convenience.**
  The guest runs as your host user (--root is available when needed).
  The working directory is bind-mounted at its host path and you can mount other directories.
  Provide your own Dockerfile and configuration files to specify whats in your VM.
- **Network allow list**
  Disable or enable networking, enforce allow lists 
- **Built-in support for common AI harnesses**
  Claude Code / Codex / OpenCode / Copilot / Pi / DeepSeek Harness (`dsh`)
  Run with `--yolo`, `--dangerously-skip-permissions`, etc- agent-vm instead provides the security.
- **Host OAuth tokens never enter the VM.**
  A TLS-intercept proxy in
  [microsandbox](https://github.com/gregwebs/microsandbox) substitutes
  the real bearer for a placeholder on the way out.
- **Per-launch GitHub repo allow-list.** Auto-detected from
  `git remote -v`; extend with `--repo OWNER/NAME`. `gh pr create`,
  `git push` etc. are filtered at the proxy — off-list calls get a 403
  before they reach GitHub.

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
- [ARCHITECTURE.md](ARCHITECTURE.md) — design notes; why things look
  the way they do.
- [ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md) —
  file-backed credential-injection and refresh boundary.
- [CODING_STANDARDS.md](CODING_STANDARDS.md) — repo coding standards.
