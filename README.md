# agent-vm

Run Claude Code / Codex / OpenCode inside a per-project libkrun microVM,
booting in ~2 seconds, with:

- **Host OAuth tokens never enter the VM.** The TLS-intercept proxy in
  [microsandbox](https://github.com/wirenboard/microsandbox) substitutes
  the real bearer for a placeholder on the way out. OAuth refresh is
  MITM'd so multi-hour sessions survive token rotation.
- **Per-launch GitHub repo allow-list.** Auto-detected from
  `git remote -v`; extend with `--repo OWNER/NAME`. `gh pr create`,
  `git push` etc. are filtered at the proxy — off-list calls get a 403
  before they reach GitHub.
- **Sandbox is the boundary.** The guest runs as your host user by
  default (`--root` for the old root-guest behavior), project bind-mounted
  at its host path, `--dangerously-skip-permissions` set by default
  (the microVM is the only thing actually keeping the agent on rails).

This is the Rust rewrite of the original Bash
[`wirenboard/agent-vm`](https://github.com/wirenboard/agent-vm) on
top of microsandbox. Living on `rewrite-microsandbox` until v1.

## Requirements

- Linux with `/dev/kvm` (rw) and membership in the `kvm` group, or an
  Apple Silicon Mac for the [supported source-build workflow](macos-build.md).
- Node.js 18+ for the npm-distributed launchers.

## Quick start

```bash
npm install -g @wirenboard/agent-vm        # or: npx @wirenboard/agent-vm <cmd>

agent-vm setup            # pulls the latest image from ghcr.io and verifies it boots

cd ~/your-project
agent-vm claude           # or codex / opencode / shell
```

Full flag, subcommand, networking, and troubleshooting reference:
**[USAGE.md](USAGE.md)**.

## Documentation

- [USAGE.md](USAGE.md) — running agent-vm: subcommands, flags, tooling
  layers, networking, credentials, troubleshooting.
- [CONTRIBUTING.md](CONTRIBUTING.md) — building from source, the release
  version-bump, and repo conventions.
- [macos-build.md](macos-build.md) — the Apple Silicon source-build guide.
- [PLAN.md](PLAN.md) — phased roadmap, what's done, what's deferred.
- [ARCHITECTURE.md](ARCHITECTURE.md) — design notes; why things look
  the way they do.
- [CODING_STANDARDS.md](CODING_STANDARDS.md) — repo coding standards.
