# @wirenboard/agent-vm

Sandboxed VMs for AI coding agents — Claude Code, Codex CLI, OpenCode,
Copilot, Pi, DeepSeek Harness — running inside per-project libkrun microVMs built on
[microsandbox](https://github.com/wirenboard/microsandbox).

This package is a thin launcher; the actual native binaries
(`agent-vm`, `msb`, libkrunfw) ship in the
platform-specific subpackage installed automatically as an
`optionalDependency` (e.g. `@wirenboard/agent-vm-linux-x64`).

## Install

```bash
npm install -g @wirenboard/agent-vm
# or
npx @wirenboard/agent-vm <subcommand>
```

Requirements: Linux with `/dev/kvm` (your user must be in the `kvm`
group) and Node 18+. macOS and Windows aren't supported yet.

## Quick start

```bash
agent-vm setup            # pull the selected image, verify configured tools
cd ~/your-project
agent-vm claude           # or codex / opencode / copilot / pi / shell
```

The compiled immutable standard-image recommendation is retained after successful
first acquisition; launcher upgrades preserve existing selections. Default launches
need no Docker or image-source checkout. Archives are explicitly imported through
`agent-vm msb image load --input FILE --tag REF`, never a download fallback.

Full docs, subcommand reference, and source:
<https://github.com/wirenboard/agent-vm>.
