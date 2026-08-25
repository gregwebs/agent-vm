# Contributing to agent-vm

How to build agent-vm from source and the conventions for developing it.
See [README.md](README.md) for an overview and [USAGE.md](USAGE.md) for
the end-user reference.

## Build from source

Clone the repository and its recursive submodules:

```bash
git clone -b rewrite-microsandbox https://github.com/wirenboard/agent-vm
cd agent-vm
git submodule update --init --recursive
```

On Apple Silicon macOS, follow the [canonical macOS guide](macos-build.md).
The workflow is directly executable and does not require `just`:

```bash
./script/build/macos.sh
```

While iterating on `agent-vm`'s Rust source, use `./script/build/macos.sh
--dev` instead for a much faster unoptimized build published to
`target/macos-dev/` — see [Fast development
build](macos-build.md#fast-development-build).

On Linux, install the host development packages, build the vendored runtime
through its supported recipe, and then build agent-vm:

```bash
sudo apt-get install -y libcap-ng-dev libdbus-1-dev pkg-config
(cd vendor/microsandbox && just build release)
cargo build --release -p agent-vm
./target/release/agent-vm setup
```

Source builds use the vendored recipe's `vendor/microsandbox/build/msb`
artifact; `agent-vm setup` pulls and verifies the selected registry image but
does not build `msb`.

On macOS, `./script/build/import-image.sh` loads an existing local
`linux/arm64` Docker image directly into agent-vm's private cache without a
registry. See [the macOS guide](macos-build.md) for the exact workflow.
`images/build.sh` remains the separate registry-backed build-and-push option.

## Release / version bump

After merging a feature branch, bump the workspace version.

Every merge into `rewrite-microsandbox` ships with a
`workspace.package.version` bump in the root `Cargo.toml` and a
follow-up `vX.Y.Z: bump for <feature>` commit. Skipping this leaves
the next release boundary ambiguous and means downstream
`agent-vm --version` lies about what's in the binary.

Convention (look at `git log --oneline | grep "^[a-f0-9]* v"`):

```
git merge --no-ff <feature-branch>     # produces "Merge ...: ..."
$EDITOR Cargo.toml                     # version = "0.1.N+1"
git commit -am "v0.1.N+1: bump for <one-line feature>"
```

`Cargo.lock` will need refreshing — run a build after the bump to
update it, then commit the lock alongside the version bump if it
moved (it always does).

## Coding standards & conventions

- [CODING_STANDARDS.md](CODING_STANDARDS.md) — documentation, bash,
  coding, and security standards for this repo.
- [AGENTS.md](AGENTS.md) — conventions for coding agents (Claude Code,
  Codex, etc.) working on this repo: submodule-merge ordering, build
  output placement, state-dir cleanup, commit-message style.
- [docs/adr/](docs/adr/) — architecture decision records for the
  important technical trade-offs.
