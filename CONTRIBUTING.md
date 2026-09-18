# Contributing to agent-vm

How to build agent-vm from source and the conventions for developing it.
See [README.md](README.md) for an overview and [USAGE.md](USAGE.md) for
the end-user reference.

## Coding standards & conventions

- [CODING_STANDARDS.md](CODING_STANDARDS.md) — documentation, bash,
  coding, and security standards for this repo.
- [AGENTS.md](AGENTS.md) — conventions for coding agents (Claude Code,
  Codex, etc.) working on this repo: submodule-merge ordering, build
  output placement, state-dir cleanup, commit-message style.
- [docs/adr/](docs/adr/) — architecture decision records for the
  important technical trade-offs.

## Build from source

Clone the repository and its recursive submodules:

```bash
git clone https://github.com/gregwebs/agent-vm
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

The pinned Rust toolchain (`rust-toolchain.toml`) is copied by hand into a
few other files (Cargo's MSRV, CI, the release workflow, the macOS build
script, and its docs). After bumping the pin, run
`./script/check-rust-toolchain.sh` — it's a sub-second local check that
fails closed with an actionable diagnostic for every copy left stale.

The CI pre-build gate is `script/test/ci-contracts.sh`: it checks runtime source
provenance, runs the harness contracts, and syntax-checks (`bash -n`) and lints
(`shellcheck`) every script the workflow runs. Run it locally with shellcheck
installed (`brew install shellcheck` on macOS, `sudo apt-get install -y
shellcheck` on Debian/Ubuntu); the full gate also needs the recursive submodule
and a working Cargo toolchain, while `bash script/test/ci-contracts.sh
--guard-only` runs just the shell guard and needs neither.


## Commit message style

Commits on this branch use a multi-paragraph "Why / How" style.
The commit and the information in its links and issues and PRs should recover all
reasoning about the changes made.


## Isolate `AGENT_VM_STATE_DIR` when building agent-vm across worktrees

`agent-vm`'s private microsandbox home (`MSB_HOME/db/msb.db`) is a
single flat directory under `$AGENT_VM_STATE_DIR` (default
`$HOME/.local/state/agent-vm`), shared by *every* `agent-vm` build you
run on this host — it is not namespaced by which worktree/branch built
it (see `docs/adr/0004-single-shared-msb-home.md`). sea-orm migrations
are one-way, so running a build from a worktree vendoring a newer
microsandbox schema, then switching to one with an older schema, trips
a fail-fast guard (`msb_preflight.rs`) that blocks every command until
you run `agent-vm doctor --reset-msb-db` — which re-pulls images on
next boot.

If you're building and running `agent-vm shell`/`run` from more than
one worktree in the same session (or expect to), set
`AGENT_VM_STATE_DIR` to a distinct path per worktree first, e.g.
`export AGENT_VM_STATE_DIR="$HOME/.local/state/agent-vm-$(basename "$PWD")"`.
Hitting the guard isn't dangerous (nothing is deleted, the error names
the fix), just a time cost worth avoiding proactively.

On macOS, keep the resulting `AGENT_VM_STATE_DIR` short. Unix-domain
sockets have a ~103-108 byte `sun_path` limit depending on platform,
and microsandbox binds each sandbox's control/agent socket under this
root — a long worktree or branch name folded into the path above can
overflow it. The socket-path preflight added by #40 fails closed with
a clear error if this happens (it never silently truncates the path);
the fix is simply to pick a shorter override, e.g. `~/.avm`.



## Release / version bump

Every feature PR bumps the workspace version.

Bump `workspace.package.version` in the root `Cargo.toml` **in the
feature branch itself**, so the PR that lands the change also lands its
version. Skipping this leaves the next release boundary ambiguous and
means downstream `agent-vm --version` lies about what's in the binary.

```
$EDITOR Cargo.toml                     # version = "0.1.N+1"
cargo build                            # refreshes Cargo.lock
git commit -am "..."                   # lock alongside the bump
```

`Cargo.lock` always moves with the version, so commit it alongside.

(Older history used a separate post-merge `vX.Y.Z: bump for <feature>`
commit on the retired `rewrite-microsandbox` branch — that's what
`git log --oneline | grep "^[a-f0-9]* v"` is showing you. PRs now squash
onto `main` and carry the bump inside.)

## Submodule merges

`vendor/microsandbox` is a submodule with its own branches. When a
worktree changes both the agent-vm code and the vendored microsandbox
code, merge inside the submodule **before** merging the superproject —
otherwise the superproject merge will conflict on the gitlink and
you'll have to redo the submodule merge anyway. Pattern:

1. `cd vendor/microsandbox && git merge --no-ff <subm-feature-branch>`
2. `cd ../.. && git add vendor/microsandbox` (bumps the gitlink)
3. `git merge --no-ff <agent-vm-feature-branch>`
   (resolves the gitlink conflict to the merge SHA from step 1)

If the feature branch lives in a separate git worktree, the
submodule branches in that worktree's `.git/modules/...` are not
visible from the main worktree. Push them across with
`git -C <worktree>/vendor/microsandbox push <main-worktree>/.git/modules/vendor/microsandbox <branch>:<branch>`
before attempting the submodule merge.
