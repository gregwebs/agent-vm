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
- [ADR-0018](docs/adr/0018-machine-checked-boundary-contracts.md) — a new
  **pure** function that decides a security boundary, a resource limit, or the
  parse of untrusted input carries a machine-checked `verus!` contract. Extract
  the decision, not the I/O.

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

### Verifying contracts locally (optional)

A few pure boundary predicates carry machine-checked Verus contracts
([ADR-0018](docs/adr/0018-machine-checked-boundary-contracts.md)). **Verus is not
needed for an ordinary build**: `cargo build`, `cargo test` and `cargo clippy` work
with no Verus on `PATH`, because a `verus!` block erases to ordinary Rust. CI verifies
the contracts in [`.github/workflows/verus.yml`](.github/workflows/verus.yml), which is
the single source of truth for the pinned release and its digest — take both from
there if this section ever looks stale.

To run the same check locally, install the pinned release. On Linux:

```bash
release=0.2026.09.16.7325eee
zip="verus-$release-x86-linux.zip"
curl -fSLO "https://github.com/verus-lang/verus/releases/download/release/rolling/$release/$zip"
echo "5e386d253a29bdac7d475a43b6f58dbcc9099c77953cb16180c9ef5832c50038  $zip" | sha256sum -c -
unzip -q "$zip"                     # unpack anywhere; creates verus-x86-linux/
export PATH="$PWD/verus-x86-linux:$PATH"
```

On macOS the asset is `verus-$release-arm64-macos.zip`, the unpacked directory is
`verus-arm64-macos/`, and the digest check is `shasum -a 256 -c -`. That asset is a
different file with a different digest; this repo pins and enforces only the
`x86-linux` digest, because that is the one CI uses.

Then, from the repository root:

```bash
CARGO_TARGET_DIR=target/verus cargo verus verify -p agent-vm
```

`CARGO_TARGET_DIR` matters: `cargo verus` sets `RUSTC_WRAPPER`, which is part of
cargo's fingerprint, so sharing one `target/` with ordinary builds makes every switch
a full rebuild. Expect a few minutes the first time and a few seconds thereafter.

`bash script/test/verus-verification.sh` runs exactly what CI runs: the verification
plus the assertion that it actually verified something, then a pair of throwaway
fixtures proving the verifier can both pass and fail.

### End-to-end (VM-boot) tests (optional)

These boot real microVMs and are the only way to observe the launcher, the
images and the guest together. **They do not run on CI**: GitHub's macOS runners
are Intel and cannot boot these `linux/arm64` guests, and they need `docker` plus
multiple GB of images. `script/test/e2e.sh` is the single entry point; it runs
the checks described below and exits non-zero on any failure.

Prerequisites: an Apple Silicon Mac with colima or Docker Desktop running, plus
the locally built `linux/arm64` dev images (`agent-vm-base:dev`,
`agent-vm-codex:dev`, … `agent-vm-template:dev`) from
[Local image builds](macos-build.md). `script/build/import-image.sh` loads those
into agent-vm's own cache; it needs the *release* bundle's `msb` at
`target/macos/bin/msb`, so run `./script/build/macos.sh` once even if you
otherwise use the `--dev` loop.

Use your **normal** state dir. Do not point `AGENT_VM_STATE_DIR` at a freshly
created directory for no reason — an already-populated dir is what makes the
import and the boot agree (see *The shared-cache trap* below):

```bash
export AGENT_VM_STATE_DIR="$HOME/.local/state/agent-vm"   # your usual state root
./script/build/import-image.sh agent-vm-base:dev
./script/build/import-image.sh agent-vm-template:dev
./script/test/e2e.sh
```

Set `AGENT_VM_E2E_OLD_LAUNCHER` (a pre-#84 binary),
`AGENT_VM_E2E_LEGACY_IMAGE` (a cached API-1/2 image),
`AGENT_VM_E2E_SETUP_BASE_REF` (a pullable `linux/arm64` base ref),
`AGENT_VM_E2E_UPDATE_CHECK=1` and/or `AGENT_VM_E2E_RUST=1` to enable the opt-in
checks; `./script/test/e2e.sh --help` lists them. Each check maps to an
acceptance criterion in the issue that introduced it (#84): the tool-free base,
the fast path (a default launch boots the published template with **zero**
`docker` invocations), per-tool-layer composition, the project-layer chain, and
the legacy API-1/2 seed fallback.

#### The shared-cache trap

A fresh `AGENT_VM_STATE_DIR` with `AGENT_VM_SHARE_MSB_CACHE` enabled is the one
state that does **not** work out of the box, and the failure is confusing, so it
is worth naming. `agent-vm`'s boot rewrites `<state>/msb-home/config.json` to
point `paths.cache` at the shared `~/.microsandbox/cache`, but
`script/build/import-image.sh` runs `msb image load` directly and never applies
that redirect. So on a fresh dir the imported blobs land in the private
`<state>/msb-home/cache`, the first boot then repoints `paths.cache` at the
shared cache, and msb finds the image in its database — `msb image ls` lists it —
but not its layer blobs there. It falls through to a registry pull of a local
tag and fails with `Not authorized … index.docker.io/.../agent-vm-template`.
An existing state dir is consistent because its `config.json` was written before
the import; `script/test/e2e.sh` also seeds a fresh dir by running a non-booting
builtin (`agent-vm doctor`) first, so it works either way. A follow-up should
teach `import-image.sh` the same shared-cache redirect so the raw recipe above
also works from scratch.

#### `bash -c`, not `bash -lc`, for in-guest commands

When you pass a command to the guest yourself, pass it through a non-login
shell. The image puts the agent CLIs on `PATH` via `ENV`, but a login shell
sources `/etc/profile`, which overwrites `PATH` and drops
`/opt/agent/.local/bin` (and the claude/opencode prefixes). The trap is that the
tools are present yet report as missing:

```bash
# correct — finds claude/codex/opencode
agent-vm shell --image agent-vm-template:dev -- bash -c 'claude --version'
# WRONG — "/etc/profile" resets PATH; `command -v claude` prints nothing
agent-vm shell --image agent-vm-template:dev -- bash -lc 'claude --version'
```

`script/test/e2e.sh` always uses `bash -c` for exactly this reason. (A shell
exported `AGENT_VM_IMAGE_TAG`/`AGENT_VM_BASE_IMAGE` is the same class of trap:
they act as `--image`/`--base-image`, so a “default config” check silently boots
the wrong image. The harness clears both.)

#### The `#[ignore]`d Rust Docker e2e tests

The repo also carries `#[ignore]`d tests that drive a real `docker buildx` build
(no VM boot). Run the whole set with a base image that has `agent-vm-install`:

```bash
AGENT_VM_E2E_BASE_IMAGE=agent-vm-base:dev \
  cargo test -p agent-vm --bin agent-vm -- e2e_ --ignored --test-threads=1
```

The compose-path test alone (the one #84 added):

```bash
AGENT_VM_E2E_BASE_IMAGE=agent-vm-base:dev \
  cargo test -p agent-vm --bin agent-vm -- \
    e2e_builtin_tool_layer_composes_onto_an_imported_base --ignored --test-threads=1
```

There is no `--lib` target, so `--bin agent-vm` is required. The layer tests
default to `alpine:latest` when `AGENT_VM_E2E_BASE_IMAGE` is unset (they skip if
it is not resolvable), and `AGENT_VM_E2E_REGISTRY_BASE` gates the one test that
needs a real registry. These tests are `#[ignore]`d, so **CI never runs them**.

#### What runs where

| Harness | Runs on CI | Notes |
|---|---|---|
| `cargo test --workspace` | yes (`ci.yml`) | `#[ignore]`d e2e excluded |
| `script/test/e2e.sh` | **no** | needs Apple Silicon + a VM boot |
| `cargo test … -- --ignored` | **no** | needs docker/buildx |
| `script/test/chrome-layer-contract.sh` / `chrome-layer-runtime.sh` | yes (`chrome-layer-contract.yml`) | docker-driver build + contract |
| `script/test/build-workflow.sh` | yes (macOS leg of `ci.yml`) | fake-plutil seam, no VM |
| `script/test/ci-contracts.sh`, `image-promotion-gate.sh`, `verus-verification.sh` | yes | static / contract gates |

## CI action pins

Every `uses:` in `.github/workflows/` pins a 40-character commit hash
([CODING_STANDARDS.md](CODING_STANDARDS.md) — *Version pinning*), so the trailing
comment is the only human-readable record of what that hash actually is. Label it
with the **exact release the hash is** (`# v5.1.0`), never a moving major (`# v5`):
a moving tag's label is true the day it is written and becomes a lie the next time
the tag moves, and nothing in the build notices.

`zizmor`'s `ref-version-mismatch` audit checks this, but it will not turn CI red
for you — it is an online audit (so `--offline` skips it silently) and the `zizmor`
job reports **success** while raising findings, which arrive as code-scanning
alerts. To check by hand:

```bash
GH_TOKEN=<token with public read> zizmor .github/workflows/
```

One action has no exact release to name: `dtolnay/rust-toolchain` publishes only
the moving `v1` tag — its per-release `1.x`/`1.x.y` refs are branches, not tags.
Label those pins `# v1 (<commit date of the pinned hash>)`. The parenthesised form
is deliberately not a parseable version string, because there is no version claim
that could be checked; it tells a reader which `v1` this is and nothing more.

Relabelling a stale comment is not the same operation as bumping a pin. Moving a
hash changes what CI runs, so decide that on its own and let Dependabot's cooldown
do it where it can.

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
