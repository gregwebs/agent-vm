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
(cd vendor/microsandbox && JUST_UNSTABLE=1 just build release)
cargo build --release -p agent-vm
./target/release/agent-vm setup
```

`JUST_UNSTABLE=1` is required because the vendored justfile uses `just`'s
unstable `[script]` attribute.

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
release=0.2026.09.20.aef82ed
zip="verus-$release-x86-linux.zip"
curl -fSLO "https://github.com/verus-lang/verus/releases/download/release/$release/$zip"
echo "7b870fa12bc589015c2fab60a8b3d9f07c7b1adb3444eb0fadffcbf7f0447b33  $zip" | sha256sum -c -
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

The `rust-dev` example custom image (`examples/layers/rust-dev`) pre-installs this
same pinned release for an in-VM agent on `linux/amd64`; see
[`examples/layers/README.md`](examples/layers/README.md#rust-development).

`bash script/test/verus-verification.sh` runs exactly what CI runs: the verification
plus the assertion that it actually verified something, then a pair of throwaway
fixtures proving the verifier can both pass and fail.

### `CARGO_TARGET_DIR` must not be on a tmpfs prefix

Several boot-free integration tests (`config_launch_driven.rs`,
`mount_fork.rs`, `mount_protected_pi.rs`) deliberately place their project root
under `CARGO_TARGET_TMPDIR` so `run::resolve_project_guest_path` mirrors the
host path into the guest instead of falling back to `/workspace`; the mirrored
path is what they assert on. `CARGO_TARGET_TMPDIR` is `<CARGO_TARGET_DIR>/tmp`,
so pointing `CARGO_TARGET_DIR` at `/tmp`, `/run`, `/dev/shm` or `/var/run` — a
common container and CI pattern — puts that root under a guest tmpfs prefix, and
the tests would fail on their mirrored-path assertions as if the product were
broken. The shared harness helper `tests/support::project_tempdir` detects this
and fails fast with a message naming the precondition. Run those tests with an
off-tmpfs target dir:

```bash
CARGO_TARGET_DIR=/build/target cargo test -p agent-vm
```

The requirement is on the **canonicalized** project scratch path (the
`CARGO_TARGET_TMPDIR` under `CARGO_TARGET_DIR`): it must avoid the guest
prefixes `/tmp`, `/run`, `/dev/shm` and `/var/run`. The default
`CARGO_TARGET_DIR=target` (inside the checkout) already satisfies this, provided
the checkout is not itself under one of those prefixes — a checkout at
`/tmp/agent-vm` would not. On macOS `/tmp` is only a symlink to `/private/tmp`;
the check runs on the canonicalized path, which is off-prefix, so it passes
there.

### End-to-end (VM-boot) tests (optional)

These boot real microVMs and are the only way to observe the launcher, the
images and the guest together. **They do not run on CI**: GitHub's macOS runners
are Intel and cannot boot these `linux/arm64` guests, and they need `docker` plus
multiple GB of images. `script/test/e2e.sh` is the single entry point; it runs
the checks described below and exits non-zero on any failure.

Prerequisites: an Apple Silicon Mac with colima or Docker Desktop running, plus
the locally built `linux/arm64` **template** image (`agent-vm-template:dev`)
from [Local image builds](macos-build.md). `script/build/import-image.sh` loads
it into agent-vm's own cache; it needs the *release* bundle's `msb` at
`target/macos/bin/msb`, so run `./script/build/macos.sh` once even if you
otherwise use the `--dev` loop. The custom-image group needs only Docker, the
release `msb` and a launcher binary — no dev images.

Use your **normal** state dir. Do not point `AGENT_VM_STATE_DIR` at a freshly
created directory for no reason — an already-populated dir is what makes the
import and the boot agree (see *The shared-cache trap* below):

```bash
export AGENT_VM_STATE_DIR="$HOME/.local/state/agent-vm"   # your usual state root
./script/build/import-image.sh agent-vm-template:dev
./script/test/e2e.sh
```

Set `AGENT_VM_E2E_LEGACY_IMAGE` (an image that supplies
`/opt/agent-vm/seed-claude-plugins.sh`) and/or `AGENT_VM_E2E_UPDATE_CHECK=1` to
enable the opt-in checks; `./script/test/e2e.sh --help` lists them. Each check
covers one of: the fast path (a default launch boots the published template with
**zero** `docker` invocations), the finished-template tool set, Pi HOME
persistence, inert former `.agent-vm/layers/` directories, and the custom-image
group (a config/`--image` selected image and setup's verification input).

`script/test/e2e.sh` takes an optional group: `all` (the default; the dev-image
checks above plus the custom-image group) or `custom-image` (only the marker-free
custom-image group). The custom-image group needs only Docker, the release
bundle's `msb`, and a launcher binary — **no dev images** — plus network for the
pinned fixture base/`apk add bash` and a digest-pinned local registry service. It
builds the `script/test/fixtures/marker-free-image` targets, boots them through
the real CLI, and asserts: a marker-free image runs a program as the host user
and as `--root`; state/HOME persists across independent boots and under an OCI
`USER`/`ENV HOME`; a missing program exits 127 with the contract message and a
no-Bash image fails with the contract diagnostic and leaves no surviving VM or
catalog entry; the configured Chrome MCP entry actually executes its configured
command/argv/env while an unrelated user MCP entry survives; supplied
`seed.d`/named seed scripts are idempotent; project-hook-exported `PATH` tools
run; and genuinely uncached nonstandard-`PATH` refs boot cold against a local
registry and again offline (warm). A file-backed Anthropic credential seeded
under a private launcher HOME reaches the guest only as the documented
non-secret placeholder (a missing host credential fails closed), and a present
non-numeric image-version stamp is ignored. The guest's effective `PATH` for that
nonstandard fixture (whose OCI `PATH` lacks `/.msb/scripts`) is
`/.msb/scripts:` + its exact OCI `PATH`. A real PTY attach check covers the
`--image`/attach branch. These checks are always-run in the custom group, not
opt-in: a missing prerequisite is a failure, not a skip. The suite must run on a
dedicated serial native host with no concurrent launches so process/catalog
absence is meaningful. The custom group always runs against a fresh private
cache under the default msb config sources: it neutralizes an inherited
`AGENT_VM_SHARE_MSB_CACHE`, `AGENT_VM_MSB_CACHE_DIR` and `MSB_CONFIG_PATH`, so it
does not exercise shared-cache mode. It makes no released-default or lineage
claim.

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
builtin that still initialises the cache (`agent-vm msb --version`) first, so it
works either way. (Not `doctor`, which is deliberately observational and writes
nothing.) A follow-up should
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
exported `AGENT_VM_IMAGE_TAG` is the same class of trap: it acts as `--image`
whenever the typed flag is omitted, outranking any configured `image`, so a
“default config” check silently boots the wrong image. The harness clears it.)

#### The `#[ignore]`d keychain test

One `#[ignore]`d test remains: `secret_store::tests::system_keychain_round_trip`
writes and removes one synthetic item in the host OS credential store, so it is
operator opt-in, never CI:

```bash
cargo test -p agent-vm --bin agent-vm secret_store::tests::system_keychain_round_trip \
  -- --ignored --exact --test-threads=1
```

There is no `--lib` target, so `--bin agent-vm` is required.

#### Test seams

Two debug-only seams are compiled out of release builds: `AGENT_VM_TEST_CREDENTIAL`
(credential provisioning) and `AGENT_VM_TEST_DEFAULT_IMAGE` (the boot-image
default slot, so a boot-free CLI test that falls through to the default does not
start a real multi-GB pull). Neither is read by a release build; a test pins the
release exclusion.

#### What runs where

| Harness | Runs on CI | Notes |
|---|---|---|
| `cargo test --workspace` | yes (`ci.yml`) | `#[ignore]`d e2e excluded |
| `script/test/e2e.sh` | **no** | needs Apple Silicon + a VM boot; `all` (dev images + custom) or `custom-image` (Docker + release `msb` + launcher, no dev images) |
| `cargo test … -- --ignored` | **no** | the one keychain round-trip test; operator opt-in, writes one host keychain item |
| `script/test/chrome-layer-contract.sh` / `chrome-layer-runtime.sh` | yes (`chrome-layer-contract.yml`) | docker-driver build + contract |
| `script/test/shipped-tool-recipes.sh` | yes (`shipped-tool-recipes.yml`, native amd64) + manually on native arm64 | real docker-driver build + numeric-uid label/report/T5 audit + label replay. A `workflow_dispatch` run with `full_contract: true` adds `--overrides --chain`; the overrides/chain matrix is not part of the default PR gate |
| `script/test/shipped-installer-network.sh` | **no** (default PR); yes on a dispatched `full_contract: true` native-amd64 run (`shipped-tool-recipes.yml`) | restricted-egress allowlist over the real vendored installers; the default PR gate never runs it |
| `script/test/pi-layer-runtime.sh` | yes (`pi-layer.yml`) | deep pi runtime matrix |
| `script/test/build-workflow.sh` | yes (macOS leg of `ci.yml`) | fake-plutil seam, no VM |
| `script/test/ci-contracts.sh`, `image-promotion-gate.sh`, `verus-verification.sh` | yes | static / contract gates |

Shipped tool versions are bumped **explicitly by a developer and committed**,
never resolved by CI: `bash script/build/agent-versions.sh --write` rewrites the
four installer defaults (`codex`, `opencode`, `claude`, `copilot`) and the
lockfile upgrade scripts bump `dsh`/`pnpm` and `pi`/`pi-claude-bridge`. Ordinary
and release builds consume only the committed values. The recipe/install
contract is documented in [`images/tools/README.md`](images/tools/README.md);
the boot-image ownership and selection contract is
[ADR-0035](docs/adr/0035-consume-user-owned-boot-images.md).

The restricted-egress gate (`shipped-installer-network.sh`) runs on a
**dispatched** native-amd64 `shipped-tool-recipes.yml` run with
`full_contract: true`: that job runs the recipe audit with `--overrides --chain`
and then the network gate with `--overrides`, producing real native-amd64
evidence for the installed vendored installers against the deny-by-default
proxy. The **default PR** run of the same workflow (no `full_contract`) runs
only the default recipe audit and does **not** invoke the network gate, so a PR
is not blocked on the restricted-egress matrix. Run the network gate locally
before merging a version bump if you want that evidence before the dispatched
run.

The Docker gate (`shipped-tool-recipes.sh`, `pi-layer-runtime.sh`) needs no VM:
it drives real `docker buildx`/`docker run`. The end-to-end VM smoke
(`script/test/e2e.sh`) is separate and must be run manually on Apple Silicon
before merge; a numeric uid in a container is **not** evidence of the
launcher/MSB boot path.

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
