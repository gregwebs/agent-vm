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
git submodule update --init --recursive vendor/microsandbox
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

Use packaged `agent-vm build --tag REF --builder NAME CONTEXT` for explicit
Dockerfile builds, or `agent-vm msb image load --input archive.tar --tag REF`
for completed Docker-save/OCI archives. Both initialize the same cache as
launch; no prewarming builtin or source importer is needed. Image authoring and
publication belong to [agent-vm-images](https://github.com/gregwebs/agent-vm-images).
Optionally initialize its contributor pin with
`git submodule update --init vendor/agent-vm-images`; Cargo and macOS bundle
builds need only the recursive microsandbox submodule, not image sources.

The pinned Rust toolchain (`rust-toolchain.toml`) is copied by hand into a
few other files (Cargo's MSRV, CI, the release workflow, the macOS build
script, and its docs). After bumping the pin, run
`./script/check-rust-toolchain.sh` — it's a sub-second local check that
fails closed with an actionable diagnostic for every copy left stale.

The CI pre-build gate is `script/test/ci-contracts.sh`: it checks runtime source
provenance, runs the harness contracts, and syntax-checks (`bash -n`) and lints
(`shellcheck`) every script the workflow runs. Run it locally with shellcheck
installed (`brew install shellcheck` on macOS, `sudo apt-get install -y
shellcheck` on Debian/Ubuntu); the full gate also needs the recursive submodule,
a working Cargo toolchain, and `jq`/`shasum`/`python3` (the boot-free
released-image controls), while `bash script/test/ci-contracts.sh --guard-only`
runs just the shell guard and needs none of those.

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

Real microVM tests do not run in CI. `script/test/e2e.sh` is the single manual
entry point: `released-image` is native amd64/arm64 and Docker-independent;
`custom-image` remains Apple Silicon-only and needs Docker/buildx, validated
debug/release bundles and network for its pinned fixtures. `all` runs both.
Every group uses private HOME/state/cache; no development template is needed.
Use a dedicated serial native host, no concurrent agent-vm/msb VMs, compatible
managed runtime policy and no matching GHCR/loopback credentials in the OS
keyring. Never edit operator policy/keychain to make a test pass.

For released-image, first authenticate/download both v0.1.3 archives using the
[source-pinned image-owner release interfaces](https://github.com/gregwebs/agent-vm-images/blob/main/docs/standard-image-releases.md).
This host-side preparation is not an installed-launcher source dependency.
Build an owned clone under `target/verify-265-source`, initializing only
`vendor/microsandbox`; build/test/check there and run `./script/build/macos.sh`.
Relocate the **complete signed bin/lib bundle** outside the checkout, then
remove only that owned disposable clone so its baked Cargo source path is absent.
Record that clone's canonical path in `AGENT_VM_E2E_BUILD_SOURCE_DIR` and bind it
to the candidate through the reviewed build logs; the join asserts that declared
path is absent. This is an operator-provided provenance binding, not detection: the
join cannot tell whether the declared directory really built the candidate, so the
reviewed logs must establish the correspondence. The helper never deletes or moves
anything — only the operator removes the owned checkout after relocation. Never
deinitialize or move the operator's image submodule. On native Linux use locally packed main/platform npm tarballs with
matching reviewed runtime/firmware and versions, installed with
`npm install --prefix OWNED_PREFIX --ignore-scripts` (not global links). Linux npm
installation cannot be demonstrated on macOS.

The released-image gate requires `jq`, `shasum`, and `python3` on `PATH`, and
`node` for an installed npm dispatcher candidate (the Linux route). `node` is
resolved from the caller `PATH` before environment isolation — so an nvm or
`/usr/local` install works — or supplied explicitly in `AGENT_VM_E2E_NODE` as an
absolute path; the dispatcher is then invoked through that vetted interpreter
rather than bypassing it for the native binary.

```bash
AGENT_VM_RELEASE_BIN=/absolute/relocated/bin/agent-vm \
AGENT_VM_E2E_RELEASE_ASSETS_DIR=/short/verified/assets-arm64 \
AGENT_VM_E2E_OTHER_ASSETS_DIR=/short/verified/assets-amd64 \
AGENT_VM_E2E_BUILD_SOURCE_DIR=/absolute/owned/build/clone \
  bash script/test/e2e.sh released-image
# On native amd64 reverse the architecture directories. An npm-installed
# candidate may add AGENT_VM_E2E_NODE=/absolute/vetted/node.
AGENT_VM_BIN=/absolute/debug/bin/agent-vm \
AGENT_VM_DEV_BIN=/absolute/debug/bin/agent-vm \
AGENT_VM_RELEASE_BIN=/absolute/release/bin/agent-vm \
  bash script/test/e2e.sh custom-image
```

The release join runs the actual installed candidate with `env -i`, private
state/cache, no image override/debug seam on first default acquisition, calibrated
failing Docker/buildx decoys, and a guest six-agent probe as the host UID:GID.
It observes the native child graph but retains the index, imports the matching
archive in a different fresh state, tests persistence/retention/override boundaries
and corrupt/opposite-architecture rejection. Logs and private caches are retained
for diagnosis; remove only owned scratch after confirming VMs stopped. It does
not import image-owner Python modules or certify signatures itself: use the
owner's public commands before invoking it and record both-architecture graph
correspondence, artifact hashes and exact candidate/runtime signatures alongside
native logs. Guest `--network none` is not proof of host-offline acquisition.

`tests/default_image_upgrade.rs` exercises the actual CLI and native registry
against genuine OCI bytes on a bound loopback listener, without Docker or a VM.
It isolates HOME/state/cwd and Docker config (empty auths, no helpers), but native
automatic auth may still perform read-only OS keyring lookup, and machine-wide
managed policy still applies. Require a noninteractive credential environment
with no matching loopback credential and absent/compatible managed policy; never
modify host keyring items or policy for tests. Failure preservation hashes old
metadata and referenced EROFS/fsmeta/VMDK artifacts independently, including a
shared-layer failure; native cache completeness alone is not an unchanged-byte
oracle. The custom group also tests explicit release upgrade A→B, an unchanged
live A in a different project, new/warm/offline B, all override boundaries,
failed-acquisition byte preservation and explicitly bootable cached A. Its
registry publication uses empty test-owned Docker auth configuration and only
the operator daemon's Unix endpoint (Colima/Docker Desktop), not copied
credentials/helpers. This requires the same signed launchers, Docker/network and dedicated serial native
host as the retained-default check. It is manual evidence, not CI VM coverage.

`tests/image_build.rs` exercises the actual native importer under fake Docker
without a VM; native e2e is manual, never a substitute for those CLI tests.

The custom-image group's retained-default check is described below.
The custom-image group needs only Docker, the release
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
`--image`/attach branch. Its retained-default check boots the digest-pinned
fixture against a fresh private HOME, asserts the first successful boot *adopts*
the fixture digest into `$HOME/.config/agent-vm/default-image.json`, that a
launcher-recommendation change does not move it, that a warm ordinary launch
makes **zero** registry manifest/tag/blob requests, and that an offline launch
from a cold private cache fails while the record survives. The two
default-recommendation fixtures differ in their guest-visible image stamp, so
the *guest* (not an echoed reference) proves which image booted. This check
requires **two validated launchers**: `AGENT_VM_DEV_BIN` (defaults to
`AGENT_VM_BIN`/the debug bundle; the recommendation seam is debug-only) and
`AGENT_VM_RELEASE_BIN` (default `target/macos/bin/agent-vm`); a missing or
seam-ignoring candidate is a failure, and the release run is required, not
skipped. It also drives a post-acquisition adoption failure (a directory where
the record lock belongs) to prove the guest command does not run and the
sandbox is torn down. These checks are always-run in the custom group, not
opt-in: a missing prerequisite is a failure, not a skip. The suite must run on a
dedicated serial native host with no concurrent launches so process/catalog
absence is meaningful. The custom group always runs against a fresh private
cache under the default msb config sources: it neutralizes an inherited
`AGENT_VM_SHARE_MSB_CACHE`, `AGENT_VM_MSB_CACHE_DIR` and `MSB_CONFIG_PATH`, while #260 uses a separate fresh shared cache. It makes no released-default or lineage
claim.

#### `bash -c`, not `bash -lc`, for in-guest commands

When you pass a command to the guest yourself, pass it through a non-login
shell. The image puts the agent CLIs on `PATH` via `ENV`, but a login shell
sources `/etc/profile`, which overwrites `PATH` and drops
`/opt/agent/.local/bin` (and the claude/opencode prefixes). The trap is that the
tools are present yet report as missing:

```bash
# correct — finds claude/codex/opencode
agent-vm shell --image ghcr.io/gregwebs/agent-vm-standard:v0.1.3 -- bash -c 'claude --version'
# WRONG — "/etc/profile" resets PATH; `command -v claude` prints nothing
agent-vm shell --image ghcr.io/gregwebs/agent-vm-standard:v0.1.3 -- bash -lc 'claude --version'
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

`AGENT_VM_TEST_DEFAULT_IMAGE` is an **initial recommendation**, not an override:
it is parsed with the same immutable-reference rule as production (an
`@sha256:…` OCI reference), it is consulted only when no retained default exists
(never to replace one), and selecting it never persists it — only a successful
acquisition adopts it (issue #261). It is also *display-redacted*: the default
tier never renders its reference in a notice, `doctor`, the
`AGENT_VM_DEBUG_CONFIG` dump, progress or an acquisition error, so a CLI default
test asserts the fixed label/redacted dump plus the record bytes and the
acquisition boundary, while the exact SDK reference is asserted in-memory in the
`boot_image` unit tests (both the selected reference and the built
`SandboxConfig`). A test that wants an *initialized* host writes the record
directly at `$HOME/.config/agent-vm/default-image.json`
(`{"version":1,"image":"<digest ref>"}`).

The default tier is also **tracing-redacted**: the dependency image stack
(`oci_client`, `microsandbox`, `reqwest`, `hyper`, …) logs the reference,
repository name and manifest URL at debug/trace, so `image_log_guard` arms a
process-global filter once the default tier is selected and suppresses every
non-`agent_vm` event for the rest of that invocation. Explicit-source
invocations keep dependency logging unchanged. The CLI regression
(`a_default_tier_invocation_suppresses_dependency_image_tracing`) asserts a
default-tier `RUST_LOG=trace pull` leaks no repository marker and includes a
positive explicit-source control.

#### What runs where

| Harness | Runs on CI | Notes |
|---|---|---|
| `cargo test --workspace` | yes (`ci.yml`) | `#[ignore]`d e2e excluded |
| `cargo check --release -p agent-vm --tests` | yes (`ci.yml`) | type-check only; pins that the release test profile still compiles under the test cfg, since CI's run is the debug profile |
| `script/test/e2e.sh` | **no** | native installed registry/archive joins; custom/all additionally require Apple Silicon and Docker |
| `cargo test … -- --ignored` | **no** | keychain round-trip; operator opt-in, never ordinary CI |
| `script/test/build-workflow.sh` | yes (macOS) | fake-plutil bundle seam, no VM/image sources |
| `script/test/ci-contracts.sh` | yes | runtime provenance, shell guards, offline pin/negative controls, Chrome static and e2e dispatch contracts |
| `script/test/verus-verification.sh` | yes | machine-checked boundary contracts |
| Image source/build/installer/runtime/egress audits | independent image repo CI | migrated; equivalence not verified by launcher CI |

Image versions/installers/locks belong to the independent
[image owner](https://github.com/gregwebs/agent-vm-images), not this Cargo workspace.
The [boot-image ownership decision](docs/adr/0035-consume-user-owned-boot-images.md)
separates that maintenance from runtime selection. Chrome's static example gate
remains here; PR-time Chrome Docker runtime coverage is reduced. Container audits
cannot substitute for native installed launcher/MSB registry/archive boot evidence.

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

Before tagging/releasing a launcher with a changed initial recommendation,
maintainers must review authenticated published registry/archive correspondence
and installed native registry **and** archive joins on both amd64 and arm64.
The v0.1.3 pin must not be released until the missing amd64 join is recorded and
the maintainer promotes the image or explicitly accepts the risk. Local CI and
arm64 evidence may permit merge; they do not complete #265, which stays open
until both architectures are verified. No recurring live adapter is wired into
`release-npm.yml`; tags/manual dispatch are release actions, not merge actions.

## Submodule merges

Both `vendor/microsandbox` and `vendor/agent-vm-images` are submodules.
Image maintenance is reviewed/merged independently before advancing its gitlink;
installed launchers do not depend on that source checkout. For either submodule,
merge inside first when both repositories changed. For example with microsandbox:

When a
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
