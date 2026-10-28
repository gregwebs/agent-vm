# Contributing to agent-vm

How to build agent-vm from source and the conventions for developing it.
See [README.md](README.md) for an overview and [USAGE.md](USAGE.md) for
the end-user reference.

## Coding standards & conventions

- [CODING_STANDARDS.md](CODING_STANDARDS.md) — documentation, bash,
  coding, and security standards for this repo.
- [AGENTS.md](AGENTS.md) — conventions for coding agents (Claude Code,
  Codex, etc.) working on this repo.
- [docs/adr/](docs/adr/) — architecture decision records for the
  important technical trade-offs.
- We use the /verus skill for writing proofs

## Build from source

You ned recursive submodules:

```bash
git submodule update --init --recursive vendor/microsandbox
```

On Apple Silicon macOS, follow the [canonical macOS guide](macos-build.md).
The workflow is directly executable and does not require `just`:

```bash
./script/build/macos.sh
```

While iterating on `agent-vm`'s Rust source, use `./script/build/macos.sh --dev` for a much faster unoptimized build published to
`target/macos-dev/` — see [Fast development build](macos-build.md#fast-development-build).

On Linux, install the host development packages, build the vendored runtime through its supported recipe, and then build agent-vm:

```bash
sudo apt-get install -y libcap-ng-dev libdbus-1-dev pkg-config
(cd vendor/microsandbox && JUST_UNSTABLE=1 just build release)
cargo build --release -p agent-vm
./target/release/agent-vm setup
```

`JUST_UNSTABLE=1` is required because the vendored justfile uses `just`'s
unstable `[script]` attribute.

Source builds use the vendored recipe's `vendor/microsandbox/build/msb`
artifact; `agent-vm setup` acquires and verifies the selected registry image but
does not build `msb`.

Use packaged `agent-vm image build --tag REF --builder NAME CONTEXT` for explicit
Dockerfile builds, or `agent-vm image import --docker REF [--tag REF]` (an archive
needs `--tag REF`) for finished images. Both initialize the same cache as
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
the single source of truth for the pinned release, its digest, and how it is installed.

To run the same check locally, install that release with `script/install-verus.sh`,
which verifies the downloaded asset against the digest pinned in `verus.yml` for
your platform, then add its directory to `PATH` and run from the repository root:

```bash
export PATH="$HOME/.verus/verus-<platform>:$PATH"
CARGO_TARGET_DIR=target/verus cargo verus verify -p agent-vm
```

`CARGO_TARGET_DIR` matters: `cargo verus` sets `RUSTC_WRAPPER`, which is part of
cargo's fingerprint, so sharing one `target/` with ordinary builds makes every switch
a full rebuild. Expect a few minutes the first time and a few seconds thereafter.

The `rust-dev` example custom image in agent-vm-images pre-installs this same pinned
release for an in-VM agent on `linux/amd64`; see its
[README](https://github.com/gregwebs/agent-vm-images/blob/main/examples/layers/README.md#rust-development).
Its Rust/Verus pins mirror `rust-toolchain.toml`/`verus.yml` and are updated in
agent-vm-images after a bump here.

`bash script/test/verus-verification.sh` runs exactly what CI runs: the verification
plus the assertion that it actually verified something, then a pair of throwaway
fixtures proving the verifier can both pass and fail. It reports an installed but
not-on-`PATH` Verus with the `export` line that fixes it, so the two failure modes
are never confused.

### Build identity in `agent-vm --version`

`agent-vm --version` (and `-V`) report the release number **and the source
revision the binary was built from** (issue #335):

```text
agent-vm 0.3.4 (08f515f2c4f8a1c3c9d2b7e6a5f4c3b2a1908f7e)
agent-vm 0.3.4 (08f515f2c4f8a1c3c9d2b7e6a5f4c3b2a1908f7e, dirty)
agent-vm 0.3.4 (08f515f2c4f8a1c3c9d2b7e6a5f4c3b2a1908f7e, state unknown)
agent-vm 0.3.4 (unknown)
agent-vm 0.3.4 (unknown, dirty)
```

The full object id is embedded at **build** time by `crates/agent-vm/build.rs`
as `AGENT_VM_BUILD_VERSION`; nothing looks at Git at runtime, so a copied
binary reports the same line on a machine without Git. The revision is chosen
in this order: a valid full `AGENT_VM_GIT_SHA`, then a valid `GITHUB_SHA`, then
`git rev-parse --verify HEAD` in the build's own repository, then `unknown`.
Overrides must be exactly 40 or 64 hexadecimal characters (lowercased); an
invalid override is ignored with a value-free warning when the probe executes. `dirty` means tracked
files (staged, unstaged, deleted, or tracked changes inside initialized
submodules) differ from HEAD; untracked and ignored files do not mark a build
dirty. Shallow clones, detached HEADs, linked worktrees, packed refs and
submodules all work; a tarball or an unversioned directory nested in another
checkout degrades to `unknown` rather than adopting the outer repository's
identity. A build where metadata could not be measured still succeeds.

The line is build metadata, not authenticity: it is inside the artifact, so it
can be fabricated, and it attests only the tree that was present when the probe
ran. See [ARCHITECTURE.md](ARCHITECTURE.md#runtime-provenance-and-platform-profiles).

```text
build.rs (overrides + Git) → embedded AGENT_VM_BUILD_VERSION
                          → --version / -V (no runtime Git)
                          → harness check + current source status
                            ├─ clean full match → native driver
                            └─ otherwise → retained evidence, refusal
```

#### Default invalidation, and the accepted blind spot

By default the build script emits precise Cargo watchers for every Git-resolved
input that decides the identity: HEAD, the index, packed refs, each link of the
HEAD symbolic-ref chain, the worktree `.git` marker, every tracked path, and
recursively every initialized submodule. With complete, representable discovery,
unchanged builds stay fresh, so `cargo build` is a no-op.

No Git, failed/incomplete metadata queries, unsafe watcher paths, or dangling
tracked symlinks without a bounded parent watcher instead retain safe partial
watchers and emit a fixed warning
plus `build.rs/agent-vm-provenance-always-rerun`. This exceptional default
fallback re-probes and recompiles the launcher every invocation until discovery
recovers. Dangling links are not silently omitted: a localized parent-directory
watch detects deletion, retargeting and replacement. Parents at a worktree root
or enclosing the package/current build outputs instead use the fallback, because
Cargo scans directories recursively and would include generated build trees.
Localized parent watches also invalidate on other changes within that subtree.

Cargo compares mtimes, not file modes or ctime. A mode-only `chmod` of a
tracked file, or replacing a tracked file with a symlink to an older-mtime
target, is therefore invisible by default and the cached clean label can
survive. **This is an accepted limitation**, not a clean-tree guarantee; the
persisted-network harness independently measures the current source status, so
it still refuses to launch from a currently dirty tree.

If you need to close those gaps, opt in explicitly:

```sh
cargo build -p agent-vm                                                # cheap, precise
AGENT_VM_BUILD_PROVENANCE_STRICT=1 cargo build -p agent-vm             # re-probe every build
```

Strict mode adds an unsatisfiable `build.rs/agent-vm-provenance-always-rerun`
dependency, so the probe (and the launcher rustc/link step) run on every build.
Only `unset`, empty, `0` and `1` are accepted; any other value — Unicode or not
— is a hard, value-free error **when the probe runs**. Because Cargo's env
fingerprint collapses absent and non-Unicode to the same absent, an
absent-to-non-Unicode-only transition may reuse a cached default build with no
diagnostic; that residual is accepted. Unset or `0` restores the cheap behavior
after one transition build. **No script, CI job or harness enables strict
mode**, and the persisted-network acceptance does not require it.

`bash script/test/build-provenance-contract.sh` drives the real build script in
owned miniature Cargo/Git workspaces (controls B1–B19; needs the pinned Cargo,
a working Git and Python). It is in `script/test/ci-contracts.sh`.

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

### Smoke boot (start here)

The cheapest boot check: one command, minutes, no Docker, no release assets and no
dedicated host. Run it before concluding anything about the host. It does not
substitute for `e2e.sh` below.

```sh
export AGENT_VM_STATE_DIR=/tmp/avm-smoke/state   # private MSB_HOME (ADR-0004)
export HOME=/tmp/avm-smoke/home                  # private config + credentials
export MSB_PATH="$PWD/vendor/microsandbox/build/msb"   # the msb this build pins
cargo build --release -p agent-vm
./target/release/agent-vm setup                  # acquires the pinned image, then boots a
                                                 # verification sandbox
```

`MSB_PATH` is the part that matters. The `msb` on `PATH` is often a different
installation — Homebrew, a packaged release, another checkout — and agent-vm
requires the exact build it was vendored against. A command that failed against
the wrong `msb` is evidence about that binary, not about the host.

Two failures that look environmental and are not:

* `... reports version "X", but this agent-vm build vendors official Microsandbox Y`
  — wrong `msb`. Point `MSB_PATH` at `vendor/microsandbox/build/msb`.
* `database schema is newer than this msb binary` — a newer agent-vm already
  forward-migrated this state root, and migrations are one-way. Give each build its
  own `AGENT_VM_STATE_DIR`, or recover with `agent-vm doctor --reset-msb-db`.

A smoke boot that fails is a **blocked run**: report the exact command and the
exact error. It is not evidence that VMs cannot boot on this host.

### End-to-end (VM-boot) tests (optional)

Real microVM tests do not run in CI. `script/test/e2e.sh` is the single manual
entry point; its `--help` lists the groups and every input, so they are not repeated
here. Use a dedicated serial native host, no concurrent agent-vm/msb VMs, compatible
managed runtime policy and no matching GHCR/loopback credentials in the OS keyring.
Never edit operator policy/keychain to make a test pass.

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

The released-image gate needs `node` for an installed npm dispatcher candidate (the
Linux route). It is resolved from the caller `PATH` before environment isolation —
so an nvm or `/usr/local` install works — or supplied explicitly in
`AGENT_VM_E2E_NODE` as an absolute path; the dispatcher is then invoked through that
vetted interpreter rather than bypassing it for the native binary.

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

The group pins the vendored runtime this checkout built —
`vendor/microsandbox/build/{msb,agentd,libkrunfw.5.dylib}` — so every selected
row, the boot-free `harness-negative` one included, needs those files on disk. A
signed bundle is not one of them, and `--dev` alone does not produce them: it
writes `build/msb-dev` and `target/macos-dev/`, while only the release build
writes `build/msb`. Build release, then dev, before the first custom-image run:

```bash
./script/build/macos.sh         # writes build/{msb,agentd,libkrunfw.5.dylib}
                                # and the firmware's .source-sha stamp
./script/build/macos.sh --dev   # writes build/msb-dev and target/macos-dev/
```

A native run that selects any `custom-image-direct-terminal-*` row also needs
`AGENT_VM_E2E_TERMINAL_EVIDENCE=<absolute empty directory>`: the driver writes a
JSON receipt plus raw captures per case into an exclusively created per-row child
there, outside `$WORK`, and the run validates the root's emptiness once. Nothing
about the invocation has to hide the caller's terminal — the script detaches each
driver process itself.

`AGENT_VM_BIN`/`AGENT_VM_DEV_BIN` name that debug launcher, which every ordinary
row runs against the release-built runtime; `AGENT_VM_RELEASE_BIN` (default
`target/macos/bin/agent-vm`) is the release launcher the retained-default,
upgrade and host-pin rows run and refuse to skip. `AGENT_VM_E2E_ONLY_ROWS` takes
exact `run_check` names, space separated. An unmatched name now **fails the run**
(the script lists every registered row and exits nonzero), so a filter can no
longer certify zero cases — but a valid filter still does not prove a row was
entered: compare the entered/PASS rows with the list, and select
`harness-negative` explicitly to run the harness self-test.

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
It covers both boot-free paths — `image refresh` (selection, A→B tag movement,
layer reuse, first-pin and default adoption, candidate approval, and the
two-process same-cache/same-reference coordination schedules) and
`image set-default` (explicit target, approved host child, retained record) —
plus failure preservation. A launch never probes a tag: the removed update check
has no test seam and no environment fallback. The suite drives the host pin
store through the compiled CLI with isolated HOME/state/cwd and Docker config
(empty auths, no helpers); native-entry automatic auth may still perform
read-only OS keyring lookup, and machine-wide managed policy still applies.
Require a noninteractive credential environment with no matching loopback
credential and absent/compatible managed policy; never modify host keyring items
or policy for tests. Replacement consent is exercised through a real PTY
(`tests/image_pin_approval.rs`) for yes/no/empty/EOF/interruption, `--yes`, and
nonterminal refusal, with every prompt/child wait bounded at 60s. Failure
preservation hashes old metadata and referenced EROFS/fsmeta/VMDK artifacts
independently, including a shared-layer failure; native cache completeness alone
is not an unchanged-byte oracle. The custom group also tests explicit release
`image set-default` A→B, an unchanged live A in a different project,
new/warm/offline B, all override boundaries, failed-acquisition byte
preservation, and explicitly bootable cached A. Its registry publication uses
empty test-owned Docker auth configuration and only the operator daemon's Unix
endpoint (Colima/Docker Desktop), not copied credentials/helpers. This requires
the same signed launchers, Docker/network and dedicated serial native host as
the retained-default check. It is manual evidence, not CI VM coverage.

`tests/image_build.rs` covers `image build` and `image import` through the
actual native importer under fake Docker without a VM; native e2e is manual, never a substitute for those CLI tests.

The custom-image group's retained-default check is described below.
The custom-image group needs Docker, the vendored runtime built from this
checkout (above), and a launcher binary — **no dev images** — plus network for the
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

The custom group also runs `custom-image-host-pins` (#390, always-run): launch
and pin registry content A before the SDK create, then observe exactly one
approval naming the selected reference and the measured `linux/arm64` platform;
observe guest A and zero registry requests on a warm launch that inherits the
removed advisory variable; reacquire A by digest into a fresh independent
state/cache and confirm neither record's bytes changed; decline (`n`, empty) and
fail a candidate and still boot A; approve B with `--yes` and boot B; and show
that an import alias over the pinned tag cannot move the guest. A live A guest
runs throughout: its PID, its own rootfs content and its booted image stamp must
be unchanged after both update verbs, and a new B guest in the same project must
read back the project-state, declared-state and launch-HOME files that the first
A launch wrote. A local rootfs selection proves only the local/OCI boundary (no
approval lookup, no store write); a boot from it is not claimed here because this
host's SDK rejects a managed `root_disk` for a non-OCI image. Fixture A/B are the
existing `marker-free` and `stamp-present` targets pushed to the run's local
registry, so the guest stamp — not printed text — proves which image booted. It
needs the same two validated launchers and Docker endpoint as the other rows.

#### Evidence location

Manual evidence lives in the PR body and the workflow `verifications.md`
artifact: row/check ID, exact command, candidate and runtime identities (path,
version, hash/signature, msb + libkrunfw), host/platform, A/B digests, expected
vs actual observable, and log paths. Do not add a `docs/verification/` directory
or a new tracked evidence convention; a blocked row is recorded as
`BLOCKED: <exact command> -> <exact error>`, never as a pass.

#### Default-deny egress harness

`script/test/egress-default-deny.sh` is the serial native networking harness;
`e2e.sh` does not certify networking. Its boot-free companion is
`bash script/test/egress-default-deny-contract.sh`. Mutation controls run with
`python3 script/test/egress-mutations.py --evidence /absolute/owned/log-directory`
(pinned Verus on PATH); only disposable source copies are changed.

The cargo controls build that copy in the harness's own target dir
(`target/egress-mutations/target`), and the proof controls use `target/verus`,
which their gate cleans on every run. Every compiling control then removes the
package's artifacts with `cargo clean -p agent-vm` before it runs: fingerprints
ignore the copy's path, so a target built elsewhere otherwise looks fresh and
re-executes a stale binary, letting a mutation confined to a test file
"survive" (#327). A control whose mutated source cargo reports as fresh, or as
never compiled, is a **harness** failure rather than a surviving mutant. Both
target dirs are warmed before the matrix, so a cold dependency build is not a
control timeout; the first run pays that build once. `results.json` records each
control's wall time, and the run prints its total. Concurrent runs are refused
rather than interleaved.

On a dedicated native macOS Apple Silicon host, build the debug bundle and
supply authenticated, verified native v0.1.3 release assets:

```bash
./script/build/macos.sh --dev
AGENT_VM_BIN="$PWD/target/macos-dev/bin/agent-vm" \
AGENT_VM_E2E_RELEASE_ASSETS_DIR=/absolute/verified/assets-arm64 \
  bash script/test/egress-default-deny.sh --smoke
# Repeat without --smoke for the full matrix.
```

Require no concurrent VMs, compatible managed policy, no matching GHCR or
loopback credentials in the OS keyring, a reachable host RFC1918/CGN address,
and firewall access for TCP 18080/18081, UDP 19090/18080 and proxy 18888.
Public HTTP/DNS controls must work before a denial is counted. Guest tools are
checked at preflight; paired IPv6/rebind groups report NOT RUN when unavailable.
On macOS, firewall access must cover the **host Python interpreter** serving the
fixtures, not just the launcher. A blocked interpreter can accept a LAN socket
and then fail with `Socket is not connected`, while loopback controls pass.
Check the interpreter's incoming-connection status; use an already-allowed
interpreter on the harness's `PATH` rather than changing operator firewall rules.
Never change operator DNS, firewall, policy or keychain to make a test pass.

The harness creates private HOME/state/cache and retains `summary.tsv`,
per-case logs and `owned.jsonl` under its printed owned work root. Preserve
commands, candidate/runtime identity and release-asset hashes alongside them.
Smoke includes NR1/NR2 (actual default Pi `--version`, unmet/all-covered built-in
request stderr) and NR3 (default shell marker, no request inheritance), alongside
LC1/HC1/I1 positive controls and D1/L1 denials. NR rows record native diagnostics,
not packet enforcement or provider-login success. Retain raw NR logs/version
labels and complete cleanup receipts. For #328, missing native prerequisites
are V7 **NOT RUN**, which blocks merge/release acceptance until exact-candidate
external evidence is supplied. Copilot inventory remains pending #340; see
[endpoint evidence](docs/default-tool-network-requests.md).

Cleanup is bounded and identity-checked; inspect reported survivors before
removing only owned scratch. Smoke is not full evidence. This harness does not
certify Linux: native Linux testing, runtime capability admission and combined
platform evidence remain outstanding under [#302](https://github.com/gregwebs/agent-vm/issues/302).

#### Config-dir guard live check

On a dedicated native host with no concurrent VMs:

```bash
./script/build/macos.sh --dev
AGENT_VM_BIN="$PWD/target/macos-dev/bin/agent-vm" \
AGENT_VM_LIVE_TEST_IMAGE=VERIFIED_NATIVE_IMAGE \
  bash script/test/config-dir-guard-live.sh
```

The script uses private HOME and state, explicit image selection, and retains
logs under its printed root. The first boot acquires into private state unless
the opt-in shared cache is enabled: `AGENT_VM_SHARE_MSB_CACHE=1` selects it and
`AGENT_VM_MSB_CACHE_DIR=<path>` sets its location — the flag is checked first,
so `AGENT_VM_MSB_CACHE_DIR` alone still acquires privately. Record the image digest,
binary hash and per-row results. It checks link laundering refusals, read-only
and fork controls, home/mount refusals and a case-variant prospective layout.
Its boot-free companion is
`bash script/test/config-dir-guard-contract.sh` (guest snippets plus the
socket-path budget; host-only, never native evidence). CI syntax-checks/lints
the script and runs the companion but **does not run native VM rows**.

#### Persisted network live check

On a dedicated macOS Apple Silicon host with no concurrent VMs:

```bash
# Build from the committed source you intend to verify: the candidate must
# report that exact clean commit, so build after committing, not before.
./script/build/macos.sh --dev
AGENT_VM_BIN="$PWD/target/macos-dev/bin/agent-vm" \
AGENT_VM_LIVE_TEST_IMAGE=VERIFIED_NATIVE_IMAGE \
  bash script/test/persisted-network-live.sh
```

Use an explicit verified native image (for example an authenticated immutable
standard-release reference). The script uses private HOME/state, short
socket-safe paths and serial owned launches.

Before any native work the harness asserts provenance. It validates that the
harness source is its own Git top level (so a tarball nested in another
checkout is refused), records `tracked-status.txt` by direct redirection of
`git status --porcelain --untracked-files=no --ignore-submodules=untracked`,
captures the candidate's stdout byte-for-byte into `binary-version.txt` and
runs `script/test/lib/build-provenance.py`
(`binary-version.txt`, full HEAD, `tracked-status.txt`). The checker accepts
**only** a known full commit equal to HEAD, a self-reported `clean` state, and
an empty tracked-status file. Dirty, unknown, mismatched or multiline output,
and a currently dirty tracked source, are rejected with a retained receipt
(`provenance-check.txt`) and **zero** scratch allocation or driver launch. The
acceptance does not depend on the candidate's build mode.

The independent source-status check is what catches a stale-clean default-mode
binary after a mode-only `chmod` of the source (which mtime watchers miss): the
freshly measured `tracked-status.txt` is dirty even though the embedded label
says `clean`. Once the source is restored clean, the self-report cannot prove
the binary's historical build tree; that limitation is inherent to an embedded
identity.

The evidence directory is self-identifying. `source.txt` records the commit,
the full `git status --porcelain` (never empty while unrelated untracked files
exist) and the tracked status above, which is empty exactly when the tracked
tree matches the commit. `tree.diff` holds the tracked
changes themselves and `tree.diff.sha256` their digest, so a reader can tell
whether the rows came from the committed source. `harness.sha256` is the hash
of **every** file under `script/test/` (the driver and its imports, the sourced
helpers, the guest probes and the oracles), enumerated from the tree rather
than hand-listed. `binary.sha256` and `binary-version.txt` identify the binary
and `image.txt` the image. The run also records stderr, request-log offsets,
inventories and identity-checked cleanup receipts. Timeout, malformed probe
output or cleanup survivors are failures, never policy denials. Scratch is
removed only after successful cleanup; failure retains it for diagnosis.

PN1 denies by default; PN2 reaches with saved host authority; PN3 disables it
with `=false`. PN4-A plants `[network]` through a tools-only dotfile symlink,
PN4-B refuses P2 before guest execution/state, and PN4c reaches after replacing
the link with a verified regular copy. PN5 refuses a HOME launch. The bounded
probe uses `egress-probe.sh::http_get` and serves `/r/marker` with exact
`receipt marker` bytes. Request deltas, not a bare connection, decide reach.
**PN4-A/B/PN4c must pass or receive a written maintainer waiver before #305
is complete.** Without that evidence a PR says “Part of #305”, not “Closes #305”.

`bash script/test/persisted-network-contract.sh` dispatches to
`script/test/lib/persisted-network-contract.py`, which exercises the write/probe
snippets on a host-only stand-in and joins the shared diagnostic TSV to
boot-free CLI tests, then runs the **actual** live shell against a harmless
driver stub to prove acceptance, rejection, receipt-before-allocation, cleanup
and status propagation (`build-provenance.py` unit controls plus P6–P10). It is
in `ci-contracts.sh`; it is **not** guest-authorship or native enforcement
evidence. CI checks the live script's syntax/lint only.
See [ADR-0040](docs/adr/0040-persisted-user-network-authority.md).

#### Config mounts live check

This is the only native evidence that a user-config `mounts` list actually
reaches a guest with the declared mode. Boot-free fake-`msb` tests are **not**
a substitute for it: they never boot a VM.

On a dedicated macOS Apple Silicon host with no concurrent VMs:

```bash
# Build from the committed source you intend to verify: the candidate must
# report that exact clean commit, so build after committing, not before.
./script/build/macos.sh --dev
AGENT_VM_BIN="$PWD/target/macos-dev/bin/agent-vm" \
AGENT_VM_LIVE_TEST_IMAGE='ghcr.io/OWNER/IMAGE@sha256:<64 hex>' \
  bash script/test/config-mounts-live.sh
```

Prerequisites, all rejected with a receipted non-zero exit before any scratch is
allocated:

- a dedicated idle host: Darwin on arm64, with no running `agent-vm` or `msb`;
- `AGENT_VM_BIN`, absolute and executable, built from the committed PR head;
- `AGENT_VM_LIVE_TEST_IMAGE`, **digest-pinned** (`…@sha256:<64 hex>`): the first
  launch acquires it into the run's private cache, and a tag would make the rows
  depend on what the registry serves later;
- the bundle's sibling `msb` and `../lib/libkrunfw.5.dylib` (the harness passes
  `MSB_PATH` explicitly and builds its environment from scratch, so an inherited
  `MSB_LIBKRUNFW_PATH`, `AGENT_VM_MSB_CACHE_DIR` or `MSB_CONFIG_PATH` cannot
  redirect the launch).

The first launch also needs a reachable registry to acquire that image. Nothing
can establish reachability before scratch exists — a probe would be a second,
different network path from the acquisition — so an unreachable registry
surfaces as that first launch's own error, with its receipted evidence retained.

The run asserts provenance before it does any native work: the harness source
must be its own Git top level, `tracked-status.txt` is captured by direct
redirection, the candidate's stdout is captured byte-for-byte as
`binary-version.txt`, and `script/test/lib/build-provenance.py` accepts **only**
a known full commit equal to HEAD, a self-reported `clean` state and an empty
tracked-status file. A rejection retains `provenance-check.txt` and allocates no
scratch.

The retained evidence set is self-identifying: `source.txt`,
`tracked-status.txt`, `all-status.txt`, `tree.diff` + `tree.diff.sha256`,
`harness.sha256` (every file under `script/test/`), `binary-version.txt`,
`candidate.txt` (realpath, SHA-256, `codesign -dv --verbose=4`), `runtime.txt`
(the sibling `msb` and `libkrunfw`: realpath, SHA-256, signature, `msb
--version`), `host.txt` (`sw_vers`, `uname -a`, `hw.model`/CPU), `image.txt`,
`image-pins.json` (the launch's own first pin, whose recorded reference and
manifest digest must **contain** the requested digest — a containment check,
deliberately not equality; see `script/test/lib/config-mounts.py`),
`summary.tsv` with a retained expected-versus-actual row per
row, per-launch logs, `owned.jsonl` and `errors.json`.

CM-N1 proves a `:ro` default is readable and unwritable while the host tree is
unchanged; CM-N2 proves a `:rw` default writes through to the host; CM-N3a/b
prove a `:fork` default holds the guest's own write across launches and never
synchronizes with the host; CM-N4 proves `--no-config-mounts` removes all three
while the project mount still works (a positive control that the guest ran);
CM-N5 proves an equivalent `--mount` reuses the config fork's identity.

The named-mount-set rows (#397, `[mount_sets]`) continue the same run over the
same owned synthetic `home/cm/{ro,rw,fork}` fixtures, after the N rows' cleanup:

- **CM-S1** — the same file with a `[mount_sets]` table and **no** `mounts`
  list: all three set mounts are absent while the project marker is present
  (definitions alone mount nothing).
- **CM-S2** — `mounts = ["all-set"]` prepended before the table: the `:ro` set
  leaf reads its exact seed and both write attempts are denied, the `:rw` leaf
  writes its exact marker through to the host, and the `:fork` leaf reads the
  copy CM-N3a wrote.
- **CM-S3** — the same file with `--no-config-mounts`: all three absent, project
  marker visible.
- **CM-S4** — the same file with `--no-config-mounts --mount all-set`: the same
  observable access and modes as S2, no unrelated mount, and the fork still
  holds the earlier `guest-fork` rather than the host's later write.

The tool-mount rows (#396, `[[tools]]`'s own `mounts`) are a separate synthetic
topology over the same owned fixtures, after the S rows' cleanup. Every synthetic
tool executes `bash` with a fixed probe argv — they test catalog selection, not an
image's installed agent version or login state — and the probe itself is the guest
program. The two invocation forms are recorded verbatim in each row's
`<row>-command.json`:

```bash
# A tool row: the tool's own `command`/`args` run the probe with one phase token.
agent-vm --no-git --image "$IMAGE" <tool> <phase>
# A declared/fallback shell row: separate argv tokens, and the product builds
# interactive bash's `-c` argument itself (run::inner_argv → shell::guest_script_word).
agent-vm --no-git --image "$IMAGE" shell bash ./guest-cm-probe.sh <phase>
```

The probe prefixes every path with `CM_ROOT` and defaults the Pi home to the real
`$HOME`; the boot-free companion below points `CM_HOME` at a synthetic home, which
is the only reason the same statements are runnable without a VM. Fork identity is
compared **within the Pi lineage** (manifests whose guest destination ends in
`/.pi`) so these rows can share the state root with the `CM-N`/`CM-S` fork without
weakening either set's evidence.

- CM-T1 `plain` — no automatic mount path, no Pi-fork-only marker; the project
  marker is present, and no Pi fork was initialized.
- CM-T2 `claude` — the shared agent parent is readable and writable, the child
  and the separate read-only directory are readable and unwritable, and no Pi
  marker appears.
- CM-T3 `pi` — the same agent topology *inherited* through `tools`, plus the Pi
  fork: the guest reads `pi-seed`, writes `pi-guest`, sees neither protected
  synthetic file, and creates a guest-only file. CM-T3-host checks afterwards
  that the host Pi source is still `pi-seed`, the protected sources are unchanged,
  the guest-only file is absent on the host, the writable marker came through and
  the read-only digests are unchanged.
- CM-T4 `bridge` — after a host-only source mutation, the guest still reads
  `pi-guest` and its guest-only file, proving the inherited fork is reused and
  never re-synchronized.
- CM-T5 declared `shell` — its omitted `tools` wildcard sees the fork and the
  agent topology, with the same permitted and denied writes.
- CM-T6 declared `shell` with `tools = []` — the inherited paths and the Pi marker
  are gone, while its own list and a user-wide default remain readable and
  unwritable.
- CM-T7 fallback `shell` — the declared shell removed, custom catalog kept: no
  user tool is referenced, and the deliberately user-wide default is still there.
- CM-T8 opt-out `pi` and declared `shell` — no defaults, no shell-own, no
  inherited agent mounts and no Pi marker; the project marker is present.
- CM-T9 opt-out plus explicit `--mount agent` — only the explicit agent topology
  returns, with the same rw/ro operations, and no tool is inferred from set
  selection.
- CM-T10 equivalent explicit Pi fork — opt-out plus an absolute CLI fork
  declaration reads `pi-guest` and the guest-only file with the same manifest
  identity.
- CM-T11 default/set/tool equivalence — the same Pi declaration selected as a
  top-level default or through a nested set reads `pi-guest` with unchanged fork
  identity and no reseed.

Absence rows test the synthetic fork-only marker and contents, never the existence
of `$HOME/.pi`: the compiled generic `.pi` guest-home link exists even when the
fork is not selected. The read-only-child assertions are about operations at that
mounted destination, not a promise of isolation from a writable ancestor (see
ADR-0048's alias/rename caveat), so a failing probe is never "fixed" by changing
the parent to read-only or by weakening the check to a serialized-config
assertion.

The guest probe renders these phases even on failure and the driver compares
exact whole lines, so a partial mount cannot pass. After proven cleanup the host
oracle also asserts the read-only tree's digest is unchanged, the `:rw` marker is
on the host, the host-side fork marker is still the later value, and there is one
fork directory and manifest identity with no initialization/reseed notice. These
rows are the only native evidence that a set selection changes *actual* mounted
access; boot-free tests cannot close them. As with the N rows, a missing
prerequisite is a receipted `BLOCKED:` line, and native acceptance for #397 stays
outstanding until S1–S4 pass.

Teardown is bounded and identity-checked: every launch is an owned process
group, stopping is TERM → bounded wait → KILL, survivors are signalled only
where their recorded identity still matches, catalog and socket-path absence is
verified, and a fixture source is written or removed only after the previous
launch's cleanup proved absence. On failure the owned scratch (with the fixture
sources) is retained and its path printed; it is never `rm -rf`ed by the
harness.

**Every attempt gets a fresh evidence directory.** The wrapper accepts an existing
directory and the driver overwrites row receipts while appending `summary.tsv`, so
reusing one would destroy a failure record:

```bash
evidence="$(mktemp -d /tmp/avm-native/evidence-run.XXXXXX)"
AGENT_VM_BIN=… AGENT_VM_LIVE_TEST_IMAGE=… AGENT_VM_CM_EVIDENCE="$evidence" \
  bash script/test/config-mounts-live.sh
```

If the first catalog observation races migration (the ~3.4 ms race recorded in
ADR-0048), keep the failure and retry with **identical** candidate, image and
config fixture inputs but a **new empty** evidence directory. A changed candidate
or fixture starts a new comparison, not an identical retry. Never report that
observation race as native enforcement failure, and never erase it.

If a prerequisite is missing, the PR body records

```text
BLOCKED: AGENT_VM_BIN=… AGENT_VM_LIVE_TEST_IMAGE=… bash script/test/config-mounts-live.sh -> <exact first error line>
```

and states that the native enforcement evidence (for #394, #396 and/or #397,
whichever rows were blocked) is **outstanding**, so the PR says "Part of #394" /
"Part of #396" / "Part of #397", not "Closes …". Existing #394/#397 receipts are
not retroactive evidence for the tool-mount rows. macOS arm64 is what these rows
cover; Linux/amd64 native evidence remains outstanding rather than implied.

`bash script/test/config-mounts-contract.sh` is the boot-free companion: it runs
the guest probe against a host-only synthetic layout (permission and negative
controls included) and asserts that the wrapper rejects a relative
`AGENT_VM_BIN` and a non-digest image without allocating scratch. It is in
`ci-contracts.sh`; it is host-only and **never** native evidence.

#### `bash -c`, not `bash -lc`, for in-guest commands

When you pass a command to the guest yourself, pass it through a non-login
shell. The image puts the agent CLIs on `PATH` via `ENV`, but a login shell
sources `/etc/profile`, which overwrites `PATH` and drops
`/opt/agent/.local/bin` (and the claude/opencode prefixes). The trap is that the
tools are present yet report as missing:

```bash
# correct — finds claude/codex/opencode
agent-vm --image ghcr.io/gregwebs/agent-vm-standard:v0.1.3 shell bash -c 'claude --version'
# WRONG — "/etc/profile" resets PATH; `command -v claude` prints nothing
agent-vm --image ghcr.io/gregwebs/agent-vm-standard:v0.1.3 shell bash -lc 'claude --version'
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

Several debug-only seams are compiled out of release builds: `AGENT_VM_TEST_CREDENTIAL`
(credential provisioning), `AGENT_VM_TEST_DEFAULT_IMAGE` (the boot-image
default slot, so a boot-free CLI test that falls through to the default does not
start a real multi-GB pull), and the two coordination gates below
(`AGENT_VM_TEST_ACQUIRE_GATE`, `AGENT_VM_TEST_PIN_GATE`). None is read by a
release build; tests pin each release exclusion.

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
`SandboxConfig`). The one intentional exception is `agent-vm image show`
(`tests/image_show.rs`), where the user explicitly asks to inspect the
selection: that surface is expected to print the full escaped reference and its
provenance, and every other default-tier surface stays redacted. A test that wants an *initialized* host writes the record
directly at `$HOME/.config/agent-vm/default-image.json`
(`{"version":1,"image":"<digest ref>"}`).

The default tier is also **tracing-redacted**: the dependency image stack
(`oci_client`, `microsandbox`, `reqwest`, `hyper`, …) logs the reference,
repository name and manifest URL at debug/trace, so `image_log_guard` arms a
process-global filter once the default tier is selected and suppresses every
non-`agent_vm` event for the rest of that invocation. Explicit-source
invocations keep dependency logging unchanged. The CLI regression
(`a_default_tier_invocation_suppresses_dependency_image_tracing`) asserts a
default-tier `RUST_LOG=trace image refresh` leaks no repository marker and includes a
positive explicit-source control.

The host approval store is a third seam. A test that wants a pre-approved host
writes `$HOME/.config/agent-vm/image-pins.json` (strict version 1, one entry per
canonical reference + platform) through the compiled CLI or by copying
CLI-produced bytes; a hand-built store must satisfy the same strict schema, or
the test is asserting corruption, not approval. Pin lookups take a shared lock
and create nothing, so an absent store is a legal read-only state; mutations
create the directory and lock. A changed pin needs `--yes` or both stdin and
stderr on a real PTY. Native cache/receipt bytes are never approval, and a
test must not delete approvals to work around a cache problem.

#### Acquisition and publication test fixtures

Image lifecycle tests drive the compiled CLI against a deterministic loopback
OCI server and the real native cache; nothing about acquisition is mocked. Three
seams make the coordination behaviour orderable without sleeps:

- `AGENT_VM_TEST_ACQUIRE_GATE` (debug only) is a Unix socket reporting
  stage names. The protocol is deterministic and single-reply. Always reported:
  `before-lock`, `lock-contended`, `snapshot`, `native-ok`, `before-restore`,
  `after-restore`, and — whichever consumer is running — `before-sdk-consume`
  (a launch has validated its cache entry and is about to hand it to the SDK)
  and `create-returned` (the create call returned, so the shared barrier is
  about to be released). `publication-contended` is emitted once, only after
  a real shared/exclusive publication-lock attempt contends; it blocks for the
  same reply before resuming the lock wait. `AGENT_VM_TEST_ACQUIRE_GATE_DETAIL`
  additionally enables the observation-only `cache-hit`, `cache-validated` (a
  complete, associated cached entry was validated and nothing has been
  republished for it yet — the one window in which a peer's tag publication is
  still ahead of this consumer), `canonical-readback` and `receipt` stages. A
  missing or malformed reply is a failure, never a skip.
- `AGENT_VM_TEST_PIN_GATE` is the same shape for the host approval transaction.
  It reports `candidate-ready`, `before-pin-lock`, `pin-locked`,
  `before-intent-save`, `intent-saved`, `default-saved`, `before-pin-save` and
  `pin-committed`, and accepts `continue`, or `fail-before-save` only at the two
  write-preceding stages (the seam is one atomic save, so a rename fault is not a
  separate stage). Stages name no reference, digest or
  path, so a gate can neither forge content nor grant approval. Release builds
  ignore the variable entirely; a test pins that exclusion.
- The publication barrier is a real `flock`; tests probe it with an independent
  descriptor instead of inferring ownership. One row holds it shared behind a
  stalled acquisition and proves an unrelated warm launch still reaches create;
  another pauses a validated launch and proves an import blocks, with the
  reverse order also asserted.

`tests/support/fake_msb.rs` installs a **complete runtime pair**: a fake `msb`
plus the adjacent `libkrunfw` the runtime resolver requires. A shell script is
enough for boot-free acquisition (`StrictAcquisition`: `--version` only,
everything else fails 93) but not for a launch: the SDK reads the Cargo version
from an embedded executable section to select its launch contract. Tests that
must reach real native cache consumption use `install_launch_binary`, which
compiles a tiny fixture with `rustc`; it answers `--version` and
`__launch-protocol` exactly and **fails every actual launch**. It is evidence of
cache consumption, never of a working VM. Guest/boot evidence stays manual in
the custom-image e2e group; `setup --no-verify` is the boot-free setup path,
while ordinary `setup` intentionally creates a verification guest.

#### What runs where

| Harness | Runs on CI | Notes |
|---|---|---|
| `cargo test --workspace` | yes (`ci.yml`) | `#[ignore]`d e2e excluded |
| `cargo check --release -p agent-vm --tests` | yes (`ci.yml`) | type-check only; pins that the release test profile still compiles under the test cfg, since CI's run is the debug profile |
| `script/test/e2e.sh` | **no** | native installed registry/archive joins; custom/all additionally require Apple Silicon and Docker; `custom-image` includes the always-run host-pin A/B rows |
| `cargo test --test image_pin_approval` | yes (`cargo test -p agent-vm`) | boot-free compiled-CLI approval matrix: PTY yes/no/empty/EOF/interruption, `--yes`, nonterminal refusal, frozen candidate, CAS/stale revision, journal recovery, cache-loss digest reacquisition. No VM evidence |
| `cargo test … -- --ignored` | **no** | keychain round-trip; operator opt-in, never ordinary CI |
| `script/test/single-binary-contract.sh` | yes (`ci.yml`) | fake payload; lone copy, reuse, concurrency, tamper, unwritable, rejected-launch state, and `image show` unpacking nothing (C12); the only `embedded-runtime` clippy pass, which is what lints the payload build module |
| `cargo test --test image_show` | yes (`cargo test -p agent-vm`) | boot-free black-box `image show` matrix: precedence, provenance, damaged/unused fallback, escaping, help/argument surface, and no runtime/cache/state/network observation. No VM evidence |
| `script/test/build-workflow.sh` | yes (macOS) | fake-plutil bundle seam, no VM/image sources |
| `script/test/ci-contracts.sh` | yes | runtime provenance, shell guards, offline pin/negative controls, Chrome launcher-path agreement and e2e dispatch contracts |
| `script/test/persisted-network-contract.sh` | yes (`ci-contracts.sh`) | host-only snippet controls, checker P1–P5 and live-shell P6–P10; no native evidence |
| `script/test/build-provenance-contract.sh` | yes (`ci-contracts.sh`) | real Cargo/Git build-identity controls B1–B19; no native evidence |
| `script/test/persisted-network-live.sh` | **no** | dedicated macOS arm64 PN rows; required evidence or written waiver |
| `script/test/config-mounts-contract.sh` | yes (`ci-contracts.sh`) | host-only probe/preflight controls; no native evidence |
| `script/test/config-mounts-live.sh` | **no** | dedicated macOS arm64 CM rows: candidate + runtime (`msb`, `libkrunfw`) identity, host/platform, digest, expected vs actual; required evidence or a `BLOCKED:` line |
| `script/test/verus-verification.sh` | yes | machine-checked boundary contracts |
| Image source/build/installer/runtime/egress audits | independent image repo CI | migrated; equivalence not verified by launcher CI |

Image versions/installers/locks belong to the independent
[image owner](https://github.com/gregwebs/agent-vm-images), not this Cargo workspace.
The [boot-image ownership decision](docs/adr/0035-consume-user-owned-boot-images.md)
separates that maintenance from runtime selection. Chrome example content checks moved
with the example to agent-vm-images; only launcher path agreement remains here.
PR-time Chrome Docker runtime coverage is reduced. Container audits
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

`agent-vm`'s private microsandbox home is a single flat directory under
`$AGENT_VM_STATE_DIR` (default `$HOME/.local/state/agent-vm`), shared by *every*
`agent-vm` build on this host — it is not namespaced by worktree or branch. Because
sea-orm migrations are one-way, switching between worktrees that vendor different
microsandbox schemas trips a fail-fast guard; the error names the fix, and
[ADR-0004](docs/adr/0004-single-shared-msb-home.md) has the rationale.

If you're building and running `agent-vm shell`/`run` from more than one worktree in
the same session (or expect to), set `AGENT_VM_STATE_DIR` to a distinct path per
worktree first, e.g.
`export AGENT_VM_STATE_DIR="$HOME/.local/state/agent-vm-$(basename "$PWD")"`.

On macOS, keep that path short: microsandbox binds each sandbox's control/agent
socket under it, and `sun_path` is limited to ~103-108 bytes, so a long worktree or
branch name folded into the path above can overflow it. The socket-path preflight
fails closed rather than silently truncating; pick a shorter override, e.g. `~/.avm`.



## Release / version bump

Every feature PR bumps the workspace version.

Provider/integration or image-source upgrade checklist:
- **Default-tool endpoint evidence:** the upgrade author audits exact names,
  TLS ports, roles, auth/feature conditions and excluded candidates against the
  pinned versions in [the canonical evidence](docs/default-tool-network-requests.md).
  Update declarations and independent expectation tests with the evidence.
  The release PR reviewer signs off before release approval. Recheck endpoint
  bug reports too; Copilot remains an explicit #340 gap, not a certified row.
  Launcher metadata does not automatically follow image-source bumps.

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
installed launchers do not depend on that source checkout. For either submodule, when a worktree changes both the agent-vm code and the
vendored code, merge inside the submodule **before** merging the superproject —
otherwise the superproject merge will conflict on the gitlink and you'll have to
redo the submodule merge anyway. Pattern:

1. `cd vendor/microsandbox && git merge --no-ff <subm-feature-branch>`
2. `cd ../.. && git add vendor/microsandbox` (bumps the gitlink)
3. `git merge --no-ff <agent-vm-feature-branch>`
   (resolves the gitlink conflict to the merge SHA from step 1)

If the feature branch lives in a separate git worktree, the
submodule branches in that worktree's `.git/modules/...` are not
visible from the main worktree. Push them across with
`git -C <worktree>/vendor/microsandbox push <main-worktree>/.git/modules/vendor/microsandbox <branch>:<branch>`
before attempting the submodule merge.
