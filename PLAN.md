# agent-vm — PLAN

Roadmap for the Rust + [microsandbox](https://github.com/wirenboard/microsandbox)
`agent-vm`. The phase-by-phase roadmap (Phases 0–9) was retired once the
rewrite became feature-usable; per-phase history lives in `git log`, the
design rationale in `ARCHITECTURE.md`, and the individual decisions in
`docs/adr/` (ADR-0001 … ADR-0010). This file tracks only **what is left to
do** to reach v1.

`main` *is* the Rust rewrite — the original Bash `agent-vm` (`claude-vm.sh`)
is no longer in any branch of this repo. Where an item below refers to
"the original", it means that retired script; the behaviour is described
rather than cited by line, since the file is not here to cite.

## Where the rewrite stands today

Everything below is working and verified for daily use. This file does not
describe these features — that is what the other two docs are for, and
duplicating them here is how this section went stale before. **How to use it**
lives in [USAGE.md](USAGE.md); **why it is built that way** lives in
[ARCHITECTURE.md](ARCHITECTURE.md) and [docs/adr/](docs/adr/). This table is
only an index, so the roadmap below has a fixed starting point.

| Capability | How to use it | Why it works that way |
|---|---|---|
| Agents `claude` / `codex` / `opencode` / `copilot` / `shell`, per-project microVM, project bind-mounted at its host path | [Subcommands](USAGE.md#subcommands) | [Sandboxes and sessions](ARCHITECTURE.md#sandboxes-and-sessions) |
| Host-rooted secrets — real tokens never enter the VM, fail-closed on a missed capture | [Credentials](USAGE.md#credentials) | [Credentials](ARCHITECTURE.md#credentials), [ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md) |
| OAuth refresh MITM for Claude + Codex, single-flighted per provider | [Credentials](USAGE.md#credentials) | [OAuth refresh MITM](ARCHITECTURE.md#the-oauth-refresh-mitm) |
| gh / git auth reused from the host, per-launch GitHub repo allow-list | [Credentials](USAGE.md#credentials) | [ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md) |
| Host-credential security snapshot (SHA-256 at launch, re-checked on exit) | [Credentials](USAGE.md#credentials) | [Security snapshot](ARCHITECTURE.md#host-credential-security-snapshot) |
| Network egress: `--publish` / `--auto-publish` / `--allow-egress` / `--allow-lan` / `--allow-host` | [Ports & egress](USAGE.md#ports--egress) | [ADR-0009](docs/adr/0009-adopt-origin-main-network-features.md) |
| Extra mounts with `ro` / `rw` / `follow-links` | [Launch flags](USAGE.md#launch-flags) | [Extra mounts](ARCHITECTURE.md#extra-mounts-ro-rw-follow-links) |
| Non-root guest by default, `--root` to opt out | [Guest user](USAGE.md#guest-user----root) | [ADR-0001](docs/adr/0001-non-root-guest-via-native-user.md), [ADR-0002](docs/adr/0002-mirror-host-home-and-username.md) |
| Project tooling layers (`.agent-vm/layers/*`, plus any `--layer DIR`, an ordered chain), incl. the Chrome DevTools MCP layer | [Project tooling layers](USAGE.md#project-tooling-layers), [Chrome DevTools MCP](USAGE.md#chrome-devtools-mcp) | [ADR-0003](docs/adr/0003-project-tooling-layers.md) |
| Project hook (`.agent-vm.runtime.sh`) | [Project hook](USAGE.md#project-hook) | — |
| Clipboard exchange | [Clipboard](USAGE.md#clipboard) | [Clipboard exchange](ARCHITECTURE.md#clipboard-exchange) |
| `agent-vm-ccusage` — token/cost across host *and* sandbox sessions | [Token usage](USAGE.md#token-usage-across-host-and-sandbox) | [`agent-vm-ccusage`](ARCHITECTURE.md#agent-vm-ccusage) |
| `agent-vm msb <args…>` passthrough and `agent-vm doctor` | [Checking what agent-vm can see](USAGE.md#checking-what-agent-vm-can-see) | [State operations](ARCHITECTURE.md#state-operations-msb-passthrough-and-doctor) |
| Image distribution: `setup`, `pull`, opt-in update check, image-API-version lock | [Image release cadence](USAGE.md#image-release-cadence) | [The base image](ARCHITECTURE.md#the-base-image) |
| Opt-in shared OCI image cache | [Shared microsandbox image cache](USAGE.md#shared-microsandbox-image-cache) | [Shared OCI image cache](ARCHITECTURE.md#shared-oci-image-cache-opt-in) |
| Official crates.io `msb_krun` 0.1.32 runtime (no fork), provenance-checked | — | [ADR-0006](docs/adr/0006-adopt-clean-v0.6.15-baseline.md), [runtime proof](ARCHITECTURE.md#runtime-provenance-and-platform-profiles) |
| microsandbox v0.6.15 + one-way state migration + forward-migration preflight | [Recovering from a forward-migrated db](USAGE.md#recovering-from-a-forward-migrated-microsandbox-db), [Upgrading older state](USAGE.md#upgrading-from-an-older-agent-vm-pre-0615-state) | [ADR-0008](docs/adr/0008-migrate-0.5.7-state-to-v0.6.15.md), [ADR-0004](docs/adr/0004-single-shared-msb-home.md) |
| Sandbox liveness: idle detection, runtime-exit handling | — | [Sandbox liveness](ARCHITECTURE.md#sandbox-liveness-idle-detection-and-runtime-exits), [ADR-0007](docs/adr/0007-heartbeat-keep-alive-and-runtime-exit-reporting.md) |
| macOS / Apple Silicon as a build and run host | [Requirements](USAGE.md#requirements), [macos-build.md](macos-build.md) | [runtime proof](ARCHITECTURE.md#runtime-provenance-and-platform-profiles) |

Two things about that list matter to the roadmap rather than to a user:

- **Network egress already exceeds the original**, which had no per-launch
  egress controls at all.
- Both the original and the rewrite are **fresh-VM-per-launch**. The rewrite is
  *not* missing a persistent-VM lifecycle the original had — see C1, which is a
  new capability, not a regression.

Two carve-outs inside the credential story are tracked as open items, not
documented as finished behaviour: Copilot has no in-session refresh (A5) and
GitHub GraphQL mutations are denied (A4).

## A. In-scope work to finish

These are within the agreed v1 scope and either unverified or incomplete.
(Onboarding config and the `.agent-vm.runtime.sh` hook were once on this list
and are **implemented**: `secrets.rs:1029-1086` force-sets
`hasCompletedOnboarding` / `hasTrustDialogAccepted` /
`hasCompletedProjectOnboarding` / per-folder trust, and `run.rs:2148-2152`
sources the project hook before exec. The refresh single-flight, the
`copilot` agent, and the in-image LSP plugins are likewise done — see
"Shipped since the last plan revision" below.)

- **A1 — Codex/OpenAI rotation coverage.** Claude's side is covered: the
  near-expiry rotation branch has an end-to-end test
  (`hidden_hook_due_anthropic_credential_rotates_through_real_host_cli_and_installs_fresh_bearer`,
  `crates/agent-vm/tests/intercept_hook_cli.rs:340`) and a real live rotation
  is recorded in `ARCHITECTURE.md` § "Smoke verification". Codex is not: no
  test reaches `openai_refresh`
  (`crates/agent-vm/src/intercept_hook/oauth_refresh.rs:738`) — only its
  missing/malformed 503 paths are exercised — and no session has crossed a
  real ChatGPT expiry (~24 h). Note that `0f301a1` once had direct rotation
  unit tests for both providers and the #54 refactor (`7d5efb5`) dropped them,
  so this is a coverage regression, not a never-written test. Effort: S for
  the test, M for the live run.
- **A2 — Project-integrity security snapshot.** `snapshot_host_creds` /
  `verify_snapshot` (`crates/agent-vm/src/secrets.rs:964,977`) fingerprint
  **only the three credential files** (`HostCredsSnapshot` has three fields,
  `secrets.rs:265-269`). The original also fingerprinted the **project repo** —
  `.git/config`, `.git/hooks/*`, `CLAUDE.md`, `Makefile`, the runtime hook —
  to catch an off-rails agent tampering with git hooks or build files. Extend
  the snapshot to cover those and warn on unexpected change. Effort: M.
- **A3 — Push-access probe.** No `git push --dry-run` anywhere in the rewrite;
  the allow-list is built from static remote parsing
  (`run.rs:1933` `parse_dir_remote_github_slugs`, `run.rs:1975`
  `parse_gitmodules_github_slugs`). The original probed with
  `git push --dry-run` to confirm real push rights before trusting a remote.
  Decide whether to add the live probe (it costs a network round-trip per
  launch). Effort: S.
- **A4 — Repository-scoped GraphQL mutations.** The proxy currently denies
  every GitHub GraphQL mutation, because none of them can yet be bound
  soundly to an allow-listed repository (ADR-0010). This intentionally breaks
  `gh` mutation workflows inside the guest; allow-listed REST routes are the
  workaround. Design the repo-scoped authorization or accept the gap as
  permanent. Effort: M.
- **A5 — Copilot in-session refresh.** Copilot gets file-backed substitution
  but no OAuth refresh route, so an expired Copilot token requires a relaunch
  (`secrets.rs:248-256`, `USAGE.md` § Credentials). Either add a refresh route
  or document it as a deliberate limit. Effort: M.

## B. Distribution / release

- **B1 — CI boot smoke.** No workflow ever runs the `agent-vm` binary.
  `.github/workflows/ci.yml` builds and tests the workspace, lints the shell
  scripts, runs `actionlint`, and exercises `script/build/macos.sh` against
  fixture toolchains — but nothing boots a VM. Add: build the image, run
  `agent-vm setup --no-verify`, then `agent-vm shell -- -c 'echo ok'`, green on
  at least linux-amd64. While in there, decide whether `cargo fmt` and
  `cargo clippy -- -D warnings` should stop being `continue-on-error: true`
  (`ci.yml:79-85`) — today both are advisory, so a lint regression merges green.
- **B2 — Finish cross-arch packaging.** Per-platform npm packaging now exists
  (`npm-dist/agent-vm-linux-x64`, `npm-dist/agent-vm-linux-arm64`, dispatched
  from `npm-dist/agent-vm/bin/agent-vm.js`), so the old "bundles one
  linux-x86_64 binary" framing is retired. Two gaps remain:
  - **linux-arm64 is not shippable.** All four cross legs are
    `continue-on-error` (`.github/workflows/release-npm.yml:81,213,344,438`)
    because the libkrunfw kernel-config seed hasn't been ported and the arm64
    multiarch dev-lib install is flaky; the publish job tolerates the missing
    artifact.
  - **darwin has no package at all.** The `darwin-arm64` / `darwin-x64`
    dispatch entries are commented out, and the "dedicated macOS release job"
    referenced at `release-npm.yml:498` does not exist — every matrix runner is
    `ubuntu-latest`. macOS is source-build-only today.
- **B3 — IPv6 DNS workaround → upstream fix.** Still a per-launch `sed`:
  `STRIP_IPV6_NAMESERVERS` (`crates/agent-vm/src/run.rs:2114-2115`) runs first
  in every guest prelude. `9676f6d` only extracted it into a documented,
  unit-tested const — it did not remove it. Replace with either a real fix to
  the v6 gateway DNS path in microsandbox or a `network.dns(disable_ipv6)`
  knob (no such knob exists in `vendor/` today; upstream issue #5).

## C. Improvements beyond the original (optional, product call)

- **C1 — Detached / persistent-VM fast launch.** Boot once per project, attach
  per invocation: ~1.5 s → ~10–50 ms.

  **The lifecycle primitives already exist and are already reachable.** `msb`
  ships `create` / `start` / `stop` / `restart` / `ps` / `exec` / `ssh` /
  `snapshot` / `logs`
  (`vendor/microsandbox/crates/cli/lib/commands/`), and `agent-vm msb <args…>`
  forwards *verbatim* with `MSB_PATH`/`MSB_HOME` pinned at agent-vm's private
  registry (`msb_cmd.rs` — it is a pure passthrough, not a read-only subset).
  So C1 is not "add `ps`/`stop`/`restart`"; those are one `agent-vm msb` away
  today.

  What's missing is on the agent-vm side, and the launcher is currently
  designed *against* reuse:

  - **Nothing survives to attach to.** The sandbox is named
    `agent-vm-{project_hash}-{pid}` (`session.rs:99`) — PID-scoped on purpose,
    so concurrent launches in one project can't collide. A name that changes
    every launch cannot be re-attached.
  - **The launcher tears it down.** `launch` ends with `stop_and_wait()` +
    `Sandbox::remove` (`run.rs:1620-1626`), and `reap_stale_project_sandboxes`
    (`run.rs:1825`) garbage-collects anything a crashed launcher left behind.
  - **No attach-if-exists / idle-timeout path** in `run.rs` at all.
  - **The hard part is config, not plumbing.** The network plan, the
    credential-injection overlay, and the per-launch GitHub repo allow-list are
    built from the cwd and applied at *builder* time
    (`run.rs:1223-1240`), before `Sandbox::create`. A reused VM would silently
    inherit the previous launch's allow-list and egress policy unless they are
    re-applied or the launch is refused — that is a security property, not a
    convenience, and it is what makes this L rather than M.

  Also needs an in-VM-state-persistence policy call (what survives between
  attaches). Effort: L.

## D. Original-only features — decisions made

Decided 2026-05-30 with the user, per-feature.

### Shipped since the last plan revision

These were roadmap items and are now done; kept here so the decision record
stays readable.

- **`copilot` agent + Copilot token** — `agent-vm copilot`
  (`main.rs:74-75`), `Agent::Copilot` (`run.rs:514`), the token routed
  through the same host-rooted / proxy-substituted flow
  (`credential_injection.rs:143-152`, `secrets.rs:202-204`), and
  `@github/copilot` installed in the image (`images/Dockerfile:428`).
  Caveat carried forward as A5.
- **LSP plugins in the image** — `clangd-lsp`, `pyright-lsp`,
  `typescript-lsp`, `gopls-lsp@claude-plugins-official` installed at build
  time (`images/Dockerfile:389-396`), plus a seeding step the plan never
  anticipated: the running guest symlinks `$HOME/.claude` to persistent state
  and shadows the baked plugin tree, so the build stashes it and the launcher
  re-seeds it (`images/Dockerfile:406-421`, `SEED_CLAUDE_PLUGINS` in
  `run.rs:2145`).
- **Refresh single-flight** — `RefreshLock` (`oauth_refresh.rs:803-836`) takes
  an exclusive `flock` per provider before any host CLI runs, with a 30 s
  attempt-damping stamp so a late waiter skips its own CLI, and a
  launcher-side `ProjectRefreshLock` (`secrets.rs:1612`).

### Won't do (confirmed non-goals)

- **GitHub App per-repo token minting.** The proxy allow-list already
  constrains pushes to cwd-derived repos; per-repo minting would add a GitHub
  App + device flow for marginal extra scoping. Keep `gh auth token` +
  allow-list.
- **USB passthrough** (`--usb` and its qemu wrapper). libkrun is a minimal VMM
  with no qemu-style device-passthrough path. Hard architectural non-goal.
- **Dynamic memory / balloon** (the balloon daemon, `memory` subcommand,
  `--max-memory`). Short-lived 2 GB microVMs torn down per launch don't squat
  host RAM the way persistent 16 GB Lima VMs did, so ballooning is moot.

Obsolete-by-architecture (no decision needed): setup `--minimal` / `--disk`
(image is Docker-built once, not provisioned per-setup), `--max-memory` (tied
to the balloon).

## Discovered upstream issues (still open)

Carried over from the old plan. These were all found against 0.5.7-era
microsandbox and predate the v0.6.15 cutover, so each is worth re-testing
against the current baseline before investing in a fix — but every workaround
is still load-bearing in the tree today. (The old list skipped #3, the
IRQ/split-irqchip issue, which is resolved; the rest are renumbered here.)

1. `PullPolicy::Always` doesn't refresh the cached manifest digest — worked
   around with our own marker file (`pulled_marker.rs`, `pull.rs:9-19`).
2. `LayerDownloadProgress` events elided for fast registries — compensated in
   `pull_progress.rs:55-59`.
3. No `Image::resolve(reference) -> RemoteRef` helper; we do a raw-HTTP HEAD to
   ask the registry what's current (`image_check.rs:6-8`).
4. IPv6 gateway DNS unresponsive in at least one libkrun config — the `sed`
   strip at `run.rs:2114` (see B3).
5. `exec_with`'s `StdinMode::Null` doesn't read as `/dev/null` to every client
   (codex blocks); worked around in the bash prelude (`run.rs:2146`).
6. High-level `exec_with` is buffer-until-exit only; switched to
   `exec_stream_with` (`run.rs:1519`, and no `.exec_with(` call sites remain).
7. Long secret placeholders (>~few hundred bytes) break sandbox boot at the
   runtime handshake; keep synthetic JWTs minimal (`secrets.rs:37-98`, whose
   comments name the exact `handshake read id_offset:` failure).

## Working agreements

1. **One feature = one PR.** Stop after each; the user signs off.
2. **ARCHITECTURE.md is the source of truth for the *why*,** and
   `docs/adr/` records the individual decisions. Every nontrivial design
   choice gets a short subsection or an ADR: chosen / rejected / why.
3. **microsandbox changes go into the submodule**, on a branch of
   `gregwebs/microsandbox`, never vendored copies. Merge the submodule
   branch before the superproject (see AGENTS.md).
4. **Bump `workspace.package.version` in the feature PR itself** (root
   `Cargo.toml`), so `main` is always releasable.
5. **Don't relocate build output to tmpfs.** Fix the root cause.
