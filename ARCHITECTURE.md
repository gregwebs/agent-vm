# agent-vm — ARCHITECTURE

How the rewrite is put together and *why*. Reading this top-to-bottom should
tell you what every nontrivial design choice in the codebase exists for.
Updated after each phase lands. Section per phase; subsection per major
decision.

## Phase 0 — Scaffolding

### Repository layout

```
microsandbox-rewrite/
├── PLAN.md                     # phased roadmap
├── ARCHITECTURE.md             # this file
├── Cargo.toml                  # workspace
├── crates/
│   └── agent-vm/
│       ├── Cargo.toml
│       └── src/main.rs         # hello-world sandbox boot
├── vendor/
│   └── microsandbox/           # git submodule, gregwebs/microsandbox
└── .gitmodules
```

### Why a Cargo workspace from day one

The binary is small today but we already know we'll need at least one
internal crate per concern (creds, image, session). A workspace lets us add
those without restructuring later, and keeps `vendor/microsandbox` out of
our crate's manifest noise.

### Why a git submodule for microsandbox (vs. crates.io, vs. path dep)

- **Credential injection depends on baseline microsandbox primitives.**
  The current `SecretSource::File` and interception support live in
  `microsandbox-network`; the old fork used a different `SecretValue`
  sentinel design. A path dep against a sibling checkout works for one
  developer but not for CI or contributors. A submodule pinned to a branch
  on our fork (`gregwebs/microsandbox`) makes the checkout self-contained and
  the upstream diff reviewable.
- **`[patch]` against crates.io** also works, but it duplicates the source-of-
  truth pointer (Cargo.lock + patch table) and hides the fact that we are
  shipping a fork. Submodule is more explicit.

### Why depend on the path under `vendor/microsandbox` even before we fork

Phase 0 doesn't change microsandbox, but we point at the submodule path so
the build wiring we set up here is the same wiring Phase 3 uses. Avoids a
mid-rewrite refactor of `Cargo.toml`.

### Why `Sandbox::builder("hello").image("alpine")` for the smoke test

Smallest possible exercise of the SDK that proves we can talk to the runtime.
Alpine is in the microsandbox examples, downloads quickly, and exits cleanly.
No need to involve our own image (that's Phase 1).

### Phase 0 runtime validation

`cargo run -p agent-vm` was exercised end-to-end on a Linux KVM host:

- One-time setup required outside the source tree: `apt install libcap-ng-dev`
  (link-time dep pulled in transitively by `msb_krun`'s `capng` crate), and
  user membership in the `kvm` group so `/dev/kvm` is openable. Both are host
  prerequisites and don't belong in the repo.
- microsandbox's build script downloads its prebuilt runtime artifacts the
  first time `cargo check` runs against the workspace
  (`microsandbox@0.4.6: downloading microsandbox runtime dependencies`).
  Nothing in our crate has to opt into this; the `prebuilt` feature is on by
  default in `microsandbox-runtime`.
- Wall-clock for the full boot + `echo` + teardown with the alpine image
  already in cache: **2.7s** on a release build. Cold first run includes the
  OCI pull on top.

This is the latest point we can confirm we're talking to a real runtime before
adding our own scaffolding; pinning the validation here means a Phase 1 image
regression won't masquerade as an SDK-integration regression.

## Phase 1 — Base OCI image

### Layout

```
images/
├── Dockerfile        # Debian 13 slim + agents
└── build.sh          # ensures registry, docker build, docker push

crates/agent-vm/src/
├── main.rs           # clap entry; dispatches to subcommands
└── setup.rs          # `agent-vm setup`: pull selected image, then verify in microsandbox
```

### Image distribution: local Docker registry vs. alternatives

`RootfsSource` (microsandbox-side) supports three image origins:

1. `Oci(reference)` — pulled from a registry (Docker Hub, GHCR, local, etc.).
2. `Bind(path)` — host directory used as the rootfs directly.
3. `DiskImage(path)` — qcow2/raw/vmdk file.

We pick **(1) with a local `registry:2` container on 127.0.0.1:5000**, exposed
to the sandbox builder as `.image("localhost:5000/agent-vm:latest")
.registry(|r| r.insecure())`. Rationale:

- **Standard OCI semantics.** microsandbox's layer cache, GC, snapshotting,
  and metadata DB all key off OCI references. Going through the registry path
  means we get all of that for free instead of working around it.
- **Same wiring as a future remote registry.** When/if we publish images to
  GHCR, the launcher's `.image(...)` call doesn't change; only the tag does.
- **Bind would require write-through or COW management.** `RootfsSource::Bind`
  hands the host directory to the VM as the rootfs. The microsandbox example
  uses it for a single one-shot sandbox; we'd need an overlay on top to share
  a template across multiple concurrent invocations. The OCI path already
  handles this via the layer cache.
- **Disk-image (qcow2) would mean building rootfs images ourselves.** Doable
  with `debootstrap` + `mkfs.ext4`, but the build steps are less familiar
  than `docker build` and the rebuild loop is slower.

The price is that we now run a Docker daemon and a `registry:2` container on
the host. Acceptable: every dev who needs to *build* the image already needs
Docker, and the registry container is ~30 MB and starts in <1 s. End users who
only pull a prebuilt image won't run the local registry at all (Phase 9
distribution territory).

### Image content: deliberately minimal

The current Dockerfile installs only what each of the three agents needs to
run plus the dev tools that are universally useful:

- Base: `ca-certificates`, `curl`, `wget`, `git`, `jq`, `bash`,
  `python3`/`pip`, `ripgrep`, `fd-find`.
- Chromium and the Chrome DevTools MCP are an opt-in `examples/layers/chrome-devtools` layer. API 2 detects its marker after boot and configures the launcher-owned MCP entry only when advertised. The wrapper retains scoped NSS CA trust and the root-to-`chrome` transition when the layer is installed.
- `gh` from cli.github.com/packages (Phase 6 — gh/git credential
  injection).
- Node.js 22 from NodeSource (needed by Claude Code, OpenCode, MCP servers).
- Agents installed via their canonical installer scripts so we track upstream
  release channels: `claude.ai/install.sh`, `opencode.ai/install`, and the
  Codex `install.sh` from GitHub releases.

Explicitly skipped in v1 (per PLAN.md scope cuts): Docker-in-VM, LSP
plugins, `mitmproxy` (microsandbox does the interception in Phase 3,
no in-VM proxy needed), GitHub Copilot CLI. Each line we keep is a
line that has to keep working through `apt-get update` churn, so the
bar to add anything is "needed by an in-scope agent flow."

Resulting image: a few GB uncompressed (Node.js and the agent CLIs are the largest contributors and the agent CLIs;
re-measure with `docker images` when you care about exact bytes).
Registry layer count is bounded by the `RUN` granularity in the
Dockerfile.

### Registry-backed image building stays in Bash

`images/build.sh` builds and pushes through a loopback registry as a separate
developer workflow. It is not invoked by `agent-vm setup`: setup pulls the
selected registry reference with `PullPolicy::Always`, then optionally boots
it for verification.

Docker's CLI remains the right interface for the registry-backed build script:
it keeps host-shell volume, port-forwarding, and `docker inspect` details out
of the Rust binary. Rebuilding the image does not require recompiling the
binary, and rebuilding the binary does not unexpectedly mutate an image
cache. Apple Silicon developers can instead use
`script/build/import-image.sh` to load an existing native local Docker image
without a registry.

The Rust side does own the **verify** step (boot from the freshly pushed
image, run the three `--version` commands), because that step is exactly the
microsandbox SDK call the launcher will make in Phase 2 — exercising it from
`setup` ensures we catch image/SDK-integration regressions before any user
session depends on them.

### `setup --no-verify` and `--image`

Two escape hatches surfaced from the start:

- `--no-verify` lets a developer iterate on the Dockerfile without paying for
  a sandbox boot each loop.
- `--image` / `AGENT_VM_IMAGE_TAG` lets us point at an alternative tag (a
  prebuilt image on GHCR, a developer's experimental tag, etc.) without
  touching `build.sh`. The default stays `localhost:5000/agent-vm:latest` so
  the happy path matches what `build.sh` produces.

## Phase 2 — Launcher MVP

### Layout

```
crates/agent-vm/src/
├── main.rs           # clap entry: setup | claude | codex | opencode | shell
├── setup.rs          # unchanged from Phase 1
├── run.rs            # `agent-vm <agent>`: build sandbox, attach or exec
└── session.rs        # project-dir hash, state dirs, sandbox name
```

### Project-scoped sandbox name + state dir

Each project gets:

- A short hash: first 6 bytes of `SHA256(canonical(cwd))` rendered as 12 hex
  chars (~48 bits — plenty for "no two project dirs on one host collide").
- A state directory at
  `${AGENT_VM_STATE_DIR-${XDG_STATE_HOME-$HOME/.local/state}/agent-vm}/<hash>/`.
- A sandbox name of `agent-vm-<hash>`.

The hash being short enough to fit in `<hostname>` is convenient when
debugging from inside the sandbox (`hostname` shows it). The sandbox name
being deterministic means a second `agent-vm claude` in the same project
*replaces* the first one (`.replace()` on the builder gives it 10 s to exit
gracefully, then SIGKILLs) instead of spawning a parallel VM.

The launcher prints a one-line banner on startup
(`==> agent-vm-<hash> in <cwd> (state: <dir>)`) so users always know which
project a given sandbox is bound to.

### Mounts: one for workspace, one for state, no third

When this layout was chosen, the microsandbox runtime was running with
libkrun's default in-kernel IOAPIC, which hands ~11 IRQs to virtio-mmio
devices total on x86_64. The OCI rootfs already consumes two slots (EROFS
lower + ext4 upper), plus virtio-net + vsock + console + agentd's
serial — adding a bind mount per agent state directory (claude, codex,
opencode) pushed us over and `RegisterBlockDevice(IrqsExhausted)` at boot
followed. We later lifted the underlying cap by enabling `msb_krun`'s
userspace split irqchip (see "Split irqchip and the virtio-IRQ ceiling"
below), but the one-workspace + one-state layout still
makes sense regardless: one virtio-fs server, one rootfs `patch` entry
per agent, and a stable on-host layout.

Resolution:

- One bind mount for `cwd → /workspace` (the project).
- One bind mount for `<state-dir> → /agent-vm-state` (everything else).
- The agents' expected paths are wired up under `$HOME` — `/root` in
  `--root` mode, `/agent-vm-state/home` in the non-root default (see
  "Guest user" above):
  - `$HOME/.claude → /agent-vm-state/claude`
  - `$HOME/.local/share/opencode → /agent-vm-state/opencode`
  - Codex uses the `CODEX_HOME=/agent-vm-state/codex` env var instead of a
    symlink, because `<install-prefix>/.codex/packages/...` contains the
    codex binary itself and a symlink would shadow it.

  Root mode's symlinks are baked into the rootfs upper overlay before VM
  start, via Phase 1's `patch` API (`/root/...` is un-shadowed rootfs, so
  this is correct there). Non-root mode's are provisioned host-side
  instead, in `<state_dir>/home` — `/agent-vm-state` is itself a *runtime*
  bind mount, which would shadow anything a patch baked at that path
  before the mount lands. Both modes draw from the same
  `session::GUEST_HOME_LINKS` mapping.

This keeps us at two virtio bind mounts no matter how many agents we add
later, and leaves plenty of IRQ headroom for user-supplied `--mount`
arguments now that the split irqchip is on.

### Split irqchip and the virtio-IRQ ceiling

`msb_krun` exposes a `MachineBuilder::split_irqchip(bool)` knob. With it
off (default), libkrun uses KVM's in-kernel IOAPIC, which is hard-capped at
24 pins and only hands IRQs 5..=15 to virtio-mmio — about 11 usable IRQs
for the whole VM. That fills up fast: rootfs lower + rootfs upper +
virtio-net + virtio-vsock + virtio-console + virtio-fs (project) +
virtio-fs (state) already saturates it on this build, so an extra
`--mount` would trip `RegisterNetDevice(IrqsExhausted)` at boot.

With split_irqchip enabled, `msb_krun` runs a userspace IOAPIC backed by
an event-loop thread it spawns automatically. Its usable device capacity is
an observed host-specific property, not a portable mount limit: Linux x86_64
uses this IOAPIC path, while Apple Silicon uses GIC. The trade-off is one
extra worker thread per VM and a slightly hotter IRQ delivery path. The
compatibility harness records conservative platform profiles rather than
turning an IRQ implementation detail into a universal CLI promise.

The runtime sets `split_irqchip(true)` unconditionally in
`vendor/microsandbox/crates/runtime/lib/vm.rs`. The user-facing
`--mount` doc and Phase 7's wiring in `crates/agent-vm/src/run.rs` were
updated to drop the pre-cap warning that previously fronted the limit.

The change also bumped `msb_krun` from 0.1.12 → 0.1.13 across the
vendor crates (`runtime`, `filesystem`, `network`). 0.1.12's userspace
IOAPIC was unusable in practice: its IRR was a single `u32` so any IRQ
delivered on pin ≥ 32 was dropped without notice, and the redirection-
table register-index calculation in `read`/`write` did an unchecked
`ioregsel - IOAPIC_REG_REDTBL_BASE` that wrapped on any access below
the redirection-table base — which the guest performs during normal
IOAPIC programming. Both fixes landed in 0.1.13, published 2026-05-26.
The PLAN's Discovered Upstream Issue #3 was originally attributed to
"the libkrun IRQ cap"; with hindsight, the cap is a real KVM-level
ceiling but the multi-mount boot failure that finally drove this work
was a separate, fixable bug inside `msb_krun_devices`'s userspace
IOAPIC, only ever reached once the split irqchip was turned on.

### Issue #43 runtime proof and platform profiles

`./script/check-runtime-provenance.sh` checks both independent Cargo roots
(the outer workspace and `vendor/microsandbox`) for the identical official
crates.io `msb_krun*` 0.1.32 cohort and checksum map. It also checks the
pinned `vendor/libkrunfw` gitlink, firmware version/ABI, and the x86 source
configuration contract. This establishes source identity, not an attestation
that an arbitrary executable came from that source; release provenance remains
separate work.

The public-CLI compatibility harness is `script/test/msb-krun-compat.sh`.
It retains process, Docker, fixture, and guest-probe orchestration in shell, while
`crates/msb-krun-compat-evidence` parses and validates host-side evidence and
writes its JSON records. The small separate workspace crate keeps that contract
buildable before the vendored `agentd` and agent-vm runtime dependencies; the
static Python provenance checker intentionally remains Cargo-independent.
On Apple Silicon macOS/HVF its device-discovery proof deliberately uses the
flattened device tree plus guest sysfs and `virtiofs` mountinfo, rather than an
x86 command-line proxy. A zero-user-bind baseline is compared with each case;
each added bind must add one `virtio,mmio` FDT node and one bound `virtiofs`
device, and selected low/boundary/final mounts must read their unique host
marker and write a unique value back to the host.

The accepted Darwin regression profile is conservative test policy:
boundary samples 4 and 64, high case 112, and stress case 64. It is not a
portable mount limit or capacity claim. The measured host booted through 128
user binds; 256 was the first attempted failure
(`RegisterFsDevice(IrqsExhausted)`); counts 129--255 were not exhaustively
tested, so the exact maximum is unmeasured. Darwin's `/proc/cmdline` stayed
about 202 bytes because arm64 HVF describes virtio-mmio devices in the device
tree. The pinned firmware's 16 KiB command-line setting and the >2 KiB,
trailing-`virtio_mmio.device=` acceptance proof are therefore Linux x86_64
KVM-only.

Linux x86_64 KVM still needs its own live `measure`, reviewed boundary/high/
cmdline/stress constants, command-line declaration ordering/count proof, and
split-irqchip/IOAPIC diagnostics. Darwin evidence and orchestration contracts
do not satisfy any of those KVM items.

### Interactive attach vs. non-TTY exec

`Sandbox::attach()` requires a real controlling TTY: it puts stdin in raw
mode and opens `/dev/tty` for its non-blocking input fd. When stdin isn't a
TTY (pipe, redirect, smoke test under `sg`/`sudo -c`, CI), `attach` returns
ENXIO.

The launcher checks `std::io::stdin().is_terminal()` and branches:

- **TTY** → `attach(cmd, args)` — the agent's TUI gets a full PTY and is
  fully interactive.
- **No TTY** → `exec_with(cmd, |e| e.args(args).cwd("/workspace"))` — runs to
  completion, then forwards collected stdout/stderr and the exit code.

Non-TTY mode loses the live streaming TUI experience but gives the caller a
clean `stdout | other-tool` story. Streaming stdout/stderr during run landed
in the Phase 4 verification session (2026-05-24) — see PLAN.md.

### Credentials: env-var only, deliberately

Phase 2 reads `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` from the host
environment and forwards them via `.env()`. This is the simplest possible
path that exercises everything else end-to-end. Phase 3 replaces this with
microsandbox's secret-substitution API backed by host-rooted token files,
and Phase 4 adds refresh semantics on top.

Concretely, the env-var path is intentionally insufficient for our real use
case (Claude Code's host OAuth, Codex's host ChatGPT auth, OpenCode's
OAuth flows). That gap stays open until Phase 3.

### `PATH` is set explicitly, not inherited

The Phase 1 Dockerfile puts the agent binaries on `PATH` via an `ENV`
directive, but that PATH only takes effect when an interactive shell sources
the image's profile. `attach()` and `exec()` both spawn the command via
`execve` directly, so we re-publish the same PATH on the sandbox builder
(`/opt/agent/.local/bin:/opt/agent/.claude/local/bin:/opt/agent/.opencode/
bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin`). Otherwise `agent-vm claude`
would `ENOENT` immediately. Agent binaries live under `/opt/agent` (a
shared, world-readable prefix, `chmod -R a+rX`) rather than `/root`, so the
same PATH resolves identically whether the guest is running non-root
(default) or as root (`--root`) — see "Guest user" above.

### Tunables: env-var-driven for now

`AGENT_VM_IMAGE_TAG`, `AGENT_VM_MEMORY_MIB`, `AGENT_VM_CPUS` cover the three
knobs you actually want to change session-to-session. `--memory` and
`--cpus` were promoted to clap flags (`1817391`); `--image` and friends are
on the Phase 9 polish list. Env-var-only kept the
Phase 2 surface small and means we don't have to design the `--memory 4G`
vs `--memory 4096` ergonomics yet.

### What Phase 2 deliberately doesn't do

- **No live DoD smoke against the Anthropic API.** The Phase 2 DoD in
  PLAN.md calls for `agent-vm claude -p 'say hi'` returning a real Claude
  response, but on this host we only have a Claude OAuth credential (not an
  `ANTHROPIC_API_KEY`), and Phase 2 explicitly does *not* implement OAuth
  plumbing. We verified all of Phase 2's wiring end-to-end via the `shell`
  subcommand (workspace mount, state persistence, env propagation, all three
  agent CLIs resolvable on PATH) and explicitly chose to close the API-call
  gap during Phase 3's host-OAuth work rather than ferry an ephemeral API
  key through this session.

## Phase 3 — Host-rooted secrets

### Layout

```
vendor/microsandbox/  (branch: agent-vm-secret-file)
└── crates/network/lib/secrets/
    ├── config.rs            # new: SecretValue { Static, File } enum
    └── handler.rs           # resolves SecretValue at connection-setup

crates/agent-vm/src/
├── secrets.rs               # new: read host creds, write placeholders
├── run.rs                   # wire TLS intercept + secret_env per provider
└── main.rs                  # register secrets module
```

### Two-layer placeholder dance

Real tokens never enter the VM. The dance per provider:

1. **Host side.** agent-vm reads the host's credential file
   (`~/.claude/.credentials.json` for Claude,
   `~/.codex/auth.json` for Codex) at every launch. It extracts the
   access token, keeps it in a short-lived Rust `String`, and registers
   it as a microsandbox secret with a stable placeholder string
   (`msb-anthropic-placeholder-a-v2` and
   `msb-openai-placeholder-a-v2`). The placeholder *constants* live in
   `crates/agent-vm/src/secrets.rs` (`ANTHROPIC_ACCESS_PLACEHOLDER` etc.) —
   prefer the constant over the literal so a future rename doesn't drift.
2. **Guest side.** agent-vm writes a "placeholder credentials" JSON
   into the per-project state dir
   (`<state>/claude/.credentials.json`,
   `<state>/codex/auth.json`) using the placeholder string instead of
   the real token. Other fields (`expiresAt`, `scopes`, `account_id`,
   `last_refresh`, etc.) are copied from the host file so the in-VM
   agent sees a plausible JSON shape. `refreshToken` is set to a
   sentinel string — Phase 3 doesn't handle refresh.
3. **TLS interception.** microsandbox's network proxy intercepts the
   sandbox's HTTPS traffic. When the agent makes a request to any
   allowed host (`api.anthropic.com`, `platform.claude.com`,
   `api.openai.com`, `chatgpt.com`, `auth.openai.com`), the proxy
   sees `Authorization: Bearer msb-…-placeholder-…` in the outgoing
   request, splices in the real token from the secret config, then
   forwards.

The agent inside the VM never sees the real token in any form
(`/proc/$$/environ`, `cat ~/.claude/.credentials.json`, network
introspection inside the guest all show only the placeholder). It
gets the real token only as a header-mangled middlebox effect on the
way out — which is structurally what microsandbox was designed for.

### Upstream extension: `SecretValue { Static, File }`

Pre-Phase 3, `SecretEntry.value` was a `String` captured at builder
time. That worked for static API keys but precluded host-side OAuth
rotation — there was no way to surface a new token to a running
sandbox short of rebuilding it.

The `agent-vm-secret-file` branch of vendor/microsandbox adds
`SecretValue { Static(String), File(PathBuf) }` and changes
`SecretEntry.value` to that enum. The handler resolves `File` at
connection-setup time, so each new request to an allowed host sees the
current file contents. Wire format stays a single JSON string for
backward compatibility with the prebuilt `msb` daemon already on
users' hosts:

| Variant | Wire format |
|---|---|
| `Static(v)` | `"v"` — a bare JSON string, identical to the old `value: String` form |
| `File(p)` | `"\0msbfile:<path>"` — a NUL-prefixed sentinel string |

The NUL prefix is unforgeable in API tokens (always printable ASCII).
Old `msb` daemons that don't recognise the sentinel treat the whole
thing as an opaque string and substitute it verbatim — broken for
`File`, but never crashes.

### Phase 3 uses `Static` only

`SecretSource::File` is the right primitive for refresh-aware
substitution, but turning it on end-to-end requires a `msb` daemon
built from our forked source replacing the prebuilt one at
`~/.microsandbox/bin/msb`. Phase 3 doesn't ship that distribution
plumbing — it captures the host token as a `String` at launch time
and passes `SecretValue::Static(token)` to microsandbox. The sandbox
lives until the token's TTL (usually hours); rotation is a Phase 4
problem.

### Allowed-host lists

Per-provider, we allow the API host *and* the OAuth-token host. The
OAuth-token host doesn't actually need substitution in Phase 3 (we
don't intercept the refresh flow yet), but we have to allow it,
otherwise the in-VM agent's refresh attempt would trigger
microsandbox's secret-violation detector (placeholder going to a
disallowed host = `BlockAndLog` blocks the request). Letting the
placeholder reach the OAuth host means the upstream server just
rejects it normally, which is at least a comprehensible failure.

| Provider | Allowed hosts |
|---|---|
| Anthropic | `api.anthropic.com`, `platform.claude.com` |
| OpenAI    | `api.openai.com`, `chatgpt.com`, `auth.openai.com` |

### `IS_SANDBOX=1`

Claude Code refuses to run as root with
`--dangerously-skip-permissions` unless `IS_SANDBOX=1` is set. By
default (non-root guest — see "Guest user" below) that root-refusal
simply never triggers, since the in-guest user isn't root; under
`--root`/`AGENT_VM_ROOT` it does still trigger, which is exactly what
`IS_SANDBOX=1` is for. Either way the whole point of the microVM is
that the sandbox itself is the boundary, so we set `IS_SANDBOX=1`
unconditionally on the builder — same env var the original Bash
agent-vm used, and harmless when the guest is non-root.

### Guest user (non-root by default) / `--root`

See `docs/adr/0001-non-root-guest-via-native-user.md` for the full
rationale. Summary: `run.rs`'s `launch()` resolves root-vs-non-root mode
up front (`--root` flag OR truthy `AGENT_VM_ROOT`, mirroring
`should_check_update`'s flag-or-env pattern). In the default non-root
mode it computes `libc::getuid()`/`getgid()` and passes `"{uid}:{gid}"`
to microsandbox's `.user(...)` on the attach/exec builders — *not* the
sandbox builder, since `agentd` (PID 1) must stay root to `setuid` per
exec. The guest env sets `HOME=/agent-vm-state/home`, `USER=agent`,
`LOGNAME=agent`; `/etc/passwd`+`/etc/group` get an `agent` entry for
the uid via `.patch().append(...)` (real rootfs, unaffected by the
`/agent-vm-state` runtime bind).

The one wrinkle: `/agent-vm-state` is a *runtime* bind mount, and
`.patch()` bakes into the rootfs's `upper.ext4` **before** the VM
boots — so anything a patch writes under `/agent-vm-state/...` is
invisible once the bind mount lands. Root mode's `/root/...` dotfile
symlinks are unaffected (un-shadowed rootfs), but the non-root guest's
`HOME` and its dotfile symlinks live *under* `/agent-vm-state`, so they
have to be materialized host-side instead —
`ProjectSession::provision_guest_home` (`session.rs`) creates
`<state_dir>/home` and its dotfile symlinks (dangling on the host,
resolving correctly once bind-mounted into the guest), using the same
`GUEST_HOME_LINKS` mapping that root mode's `.patch()` block draws from.

`--root`/`AGENT_VM_ROOT` restores the legacy root guest. Docker-in-VM
needs it (dockerd needs root); the Chrome MCP's `sudo -u chrome` path
(below) is also root-mode-only.

### Smoke verification

End-to-end verified on a nested-VM test host (cwd
`/home/boger.linux/agent-vm-phase3-test`):

- `cat /root/.claude/.credentials.json` inside the guest shows the
  placeholder, not the real token. ✓
- `cat /proc/1/environ | tr '\0' '\n' | grep -i token` finds only
  `MSB_AGENT_VM_ANTHROPIC_UNUSED=msb-…-placeholder-…`. ✓
- TLS-intercepted curl to `https://api.anthropic.com` sees the
  microsandbox CA on the server cert (`CN=microsandbox CA`),
  confirming requests go through the substitution proxy. ✓
- `AGENT_VM_DEBUG_CONFIG=1` dumps the SandboxConfig JSON and the
  secret value is the host's real `accessToken` (which on this nested
  test host is itself a placeholder relayed to the outer host's real
  bridge — see below). ✓

The *final* leg ("api.anthropic.com returns a real response") can't
be verified on this host because we're running inside an outer
agent-vm whose own credential bridge intercepts requests on the outer
host's localhost — which our nested microsandbox can't reach. On a
non-nested host with a real Claude OAuth credential, the substituted
bearer reaches Anthropic verbatim and the response is real. The same
flow is structurally identical to how the original Bash agent-vm's
credential-proxy works.

### What Phase 3 deliberately doesn't do

- **No refresh.** Long sessions will hit a 401 when the captured
  access token expires (typically hours). Phase 4 closes this.
- **No `~/.microsandbox/bin/msb` replacement.** The `SecretSource::File`
  variant requires a `msb` rebuilt from our fork to actually re-read
  the file. Without that the Static path is what gets exercised, and
  it does work against unpatched `msb` (wire-format compatibility was
  the explicit design goal of the bare-string sentinel encoding).
- **No host-side OAuth token endpoint short-circuiting.** When the
  in-VM agent tries to refresh, the request goes upstream and is
  rejected by Anthropic/OpenAI because the placeholder refresh token
  isn't real. The original Bash agent-vm has logic to MITM the
  `platform.claude.com/v1/oauth/token` and `auth.openai.com/oauth/token`
  endpoints and forge responses from re-reads of the host file. That's
  Phase 4.

## Phase 4 — OAuth refresh: file-backed secrets + interceptor hook

Phase 3 left a 401-then-die failure mode: when the captured access
token expires mid-session the in-VM agent gets 401 from the API, tries
to refresh against the OAuth endpoint with the placeholder refresh
token, and gets 401 again. The user has to exit and re-launch.

Phase 4 closes the loop end-to-end. Two upstream microsandbox
extensions plus an agent-vm subprocess handle it.

### Pieces

```
vendor/microsandbox/  (branch: agent-vm-secret-file)
└── crates/network/lib/
    ├── secrets/config.rs       # SecretSource::File is active for per-connection reads
    └── intercept/              # new: per-route request-interceptor hook
        ├── config.rs           #   InterceptConfig (rules + hook command)
        └── handler.rs          #   per-connection state machine

crates/agent-vm/src/
├── msb_install.rs              # discover and validate msb's official-version identity; point MSB_PATH at it
├── intercept_hook.rs           # hook adapter/top dispatch and GitHub policy
│   └── intercept_hook/
│       ├── http.rs             # shared hook HTTP parsing/response framing
│       └── oauth_refresh.rs    # private OAuth validation, rotation, and reply module
├── secrets.rs                  # switched from Static(token) to File(<state>.secrets/{anthropic,openai})
└── run.rs                      # registers the interceptor with two rules
```

### `msb` shipped via `MSB_PATH`

At startup, every agent-vm invocation resolves and validates its bundled
`msb`'s version identity before constructing the async runtime, then sets
`MSB_PATH` to that binary (the top of microsandbox's resolution ladder).
Since agent-vm issue #40, "validates" means confirming `msb --version`
reports exactly the official upstream Microsandbox version this agent-vm
build vendors (`msb_install.rs::verify_official_identity`) — not, as when
this Phase 4 section was written, a `+agent-vm`-suffixed fork marker. The
current baseline wiring uses `SecretSource::File` plus per-route interception
in the active boot path. The old fork's `SecretValue` sentinel was replaced
by a durable host-only file reference, so rotated token bytes are never
serialized into sandbox configuration. Discovery prefers an
explicit `MSB_PATH`, then an `msb` sibling in an installed bundle, then the
signed source artifact at `vendor/microsandbox/build/msb`. The user's
`~/.microsandbox/bin/msb` is never touched, so upstream-installed tooling on
the same host keeps using its own prebuilt.

The root `script/build/macos.sh` source-build interface owns production of the
vendored runtime. It directly drives the pinned vendored macOS build sequence
and assembles the signed artifact with its firmware, so `just` is not a root
build prerequisite. `agent-vm setup` does not build or refresh `msb`; it only
pulls and optionally boots the selected registry image. On macOS, Cargo's raw
`vendor/microsandbox/target/release/msb` lacks the required
`com.apple.security.hypervisor` entitlement and is not a runnable substitute.

The real msb binary lives in the `microsandbox-cli` crate; the
`microsandbox` crate has a separate `microsandbox` binary that's
just a 5-line shim forwarding to `~/.microsandbox/bin/msb`. Building
the wrong target produces a 389 KB shim that boots silently then
hangs at VM init — about 30 minutes of debugging into a
no-VMM-symbols-in-the-binary surprise. Recorded here so the next
person doesn't redo it.

### `SecretSource::File`

Phase 3's per-launch snapshot becomes a per-launch *file write*. We
write the host's `accessToken` to a host-only secret file (see next
subsection for *where*) with 0600 perms via atomic-write-then-rename.
The launcher passes the file path to microsandbox as a
`SecretSource::File`.

msb's TLS-intercept proxy calls `SecretValue::resolve()`
at *connection-setup* time — every new TCP connection re-reads the
file. So any host-side rotation (whether triggered by the user's
external `claude` use or by our interceptor hook below) is visible
to the very next request, without rebuilding the sandbox.

### Token files live *outside* the guest bind mount

The launcher bind-mounts the per-project `state_dir` into the guest at
`/agent-vm-state` as a *single* mount. The single-bind shape originally
fell out of libkrun's tight virtio-IRQ cap (one bind for all per-agent
state instead of one per agent — see "Mounts: one for workspace, one
for state, no third"), and we've kept it after lifting the cap because
it gives a stable on-host layout and a single virtio-fs server. That
makes mount placement security-critical: **anything under `state_dir`
is readable from inside the VM.**

The real access-token files therefore must *not* live under
`state_dir`. They sit in a sibling host-only directory
`${state_root}/<hash>.secrets/` (mode 0700), derived from `state_dir`
by `secrets::{anthropic,openai}_token_path` so the launcher and the
refresh hook agree on the path without passing it explicitly. The
microsandbox proxy reads these files on the *host* side via
`SecretSource::File`, so they never need to be mounted into the guest at
all.

This was a real leak found during Phase 4 end-to-end verification: the
first cut wrote the tokens to `<state>/tokens/{anthropic,openai}`, i.e.
*inside* the mount, so `cat /agent-vm-state/tokens/anthropic` in the
guest returned the host's real bearer — silently defeating the entire
"real tokens never enter the VM" guarantee. The nested test host masked
it (there the "real" token is itself the outer bridge's placeholder), so
it only surfaced once we grepped the guest filesystem for the token
during verification. A `token_files_live_outside_the_guest_mount` unit
test now guards the invariant.

### Request-interceptor hook (the OAuth refresh MITM)

`microsandbox-network` gained an `InterceptConfig` that the launcher
fills with:

```rust
.intercept(|i| i
    .hook(["…/agent-vm", "_intercept-hook", "--state-dir", "…"])
    .rule("platform.claude.com", "POST", "/v1/oauth/token")
    .rule("auth.openai.com",     "POST", "/oauth/token"))
```

When the in-VM agent posts an OAuth refresh request, the proxy:

1. Buffers the full request under the configured 2 MiB cap. Oversized
   OAuth and GitHub API requests are refused; smart-HTTP dispatches on
   headers and streams its body after the repository verdict.
2. Spawns the hook command with the request bytes on stdin and four
   env vars (`MSB_INTERCEPT_SNI/_HOST_RULE/_METHOD/_PATH_PREFIX`).
3. Reads the hook's stdout as the response and writes it back to the
   guest, encrypted under the forged TLS cert.
4. Closes the connection without ever touching the upstream server.

The hook (`agent-vm _intercept-hook`) is the same binary in a hidden
clap subcommand mode:

1. Reads the request from stdin and strictly validates HTTP/1.1 framing,
   Host/SNI/authority, exact provider route, encoding, grant, and
   placeholder before it can start a host command.
2. Spawns `claude -p hi --model sonnet` (or `codex exec --skip-git-
   repo-check 'Reply OK'`) on the **host** so the host CLI rotates
   `~/.claude/.credentials.json` / `~/.codex/auth.json` the normal way.
3. Re-reads the rotated host file, rewrites the host-only token file
   (`<state>.secrets/{anthropic,openai}`) so the next non-refresh
   request from the guest gets the new bearer via `SecretSource::File`.
4. After complete validation, the private OAuth module consumes the bearer
   into the host-only file and returns only typed public metadata. It then
   synthesizes an OAuth refresh-response JSON shaped like what the upstream
   server would return, but with **placeholder** strings in the
   `access_token` / `refresh_token` fields. The in-VM agent updates its
   credentials.json to those placeholders and continues.
5. The adapter writes the response to stdout, which is the interceptor
   protocol channel rather than logging, then exits 0.

The guest never holds a real token at any layer:
- `~/.claude/.credentials.json` always contains placeholders (Phase 3).
- The real-token file is on the host *outside* the guest bind mount
  (see "Token files live outside the guest bind mount").
- The proxy substitutes real-for-placeholder on the way *out* (Phase 3).
- The OAuth refresh response also returns placeholders (Phase 4).
- The host CLI on the host is the only thing that ever touches real
  OAuth machinery, and it writes to a file we re-read.

### Hook-process boundary, not callback

The interceptor uses a subprocess (fork+exec per request) rather than
a callback into the SDK. Reasons:

- `Vec<Box<dyn RequestInterceptor>>` isn't serializable. The
  network config is JSON-piped from the SDK to a separate `msb`
  process, so anything we configure on the SDK side has to round-trip
  through JSON.
- Refresh requests are rare (once per hour at worst). Fork-per-request
  overhead is irrelevant against the latency of the host `claude`
  invocation that the hook does anyway.
- A subprocess can dispatch on any logic without us having to
  re-extend microsandbox each time we add a provider.

### Smoke verification

```
Inside the guest:
  POST https://platform.claude.com/v1/oauth/token
  body: {"grant_type":"refresh_token","refresh_token":"…PLACEHOLDER_REFRESH…"}

Response:
  HTTP 200 application/json
  {"access_token":"msb-anthropic-placeholder-a-v2",
   "refresh_token":"msb-anthropic-placeholder-r-v2",
   "expires_in":3499, "token_type":"Bearer",
   "scope":["user:file_upload","user:inference",…]}
```

Confirmed on the same nested-VM test host as Phase 3. The hook ran,
host `claude -p` rotated the host file, the new bearer landed in
`<state>.secrets/anthropic`, and the synthesized response reached the
guest. `expires_in: 3499` is the freshly-derived seconds-until-expiry
of the just-rotated token.

### What Phase 4 deliberately doesn't do

- **No proactive expiry timer.** Discussed and rejected: the
  guest's own refresh attempt at 401-time triggers our hook, which
  triggers the host-side refresh. If the user runs `claude` on the
  host between sessions, the host file is already fresh and the
  `SecretSource::File` re-read picks it up with no hook involved.
  A timer would be belt-and-suspenders.
- **No msb shipped via `~/.microsandbox/bin/msb`.** The MSB_PATH
  override is per-agent-vm-invocation only; other microsandbox SDK
  consumers on the same host keep using the upstream prebuilt.
- **Same-project single-flight only.** A provider-specific host-only
  lock serializes refreshes for one project. A contended waiter skips
  its CLI only after it observes a changed readable token digest;
  uncontended and degraded acquisitions rotate. Different projects may
  still duplicate work and rely on the provider CLI's credential lock.

## Phase 5 — Sandbox liveness: heartbeat keep-alive and runtime-exit reporting

A sandbox is a libkrun microVM: the host launcher spawns a hidden `msb
sandbox …` child process (the VMM), which runs the vendored runtime
(`vendor/microsandbox/crates/runtime/lib/vm.rs`) and never returns — libkrun
calls `_exit()` on shutdown. Two independent mechanisms decide whether that
child is still alive and well, and issue #41 tightened both after a
long-lived PTY session was reclaimed mid-use.

### Two liveness mechanisms

1. **Heartbeat** (idle / health). The guest agent (`agentd`) writes
   `/.msb/heartbeat.json` once a second; it appears host-side via virtiofs
   in the sandbox runtime directory. `HeartbeatReader`
   (`vendor/microsandbox/crates/runtime/lib/heartbeat.rs`) polls it every
   second from a monitor task in `vm.rs` to decide idle-vs-active, and —
   since #41 — whether the agent has gone truly unresponsive.
2. **Child process supervision.** The SDK owns the VMM child
   (`vendor/microsandbox/sdk/rust/lib/runtime/handle.rs`'s `ProcessHandle`,
   spawned by `runtime/spawn.rs`'s `spawn_sandbox`) and is responsible for
   reaping it and surfacing an unexpected exit instead of letting a
   host-side `wait()` or exec stream block forever.

### The bug: brief heartbeat staleness looked identical to a dead agent

Under host load or virtiofs write latency, `heartbeat_seq` can stop
advancing for several seconds even though the guest is healthy and a PTY
exec session is actively running. Before #41, the only two heartbeat
outcomes bearing on liveness were "idle" and "not idle" — there was no
staleness budget at all, so a genuinely wedged `agentd` past boot had no
way to be caught, and any budget added naively would have killed exactly
the busy-but-momentarily-quiet sessions the bug report was about.

`HeartbeatReader::check` resolves this with a **two-window confirmation**
rather than a single deadline:

```
heartbeat_seq advances every ~1s; STALE budget S = 5s; a hiccup pauses it for ~6s
time →   0s ......... 5s ......... 10s ......... 15s
seq      1 2 3 4 5 6 [------ paused ------] 7 8 9 ...
exec:    RUNNING RUNNING RUNNING RUNNING RUNNING RUNNING (never ends)

stale_for < S              → Active (fresh)
stale_for in [S, 2S)        → Active (grace: crossed the budget once, not confirmed)
stale_for >= 2S             → AgentUnresponsive (confirmed: no fresh seq for a full
                               second window)
any fresh heartbeat_seq     → resets the grace window immediately
```

`stale_confirmed_at` records the instant staleness first crosses `S`; only
once *another* full `S` elapses with no fresh sequence in between does the
decision flip to `AgentUnresponsive`. A missing heartbeat (never seen at
all) gets the analogous but much longer `HEARTBEAT_BOOT_GRACE` (180s)
before being declared unresponsive — this only covers a guest whose relay
already passed `wait_ready` but whose `agentd` never started writing
`heartbeat.json`; a guest that never boots the relay at all is still
reclaimed by the relay's own `wait_ready` timeout, unchanged by this
monitor. An **active exec session never goes idle**, regardless of
staleness — busy is healthy.

`AgentUnresponsive` is a distinct decision from `Idle`: it stores
`EXIT_REASON_AGENT_UNRESPONSIVE`, requests a *bounded* guest shutdown
(`request_guest_shutdown_with_timeout`, ~1s — deliberately not the normal
60s idle-shutdown default, since an agent already confirmed unresponsive is
unlikely to service a graceful shutdown request either) rather than the
normal graceful path, and triggers host exit either way so a wedged relay
can never block the sandbox's teardown.

### Child supervision: never block forever on an exited VMM

If the VMM child dies unexpectedly (crash, OOM-kill, `SIGKILL` from
outside), two things must not happen: the launcher must not block forever
in `ProcessHandle::wait()` or in an open exec stream's event loop, and the
diagnostic evidence must not be lost.

- `ProcessHandle::wait()` classifies the exit (`abnormal` = non-zero status
  or terminated by signal) and — once, guarded by an `exit_logged` flag so
  repeated `wait()` calls on the same fused `tokio::process::Child::wait()`
  never duplicate a line — appends a record to `<sandbox log dir>/msb-exit.log`
  alongside the runtime's own `runtime.log`/`kernel.log`. A clean exit
  writes nothing; the file is a crash post-mortem, not a lifecycle audit
  log. `disarm()` (used on the detached-sandbox path) clears the log
  directory reference first, since a detached handle's eventual `wait()`
  observes only kernel-reparenting behavior (reaps to `Ok(0)` instantly, or
  hangs forever) rather than the VMM's real termination — logging that
  would misrepresent what actually happened.
- `agent-vm`'s streaming-exec loop (`crates/agent-vm/src/run.rs`,
  `next_exec_step`) races the exec event stream against
  `Sandbox::wait()` with `tokio::select!`. In the ordinary case the relay
  socket closing when the VMM dies already ends the event stream promptly
  (`recv()` → `None`, already handled as an actionable "stream ended
  without Exited" error). The race is the belt-and-suspenders backstop for
  the case where that doesn't happen: if the runtime exits while the
  stream is still open, the loop reports a diagnostic naming
  `msb-exit.log` immediately instead of hanging on `recv()`.

### What Phase 5 deliberately doesn't do

- **No proactive polling of `try_wait()` from a timer.** The exec-stream
  race and the relay's own EOF handling already surface a VMM death
  promptly for the paths that matter (an open exec session); adding a
  separate poll loop would duplicate that without covering a new case.
- **No sea-orm schema change.** `TerminationReason::AgentUnresponsive` and
  its `EXIT_REASON_AGENT_UNRESPONSIVE` mapping already existed in the
  v0.6.15 baseline (added for the relay's boot-failure path); #41 reuses
  both rather than adding new termination-reason variants or migrations.
- **No stderr-tee task.** An earlier fork implementation (pre-v0.6.15)
  buffered the VMM's stderr through a tee task so a panic backtrace's tail
  survived shutdown; the current baseline already redirects stderr
  directly into `runtime.log` via `Stdio::from(...)`, so there's no
  separate task to drain or race in `wait()`.
