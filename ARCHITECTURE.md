# agent-vm — ARCHITECTURE

How agent-vm is put together and *why*. Reading this top-to-bottom should tell
you what every nontrivial design choice in the codebase exists for.

This describes the system **as it is now**, organized by subsystem. It is not a
changelog: when a decision was superseded, only the decision that survived is
written down, and `git log` holds the rest. Individual decisions that needed
their own write-up live in [`docs/adr/`](docs/adr/) and are indexed
[at the end](#decision-record-index). What the features *do*, from a user's
side, is [USAGE.md](USAGE.md); what is still unbuilt is [PLAN.md](PLAN.md).

## Contents

- [Shape of the system](#shape-of-the-system)
- [Sandboxes and sessions](#sandboxes-and-sessions)
- [The base image](#the-base-image)
- [Credentials](#credentials)
- [Runtime and state](#runtime-and-state)
- [Host-side tools](#host-side-tools)
- [Decision record index](#decision-record-index)
- [Deliberate non-goals](#deliberate-non-goals)

## Shape of the system

```
crates/agent-vm/src/
├── main.rs                 # clap entry; pins MSB_PATH/MSB_HOME before the runtime
├── run.rs                  # launch(): build the sandbox, attach or stream-exec
├── session.rs              # project hash, state dirs, sandbox name, guest home
├── secrets.rs              # capture host credentials; write guest placeholders
├── credential_injection.rs # overlay host mappings + file-backed sources on the network plan
├── intercept_hook.rs       # hidden `_intercept-hook` subcommand: OAuth + GitHub policy
│   └── intercept_hook/
│       ├── http.rs         #   shared request parsing / response framing
│       └── oauth_refresh.rs#   OAuth validation, rotation, single-flight
├── network.rs              # egress policy and published ports
├── mount.rs                # --mount grammar and volume wiring
├── layer.rs                # project tooling layers (.agent-vm/layers/, plus --layer)
├── msb_install.rs          # locate + version-verify the bundled msb; MSB_HOME
├── msb_preflight.rs        # fail fast on a forward-migrated msb.db
├── doctor.rs               # operator diagnostics and db recovery
└── …                       # clipboard, pull, setup, user, env_flag, …

images/                     # the base OCI image and its build script
vendor/microsandbox/        # git submodule: the runtime and its SDK
bin/agent-vm-ccusage        # host-side token/cost reporting across sandboxes
```

A launch is one pass, and the ordering is load-bearing:

1. `main()` resolves and version-verifies the bundled `msb`, then points
   `MSB_PATH`/`MSB_HOME` at it — **before** constructing the tokio runtime,
   because those are `setenv` calls and `setenv` is not thread-safe under POSIX.
2. `msb_preflight` refuses to continue against a `msb.db` newer than the
   bundled schema.
3. `session` derives the project hash, state dir, and sandbox name from the cwd.
4. `secrets` captures host credentials into host-only files and writes
   placeholder credentials into the guest state dir.
5. `run::launch` builds the sandbox — image, mounts, guest user, PATH, network
   plan, then the credential-injection overlay — and creates it.
6. The agent runs, attached to a PTY or through a streaming exec.
7. Teardown stops the sandbox, removes it, and re-checks the credential
   snapshot.

### Why a git submodule for microsandbox

agent-vm depends on microsandbox primitives that are not merely API surface —
file-backed secrets and request interception decide whether a token can leak.
A submodule pinned to `gregwebs/microsandbox` makes the checkout
self-contained, makes the diff against upstream reviewable, and is honest about
the fact that the runtime is vendored.

`[patch.crates-io]` also works, but it splits the source-of-truth pointer
across `Cargo.lock` and a patch table, and hides the vendoring. A path
dependency on a sibling checkout works for one developer and for nobody else.

The submodule is **not** a fork any more: agent-vm builds against the stock
crates.io `msb_krun*` cohort, and the fork it used to carry was retired
([ADR-0006](docs/adr/0006-adopt-clean-v0.6.15-baseline.md)). What remains
vendored is the microsandbox source itself, at a pinned version.

## Sandboxes and sessions

### Project-scoped identity

Each project directory gets:

- **A short hash** — the first 6 bytes of `SHA256(canonical(cwd))` as 12 hex
  chars. ~48 bits is plenty for "no two project dirs on one host collide", and
  it is short enough to fit in a hostname, which makes it visible from inside
  the guest when debugging.
- **A state directory**,
  `${AGENT_VM_STATE_DIR-${XDG_STATE_HOME-$HOME/.local/state}/agent-vm}/<hash>/`.
- **A sandbox name**, `agent-vm-<hash>-<pid>`.

The PID suffix is deliberate. An earlier design used a bare `agent-vm-<hash>`,
which made the name double as garbage collection: a second launch in the same
project would `.replace()` the first, giving it 10 s to exit and then killing
it. That is wrong once you want two agents in one project at once, so the name
became per-launch — at the cost of losing the implicit GC. `reap_stale_project_sandboxes`
(`run.rs`) restores it explicitly, removing leftover `agent-vm-<hash>-<pid>`
entries whose PID is no longer alive, so a launcher that crashed between create
and teardown does not leak its overlay, logs, and DB row forever. Liveness is
checked before removal, so a peer launcher running right now is never touched.

The launcher prints one banner (`==> <sandbox> in <cwd> (state: <dir>)`) so it
is always clear which project a VM belongs to.

### Mounts: one for the workspace, one for state

The guest gets exactly two bind mounts of its own:

- `cwd → ` the project's own host path (so in-guest paths match host paths).
- `<state-dir> → /agent-vm-state` — everything else.

Per-agent state is arranged *under* that single state mount rather than as
separate mounts:

- `$HOME/.claude → /agent-vm-state/claude`
- `$HOME/.local/share/opencode → /agent-vm-state/opencode`
- Codex instead gets `CODEX_HOME=/agent-vm-state/codex`, because
  `<install-prefix>/.codex/packages/…` contains the codex binary itself and a
  symlink there would shadow it.

This shape originally fell out of a hard virtio-IRQ ceiling (below). The
ceiling is lifted and the shape stayed, because it is better on its own terms:
one virtio-fs server, a stable on-host layout, and a constant mount count no
matter how many agents are added later — which leaves the device budget for the
user's own `--mount` arguments.

Where those symlinks get created depends on the guest user, and the asymmetry
is easy to trip over. `.patch()` bakes into the rootfs upper overlay *before*
the VM boots, so it works for root mode's `/root/…` links (un-shadowed rootfs)
but is invisible for the non-root default, whose `HOME` lives under
`/agent-vm-state` — a *runtime* bind mount that shadows whatever the patch
wrote. Non-root links are therefore materialized host-side by
`ProjectSession::provision_guest_home`, dangling on the host and resolving once
mounted. Both paths draw from the same `session::GUEST_HOME_LINKS` table.

### Extra mounts: `ro`, `rw`, `follow-links`

`--mount HOST[:GUEST][:MODE]...` (`mount.rs`).

**Modes are a suffix list, not a flag.** `ro`/`rw` could have been separate
flags (`--mount-ro`), but the mode belongs to *that* mount, not to the launch.
`rw` is the default and is accepted only so a `--mount` line can say what it
means.

**`ro` and `follow-links` deliberately coexist.** `follow-links` *implies*
read-only, so they are not mutually exclusive — which is why the conflict
policy lives in one table in `mount.rs` rather than being spread across
per-pair checks that would each have to encode the exception.

**`follow-links` binds the real directories, not the links.** virtio-fs passes
a symlink through as a symlink, so a link pointing outside the bind is dangling
in the guest. The walk resolves links under `HOST` transitively and appends one
read-only bind per discovered target directory, with a depth cap on
*link-follow chains* specifically — not on ordinary directory nesting, which is
unbounded and fine. Discovered binds carry `follow_links: false`, so the walk
cannot re-expand its own output.

**Targets are bound at their literal guest path.** A discovered target is
reachable in the guest by the path the link text implies, which is not always
its canonicalized host path: canonicalization resolves symlinks *before*
applying a following `..`, so the two answers part company exactly there.
Binding at the canonical path would leave the guest resolving a link to a path
nothing is mounted at. The rejected alternative — rewriting link text inside
the guest — mutates the user's project.

### Split irqchip and the virtio-IRQ ceiling

`msb_krun` exposes `MachineBuilder::split_irqchip(bool)`. With it off, libkrun
uses KVM's in-kernel IOAPIC: hard-capped at 24 pins, and only IRQs 5..=15 go to
virtio-mmio — about 11 for the whole VM. Rootfs lower + rootfs upper +
virtio-net + virtio-vsock + virtio-console + two virtio-fs binds already
saturates that, so a single extra `--mount` tripped
`RegisterNetDevice(IrqsExhausted)` at boot.

With it on, `msb_krun` runs a userspace IOAPIC backed by an event-loop thread
it spawns automatically. The cost is one extra worker thread per VM and a
slightly hotter IRQ delivery path. The runtime enables it unconditionally
(`vendor/microsandbox/crates/runtime/lib/vm.rs`).

Resulting capacity is an **observed, host-specific property, not a portable
limit** — Linux x86_64 uses this IOAPIC path while Apple Silicon uses GIC — so
it is recorded as conservative per-platform test profiles rather than promised
as a CLI contract.

Worth knowing if you go archaeology-hunting: the multi-mount boot failure that
drove this work was not the KVM pin cap itself but a separate bug inside
`msb_krun_devices`' userspace IOAPIC, only reachable *once* split irqchip was
turned on (a `u32` IRR that silently dropped any IRQ on pin ≥ 32, and an
unchecked redirection-table index that wrapped on any access below the table
base). Both were fixed upstream in `msb_krun` 0.1.13.

### Runtime provenance and platform profiles

`./script/check-runtime-provenance.sh` checks both independent Cargo roots (the
outer workspace and `vendor/microsandbox`) for the identical official crates.io
`msb_krun*` 0.1.32 cohort and checksum map, plus the pinned `vendor/libkrunfw`
gitlink, firmware version/ABI, and the x86 source-configuration contract. This
establishes **source identity**, not an attestation that a given executable came
from that source; release provenance is separate, unfinished work.

The public-CLI compatibility harness is `script/test/msb-krun-compat.sh`. It
keeps process, Docker, fixture, and guest-probe orchestration in shell, while
`crates/msb-krun-compat-evidence` parses and validates host-side evidence and
writes its JSON records. That evidence crate is a separate small workspace
member so the contract stays buildable ahead of the vendored `agentd` and the
agent-vm runtime dependencies; the static Python provenance checker stays
Cargo-independent for the same reason.

On Apple Silicon macOS/HVF the device-discovery proof uses the flattened device
tree plus guest sysfs and `virtiofs` mountinfo rather than an x86 command-line
proxy. A zero-user-bind baseline is compared against each case: every added
bind must add one `virtio,mmio` FDT node and one bound `virtiofs` device, and
selected low/boundary/final mounts must read their unique host marker and write
a unique value back.

The accepted Darwin profile is conservative test policy — boundary samples 4
and 64, high case 112, stress case 64 — and is **not** a capacity claim. The
measured host booted through 128 user binds; 256 was the first attempted
failure (`RegisterFsDevice(IrqsExhausted)`); 129–255 were never tested, so the
real maximum is unmeasured. Darwin's `/proc/cmdline` stayed around 202 bytes
because arm64 HVF describes virtio-mmio devices in the device tree, so the
pinned firmware's 16 KiB command-line setting and the >2 KiB trailing-
`virtio_mmio.device=` acceptance proof are Linux x86_64 KVM-only.

Linux x86_64 KVM still needs its own live `measure`, reviewed
boundary/high/cmdline/stress constants, command-line declaration
ordering/count proof, and split-irqchip/IOAPIC diagnostics. Darwin evidence
satisfies none of those.

### Interactive attach vs. non-TTY streaming exec

`Sandbox::attach()` needs a real controlling TTY — it puts stdin in raw mode and
opens `/dev/tty` for its non-blocking input fd — and returns ENXIO when stdin is
a pipe, a redirect, or CI. The launcher checks `stdin().is_terminal()`:

- **TTY** → `attach(cmd, args)`, so the agent's TUI gets a full PTY.
- **No TTY** → `exec_stream_with(...)`, which streams stdout/stderr as they are
  produced and forwards the exit code.

The streaming form matters: the SDK's buffer-until-exit `exec_with` made a long
non-interactive run look hung, so there are no `.exec_with(` call sites left.

The exec loop races the event stream against `Sandbox::wait()` so a VMM that
dies mid-stream produces a diagnostic rather than a hang on `recv()`; see
[Sandbox liveness](#sandbox-liveness-idle-detection-and-runtime-exits).

### Guest `PATH`

`attach()` and `exec()` both spawn via `execve` directly, so the image's `ENV
PATH` — which only takes effect for a shell that sources the profile — is not
in play. The launcher reads `PATH` out of the booted image's OCI config
(`path_from_config_env`, last `PATH=` entry wins, matching successive shell
assignments across base and derived `ENV` layers) and publishes it on the
builder. `FALLBACK_GUEST_PATH` covers the cold-start case where image metadata
is not cached yet, and is hand-synced with `images/Dockerfile`.

Agent binaries live under `/opt/agent` — a shared, world-readable prefix
(`chmod -R a+rX`) rather than `/root` — so the same `PATH` resolves identically
whether the guest runs non-root or as root.

### Guest user (non-root by default) / `--root`

Full rationale in
[ADR-0001](docs/adr/0001-non-root-guest-via-native-user.md) and
[ADR-0002](docs/adr/0002-mirror-host-home-and-username.md).

`launch()` resolves root-vs-non-root up front (`--root` or a truthy
`AGENT_VM_ROOT`). In the default non-root mode it passes `libc::getuid()`/
`getgid()` as `"{uid}:{gid}"` to `.user(...)` on the **attach/exec** builders —
not the sandbox builder, because `agentd` (PID 1) has to stay root in order to
`setuid` per exec. The guest gets an `/etc/passwd`+`/etc/group` entry for that
uid via `.patch().append(...)`, and its `HOME` under `/agent-vm-state/home`.

Matching the host uid is not only defense-in-depth: passthroughfs only grants
owner bits to a non-root guest uid when it equals the real host uid, so it is
what keeps the project and state binds writable.

`--root`/`AGENT_VM_ROOT` restores the legacy root guest. Docker-in-VM needs it,
and the Chrome MCP's `sudo -u chrome` path is root-mode-only.

`IS_SANDBOX=1` is set unconditionally. Claude Code refuses to run as root with
`--dangerously-skip-permissions` unless it is set; under the non-root default
that refusal never triggers anyway, and under `--root` this is exactly what the
variable is for. The microVM is the security boundary either way.

### Sandbox liveness: idle detection and runtime exits

A sandbox is a libkrun microVM: the launcher spawns a hidden `msb sandbox …`
child (the VMM) which runs the vendored runtime and never returns — libkrun
calls `_exit()` on shutdown. Three separate things decide when that ends, and
the division of labour between them is the whole design.
Background: [ADR-0007](docs/adr/0007-heartbeat-keep-alive-and-runtime-exit-reporting.md)
— but note that ADR proposes a staleness-budget design that is *not* what
ships; see [issue #86](https://github.com/gregwebs/agent-vm/issues/86).

**The heartbeat monitor only answers "is this sandbox idle?"** `agentd` writes
`/.msb/heartbeat.json` once a second and it appears host-side via virtiofs;
`HeartbeatReader::check` (`vendor/microsandbox/crates/runtime/lib/heartbeat.rs`)
polls it from a monitor task in `vm.rs` and returns exactly three decisions —
`PendingBoot`, `Active`, `Idle`.

A stale or missing heartbeat is deliberately **never, on its own, grounds to
kill a sandbox**. That is the lesson from a long-lived PTY session that got
reclaimed mid-use: under host load or virtiofs write latency `heartbeat_seq`
can stop advancing for seconds while the guest is perfectly healthy, so any
staleness budget kills exactly the busy-but-momentarily-quiet sessions it was
supposed to protect. A busy-but-quiet agent is a healthy agent. Two
consequences fall out:

- **An active exec session is never idle** — `active_exec_sessions > 0` short-
  circuits to `Active` before the idle timeout is even consulted.
- **No heartbeat seen at all is `PendingBoot`, not death.** The monitor has no
  opinion about a guest that never came up.

**Boot failure belongs to the relay, not the heartbeat.** The 180 s boot
deadline that a heartbeat "boot grace" path used to own now lives where the
information actually is: if the agent relay's `wait_ready` fails (or its task
panics), `vm.rs` stores `EXIT_REASON_AGENT_UNRESPONSIVE` and triggers exit.
That reason surfaces in the DB as `TerminationReason::AgentUnresponsive`.
Moving it there is what let the heartbeat monitor become purely about idleness.

**Idle shutdown is graceful; teardown is bounded.** An `Idle` decision calls
`request_guest_shutdown`, which is `request_guest_shutdown_with_timeout` at a
60 s default; the bounded variant exists for paths that must not wait that long.

**The launcher must never hang on a VMM that is already gone.** agent-vm's
streaming-exec loop (`next_exec_step` in `run.rs`) races the exec event stream
against `Sandbox::wait()` with `tokio::select!`. In the ordinary case the relay
socket closing when the VMM dies ends the event stream promptly (`recv()` →
`None`, handled as an actionable "stream ended without Exited" error rather
than being conflated with "the agent exited 1"). The race is the
belt-and-suspenders backstop for when that does not happen. Because the socket
EOFs essentially instantly on a real VMM kill, `recv() → None` wins the race
almost every time, so `next_exec_step` gives the `wait()` future a bounded
chance to finish *after* the stream closes rather than dropping it mid-flight.

## The base image

### What is in it

The Dockerfile (`images/Dockerfile`, Debian 13 slim) carries what the agents
need and the tools that are universally useful in an agent session: base CLI
utilities (`curl`, `wget`, `git`, `jq`, `python3`, `ripgrep`, `fd-find`) plus
network and process diagnostics, `gh` from the GitHub apt repo, Node.js 22 from
NodeSource, the Docker engine with `fuse-overlayfs`, zellij, the four
`claude-plugins-official` LSP servers, and the agent CLIs themselves — Claude
Code, Codex, OpenCode, and `@github/copilot` — installed through their canonical
installer scripts so the image tracks upstream release channels.

Every line has to keep working through `apt-get update` churn, so the bar to
add anything is "needed by an in-scope agent flow". Chromium is *not* in the
base image: it is an opt-in `examples/layers/chrome-devtools` tooling layer,
detected after boot via an image-capability marker.

Two build-time subtleties are worth knowing:

- The agent CLIs are installed under `HOME=/opt/agent` and the tree is made
  world-readable, which is what lets the same `PATH` work for both guest-user
  modes.
- The running guest symlinks `$HOME/.claude` onto persistent state, which
  **shadows** the LSP plugin tree baked at build time. The build therefore
  stashes the plugins to `/opt/agent-vm/claude-seed` and the launcher prelude
  re-seeds them (`SEED_CLAUDE_PLUGINS` in `run.rs`). Without that the guest
  ships with zero plugins and the build still looks clean.

### Distribution: OCI references, not bind or disk images

microsandbox's `RootfsSource` supports an OCI reference, a host directory
(`Bind`), or a qcow2/raw/vmdk file. agent-vm uses the OCI path, defaulting to
`ghcr.io/wirenboard/agent-vm-template:latest`.

- **Standard OCI semantics.** microsandbox's layer cache, GC, snapshotting, and
  metadata DB all key off OCI references. Going through that path means getting
  all of it for free.
- **`Bind` would need overlay management.** It hands a host directory to the VM
  as the rootfs, so sharing one template across concurrent sandboxes would mean
  building copy-on-write on top. The layer cache already does this.
- **A disk image would mean building rootfs images ourselves** with
  `debootstrap` + `mkfs.ext4` — a slower, less familiar loop than
  `docker build`.

The binary and the image are version-locked by an **image-API-version** integer
(`/etc/agent-vm-image-version`), so a mismatch is a clean launch-time error
rather than a mysterious in-VM failure.

`images/build.sh` builds and pushes through a loopback `registry:2` as a
separate developer workflow; it is not called by `agent-vm setup`. Docker's CLI
stays the right interface for it — that keeps volume, port-forwarding, and
`docker inspect` details out of the Rust binary, and means rebuilding the image
does not recompile the binary or vice versa. Apple Silicon developers can skip
the registry entirely with `script/build/import-image.sh`.

The Rust side does own the **verify** step (boot the pulled image, run the
agents' `--version`), because that is exactly the SDK call the launcher makes —
exercising it from `setup` catches image/SDK integration regressions before a
user session depends on them. `--no-verify` skips it for Dockerfile iteration;
`--image` / `AGENT_VM_IMAGE_TAG` points at an alternative tag without touching
`build.sh`.

Project tooling layers (`.agent-vm/layers/*/`, plus any `--layer DIR`
appended after them) are an ordered chain, each step's Dockerfile built
`FROM` the previous one; only the final image is booted, ingested
registry-lessly. See [ADR-0003](docs/adr/0003-project-tooling-layers.md).

## Credentials

The guarantee: **a real token never enters the VM, in any form.** Not in the
environment, not in a file the guest can read, not in the sandbox config, and
not in an OAuth response. The guest holds placeholders; the proxy substitutes
on the way out.

Current design of record:
[ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md).

### The two-layer placeholder dance

Per provider, at every launch:

1. **Host side.** agent-vm reads the host credential file
   (`~/.claude/.credentials.json`, `~/.codex/auth.json`,
   `~/.local/share/opencode/auth.json`, `gh auth token`), and writes the real
   bearer to a host-only file with 0600 perms via atomic-write-then-rename.
   Placeholder *constants* live in `secrets.rs`
   (`ANTHROPIC_ACCESS_PLACEHOLDER` and friends) — always prefer the constant
   over the literal so a rename cannot drift.
2. **Guest side.** A placeholder credentials JSON goes into the per-project
   state dir. Other fields (`expiresAt`, `scopes`, `account_id`, …) are copied
   from the host file so the in-VM agent sees a plausible shape.
3. **On the wire.** The TLS-intercept proxy sees
   `Authorization: Bearer msb-…-placeholder-…` going to an allowed host,
   splices in the real token, and forwards.

Placeholders are kept **short**: long ones (more than a few hundred bytes)
break sandbox boot at the runtime handshake with `handshake read id_offset:`.
Where a provider requires a JWT *shape*, the placeholder is a minimal
`alg:none` synthetic JWT rather than anything realistic.

Substitution is bound to an **exact host** per credential, so a placeholder
that reaches any other host is never swapped — and, because microsandbox
treats a placeholder heading somewhere unexpected as a violation, is blocked
and logged rather than leaked.

### Token files live outside the guest bind mount

The per-project `state_dir` is bind-mounted into the guest as a single mount,
which makes mount placement security-critical: **anything under `state_dir` is
readable from inside the VM.**

Real token files therefore live in a *sibling* host-only directory,
`${state_root}/<hash>.secrets/` (0700), derived from `state_dir` by
`secrets.rs` so the launcher and the hook agree on the path without passing it
around. The proxy reads them host-side, so they never need mounting at all.

This was a real leak, not a hypothetical: the first cut wrote tokens to
`<state>/tokens/{anthropic,openai}` — inside the mount — so
`cat /agent-vm-state/tokens/anthropic` in the guest returned the host's real
bearer, silently defeating the whole guarantee. A
`token_files_live_outside_the_guest_mount` unit test now pins the invariant.

### File-backed secrets and per-connection re-read

The launcher hands microsandbox a `SecretSource::File` path rather than a token
string. The proxy resolves it at **connection-setup** time, so every new TCP
connection re-reads the file and any host-side rotation — by our own refresh
hook, or by the user simply running `claude` on the host — is visible to the
very next request with no sandbox rebuild.

This is also why token bytes are never serialized into sandbox configuration:
the config carries a path, not a secret.

### The OAuth refresh MITM

The launcher registers an interceptor with per-route rules:

```rust
.intercept(|i| i
    .hook(["…/agent-vm", "_intercept-hook", "--state-dir", "…"])
    .rule("platform.claude.com", "POST", "/v1/oauth/token")
    .rule("auth.openai.com",     "POST", "/oauth/token"))
```

When the in-VM agent posts a refresh, the proxy buffers the request (2 MiB cap;
oversized OAuth and GitHub API requests are refused, while smart-HTTP dispatches
on headers and streams its body after the repository verdict), spawns the hook
with the bytes on stdin and the matched route in env vars, writes the hook's
stdout back to the guest under the forged TLS cert, and closes — **without ever
contacting the upstream server**.

The hook is the same binary in a hidden subcommand:

1. **Validate before acting.** Strict HTTP/1.1 framing, Host/SNI/authority,
   exact provider route, encoding, grant type, and the refresh placeholder are
   all checked before anything can take a lock, spawn a process, or touch a
   file.
2. **Inspect with a fresh clock.** A bearer comfortably above the serving floor
   is re-synced and served with **no host command spawned**. A missing,
   unreadable, or malformed credential never spawns one either — it is
   unavailable outright, and host `claude login` / `codex login` is what
   recovers it.
3. **Rotate only when due.** A bearer at or under the provider's serving margin
   takes a per-provider host-only lock (bounded, 20 s ceiling), re-reads under
   the lock, and — unless it is already fine or damped by a fresh 30-second
   attempt stamp — runs the host CLI (`claude -p hi --model sonnet`, or
   `codex exec --skip-git-repo-check 'Reply with OK'`) in an empty 0700 working
   directory with a cleared allow-listed environment, no bypass flags, and a
   bounded process-group reap. The CLI rotates the host credential file the
   ordinary way.
4. **Install under the lock.** Whether the CLI ran, failed, or was skipped, the
   hook re-reads the host file once more *while still holding the lock* and
   rewrites the host-only token file. Holding the lock through the install is
   what stops a launcher from re-capturing a stale host snapshot and clobbering
   a token this rotation just installed.
5. **Reply in placeholders only.** The response is a synthesized OAuth
   refresh-response JSON shaped like the upstream server's, with placeholder
   `access_token`/`refresh_token`. `scope` is always a bounded, RFC 6749
   `scope-token`-filtered, space-joined string that always contains
   `user:inference` — normalized, never passed through from host data. Every
   expected post-validation failure becomes a typed `503
   temporarily_unavailable` naming the host re-login command, never a raw error
   or a dropped connection.

Stdout is the interceptor protocol channel, not a logging sink; that is what
resolves the cleartext-logging concern without suppression.

**Why a subprocess and not a callback.** `Vec<Box<dyn RequestInterceptor>>` is
not serializable, and the network config is JSON-piped from the SDK to a
separate `msb` process, so anything configured SDK-side has to round-trip
through JSON. Refresh requests are rare — once an hour at worst — so
fork-per-request costs nothing against the host CLI invocation the hook makes
anyway. And a subprocess can dispatch on any logic without re-extending
microsandbox per provider.

**Single-flight.** Same-provider, same-project refreshes serialize on a
host-only `flock` held through final credential installation, with the
attempt-damping stamp so a late waiter skips a redundant CLI run. Cross-project
refreshes may still duplicate work and fall back on the provider CLI's own
locking.

### GitHub scoping

`gh`/`git` credentials are constrained to a per-launch repository allow-list,
built from the cwd's `git remote -v`, its `.gitmodules`, and any `--repo`
overrides.

Allow-listed REST routes receive the bearer; off-list, malformed, and unknown
REST routes get a synthesized 403. Off-list smart-HTTP alone may continue
**anonymously**, with `Authorization` stripped, so a public clone still works.
GraphQL mutations are denied outright until they can be bound soundly to an
allow-listed repository — a deliberate compatibility cost, tracked in PLAN.md.

### Static provider keys and guest-state safety

OpenCode static API keys are captured only for OpenCode and `shell` launches,
each stored in its own 0600 sibling file and substituted only on its exact
provider host. They have no hook route and refresh on relaunch, not in session.
Copilot is file-backed the same way and likewise has no in-session refresh.

Guest state is writable by the guest uid, so it is never trusted through a
joined pathname after launch. Reads, create-if-absent defaults, and atomic
replacements all use descriptor-relative no-follow opens anchored under the
opened state root, portably across Linux and Darwin.

A launch whose Claude credential could not be captured **fails closed before
boot** rather than starting a signed-out agent — and `secrets::refresh` removes
any guest Claude placeholder left from an earlier successful launch, since a
stale placeholder would be sent verbatim as a bearer and the agent would look
signed in until every request 401'd.

### Host-credential security snapshot

At launch, `snapshot_host_creds` SHA-256s the three host credential files;
`verify_snapshot` re-hashes them on exit through a `SnapshotGuard` `Drop` and
prints one line naming any that changed.

**Non-fatal by design.** The refresh hook legitimately rewrites these files
mid-session, so a change is not proof of tampering — the value is that an
*unexpected* change becomes visible. Failing a launch on a legitimate refresh
would be worse than the warning.

**The `Drop` impl must never panic.** It has nowhere to propagate an error, and
`eprintln!` panics on a stderr write failure, which would convert a clean
launch failure into an abrupt exit-101. The notice is therefore a best-effort
`writeln!` with its result discarded.

Scope is those three files only; extending it to project integrity is tracked
in PLAN.md.

### Verified behaviour

The guarantee has been checked from inside a guest, not just reasoned about:

- `cat` of the guest credentials file shows the placeholder, not the token.
- `/proc/1/environ` contains no real token.
- A TLS-intercepted request shows the microsandbox CA on the server cert,
  confirming it goes through the substitution proxy.

And the refresh path end-to-end, against a real host `claude`:

```
Guest → POST https://platform.claude.com/v1/oauth/token
        {"grant_type":"refresh_token","refresh_token":"…PLACEHOLDER_REFRESH…"}

Guest ← HTTP 200 application/json
        {"access_token":"msb-anthropic-placeholder-a-v2",
         "refresh_token":"msb-anthropic-placeholder-r-v2",
         "expires_in":3499,"token_type":"Bearer",
         "scope":"user:file_upload user:inference"}
```

The hook ran, host `claude -p` rotated the host file, the new bearer landed in
`<state>.secrets/anthropic`, and the synthesized response reached the guest.
`expires_in: 3499` is the freshly derived seconds-until-expiry of the token that
was just rotated.

## Runtime and state

### `msb` is pinned via `MSB_PATH`

Every invocation resolves its bundled `msb` and confirms `msb --version`
reports exactly the official upstream version this build vendors
(`msb_install::verify_official_identity`), then sets `MSB_PATH` — the top of
microsandbox's resolution ladder — so a separately installed `msb` cannot
shadow it. Discovery prefers an explicit `MSB_PATH`, then an `msb` sibling in
an installed bundle, then the source artifact at
`vendor/microsandbox/build/msb`. The user's `~/.microsandbox/bin/msb` is never
touched, so other microsandbox tooling on the same host keeps working.

`agent-vm setup` does not build or refresh `msb`; it pulls and optionally boots
the selected image. Production of the vendored runtime belongs to
`script/build/macos.sh`, which drives the pinned macOS build sequence and
assembles the signed artifact with its firmware — so `just` is not a root build
prerequisite. On macOS, Cargo's raw `vendor/microsandbox/target/release/msb`
lacks the `com.apple.security.hypervisor` entitlement and is not a runnable
substitute.

One trap, recorded so nobody re-derives it: the real `msb` binary lives in the
`microsandbox-cli` crate. The `microsandbox` crate ships a *different* `msb`
binary that is a 5-line shim forwarding to `~/.microsandbox/bin/msb`. Building
the wrong target yields a ~389 KB shim that boots silently and then hangs at VM
init, with no VMM symbols in the binary to explain why.

### One shared `MSB_HOME`

agent-vm keeps its sandbox registry in a private `MSB_HOME` rather than the
user's `~/.microsandbox`, so a separately installed `msb ls` does not see
agent-vm's sandboxes and vice versa. It is a single flat directory shared by
every agent-vm build on the host, deliberately *not* namespaced per schema —
see [ADR-0004](docs/adr/0004-single-shared-msb-home.md), and note the macOS
socket-path length constraint that decision turns on.

### Forward-migration preflight

sea-orm migrations in microsandbox are one-way. If a newer, separately
installed `msb` opens agent-vm's private `msb.db`, it forward-migrates the
schema and the older bundled `msb` can never open it again — historically
surfacing as an opaque raw sea-orm error on the next command.

`msb_preflight` detects this up front, on both the boot path and the `msb`
passthrough (any msb subcommand can open the db, so the guard cannot live only
in `launch`), and its error names the recovery command. Migration of genuine
0.5.7 state is a separate, supported path:
[ADR-0008](docs/adr/0008-migrate-0.5.7-state-to-v0.6.15.md).

### State operations: `msb` passthrough and `doctor`

**`agent-vm msb <args…>` is a verbatim passthrough** (`msb_cmd.rs`), not a
curated subset: it execs the pinned binary with `MSB_PATH`/`MSB_HOME` already
set, inherits stdio and environment, and maps the child's exit status through
(signal death → `128+signo`, so it can never read as success). Re-exposing a
chosen subset would mean tracking msb's CLI forever; the point is that `ls`,
`ps`, `stop`, `exec`, `logs` and the rest work exactly as documented upstream.
`disable_help_flag` lets `--help` reach msb instead of clap.

**`agent-vm doctor` is the operator surface** (`doctor.rs`) for two questions
the launcher cannot answer mid-failure: what credentials the host actually has
(present / absent / unusable, Claude token expiry, and which reached this
project — never token bytes), and whether the private db is recoverable.

`--reset-msb-db` moves `MSB_HOME/db` aside to a timestamped sibling rather than
deleting it: reversible by construction, and the undo `mv` is printed. msb owns
that directory outright — no agent-vm code creates, opens, or writes it — so it
recreates it at the bundled schema on next boot and re-pulls images.

### Shared OCI image cache (opt-in)

`AGENT_VM_SHARE_MSB_CACHE` points msb's image cache at the
`~/.microsandbox/cache` a separately installed msb uses, instead of agent-vm's
private `MSB_HOME/cache`; `AGENT_VM_MSB_CACHE_DIR` overrides the location for a
non-default layout (`msb_install.rs`).

Off by default, because sharing a cache couples agent-vm's image state to a
binary it does not version-check. The value goes through the strict `env_flag`
parser, so a typo fails closed to the private cache rather than silently
enabling sharing.

## Host-side tools

### Clipboard exchange

`agent-vm clipboard {get,put}` (`clipboard.rs`) moves a string across the VM
boundary through a per-project `<state>/clipboard.txt`, bind-mounted into the
guest at `/agent-vm-state/clipboard.txt`.

**Why a file and not a channel.** The guest already has the state mount; a file
needs no new device, no port, no protocol, and no guest-side agent-vm binary —
the agent just reads and writes a path. A vsock or HTTP channel would add a
second control plane for a feature whose entire job is handing over some text.

**Why the system clipboard is opt-in (`--sys`).** Reaching X11/Wayland/macOS
pasteboard means shelling out to whichever of `xclip` / `wl-copy` / `wl-paste`
/ `pbcopy` / `pbpaste` exists — a host-environment dependency. Without the
flag the command is pure stdio and works headless.

### `agent-vm-ccusage`

`bin/agent-vm-ccusage` unions the host's `~/.claude` session history with every
per-project agent-vm session dir under the state root and hands the combined
list to `ccusage` via `CLAUDE_CONFIG_DIR`, so token/cost reporting covers host
*and* sandbox sessions in one summary.

It resolves the state root by the same precedence the launcher uses, and
*skips* any directory whose path contains a comma: `CLAUDE_CONFIG_DIR` is
comma-separated with no escape mechanism, so such a path would silently
mis-tokenize into two wrong directories. Skipping with a warning beats merging
directories the user never asked for.

## Decision record index

| Decision | ADR |
|---|---|
| Non-root guest via a native user | [ADR-0001](docs/adr/0001-non-root-guest-via-native-user.md) |
| Mirroring the host `$HOME` and username into the guest | [ADR-0002](docs/adr/0002-mirror-host-home-and-username.md) |
| Project tooling layers (`.agent-vm/layers/`, plus any `--layer DIR`) | [ADR-0003](docs/adr/0003-project-tooling-layers.md) |
| One shared `MSB_HOME`, not schema-namespaced | [ADR-0004](docs/adr/0004-single-shared-msb-home.md) |
| Deferring the sea-orm / sqlx major bump | [ADR-0005](docs/adr/0005-defer-sea-orm-sqlx-major-bump.md) |
| Adopting a clean microsandbox v0.6.15 baseline (dropping the fork) | [ADR-0006](docs/adr/0006-adopt-clean-v0.6.15-baseline.md) |
| Heartbeat keep-alive and runtime-exit reporting | [ADR-0007](docs/adr/0007-heartbeat-keep-alive-and-runtime-exit-reporting.md) |
| Migrating 0.5.7 state to v0.6.15 | [ADR-0008](docs/adr/0008-migrate-0.5.7-state-to-v0.6.15.md) |
| Adopting `origin/main`'s network features | [ADR-0009](docs/adr/0009-adopt-origin-main-network-features.md) |
| Wiring file-backed credential injection | [ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md) |

## Deliberate non-goals

Things that were considered and rejected, so they do not get re-proposed. These
are settled design positions; work that is merely *unbuilt* lives in
[PLAN.md](PLAN.md).

- **No proactive token-expiry timer.** The guest's own refresh attempt at
  401-time triggers the hook, which triggers the host-side refresh. If the user
  ran `claude` on the host between sessions, the file is already fresh and the
  per-connection re-read picks it up with no hook at all. A timer is
  belt-and-suspenders.
- **No replacing `~/.microsandbox/bin/msb`.** The `MSB_PATH` override is
  per-invocation, so other microsandbox SDK consumers on the same host keep
  using their own prebuilt.
- **No cross-project refresh single-flight.** The lock is per provider, per
  project. Different projects may duplicate a refresh and fall back on the
  provider CLI's own credential locking.
- **No proactive `try_wait()` polling from a timer.** The exec-stream race and
  the relay's EOF handling already surface a VMM death promptly for the paths
  that matter; a poll loop would duplicate that without covering a new case.
- **No heartbeat staleness budget.** Killing a sandbox because its heartbeat
  went quiet reclaims healthy, busy sessions; boot failure is the relay's job.
  See [Sandbox liveness](#sandbox-liveness-idle-detection-and-runtime-exits).
- **No stderr-tee task.** The VMM's stderr is redirected straight into
  `runtime.log` via `Stdio::from(...)`, so there is no separate task to drain
  or race in `wait()`.
- **No in-VM proxy.** microsandbox does the interception on the host side;
  there is nothing for `mitmproxy` or similar to do inside the guest.
- **No env-var credential path.** Forwarding `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`
  from the host was the bootstrap approach and is gone: it cannot express host
  OAuth, and it puts a real secret in `/proc/$$/environ` inside the guest.
