# Using agent-vm

The full reference for running agent-vm. See [README.md](README.md) for
an overview, and [CONTRIBUTING.md](CONTRIBUTING.md) to build from source
or develop agent-vm.

## Requirements

- Linux with `/dev/kvm` (rw) and membership in the `kvm` group, or an
  Apple Silicon Mac for the [supported source-build workflow](macos-build.md).
- Node.js 18+ for the npm-distributed launchers.

The packaged Linux workflow installs its matching libkrunfw on first launch.
Apple Silicon source builds assemble a self-contained local runtime bundle.

## Quick start

```bash
npm install -g @wirenboard/agent-vm        # or: npx @wirenboard/agent-vm <cmd>

agent-vm setup            # pulls the latest image from ghcr.io and verifies it boots

cd ~/your-project
agent-vm claude           # or codex / opencode / shell
```

The npm package bundles a prebuilt `agent-vm` binary, `msb`, and
libkrunfw. agent-vm finds them via `current_exe()`-relative paths, so a
user's separate `~/.microsandbox/bin/msb` (if any) never shadows the
bundled build.

## Subcommands

```
claude | codex | opencode | shell   launch an agent in a per-project sandbox
pull                                refresh the cached image
setup                               pull base image + verify boot
msb <args...>                       forward to the bundled msb (e.g. msb ls, msb status)
clipboard {get,put} [--sys]         exchange a string with the project sandbox
```

`agent-vm` keeps its sandbox registry under a private `MSB_HOME` —
`~/.local/state/agent-vm/msb-home` on Linux, `~/.agent-vm-msb` on macOS
(shortened so per-sandbox Unix-socket paths stay well under macOS's
104-byte `sun_path` limit; override either with `AGENT_VM_STATE_DIR`) —
so a separately-installed `msb ls` won't show the sandboxes agent-vm
launched — it reads the default `~/.microsandbox` instead. `agent-vm msb
ls` (and any other `agent-vm msb <args...>`) forwards to the bundled
`msb` with `MSB_HOME`/`MSB_PATH` already pointed at agent-vm's own
state, so it sees the same sandboxes agent-vm does.

## Image release cadence

The base OCI image (`ghcr.io/wirenboard/agent-vm-template:latest`) is
rebuilt hourly by CI, picking up the latest Claude Code, Codex CLI,
and OpenCode releases automatically. Pin a specific build with
`--image ghcr.io/wirenboard/agent-vm-template:YYYY-MM-DDTHH` (date tags are
immutable; the last 14 days are retained).

The agent-vm binary and the image are version-locked through an
**image-API-version** integer
(`/etc/agent-vm-image-version` inside the image). Mismatch → clean
error at launch instead of mysterious in-VM failures.

Each launcher accepts:

| flag | what |
|---|---|
| `--memory N` | VM memory GiB (default 2) |
| `--cpus N` | vCPUs (default 2) |
| `--image REF` | override the OCI image |
| `--update-check` | check the registry for a newer image on launch (off by default) |
| `--no-git` | skip gh/git auth injection (still respects `--repo`) |
| `--repo OWNER/NAME` | add to the GitHub allow-list (repeatable) |
| `--mount HOST[:GUEST][:ro\|:rw]` | extra bind mount (one virtio-fs each); append `:ro` for a read-only bind, `:rw` is the default; capacity is host-specific ([runtime evidence](ARCHITECTURE.md#issue-43-runtime-proof-and-platform-profiles)) |
| `--root` | run the guest as root (uid 0) instead of the default host user — see [Guest user](#guest-user----root) |
| `--layer DIR` | project tooling-layer directory (default `.agent-vm/layer/`) — see [Project tooling layers](#project-tooling-layers) |
| `--yes` / `-y` | assume "yes" to the tooling-layer build confirmation (CI/non-interactive) |

Trailing args go to the agent: `agent-vm claude -p "say hi"`,
`agent-vm shell -- -c 'cargo test'`.

Env-var knobs (all opt-in; most accept any value, empty included —
`AGENT_VM_UPDATE_CHECK` is the exception, see its row):

| var | what |
|---|---|
| `RUST_LOG` | tracing filter; default `warn`. e.g. `RUST_LOG=agent_vm=debug` |
| `AGENT_VM_PROFILE` | print per-phase wall-time (create/run/stop/remove) |
| `AGENT_VM_DEBUG_CONFIG` | dump the SandboxConfig JSON before boot |
| `AGENT_VM_NO_CHROME_MCP` | disable Chrome MCP auto-configuration for a Chrome-capable image/layer |
| `AGENT_VM_IMAGE_TAG` | override the OCI image (same as `--image`) |
| `AGENT_VM_MEMORY_GIB` / `AGENT_VM_CPUS` | same as `--memory` / `--cpus` |
| `AGENT_VM_UPDATE_CHECK` | opt into the launch-time registry update check (accepted: `1`/`true`/`yes`/`on`) |
| `AGENT_VM_ROOT` | same as `--root` (accepted: `1`/`true`/`yes`/`on`) |
| `AGENT_VM_LAYER` | same as `--layer` |
| `AGENT_VM_YES` | same as `--yes` (accepted: `1`/`true`/`yes`/`on`) |

## Project tooling layers

A project can add tools on top of the base image — compilers,
cross-toolchains, whatever the base doesn't carry — by dropping a
`.agent-vm/layer/Dockerfile` in the project root (or pointing `--layer` /
`AGENT_VM_LAYER` at another directory). When a layer is declared, `agent-vm
claude`/`codex`/`opencode`/`copilot`/`shell` builds base + layer with
`docker buildx build`, loads the result into the microsandbox image cache
**registry-lessly** (no `registry:2` sidecar, no registry contact at boot),
and boots that derived image instead of the base.

The derived image is content-hash-identified — the tag itself
(`agent-vm-layer:<project-slug>-<hash>`) is the staleness check. An
unchanged layer boots straight from the cache on every launch after the
first; editing the Dockerfile changes the hash and triggers a rebuild.
Building requires `docker buildx` on the host and, unless the hash is
already cached, a one-time confirmation:

```
Build project tooling layer 'agent-vm-layer:my-app-1a2b3c...'? [y/N]
```

Pass `--yes` (or set `AGENT_VM_YES=1`) to skip the prompt — required for
CI/non-interactive launches. A build failure is a hard stop: agent-vm never
falls back to booting the plain base with a missing toolchain.

The Dockerfile must follow a small contract (start `ARG BASE_IMAGE=...` /
`FROM ${BASE_IMAGE}`, keep `ENV PATH` additive, install world-readable
tools; the launcher builds for the host's own architecture, `linux/amd64`
on x86_64 and `linux/arm64` on Apple Silicon) — see
[`docs/adr/0003-project-tooling-layers.md`](docs/adr/0003-project-tooling-layers.md)
for the full contract and design rationale.

## Shared microsandbox image cache

By default agent-vm keeps its microsandbox state — including the OCI image
cache — entirely private under `MSB_HOME` (see above), so a
separately installed `msb` (Homebrew on macOS; a distro package,
`cargo install`, or a from-source build on Linux) can never shadow
agent-vm's KVM-enabled `libkrunfw`. That also means agent-vm and any other
`msb` install each store and pull their own copy of every image.

Set `AGENT_VM_SHARE_MSB_CACHE=1` (accepted values: `1` or `true`) to opt into
redirecting only agent-vm's image cache at the shared `~/.microsandbox/cache`
directory that other `msb` uses, so image layers/vmdk/manifests aren't stored
or pulled twice. Use `AGENT_VM_MSB_CACHE_DIR=<path>` to point at a
non-default cache location instead.

What stays private: `db/`, `tls/`, `secrets/`, and `sandboxes/` remain under
`MSB_HOME`; only the cache is shared. `libkrunfw` is
unaffected (resolved via `MSB_PATH`, not the cache override), so the
shadowing protection above is unchanged.

Caveat: only enable this when the other `msb`'s version is close to the
vendored fork's — the on-disk cache format (erofs/vmdk/manifest schema) is
not guaranteed compatible across microsandbox versions. Avoid running the
two concurrently against the shared cache with mismatched versions. If
images misbehave, unset the variable to fall back to the private cache.

**Reverting is a manual step.** The redirect is persisted to
`MSB_HOME/config.json`. Unsetting
`AGENT_VM_SHARE_MSB_CACHE` does **not** by itself restore the private cache —
agent-vm only writes `config.json` when the flag is on, so a later flag-off
run leaves the previously written `paths.cache` pointing at the shared
directory. To fully revert, delete that `config.json` (or remove the
`paths.cache` key from it).

## Recovering from a forward-migrated microsandbox db

sea-orm migrations in microsandbox are one-way. If a newer, separately
installed `msb` ever opens agent-vm's private `MSB_HOME/db/msb.db`, it
forward-migrates the schema — and the older bundled `msb` agent-vm ships
can then never open that database again. Every subsequent `agent-vm`
command that talks to the db (`claude`, `codex`, `shell`, ...) fails.

agent-vm detects this up front — on `shell`/`run` and on `agent-vm msb
<args...>` — and stops with a message naming the offending migration(s)
instead of letting the raw sea-orm error through. Recover with:

```
agent-vm doctor --reset-msb-db
```

This moves `msb-home/db/` (including the `-wal`/`-shm`/lock files) aside to
a timestamped `db.reset-<epoch-seconds>` sibling — non-destructive, and
reversible: the command prints the exact `mv` to undo it. It resolves
`MSB_HOME` the same way `agent-vm` itself does, so it only ever touches
agent-vm's private state, never a separate `~/.microsandbox` install. If no
`db/` exists, it prints a no-op message and exits 0.

The next `agent-vm shell`/`run` finds no `db/` and lets the bundled `msb`
recreate it fresh at its own schema, re-pulling images on first boot — no
further action needed.

## Upgrading from an older agent-vm (pre-0.6.15) state

Upgrading agent-vm from a build that vendored an older Microsandbox
(0.5.7 and earlier) to one vendoring v0.6.15+ needs no manual step: the
next `agent-vm shell`/`run` forward-migrates `MSB_HOME/db/msb.db`
automatically, in place, on first boot. Existing images, sandbox
records, snapshots, and named volumes remain usable afterward, and
re-running the same or a newer build again is a no-op (see
`docs/adr/0008-migrate-0.5.7-state-to-v0.6.15.md` for how this was
verified).

If you roll **back** to an older agent-vm build after a newer one has
already forward-migrated the db, you'll hit the named ahead-guard
described above — recover the same way, with `agent-vm doctor
--reset-msb-db`.

## Guest user / `--root`

By default the in-guest agent runs as **the host user** — the same
uid/gid that invoked `agent-vm` — instead of root. This is defense-in-depth
on top of the microVM boundary itself; matching the host uid is also
required to keep write access to the project/state bind mounts (a
non-root guest uid only gets owner bits on those when it equals the real
host uid). `whoami`/`id` inside the guest report a user named `agent`
resolving to your host uid/gid; `$HOME` is `/agent-vm-state/home` (a
directory inside the per-project state dir), with the same
`.claude`/`.gitconfig`/`.config/gh`/etc. dotfile symlinks root mode has
always had, just rooted there instead of at `/root`.

Pass `--root` (or set `AGENT_VM_ROOT=1`) to restore the previous
behavior: guest uid 0, `HOME=/root`. You need `--root` for:

- **Docker-in-VM** — `dockerd` needs root; there's no non-root path for it.
- Anything else that specifically expects to run as root inside the guest.

See [`docs/adr/0001-non-root-guest-via-native-user.md`](docs/adr/0001-non-root-guest-via-native-user.md)
for the full design rationale.

## Chrome DevTools MCP

The base image does not include Chromium. Select the marker-bearing
[`chrome-devtools` tooling layer](examples/layers/chrome-devtools/) to install
it and have the launcher add its owned `mcpServers.chrome-devtools` entry.
Removing the layer removes that stale owned entry while preserving other MCPs.
`AGENT_VM_NO_CHROME_MCP=1` removes the automatic entry but leaves Chromium
available for manual use. The wrapper preserves Chromium's nested sandbox:
non-root guests run it directly and root guests switch only to the dedicated
`chrome` user. It imports the per-install microsandbox CA into that user's NSS
database rather than using an insecure certificate flag, and disables MCP
telemetry.

## Credentials

Reads from the host:

- `~/.claude/.credentials.json` (Claude)
- `~/.codex/auth.json` (Codex, OpenCode)
- `gh auth token` (git/gh)

The guest gets placeholder strings; the proxy substitutes on the wire.
Real tokens live in `${XDG_STATE_HOME}/agent-vm/<hash>.secrets/` (0700)
on the host, **outside** the bind mount the guest sees. A SHA-256
snapshot of the three credential files is taken at launch and
re-checked on exit; unexpected mutations print a warning.

The proxy re-reads each configured host-only token file on every eligible
connection. For Claude/Codex, an expired bearer triggers an OAuth hook that
validates the exact request, runs `claude -p`/`codex exec` on the host, and
returns placeholders only; a failed refresh fails the request closed. GitHub
credentials are sent only to the per-launch repository allow-list, so off-list
API calls receive a proxy denial or anonymous smart-HTTP request without the
host bearer. GraphQL mutations are denied until they have a sound
repository-scoped authorization design; use an allow-listed REST route where
available. Copilot has no in-session refresh path: relaunch to recapture an
expired Copilot token.

## Project hook

If the project root contains an executable `.agent-vm.runtime.sh`,
the launcher sources it inside the guest before exec'ing the agent.
Use for `npm install`, env exports, dev-server startup. Non-zero
exit aborts the launch.

## Ports & egress

The default network policy (`public_only`) lets the guest reach
the public internet plus DNS, and denies everything else
(loopback, RFC1918 LAN, link-local, cloud-metadata, the host).
Open holes per-launch with these flags — they compose:

| flag | what it opens | guest-side address |
|---|---|---|
| `--publish HOST:GUEST[/proto]` | host port `HOST` → guest port `GUEST` (`tcp` default; `/udp` for UDP) | inbound to the guest |
| `--auto-publish` | every `0.0.0.0:*` / `127.0.0.1:*` listener inside the guest is mirrored to the host loopback (Lima-style) | host: `127.0.0.1:<guest-port>` |
| `--allow-egress IP\|CIDR` (repeatable) | one IP or one CIDR through the egress deny | dial directly by IP |
| `--allow-lan` | the whole `DestinationGroup::Private` (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) | dial any LAN IP |
| `--allow-host` | the per-sandbox gateway IP, which the smoltcp stack rewrites to host `127.0.0.1` | `host.microsandbox.internal:<port>` (already in guest `/etc/hosts`) |

Loopback (guest's own `127.0.0.1`), link-local, and cloud metadata
(`169.254.169.254`) stay denied even with `--allow-lan` — they're
disjoint groups by design. `--allow-host` is the narrowest way to
reach a dev server bound to host `127.0.0.1`; `--allow-lan` is the
broadest. A compromised in-guest process gets full access to
whatever you open, so prefer the narrowest flag that fits.

## Troubleshooting

- **`RegisterNetDevice(IrqsExhausted)` at boot** — device capacity is host
  and runtime dependent. Drop a `--mount` to recover. Linux x86_64 uses a
  split userspace IOAPIC while Apple Silicon uses GIC; do not infer one
  platform's device limit from another.
- **`handshake read id_offset: timed out`** — `free -h`; the VM needs
  more memory than is available. Try `--memory 1`.
- **GitHub 403 from the proxy** — repo isn't in the allow-list.
  Pass `--repo OWNER/NAME` or run from a project with the right
  remote.
