# agent-vm

Run Claude Code / Codex / OpenCode inside a per-project libkrun microVM,
booting in ~2 seconds, with:

- **Host OAuth tokens never enter the VM.** The TLS-intercept proxy in
  [microsandbox](https://github.com/wirenboard/microsandbox) substitutes
  the real bearer for a placeholder on the way out. OAuth refresh is
  MITM'd so multi-hour sessions survive token rotation.
- **Per-launch GitHub repo allow-list.** Auto-detected from
  `git remote -v`; extend with `--repo OWNER/NAME`. `gh pr create`,
  `git push` etc. are filtered at the proxy — off-list calls get a 403
  before they reach GitHub.
- **Sandbox is the boundary.** The guest runs as your host user by
  default (`--root` for the old root-guest behavior), project bind-mounted
  at its host path, `--dangerously-skip-permissions` set by default
  (the microVM is the only thing actually keeping the agent on rails).

This is the Rust rewrite of the original Bash
[`wirenboard/agent-vm`](https://github.com/wirenboard/agent-vm) on
top of microsandbox. Living on `rewrite-microsandbox` until v1.

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

The npm package bundles a prebuilt `agent-vm` binary, the patched
`msb`, and libkrunfw. agent-vm finds them via
`current_exe()`-relative paths, so a user's separate
`~/.microsandbox/bin/msb` (if any) never shadows the patched build.

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

## Subcommands

```
claude | codex | opencode | shell   launch an agent in a per-project sandbox
pull                                refresh the cached image
setup                               pull base image + verify boot
msb <args...>                       forward to the bundled msb (e.g. msb ls, msb status)
clipboard {get,put} [--sys]         exchange a string with the project sandbox
```

`agent-vm` keeps its sandbox registry under a private `MSB_HOME`
(`~/.local/state/agent-vm/msb-home`), so a separately-installed `msb ls` won't
show the sandboxes agent-vm launched — it reads the default
`~/.microsandbox` instead. `agent-vm msb ls` (and any other `agent-vm msb
<args...>`) forwards to the bundled `msb` with `MSB_HOME`/`MSB_PATH` already
pointed at agent-vm's own state, so it sees the same sandboxes agent-vm does.

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
| `--mount HOST[:GUEST][:ro\|:rw]` | extra bind mount (one virtio-fs each, ~210 mount headroom); append `:ro` for a read-only bind, `:rw` is the default |
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
| `AGENT_VM_NO_CHROME_MCP` | skip the Chrome DevTools MCP entirely (no entry in claude.json, no chrome-user setup at boot) |
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
cache — entirely private under `~/.local/state/agent-vm/msb-home/`, so a
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
`~/.local/state/agent-vm/msb-home/`; only the cache is shared. `libkrunfw` is
unaffected (resolved via `MSB_PATH`, not the cache override), so the
shadowing protection above is unchanged.

Caveat: only enable this when the other `msb`'s version is close to the
vendored fork's — the on-disk cache format (erofs/vmdk/manifest schema) is
not guaranteed compatible across microsandbox versions. Avoid running the
two concurrently against the shared cache with mismatched versions. If
images misbehave, unset the variable to fall back to the private cache.

**Reverting is a manual step.** The redirect is persisted to
`~/.local/state/agent-vm/msb-home/config.json`. Unsetting
`AGENT_VM_SHARE_MSB_CACHE` does **not** by itself restore the private cache —
agent-vm only writes `config.json` when the flag is on, so a later flag-off
run leaves the previously written `paths.cache` pointing at the shared
directory. To fully revert, delete that `config.json` (or remove the
`paths.cache` key from it).

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

The image ships chromium and a `chrome-devtools` MCP entry pinned to
`chrome-devtools-mcp@1.0.1`. To keep chromium's nested user-namespace
sandbox active (we'd rather not pass `--no-sandbox`) chromium needs to run
as a non-root user. In the default non-root guest mode the agent is
already non-root, so the MCP wrapper (`agent-vm-chrome-mcp`) just runs
chromium directly as that user — no `sudo` involved — and imports the
microsandbox MITM CA into its own per-user NSS DB. Under `--root` the
wrapper instead re-execs the MCP under a dedicated `chrome` user via a
sudo wrapper, same as before this change. Either way the launcher/wrapper
installs the per-boot microsandbox MITM CA into the running user's NSS DB
at startup so chromium accepts the intercepted TLS chain without
`--acceptInsecureCerts` (which would trust *any* untrusted cert).

If the CA install fails (e.g. someone broke the in-image sudoers rule)
the launcher prints a warning naming the symptom — without it, every
HTTPS navigate would silently return `ERR_CERT_AUTHORITY_INVALID`.
Set `AGENT_VM_NO_CHROME_MCP=1` to skip the whole setup.

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

For Claude/Codex, when the in-VM agent's bearer expires the
hook MITMs the OAuth refresh, runs `claude -p`/`codex exec` on the
host to rotate, and feeds the new placeholder back to the guest — no
re-attach required.

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

- **`RegisterNetDevice(IrqsExhausted)` at boot** — the userspace split
  irqchip raises the cap to ~219 IRQs, so this should only happen with
  hundreds of `--mount`s or on a host whose KVM lacks
  `KVM_CAP_SPLIT_IRQCHIP` (pre-Linux 4.7 or some nested-virt /
  seccomp-restricted setups). Drop a `--mount` to recover.
- **`handshake read id_offset: timed out`** — `free -h`; the VM needs
  more memory than is available. Try `--memory 1`.
- **GitHub 403 from the proxy** — repo isn't in the allow-list.
  Pass `--repo OWNER/NAME` or run from a project with the right
  remote.

## See also

- [PLAN.md](PLAN.md) — phased roadmap, what's done, what's deferred.
- [ARCHITECTURE.md](ARCHITECTURE.md) — design notes; why things look
  the way they do.
- [AGENTS.md](AGENTS.md) — conventions for coding agents (Claude
  Code, Codex, etc.) working on this repo: post-merge version bump,
  submodule-merge ordering, what not to do.
