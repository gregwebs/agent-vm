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
cargo build

agent-vm setup            # pulls the latest image from ghcr.io and verifies it boots

cd ~/your-project
agent-vm claude           # a configured launch verb; see `agent-vm --help`
```

The npm package bundles a prebuilt `agent-vm` binary, `msb`, and
libkrunfw. agent-vm finds them via `current_exe()`-relative paths, so a
user's separate `~/.microsandbox/bin/msb` (if any) never shadows the
bundled build.

## Subcommands

```
<tool>                              launch a configured tool in a per-project sandbox
                                    (the verbs come from your tool configuration;
                                    run `agent-vm --help` for the exact list)
build --tag REF [OPTIONS] [CONTEXT]  explicitly build + import a user Dockerfile
pull                                refresh the cached image
setup                               pull base image + verify boot
doctor                              report host credentials + microsandbox state
                                    + the resolved tool configuration
                                    (--reset-msb-db recovers a forward-migrated db)
msb <args...>                       forward to the bundled msb (e.g. msb ls, msb status)
clipboard {get,put} [--sys]         exchange a string with the project sandbox
secret set SERVICE                  store or replace one of your own values in the
                                    host system keychain (hidden prompt, or pipe it on stdin)
secret ls                           list the service names agent-vm has stored, and their status
secret rm SERVICE                   remove one stored value
```

The launch verbs are generated from your tool configuration (see *Tool
configuration* below). With no config files you get the seven shipped defaults
`dsh`, `pi`, `codex`, `opencode`, `claude`, `copilot`, `shell`; if your config
declares only `claude`, then only `agent-vm claude` (plus the built-ins and a
`shell` fallback) exists. `agent-vm --help` and `agent-vm doctor` always show
the same list, in the same order.

`agent-vm setup` pulls the selected image and, unless `--no-verify` is given,
boots a throwaway sandbox and verifies **every tool your configuration
declares** by running its `command` with `--version` (a direct argv exec,
never a shell string). A command your configuration does not name is not
checked at all (the built-in `shell` fallback is a launch affordance, not a
declaration, so it is not verified). **Every declared tool is required — on the
default boot image
and on any image you selected** (`--image`, `AGENT_VM_IMAGE_TAG`, or a config
`image`): if a declared command is missing, or its `--version` exits non-zero,
`setup` fails, because agent-vm never installs software. Every tool is expected
to answer `--version`; a presence/executability-only check may be offered later
as an alternative, but is not available today. A failing probe is diagnosed as
one of three cases: no entry found on the guest `PATH` (for a bare command
name) or at the configured path (for a command that names one), present but not
a runnable executable (a non-executable file or a directory), and present and
executable but `--version` failed.
`setup` executes the configured commands inside the
throwaway VM — the
same trust as running any agent-vm command in a directory with a `.agent-vm/`.
A broken config warns and falls back: verification uses the shipped default
tools and the image already selected by `--image`/`AGENT_VM_IMAGE_TAG` (or the
default boot image), so a config typo never blocks the pull/boot/verify
recovery path.

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

The independent [image repository](https://github.com/gregwebs/agent-vm-images)
publishes one standard image, `ghcr.io/gregwebs/agent-vm-standard`, containing
Debian facilities and all six agents (dsh, pi, codex, opencode, claude, copilot).
Image versions are independent of launcher versions. There is no hourly or
`latest` recommendation, launcher-version promotion floor, or 14-day retention
policy. The tool-free base is a local source building block, not a public product.

This launcher initially recommends the v0.1.3 multiarch index:

```text
ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de
```

Native msb selects its Linux host-platform child. Successful default acquisition
retains the **index** reference; explicit `upgrade` retains its resolved native
**child** digest. Existing records and explicit selections are unaffected.
Matching per-architecture GitHub Release archives are for explicit import, never
a registry-failure fallback. See the [image owner's release contract](https://github.com/gregwebs/agent-vm-images/blob/main/docs/standard-image-releases.md)
for authentication and publication policy. A source rebuild need not reproduce
published bytes. Compatibility is the [boot image contract](#boot-image-contract),
not an image-side version stamp.

## Selecting the boot image

One image per session, chosen **independently of the tool you launch** (the tool
catalog never changes it). First present source wins:

| source | how |
|---|---|
| command line | `--image REF` |
| environment | `AGENT_VM_IMAGE_TAG=REF` (an empty value counts as unset) |
| user config | top-level `image = "REF"` in `~/.config/agent-vm/config.toml` |
| project config | top-level `image = "REF"` in `<cwd>/.agent-vm/config.toml` |
| default | your retained digest (see [The retained default](#the-retained-default)), or the initial recommendation when nothing is retained |

`agent-vm shell`, `agent-vm claude` and `agent-vm mytool` all boot the same
image; so do `pull` and `setup`.

**Config-file `image` values are OCI references only.** The runtime treats a
leading `/`, `./`, `../`, `.` or `..` as a host rootfs bind or disk image, so a
repository-supplied `.agent-vm/config.toml` with `image = "/"` would boot the
host root filesystem as a writable guest rootfs. agent-vm refuses such a value
with an error naming the file (never echoing the value).
`--image`/`AGENT_VM_IMAGE_TAG` keep their permissive pass-through, so a local
rootfs or disk image is still bootable **from the command line**, where you
typed it.

**No launch builds an image or runs Docker.** Selection and acquisition only. An
image that fails to acquire is a launch failure — there is no fallback image and
no local build.

**A missing program fails; agent-vm never installs it.** If the selected image
does not contain the tool's `command`, the launch prints a contract diagnostic
and exits 127.

### The retained default

The last row of the precedence table is a **retained default**: a bookmark you
acquired once, kept in the user-scoped file
`$HOME/.config/agent-vm/default-image.json`:

```json
{"version":1,"image":"ghcr.io/gregwebs/agent-vm-standard@sha256:04701db70ef6c2c75078ca39a85ce4b4c15b04cacfea47836c2e5d113c4d42de"}
```

It *names exact image content* (a digest, never a moving tag); microsandbox
separately downloads and caches that content. So the default is independent of
the msb cache and of every project: clearing the cache, enabling the shared
cache, changing `AGENT_VM_STATE_DIR` or working in another directory does not
move it. Change it deliberately with [explicit upgrade](#explicitly-upgrading-the-default).
It is deliberately a separate file from `config.toml` — writing a
top-level `image =` there would make the *user config* tier win over the
*project* tier, which is a precedence change, not a bookmark.

The launcher also carries an **initial recommendation** (an immutable
`@sha256:…` reference compiled into the binary; currently the released v0.1.3
multiarch index, and a newer release may change it). How the two interact:

- **Selection is lazy and read-only.** A higher source wins without reading the
  record; `help`, `doctor`, `--help` and `pull/setup --help` never write one.
- **An absent record uses the launcher's recommendation — but only *acquires*
  it.** The record is written **only after that image was actually acquired**
  (success-before-adoption). If the acquisition fails, nothing is retained: no
  half-written record, no substitute image.
- **A failed first acquisition can still be rescued.** Because a failed attempt
  retains nothing, a later release whose recommendation your host *can* acquire
  (for example after a network failure) becomes your default on its next
  successful launch. Nothing is stranded on bytes your host cannot boot.
- **A retained default is never silently replaced.** A different recommendation,
  a launcher upgrade, a project image, or a cache loss leaves the retained
  digest alone. automatic `adopt` is write-once (first writer wins), so concurrent first
  launches cannot overwrite each other.
- **The digest must resolve.** A retained digest whose content is unavailable
  (registry gone, content deleted) fails the launch with the same error a
  user-typed reference would; it is not silently redirected to another image.
  Restore network access and retry.

`pull` refreshes *the selected reference*; it is **not** an upgrade of the
default's identity. `pull --image REF` refreshes `REF` and never adopts it as
your default. Use `--image`/`AGENT_VM_IMAGE_TAG`/config `image` to boot a
different image for one session, or to point a fresh host at another one.

**Mutable tags vs. digests.** A mutable tag (`:latest`) names *whatever the
registry serves now*: after a cache loss a `:latest` launch may fetch different
bytes than before. A digest names exact content. That is why the retained record
and the initial recommendation are digest-pinned, and why the launcher never
polls a tag to "refresh" your default (the opt-in `--update-check`/
`AGENT_VM_UPDATE_CHECK` freshness banner is unrelated and stays opt-in).

**Observing and recovering.** `agent-vm doctor` prints a fixed label —
`retained default` or `not selected; initial recommendation` — and the record
path; it never prints the reference itself. The default tier is host state (an
untrusted, user-writable file whose reference may name a private registry), so
notices, `agent-vm doctor`, the opt-in `AGENT_VM_DEBUG_CONFIG` dump and
acquisition errors name `the default boot image` and redact its reference rather
than echoing it. Your own `--image`/`AGENT_VM_IMAGE_TAG`/config `image` values
are unaffected: they are your inputs, and they are still shown. It is strictly
observational — it creates nothing. If the record is
corrupt, unreadable (a symlink, FIFO, directory, oversized or non-UTF-8 file)
or names a non-digest reference, every verb that needs the default fails and
names the escaped path with a fixed reason; nothing is auto-reset. To recover,
restore the intended digest record from backup, or deliberately move the file
aside to reinitialize from the current recommendation.

### Explicitly upgrading the default

```sh
agent-vm upgrade --image ghcr.io/owner/standard:release-2
agent-vm shell --no-git -- bash -c 'my-program --version'
```

`--image REF` is required and accepts an OCI tag or digest, not a local path.
Environment/config launch images do not choose the upgrade target, even with
broken tool configuration. There is no automatic latest discovery; explicitly
requesting `:latest` resolves it only for this invocation.

```text
explicit OCI target → native acquire → immutable host manifest pin
                    → native pinned-cache acquire → host-Linux config check
                    → selection flock → atomic retained-record replacement
```

The command uses the ambient **local** microsandbox cache and native registry
auth/TLS settings. It consumes registry content without Docker and **does not
boot or replace a VM**. Only future sessions falling through to the default
change: CLI, environment, user and project image overrides and running sessions
are untouched. Acquisition or publication failure exits nonzero and leaves the
old selection and cached image usable; unused new artifacts may remain cached.
No old images are deleted. A successfully re-acquired same digest leaves valid
record bytes unchanged. Atomic rename protects against interruption, not
power-loss durability (`fsync` is not added).

An absent record can be initialized directly, without consulting the initial
recommendation. A damaged record is rejected, not automatically repaired; use
the recovery procedure above. Concurrent explicit publications serialize under
the same lock as ordinary adoption; the last successful explicit commit wins,
and a delayed ordinary adopter cannot overwrite it. A launch that already
selected the previous default may still boot it.

Roll back by passing a known previous full digest reference to the same
`upgrade --image` command. Acquisition must succeed again before selection
changes; `pull --image` remains a cache refresh, never default replacement.

Upgrade progress/application errors use a fixed redacted image label, not the
old or requested reference or native source chains. Inspect your user-owned
record directly for the pin. Clap usage errors may echo an invalid value you
supplied on argv (status 2); this exception does not apply to stored references.
See [the retained default](#the-retained-default) for scope and recovery.

### Customizing the image

Build user-owned software with an ordinary Dockerfile, then explicitly select it.
Directory names never activate composition; see [`examples/layers/`](examples/layers/).

Extend the released Debian-based standard image, or clone the independent
[image sources](https://github.com/gregwebs/agent-vm-images) and build the
tool-free base locally with an ordinary `FROM`. Source build/version maintenance
instructions belong there; installed agent-vm needs neither that checkout nor
its contributor submodule. The examples need Debian/apt/Node facilities, not just
the minimal boot contract.


#### Explicit builds and archive import

```text
Dockerfile/context → Docker buildx cache → completed anonymous OCI archive
                                          ↓ native cache import
                                      result reference
                                          ↓ shell --image REF
                                       guest execution
```

```sh
agent-vm build --tag my-image:dev --builder native-oci .
agent-vm shell --image my-image:dev -- my-program
```

The bounded option surface is:

```text
agent-vm build --tag REF [-f|--file DOCKERFILE]
  [--build-arg KEY[=VALUE]]... [--target STAGE] [--builder NAME]
  [--pull] [--no-cache] [--progress MODE] [CONTEXT]
```

`--tag`/`-t` is required: a mutable OCI reference, not a digest or local path.
Bare names use native `latest` semantics. Context defaults to `.`; file/context
paths remain relative to the caller, and build arguments are verbatim argv
values (including spaces, empty values and bare keys). Docker owns `FROM`,
multistage semantics and caching. No `BASE_IMAGE` is injected; supplying that
build argument is an ordinary user Dockerfile choice. Platform is always host
Linux architecture, with one anonymous OCI output and attestations disabled.
Unsupported buildx flags, including `--platform`, `--output`, `--load` and
`--push`, are usage errors; use an external build for other controls.

An OCI-capable builder is required. Classic Docker image-store drivers may
reject OCI export. An isolated `docker-container` builder can export OCI but
may not see daemon-only local `FROM` tags. Select your builder explicitly;
agent-vm never creates/changes one, transports parents, pushes or retries a
failed build. For daemon-only workflows, save the completed image and import
**only after save succeeds**:

```sh
docker image save --output image.tar SOURCE &&
  agent-vm msb image load --input image.tar --tag my-image:dev
```

For the standard release, first download/authenticate the exact native v0.1.3
archive using the [image owner's public release instructions](https://github.com/gregwebs/agent-vm-images/blob/main/docs/standard-image-releases.md).
Then, for example on arm64:

```sh
agent-vm msb image load --input agent-vm-standard-v0.1.3-linux-arm64.oci.tar --tag my-standard:0.1.3
agent-vm shell --image my-standard:0.1.3 -- bash -c 'pi --version'
```

Import does not adopt a default selection. There is no automatic archive download
or fallback. A finished archive can be imported without Docker:

```sh
agent-vm msb image load --input image.tar --tag my-image:dev
agent-vm shell --image my-image:dev -- my-program
```

Build imports into the same resolved native cache launch reads, including a
persisted shared redirect or `MSB_CONFIG_PATH`. The result is not tagged in the
Docker store and may not appear in `msb image ls` until first launch persists
cached metadata. Export must succeed before native ingestion; failed export or
single-image ingestion preserves the old result reference. Native blobs can
remain after failed ingestion. Concurrent updates retain native semantics.
Build never reads image selection/defaults, writes configuration or adopts a
default, boots a guest, installs runtime tools or triggers automatic launch
builds. Successful import is **not** proof of the boot image contract;
`shell`/`setup` diagnose unusable software.

Allow space for the completed staged archive under private `MSB_HOME/tmp`,
native import staging, materialized content and Docker's own builder cache.
Ordinary return paths clean only this invocation's staging; interruption may
leave staging, but never imports before exporter success.

Host builds are **not credential-shielded guest execution**: trust the
Dockerfile/context/builder. Docker inherits ordinary host environment,
credentials and stdin; agent-vm does not invoke runtime credential capture or
provisioning. Avoid sensitive CLI values: ordinary clap usage errors can echo
rejected values. Fixed parser reason strings are not redaction.

## Boot image contract

Any image selected for a session (via `--image`, a config `image`, or
the default) must satisfy this contract. agent-vm **never** installs software,
substitutes another image, or runs the guest command on the host, so a breach is
a launch failure naming the image and the missing piece.

**Required:**

1. A Linux image for the host's architecture (arm64 on Apple Silicon) whose
   binaries execute there.
2. **Bash on the image's `PATH`.** Every launch runs `bash -c` with a small
   prelude: it strips IPv6 nameservers from `/etc/resolv.conf`, runs executable
   `/opt/agent-vm/seed.d/*` hooks and the supplied
   `/opt/agent-vm/seed-claude-plugins.sh` entry point when present, and sources
   the project's `.agent-vm.runtime.sh`. The real acquired image OCI `PATH` is
   preserved, in order, on first and warm launches; the launcher's fallback
   (`/usr/local/bin:/usr/bin:/usr/sbin:/bin`) applies **only** when the image
   declares no `PATH` at all, never merely because a cold launch had no cached
   metadata. This is the per-exec *starting* `PATH`: microsandbox's agentd
   prefixes its own `/.msb/scripts` directory only when that directory is absent
   as a `:`-segment; otherwise it leaves the supplied value unchanged, and
   existing values, order and duplicates are always preserved (an image `PATH`
   without that segment therefore starts as `/.msb/scripts:<image PATH>`).
   Runtime hooks run next and can change `PATH`.
3. The selected tool's external `command` executable at its configured pathname,
   or resolvable on the final hook-modified `PATH`, and executable by the guest
   user — by default the host numeric `uid:gid` (not root, not an image account),
   so install world-readable/executable.
4. A runtime-initializable filesystem: regular `/etc/passwd` and `/etc/group`
   (default mode appends the guest identity; boot fails with
   `cannot append to '/etc/passwd'` otherwise), and root-mode dotfile links live
   under `/root`.

**Not required:** Debian, a package manager, a particular install prefix, a
fixed image account, agentd installed in the image, or
`/etc/agent-vm-image-version`.

**Behaviour to know:** microsandbox's agentd is PID 1, so the image's
`ENTRYPOINT`/`CMD` never run. Default mode overrides the image `USER`; `--root`
consistently runs uid:gid 0:0 in the sandbox bind mapping and each exec. In
default mode `$HOME` is your host home path, backed by `<state>/home`, which
**hides** whatever the image put there. Under `--root`, HOME=/root and
USER/LOGNAME=root even if the OCI `USER` or `ENV HOME` conflict; plain root HOME
files stay ephemeral while declared/config links target persistent state. TLS:
agentd adds the session CA to the system bundle
(`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt` or
`/etc/ssl/cert.pem`) and sets `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/
`CURL_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS`; software with its own trust store
(Chromium/NSS, Java keystores, …) needs its own integration.

**Optional integrations** (inert when absent, ordinary image content — not
lineage/ABI/migration promises): executable `seed.d` hooks, the supplied
`/opt/agent-vm/seed-claude-plugins.sh` entry point, and the Chrome capability
marker/wrapper.

**Failures:** a missing/unrunnable Bash yields an image-contract diagnostic; a
missing selected program prints a contract message and exits **127**. There is
never an install, a fallback image, or host execution.

Minimal example:

```dockerfile
FROM alpine:3.22
RUN apk add --no-cache bash
COPY --chmod=0755 my-program /usr/local/bin/my-program
```

Build and launch on a macOS checkout:

```sh
agent-vm build --tag my-image:dev --builder native-oci .
agent-vm shell --image my-image:dev
```

Or push to a registry and use its reference directly with `--image`.

## Launch flags

Each launcher accepts:

| flag | what |
|---|---|
| `--memory N` | VM memory GiB (default 2) |
| `--cpus N` | vCPUs (default 2) |
| `--image REF` | boot this image instead of the configured one (env `AGENT_VM_IMAGE_TAG`); see [Selecting the boot image](#selecting-the-boot-image) |
| `--update-check` | check the registry for a newer image on launch (off by default) |
| `--no-git` | skip gh/git auth injection (still respects `--repo`) |
| `--repo OWNER/NAME` | add to the GitHub allow-list (repeatable) |
| `--allow-missing-credentials` | warn and launch when a requested YAML credential is missing or unreadable, instead of refusing — see [Authorizing a stored value for injection](#authorizing-a-stored-value-for-injection). Never covers a built-in provider's own missing host credential |
| `--mount HOST[:GUEST][:MODE]...` | extra live bind or project-scoped `:fork`. Directory binds default to writable; a regular file needs an explicit `:ro`. Modes: `:ro`, `:rw`, `:fork`, `:follow-links`, and fork-only repeatable `:exclude=REL`; see [Extra and forked mounts](#extra-and-forked-mounts). A live bind that would expose a host Pi credential file is refused — see [Host Pi credential files are never mounted](#host-pi-credential-files-are-never-mounted). Capacity is host-specific. |
| `--root` | run the guest as root (uid 0) instead of the default host user — see [Guest user](#guest-user----root) |

### Extra and forked mounts

`--mount` accepts `HOST[:GUEST][:MODE]...`. `GUEST` defaults to `HOST` (a
mirror at the same absolute path). Valid mode tokens are `ro`, `rw`, `fork`,
`follow-links`, and `exclude=REL`; contradictory tokens (`ro`+`rw`,
`rw`+`follow-links`, `fork`+`ro`, `fork`+`rw`) are parse errors.

| declaration | source and behavior |
|---|---|
| `HOST[:GUEST]`, `:rw` | directory, live writable bind |
| `:ro` | directory or regular file, read-only bind |
| `:follow-links`, `:ro:follow-links` | read-only discovery of resolved directory targets (unchanged; see below) |
| `:fork` | directory root copied once into project state; nested link text preserved |
| `:fork:follow-links` | directory root copied once; symlink targets materialized into the copy |
| `:exclude=REL` | only with `:fork`; repeatable, normalized seed omissions |
| a live bind (`ro`/`rw`/`follow-links`) that would expose a host Pi credential file | **refused**; nothing is masked. `:fork` only where forking the root would help — see [Host Pi credential files are never mounted](#host-pi-credential-files-are-never-mounted) |

A live bind is a directory, or a regular file with `:ro`. A bare file mount
defaults to writable and is rejected, as is `:rw` on a file; the error names
the source and suggests `:ro` or forking the containing directory. `:fork`
copies a **directory** only: a file fork root is rejected, and a file cannot
be `:fork`ed. There is no writable single-file mount.

`:fork` creates a writable project-scoped copy on first launch. Later launches
bind that stored copy, never synchronize with `HOST`, and print the exact reset
directory. `:fork:follow-links` materializes link targets into that copy;
without it nested link text is preserved. `fork` conflicts with `ro` and `rw`.

Repeat `:exclude=REL`, for example
`--mount /host:/guest:fork:exclude=credentials.json:exclude=cache`. `REL` is a
nonempty normal relative path: it cannot contain `:`, control characters, `.`,
`..`, empty components, or an absolute path. Exclusions are **fork-only** — on
any live bind they are a parse error (`:exclude is only supported on :fork
mounts`). Fork initialization omits excluded entries, so a guest can later
create its own content there; an explicit child mount at an omitted path is
allowed, including a read-only file bind. Normal mount policies still apply:
file children must be read-only. Exclusions are not a persistent guest access
restriction.

Forks consume the full initial-copy disk cost. Their source is not an atomic
snapshot if it changes while copying. To reset/reseed, stop every launch using
the fork, remove the printed fork directory, and launch the identical
declaration again. Changing the source spelling, normalized guest path, follow
policy, or exclusions creates a distinct fork. A v2 fork whose manifest `kind`
is `file` (from an older build) fails closed: the error names the exact
directory to remove, and nothing is reseeded, migrated, or deleted
automatically.

Fork identity is versioned, and the current version is **v3** (the [host Pi
credential rule](#host-pi-credential-files-are-never-mounted) did not exist in
v2). Every fork from an earlier build is therefore re-copied once from its
source; the old directory is not deleted, and the launcher prints its exact
path — `A fork from an earlier agent-vm build is no longer used: … It may
contain a copy of a host credential file — remove it` — so nothing is left
buried in state. **That notice repeats on every launch until the printed
directory is removed**; there is no acknowledgement, because acknowledging it
would leave a directory that may hold a plaintext credential. A v2 fork whose
original source is gone cannot be reseeded: the launch errors on the missing
source, and the printed orphan is what you remove.

### Host Pi credential files are never mounted

Two host files must never reach the guest: `~/.pi/agent/auth.json` (Pi's
provider credentials) and `~/.pi/agent/models.json` (its provider
configuration). `agent-vm` keeps host-imported Pi credentials host-side and
gives the guest placeholders, so a mount that handed over the real file would
defeat that for the one tool agent-vm is about to launch.

- A **live bind** (`ro`, `rw`, `follow-links`, and every bind `follow-links`
discovers) that would expose either file — directly, through an ancestor such
as `$HOME` or `/`, through a remapped guest path, through a symlink alias, or
through a hardlink — is **refused**. Nothing is masked: a live bind is a window
onto bytes written *after* boot, and `pi auth login` on the host can create
`auth.json` inside it, so masking cannot cover the dangerous case at all. The
refusal prints the exposed file's canonical path and the mount root's, so a
`/tmp/…` spelling does not read as a different directory.
- `:fork` is different in kind — a one-time copy made host-side — so it is
allowed: the two files are **omitted** from the copy, with a notice, and
everything else is copied. Their containing directory stays, and the host files
are untouched.
- The **remedy in a refusal depends on what was mounted**, because `:fork` is
not always one. A root at or inside `~/.pi` gets the `:fork` recommendation; a
regular file (the credential itself) cannot be mounted at all and no `:fork` is
suggested; a root *above* `~/.pi` — `$HOME`, `/` — is told to mount a narrower
path, with `:fork` explicitly named as *not* a substitute, because forking it
would copy everything else under it into writable project state.
- A mount **at or inside `~/.pi`** (for example `--mount ~/.pi/extensions:ro`)
is allowed but warns twice: that a live bind of host Pi state should be a
`:fork`, and that host Pi extensions and installed packages may be built for
this host's OS/arch and may not run in the Linux guest.
- **Launching from `$HOME`, `~/.pi`, `~/.pi/agent`, or any ancestor of them is
refused with no `--mount` at all**, because the project bind is the
canonicalized cwd: `cd ~ && agent-vm shell` would hand the guest the whole host
`$HOME`. A cwd **elsewhere inside `~/.pi`** (say `~/.pi/extensions`) exposes no
credential file, so it is allowed — and warns, twice, for the same reasons a
mount there does.
- **`$HOME` unset loses nothing.** The launch's home is `$HOME` when it is set,
otherwise the home recorded for your uid in the account database
(`getpwuid_r`), so a daemon, CI, or `env -i` launch still runs the checks above
— including against the project bind. Only when *neither* names a home is a
launch that declares a `--mount` refused, because the Pi home cannot be
located.

When `~/.pi` does not exist, none of the refusals apply: there is nothing to
leak today, so the same routes produce a one-line advisory instead (the
residual risk is installing Pi *and* logging in during a live session). Known,
accepted gaps, all in [`docs/adr/0020`](docs/adr/0020-protect-host-pi-credential-files.md):
a hardlink to the file inside an otherwise-unrelated live bind; a filesystem
whose inode identity is unreliable *and* whose alias is not a path containment;
and a copy you made yourself.

`follow-links` (unchanged) walks `HOST` on the host and bind-mounts each
resolved directory target at its real absolute path, so links that leave
`HOST` resolve in the guest. A resolved target outside `$HOME` is a hard
error; a symlink to a file or a dangling symlink is skipped with a warning.
`follow-links` implies `:ro`.

Trailing args go to the agent: `agent-vm claude -p "say hi"`,
`agent-vm shell -- -c 'cargo test'`.

Env-var knobs (all opt-in), in three shapes. A row that lists an
accepted-value set is a boolean switch: its value is parsed — trimmed and
ASCII-case-insensitive — and only a listed value turns the knob on, so a
typo leaves it off. A row that stands in for a flag taking an argument
(`RUST_LOG`, `AGENT_VM_IMAGE_TAG`, `AGENT_VM_MEMORY_GIB`/`AGENT_VM_CPUS`)
uses its value as-is. Everything else is presence-only: any value, empty
included, enables it.

| var | what |
|---|---|
| `RUST_LOG` | tracing filter; default `warn`. e.g. `RUST_LOG=agent_vm=debug`. Once an invocation selects the *default* boot image, dependency events are suppressed (the image stack would log the record-sourced reference); explicit-image invocations are unchanged |
| `AGENT_VM_PROFILE` | print per-phase wall-time (create/run/stop/remove) |
| `AGENT_VM_DEBUG_CONFIG` | dump the SandboxConfig JSON before boot |
| `AGENT_VM_NO_CHROME_MCP` | disable Chrome MCP auto-configuration for a Chrome-capable image |
| `AGENT_VM_IMAGE_TAG` | override the OCI image (same as `--image`; outranks any config `image`; an empty value counts as unset) |
| `AGENT_VM_MEMORY_GIB` / `AGENT_VM_CPUS` | same as `--memory` / `--cpus` |
| `AGENT_VM_UPDATE_CHECK` | opt into the launch-time registry update check (accepted: `1`/`true`/`yes`/`on`) |
| `AGENT_VM_ROOT` | same as `--root` (accepted: `1`/`true`/`yes`/`on`) |

`AGENT_VM_BASE_IMAGE`, `AGENT_VM_LAYER` and `AGENT_VM_YES` are no longer read.
They are ordinary unread environment variables now — a launch that still
exports one boots normally.

## Shared microsandbox image cache

By default agent-vm keeps its microsandbox state — including the OCI image
cache — entirely private under `MSB_HOME` (see above), so a
separately installed `msb` (Homebrew on macOS; a distro package,
`cargo install`, or a from-source build on Linux) can never shadow
agent-vm's KVM-enabled `libkrunfw`. That also means agent-vm and any other
`msb` install each store and pull their own copy of every image.

Set `AGENT_VM_SHARE_MSB_CACHE` (accepted: `1`/`true`/`yes`/`on`) to opt into
redirecting only agent-vm's image cache at the shared `~/.microsandbox/cache`
directory that other `msb` uses, so image layers/vmdk/manifests aren't stored
or pulled twice. Use `AGENT_VM_MSB_CACHE_DIR=<path>` to point at a
non-default cache location instead. This opt-in is one-way: the first run
with it set writes `MSB_HOME/config.json`, and unsetting the variable later
does not revert that write (see *Reverting is a manual step* below). Every
spelling in the accepted set counts, so a `AGENT_VM_SHARE_MSB_CACHE=yes`
left over in a shell profile opts you in on the next run.

What stays private: `db/`, `tls/`, `secrets/`, and `sandboxes/` remain under
`MSB_HOME`; only the cache is shared. `libkrunfw` is
unaffected (resolved via `MSB_PATH`, not the cache override), so the
shadowing protection above is unchanged.

Caveat: only enable this when the other `msb`'s version is close to the
vendored fork's — the on-disk cache format (erofs/vmdk/manifest schema) is
not guaranteed compatible across microsandbox versions. Avoid running the
two concurrently against the shared cache with mismatched versions. If
images misbehave, unset the variable **and** remove the persisted redirect
as described in *Reverting is a manual step* below — unsetting the variable
alone does not fall back to the private cache.

**Reverting is a manual step.** The redirect is persisted to
`MSB_HOME/config.json`. Unsetting
`AGENT_VM_SHARE_MSB_CACHE` does **not** by itself restore the private cache —
agent-vm only writes `config.json` when the flag is on, so a later flag-off
run leaves the previously written `paths.cache` pointing at the shared
directory. To fully revert, delete that `config.json` (or remove the
`paths.cache` key from it).

## Checking what agent-vm can see

```
agent-vm doctor
```

Prints the active `MSB_HOME` and bundled schema, then every host
credential source agent-vm reads — present / absent / unusable, plus how
long the Claude token has left — and which of them were captured for the
project you run it in. It never prints token bytes. This is the first
thing to run when an in-VM agent comes up signed out. See
[Credentials](#credentials).

It also prints the resolved [tool configuration](#tool-configuration) — the same
verb list `agent-vm --help` shows.

**Launch-aware credentials.** A `credentials.yaml` entry named after a built-in
provider replaces that provider's credential handling for every launch that
requests it (see [Authorizing a stored value for injection](#authorizing-a-stored-value-for-injection)). So
the host-credential rows are annotated: a provider a configured launch replaces
reads `replaced by credentials.yaml for <verbs> (host file not read)` rather
than leaving a green/absent row to be misread, and a provider no configured
launch requests reads `not requested by any configured launch`. When a
configured launch requests an authorized service, `doctor` also prints a
`==> credentials.yaml (launch credentials)` section naming it as `authorized for
this launch`. This reads the authorization file only — **not** the credential
store — so it never prompts and never writes; whether a value is actually stored
is [`agent-vm secret ls`](#storing-your-own-secret-values)'s answer, and the
section says so. A host with no `credentials.yaml`, or with only authorizations
no launch requests, prints no credential rows; the section still appears when
the file itself needs a diagnostic (a file-mode or compatibility-alias warning).

**Guest-managed Pi credentials.** The same run also reports the project's
persistent Pi state (canonical `<state>/pi/agent/{auth,models}.json`, plus any
real pre-#96 `<state>/home/.pi` that a launch has not yet moved). The report is
**structural**: it names a provider ID, a credential kind (`api_key`/`oauth`/
`configuration`/`unknown`) and field names such as `key`, `access`, `env` or
`headers.Authorization` — never a value, command, environment reference or URL.
An exact agent-vm placeholder is quiet; anything else, or a malformed/unsafe/
oversized file, is reported as potentially sensitive. Only `auth.json` and
`models.json` are inspected — settings, sessions and installed packages are not.

`doctor` never resolves `!command` values, expands environment references,
refreshes OAuth, or writes, rewrites or removes anything; it only reads: the host
credential files above, the tool configuration, `credentials.yaml`, and the two
Pi files. Ordinary `doctor` also performs **no** initialization at all — it is
dispatched before microsandbox bootstrap, so it works even when the bundled `msb`
is missing or unpatched, and it reports the computed paths rather than validating
that binary. The explicit `agent-vm doctor --reset-msb-db` is the mutating
exception and keeps its existing behaviour.

The report is advisory, not enforcement: it neither blocks a launch nor promises
that a host substitution exists. Your decision whether to remove or rotate a
guest-managed credential.

## Tool configuration

The launch verbs are generated from a tool configuration resolved on every
invocation. `agent-vm doctor` prints exactly what was resolved (and `agent-vm
--help` shows the same verb list, in the same order). The design rationale is
in [ADR-0015](docs/adr/0015-config-driven-tools.md).

> Running `agent-vm` in a directory means trusting that directory's
> `.agent-vm/` — a project config can declare and (where a tool needs them)
> wire up arbitrary commands and credentials. See ADR-0015's trust-model
> section.

### Where the files live

| Tier | Path |
|---|---|
| user | `$HOME/.config/agent-vm/config.toml` |
| project | `<project root>/.agent-vm/config.toml` (`<project root>` is the canonical current directory) |

Both are optional (an absent file is reported as `absent`; a present but
empty one as `found, 0 tools`). `$XDG_CONFIG_HOME` and any config-path
override are deliberately **not** honored.

### Schema

```toml
# Top-level, optional: the boot image for every session (an OCI reference).
image = "ghcr.io/gregwebs/agent-vm-standard:v0.1.3"

[[tools]]
name = "mytool"                      # required; the `agent-vm <name>` verb
command = "mytool"                   # required; the guest command name
args = ["--flag"]                    # optional; default argv (array of strings)
credentials = ["openai"]             # optional; credential provider names
tools = ["claude"]                   # optional; tools to provision (same file, or name one)
persist = [".cache/mytool"]          # optional; guest-HOME-relative, kept under <state>/persist/
env = { VAR = "value" }              # optional; guest env pairs for this tool
interactive_shell = false            # optional; join trailing args into `-c`
```

- `image` — optional top-level; an OCI image reference selecting the **boot
  image** for every session (see
  [Selecting the boot image](#selecting-the-boot-image)). It is independent of
  the tools: a file that sets only `image` declares zero tools and keeps the
  shipped defaults. Only OCI references are accepted here; a local path is
  rejected (use `--image` for a local rootfs).
- `name` — required; a single command-name token: nonempty, no
  whitespace/control characters, no `/` (a name is not a path), not an
  all-dots spelling (`.`/`..`), no leading `-`, and not one of the reserved
  subcommands `build`, `setup`, `pull`, `msb`, `clipboard`, `doctor`, `secret`,
  `_intercept-hook`, `help`. Names are case-sensitive. Naming a tool `claude`
  is normal — that is the point.
- `command` — required, nonempty, NUL-free. The guest command name; it is
  never executed by `doctor`.
- `args` — optional, the default argv prepended to the user's own args unless
  the user already passed the same flag. `doctor` shows only the argument
  **count**, never the values, so a secret accidentally placed here is not
  echoed. Args are not shell-split or expanded.
- `credentials` — optional; provider **config names**, which differ from
  the `agent-vm doctor` row labels. Valid: `anthropic`, `openai`,
  `opencode-static`, `copilot`. Note `opencode` (the doctor label) is **not**
  a valid name — use `opencode-static`. This is the **requirement** set: a
  launch hard-fails before boot when one of them yielded no usable host login.
- `tools` — optional; the names of **other tools whose credentials this tool's
  guest should have**. Not provider names. Named tools are *provisioned*, never
  *required*, so naming a tool you have no host login for degrades silently
  rather than failing the launch. The single entry `"*"` closes over the tools
  declared in the **same configuration file** as this tool, and must be the only
  entry; `*` is not a legal tool `name`. A tool in a *different* file (for
  example a tool in your user config, from inside a project config) is reached
  only by **naming it explicitly** — that name is the opt-in. Naming a tool the
  catalog does not provide is a hard error. **Omitted means `["*"]` for a tool
  named `shell` and `[]` for every other name** — write `tools = []`
  explicitly to give a `shell` no provisioning at all. `opencode-static` only
  produces a working sign-in when `openai` is also provisioned.
- `persist` — optional; guest-`$HOME`-relative paths to keep across runs.
  Each path is symlinked into the project state dir under `<state>/persist/`,
  so the real file lives next to the rest of the project state (`agent-vm
  doctor` prints the state dir) — one place to find and back it up. Absolute
  paths, any `..` component, NUL, and root-equivalent spellings (`.`/`./`/empty)
  are rejected; harmless `.`/`//`/trailing-`/` spellings are normalized. Two
  paths that **overlap** — equal, or one a component-wise ancestor of the other
  — are a hard error whether they are two entries of the same tool, two
  different tools, or a `persist` path against one of the dotfiles agent-vm
  itself links into the state dir (the credential/config links `agent-vm
  doctor` lists, e.g. `.claude`, `.config/gh`, `.pi`); one would silently
  shadow the other. `.cache` and `.cachex` do **not** overlap (components, not string
  prefixes). Which paths a launch gets follows the same `tools` closure as its
  credentials, so a `shell` (whose omitted `tools` is `["*"]`) sees every
  declared path in its own file. A `persist` path that would collide with the
  project bind mount or a `--mount` under `$HOME` is rejected at launch, before
  anything is provisioned, because agentd creates those mount points inside the
  already-mounted `$HOME`. On the first launch after an entry is added, real
  content already at the guest path is **moved** into `<state>/persist/` (never
  deleted); if the target already holds content too, the launch fails naming
  both paths and you choose. Targets are deliberately **not** pre-created, so a
  **directory-valued** entry needs one `mkdir -p '<state>/persist/<path>'` on
  the host (or `/agent-vm-state/persist/<path>` from `agent-vm shell`) once per
  project — a file-valued entry such as `.aider.conf.yml` just works, because
  the guest's `open(O_CREAT)` through the dangling symlink creates the real
  file. Leftover links from a previous launch of a different tool are benign:
  nothing prunes them, by design.
- `env` — optional; a table of guest environment variables set for this tool
  only. Keys must be nonempty and contain no `=`, NUL, whitespace or control
  characters, and must not start with `MSB_` (reserved by microsandbox).
  `HOME`, `USER` and `LOGNAME` are **rejected**: agent-vm owns the guest
  identity environment, and it publishes those three only in the default
  non-root mode — under `--root` a tool declaration would win outright and
  would break the guest's credential symlinks, so the declaration is refused
  in every mode rather than being honoured in one of them. Values are literal
  strings: no `$VAR` expansion, no shell splitting — the same rule as `args`.
  `doctor` shows only the **count**, never the values, so `doctor` never echoes
  a secret accidentally placed here. The opt-in `AGENT_VM_DEBUG_CONFIG` dump
  still shows values, the same exposure class as `args`. These pairs are
  published into the guest **before** agent-vm's own environment, and the guest
  applies them last-wins, so declaring `PATH`, `IS_SANDBOX` or `LANG` has no
  effect — agent-vm always overrides them.
- `interactive_shell` — optional boolean, default `false`. When true, the
  user's trailing args are joined (and shell-escaped) into a single `bash -c`
  command line instead of being appended as separate argv entries. The shipped
  `shell` tool sets it.

Unknown keys, wrong types, malformed TOML, unknown
provider names, duplicate tool names within one file, and **overlapping**
`persist` entries (equal or one an ancestor of the other — within one tool,
across tools, or against a path agent-vm itself links into the state dir) are
all **hard errors** — as are invalid `tools` entries: `"*"`
mixed with other entries, an empty or NUL-containing name, a tool name no
catalog tool provides, and a tool named `*`. They are also hard errors for
invalid `env` entries: a key that is empty, or contains
`=`/NUL/whitespace/control characters, or starts with `MSB_`, or is
`HOME`/`USER`/`LOGNAME`, and an `env` **value** containing NUL. There is no
silent fallback to the defaults.

### Merge order and defaults

The user file is authoritative for any tool name it contains; the project
file may add whole tool definitions the user did not write. This is a union
of whole definitions, **not** a field-by-field overlay: a repo cannot fill in
an omitted `persist`, `credentials`, or `tools` on a user-defined tool.
Resolved order is user declarations first, then project-only declarations (the
order `--help` and `doctor` both use). The top-level `image` is **not** merged:
the user tier's `image` wins over the project tier's, and a file that declares
no tools (for example an image-only file) still keeps the shipped defaults —
but a project that **declares tools** still replaces the shipped set, exactly
as before (ADR-0015). When a project declaration of an
existing name differs, `doctor` warns once and the user definition wins, e.g.:

```text
warning: tool "claude" in /home/alice/.config/agent-vm/config.toml overrides
         /work/repo/.agent-vm/config.toml; differing fields: command, args
```

`doctor` also prints the selected boot image (excluding `--image`, which it does
not accept), so you can see which source won:

```text
==> boot image
AGENT_VM_IMAGE_TAG: <unset>
user:    ghcr.io/gregwebs/agent-vm-standard:v0.1.3 [/home/alice/.config/agent-vm/config.toml]
project: none
default: retained default [/home/alice/.config/agent-vm/default-image.json]
selected (without --image): ghcr.io/gregwebs/agent-vm-standard:v0.1.3 (from user config /home/alice/.config/agent-vm/config.toml)
```

### The `shell` fallback

When the resolved catalog declares no tool named `shell`, the built-in `shell`
(from [`crates/agent-vm/src/default-tools.toml`](crates/agent-vm/src/default-tools.toml))
is appended, so a config that omits — or typos — `shell` never leaves you
without a way into the guest. It is **conditional**: a config that *declares*
`shell` (even as `zsh`) keeps its own definition, and the fallback does not
fire on an unparseable config (see *Errors and recovery*). `doctor` labels the
row with a note when the fallback is in use.

Only when **both** files declare zero tools (missing, empty, or `tools = []`)
does the compiled-in defaults list apply: `dsh`, `pi`, `codex`, `opencode`,
`claude`, `copilot`, `shell`, in that order. They are defined once in
[`crates/agent-vm/src/default-tools.toml`](crates/agent-vm/src/default-tools.toml),
embedded into the binary (never written to disk). **`codex` and `opencode`
have empty `args` on purpose** — their non-interactive configuration is
persisted as files, not a flag; do not add one.

`codex` and `shell` are the only shipped tools that declare `env`: both set
`CODEX_HOME=/agent-vm-state/codex`. Codex is the one agent with no
`~/<dotfile>` symlink into the project state dir (its install prefix holds
`packages/`, so a `~/.codex` symlink would shadow the binary itself), and in
the shipped catalog `shell` provisions every tool in `default-tools.toml` (its
omitted `tools` defaults to the wildcard, which closes over that file), so the
OpenAI credential is provisioned into that state dir on a shell launch;
dropping the pointer would leave a fully-provisioned, unreachable credential.
The other three agents never read `CODEX_HOME`. See
[ADR-0016](docs/adr/0016-tool-declared-guest-env.md).

**`pi`.** Pi's user state (`~/.pi`, i.e. auth, settings, sessions, and global
packages under `~/.pi/agent`) is **project-scoped persistent state** at
`/agent-vm-state/pi`, in both guest modes — a `/login` inside a throwaway VM
survives a relaunch. The checkout's own `.pi/` resources are a separate path on
a separate mount. Agent-vm forces **no** project-trust policy: Pi's own trust
prompt appears when it would under vanilla Pi, and the answer you give is
remembered in the now-persistent `~/.pi/agent/trust.json`, so you decide once.
An explicit `--approve`/`--no-approve` (or `-a`/`-na`) is honoured because it is
simply Pi's own flag, forwarded untouched. Note that agent-vm's own parser
consumes the **first** `--` on the outer command line, so deliver a literal `--`
to Pi with a second one: `agent-vm pi -- -- …`. `pi <subcommand>` (`pi list`,
`pi auth`, …) is forwarded **verbatim**, so the wrapper injects no `--extension`
there and subcommands stay subcommands. `pi` also ships with empty `args`,
like `codex`/`opencode` — any default flag would belong in the wrapper, not in a
config `args` list, because a prepended flag would displace a subcommand.

**The `claude-bridge` provider.** The image ships
[`pi-claude-bridge`](https://github.com/elidickinson/pi-claude-bridge), pinned,
under `/opt/agent-vm/pi-packages/`, and the wrapper loads it on every
non-subcommand `pi` invocation — so `/model` offers a `claude-bridge/…` entry
with no install step. It is **not** a Pi-managed package: `pi list` does not show
it, `pi update` and `pi uninstall` cannot see it, and its pin moves only when
this repo moves it
([ADR-0023](docs/adr/0023-image-owned-pi-extension-packages.md)). Its settings
live in `~/.pi/agent/claude-bridge.json` — `provider.plan`,
`askClaude.enabled`, and `provider.pathToClaudeCodeExecutable`. agent-vm seeds
exactly that last key so the bridge runs the image's own `claude` rather than the
Agent SDK's own platform package — guest-platform size in
[ADR-0023](docs/adr/0023-image-owned-pi-extension-packages.md). There is no
once-marker: the hook runs on **every** launch and re-adds the key whenever it is
absent, so **changing** the value is honoured but **removing** it is not (the
bridge needs it). Set `AGENT_VM_PI_NO_BRIDGE=1` (any non-empty value) to take the
bridge out of the picture entirely — the recovery hatch if it ever throws, or if
you installed your own copy.

**Env.** The wrapper forces `PI_SKIP_VERSION_CHECK=1`, because agent-vm owns the
binary (a root-owned image layer) and Pi's "newer version" fetch can only ever be
noise. It forces **no** telemetry policy: `PI_TELEMETRY` is left exactly as the
**guest** environment sets it, and Pi's own default applies when it is unset.
agent-vm does not forward the host's value, so the supported override is
guest-side — a tool's config `env`, or an `export` inside `agent-vm shell`.

**Credential warnings.** Because a guest can leave a Pi credential in the
project's persistent state that any later tool in that project can read, every
launch (`claude`, `codex`, `opencode`, `copilot`, `pi`, `shell`, and any custom
tool) prints a field-only advisory on stderr **before** the guest runs when it
finds a non-placeholder or unrecognized entry — for example
`auth.json: provider=anthropic type=api_key fields=key`. Placeholder-only state
is quiet. `agent-vm doctor` shows the same facts without starting Pi. This
advisory is **separate** from the in-guest Pi extension's own warning about a
future sign-in; the two are complementary and the launcher warning is emitted
regardless of whether Pi itself starts. It never prints a value, command or
environment reference, and it never blocks the launch.

The built-in `shell` declares **no** `credentials` and omits `tools`, so in the
shipped catalog it *provisions* every provider `default-tools.toml`'s tools
declare without *requiring* any of them: `agent-vm shell` still works for a user
with no Anthropic or Copilot login, and an in-guest `copilot` works too. The
wildcard is scoped to the file it is written in — if you replace the shipped
catalog, your own `shell` gets the same name-based default but closes over
**your** file. Add `tools = []` to opt out.

If you declare your own `codex` or `shell` tool in
`~/.config/agent-vm/config.toml` or `.agent-vm/config.toml`, your definition
wins wholesale and does **not** inherit the shipped `env` — add
`env = { CODEX_HOME = "/agent-vm-state/codex" }` to it, or codex will start in
the guest as signed out.

### Errors and recovery

A config parse/validation error fails any launch verb with *that* error — never
clap's "unrecognized subcommand". Ordinary `agent-vm doctor` still exits
nonzero, but the failure is rendered inside the `==> tool configuration`
section, naming the file and declaration (or a line/column for syntax errors),
so the sections above it — state, credentials, and the operations list — still
print: a repo-supplied config cannot hide them. `agent-vm --help` still exits 0
and lists the built-ins with a note pointing at `agent-vm doctor`. Diagnostics
never echo argument or command values, and control characters in paths and
names are escaped as `\xNN`. `agent-vm doctor --reset-msb-db` **never reads
config**, so a broken config can never block recovering a forward-migrated db.

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

## Guest user / `--root`

By default the in-guest agent runs as **the host user** — the same
uid/gid that invoked `agent-vm` — instead of root. This is defense-in-depth
on top of the microVM boundary itself; matching the host uid is also
required to keep write access to the project/state bind mounts (a
non-root guest uid only gets owner bits on those when it equals the real
host uid). `whoami`/`id` inside the guest report your host username
(resolved from `$USER`) with your host uid/gid; `$HOME` is your **host home
path** (for example
`/Users/alice`), backed by the host directory `<state>/home` inside the
per-project state dir, with the
`.claude`/`.gitconfig`/`.config/gh`/`.pi`/etc. dotfile symlinks rooted there
instead of at `/root`.

Pass `--root` (or set `AGENT_VM_ROOT=1`) to run the guest as uid 0 with
`HOME=/root`. You need `--root` for:

- **Docker-in-VM** — `dockerd` needs root; there's no non-root path for it.
- Anything else that specifically expects to run as root inside the guest.

See [`docs/adr/0001-non-root-guest-via-native-user.md`](docs/adr/0001-non-root-guest-via-native-user.md)
for the full design rationale.

## Chrome DevTools MCP

The default boot image does not include Chromium. An image that provides the
**[Chrome DevTools capability](#boot-image-contract)** — Chromium plus the
`/etc/agent-vm-capabilities/chrome-devtools-mcp` marker or the
`/usr/local/bin/agent-vm-chrome-mcp` wrapper — gets the launcher's owned
`mcpServers.chrome-devtools` entry; any other image boots normally with the
entry removed. Build and select such an image with ordinary Docker (see
[`examples/layers/chrome-devtools/`](examples/layers/chrome-devtools/) for a
Dockerfile that installs it `FROM` the default boot image).
`AGENT_VM_NO_CHROME_MCP=1` removes the automatic entry but leaves Chromium
available for manual use. The launcher adds its owned
`mcpServers.chrome-devtools` entry when the boot image advertises the capability
(`/etc/agent-vm-capabilities/chrome-devtools-mcp`) **or** supplies
`/usr/local/bin/agent-vm-chrome-mcp` without the marker; otherwise it removes any
stale owned entry and the launch proceeds. This is supplied-artifact detection,
not image identity or lineage. The wrapper preserves Chromium's nested sandbox:
non-root guests run it directly and root guests switch only to the dedicated
`chrome` user. It imports the per-install microsandbox CA into that user's NSS
database rather than using an insecure certificate flag, and disables MCP
telemetry.

## Credentials

**Sign in on the host, never inside the VM.** The guest only ever holds
placeholder tokens; the proxy swaps in the real host token on the way
out. So `claude login` / `codex login` / `gh auth login` are host
commands. Running `/login` *inside* the guest cannot work — the OAuth
hook accepts only a refresh grant carrying the placeholder refresh
token, so an authorization-code exchange is rejected and Claude Code
reports a bare `OAuth error: Request failed with status code 400`.
A Claude launch with no usable host credential now fails before boot
rather than starting a signed-out agent.

Run `agent-vm doctor` to see what was found on the host, when the Claude
token expires, and which credentials reached the current project.

### What each verb gets

A launch only captures, injects and proxies the credentials its verb
**provisions**: its own `credentials`, plus those of every tool it names in
`tools`, transitively. `agent-vm codex` never captures your Anthropic token;
`agent-vm claude` never captures your OpenAI one. `agent-vm shell` provisions
all four, because in the shipped catalog the built-in `shell`'s wildcard closes
over `default-tools.toml`'s six agents. `agent-vm doctor` prints each verb's
resolved set as `provisions=…` next to its `credentials=…` requirement set.

The guest's `~/.claude`, `~/.copilot` and `~/.config/opencode` symlinks are
created on every launch regardless — they are furniture, not capability. What a
guest can *use* is the placeholder plus its proxy substitution entry, and
neither exists for a provider the verb did not provision.

Reads from the host:

- `~/.claude/.credentials.json` (Claude)
- `~/.codex/auth.json` (Codex, OpenCode OAuth)
- `~/.local/share/opencode/auth.json` (OpenCode static API providers)
- `gh auth token` (git/gh)

The guest gets placeholder strings; the proxy substitutes on the wire.
Real tokens live in `${XDG_STATE_HOME}/agent-vm/<hash>.secrets/` (0700)
on the host, **outside** the bind mount the guest sees. A SHA-256
snapshot of the three credential files is taken at launch and
re-checked on exit; unexpected mutations print a warning.

OpenCode and `shell` launches also capture the supported static OpenCode IDs:
`zai`, `zai-coding-plan`, `zhipuai`, `zhipuai-coding-plan`, `kimi-for-coding`,
`moonshotai`, and `moonshotai-cn`. Each is stored in its own 0600 sibling file
and substitutes only on its exact provider host; static keys refresh on
relaunch, not during a running session.

The proxy re-reads each configured host-only token file on every eligible
connection. For Claude/Codex, an expired bearer triggers an OAuth hook that
validates the exact request, runs `claude -p`/`codex exec` on the host, and
returns placeholders only; an unavailable or failed refresh returns a
credential-free temporary-unavailable response rather than exposing a token. GitHub
credentials are sent only to the per-launch repository allow-list, so off-list
API calls receive a proxy denial or anonymous smart-HTTP request without the
host bearer. GraphQL mutations are denied until they have a sound
repository-scoped authorization design; use an allow-listed REST route where
available. Copilot has no in-session refresh path: relaunch to recapture an
expired Copilot token.

### Credential-free agents (`pi`, `dsh`)

`pi` and `dsh` declare no `credentials` on purpose: both are multi-provider
agents that enroll or configure providers **inside** the guest, so neither
inherits a provider's pre-boot hard bail. Sign in (or paste an API key) in the
guest instead, and it persists per project:

- `pi` keeps user state under `~/.pi/agent`.
- `dsh` keeps its whole home under `~/.dsh` (profiles, sessions, and the
  `~/.dsh/.credentials.yaml` document the Models UI writes). Its shipped
  default command is `dsh web`, so reach the UI with `--publish` or
  `--auto-publish`:

  ```sh
  agent-vm dsh --auto-publish --yes
  ```

  Anthropic and OpenAI support needs no extra plugin: the harness mounts its
  built-in `llm-pi-ai` multi-provider adapter dormant, so pick the provider in
  the Models UI and store its key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or
  `DEEPSEEK_API_KEY` for the default DeepSeek provider). Community plugins are
  not baked into the image; add one in the guest with
  `dsh plugin --profile web add <package>` (pnpm is installed).

"Declares no `credentials`" is not the whole story for `pi`, though: it also
declares `tools = ["claude"]`, so a `pi` launch **provisions** the Anthropic
credential **without requiring** it
([ADR-0017](docs/adr/0017-tool-declared-provisioning.md) alternative 2). That is
what makes the shipped `claude-bridge` provider work with no in-guest login:
`agent-vm pi` writes the Anthropic placeholder into the project's
`~/.claude/.credentials.json` and registers the proxy substitution, so the
Claude Code child the bridge spawns reaches Anthropic with your **host**
credential. Four consequences are worth knowing:

- **A host `ANTHROPIC_API_KEY` wins over all of it.** agent-vm publishes a
  host-set `ANTHROPIC_API_KEY` into the guest as the **real, unsubstituted**
  value (`OPENAI_API_KEY` likewise); Claude Code prefers the environment
  variable over `~/.claude/.credentials.json`, so it bypasses the placeholder
  proxy entirely and, if the key is unusable, every bridge turn fails with an
  Anthropic auth error. `unset ANTHROPIC_API_KEY` before starting `pi`. This is a
  pre-existing defect that also affects `agent-vm claude` and `agent-vm shell`
  ([#165](https://github.com/gregwebs/agent-vm/issues/165)); `agent-vm pi` does
  not introduce it, it adds a third verb it bites.
- **An in-guest `claude login` cannot complete once the host has a credential.**
  The launch registers the `POST platform.claude.com/v1/oauth/token` intercept
  route, and the hook answers token *refresh* grants only: an authorization-code
  exchange is rejected and Claude Code reports a bare `OAuth error … status code
  400`. With **no** host credential nothing is registered, so `claude login`
  works — that is exactly the case where you would want it.
- **An image that ships the `pi-claude-bridge` provider must also carry a
  working `claude` executable.** The default boot image ships Pi with the
  image-owned `pi-claude-bridge` extension, whose Claude Code child is the same
  image's `claude` binary. An image that ships that provider but omits the
  `claude` **executable** ships a bridge that cannot spawn anything: the seed
  hook no-ops and every turn fails with `Native CLI binary … not found`. That is
  an image problem — installing software is the image's job, so rebuild the image
  with `claude` (or select an image that already has it). A custom Pi image that
  deliberately uses another provider does not need the bridge, so this does not
  apply to it.
- **The catalog declaration is separate from the image.** The shipped `pi` tool
  declares `tools = ["claude"]`, which provisions Anthropic through Claude Code's
  credential. A custom catalog that copies that declaration must also resolve a
  `claude` tool (or its `credentials` requirement); otherwise the declaration
  fails on a **dangling-tool error**, which is a *config* problem, not an image
  one. Merely having `claude` installed in the image does **not** synthesize the
  catalog entry or its provisioning edges — drop the reference or declare the
  credential requirement directly if the catalog deliberately omits `claude`.

### Storing your own secret values

`agent-vm secret` manages values **you** give agent-vm directly, for a
credential no agent CLI keeps a file for. They live in the host OS credential
store (macOS Keychain, Linux Secret Service) under agent-vm's own namespace,
`dev.agent-vm.credentials` — separate from Docker's `com.docker.sandboxes` and
from microsandbox's own registry entry. agent-vm never reads or writes those.

```sh
agent-vm secret set anthropic                       # hidden prompt
printf '%s' "$ANTHROPIC_API_KEY" | agent-vm secret set anthropic
agent-vm secret ls
agent-vm secret rm anthropic
```

- **The value is never an argument.** `agent-vm secret set SERVICE VALUE` and
  `--token VALUE` are **refused**, not warned about: the shell history and the
  process argument list would both expose the value. Pipe it on stdin, or run
  the command with no value for a hidden interactive prompt. Note that refusing
  the value stops agent-vm from storing or printing it; it cannot un-type it —
  if you typed it on the command line, the shell has already recorded it in its
  history, so treat it as exposed and rotate it.
- **A name is metadata, not a secret.** Names are shown by design (`secret ls`
  lists them, `set`/`rm` echo the name on success), and the accepted alphabet is
  a superset of the characters real API keys use. If you accidentally type a key
  in the `SERVICE` position, agent-vm will *accept* it as a name and print it —
  argv, shell history and listings are all on the record. A key typed on the
  command line should be treated as exposed. (agent-vm does not try to guess
  which names “look like” credentials: that would reject valid names, so the
  responsibility stays with the operator.)
- **Names are case-folded to ASCII lowercase.** A name is 1-64 characters from
  `[a-zA-Z0-9._-]`, starting with a letter or digit; letters are folded, so
  `Anthropic`, `ANTHROPIC` and `anthropic` are the **same** credential (keychain
  accounts are case-sensitive, so folding is what stops three spellings becoming
  three invisible entries). The folded name is what `secret ls` prints and what
  the keychain stores, so type a name here and not a key.
- **The accepted value shape is narrow, on purpose.** Printable ASCII
  (`0x20`-`0x7E`), 1-4096 bytes, no leading or trailing space. A multi-line,
  non-ASCII or NUL-containing credential is rejected at storage time rather than
  stored and rejected later.
- `ls` prints **names and storage status only** — never a value, not even part
  of one. `stored` means the keychain answered; `missing` means it answered and
  found nothing; `unavailable: …` means it could not be asked (locked, denied,
  or no Secret Service running).
- **An empty listing proves nothing about the keychain.** It exits zero and
  means only "no names are tracked"; no probe ran. A listing with any
  `unavailable:` row exits non-zero, so a script is never told everything is
  fine when agent-vm could not see the store.
- **Storing a value does not authorize its use.** The only thing that reads a
  stored value back is an *authorized launch* (see below); `secret` never prints
  one, and `ls`/`doctor` remain structurally unable to. Authorization, and any
  injection into a request, is separate host configuration. See the
  [credential shielding specification](docs/specs/credential-shielding.md) and
  [ADR-0025](docs/adr/0025-yaml-credential-shielding.md).
- **No fallback, ever.** If the platform credential store is unavailable, the
  operation fails with a classified message. agent-vm never writes a value to a
  plaintext file, and never degrades to an environment variable.

agent-vm keeps a **names-only** record of what it has stored at
`~/.config/agent-vm/secret-inventory.json` (mode 0600), beside a
`.secret-inventory.lock` (0600). The file lists service names and nothing else;
its own `note` field says so. It is not an authorization list. Deleting it
loses only the *listing*: the stored values are untouched and
`agent-vm secret rm NAME` still works by name. If you hand-edit it, a
malformed file or an invalid name is a hard error on every verb, naming the
file and telling you to delete it to reset the listing — agent-vm never
silently resets a file you wrote.

### Authorizing a stored value for injection

A stored value does nothing until you *authorize* it: name the exact HTTPS
origin and the exact request header it may occupy, in
`~/.config/agent-vm/credentials.yaml`. There is no approval registry and no
generation CLI — editing the file **is** the authorization, and re-editing it is
reauthorization.

```yaml
credentials:
  - service: my-service          # the name you used with `agent-vm secret set`
    required: true               # fail before boot if it is missing/unreadable
    apiKey:
      name: MY_SERVICE_KEY       # the guest environment variable this owns
      sentinelEnv: true          # put `proxy-managed` there (default: false)
      inject:
        - domain: api.my-service.example   # bare host means HTTPS 443
          header: x-api-key
          format: "%s"                     # exactly one %s
        - domain: api-2.my-service.example:8443
          scheme: bearer                   # shorthand for authorization + "Bearer %s"
```

Then have a tool request it, in a user or project `config.toml`:

```toml
[[tools]]
name = "my-agent"
command = "my-agent"
credentials = ["my-service"]
```

What to expect:

- **The value never enters the guest.** The request to the authorized origin
  carries it; the guest sees only the placeholder
  (`sentinelEnv: true`) or nothing at all (`sentinelEnv: false`, the default).
  Injection does not depend on `sentinelEnv`.
- **Only the exact origin.** A bare `domain` means port 443; an explicit port is
  exact. A request to another port, another host, or over cleartext is
  *forwarded uninjected* — not blocked, and not an error.
- **Each credential's port is declared as TLS-intercepted.** The runtime decides
  TLS interception per **port**, so agent-vm adds the credential origin's port
  to the launch's intercepted ports (unioning it with the default 443 and
  anything already configured). Declaring a port intercepts TLS for **every**
  host on that port, not only the credential's origin — that is the cost of a
  per-port interception decision, so prefer the default 443 unless the service
  really lives on another port.
- **Egress policy is unchanged.** Authorizing an origin does not open egress to
  it. If your policy denies the host, the request never reaches injection.
- **Rotation is launch-scoped.** A value rotated with `agent-vm secret set`
  while a sandbox runs is *not* picked up; the next launch uses the new value.
- **Malformed authorization fails closed.** An unreadable, foreign-owned,
  group/other-writable, symlinked or malformed `credentials.yaml` refuses a
  launch that requests a credential, with a message naming the file but never
  its contents. A launch that requests nothing is unaffected.
- **Names owned by an authorization win.** If `apiKey.name` is
  `OPENAI_API_KEY`, agent-vm stops forwarding the host's `OPENAI_API_KEY` for
  that launch, suppresses any provider-forwarded variable of the same name, and
  refuses a tool-declared `env` key of the same name. Names agent-vm itself must
  publish (`IS_SANDBOX`, `LANG`, `PATH`, `HOME`/`USER`/`LOGNAME`, the `MSB_`
  namespace) cannot be authorized as `apiKey.name` at all. A `sentinelEnv: false`
  variable the boot image defines is refused, and unreadable image metadata
  fails the launch closed rather than risking a value that should have been
  unset.
- **A same-named built-in is replaced, completely.** An entry named `anthropic`,
  `openai`, `opencode-static` or `copilot` is a precedence-setting
  authorization: for a launch that *requests* that name, it takes over the
  built-in provider's **credential handling**, and there is **no fallback** to
  the built-in if the authorized value is unavailable — falling back would
  downgrade a shielded credential to a guest-visible placeholder you never asked
  for. The built-in's **configuration and persistence** are untouched. An entry
  nothing requests changes nothing at all.

| provider | credential handling the entry replaces | configuration/persistence kept |
|---|---|---|
| `anthropic` | host `~/.claude/.credentials.json` capture, the guest `claude/.credentials.json` placeholder, the proxy secret and its OAuth refresh route, the built-in's required-credential bail | `claude/settings.json` and `claude.json` onboarding bypasses, the `.claude` guest-HOME link, the state dir |
| `openai` | host `~/.codex/auth.json` capture, the guest `codex/auth.json` placeholder, the proxy secret and its OAuth refresh route, OpenCode's synthetic `openai` row | `codex/config.toml`, the `.codex`/`CODEX_HOME` wiring |
| `opencode-static` | every BYO API-provider row read from the host `~/.local/share/opencode/auth.json` and its host token file, OpenCode's synthetic guest rows, agent-vm's `model` pin | `opencode-config/opencode.json` (`$schema`, `autoupdate`), user-authored guest `auth.json` rows |
| `copilot` | host device-flow capture, the `copilot/config.json` `github_token` placeholder, `COPILOT_GITHUB_TOKEN`, the proxy secret | `copilot/config.json` `trusted_folders` (so a fresh state dir does not prompt "do you trust this folder?") |

  Two consequences deserve spelling out:
  - replacing `openai` also drops OpenCode's synthetic `openai` row, because
    that row is derived from the same captured host token — one credential, one
    handling;
  - replacing `opencode-static` also retires agent-vm's `model: openai/gpt-5.5`
    default: agent-vm's capture gate sees no OpenAI credential for a replaced
    provider, so it does not re-assert the default — even for a sentinel entry
    (`apiKey.name: OPENAI_API_KEY`, `inject: api.openai.com`) that *does* give
    the guest a working OpenAI key through the proxy. If your entry is an
    OpenAI-compatible key, set `model` in your own
    `opencode-config/opencode.json`.
- **Switching to a shield leaves the old on-disk host copy.** A replacement
  stops agent-vm *capturing* the built-in's host credential, but a host-only
  token file an earlier un-replaced launch wrote under
  `<state>.secrets/<provider>` (0600, in the never-bind-mounted host-only
  directory) is left in place — deleting it would be new destructive behaviour
  on data a concurrent launch may hold. The **guest-visible** placeholder *is*
  cleared; the real host copy is not. Remove the state directory to clear it.
- **A renamed authorization does not shield the built-in's variable.**
  Ownership is by variable name: a YAML `anthropic` entry with
  `apiKey.name: MY_KEY` leaves the host's `ANTHROPIC_API_KEY` forwarded into the
  guest verbatim. agent-vm warns at launch (naming the provider and the still-
  forwarded variable, never the value) and suggests `apiKey.name:
  ANTHROPIC_API_KEY` or unsetting it on the host. Removing the raw forwarding
  outright is [#163](https://github.com/gregwebs/agent-vm/issues/163).
- **`--allow-missing-credentials` (host-only).** A per-launch flag that warns
  and continues instead of refusing when a requested `credentials = [...]` name
  has no authorization, and when an authorized `required: true` credential's
  value cannot be read. The guest gets neither the credential nor a fallback, so
  the in-guest tool may still fail its own sign-in. It cannot bypass a malformed,
  unsupported or rejected `credentials.yaml`, an integrity refusal (foreign owner
  or group/other write), a stored value the store rejects, a `sentinelEnv: false`
  name the boot image defines (or unreadable image metadata), a tool-`env` name
  conflict, or **a built-in provider's own missing host credential** — that last
  one still refuses the launch. There is deliberately no environment variable: it
  is a per-launch decision you make at the command line, and a project config has
  no way to set it.
- **`agent-vm doctor` resolves the launch context from the configured verbs.**
  It annotates each host credential row — a provider a configured launch
  replaces reads `replaced by credentials.yaml for <verbs> (host file not
  read)`, and a provider no configured launch requests reads `not requested by
  any configured launch` — and names each requested authorization as
  `authorized for this launch`. It reads the authorization file, never the
  credential store, so it neither prompts nor writes; `agent-vm secret ls`
  reports whether a value is stored. See
  [Checking what agent-vm can see](#checking-what-agent-vm-can-see).
- **Unsupported, by name, never silently ignored.** `source` (an environment
  source is #163), `permissions`/`permissions.network`, `oauth`, `basic`,
  `username`, request signing, query/body injection, kit/hooks/images/mounts/
  ports/composition, and wildcard, path, cleartext, userinfo, IP-literal or
  non-ASCII destinations are all refused with the reason.
- **macOS and Linux only.** Windows and the cloud backend refuse
  credential-bearing launches upstream.
- **A stale `msb` fails the capability probe.** The runtime is asked to report
  `header-credential-launch-v1`; an `msb` built before this feature refuses the
  launch before any sandbox record is written, and agent-vm tells you to rebuild
  it from `vendor/microsandbox` (check `MSB_PATH`).

On macOS the keychain ACL is bound to the calling binary's code-signing
identity, so a locally rebuilt unsigned `agent-vm` may be asked
*"agent-vm wants to use your confidential information…"*, and `secret ls`
probes once per listed name. That is possible and identity-dependent, not
guaranteed — and if you deny the prompt, the row reads `unavailable: …` rather
than crashing. This is also why overriding `$HOME` (and so the login keychain's
path) makes every verb report the store as unavailable.

## Project hook
If the project root contains an executable `.agent-vm.runtime.sh`,
the launcher sources it inside the guest before exec'ing the agent.
Use for `npm install`, env exports, dev-server startup. Non-zero
exit aborts the launch.

## Clipboard

Move a string across the VM boundary without a shared shell:

```
agent-vm clipboard put "some text"    # or: ... | agent-vm clipboard put
agent-vm clipboard get
```

Run both from the project directory — the clipboard is per-project. It is a
plain file, `clipboard.txt` in the project's state dir, bind-mounted into the
guest at `/agent-vm-state/clipboard.txt`, so the in-VM agent can read and
write that path directly with no special tooling.

`--sys` / `-s` also exchanges with the host's system clipboard (`xclip`,
`wl-copy`/`wl-paste`, or `pbcopy`/`pbpaste`, whichever is on `PATH`). Without
it the command is pure stdin/stdout and works headless.

## Token usage across host and sandbox

`ccusage` only sees the session history under `~/.claude`, so it misses
everything an agent did inside a sandbox. `bin/agent-vm-ccusage` unions the
host history with every per-project agent-vm session directory and reports
them together:

```
bin/agent-vm-ccusage            # extra args are forwarded to ccusage
```

It runs `npx -y ccusage@latest`, so it needs Node and network on first use;
nothing has to be installed up front.

It finds the per-project directories under the same state root the launcher
uses (`AGENT_VM_STATE_DIR`, else `$XDG_STATE_HOME/agent-vm`, else
`~/.local/state/agent-vm`). A directory whose path contains a comma is skipped
with a warning — `CLAUDE_CONFIG_DIR` is comma-separated with no way to escape
one.

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
