# Using agent-vm

The full reference for running agent-vm. See [README.md](README.md) for
an overview, and [CONTRIBUTING.md](CONTRIBUTING.md) to build from source
or develop agent-vm.

## Requirements

- Linux with `/dev/kvm` (rw) and membership in the `kvm` group, or an
  Apple Silicon Mac for the [supported source-build workflow](macos-build.md).
- Node.js 18+ for the npm-distributed launchers.

The packaged Linux workflow installs its matching libkrunfw on first launch.
Apple Silicon source builds assemble a self-contained local runtime bundle, or
a [single binary](macos-build.md#build-a-single-binary) with `./script/build/macos.sh --single-binary`.

## Quick start

```bash
cargo build

agent-vm setup            # acquires the selected image and verifies it boots

cd ~/your-project
agent-vm --allow-internet-egress claude
```

See [Ports & egress](#ports--egress) for narrower grants and their risks.

The npm package bundles a prebuilt `agent-vm` binary, `msb`, and
libkrunfw. agent-vm finds them via `current_exe()`-relative paths, so a
user's separate `~/.microsandbox/bin/msb` (if any) never shadows the
bundled build.

## Version / build identity

```text
$ agent-vm --version
agent-vm 0.3.4 (08f515f2c4f8a1c3c9d2b7e6a5f4c3b2a1908f7e)
```

`--version`/`-V` print the release number and the Git commit the binary was
built from, measured once at build time:

```text
agent-vm 0.3.4 (08f515f..., dirty)         tracked files differ from the commit
agent-vm 0.3.4 (08f515f..., state unknown) Git/status could not be measured
agent-vm 0.3.4 (unknown)                  built without Git metadata
```

The revision is always a full object id. The value is baked into the binary, so
copying it to a machine without Git does not change the output, and setting
`AGENT_VM_GIT_SHA`/`GITHUB_SHA`/`AGENT_VM_BUILD_PROVENANCE_STRICT` at runtime
does nothing. This is build metadata, not a signature — it does not prove the
binary came from that source. See [CONTRIBUTING.md](CONTRIBUTING.md#build-identity-in-agent-vm---version)
for how it is chosen and for the default invalidation limits.

## Subcommands

```
<tool>                              launch a configured tool in a per-project sandbox
                                    (the verbs come from your tool configuration;
                                    run `agent-vm --help` for the exact list)
run PROGRAM [ARG...]                run a guest executable directly; no catalog
                                    entry, defaults, environment or provisioning
                                    (see Direct commands below)
-- PROGRAM [ARG...]                 the same, spelled with the top-level separator
image show                          print the boot image a launch here would
                                    select, with its source (read-only, offline)
image build --tag REF [OPTIONS] [CONTEXT]
                                    explicitly build + import a user Dockerfile
image import (--docker REF [--tag REF] | --input FILE --tag REF)
                                    import a finished image into agent-vm's cache
image refresh [--image REF] [--yes]
                                    approve/acquire the selected OCI image,
                                    without booting a VM or changing the
                                    retained default
image set-default --image REF [--yes]
                                    approve and retain a new digest-pinned default
setup                               acquire the selected image + verify boot
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

### Changed in 0.7.0: image operations moved under `image`

`pull` and `upgrade` are gone; there are no aliases or hidden spellings, and a
configured tool may now use either name.

| before | now |
|---|---|
| `agent-vm pull [--image REF]` | `agent-vm image refresh [--image REF]` |
| `agent-vm upgrade --image REF` | `agent-vm image set-default --image REF` |
| `agent-vm pull --help` | `agent-vm image refresh --help` |

Flags follow their subcommand: `agent-vm image refresh --image REF` works,
`agent-vm --image REF image refresh` and `agent-vm image --image REF refresh`
do not. The rule is positional: an unknown or spaced flag *before* the tool
verb is an unknown-option usage error (status 2), while a token *after* the
verb is forwarded to the tool verbatim (and a built-in verb rejects it). There
is no compatibility alias for a flag agent-vm no longer has: before the verb it
is an unknown option, after it the tool sees it.

`image refresh` is **boot-free native acquisition**: it resolves the selected
reference (or `--image REF`), checks its current manifest, reuses unchanged
cached layers, and publishes a complete host-Linux cache entry using the
ambient microsandbox cache with native registry auth, trust and managed HTTP
policy. It creates no sandbox, boots no guest and touches no project or running
guest. Selection, precedence and recovery are unchanged. Every OCI selection
is also a host-wide **image approval** (next section); refresh is one of the
two explicit operations allowed to re-resolve a source and ask for consent. A
launch never checks a tag for movement: there is no launch-time update check,
flag, environment variable, banner or marker.

`image set-default` is the renamed deliberate default operation (below), with
the same acquisition-before-publication safety. Refresh and set-default accept
only OCI references; a local rootfs/disk path is rejected with advice to launch
it explicitly (`agent-vm --image PATH <tool>`). Local-path **launches** remain
supported. `setup` now enforces the same OCI-only acquisition rule for its
image (local-path launches are still fine), while its optional verification
guest is separate and unchanged. A bare `image refresh` with no override still
reacquires your retained digest, not the tag it was originally selected from.

`agent-vm setup` acquires the selected image and, unless `--no-verify` is given,
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
default boot image), so a config typo never blocks the acquire/boot/verify
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
retains the **index** reference; explicit `image set-default` retains its
resolved native **child** digest. Existing records and explicit selections are unaffected.
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
image. `image refresh` acquires that same selection without booting;
`setup` acquires it and optionally boots a verification guest.

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

### Host-wide approval of OCI image content

Every OCI image you select — `--image`, `AGENT_VM_IMAGE_TAG`, user or project
`image`, or the default tier — is **approved once per host and platform**.
agent-vm keeps that approval in:

```text
$HOME/.config/agent-vm/image-pins.json   approvals (private, version 1)
$HOME/.config/agent-vm/image-pins.lock   coordination
```

One entry binds the canonical OCI reference plus the host Linux platform
(`linux/arm64`, `linux/amd64`) to the approved host-platform manifest **child**
digest. The store is host-wide: every project and every launch `HOME` share it,
and it is independent of the microsandbox cache, of `AGENT_VM_STATE_DIR` and of
project files. Approvals are never written into `config.toml`. Selection
precedence is unchanged (table above): a pin never chooses the image; it fixes
what an already-selected reference may resolve to.

**Acquisition precedes the guest, approval precedes create.** On the first
selection of a reference, agent-vm acquires and validates the image, commits
the first pin, and only then hands `repo@approved-digest` to the SDK. The pin
therefore records measured content, not a successful boot: a later builder,
credential or runtime failure leaves it in place, and no launch consumes bytes
it did not approve. A first pin needs no prompt. `setup` prepares the same way;
its verification guest boots the approved child (or the first pin it just
committed), and `--no-verify` stops after preparation without a VM.

What this buys:

- **Warm launches are offline and registry-free.** An existing approval is
  consumed as `repo@child`; the mutable tag is never queried. A registry
  outage, a moved tag or a tag deleted upstream does not change a warm launch.
- **Clearing cache cannot upgrade content.** With the cache or state root
  gone, the approved digest is reacquired from its registry. If that content is
  unavailable the launch fails; it never falls back to whatever the tag serves
  now. The approval lives outside every cache and state root, so only moving
  `HOME` or deleting the store loses it.
- **Only two verbs check for movement.** `agent-vm image refresh` and
  `agent-vm image set-default` resolve their target's current registry content
  even when a pin exists. No launch, setup or background probe does.
- **Host checks are not guest compatibility.** Platform, manifest and digest
  validation say which bytes are approved; they do not promise the applications
  inside them work. That remains the [boot image contract](#boot-image-contract).

A digest you type yourself keeps its stated identity: mismatching content is an
integrity failure, never an invitation to approve the replacement. A multiarch
**index** selection may resolve to its verified host-platform child, and the
approval names that child; equivalent guest content reached under a different
manifest digest or digest algorithm keeps the stored approval and asks nothing.

Local rootfs directories and disk images are launched but never pinned: a local
path passes through unchanged and touches neither the store nor the cache
barrier. `image refresh` and `image set-default` reject local paths as targets.

#### Replacing an approval

When an explicit refresh or set-default resolves different content for an
existing mutable pin, agent-vm prints the change and asks on stderr:

```text
Replace the approved image for ghcr.io/owner/app:dev (linux/arm64)?
  old: sha256:<full old digest>
  new: sha256:<full current digest>
Approve this exact image change? [y/N]
```

The default is **No**. One line is read (at most 64 bytes); `y` or `yes`,
ASCII-case-insensitive after surrounding whitespace, approves. Empty input,
`n`, an invalid or overlong line, end-of-file or an I/O error declines with
status 1 and no reprompt. The operation is repeatable, so declining is cheap.
The exact validated candidate is frozen before the prompt: a registry that
moves again during the decision cannot substitute content under the same
consent. The approval binds that candidate's digest plus the pin revision and
digest that were displayed; a concurrent writer that moved the pin first fails
the compare-and-swap and asks you to retry, rather than silently authorizing
the wrong predecessor.

`--yes` pre-authorizes exactly the resolved candidate:

```sh
agent-vm image refresh --yes
agent-vm image refresh --image ghcr.io/owner/app:dev --yes
agent-vm image set-default --image ghcr.io/owner/app:dev --yes
```

`--yes` exists only on these two verbs (no `-y`, no environment variable and no
launch, setup, build or import flag). The change is still printed, so the old
and new digests appear in the log without a human at the terminal. A first pin
or an unchanged digest never prompts and does not need `--yes`.

Without `--yes`, a replacement needs **both stdin and stderr to be terminals**.
Pipes, files, CI runners and `2>log` all refuse a changed pin with status 1,
fixed guidance naming the `--yes` form, and the stored approval untouched;
stdin is not read, so a piped script cannot answer a question it was never
shown. A first pin or an unchanged digest succeeds without a terminal. Cloud
and CI automation must therefore use `--yes`, which authorizes one exact
candidate rather than "whatever is current".

#### Damaged or reset approvals

A damaged store (wrong schema, unknown field, duplicate key, oversized,
non-UTF-8, symlink, FIFO, unreadable, or a lock that is not a regular file) is
a hard error, never "no approvals yet". OCI launches, setup and updates fail
until it is repaired, because silently re-pinning would authorize content
nobody approved. The damaged bytes are left in place. Recovery: restore the
file from a backup; or, to deliberately **reset approvals**, move
`image-pins.json` aside and leave the cache alone. A reset makes the next
selection of each reference a first selection again — it re-approves whatever
that reference resolves to at that moment. Never delete approvals to work
around a cache problem: cache records have their own restore/reacquire
recovery, and an approval is not cache evidence.

#### Retained default and staging boundaries

The [retained default](#the-retained-default) keeps its existing digest-only
storage: `default-image.json` never records a source tag, platform or tool
metadata. `image set-default` stores its approved host child there, so a bare
`image refresh` still reacquires the retained digest rather than following the
tag it was originally selected from (issue #392). Automatic adoption is
unchanged in *when* it may happen: an absent record is retained only after
successful acquisition — for any successful default-tier preparation, not only a
first pin — and an existing record is never moved by a launch.

`image build` and `image import` publish cache aliases but never create or
replace a pin or the retained default (issue #391). Importing over a tag you
once approved does **not** approve the imported bytes: a launch keeps using the
approved digest until you run `image refresh --image REF` and approve the
change. A daemon-only image may not be available from a registry, so it cannot
be registry-refreshed; the import itself remains the supported way to get it
into the cache.

The store holds at most 4096 approvals of at most 4096 source bytes each, and
the record may not exceed 4 MiB; exceeding a bound is a schema error, not a
partial load.

### Inspecting the selected boot image

`agent-vm image show` prints the image a launch in this project would select,
and where it came from, without acquiring or booting anything:

```console
$ agent-vm image show
Image: registry.example/env:dev
Source: AGENT_VM_IMAGE_TAG
```

It accepts no options except `--help`. In particular there is no `--image`:
`image --image REF show` and `image show --image REF` are rejected.

`Image:` is the full selected reference, escaped for the terminal (`\` is
doubled, `"` is escaped, other control and non-ASCII bytes become `\xNN`),
exactly as the selector holds it — never trimmed, resolved or normalized.
`Source:` is one of five fixed labels, and `File:` appears only for the winning
file-backed source, escaped the same way:

| `Source:` | `File:` |
|---|---|
| `AGENT_VM_IMAGE_TAG` | — (not a file) |
| `user config` | `~/.config/agent-vm/config.toml` |
| `project config` | `<cwd>/.agent-vm/config.toml` |
| `retained default` | `$HOME/.config/agent-vm/default-image.json` |
| `initial recommendation` | — (nothing was read) |

These are the [selection table](#selecting-the-boot-image) rows in the same
order; `AGENT_VM_IMAGE_TAG=""` counts as unset, exactly as for a launch.

`Image:` reports the selected **source**, not the approved guest content. The
digest a launch would actually consume is a separate host approval and is not
printed here.

The command is read-only and offline. It consults no cached image, Docker,
msb, registry, keychain or VM, and creates no record, lock, configuration
directory, cache or runtime state; it needs neither an installed runtime nor
image sources. It therefore makes no claim about whether the selected image
exists, can be downloaded or can boot. When the default tier is the observed
source, the report depends on a healthy pin store and a bounded shared-lock
read, because the store's journal defines the logical fallback; a damaged store
fails that observation safely while a higher explicit source still prints.

Failures use the diagnostics selection already has, on stderr with an empty
stdout. An unreadable or invalid configuration is fatal **even when the
environment would win**, and a damaged retained record is fatal only when the
fallback is actually needed: a valid environment/user/project image succeeds
without reading it. `agent-vm doctor` remains the verb that reports such state
without failing early.

Unlike every other output, `image show` deliberately reveals the full
reference, including a private retained default — that is what asking for the
selection means. Its own logs stay silent, and `doctor`, launch notices, the
`AGENT_VM_DEBUG_CONFIG` dump and acquisition errors keep redacting as before.
Log output captured while running a successful `agent-vm image show` can
therefore contain a private registry name.

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
move it. Change it deliberately with
[image set-default](#explicitly-setting-the-default).
It is deliberately a separate file from `config.toml` — writing a
top-level `image =` there would make the *user config* tier win over the
*project* tier, which is a precedence change, not a bookmark.

The launcher also carries an **initial recommendation** (an immutable
`@sha256:…` reference compiled into the binary; currently the released v0.1.3
multiarch index, and a newer release may change it). How the two interact:

- **Selection is lazy and read-only.** A higher source wins without reading the
  record; `help`, `doctor`, `--help`, `image refresh --help` and `setup --help`
  never write one.
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
  digest alone. Automatic adoption is insert-if-absent under the host lock, so
  concurrent first launches cannot overwrite each other.
- **The digest is also a host approval.** The default tier participates in the
  same [host-wide approval](#host-wide-approval-of-oci-image-content) as every
  other source: once pinned, a launch consumes the approved child and makes no
  registry contact. The record still holds only the digest (#392), so a bare
  `image refresh` reacquires it rather than following a tag.
- **The digest must resolve.** A retained digest whose content is unavailable
  (registry gone, content deleted) fails the launch with the same error a
  user-typed reference would; it is not silently redirected to another image.
  Restore network access and retry.

`image refresh` acquires *the selected reference* again; it is **not** a change
of the default's identity. `image refresh --image REF` reacquires `REF` and
never adopts it as your default. Use
`--image`/`AGENT_VM_IMAGE_TAG`/config `image` to boot a different image for one
session, or to point a fresh host at another one. Refreshing does not boot a
guest, so neither a running guest nor project state is touched; it checks the
reference's current manifest and reuses unchanged layers.

**Mutable tags vs. digests.** A mutable tag (`:latest`) names *whatever the
registry serves now*: after a cache loss a `:latest` launch may fetch different
bytes than before. A digest names exact content. That is why the retained record
and the initial recommendation are digest-pinned, and why the launcher never
polls a tag: a launch makes no registry contact beyond acquiring what an
[approval](#host-wide-approval-of-oci-image-content) already names, and
checking for movement is the explicit `agent-vm image refresh` operation's job.

**Observing and recovering.** `agent-vm doctor` prints a fixed label —
`retained default` or `not selected; initial recommendation` — and the record
path; it never prints the reference itself. The default tier is host state (an
untrusted, user-writable file whose reference may name a private registry), so
notices, `agent-vm doctor`, the opt-in `AGENT_VM_DEBUG_CONFIG` dump and
acquisition errors name `the default boot image` and redact its reference rather
than echoing it. Your own `--image`/`AGENT_VM_IMAGE_TAG`/config `image` values
are unaffected: they are your inputs, and they are still shown. The one
deliberate exception is [`agent-vm image show`](#inspecting-the-selected-boot-image),
which prints the reference because you asked for the selection. It is strictly
observational — it creates nothing. If the record is
corrupt, unreadable (a symlink, FIFO, directory, oversized or non-UTF-8 file)
or names a non-digest reference, every verb that needs the default fails and
names the escaped path with a fixed reason; nothing is auto-reset. To recover,
restore the intended digest record from backup, or deliberately move the file
aside to reinitialize from the current recommendation. That is separate from a
damaged [pin store](#damaged-or-reset-approvals), which needs its own repair or
deliberate reset.

### Explicitly setting the default

```sh
agent-vm image set-default --image ghcr.io/owner/standard:release-2
agent-vm --no-git shell bash -c 'my-program --version'
```

`--image REF` is required and accepts an OCI tag or digest, not a local path.
Environment/config launch images do not choose the set-default target, even with
broken tool configuration. There is no automatic latest discovery; explicitly
requesting `:latest` resolves it only for this invocation. A changed approval
needs consent — the terminal prompt, or `--yes` for unattended use
([Replacing an approval](#replacing-an-approval)).

```text
explicit OCI target → resolve current registry content once → validated candidate
                    → approval (first/unchanged: none; changed: prompt or --yes)
                    → revalidate the frozen candidate under a shared barrier
                    → shared cache barrier → pin EX → default EX (journaled)
                        atomic pin store  {old pins, pending_default}
                        atomic default    {approved host child}
                        atomic pin store  {new pins, no pending_default}  ← commit
                    → release; future launches consume the approved child
```

The command uses the ambient **local** microsandbox cache and native registry
auth/TLS settings. It consumes registry content without Docker and **does not
boot or replace a VM**. Only future sessions falling through to the default
change: CLI, environment, user and project image overrides and running sessions
are untouched. Acquisition, approval or publication failure exits nonzero and
leaves the old selection and cached image usable; unused new artifacts may
remain cached. A declined or nonterminal refusal also leaves the previous
fallback in place. No old images are deleted. A successfully re-acquired same
digest leaves valid record bytes unchanged and asks nothing. Interruption
before the final pin write is repaired by the next *write* to the store — an
explicit image command, or a launch or `setup` that has to record a first pin or
retain the fallback — which restores the old logical default; readers never
recover, and no fsync/power-loss durability is claimed.

An absent record can be initialized directly, without consulting the initial
recommendation. A damaged record is rejected, not automatically repaired; use
the recovery procedure above. Approval and fallback commit together under the
host lock; an explicit replacement is a compare-and-swap on the revision and
digest you were shown, so a concurrent writer that moved the pin first makes
this operation fail instead of overwriting it, and a delayed ordinary adopter
cannot overwrite an established pin. A launch that already selected the
previous default may still boot it.

Roll back by passing a known previous full digest reference to the same
`image set-default --image` command. Acquisition must succeed again before
selection changes; `image refresh --image` remains a cache reacquisition, never
default replacement.

Set-default progress/application errors use a fixed redacted image label, not the
old or requested reference or native source chains. Inspect your user-owned
record directly for the pin. Clap usage errors may echo an invalid value you
supplied on argv (status 2); this exception does not apply to stored references.
See [the retained default](#the-retained-default) for scope and recovery.

### Customizing the image

Build user-owned software with an ordinary Dockerfile, then explicitly select it.
Directory names never activate composition; see the agent-vm-images
[examples](https://github.com/gregwebs/agent-vm-images/tree/main/examples/layers).

Extend the released Debian-based standard image, or clone the independent
[image sources](https://github.com/gregwebs/agent-vm-images) and build the
tool-free base locally with an ordinary `FROM`. Source build/version maintenance
instructions belong there; installed agent-vm needs neither that checkout nor
its contributor submodule. The examples need Debian/apt/Node facilities, not just
the minimal boot contract.


#### Explicit builds and archive import

**Changed in 0.5.0:** `agent-vm build` is now `agent-vm image build` (same
options and behavior, except the completion notice is printed on stdout).
There is no alias: `agent-vm build` now fails as an unknown command, and a
configured tool may now be named `build` — with such a tool,
`agent-vm build …` launches it instead. A tool named `image` is refused as reserved.

```text
Dockerfile/context → image build → completed anonymous OCI archive
Docker daemon image / archive → image import ────────────────┘
                                          ↓ native cache import
                                      result reference
                                          ↓ agent-vm --image REF shell
                                       guest execution

image import (only after publication) → the same selection `image show` reports
                                      → completion guidance (read-only; no write,
                                        adopt, configuration or boot)
```

```sh
agent-vm image build --tag my-image:dev --builder native-oci .
agent-vm --image my-image:dev shell my-program
```

The bounded option surface is:

```text
agent-vm image build --tag REF [-f|--file DOCKERFILE]
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
failed build. Import a finished daemon image in one command; Docker
`image save` must succeed before anything is imported:

```sh
agent-vm image import --docker my-image:dev        # result reference = source
agent-vm image import --docker my-image:dev --tag my-renamed:dev
```

`--tag` is optional **only** with `--docker`: the source then supplies the
result reference, so the common case needs one flag. An explicit `--tag` (also
`-t`) still overrides it. Both routes cross the same parser, so an inferred
reference is exactly as strict as a typed one: a mutable OCI reference, no
digest and no local path. Docker's own source grammar is wider (a digest, an ID
or a path-like name is a valid thing to save), so a source that cannot also be
a destination needs an explicit `--tag`; agent-vm never rewrites it into
`latest`. An archive always needs `--tag`.

For the standard release, first download/authenticate the exact native v0.1.3
archive using the [image owner's public release instructions](https://github.com/gregwebs/agent-vm-images/blob/main/docs/standard-image-releases.md).
Then, for example on arm64:

```sh
agent-vm image import --input agent-vm-standard-v0.1.3-linux-arm64.oci.tar --tag my-standard:0.1.3
agent-vm --image my-standard:0.1.3 shell bash -c 'pi --version'
```

Import does not adopt a default selection. There is no automatic archive download
or fallback. A finished archive works with no Docker on PATH:

```sh
agent-vm image import --input image.tar --tag my-image:dev
agent-vm --image my-image:dev shell my-program
```

Build and import publish into the same resolved native cache launch reads,
including a persisted shared redirect or `MSB_CONFIG_PATH`. The result is not
tagged in the Docker store and may not appear in `msb image ls` until first
launch persists cached metadata.

The import publishes `--tag` **and** any names the archive itself carries —
Docker-save `RepoTags` (so `--docker SOURCE` also leaves `SOURCE` in agent-vm's
cache) and OCI `ref.name` annotations — for every image in a multi-image archive;
`--tag` names the first image. The loader commits these references one at a time.
Export/save must succeed before ingestion; if ingestion then fails, `--tag` is
restored to what it named before (or removed if new), but an archive-supplied
name may already have changed. Native blobs can remain after failed ingestion.
Rollback failure is reported with the import error. Process termination
mid-import is not covered; concurrent writers are not serialized and rollback
can revert another writer's commit.

Build prints the `--image` value to launch with on stdout. Import prints the
same sentence unless the configuration already selects exactly the reference it
just published: then there is nothing to launch differently, so it prints
nothing. When a *different* image is explicitly configured — environment, user
config or project config — import adds one line suggesting
`agent-vm image show` to see the current selection. It never prints that
selected reference, its source or its file, and a broken configuration or an
invalid override cannot fail a completed import: the selection is then unknown,
which behaves like "a different image configured" (guidance plus the hint). A
retained or recommended fallback is not a configured image, so it gets only the
launch sentence.

Errors and Docker's progress go to stderr. Usage errors from `image import` do
not echo rejected values. A printed reference is a shell word: a plain one prints
unchanged, and one holding non-ASCII or control bytes uses `$'…'` escapes that
leave the reference unchanged. Those escapes are read only by bash and zsh, so
such a notice says `(quoted for bash or zsh)`.

A registry acquisition failure for an explicit mutable tag prints an import
hint and retains the registry error chain. It does not prove the image exists
in Docker. Digests and the redacted default image get no hint; launch never
runs Docker or automatically imports.

Neither verb writes configuration, a host pin or a retained default, adopts a
default, boots a guest, installs runtime tools or triggers a launch build. Build
does not consult image selection at all. Import observes it — read-only, with
the same selector and environment rule as `image show` — once, after the native
publication succeeds, and only to decide that guidance. The observation is a
snapshot: a later config edit or launch decides what actually boots. Import
publishing a name does not approve that name's content (#391); see
[Retained default and staging boundaries](#retained-default-and-staging-boundaries).
Successful import is **not** proof of the boot image contract;
`shell`/`setup` diagnose unusable software.

Allow space for the completed staged archive under private `MSB_HOME/tmp`,
native import staging, materialized content and Docker's own builder cache.
Ordinary return paths clean only this invocation's staging; interruption may
leave staging, but never imports before exporter success.

Host builds are **not credential-shielded guest execution**: trust the
Dockerfile/context/builder. Docker inherits ordinary host environment,
credentials and stdin; agent-vm does not invoke runtime credential capture or
provisioning. Avoid sensitive build CLI values: build's ordinary clap usage
errors can echo rejected values; only import gets value-free parse errors.

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
`CURL_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS`. Client-side constraints are in
[TLS client requirements](#tls-client-requirements).

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
agent-vm image build --tag my-image:dev --builder native-oci .
agent-vm --image my-image:dev shell
```

Or push to a registry and use its reference directly with `--image`.

## Launch options

Launch options go before the tool verb: `agent-vm [launch options] <tool> [tool arguments…]`.
Every tool argument is forwarded verbatim, including `--help` and `--`.
The direct runner takes them in the same position: `agent-vm [launch options] run PROGRAM [ARG…]`,
or the equivalent `agent-vm [launch options] -- PROGRAM [ARG…]` — see
[Direct commands](#direct-commands).

> **Changed in 0.4.0:** launch options moved before the tool verb. Write
> `agent-vm --mount ~/ref pi`, not `agent-vm pi --mount ~/ref`. Old-order flags are now
> forwarded to the tool **without a warning**, so update scripts. `agent-vm <tool> --help` now
> shows the tool's help; use `agent-vm --help` for launch options and `agent-vm help <tool>`
> for examples. A `--` after the verb is forwarded too, so `agent-vm pi -- -- …` becomes
> `agent-vm pi -- …`.

Available launch options:

| flag | what |
|---|---|
| `--memory N` | VM memory GiB (default 2) |
| `--cpus N` | vCPUs (default 2) |
| `--image REF` | boot this image instead of the configured one (env `AGENT_VM_IMAGE_TAG`); see [Selecting the boot image](#selecting-the-boot-image) |
| `--no-git` | skip gh/git auth injection (still respects `--repo`) |
| `--repo OWNER/NAME` | add to the GitHub allow-list (repeatable) |
| `--allow-missing-credentials` | warn and launch when a requested YAML credential is missing or unreadable, instead of refusing — see [Authorizing a stored value for injection](#authorizing-a-stored-value-for-injection). Never covers a built-in provider's own missing host credential |
| `--mount SET\|HOST[:GUEST][:MODE]...` | a bare `SET` name selects that user-defined [mount set](#named-mount-sets-user-config), exactly and case-sensitively, and never a relative path, a directory or a tool; otherwise an extra live bind or project-scoped `:fork`. Directory binds default to writable; a regular file needs an explicit `:ro`. Modes: `:ro`, `:rw`, `:fork`, `:follow-links`, and fork-only repeatable `:exclude=REL`; see [Extra and forked mounts](#extra-and-forked-mounts). A live bind that would expose a host Pi credential file is refused — see [Host Pi credential files are never mounted](#host-pi-credential-files-are-never-mounted). Capacity is host-specific. |
| `--allow-internet-egress`, `--allow-lan`, `--allow-host`, `--allow-egress`, `--publish`, `--auto-publish` | see [Ports & egress](#ports--egress); egress is denied by default |
| `--no-config-mounts` | skip this launch's automatic [config mounts](#config-mounts-user-config) (the user config's `mounts`); an explicit `--mount`, including `--mount NAME`, credentials, persisted paths and every config check still apply |
| `--root` | run the guest as root (uid 0) instead of the default host user — see [Guest user](#guest-user----root) |

### Direct commands

Run a guest executable without a catalog entry:

```
agent-vm [launch options] run PROGRAM [ARG...]
agent-vm [launch options] -- PROGRAM [ARG...]
```

Both spellings are the same route: they execute exactly the program and argv you
write. Nothing about a same-named catalog tool is used — no command, default
`args`, `env`, credentials, network requests, transitive tools or declared
`persist`. `agent-vm [launch options] -- PROGRAM` consumes only that one
top-level separator.

Arguments are literal. No expansion, word splitting, globbing or deduplication
happens, and empty arguments are preserved:

```
agent-vm run printf '%s\n' '$HOME'   # prints the literal text $HOME
agent-vm run bash -c 'echo $HOME'    # shell syntax needs an explicit shell
agent-vm run make test -- --verbose --help   # --help belongs to make
```

`run` itself takes no options and has no help flag, so `run --help` is the
guest program `--help`; use `agent-vm help run` for the runner's help. A
non-Unicode argument is rejected with its position and never replaced; an absent
or empty PROGRAM is a usage error (status 2) before anything boots.

**Statuses.** The program's own status is passed through, including a nonzero or
reserved-looking one. The direct route adds only its own failures:

| status | meaning |
|---|---|
| 127 | the executable is absent from the effective guest `PATH` (also: a bare name that resolves to a *directory*, which `type -P` does not treat as an executable) |
| 126 | the path exists but is not executable, or a directory named by path |
| 125 | the launcher itself failed: configuration, guest setup, transport/output or cleanup |
| 2 | a pre-boot usage error (absent/empty PROGRAM, invalid UTF-8, malformed launch options) |

125 does not cover panics, aborts or signals. Sink failures count as 125: a
direct launch whose stdout/stderr cannot be written fails instead of reporting a
guest success. Shell and catalog-tool launches keep their existing best-effort
output and their existing statuses.

**What is retained.** Image selection, the project cwd, guest identity
(`--root` or the host user), mounts, the persistent HOME/state, default-deny
network authority, independent GitHub handling, bootstrap and the optional
project-root `.agent-vm.runtime.sh` hook all apply to a direct launch exactly as
to a tool. The hook runs before the executable lookup, so its `PATH` exports
affect it; a failing hook passes its status through and the program does not
run. A host executable with the same name is never run: the lookup happens in
the guest.

**What is not inherited.** No catalog entry is selected (not even the `shell`
fallback), so no catalog-declared credential capture, substitution route, bypass
configuration or `persist` link applies. Generic HOME/state furniture and
credentials the guest itself stored earlier remain — direct launches are not a
fresh-state guarantee. Image-capability furniture such as the Chrome DevTools MCP
entry in `claude.json` is retained: it belongs to the image, not to a catalog
entry.

> **Changed in 0.7.3: `run` is reserved.** A tool declared with `name = "run"`
> is refused with a rename diagnostic. Rename it (for example `run-tool`) and
> launch it by the new name, or use `agent-vm run PROGRAM` for a direct launch.

> **Slice 1.** Streamed stdin, terminal overrides (`-t`/`-T`) and signal
> forwarding are not implemented yet; see issues #399–#401. Piped input to
> `agent-vm run cat` does not reach the guest, and the PTY choice is still the
> host stdin's.

### Extra and forked mounts

`--mount` accepts either a bare [mount set](#named-mount-sets-user-config) name
(`--mount agent`) or `HOST[:GUEST][:MODE]...`. A bare name is an exact lookup in
your config's `[mount_sets]` and takes no modes; every working absolute path keeps
this grammar, `HOST` must be absolute (the shell expands `~`, so a quoted `~/ref`
is refused), `GUEST` defaults to `HOST` (a mirror at the same absolute path), and
valid mode tokens are `ro`, `rw`, `fork`, `follow-links`, and `exclude=REL`.
Contradictory tokens (`ro`+`rw`, `rw`+`follow-links`, `fork`+`ro`, `fork`+`rw`)
are parse errors.

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

### Config mounts (user config)

`~/.config/agent-vm/config.toml` can name mounts for **every** launch in every
project:

```toml
# at the top of the file, before any [table] header
mounts = ["~/reference:ro", "~/scratch:/work/scratch:rw"]
```

An entry is either a bare [mount set](#named-mount-sets-user-config) name or the
[`--mount`](#extra-and-forked-mounts) grammar — `HOST[:GUEST][:MODE]...` with the
same modes (`ro`, `rw`, `fork`, `follow-links`, fork-only `exclude=REL`), the same
guest-path rules (absolute, not `/`, no `..`, `:`, `;`, `,` or control
characters), and the same checks (host Pi credential files,
the [protected config directory](#agent-vms-config-directory-is-never-writable-from-the-guest),
core-mount collisions, the file-mount restriction, and collisions with a declared
`persist` path). Only `HOST` differs:

- `~/` is replaced by your `$HOME` **text**, exactly as an unquoted
  `--mount ~/ref` is expanded by the shell. Nothing else relative is accepted:
  `$HOME/x`, `${HOME}/x`, `~`, `~user/x`, `rel` and `./x` are rejected — there is
  no environment expansion. A `$HOME` ending in `/` therefore produces `//`,
  which is also what the shell gives you.
- The spelling is preserved, never canonicalized, because fork identity depends
  on it: `~/ref` and an equivalent absolute path name the same source only if
  they are the same bytes.
- **These mounts reach every project you launch in, including repositories you
  have not read.** Prefer `:ro` and `:fork`; a `:rw` config mount is a standing
  invitation to every future checkout. Their git remotes join the GitHub
  allow-list exactly as a `--mount`'s do, for the launch that mounts them.
- `:fork` config mounts are per project, like every fork: the copy lives in that
  project's state, and a second project seeds its own.

**Identical declarations merge; different ones are refused.** A config entry and
a `--mount`, or two config entries, that claim the same guest path are merged
when they are the same declaration (same host spelling, mode, follow policy and
fork exclusions) and rejected otherwise — naming both, for example
`guest path /work/scratch is claimed by different declarations (mounts[1] in
"/Users/you/.config/agent-vm/config.toml" and --mount); identical declarations
are merged and different ones are refused`. There is no last-wins and no CLI
override, so a repository cannot silently replace what you declared. Guest
spellings are normalized first (`/g//./x` is `/g/x`), host spellings are not, so
`~/ref` and `~/ref/` at one guest path are a refusal — the same refusal two
`--mount` arguments produce today. Parent and child guest directories remain
distinct mounts.

Selected config mounts apply to catalog tools (including the shipped ones), your
own project-defined tools, `shell`, and the [direct](#direct-commands) `run` /
`--` routes. `setup`'s verification guest ignores them, and `image refresh` boots
no guest. Project (`.agent-vm/config.toml`) and built-in configs may not declare
`mounts` at all: an empty `mounts = []` is refused there too, because mere
presence, not non-empty contents, is what asks for authority.

**The file must be trusted.** A user config that contains `mounts` — even
`mounts = []` — must pass the same verified-file policy as `[network]`: a regular
file, reached directly, with one hard link, owned by you and not
group/other-writable, in an immediate directory owned by you and not
group/other-writable. The rule is about *presence*, because the file an attacker
would plant is cheapest to plant empty. A tools/image-only symlinked config keeps
working; a symlinked, hard-linked, foreign-owned, `go-w` or dangling one that
carries `mounts` is refused with the reason and the field. See [Persisted
grants](#persisted-grants-user-config) for the exact policy and its accepted
gaps.

**A missing source is not a config error.** Load needs no mount source: a config
naming a path you have not created — or one you cannot reach — loads, `doctor`,
`--help` and `--no-config-mounts` launches all work. A *selected* declaration
with a missing source fails that launch in preflight (`canonicalizing mounts[0]
in "…" host …`, under `preparing mounts (including mounts from "…";
--no-config-mounts skips them)`) rather than being skipped silently. A preflight
refusal *about a declaration* names it as `mounts[N] in "<file>"` and escapes
the spelling it echoes, so the sentence points at the entry to edit and not only
at the file, and a newline in an entry cannot add a line to it. Two exceptions,
both because the thing refused is not a declaration: a `:follow-links`-discovered
bind is refused as `--mount "<discovered path>"` and names the entry that made it
discoverable only in its `(discovered by …)` phrase, and the fork notices
(`==> Initialized fork …`, `==> Omitted …`) escape the spelling without
repeating `mounts[N]`. A `:fork` whose copy is already READY is reused without
reading the original source, exactly as a `--mount` fork is.

**`--no-config-mounts`** skips the automatic selection for one launch:

```sh
agent-vm --no-config-mounts shell       # this launch: no config mounts
agent-vm --no-config-mounts --mount ~/x:ro shell   # --mount still applies
```

It is a launch option, so it goes before the verb ([launch options go before the
tool verb](#launch-options)): write `agent-vm --no-config-mounts shell`, not `agent-vm shell --no-config-mounts`,
because after the tool verb it is a tool argument forwarded verbatim and the
config mounts still apply. It disables the automatic selection and its
preparation only. Explicit `--mount` (including `--mount NAME`, which still
applies a [named set](#named-mount-sets-user-config)), credentials, persisted
paths, agent-vm's own project/state mounts, egress authority, and every config
check (schema, mount sets, references and cycles, file trust) are unchanged: a
broken or untrusted mount config still fails the launch, because that is a
`config::load` error and the flag cannot run before it. It is also a usage error
on a built-in verb (`agent-vm --no-config-mounts doctor`), like every other launch
option.

**Where `mounts` lands in the file matters.** TOML assigns a key to the most
recent `[table]` header, so write it **before the first one**:

| written as | result |
|---|---|
| `mounts = ["~/ref:ro"]` before any header | top-level; verified and selected |
| `[network]` then `mounts = [...]` | a network setting: refused with `[network]: mounts is not a network setting; a top-level mounts list must be written before the first table header` |
| `[[tools]]` … then `mounts = [...]` | a tool field: the fixed schema-repair paragraph, with the line and column and the same "write it before the first table header" sentence |
| `[mounts]` (table form) | top-level and present, so verified, then `mounts: must be an array of strings` |
| `[tools.env]` with `mounts = "~/private:ro"` | a legitimate **environment variable** named `mounts`; no mount is selected and no authority is asked for |
| `[mount_sets]` then `mounts = [...]` | a **set named `mounts`** with one declaration, not the defaults list: `mounts` is a valid set name and is not reserved. Only the position decides |
| `[mount_sets.foo]` (nested table) | refused: a set's value must be an array of declarations or set names |
| `mount_sets = []` or any non-table | `mount_sets: must be a table of named arrays of mount declarations` |

A launch that selected config mounts prints one line, naming the file and how
many declarations it contributed:

```text
==> Config mounts: 2 from "/Users/you/.config/agent-vm/config.toml"
==> Config mounts: skipped 2 from "/Users/you/.config/agent-vm/config.toml" (--no-config-mounts)
```

Expect no such line when the list is empty or absent, or when a skipped list was
empty: there is nothing to report.

> **Added in 0.7.4.** ADR-0046 records why the file-trust rule, the merge rule
> and the preflight order are what they are. Named mount sets arrived in 0.7.13
> (below); per-tool mount fields are still deliberately deferred.

### Named mount sets (user config)

A **mount set** is a named list of mount declarations in the same user config.
Declaring one mounts nothing — only the defaults list or an explicit `--mount`
selects it — and a set may name other sets:

```toml
# at the top of the file, before any [table] header
mounts = ["agent"]           # optional automatic selection

[mount_sets]
agent = [
  "~/.agents/skills:ro",
  "~/.agents",
  "~/.config/github-app:ro",
]
pi-agent = ["agent", "~/.pi:fork"]
empty = []
```

```sh
agent-vm --mount agent shell
agent-vm --no-config-mounts --mount pi-agent shell
```

The first selects that set for one launch. The second suppresses the automatic
`mounts` list and still selects `pi-agent` explicitly — `--no-config-mounts`
removes the defaults, never your own command line. Both are launch options, so
they go **before** the verb. Neither changes credential provisioning or your
persisted paths.

**Names.** A set name is case-sensitive ASCII: `[A-Za-z0-9_]` first, then
`[A-Za-z0-9_.-]`. So `agent`, `pi-agent`, `_local`, `a.b` and `A` are names, and
`A` differs from `a`. `agent:ro`, `-agent`, `--mount`, `../x`, `./x`, `~x`,
`a/b`, `a b` and any non-ASCII spelling are not. Tool, route and command words are
not reserved: a set may be called `pi` or `shell`, and `--mount pi` selects the
set and never a tool. There is no implicit `agent` set and no inference from tool
names.

**`--mount` and config entries share one classification.** A host segment
starting with `/` or `~/` is a path and keeps the whole `HOST[:GUEST][:MODE]...`
grammar, so every absolute `--mount` that works today still works and is never
reclassified. A valid bare name is an exact set lookup: no case folding, no
trimming, no cwd-relative path, no directory discovery and no tool fallback, so a
directory named `agent` in your project changes nothing. Anything else goes to the
path grammar and is refused as it always was (`./x`, `~x`, `$X`, `a b`). A name
with any `:` — `agent:ro`, `agent:fork`, `agent:/guest`, `agent:exclude=x` — is
refused: a set reference is a bare name, and modes, guest paths and exclusions
belong to the path declarations *inside* the set.

**Everything is validated at load, whether or not anything selects it.** Unknown
names, an invalid definition and a set-reference cycle are config errors, in an
unused set and under `--no-config-mounts` too. A set whose own transitive closure
claims one guest path twice with *different* declarations is a config error as
well; two separately valid sets may still disagree at one guest path, and that
fails only when a launch selects both. `tools` reference cycles stay legal — they
are a different graph reaching a fixed point.

The closure walk is bounded so a crafted file cannot hang config load: it spends
at most **65,536 leaf visits** across every declared set's closure. Past that the
load fails with `mount_sets: expansion work exceeds limit of 65536 leaf visits`,
under `--no-config-mounts` and in `doctor` too. Hundreds of ordinary small sets
are far below it; the fix for the message is to compose fewer sets per closure,
not to opt out, because load validation runs regardless.

**Declarations are inert; selection is what mounts.** A `[mount_sets]` table (an
empty one included) and an empty set select nothing, and a sets-only file prints
no `==> Config mounts:` line. Repeated paths, a set named twice and a shared
nested set all deduplicate to one bind per declaration. Differing declarations at
one guest path are refused in every combination — default versus set, set versus
set, and `--mount` versus a selected set, in either order — with both declared
sites named and no override. Guest spellings are normalized first, host spellings
are not, precisely as for direct entries.

**Host paths and identity are unchanged.** Inside a set, `~/` expands by
concatenation onto your host `$HOME` text (not the guest's, and not the config
file's directory); guest destinations stay absolute; there is no environment or
other relative expansion. The expanded spelling is preserved, so fork identity is
unchanged: moving the same declaration between `--mount`, the defaults list and a
named or nested set reuses the same project-scoped fork, and no set name, nesting,
config origin or traversal order can reseed it.

**Modes and protections belong to the leaves.** There are no per-set mode
overrides and no new mount modes; each path declaration carries its own `:ro`,
`:rw`, `:fork`, `:follow-links` and `:exclude=REL`, and the same protections
apply (host Pi credential files, the [protected config
directory](#agent-vms-config-directory-is-never-writable-from-the-guest), core
guest paths, the file-mount restriction, `persist` collisions). A read-only child
under a writable parent is allowed, and it does **not** prove the guest has no
writable alias to that child through the parent.

**Source existence is a launch-time question.** An unused set may name a path
that does not exist — its source is never stat'd, opened or canonicalized at load
— so it cannot block an unrelated launch. Selecting it fails that launch in
preflight, naming `mount_sets["NAME"][I] in "<file>"`, unless an already
initialized `:fork` copy is reusable. A sets-only config is authority-bearing
exactly like one with `mounts`, and is refused from the project and built-in
tiers: a project cannot declare sets and cannot select a user name.

> **Added in 0.7.13.** ADR-0048 is the accepted design for named sets,
> [ADR-0046](docs/adr/0046-verified-user-config-mounts.md) the verified-file rule
> they inherit. Tool-level `mounts` and tier-local tool mount inheritance remain
> unimplemented.

### agent-vm's config directory is never writable from the guest

`~/.config/agent-vm` holds `credentials.yaml`, which authorizes launch secrets,
and `config.toml` `[network]`, which authorizes egress.
A guest must not be able to plant authority for a later launch. Every launch
refuses writable project, state, guest-home and extra binds that contain or
alias this directory, or a directory its lookup searches, even if no authority
file exists yet. Both raw `$HOME` and the account home are measured.

Missing state/home sources are checked too: future names compare ignoring ASCII
case, and names outside `[A-Za-z0-9._-]` or ending in `.` may match any name,
a conservative rule that can refuse safe layouts. The state root is always
absolute: a relative `AGENT_VM_STATE_DIR` is refused, and a relative
`XDG_STATE_HOME` is ignored with a note (see
[Recovering from a forward-migrated microsandbox db](#recovering-from-a-forward-migrated-microsandbox-db)).

`ro` and `:fork` are fine under this guard; a bind strictly inside the directory
is also allowed. Pi's separate policy still applies. **0.3.0 breaks launching
from `$HOME` for everyone**, not just Pi users. Run from a project directory,
mount read-only or a narrower source, or relocate `AGENT_VM_STATE_DIR` when
state or guest home exposes authority. Forking a broad home copies everything,
so prefer a narrower source.

Every launch also refuses a regular `config.toml` with more than one hard link
(or any link count other than one), even without network settings. Remove the
other links or replace it with a copy. Non-launch verbs still work.
`credentials.yaml` hard links remain #319; runtime races and nested mount
aliases remain #322/#321. See [ADR-0038](docs/adr/0038-config-dir-exposure-guard.md)
for the trusted boundary and accepted gaps.

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

When `~/.pi` does not exist, none of the **Pi** refusals apply (the config-directory guard above still applies): there is nothing to
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

Tool arguments go to the tool verbatim: `agent-vm claude -p "say hi"`;
the shell tool runs its arguments as one command: `agent-vm shell cargo test`.

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

After host agent credentials, a `==> credential store` section reports exactly
one status row before the tool configuration:

```text
credential store: not probed (0 tracked names)
credential store: reachable
credential store: unavailable (<fixed failure advice>)
credential store: not probed (inventory unavailable)
```

The first row means the validated names-only inventory is empty or absent: no
native lookup runs, and store health remains unknown. Otherwise doctor makes one
reserved-account lookup, regardless of the number of tracked names, without
reading user credentials, taking an inventory lock or creating files. A pending
read emits one warning after about 2s and is abandoned after about 5s, even on a
terminal (plus scheduler/output overhead). Reachable does **not** mean writable,
unlocked, or that every item is accessible. An inventory error adds an escaped
recovery diagnostic. See [ADR-0024](docs/adr/0024-host-secret-inventory.md#amendment-credential-store-diagnostics-agent-vm-379)
for the store boundary and platform limitations.

The reserved account is never written by agent-vm and cannot be selected through
`ServiceName`; it is not an OS-enforced reservation against other programs or
manual keychain editing. Under normal successful searches its absence becomes
NoEntry/Absent. Native setup/search failures, including a missing Linux default
collection, remain classified failures rather than being forced to Reachable.
A lookup may prompt or fail before absence can be established. On macOS an
externally created matching reserved item could have its bytes read and discarded
inside keyring; no secret bytes cross the adapter. Neither a no-prompt guarantee
nor a universal absent-account NoEntry guarantee is made.

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
this launch`. This launch-authorization view reads the authorization file only —
**not** the credential store — so that view never prompts and never writes; whether
a value is actually stored
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
Pi files, plus the names-only secret inventory and optional bounded native
credential-store check above. Ordinary `doctor` also performs **no** initialization
at all — it is dispatched before microsandbox bootstrap, so it works even when the bundled `msb`
is missing or unpatched, and it reports the computed paths rather than validating
that binary. The explicit `agent-vm doctor --reset-msb-db` is the mutating
exception and keeps its existing behaviour.

Ordinary doctor exits nonzero for inventory discovery/load errors or credential-store
availability failures, after printing the complete report when `MSB_HOME` can be
computed. An absent inventory is a successful not-probed result. An uncomputable
`MSB_HOME` still fails early. Configuration, boot-image and invalid-image-environment
errors retain precedence over store health failures; output I/O failures take
precedence over deferred diagnostics. Reset skips inventory discovery/loading and
native availability entirely, even with broken configuration or inventory.

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

`[network]` authority and `mounts` are user-tier only, from a verified file. The
project tier refuses both. See [Persisted grants](#persisted-grants-user-config)
and [Config mounts](#config-mounts-user-config).

```toml
# Top-level, optional: the boot image for every session (an OCI reference).
image = "ghcr.io/gregwebs/agent-vm-standard:v0.1.3"

# Optional, USER CONFIG ONLY, and it must come before the first table header:
# mounts = ["~/reference:ro", "~/scratch:/work/scratch:rw"]

# Optional, USER CONFIG ONLY (never put this in project config):
# [network]
# allow_internet_egress = false
# allow_lan = true
# allow_host = false
# allow_egress = ["10.0.0.5", "api.example.com"]

[[tools]]
name = "mytool"                      # required; the `agent-vm <name>` verb
command = "mytool"                   # required; the guest command name
args = ["--flag"]                    # optional; default argv (array of strings)
credentials = ["openai"]             # optional; credential provider names
tools = ["claude"]                   # optional; tools to provision (same file, or name one)
persist = [".cache/mytool"]          # optional; guest-HOME-relative, kept under <state>/persist/
env = { VAR = "value" }              # optional; guest env pairs for this tool
interactive_shell = false            # optional; join tool arguments into `-c`
network_requests = ["api.example.com"] # optional; destinations the tool expects (never grants access)
```

- `image` — optional top-level; an OCI image reference selecting the **boot
  image** for every session (see
  [Selecting the boot image](#selecting-the-boot-image)). It is independent of
  the tools: a file that sets only `image` declares zero tools and keeps the
  shipped defaults. Only OCI references are accepted here; a local path is
  rejected (use `--image` for a local rootfs).
- `mounts` — optional top-level array of strings, **user config only** and only
  before the first `[table]` header: config mounts for every launch, with
  `--mount`'s `HOST[:GUEST][:MODE]...` grammar. The project and built-in tiers
  refuse the key even when it is empty. See
  [Config mounts](#config-mounts-user-config).
- `name` — required; a single command-name token: nonempty, no
  whitespace/control characters, no `/` (a name is not a path), not an
  all-dots spelling (`.`/`..`), no leading `-`, and not one of the reserved
  subcommands `image`, `setup`, `msb`, `clipboard`, `doctor`, `secret`,
  `_intercept-hook`, `run`, `help`. Names are case-sensitive. Naming a tool `claude`
  is normal — that is the point. `pull` and `upgrade` are no longer reserved
  (they were removed as built-ins in 0.7.0), so a configured tool may use them.
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
  rather than failing the launch. Every reference — an explicit name or the
  single entry `"*"` — resolves inside the **same configuration file** as the
  declaring tool (its *tool reference scope*), including definitions another
  file hides from the verb list. `"*"` must be the only entry; multiple explicit
  names are allowed. `*` is not a legal tool `name`. A name declared only in the
  *other* tier is a hard error, never an opt-in to crossing files. The
  synthesized `shell` fallback is not a declaration in any file, so
  `tools = ["shell"]` needs a local `shell`.
  **Omitted means `["*"]` for a tool named `shell` and `[]` for every other
  name** — write `tools = []` explicitly to give a `shell` no provisioning at
  all. `opencode-static` only produces a working sign-in when `openai` is also
  provisioned. See
  [Tool references are local to their file](#tool-references-are-local-to-their-file).
- `persist` — optional; guest-`$HOME`-relative paths to keep across runs.
  Each path is symlinked into the project state dir under `<state>/persist/`,
  so the real file lives next to the rest of the project state (`agent-vm
  doctor` prints the state dir) — one place to find and back it up. Absolute
  paths, any `..` component, NUL, and root-equivalent spellings (`.`/`./`/empty)
  are rejected; harmless `.`/`//`/trailing-`/` spellings are normalized. Two
  paths that **overlap** — equal, or one a component-wise ancestor of the other
  — are a hard error in each of these comparisons: the entries of one tool; the
  paths of every definition that wins a launch verb, even two that no single
  launch links together (the whole-catalog check `load` has always made, so a
  broken catalog never loads); the definitions one launch actually links — each
  winning root's resolved `tools` closure, hidden definitions included, which is
  what catches a conflict with a definition the verb list hides; and a path
  against one of the dotfiles agent-vm itself links into the state dir (the
  credential/config links `agent-vm doctor` lists, e.g. `.claude`, `.config/gh`,
  `.pi`), where one would silently shadow the other. A hidden definition's paths
  are **not** compared against every other retained definition, and a closure no
  winning root reaches is never checked: those definitions never link together
  in one launch, so two tiers' mutually exclusive closures stay legal. `.cache`
  and `.cachex` do **not** overlap (components, not string prefixes). Which
  paths a launch gets follows the same `tools` closure as its credentials, so a
  `shell` (whose omitted `tools` is `["*"]`) sees every declared path in its own
  file. A `persist` path that would collide with the
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
  user's tool arguments are joined (and shell-escaped) into a single `bash -c`
  command line instead of being appended as separate argv entries. The shipped
  `shell` tool sets it.

- `network_requests` — optional array in either tier, using the
  [hostname allowance grammar](#hostname-allowance-grammar). Bare names mean
  port 443; IP/CIDR entries are refused. At most 64 declared entries per tool;
  names are canonicalized, deduplicated and sorted. This is a declaration only:
  it never authorizes a lookup or connection, never provisions a credential or
  tool, and is not inherited through `tools`. Launches and `doctor` print these
  values (`doctor` lists up to 8): public metadata must not contain secrets.

Unknown keys, wrong types, malformed TOML, unknown
provider names, duplicate tool names within one file, and **overlapping**
`persist` entries (equal or one an ancestor of the other, in exactly the
comparisons the `persist` entry above lists) are
all **hard errors** — as are invalid `tools` entries: `"*"`
mixed with other entries, an empty or NUL-containing name, and a tool name no
definition in that same configuration file provides (including a name only the
other tier, or only the shipped catalog, declares), and a tool named `*`. They
are also hard errors for
invalid `env` entries: a key that is empty, or contains
`=`/NUL/whitespace/control characters, or starts with `MSB_`, or is
`HOME`/`USER`/`LOGNAME`, and an `env` **value** containing NUL. There is no
silent fallback to the defaults. Invalid `network_requests` entries and more
than 64 declared entries are also hard errors.

### Merge order and defaults

The user file is authoritative for any tool name it contains; the project
file may add whole tool definitions the user did not write. This is a union
of whole definitions, **not** a field-by-field overlay: a repo cannot fill in
an omitted `persist`, `credentials`, or `tools` on a user-defined tool.
A project cannot add requests to a user-declared tool: a differing list is a
`network_requests` conflict, and the user definition wins.
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

### Tool references are local to their file

A `tools` reference resolves in the **file that declares the tool**, not in the
merged verb list. This is the guarantee that keeps a repository from activating
your credentials: naming a tool in a project config cannot pull in a tool your
user config owns.

Two consequences are worth knowing, because they are hard errors rather than
degraded behaviour:

- **A name only the other file declares is refused.** With `pi` in your user
  config, a project tool that says `tools = ["pi"]` fails. The error names the
  tier, the declaring file, the declaration index, the tool and the field
  (`tools[0]`). Declaring any tools also replaces the shipped catalog, so
  naming a shipped agent such as `claude` from a custom catalog is the same
  error.
- **Every definition's references are validated, including one no verb reaches.**
  A project `pi` that loses its name to your user `pi` is not a verb, but its own
  `tools` list must still resolve locally. Shadowing a broken definition is not a
  way to ignore it.

A definition that *is* declared locally still supplies its own provisioning even
when it loses the verb: with a user `pi` and a project `pi`, `agent-vm pi` runs
yours while a project `helper` that names `pi` gets the project `pi`'s
credentials and persisted paths. The same holds transitively and for `"*"`, and
a reference cycle is a fixed point rather than an error.

Migration, per file that fails:

```toml
# Before — the project relied on the user config's `pi`.
[[tools]]
name = "helper"
command = "helper"
tools = ["pi"]

# After — declare the tool (and its own `tools` references) in this file.
[[tools]]
name = "pi"
command = "pi"
credentials = ["anthropic"]

[[tools]]
name = "helper"
command = "helper"
tools = ["pi"]
```

Copy the definition you need rather than trimming it: `tools = []` drops the
credentials and persisted paths the reference was there for. Nothing is merged
field-by-field, and a name both files declare is still a whole-definition
conflict — one `doctor` warning, and the user definition keeps the verb — while
the project's own tools now resolve to the project copy.

The same rule applies to the synthesized `shell` fallback: it is a launch
affordance, not a declaration in your file, so `tools = ["shell"]` needs a local
`[[tools]] name = "shell"` or that edge removed. A *declared* `shell` with an
omitted `tools` still defaults to `"*"` over its own file.

### The `shell` fallback

When the resolved catalog declares no tool named `shell`, the built-in `shell`
(from [`crates/agent-vm/src/default-tools.toml`](crates/agent-vm/src/default-tools.toml))
is appended, so a config that omits — or typos — `shell` never leaves you
without a way into the guest. It is **conditional**: a config that *declares*
`shell` (even as `zsh`) keeps its own definition, and the fallback does not
fire on an unparseable config (see *Errors and recovery*). `doctor` labels the
row with a note when the fallback is in use.

Under a custom catalog the fallback provisions **nothing**: no credential
provider, no requested credential name, no `persist` path, and no shipped agent
restored. It is resolved from a scope holding only that one shipped `shell`
definition, so its omitted `tools` reaches itself alone — unlike a *declared*
`shell`, whose `"*"` covers its own file. It is also not an explicit-reference
target (see
[Tool references are local to their file](#tool-references-are-local-to-their-file)).

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
simply Pi's own flag, forwarded untouched. A literal `--` after the verb reaches Pi
unchanged. `pi <subcommand>` (`pi list`,
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

**The `agent-vm-codex` provider — pending image delivery.** PR B changes the
launcher, not the image: the pinned v0.1.3 standard image lacks this provider,
its wrapper activation and the registry-gated host-import warning clause.
[ADR-0044](docs/adr/0044-pi-reaches-host-codex-through-an-image-owned-provider.md)
defines PR A's contract for images carrying it: a small agent-vm-owned
extension, `/opt/agent-vm/pi-extensions/agent-vm-codex.js`, loaded by the same
wrapper. On such an image, when the project's guest
`/agent-vm-state/codex/auth.json` holds agent-vm's exact placeholder **and** your host has a `codex login`, it registers
an `agent-vm-codex` provider, so `/model` offers `agent-vm-codex/<id>` — Pi's own
`openai-codex` model ids — with no in-guest sign-in. Requests carry the guest
placeholder, and the proxy substitutes your host subscription token on
`chatgpt.com`; a refresh stays host-side on `auth.openai.com`. See
[ADR-0044](docs/adr/0044-pi-reaches-host-codex-through-an-image-owned-provider.md).
Three things to know:

- **It is a distinct provider, not Pi's own `openai-codex`.** An in-guest
  `/login openai-codex` therefore writes a different entry and is never
  shadowed — but see *Credential-free agents* below for why that login cannot
  complete once the host has a Codex login.
- **SSE only.** The extension forces Pi's SSE transport for this provider, so
  the WebSocket session reuse Pi otherwise negotiates under `transport: auto` is
  not used here.
- **A failed refresh says so.** If the host cannot refresh its login, the turn
  fails with a message asking you to run `codex login` on the **host**, then
  start a new turn. It carries no status, code or reply body, and Pi's session
  retry does not restart it.

Your **image** has to carry this extension. The shipped v0.1.3 standard image
predates it, and the image version that ships it is **pending publication** —
check the image's release notes, or `ls /opt/agent-vm/pi-extensions/` in the
guest. On an image without it the placeholder is still written and nothing
reads it, so `agent-vm-codex/*` is simply absent from `/model`. On an image
carrying A, its warning change uses the same registration gate: the host-import
sentence appears only when this provider registered. The current pin has no
such sentence or gate.

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

A `[network]` table is refused in the project tier with the file, setting and
tier named; in the user tier it is verified (see [Persisted grants](#persisted-grants-user-config)).

A config parse/validation error fails any launch verb with *that* error — never
clap's "unrecognized subcommand". Ordinary `agent-vm doctor` still exits
nonzero, but the failure is rendered inside the `==> tool configuration`
section, naming the file — and, for a tool declaration, its tier and index (a
syntax error gives a line/column instead) — so the sections that do not depend
on the config still print: a repo-supplied config cannot hide them. `agent-vm
--help` still exits 0
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
reversible: the command prints the instruction that puts it back. That
instruction is one line even when the path holds a control byte, and it names
the bytes the filesystem actually holds (not the escaped spelling the
`from:`/`to:` lines show). It is a guard, not a bare `mv`: if a launch has
recreated `db/` in the meantime, it refuses — naming both paths on stderr, with
a nonzero exit — because moving the backup then would nest it inside the new
database instead of restoring anything. Move the current `db/` aside and paste
it again, or keep the new database. A path that needs no quoting prints as
itself, so no shell reinterprets it; one that needs `$'…'` is read only by bash
or zsh, so the report prints `(quoted for bash or zsh)` on the next line. That
note is about the words: the command itself is POSIX shell syntax, so run it
with `sh`, bash or zsh, not fish. Interactive Bash with history expansion on is
the one exception: if the path contains `!`, enter `set +H` on
an earlier line first, or paste into zsh instead. The command resolves
`MSB_HOME` the same way `agent-vm` itself does, so it only ever touches
agent-vm's private state, never a separate `~/.microsandbox` install. The instruction names absolute paths, so it works
from any directory. The state root itself is absolute by rule: a relative
`AGENT_VM_STATE_DIR` is refused before anything moves, and a relative
`XDG_STATE_HOME` is ignored (as the XDG spec asks) with a note on stderr naming
the root actually used. If no `db/` exists, it prints a no-op message and exits
0.

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
entry removed. Build and select such an image with ordinary Docker (see the
agent-vm-images
[`chrome-devtools` example](https://github.com/gregwebs/agent-vm-images/tree/main/examples/layers/chrome-devtools)
for a Dockerfile that installs it `FROM` the default boot image).
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
  agent-vm --auto-publish dsh --yes
  ```

  Anthropic and OpenAI support needs no extra plugin: the harness mounts its
  built-in `llm-pi-ai` multi-provider adapter dormant, so pick the provider in
  the Models UI and store its key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or
  `DEEPSEEK_API_KEY` for the default DeepSeek provider). Community plugins are
  not baked into the image; add one in the guest with
  `dsh plugin --profile web add <package>` (pnpm is installed).

"Declares no `credentials`" is not the whole story for `pi`, though: it also
declares `tools = ["claude", "codex"]`, so a `pi` launch **provisions** the
Anthropic and OpenAI credentials **without requiring** either
([ADR-0017](docs/adr/0017-tool-declared-provisioning.md) alternative 2). The
first edge is what makes the shipped `claude-bridge` provider work with no
in-guest login: `agent-vm pi` writes the Anthropic placeholder into the
project's `~/.claude/.credentials.json` and registers the proxy substitution, so
the Claude Code child the bridge spawns reaches Anthropic with your **host**
credential. The second writes `/agent-vm-state/codex/auth.json`, which the
`agent-vm-codex` provider carries to `chatgpt.com` on an image carrying PR A
([ADR-0044](docs/adr/0044-pi-reaches-host-codex-through-an-image-owned-provider.md)).
Six consequences are worth knowing:

- **Host API keys are not forwarded.** agent-vm does not publish host
  `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` into the guest (#163). To use an exported
  key, authorize it with `source: env` (see
  [Authorizing a stored value for injection](#authorizing-a-stored-value-for-injection)).
- **An in-guest `claude login` cannot complete once the host has a credential.**
  The launch registers the `POST platform.claude.com/v1/oauth/token` intercept
  route, and the hook answers token *refresh* grants only: an authorization-code
  exchange is rejected and Claude Code reports a bare `OAuth error … status code
  400`. With **no** host credential nothing is registered, so `claude login`
  works — that is exactly the case where you would want it.
- **An in-guest `pi` `/login openai-codex` cannot complete, and an existing
  guest `openai-codex` login cannot refresh, once the host has a Codex login.**
  The same rule, one provider over: the `POST auth.openai.com/oauth/token`
  intercept route answers placeholder refresh grants only, so an
  authorization-code exchange (403) and a real refresh token both fail. The
  mirror of the `claude login` bullet above, with the same shape: with **no**
  host Codex login, nothing is registered and `openai-codex` works normally.
  Workarounds: use the host-backed `agent-vm-codex/*` provider (which needs an
  image carrying that extension), or launch from a host with no Codex login.
- **A host Codex login overwrites a credential at `/agent-vm-state/codex/auth.json`.**
  Successful capture replaces tokens stored there, for example by a prior
  `agent-vm codex`/`shell` launch or an explicit `CODEX_HOME`, with agent-vm's
  placeholder. Pi inherits neither `CODEX_HOME` nor a guest-HOME `.codex` link;
  this does not overwrite an arbitrary HOME-relative in-Pi `codex login`.
  With no host Codex login the file is left byte-for-byte alone.
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
  declares `tools = ["claude", "codex"]`, which provisions Anthropic through
  Claude Code's credential and OpenAI through Codex's. A custom catalog that
  copies that declaration must also resolve `claude` and `codex` tools (or their
  `credentials` requirements); otherwise the declaration fails on a
  **dangling-tool error**, which is a *config* problem, not an image one. Merely
  having either installed in the image does **not** synthesize the catalog entry
  or its provisioning edges — drop the reference or declare the credential
  requirement directly if the catalog deliberately omits one.

**A launcher release newer than your image.** The `pi` provisioning edge above
is applied by the **launcher**, so it takes effect on any image, while the
`agent-vm-codex` provider only exists on an image that carries the extension.
Until you adopt such an image — retained images stay put until you choose a new
one ([ADR-0035](docs/adr/0035-consume-user-owned-boot-images.md)) — a `pi` launch
from a host with a Codex login still installs the `auth.openai.com` intercept
route and still writes the guest `codex/auth.json` placeholder. No token byte
reaches the guest, but the two consequences above (blocked in-guest
`openai-codex`, overwritten guest Codex state) apply **without** offering the
`agent-vm-codex/*` workaround. The workaround arrives with the image, not with
the launcher.

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
  or no Secret Service running), including a read agent-vm abandoned because the
  platform call never returned — see the macOS keychain prompt note below.
  Lock contention is a command-level error: `secret ls` exits non-zero with no
  rows, not an `unavailable:` row, even when the inventory is empty (agent-vm #291).
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
- **No secret-store fallback, ever.** If the platform credential store is
  unavailable, the operation fails with a classified message. agent-vm never writes a value to a
  plaintext file, and never degrades to an environment variable. An environment
  source exists only when an authorization explicitly selects it.

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

#### Reading the value from a host environment variable (`source: env`)

Prefer keychain storage. For workflows that need an exported key, authorize the
host variable explicitly in `~/.config/agent-vm/credentials.yaml`:

```yaml
credentials:
  - service: openai
    source: env
    apiKey:
      name: OPENAI_API_KEY
      sentinelEnv: true
      inject: [{domain: api.openai.com, scheme: bearer}]
```

The host and guest variable names match. For a launch, a requested, authorized
env source's value is captured once before any child of that launch is spawned
and removed from agent-vm's environment, so the launch's `msb`, `git` and `gh`
children do not inherit it. Verbs that select no credentials — `agent-vm msb
<verb>` and `agent-vm setup` — do not remove it, so this is a per-launch
guarantee, not a scrub of every process. The parent shell
keeps its variable. Set-but-empty means unset; rotation takes effect on the next
launch. There is no keychain fallback. Names agent-vm reads as its own
configuration (`AGENT_VM_*`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`) are refused
because removing them would change launcher configuration. Same-uid inspection
of the launcher, including Linux `/proc/<pid>/environ`'s initial environment
block, is out of scope ([ADR-0025](docs/adr/0025-yaml-credential-shielding.md)).

**Migration since 0.3.9:** an exported `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` is no
longer copied into the guest. To use them through shielding:

```yaml
credentials:
  - service: anthropic
    source: env
    apiKey:
      name: ANTHROPIC_API_KEY
      sentinelEnv: true
      inject: [{domain: api.anthropic.com, header: x-api-key, format: "%s"}]
  - service: openai
    source: env
    apiKey:
      name: OPENAI_API_KEY
      sentinelEnv: true
      inject: [{domain: api.openai.com, scheme: bearer}]
```

A same-named entry replaces the built-in's credential handling; see the
replacement table below. Egress must still allow the origin.

For the keychain example above, request `my-service` in a user or project
`config.toml` (an env source is requested the same way, by service name):

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
- **Authorization does not grant egress.** Egress is denied by default; an
  authorized origin also needs `--allow-internet-egress` (or a numeric allowance).
  A denied destination never reaches injection.
- **Rotation is launch-scoped.** A value rotated with `agent-vm secret set`
  while a sandbox runs is *not* picked up; the next launch uses the new value.
- **Malformed authorization fails closed.** An unreadable, foreign-owned,
  group/other-writable, symlinked or malformed `credentials.yaml` refuses a
  launch that requests a credential, with a message naming the file but never
  its contents. A launch that requests nothing is unaffected.
- **Names owned by an authorization win.** If `apiKey.name` is
  `OPENAI_API_KEY`, agent-vm suppresses any provider-forwarded variable of the
  same name and refuses a tool-declared `env` key of the same name. Names agent-vm itself must
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
- **`--allow-missing-credentials` (host-only).** A per-launch flag that warns
  and continues instead of refusing when a requested `credentials = [...]` name
  has no authorization, and when an authorized `required: true` credential's
  value cannot be read, or its `source: env` variable is unset or empty. The
  guest gets neither the credential nor a fallback, so the in-guest tool may still fail its own sign-in. It cannot bypass a malformed,
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
  reports whether a keychain value is stored. Env rows name the host variable;
  doctor never reads its value or presence. See
  [Checking what agent-vm can see](#checking-what-agent-vm-can-see).
- **Unsupported, by name, never silently ignored.** `source` values other than
  `env`, `apiKey.env`, `permissions`/`permissions.network`, `oauth`, `basic`,
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

If the prompt is never answered — a locked keychain with nobody at the GUI, a
launch from a script — agent-vm **abandons the read** instead of waiting
indefinitely, and reports the same "could not be read" class (a tight bound when
stdin is not a TTY, a generous one when it is; the values live with the store in
`crates/agent-vm/src/secret_store.rs`). A read that is still unanswered after a
couple of seconds says so first: one `warning:` line on stderr, naming the
service, so a launch waiting on a prompt you can answer does not look hung.
An unattended `secret ls` reports this as an `unavailable:` row rather than
hanging on that read, and the inventory lock it holds is released (agent-vm #251).

Every `secret` verb, and every launch that reads a stored value, first takes
`~/.config/agent-vm/.secret-inventory.lock`. A `secret set` or `secret rm` keeps
it while the keychain decides — including while an unlock prompt is up — because
an abandoned write could still land after agent-vm reported it failed. Any other
agent-vm process that needs the lock meanwhile waits the same bound and then
gives up: a `secret` verb fails naming the lock file and changes nothing; a
launch reports the credential as could-not-be-read (agent-vm #291). A wait that
is still contended after a couple of seconds says so **while it waits**: one
`warning:` line on stderr naming the lock file and the total wait, because a
command queued behind someone else's prompt otherwise looks hung (agent-vm
#377). That line is not a failure — the same wait continues to its limit, so the
command can still succeed if the holder finishes first. At the
pre-boot check, an optional credential is withheld; a required credential refuses
the launch unless `--allow-missing-credentials` was passed. A failure on the
later spawn-time read refuses the launch, even if the credential was originally
optional. Answer the prompt or let the other command finish, then retry. Use
lsof to inspect processes with the lock file open; that alone does not identify
its holder.

## Project hook
If the project root contains an executable `.agent-vm.runtime.sh`,
the launcher sources it inside the guest before exec'ing the agent or a
[direct command](#direct-commands). Use for `npm install`, env exports,
dev-server startup. Non-zero exit aborts the launch and the program does not
run. Its exports affect the effective `PATH`, so a hook can add a project bin
directory that a direct launch then resolves.

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
`~/.local/state/agent-vm`), applying the launcher's rule: a relative
`AGENT_VM_STATE_DIR` is refused and a relative `XDG_STATE_HOME` is ignored. A
directory whose path contains a comma is skipped with a warning —
`CLAUDE_CONFIG_DIR` is comma-separated with no way to escape one.

## Ports & egress

Tool-launch guest egress is **denied by default**, including DNS query authorization.
Before **0.2.0**, the guest reached the public internet by default; agents that
call provider APIs now need `--allow-internet-egress`, or a TLS hostname
allowance (`--allow-egress api.example.com`) narrower than the whole internet.
Grants compose independently. CLI grants apply only to this launch; persisted
grants come from the user config.
The temporary guest booted by `setup` for verification still uses the SDK
public-internet and DNS default; this launch policy does not cover it. `setup`
runs each
configured tool's declared `command --version` from a project-selectable image.
These guests have no project mounts or secrets.

| flag | what it opens | guest-side address |
|---|---|---|
| `--allow-internet-egress[=BOOL]` | public internet plus DNS queries | public addresses |
| `--allow-lan[=BOOL]` | Private group: 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7 | LAN IP |
| `--allow-host[=BOOL]` | sandbox gateway, rewritten to host loopback; includes the host resolver | `host.microsandbox.internal:<port>` |
| `--allow-egress SPEC` (repeatable) | one numeric IP/CIDR, optionally protocol/port-scoped, **or** one hostname (TLS only) | dial by IP or TLS SNI |
| `--publish HOST:GUEST[/proto]` | host port → guest port (`tcp` default; `/udp` for UDP); **never opens egress** | inbound to guest |
| `--auto-publish` | mirrors guest wildcard/loopback listeners to host loopback | host `127.0.0.1:<guest-port>` |

Each Boolean flag without a value means true; `--allow-internet-egress=false`,
`--allow-lan=false` and `--allow-host=false` grant nothing for that group.
Explicit `=false` overrides a saved true for that group.
LAN and host never imply public internet access. Guest loopback, link-local
and cloud metadata are not part of the LAN grant. Prefer the narrowest grant:
every process in the guest receives the authority you open.

### Persisted grants (user config)

Only `~/.config/agent-vm/config.toml` can carry persisted grants:

```toml
[network]
allow_lan = true
allow_egress = ["10.0.0.5", "api.example.com"]
```

| Launch options | internet | LAN | host | allowances |
|---|---|---|---|---|
| none | false | true (persisted grant) | false | `10.0.0.5/32`, TLS `api.example.com` (persisted grants) |
| `--allow-lan=false` | false | false (CLI) | false | same persisted allowances |
| `--allow-internet-egress --allow-egress 10.0.0.5/32 --allow-egress 192.168.1.0/24` | true (CLI) | true (persisted grant) | false | one `10.0.0.5/32` (both sources), TLS `api.example.com` (persisted grants), `192.168.1.0/24` (CLI) |

Each Boolean is CLI → persisted grant → false. Allowances are the persisted-first
canonical union; flags never subtract persisted entries. Launches never write
grants back.
The same numeric and hostname grammar applies; an empty table grants nothing
but still requires a verified file.

The config must be a regular file, **not a symlink**, with one hard link, owned
by you and not group/other-writable (`0600` or `0644` is fine). Its immediate
directory must be owned by you and not group/other-writable (`0700` is fine).
Keep `~` and `~/.config` writable only by you: ancestors and ACLs are **not**
checked. A tools/image-only symlink still works; review the file's `[network]`
table before replacing it with the file itself to carry authority.

This one policy covers **every** authority-bearing user field: the same check
runs for `[network]`, for [`mounts`](#config-mounts-user-config), and for a file
containing both. Presence decides it, not contents — `mounts = []` and an empty
`[network]` grant nothing yet are exactly the bytes worth planting, so a file
that carries either is verified. A tools/image-only symlink keeps working;
adding authority to it does not.

Notices name the file and each grant's source, for example:

```text
==> Egress policy: allowing 10.0.0.5/32 (persisted grants and --allow-egress)
==> Egress policy: --allow-lan=false overrides persisted grant allow_lan = true
```

Persisted hostname grants with a selected host HTTP proxy refuse **every launch**.
`--allow-*=false` does not clear `allow_egress`, and adding a numeric
`--allow-egress` does not bypass the refusal. Unset the proxy variables (or use
`NO_PROXY=*`), or remove the persisted hostname grant to recover.

`setup`'s verification guest ignores these grants (#303). `image refresh` boots
no guest at all, and no acquisition backend uses this launch policy. The
directory exposure guard is unchanged: launching from `$HOME` remains refused.
See [ADR-0040](docs/adr/0040-persisted-user-network-authority.md) for the threat,
trusted boundary and accepted gaps.

### Numeric allowance grammar

| form | example | scope |
|---|---|---|
| IP or CIDR | `192.0.2.7`, `10.0.0.0/8`, `2001:db8::/32` | any transport/port |
| `tcp://` or `udp://` + IP/CIDR | `tcp://10.0.0.0/8`, `udp://2001:db8::/32` | selected transport, any port |
| IPv4 + `:PORT` | `tcp://192.0.2.7:443` | selected port |
| bracketed IP/CIDR + `:PORT` | `[2001:db8::7]:22`, `udp://[10.0.0.0/8]:53`, `[2001:db8::/32]:443` | selected port; brackets required for CIDR + port and IPv6 + port |
| bracketed IP/CIDR without port | `[2001:db8::/32]` | any port |

Schemes are case-insensitive; there is no implicit port 443.
Ports are canonical decimal 1–65535 (no sign, whitespace or leading zero).
Bare IPv6 is an address, never guessed as an address-plus-port. CIDR prefixes also accept signed/zero-padded lengths (`/+24`, `/024`) and
IPv4 netmasks (`/255.255.255.0`), rendered as canonical prefix lengths. CIDRs are
canonicalized to network boundaries; IPv4-mapped IPv6 is normalized to IPv4
when its prefix permits that. Duplicate canonical grants keep their first
occurrence. Numeric grants
are address-wide, not hostname-isolated: any service sharing an allowed IP
can be reached within the grant's transport/port scope.

Numeric CIDRs match **any address** in the range, not just public or LAN
addresses. A CIDR covering the sandbox gateway (IPv4 in `100.64.0.0/10`, IPv6
in ULA `fd00::/8`), such as `100.64.0.0/10`, `fd00::/8`, `fc00::/7`,
`0.0.0.0/0` or `::/0`, reaches host loopback services through the gateway.
A CIDR covering link-local metadata (such as `169.254.0.0/16` or `0.0.0.0/0`)
also grants access to those metadata endpoints, within its transport/port scope.

### Hostname allowance grammar

A hostname allowance covers **TLS on intercepted ports only**. It is the narrow
alternative to `--allow-internet-egress`: instead of every public address, it
authorizes one exact name, verified by the TLS SNI the guest sends and by the DNS
answer the runtime cached for it ([ADR-0037](docs/adr/0037-hostname-egress-allowances.md)).
Plain HTTP to a hostname is **not** supported.

| form | example | scope |
|---|---|---|
| bare hostname | `api.example.com` | every intercepted port of this launch (443 by default) |
| `tcp://HOST` | `tcp://api.example.com` | same as bare |
| `tcp://HOST:PORT` | `tcp://git.corp.example:8443` | that port only |
| scheme-less `HOST:PORT` | `api.example.com:8443` | same as `tcp://HOST:PORT` |

A hostname is ASCII and case-insensitive, canonicalized to lowercase, with at
most one terminal dot (stripped, so `API.Example.COM.` is `api.example.com`).
Its labels must be letters, digits and `-`; the **final label must not be
numeric**, which rejects inet_aton forms such as `1234`, `1.2.3`, `127.1` and
`0x7f.1`. Wildcards (`*.example.com`), a leading dot, userinfo, a path, query or
fragment, brackets, non-ASCII (write an A-label) and the host alias are refused.
A single-label name such as `build` is accepted and authorizes exactly that DNS
name — no search-domain expansion, so a guest stub that appends a search suffix
queries a different name and gets NXDOMAIN.

**Ports are global to the launch, and widen cross-host.** The intercepted ports
are `{443}` unioned with every `PORT` any `tcp://HOST:PORT` entry names. A bare
hostname gets all of them, so adding `tcp://git.corp.example:8443` also widens
every bare hostname to 8443 and makes 8443 TLS-only for **every** destination
(see the interception paragraph below). Write `tcp://api.example.com:443` to pin
one port. `tcp://host:80` is accepted, but port 80 then becomes TLS-only
globally, not plain HTTP. Credential-only ports never widen a hostname rule.
Ports 53 and 853 (the DNS dispatch ports) and `udp://HOST` are refused; UDP can
only be allowed by an explicit IP/CIDR permission.

**Startup notices group names.** Names whose complete effective port set and
grant source are identical share one line, in first-seen order, followed once by
the TLS-only security clause:

```text
==> Egress policy: allowing TLS to api.example.com, api.anthropic.com on ports 443 (persisted grants)
==> Egress policy: hostname allowances are TLS-only (SNI and DNS verified; no plain HTTP)
```

The source tag names the sources that list the hostname, not proof that each one
grants every displayed port: a persisted bare name plus a CLI `tcp://NAME:PORT`
for the same name is one `(persisted grants and --allow-egress)` line on the
union of ports. A launch without a persisted `[network]` table prints no tag at
all. See [Persisted grants](#persisted-grants-user-config).

**Private answers need an extra grant.** A hostname resolving to a private or
reserved address is not admitted by the hostname rule alone; add `--allow-lan`,
or a **port-less** local numeric allowance. A bare or `tcp://` CIDR admits the
answer and authorizes the address wide; a port-less `udp://CIDR` admits it
**without** authorizing TCP, giving name-isolated TCP authority. A port-scoped
numeric rule does not qualify (rebind protection).

**A selected host HTTP proxy refuses a hostname launch.** `HTTPS_PROXY`,
`HTTP_PROXY` or `ALL_PROXY` pointing at a usable `http://` proxy makes the
runtime route through a proxy that resolves the CONNECT name itself, so the
address it dials would not be the one policy checked. A hostname launch is then
refused before launch with fixed text; unset the proxy, use an IP/CIDR
allowance, or use `--allow-internet-egress`. `NO_PROXY=*` is the only exemption
(a per-name `NO_PROXY` entry does not lift the refusal). A non-`http` value (for
example a `socks5://` proxy) is not selected and keeps the existing notice.

### DNS and launch behavior

| grants | DNS queries |
|---|---|
| none, numeric only, or LAN only | denied |
| host (with or without LAN/numeric) | host resolver authorized |
| internet (with any other grants) | queries authorized |
| hostname only | only the allowed hostnames resolve (each `Domain` rule authorizes its own lookups) |

With hostnames but no internet or host grant, only the allowed names resolve;
other names get NXDOMAIN when the forwarder is available. A hostname grant does
**not** emit `allow_dns()` — its `Domain` rule authorizes its own lookup. Private
answers still need `--allow-lan` or a port-less local numeric allowance, as above.

Denied queries return NXDOMAIN promptly **when the runtime's DNS forwarder is
available**. If host DNS configuration cannot be read and the forwarder cannot
initialize, queries time out instead. Plain port-53 DNS to a numerically
allowed resolver IP still returns NXDOMAIN in this release; this is an accepted limitation
([microsandbox #75](https://github.com/gregwebs/microsandbox/issues/75)). Use DoH
on an allowed IP or `--allow-internet-egress` instead.

With `--allow-internet-egress`, private DNS answers still receive NXDOMAIN
(rebind protection) unless `--allow-lan` or a local numeric allowance **without
a port** covers the answer. `tcp://`/`udp://` without a port qualifies;
port-scoped allowances do not. Query authorization does not remove resolver,
rebind or platform-policy checks. `--allow-host` includes host-resolver queries,
which can carry data to that resolver even without internet permission.

Image seed hooks, project `.agent-vm.runtime.sh`, MCP servers and provider CLIs
run under this same policy; network operations may fail offline. A non-zero
**project runtime hook** aborts launch. Image seed hooks end in `; true`, so their
failure is not propagated; this release does not change that handling.

Host `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment settings carry only
connections already allowed by policy. A denied destination is never dialed,
directly or through the proxy. Loopback/link-local dial targets always go direct.
A hostname launch refuses a selected host HTTP proxy (see *Hostname allowance
grammar*); `NO_PROXY=*` is the only exemption.

### Tool network requests

Shipped Claude/Codex/OpenCode/Pi declare a [scoped baseline](docs/default-tool-network-requests.md)
for provider, provisioned account-refresh, relay and catalog paths, not every
optional connection. Copilot is deliberately incomplete pending [#340](https://github.com/gregwebs/agent-vm/issues/340).
Dsh has no configured universal provider; shell has no provider destination and
inherits no requests from wildcard provisioning. Empty metadata does not mean
offline. Custom catalogs do not inherit these defaults.

For already-provisioned Claude auth with no grants, the built-in report lists
`api.anthropic.com`, `mcp-proxy.anthropic.com`, `platform.claude.com` as unmet;
see the [restricted built-in example](docs/default-tool-network-requests.md#restricted-built-in-example)
and the evidence document for versions, exclusions and maintenance ownership.

Only the launched tool's own `network_requests` are reported. Unmet requests
are informational; the launch always continues and no authority is added.
“Covered” means lookup-free syntactic coverage by public or same-name grants,
not a connectivity promise.

| Launch grant | Request coverage |
|---|---|
| `--allow-internet-egress` | Any name and port |
| Same-name hostname allowance | Its effective ports, including bare-name cross-host widening |
| IP/CIDR, `--allow-lan`, `--allow-host` | Not matched to names; may be a false “unmet” |

Covered names still depend on resolution/NXDOMAIN and private-answer eligibility
([DNS and launch behavior](#dns-and-launch-behavior)), and
[TLS client requirements](#tls-client-requirements).

No requests means no report. With all covered, the single line is:

```text
==> Tool network requests (user config): all 2 covered by this launch's public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply); requests never grant access
```

With unmet requests (tier labels are `built-in defaults`, `user config` or
`project config`):

```text
==> Tool network requests (project config): 2 of 2 not covered by this launch's public or same-name grants (no lookup; DNS, private-answer and TLS client limits still apply); requests never grant access and the launch continues
==>   unmet: api.example.com
==>   unmet: tcp://git.corp.example:8443
==>   to grant: --allow-egress HOST or tcp://HOST:PORT, or --allow-internet-egress; IP/CIDR, --allow-lan and --allow-host grants are not matched to names
```

At most 8 sorted unmet entries are printed; further entries produce
`==>   … and N more not shown`. The report is at most 11 lines. Covered
requests are never listed beside approval wording, and the grant hint never
contains a project-supplied value.

### TLS client requirements

TLS interception is per-port and global. Port 443 is intercepted whenever a
launch has credentials, any hostname allowance (including a bare name on a
zero-credential launch), or published ports; each `tcp://HOST:PORT` hostname
allowance adds its `PORT` to the intercepted set for the whole launch. Tool
`network_requests` themselves never enable TLS. On every intercepted port, for
every destination, clients must send a TLS ClientHello with SNI; no-SNI and
non-TLS traffic is dropped. UDP/QUIC is dropped, so HTTP/3 clients must fall
back to TCP.

Clients must trust the sandbox CA installed by the
[boot image contract](#boot-image-contract). Clients with their own store or
pins (Java keystores, Chromium/NSS, Python `certifi` used directly, pinned
certificates) need separate CA integration or compatible pinning; without it,
they fail under interception.

When relying on a hostname allowance, the ClientHello SNI must equal the allowed name,
and the dialed address must be bound to that name in the runtime DNS cache.
Resolve through the guest's configured resolver: a client using its own DoH,
hard-coded addresses or `/etc/hosts` cannot establish that binding itself.
An unbound address is refused unless another grant covers the flow.
This cache-binding requirement does not apply to Public-group or numeric flows.

**DNS-cache bindings expire.** When relying on a hostname allowance, a client
that keeps using a previously resolved IP past the runtime's minimum
resolved-hostname TTL gets a reset unless the binding is refreshed. CNAME
chains bind under the queried name, so a stub resolver that re-queries the CNAME
target separately gets NXDOMAIN.

A covered network request is still subject to these client requirements.

**Plain-text protocols can be interrupted once any hostname rule exists.** With
at least one hostname rule, a numeric/group-authorized flow on a non-intercepted
port has its first flight inspected: a missing or multiple HTTP `Host` header is
blocked; printable bytes that contain a header boundary (`\r\n\r\n`) are parsed
as HTTP and an invalid request line or non-`HTTP/1.x` version is blocked —
including mid-stream, so plain-text protocols (SMTP DATA, IMAP literals, Redis
inline, IRC) can be blocked. Printable bytes that look like an HTTP request
prefix are buffered, then blocked. Conclusively binary first flights pass
unchanged, and a server-first banner relays before the handler waits for client
bytes. This narrows what numeric grants carry; it never widens a hostname rule.

Project `[network]` can never grant authority. Verified user-tier grants merge
with launch flags as described in [Persisted grants](#persisted-grants-user-config).

## Troubleshooting

- **Could not find its bundled `msb` binary after copying:** copy the whole
  bundle (`bin/agent-vm`, `bin/msb`, `lib/libkrunfw.5.dylib` on macOS), or
  build the opt-in single binary with `./script/build/macos.sh --single-binary`.
  Symlinking `agent-vm` to a complete bundle is supported.
- **Could not unpack its embedded `msb` runtime:** make the cache writable,
  or set `XDG_CACHE_HOME` to an absolute writable directory. The default is
  `~/.cache/agent-vm/runtime/<id>/`, separate from launch state.
- **Does not match the runtime embedded:** remove only the runtime directory
  named by the diagnostic and retry; do not re-sign extracted msb.
  `agent-vm doctor` shows the unpacked runtime path without creating it.

- **Config-directory exposure / “launch authority”** — run from a project,
  not `$HOME`; use `:ro` or a narrower mount. For a state/home bind, move
  `AGENT_VM_STATE_DIR` outside the authority lookup route.
- **“does not exist yet; once created it could be, or contain”** — a missing
  state/home source could hold a future authority lookup directory. Remove
  the exposing symlink layout or choose unrelated state. Relative state
  roots are resolved against the launch cwd; messages retain `..` spelling.
- **“reached through a symbolic link”** — the link target may be writable by a
  guest or project. Review the file's `[network]` table before replacing the
  link with the file itself; tools/image-only symlinks still work without
  `[network]`.
- **“group- or other-writable”** — another account or a guest may have written
  the file or its directory. Review the `[network]` table before `chmod go-w`;
  a mode change does not establish authorship. The file and directory must both
  be owned by you.
- **“has … hard links” / “with … hard links”** — another name for `config.toml`
  may be guest- or project-writable. Review the `[network]` table before
  removing links or copying the file. The launch-time check applies regardless
  of content; `[network]` also invokes the read-time check.

- **`RegisterNetDevice(IrqsExhausted)` at boot** — device capacity is host
  and runtime dependent. Drop a `--mount` to recover. Linux x86_64 uses a
  split userspace IOAPIC while Apple Silicon uses GIC; do not infer one
  platform's device limit from another.
- **`handshake read id_offset: timed out`** — `free -h`; the VM needs
  more memory than is available. Try `--memory 1`.
- **GitHub 403 from the proxy** — repo isn't in the allow-list.
  Pass `--repo OWNER/NAME` or run from a project with the right
  remote.
