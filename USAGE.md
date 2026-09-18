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
pull                                refresh the cached image
setup                               pull base image + verify boot
doctor                              report host credentials + microsandbox state
                                    + the resolved tool configuration
                                    (--reset-msb-db recovers a forward-migrated db)
msb <args...>                       forward to the bundled msb (e.g. msb ls, msb status)
clipboard {get,put} [--sys]         exchange a string with the project sandbox
```

The launch verbs are generated from your tool configuration (see *Tool
configuration* below). With no config files you get the five shipped defaults
`codex`, `opencode`, `claude`, `copilot`, `shell`; if your config declares only
`claude`, then only `agent-vm claude` (plus the built-ins and a `shell`
fallback) exists. `agent-vm --help` and `agent-vm doctor` always show the same
list, in the same order.

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

## Launch flags

Each launcher accepts:

| flag | what |
|---|---|
| `--memory N` | VM memory GiB (default 2) |
| `--cpus N` | vCPUs (default 2) |
| `--image REF` | override the OCI image |
| `--update-check` | check the registry for a newer image on launch (off by default) |
| `--no-git` | skip gh/git auth injection (still respects `--repo`) |
| `--repo OWNER/NAME` | add to the GitHub allow-list (repeatable) |
| `--mount HOST[:GUEST][:MODE]...` | extra live bind or project-scoped `:fork`. Directory binds default to writable; a regular file needs an explicit `:ro`. Modes: `:ro`, `:rw`, `:fork`, `:follow-links`, and fork-only repeatable `:exclude=REL`; see [Extra and forked mounts](#extra-and-forked-mounts). Capacity is host-specific. |
| `--root` | run the guest as root (uid 0) instead of the default host user — see [Guest user](#guest-user----root) |
| `--layer DIR` | append a tooling layer after the project's own `.agent-vm/layers/*` (repeatable, command-line order; relative to the project dir) — see [Project tooling layers](#project-tooling-layers) |
| `--yes` / `-y` | assume "yes" to the tooling-layer chain build confirmation (CI/non-interactive) — see [Project tooling layers](#project-tooling-layers) |

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
| `RUST_LOG` | tracing filter; default `warn`. e.g. `RUST_LOG=agent_vm=debug` |
| `AGENT_VM_PROFILE` | print per-phase wall-time (create/run/stop/remove) |
| `AGENT_VM_DEBUG_CONFIG` | dump the SandboxConfig JSON before boot |
| `AGENT_VM_NO_CHROME_MCP` | disable Chrome MCP auto-configuration for a Chrome-capable image/layer |
| `AGENT_VM_IMAGE_TAG` | override the OCI image (same as `--image`) |
| `AGENT_VM_MEMORY_GIB` / `AGENT_VM_CPUS` | same as `--memory` / `--cpus` |
| `AGENT_VM_UPDATE_CHECK` | opt into the launch-time registry update check (accepted: `1`/`true`/`yes`/`on`) |
| `AGENT_VM_ROOT` | same as `--root` (accepted: `1`/`true`/`yes`/`on`) |
| `AGENT_VM_YES` | same as `--yes` (accepted: `1`/`true`/`yes`/`on`) |

`AGENT_VM_LAYER` was removed; if set, launches fail with a pointer to
`--layer`.

## Project tooling layers

A project can add tools on top of the base image — compilers,
cross-toolchains, whatever the base doesn't carry — by declaring an ordered
**chain** of layers under `.agent-vm/layers/`. Each immediate subdirectory
is one step, built `FROM` the previous step (the base image for the first
step), in byte-lexicographic order by directory name:

```
.agent-vm/layers/10-toolchain/Dockerfile
.agent-vm/layers/20-chrome/Dockerfile
```

A single-step chain (just `.agent-vm/layers/10-tools/`) is the common case
and is not a special case — it behaves exactly like the single layer this
feature originally shipped as.

`--layer DIR` (repeatable) **appends** more steps after the project's own
`.agent-vm/layers/*` chain, in the order given on the command line:

```
agent-vm shell --layer ../shared/debug-tools --layer examples/layers/chrome-devtools
```

It appends rather than prepends because content-hash chaining is
*prefix-stable*: a step's hash depends only on the steps before it, so
appending never moves any project step's tag — a project's own chain stays a
pure cache hit whether or not a `--layer` is passed that launch. `--layer`
also works with **no** `.agent-vm/layers/` at all, which is how you try a
checked-in example without copying it into the project first:

```
agent-vm shell --layer examples/layers/chrome-devtools --yes
```

Relative `--layer` paths resolve against the project directory (unlike
`--mount`, which requires absolute paths — trying an example by relative path
is the point). There is deliberately no environment variable for `--layer`;
see the `AGENT_VM_LAYER` note above. The first time a `--layer` is appended
after a project chain whose last step was already built, that last step gets
rebuilt once (re-exported into docker's local image store, since it was
built as a final/OCI step and never landed there) — this is expected, not a
bug, and buildx's own build cache usually makes it fast; dropping the flag
again afterward is a pure cache hit, because the project's own tag never left
the msb cache. Trying a layer via `--layer` and then adopting it into the
project (copying it under `.agent-vm/layers/`) costs nothing either: the hash
covers the directory's contents and every step before it, never how it was
named on the command line, so the adopted layer is a cache hit too.

When a chain is declared, any launch verb
builds each step with `docker buildx build`, chaining every step `FROM` the
previous one's tag, loads **only the final step's** result into the
microsandbox image cache **registry-lessly** (no `registry:2` sidecar, no
registry contact at boot), and boots that derived image instead of the base.
Intermediate steps live in docker's own local image store, never booted and
never ingested into the msb cache. Step 0 resolves its base through the
Docker-local base link `agent-vm-base:<msb-manifest-digest-hex>` (created at
import time by `./script/build/import-image.sh`; for a registry base, the
first build instead pulls the exact digest and creates the link itself) — this
resolution happens **only on an actual build**, never on a cached launch.

Each step's identity is a content hash that transitively covers every step
beneath it, so the tag itself is the staleness check — there is no separate
state file. An unchanged chain boots straight from the cache on every launch
after the first, with no docker process spawned at all. Editing a step's
Dockerfile changes that step's hash and every later step's hash, so editing
an early step rebuilds the whole suffix above it; editing the last step
rebuilds only itself. Building requires the default `docker` buildx driver
on the host (`docker buildx use default` if unsure — see below) and, unless
every step's hash is already cached, one confirmation for the whole chain:

```
Build project tooling layer 'agent-vm-layer:my-app-1a2b3c...'? [y/N]
```

for a single-step chain, or for a multi-step chain (`--layer` steps are
labeled with their flag, as typed, so it's clear which came from the project
and which from the command line):

```
Build project tooling layer chain (3 steps)?
  1/3  .agent-vm/layers/10-toolchain            agent-vm-layer:my-app-1a2b3c…
  2/3  .agent-vm/layers/20-lint                 agent-vm-layer:my-app-9f8e7d…
  3/3  --layer examples/layers/chrome-devtools  agent-vm-layer:my-app-2c1d9e…
 [y/N]
```

Pass `--yes` (or set `AGENT_VM_YES=1`) to skip the prompt — required for
CI/non-interactive launches. A failure in any step is a hard stop: agent-vm
never boots the base, or a partially-built chain, in place of a step that
failed.

Each step's **built image** must satisfy the **layer image contract** — eight
clauses, four enforced at build time. The normative text is
[`docs/adr/0003-project-tooling-layers.md`](docs/adr/0003-project-tooling-layers.md)
("The layer image contract").

What agent-vm rejects, and how to fix it:

1. **C1** — build `FROM ${BASE_IMAGE}`: declare a global `ARG BASE_IMAGE=...` before the first `FROM`.
2. **C2** — keep `PATH` additive: never remove a directory the previous step had.
3. **C3** — end the last step as root: no trailing `USER <someone-else>`.
4. **C4** — don't pin `--platform` on your final `FROM`; agent-vm also refuses to build on a base image of the wrong platform.

The other four clauses (C5–C8: not touching agent-vm's own files, keeping
`/bin/bash` and `/etc/passwd`/`/etc/group` appendable, installing tools
readable by any uid, advertising a capability only when it works) are
documented-only — see the ADR. A `RUN` that installs foreign-architecture
binaries **is not detected**: it fails at run time with `Exec format error`.

A violation is a hard failure that aborts the launch, with no opt-out, and
the offending image is discarded so the next launch rebuilds and re-checks it
instead of booting it from cache:

```text
Error: tooling layer step 1/1 (.agent-vm/layers/10-a) violates the layer image contract, clause C3 (ends as root): the built image's config sets User="chrome", so a --root launch would run every command as that user instead of root
Fix: end the Dockerfile with `USER root`
See docs/adr/0003-project-tooling-layers.md, "The layer image contract".
```

The four enforced clauses apply only to images **built after** this version:
agent-vm does not revalidate an already-cached image (a pre-upgrade artifact, or
one whose discard after a violation failed), so it keeps booting until a step
is edited and its hash moves. See
[`docs/adr/0003-project-tooling-layers.md`](docs/adr/0003-project-tooling-layers.md)
for the full contract and design rationale, including why chaining hashes
against each step's content hash rather than a docker image id, and why
`FROM` takes the previous step's tag.

Requires the default `docker` buildx driver, not `docker-container`
(`docker buildx ls` shows the active builder's driver) — chain steps
resolve `FROM <tag>` through docker's own local image store, which an
isolated `docker-container` builder can't see. If a step's build succeeds
but the *next* step fails to resolve `FROM` it, run `docker buildx use
default`, or create one with `docker buildx create --driver docker --use`.

**Upgrading from a single `.agent-vm/layer/` directory** (the pre-chain
layout): move it under `.agent-vm/layers/` as a numbered step —
`git mv .agent-vm/layer .agent-vm/layers/10-tools` — and re-run. The layer
hash covers the directory's contents, not its path, so the move does not
invalidate an already-built image; a leftover `.agent-vm/layer/` is
otherwise a hard error telling you to move it.

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
[[tools]]
name = "mytool"                      # required; the `agent-vm <name>` verb
command = "mytool"                   # required; the guest command name
args = ["--flag"]                    # optional; default argv (array of strings)
layer = { builtin = "codex" }        # optional; EXACTLY one of builtin/path
credentials = ["openai"]             # optional; credential provider names
tools = ["claude"]                   # optional; tools to provision (same file, or name one)
persist = [".cache/mytool"]          # optional; guest-HOME-relative paths
env = { VAR = "value" }              # optional; guest env pairs for this tool
interactive_shell = false            # optional; join trailing args into `-c`
```

- `name` — required; a single command-name token: nonempty, no
  whitespace/control characters, no `/` (a name is not a path), not an
  all-dots spelling (`.`/`..`), no leading `-`, and not one of the reserved
  subcommands `setup`, `pull`, `msb`, `clipboard`, `doctor`,
  `_intercept-hook`, `help`. Names are case-sensitive. Naming a tool `claude`
  is normal — that is the point.
- `command` — required, nonempty, NUL-free. The guest command name; it is
  never executed by `doctor`.
- `args` — optional, the default argv prepended to the user's own args unless
  the user already passed the same flag. `doctor` shows only the argument
  **count**, never the values, so a secret accidentally placed here is not
  echoed. Args are not shell-split or expanded.
- `layer` — optional; a table with **exactly one** of `builtin` (one of
  `codex`, `opencode`, `claude`, `copilot`) or `path` (a declared path). A
  layer is metadata only in this release: it is **not** resolved, checked
  for existence, or built (see [#84](https://github.com/gregwebs/agent-vm/issues/84)).
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
- `persist` — optional; guest-HOME-relative paths to preserve across runs.
  Absolute paths, any `..` component, NUL, and root-equivalent spellings
  (`.`/`./`/empty) are rejected; harmless `.`/`//`/trailing-`/` spellings are
  normalized. Metadata only in this release (see
  [#83](https://github.com/gregwebs/agent-vm/issues/83)).
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

Unknown keys, wrong types, malformed TOML, unknown `layer.builtin`, unknown
provider names, duplicate tool names within one file, duplicate normalized
persist entries within one tool, and two tools claiming the same normalized
persist path are all **hard errors** — as are invalid `tools` entries: `"*"`
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
an omitted `persist`, `layer`, `credentials`, or `tools` on a user-defined tool.
Resolved order is user declarations first, then project-only declarations (the
order `--help` and `doctor` both use). When a project declaration of an
existing name differs, `doctor` warns once and the user definition wins, e.g.:

```text
warning: tool "claude" in /home/alice/.config/agent-vm/config.toml overrides
         /work/repo/.agent-vm/config.toml; differing fields: command, args
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
does the compiled-in defaults list apply: `codex`, `opencode`, `claude`,
`copilot`, `shell`, in that order. They are defined once in
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

The built-in `shell` declares **no** `credentials` and omits `tools`, so in the
shipped catalog it *provisions* every provider `default-tools.toml`'s tools
declare without *requiring* any of them: `agent-vm shell` still works for a user
with no Anthropic or Copilot login, and an in-guest `copilot` now works too. The
wildcard is scoped to the file it is written in — if you replace the shipped
catalog, your own `shell` gets the same name-based default but closes over
**your** file. Add `tools = []` to opt out.

**Upgrading (provisioning).** The built-in `shell` no longer declares
`credentials`, and a tool's `tools = ["*"]` closes over the tools declared in
**the same configuration file** — never another file's. So if your config
declares tools, every `shell` in it — one you declared or the appended
fallback — provisions only what its *own file* declares, and a file whose only
tool is `shell` provisions nothing. Before this release such a `shell` still
captured the host's Anthropic and OpenAI logins unconditionally. To restore
that on your `shell`, declare one in **your own file** if you were relying on
the appended fallback, and then either

* **declare the agent tools in that same file**, so the wildcard closes over
them again, or
* **put providers on its `credentials`**:

```toml
[[tools]]
name = "shell"
command = "zsh"
credentials = ["openai", "opencode-static"]   # safe: no hard bail
```

`credentials` is the **requirement** set, so adding `anthropic` or `copilot`
there makes `agent-vm shell` hard-fail for a user without that host login —
which is exactly why the shipped `shell` no longer carries them. Run `agent-vm
doctor` to see the resolved set as `provisions=…`.

**Upgrading:** `CODEX_HOME` used to be set on *every* launch. It is now
declared by the shipped `codex` and `shell` tools. If you declare your own
`codex` or `shell` tool in `~/.config/agent-vm/config.toml` or
`.agent-vm/config.toml`, your definition wins wholesale and does **not**
inherit the shipped `env` — add `env = { CODEX_HOME = "/agent-vm-state/codex" }`
to it, or codex will start in the guest as signed out.

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
it and have the launcher add its owned `mcpServers.chrome-devtools` entry —
either copy it into the project as a numbered step
(`.agent-vm/layers/NN-chrome-devtools/`) or try it without copying via
`agent-vm claude --layer examples/layers/chrome-devtools --yes`. Removing the
layer removes that stale owned entry while preserving other MCPs.
`AGENT_VM_NO_CHROME_MCP=1` removes the automatic entry but leaves Chromium
available for manual use. The wrapper preserves Chromium's nested sandbox:
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
over `default-tools.toml`'s four agents. `agent-vm doctor` prints each verb's
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
