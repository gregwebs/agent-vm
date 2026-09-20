# CONTEXT.md — domain vocabulary

Terms used consistently across code, comments, docs, and commit messages in
this repo. When a term below conflicts with something already in the code,
the code is the bug — file it, don't silently reintroduce the old name.

## Guest user

The identity the in-guest agent process runs as (the numeric `uid:gid`).
`.user(...)` is set in **two** places, both load-bearing, for different
reasons (see `docs/adr/0001-non-root-guest-via-native-user.md`):

- On the **sandbox builder** (`run.rs`, before `Sandbox::create`): drives
  agentd's `InitResolved.default_user`, which the host installs as
  passthroughfs's `BindIdentityMap` — this is what makes bind-mounted
  files (HOME/project/state) stat with owner bits matching the guest's
  real uid instead of uid 0.
- On the **per-exec attach/exec builders**: governs the actual `setuid`
  of the exec'd process (PID 1 / agentd stays root so it *can* `setuid`
  per exec).

- **Default: the host user.** The uid/gid of whoever invoked `agent-vm`
  (`libc::getuid()`/`getgid()`), so the guest agent runs non-root inside the
  microVM — defense-in-depth on top of the microVM boundary itself, and
  required to keep write access to the host-uid-owned project/state bind
  mounts (a non-root guest uid gets owner bits from passthroughfs only when
  it matches the real host uid).
- **`--root` / `AGENT_VM_ROOT`** restores the legacy **root guest** (uid 0)
  — see below.

_Avoid_: "dev user", "container user" — this isn't a fixed image account,
it's whichever uid launched `agent-vm`.

## Guest username

The **cosmetic** name attached to the guest user's numeric uid — what
`whoami`/`$USER`/the shell prompt show. Distinct from the "Guest user"
above (the access-control identity): a username mismatch doesn't change
what files the guest can access, it just makes `whoami` say something
misleading.

Resolved env-first (`resolve_guest_username`/`choose_guest_username` in
`run.rs`): `$USER` → `$LOGNAME` → the passwd-DB name for the uid
(`getpwuid_r`) → the numeric uid as a string, each non-numeric candidate
checked against a safe `/etc/passwd` charset and skipped on failure.
Env-first because on this project's reference dev host `getpwuid(uid)`
returns no entry at all for the real host uid while `$USER` is reliably
set. Default in non-root mode: the host user's own username (`agent`
no more). See `docs/adr/0002-mirror-host-home-and-username.md`.

## Root mode

The opt-out, enabled by the `--root` flag or a truthy `AGENT_VM_ROOT` env
var (parsed by the shared `env_flag` module — `1|true|yes|on`, trimmed and
ASCII-case-insensitive, the same parser behind every value-parsing boolean
`AGENT_VM_*` variable). Runs the guest as uid 0 with `HOME=/root` — the
pre-non-root-default behavior.
Required for docker-in-VM (dockerd needs root); when the Chrome DevTools layer is installed, its MCP uses the `sudo -u chrome` path only in this mode.

_Avoid_: "privileged mode" — the microVM boundary applies identically in
both modes; root mode only changes the *in-guest* uid.

## Guest HOME

The in-guest `$HOME` for the current guest user mode:

- **Non-root mode (default):** the **mirrored host `$HOME` path** (e.g.
  `/Users/claude`) — a real bind mount (not a symlink) of the host-owned
  `<state_dir>/home`, provisioned host-side by
  `ProjectSession::provision_guest_home` (`crates/agent-vm/src/session.rs`)
  and mounted at the host path by `run.rs`'s `core_dir_volumes`. Mirroring
  the literal host path (not `/agent-vm-state/home`) is consistent with
  the guest's project-path mirroring, so `$HOME`-relative paths stay
  interpretable on the host. See
  `docs/adr/0002-mirror-host-home-and-username.md` for the bind-vs-symlink
  rationale and the nested-mount ordering this depends on when the
  project lives inside `$HOME`.
- **Root mode:** `/root` — dotfile symlinks baked into the rootfs by
  `run.rs`'s `.patch()` block, unchanged.

Both modes share one symlink mapping,
`credential_provider::guest_home_links()`, so the two provisioning paths can't
drift (see **Credential provider** → **Guest home link**).

## Private MSB_HOME

The private Microsandbox home agent-vm points `msb` at:
`<state_root>/msb-home` — a single flat directory, shared by every
agent-vm build on the host under a given `$AGENT_VM_STATE_DIR`, never
namespaced by schema. Because sea-orm migrations are one-way, two
builds vendoring different microsandbox schemas sharing this home can
collide (an older build can't open a DB a newer build already
forward-migrated); `msb_preflight`'s ahead-of-bundle guard turns that
into a named, recoverable stop (`agent-vm doctor --reset-msb-db`)
rather than namespacing it away structurally. See
`docs/adr/0004-single-shared-msb-home.md`.

_Avoid_: "MSB_HOME" alone when the private-vs-shared distinction
matters — `MSB_HOME` is the env var; the shared `~/.microsandbox` a
separately-installed `msb` uses is a different thing agent-vm
deliberately does not point at (except the opt-in cache share).

_Avoid_: "MSB_HOME" alone when the schema-scoping matters — `MSB_HOME` is the
env var the schema home is exported under, but the schema home is the
concept (an env var can point anywhere).

## Credential provider

A **compiled-in credential subsystem** a launched tool can depend on. The four
variants are `Anthropic`, `OpenAi`, `OpencodeStatic` and `Copilot`
(`crates/agent-vm/src/credential_provider.rs`). A provider owns everything
needed to be signed in: the host credential file it captures, its
placeholders, its eager state dir, its guest-HOME links, its first-run bypass
config, its guest env, and its proxy secret/routes — plus, for
`Anthropic`/`OpenAi`, the OAuth-rotation facts (SNI host, token path, accepted
refresh placeholders, host login hint) the interception hook reads.

Which tool needs which provider **is configuration** (#80/#82): a tool names
its providers in config (`anthropic` / `openai` / `opencode-static` /
`copilot`, `CredentialProvider::config_name`), and `Tool::credential_providers`
turns that into the `ProviderSet` the launch treats as the **requirement** set.
A **Tool** (#82's term) is a resolved command carrying a provider set; do not
call a provider a "tool" or "agent".

The only guest env a provider owns is `COPILOT_GITHUB_TOKEN` (Copilot, and only
when this launch both provisions Copilot **and** captured its token).
`CODEX_HOME` is **not** a provider fact: it names codex-the-
tool's config dir, so it lives on the `codex` (and `shell`) tool's own `env`
([agent-vm #119](https://github.com/gregwebs/agent-vm/issues/119), ADR-0016).

Every provider-owned facet a launch can reach is gated on one predicate: the
launch's **provisioning set** — host credential capture, the guest placeholder
files, the proxy secret and its intercept route, the first-run bypass configs,
and the provider guest env. There is no per-facet scope. The two pre-#118
spellings of that gating (`Scope`, `CaptureScope`) are deleted. See
[ADR-0017](docs/adr/0017-tool-declared-provisioning.md). `Copilot` is the one
provider whose placeholder lives in a *config* file written after capture, so
its config is written and its env var exported only when its token was wired.

**GitHub egress is not a provider.** The `gh` token is gated by `--no-git` /
detected repos, orthogonal to the launched tool, so it has no
`CredentialProvider` variant; `credential_injection` keeps its own block and
splices it into the proxy's fixed `WIRE_ORDER`. GitHub egress no longer feeds
any provider's **capture** (the pre-#118 Copilot disjunction is gone).

_Avoid_ the `doctor_label` (`claude` / `codex` / `opencode` / `copilot`) as the
provider's name: the label names the host CLI that owns the file (retained so
`agent-vm doctor` output stays byte-identical), while the config name for
OpenCode is `opencode-static`. A user copying `opencode` out of `agent-vm
doctor` into `credentials = [...]` is rejected by #80's validator.

_Not the same as_ `OpencodeApiProvider`: that is a *dynamic*,
user-populated BYO-API-key row inside OpenCode's `auth.json`, not a
compiled-in subsystem.

### Required credential providers

The providers a tool names in `credentials = [...]`. This is the
**requirement** set: a launch hard-fails before boot when one of them yielded
no usable host credential (`credential_provider::missing_credential_error`,
consumed by `run::launch`). The requirement set is a subset of the provisioning
set — being provisioned is not being required — and it is **equal** to it
whenever the tool declares no `tools`, which is the common case (four of the
five shipped verbs: `codex`, `opencode`, `claude`, `copilot`).

### Available tools

The catalog tools a tool names in `tools = [...]` (`config::DeclaredTools`):
the tools it wants **available in its guest**. They name *tools*, never
credential providers. `["*"]` — which must be the sole entry, and which is the
default for a tool named `shell` — closes over the tools declared in the
**same configuration file** as the declaring tool, **not** the merged catalog
(the file is identified by `config::ToolOrigin`; the built-in `shell` fallback's
file is the embedded `default-tools.toml`). A tool declared in a *different*
configuration file is reachable only by **naming it explicitly** — that explicit
name is the cross-file opt-in. An omitted `tools` is `[]` for every other name.
A name that no catalog tool provides is a hard config error.

_Avoid_: "dependencies" — a named tool is provisioned, not required, and
nothing is installed or built for it (that is a **tooling layer**).

### Provisioning set

Everything one launch provisions: the least fixed point of

    provisioning(t) = credentials(t) ∪ ⋃ { provisioning(u) | u ∈ tools(t) }

over the launch catalog (`config::CatalogEntry::provisioned`), where a `"*"`
entry expands to the declaring tool's **own configuration file** (origin
equality), not the whole catalog. It is the **single** gate on every
provider-owned facet — host credential capture, the guest placeholder files,
the proxy secret and its intercept route, the first-run bypass configs, and the
provider guest env. A cycle is a fixed point, not an error. The same closure
also folds the tools' `persist` paths (`config::CatalogEntry::persist`), which
the launch turns into guest-HOME links (`guest_home::links`) — one closure, two
facets.

Distinct from the **required credential providers**: in the shipped catalog
`agent-vm shell` provisions all four without requiring any, so it works for a
user with no Anthropic or Copilot login. (Under a *custom* catalog the fallback
`shell` is a different file from the user's tools and provisions only its own
`credentials`; see **Available tools**.)

_Avoid_: "the selected tool's providers" / "when selected". That phrasing came
from the pre-#118 `Scope`/`CaptureScope` fields, which are deleted: gating is
membership in the provisioning set, which is not the launched tool's own
`credentials`. See [ADR-0017](docs/adr/0017-tool-declared-provisioning.md).

### Guest home link

A `(home_relative, state_relative)` pair mapping a guest `$HOME` dotfile to an
entry under the per-project state dir (`credential_provider::HomeLink`).
Provider-owned links come first, in `CredentialProvider::ALL` order, then the
`GENERIC_HOME_LINKS` that no provider owns (`.gitconfig`, `.config/gh`,
`.bash_history`), then one link per `persist` path in the launch's
**provisioning closure**, under `<state>/persist/`
(`guest_home::links(persist)`). Both guest-user modes consume the single
`guest_home::links` list, so root mode's `.patch()` symlinks and non-root mode's
host-side provisioning cannot drift (ADR-0002). `LinkSource` marks which links
are compiled-in and which are config-declared; the non-root site reads it (only
a **declared** link may replace real content by migrating it — a compiled one
keeps `force_symlink`'s refuse-a-directory contract), while root mode
force-symlinks both, because `/root` is rebaked into a fresh rootfs every boot
so nothing real is ever at a link path there.

## Tool

A validated **declarative tool definition** (`config::Tool`): a guest
`command`, its default `argv`, an optional **tooling layer**, a list of
**credential providers** (`credentials`, the requirement set), a list of
**available tools** (`tools`, which drives the provisioning set), extra
guest-HOME-relative `persist` paths, a guest `env` map, an `interactive_shell`
flag, and the **tool config tier** it came from. A tool is **data**, not a
credential provider and not a command to execute on the host.

A tool *is* the launch verb: `agent-vm <name>` works because the resolved
configuration declares a tool named `<name>`, and the CLI builds its
subcommands from that catalog (#82). `layer` is consumed by the launch (#84): it
is the tool's **tool layer**. `persist` is consumed by the launch (#83).
`interactive_shell` selects the bash `-c` argument-joining the shipped `shell`
tool uses.

`credentials` is the **requirement** set (a launch hard-fails when one yields
nothing); `tools` drives the **provisioning** set (named tools are provisioned,
never required). See **Required credential providers** and **Available tools**.

`env` is published into the guest **before** the launcher's own environment
and the guest applies it last-wins, so it cannot override `PATH`,
`IS_SANDBOX` or `LANG` — but `HOME`, `USER` and `LOGNAME` are published only
in non-root mode, so position would not protect those under `--root`; that
identity triple is **rejected** at the config seam in every mode instead. See
[ADR-0016](docs/adr/0016-tool-declared-guest-env.md).

### Launch catalog

The verbs a launch actually offers (`config::LaunchCatalog`): the resolved
merge result, plus the built-in `shell` appended when no declared tool claims
that name. The catalog resolves each entry's **provisioning set**
(`config::CatalogEntry`) before dispatch, so `--help`, `doctor` and
`run::launch` cannot disagree about it either. Both `agent-vm --help` and
`agent-vm doctor` render it, so their verb lists and order cannot disagree.
Distinct from `ResolvedTools`, which is the pure merge result and never
contains the fallback.

_Avoid_: calling a **credential provider** a "tool" or "agent".

### Tool config tier

One of the two ordered, optional config files resolved by `config::load`: the
**user** tier (`$HOME/.config/agent-vm/config.toml`) or the **project** tier
(`<cwd>/.agent-vm/config.toml`). Each tier is parsed and validated
independently before merging, retains whether it was `absent`, `found` (with a
declared-tool count), or — for the user tier only — unavailable because
`$HOME` is unset. Only when both tiers declare **zero** tools do the
compiled-in defaults (embedded from `default-tools.toml`) apply.

Their merge is a **union of whole definitions**, not a field overlay: the user
tier is authoritative for every name it declares, the project tier may only
add names the user did not write, and a differing project declaration yields a
`config::ConfigConflict` warning rendered by `doctor` (user definition wins).

A load failure is **deferred**, not fatal at startup (#82): the CLI is
built from the loaded catalog, but a broken config is carried as data so
`doctor` (and the in-guest `clipboard`/`_intercept-hook`) keep working, a
launch verb reports the config error rather than clap's "unrecognized
subcommand" (a verb near a built-in gets a did-you-mean hint *appended* to
that error, never in place of it), and `--help` still lists the built-ins.

## Chain root

The published image reference a launch's chain builds `FROM` and boots when no
project tooling layer is declared — resolved by the pure
`tool_layer::chain_root` (type `tool_layer::ChainRoot`). It is one of:

- the **composed default image** verbatim, when `--image` is unset, no
  `--base-image` is given, and the catalog's declared layer sequence equals the
  shipped default;
- the **base image** when the declared sequence differs, or `--base-image` is
  given (both compose the declared tool layers locally);
- a `--image` value, booted verbatim with no tool composition.

This is the term to use wherever older text said "the base a layer builds
`FROM`". It is the reference `--update-check` probes and `agent-vm pull`
fetches (always a published tag, never a locally composed
`agent-vm-layer:<hash>`). See `docs/adr/0019-tool-free-base-and-per-tool-layers.md`.

_Avoid_: calling the chain root "the base image" — under the fast path it is the
composed default, not the base.

## Base image

The **tool-free** OCI base agent-vm composes from when a launch needs local tool
layers (default `ghcr.io/wirenboard/agent-vm-base:latest`) — Debian 13 plus the
docker engine, diagnostic CLIs, the `agent-vm-install` helper and the host-CA
shim, but **no agent CLI**. Resolved via `--base-image` /
`AGENT_VM_BASE_IMAGE` / `defaults::DEFAULT_BASE_IMAGE_REF`. msb's resolved
per-platform **manifest digest** is authoritative: it is step 0's hash input and
what boot resolves, even when Docker needs a separate build-time name for the
same base (see **Base link**). See
`docs/adr/0019-tool-free-base-and-per-tool-layers.md`.

> The published `ghcr.io/…/agent-vm-base` repository is a **different namespace**
> from `layer::BASE_REPO`'s unqualified Docker-local `agent-vm-base:<hex>` links
> (see **Base link**). The names coincide by intent but never collide, because a
> link tag is always 64 hex characters.

## Composed default image

The OCI **guest template** agent-vm boots verbatim when the declared tool set
equals the shipped default: `ghcr.io/wirenboard/agent-vm-template:latest`
(`defaults::DEFAULT_IMAGE_REF`), published by CI as the base plus the four
shipped **tool layers** chained in declaration order. It is never rebuilt
locally. With no project tooling layers the launch performs zero Docker calls;
with project layers, they chain on top of it.

## Tool layer

One tooling layer the catalog declares, via a `[[tools]]` entry's `layer` field:
either `{ builtin = "codex"|"opencode"|"claude"|"copilot" }` (a source embedded
in the binary from `images/tools/`, materialised into a throwaway build context
on the compose path) or `{ path = "…" }` (a directory anchored on the declaring
config file's directory). Distinguish from **Tooling layer**, which is
project-declared and named on disk or on the command line. The chain a launch
builds is the catalog's tool layers, then the project's tooling layers, then any
`--layer` steps. Resolved by `tool_layer::chain_root` → `tool_layer::materialize`.
See `docs/adr/0019-tool-free-base-and-per-tool-layers.md`.

## Base link

The Docker-local name `agent-vm-base:<manifest-digest-hex>` for an msb-cached
base image — what buildx's step-0 `FROM` resolves, created by
`script/build/import-image.sh` at import time (or, for a registry base, by a
build-time `docker pull <repo>@<digest>` + `docker tag`). It is the *bridge*
between the two image stores, not a second identity: the manifest digest stays
step 0's hash input, and the link is never consulted on a cache-hit launch
(which spawns no Docker process). See
`docs/adr/0003-project-tooling-layers.md`'s issue-#98 amendment. Distinct from
the published `ghcr.io/…/agent-vm-base` repository (see **Base image**): this is
an unqualified, Docker-local tag, always 64 hex characters.

## Tooling layer

A `Dockerfile` (plus its build context — the rest of that directory) that
adds project-specific tools `FROM` the previous step in the chain:
compilers, cross-toolchains, anything the current image doesn't carry. Not
necessarily project-owned: a step is either a catalog **tool layer**, a
`.agent-vm/layers/` subdirectory of the project, or a `--layer DIR` directory
anywhere else on disk. A single tooling layer is one step of a "layer chain"
(see below); project steps are resolved by
`layer::resolve_layer_chain`. There is no environment-variable override —
`$AGENT_VM_LAYER` is rejected outright if set — but there is composition: the
chain is the catalog's tool layers (issue #84), then the project's own
`.agent-vm/layers/*/` steps, then any `--layer
DIR` values (repeatable, appended after, never prepended). Every step's
built image must satisfy the **Layer image contract**. See
`docs/adr/0003-project-tooling-layers.md`.

## Layer chain

The chain a launch builds, in build order: the catalog's **tool layers** (issue
#84), then the project's tooling layers — the
immediate subdirectories of `.agent-vm/layers/`, sorted byte-lexicographically
by directory name (`10-toolchain` before `20-chrome`) — then each `--layer DIR`
in command-line order. Each step builds `FROM` the previous step (the **chain
root** for step 0); only the **final** step is ingested into the msb cache —
intermediates live in docker's own local image store, pinned for the next
step by tag. `layer::plan_chain` computes the whole chain's identities up
front (pure, no I/O beyond hashing); `layer::execute_chain` drives the build.
An empty chain boots the chain root with no build (the fast path).
A leftover singular `.agent-vm/layer/` (the pre-chain, one-layer-only layout)
is a hard migration error naming the path, not a supported alias, and a
`--layer` cannot reach it either — the check runs first and unconditionally.
See `docs/adr/0003-project-tooling-layers.md`.

## Derived image

Base image + the **whole layer chain**, built one `docker buildx build` per
chain step, tagged `agent-vm-layer:<project-slug>-<hash>`, and booted in
place of the base whenever the project declares a chain. Only the final
step's image is the derived image proper — intermediate steps are build-time
scaffolding in docker's own image store, never booted and never ingested.
Ingested **registry-lessly** — via `microsandbox_image::load_archive`, never
a `registry:2` push — so booting a derived image makes no registry contact.
Only the final derived image boots, so only it is subject to the **Layer
image contract**'s clause C3 ("ends as root"); C1/C2/C4 apply to every built
step. See `docs/adr/0003-project-tooling-layers.md`.

## Layer identity / hash

The content hash `layer::resolve` computes over a step's `base_image_id`
plus that step's whole tooling-layer directory tree (git-mode-normalized:
only the execute bit is tracked, so checkout umask can't move the hash).
For chain step 0, `base_image_id` is the base image's resolved manifest
digest; for every step after it, `base_image_id` is the *previous step's*
content hash — never a docker-assigned image id (see the ADR's *chain*
amendment) or the **Base link** tag (see the ADR's issue-#98 amendment).
That makes the hash transitive: each step's hash
covers everything beneath it, so editing an early step invalidates every
step above it, and the whole chain's tags are computable without spawning a
process. The tag *is* the staleness check — there is no separate state file
recording "what was last built" to fall out of sync with the image store. A
hash hit reuses the already-ingested derived image with no rebuild and no
confirmation prompt; a hash miss (new project, or an edited
Dockerfile/layer file) prompts to build the whole chain unless `--yes` /
`$AGENT_VM_YES` is set. See `docs/adr/0003-project-tooling-layers.md`.

## Layer image contract

The eight clauses every **chain step**'s image must satisfy. Four are
enforced at build time against the *built image's* OCI config: C1 (builds on
its predecessor), C2 (keeps `PATH` additive), C3 (ends as root, final step
only), C4 (targets the host platform — its base-image and `--platform`
halves; see the ADR for what C4 does not cover). Four are documented-only,
because they would need every built layer decompressed: C5 (doesn't touch
agent-vm's own files), C6 (keeps `/bin/bash` and `/etc/passwd`/`/etc/group`
appendable), C7 (installs tools readable by any uid), C8 (advertises a
capability only when it works). A violation is a **hard error** (no opt-out),
and the offending image is discarded (best-effort; a failed discard is
reported alongside) so the next launch rebuilds and re-checks. The checks
live in `crates/agent-vm/src/layer/contract.rs`; the ADR is canonical (the
clauses, the grandfathering hole, what C4 omits).

_Avoid_: "Dockerfile contract" — only a layer's *final* stage is exported, so
`FROM ${BASE_IMAGE}` matters there; the checks are on built images.

## Boundary contract

A `verus!` block, in the module that owns a **pure** function whose decision is
a security boundary, a resource limit, or the parse of untrusted input,
carrying machine-checked `requires`/`ensures` and loop invariants. The rule for
when one is required, the **verified surface** (one row per site, naming exactly
what is proved), the **trusted boundary** (what the proved code calls and
trusts — `str::as_bytes`, `OsStr::len`, `url::Url::parse`, `anyhow` formatting,
the `String`/`Vec` assembly, every syscall), and the rule that a contract is
obtained by **extracting the decision, not the I/O**, are all
[ADR-0018](docs/adr/0018-machine-checked-boundary-contracts.md). A plain build
needs no Verus: the macro erases to ordinary Rust. CI verifies the contracts in
`.github/workflows/verus.yml`, gated and self-asserting (a run that verifies
nothing fails).

_Avoid_: "verified module" — the unit is the decision, not the module it lives
in; "contract test" — a test samples the input space, a contract is checked for
all inputs.

## Forked mount

A writable, project-scoped persistent mount initialized once from a host **directory**. After initialization, the fork and source are independent: changes do not propagate in either direction. A fork can optionally omit entries while seeding (`:fork:exclude=REL`); omissions are seed-only and are not a persistent guest access restriction. Files are never forked — a regular file is mounted read-only instead. A fork never copies a **Protected host file**, whatever the declaration says (see [ADR-0020](docs/adr/0020-protect-host-pi-credential-files.md)).

_Avoid_: "bind mount", which remains connected to the host path; "copy-on-write mount", which implies lazy shared backing storage.

## Protected host file

One of the two host Pi files agent-vm must never hand to a guest — `~/.pi/agent/auth.json` (credentials) and `~/.pi/agent/models.json` (provider configuration) — and the reason [ADR-0020](docs/adr/0020-protect-host-pi-credential-files.md) exists: Pi's imported host credentials are kept host-side and represented in the guest by placeholders (Pi's mixed credential ownership is an ADR in another workstream — see [#91](https://github.com/gregwebs/agent-vm/issues/91)/[#94](https://github.com/gregwebs/agent-vm/issues/94)), which a mount that exposed the file as a file would defeat. Reachability is decided by canonical **identity** (`(dev, ino)`) *and* component-wise canonical **containment**, never by lexical path matching alone; a live bind that would expose one is refused, and a fork omits it from the copy. The refusal's remedy depends on the root: `:fork` at or inside the Pi home, a narrower path *above* it, and nothing for a root that is the file itself. Whether an exposure is a refusal or an advisory depends on whether `$HOME/.pi` exists, and an unset `$HOME` does not lose the check — the home comes from the account record. The accepted gaps (a hardlink inside an unrelated live bind, a filesystem with unreliable inode identity, a copy the user made themselves) are named in the ADR.

_Avoid_: "masked file" — masks were removed by [ADR-0014](docs/adr/0014-narrow-fork-mounts-to-directories.md) and nothing is overlaid; "excluded" — `:exclude=REL` is a user-declared seed option, while this is an unconditional launch invariant.
