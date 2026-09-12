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

Which tool needs which provider is a **code** fact today and becomes
**configuration** in #80/#82, where the config name is `anthropic` / `openai`
/ `opencode-static` / `copilot` (`CredentialProvider::config_name`). A
**Tool** (#82's term) is a resolved command carrying a provider set; do not
call a provider a "tool" or "agent".

The legacy gating is **asymmetric**: `Anthropic`/`OpenAi` capture runs on
*every* launch regardless of the selected tool, and the claude/codex/opencode
bypass configs are written unconditionally (`Scope::Always`). This is
preserved behaviour, not a design goal — narrowing it belongs to #82, which is
why each cell is an explicit `Scope`/`CaptureScope` field rather than an
inference from the selected set. `Copilot` is the one provider the proxy only
registers when it is selected.

**GitHub egress is not a provider.** The `gh` token is gated by `--no-git` /
detected repos, orthogonal to the launched tool, so it has no
`CredentialProvider` variant; `credential_injection` keeps its own block and
splices it into the proxy's fixed `WIRE_ORDER`.

_Avoid_ the `doctor_label` (`claude` / `codex` / `opencode` / `copilot`) as the
provider's name: the label names the host CLI that owns the file (retained so
`agent-vm doctor` output stays byte-identical), while the config name for
OpenCode is `opencode-static`. A user copying `opencode` out of `agent-vm
doctor` into `credentials = [...]` is rejected by #80's validator.

_Not the same as_ `OpencodeApiProvider`: that is a *dynamic*,
user-populated BYO-API-key row inside OpenCode's `auth.json`, not a
compiled-in subsystem.

### Guest home link

A `(home_relative, state_relative)` pair mapping a guest `$HOME` dotfile to an
entry under the per-project state dir (`credential_provider::HomeLink`).
Provider-owned links come first, in `CredentialProvider::ALL` order, then the
`GENERIC_HOME_LINKS` that no provider owns (`.gitconfig`, `.config/gh`,
`.bash_history`). Both guest-user modes consume the single
`credential_provider::guest_home_links()` list, so root mode's `.patch()`
symlinks and non-root mode's host-side provisioning cannot drift (ADR-0002).

## Base image

The OCI **guest template** agent-vm boots inside each per-project microVM
(default `ghcr.io/wirenboard/agent-vm-template:latest`) — Debian plus the
in-VM coding agents (Claude Code, Codex CLI, OpenCode). "Base image" and
"guest template" name the same thing; use "base image" in code and docs that
also talk about tooling layers, since it is the base a layer builds `FROM`.
Resolved via `--image` / `AGENT_VM_IMAGE_TAG` / `defaults::DEFAULT_IMAGE_REF`
(`run.rs`'s `base_image` binding). msb's resolved per-platform **manifest
digest** is authoritative: it is step 0's hash input and what boot resolves,
even when Docker needs a separate build-time name for the same base (see
**Base link**). See `docs/adr/0003-project-tooling-layers.md`.

## Base link

The Docker-local name `agent-vm-base:<manifest-digest-hex>` for an msb-cached
base image — what buildx's step-0 `FROM` resolves, created by
`script/build/import-image.sh` at import time (or, for a registry base, by a
build-time `docker pull <repo>@<digest>` + `docker tag`). It is the *bridge*
between the two image stores, not a second identity: the manifest digest stays
step 0's hash input, and the link is never consulted on a cache-hit launch
(which spawns no Docker process). See
`docs/adr/0003-project-tooling-layers.md`'s issue-#98 amendment.

## Tooling layer

A `Dockerfile` (plus its build context — the rest of that directory) that
adds project-specific tools `FROM` the previous step in the chain:
compilers, cross-toolchains, anything the base doesn't carry. Not
necessarily project-owned: a step is either a `.agent-vm/layers/` subdirectory
of the project, or a `--layer DIR` directory anywhere else on disk. A
single tooling layer is one step of a "layer chain" (see below); resolved by
`layer::resolve_layer_chain`. There is no environment-variable override —
`$AGENT_VM_LAYER` is rejected outright if set — but there is composition: the
chain is the project's own `.agent-vm/layers/*/` steps, then any `--layer
DIR` values (repeatable, appended after, never prepended). Every step's
built image must satisfy the **Layer image contract**. See
`docs/adr/0003-project-tooling-layers.md`.

## Layer chain

The project's tooling layers plus any `--layer` flags, in build order: the
immediate subdirectories of `.agent-vm/layers/`, sorted byte-lexicographically
by directory name (`10-toolchain` before `20-chrome`), then each `--layer DIR`
in command-line order. Each step builds `FROM` the previous step (the base
image for step 0); only the **final** step is ingested into the msb cache —
intermediates live in docker's own local image store, pinned for the next
step by tag. `layer::plan_chain` computes the whole chain's identities up
front (pure, no I/O beyond hashing); `layer::execute_chain` drives the build.
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

## Forked mount

A writable, project-scoped persistent mount initialized once from a host file or directory. After initialization, the fork and source are independent: changes do not propagate in either direction.

_Avoid_: "bind mount", which remains connected to the host path; "copy-on-write mount", which implies lazy shared backing storage.
