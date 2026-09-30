# CONTEXT.md — domain vocabulary

Terms used consistently across code, comments, docs, and commit messages in
this repo. When a term below conflicts with something already in the code,
the code is the bug — file it, don't silently reintroduce the old name.
Mechanism and rationale live in [ARCHITECTURE.md](ARCHITECTURE.md) and
[docs/adr/](docs/adr/); this file defines the terms.

## Launcher

The **host-side** `agent-vm` process for a single launch: it resolves the
**catalog**, picks the **composition root**, acquires or composes the image,
plumbs credentials and mounts, builds the guest env and the in-guest prelude,
then hands the sandbox config to microsandbox and supervises the session
(`run.rs`). It is the host half of the pair whose other half is the **in-guest**
side (`intercept_hook`, agentd).

_Avoid_: using it for the image builder alone (that is the **Layer DAG**, one
phase of what the launcher does); for the `agent-vm` binary in its
non-launching verbs (`doctor`, `pull`, `setup`), which share the binary but
launch nothing; or for microsandbox.

## Guest user

The numeric `uid:gid` the in-guest agent process runs as. `.user(...)` is set
in two places (`run.rs`), both load-bearing: on the **sandbox builder**, driving
agentd's `InitResolved.default_user` and passthroughfs's `BindIdentityMap`
owner bits; and on the **per-exec attach/exec builders**, governing the
`setuid` of the exec'd process (agentd stays root so it *can* `setuid`).

**Default: the host user** (`libc::getuid()`/`getgid()`). Matching the host uid
is what makes passthroughfs grant owner bits on the project/state binds, and it
puts a non-root barrier inside the microVM. See
[ADR-0001](docs/adr/0001-non-root-guest-via-native-user.md) and **Root mode**.

_Avoid_: "dev user", "container user" — this isn't a fixed image account,
it's whichever uid launched `agent-vm`.

## Guest username

The **cosmetic** name attached to the guest user's numeric uid — what
`whoami`/`$USER`/the shell prompt show. Distinct from **Guest user** (the
access-control identity): a username mismatch doesn't change file access.
Resolved env-first in `run.rs`: `$USER` → `$LOGNAME` → the passwd-DB name for
the uid → the numeric uid as a string, each non-numeric candidate
charset-checked. See
[ADR-0002](docs/adr/0002-mirror-host-home-and-username.md).

## Root mode

The opt-out, enabled by `--root` or a truthy `AGENT_VM_ROOT` (the shared
`env_flag` parser, like every value-parsing boolean `AGENT_VM_*`). Runs the
guest as uid 0 with `HOME=/root`. Required for docker-in-VM; when the Chrome
DevTools layer is installed, its MCP uses the `sudo -u chrome` path only in
this mode.

_Avoid_: "privileged mode" — the microVM boundary applies identically in
both modes; root mode only changes the *in-guest* uid.

## Guest HOME

The in-guest `$HOME` for the current mode. **Non-root (default):** the
mirrored host `$HOME` path — a real bind mount of `<state_dir>/home`,
provisioned host-side by `ProjectSession::provision_guest_home`; mirroring the
literal host path keeps `$HOME`-relative paths interpretable on the host.
**Root:** `/root`, with dotfile symlinks baked by `run.rs`'s `.patch()` block.
Both modes consume the single `credential_provider::guest_home_links()` mapping
so they cannot drift. See
[ADR-0002](docs/adr/0002-mirror-host-home-and-username.md).

`~/.pi` is project-scoped persistent state at `/agent-vm-state/pi` in both
modes (see **Guest home link**). A **Guest-managed Pi credential** is one
created inside the guest and persisted there; a **Known placeholder** is an
exact agent-vm placeholder constant (whole-value match, not a prefix), which
the launch scanner stays quiet about. See
[ADR-0011](docs/adr/0011-pi-mixed-credential-ownership.md).

## Private MSB_HOME

The private Microsandbox home agent-vm points `msb` at:
`<state_root>/msb-home` — a single flat directory, shared by every agent-vm
build on the host under a given `$AGENT_VM_STATE_DIR`, never namespaced by
schema. Because sea-orm migrations are one-way, two builds with different
schemas sharing it can collide; `msb_preflight` turns that into a named,
recoverable stop (`agent-vm doctor --reset-msb-db`) rather than namespacing it
away structurally. See
[ADR-0004](docs/adr/0004-single-shared-msb-home.md).

_Avoid_: bare "MSB_HOME" when the private-vs-shared distinction matters —
`MSB_HOME` is the env var, and the shared `~/.microsandbox` a separately
installed `msb` uses is a different thing agent-vm deliberately does not point
at (except the opt-in cache share); and when schema-scoping matters — the
schema home is the concept, the env var just points at it.

## Credential shielding

The explicitly authorized use of a credential on behalf of an untrusted guest
without exposing the credential's real value to that guest. This is not general
secret detection or control of account usage; usage limits and detection belong
to the remote credential issuer.

_Avoid_: "credential masking", which can be confused with output redaction or
file masking.

## Credential source

A host-side location from which a credential value is obtained, such as a named
environment variable or a system keychain item. Its identity is distinct from
the secret value, which can rotate without changing the source.

## Credential authorization

A user's permission to use a credential source at specified HTTPS destinations
and in specified request headers. It is host-wide, not project-scoped;
a project may request its use but cannot confer or broaden that permission.

_Avoid_: "grant", when referring to this permission.

## Credential request

A tool or project's declaration that it needs an authorized credential and where
its guest-facing placeholder should appear. A request is not authorization.

## Authorized credential

A **credential authorization** in effect: a named **secret store** service, the
exact HTTPS origin it may be sent to, and the exact request header it may occupy,
as declared in `~/.config/agent-vm/credentials.yaml`. It is host-wide and
user-owned; a **credential request** can name one but cannot bring one into
effect. Storing a value at the same service is not an authorization.

_Avoid_: "the credential" (that is the value), or "configured credential" (a
request is also configuration).

## Replaced provider

A **built-in credential provider** whose credential handling a same-named
**authorized credential** has taken over for one launch: acquisition, guest
placeholder, proxy injection and OAuth capture/refresh all come from the
authorization instead. The provider's guest configuration and persisted state
(onboarding bypass files, Copilot's `trusted_folders`, `$HOME` symlinks, state
directories) are untouched — a credential authorization does not speak for them.
There is no fallback to the built-in when the authorization is unavailable.

Because replacement is a *name* fact, `agent-vm doctor` reports it for the whole
configured catalog without being told which verb is about to run: a provider a
verb requests is replaced for that verb, and the host-credential row names the
verbs (#178).

_Avoid_: "overridden provider" (an override suggests a fallback; there is none).

## Header credential

The runtime's durable form of an authorized credential: a non-secret
`(id, reference, origin, header, format)` record with **no value field**. The
value is resolved separately, host-side, immediately before the sandbox process
is forked, and travels only on the runtime's private launch-config descriptor. A
**header credential** is what appears in the sandbox config; a plaintext value
never does.

## Sentinel

The non-secret placeholder published to a guest environment variable when an
authorization sets `sentinelEnv: true`. It is `proxy-managed` (Docker's literal)
and carries no substitution authority: the real value is substituted host-side
into the authorized request header, so the sentinel's only job is to make the
guest's variable non-empty and obviously not a credential. It is unrelated to
the built-in providers' structurally valid JWT placeholders.

_Avoid_: "placeholder" unqualified, which in this repo also means those built-in
provider placeholders and the `!command` credential sentinels.

## Secret store

agent-vm's own namespace in the **host OS credential store** (macOS Keychain,
Linux Secret Service): the reverse-DNS service name `dev.agent-vm.credentials`,
under which every `agent-vm secret set` entry is an account named by the
folded service name. Distinct from Docker's `com.docker.sandboxes` namespace and
from microsandbox's own `dev.microsandbox.registry` entry, which agent-vm
neither reads nor writes. Host-wide, not project-scoped: every agent-vm process
on the machine addresses the same entries regardless of state dir.

_Avoid_: "keychain" unqualified, which is both the macOS product and the
cross-platform concept; and "vault", which implies a different storage model.

## Secret inventory

The **non-secret**, user-scoped record of which service names agent-vm has
stored — `~/.config/agent-vm/secret-inventory.json`, names only, never bytes. It
exists because the OS credential store is a key→value lookup with no portable
enumeration API, so `agent-vm secret ls` probes one name per recorded entry. It
is explicitly **not** an authorization list: storing a value does not authorize
its use, and deleting the inventory loses only the listing, never a stored
value. Its scope is user-scoped rather than state-scoped because the secret
store it describes is host-wide.

_Avoid_: "credential list", "allowlist", or any wording that reads as
permission.

## Credential provider

A **compiled-in credential subsystem** a launched tool can depend on. The four
variants are `Anthropic`, `OpenAi`, `OpencodeStatic`, and `Copilot`
(`crates/agent-vm/src/credential_provider.rs`). A provider owns everything
needed to be signed in: its host credential file, placeholders, eager state
dir, guest-HOME links, first-run bypass config, guest env, proxy
secret/routes, and — for `Anthropic`/`OpenAi` — the OAuth-rotation facts the
interception hook reads.

Which tool needs which provider **is configuration**: a tool names providers
(`anthropic` / `openai` / `opencode-static` / `copilot`,
`CredentialProvider::config_name`), and `Tool::credential_providers` turns that
into the `ProviderSet` the launch treats as the **requirement** set. The only
guest env a provider owns is `COPILOT_GITHUB_TOKEN` (Copilot, and only when the
launch provisions Copilot *and* captured its token); `CODEX_HOME` names
codex-the-tool's config dir and is a tool fact
([ADR-0016](docs/adr/0016-tool-declared-guest-env.md)).

Every provider-owned facet is gated on one predicate: the launch's
**provisioning set**. There is no per-facet scope. See
[ADR-0017](docs/adr/0017-tool-declared-provisioning.md).

**GitHub egress is not a provider.** The `gh` token is gated by `--no-git` /
detected repos, orthogonal to the launched tool; `credential_injection` keeps
its own block and does not feed any provider's capture.

_Avoid_ the `doctor_label` (`claude` / `codex` / `opencode` / `copilot`) as the
provider's name: the label names the host CLI that owns the file, while the
config name for OpenCode is `opencode-static`. A user copying `opencode` out
of `agent-vm doctor` into `credentials = [...]` is rejected.

_Not the same as_ `OpencodeApiProvider`: a *dynamic*, user-populated BYO-API-key
row inside OpenCode's `auth.json`, not a compiled-in subsystem.

### Required credential providers

The providers a tool names in `credentials = [...]`. This is the
**requirement** set: a launch hard-fails before boot when one yields no usable
host credential (`credential_provider::missing_credential_error`). It is a
subset of the provisioning set, and **equal** to it whenever the tool declares
no `tools` — the common case (five of the seven shipped verbs; `pi` and `shell`
are the two whose provisioning set is wider).

### Available tools

The catalog tools a tool names in `tools = [...]`: the tools it wants
**available in its guest**. They name *tools*, never credential providers.
`["*"]` — which must be the sole entry, and is the default for a tool named
`shell` — closes over the tools declared in the **same configuration file** as
the declaring tool, not the merged catalog. A tool in a *different* file is
reachable only by **naming it explicitly**. An omitted `tools` is `[]` for
every other name. A name no catalog tool provides is a hard config error.

_Avoid_: "dependencies" — a named tool is provisioned, not required, and
nothing is installed or built for it (that is a **Layer** with a `command`).

### Provisioning set

Everything one launch provisions: the least fixed point of

    provisioning(t) = credentials(t) ∪ ⋃ { provisioning(u) | u ∈ tools(t) }

over the launch catalog, where a `"*"` entry expands to the declaring tool's
own configuration file. It is the **single** gate on every provider-owned
facet, and the same closure also folds the tools' `persist` paths into
guest-HOME links. A cycle is a fixed point, not an error. See
[ADR-0017](docs/adr/0017-tool-declared-provisioning.md).

_Avoid_: "the selected tool's providers" / "when selected". Gating is
membership in the provisioning set, which is not the launched tool's own
`credentials`.

### Guest home link

A `(home_relative, state_relative)` pair mapping a guest `$HOME` dotfile to an
entry under the per-project state dir (`credential_provider::HomeLink`).
Provider-owned links come first, then the `GENERIC_HOME_LINKS` no provider
owns, then one per `persist` path in the provisioning closure. Both guest-user
modes consume the single `guest_home::links` list. `LinkSource` marks
compiled-in vs config-declared: only a **declared** link may replace real
content by migrating it; root mode force-symlinks both. The compiled `.pi`
link is a **bounded exception**: `ProjectSession::migrate_legacy_pi_home` runs
one named, deletable one-shot move of a pre-#96 real `<state>/home/.pi` into
`<state>/pi` before provisioning
([ADR-0021](docs/adr/0021-project-scoped-pi-home-and-wrapper-parity.md)).

## Catalog

The resolved, validated model of a configuration's declared **Layers** — what
`config::load` produces, as one value so the catalog and a deferred
configuration error cannot disagree about which state the process is in:
`Catalog::Ready(LaunchCatalog)` or `Catalog::Broken(err)`. It is built from the
**tool config tiers** (user, then project), merged as a union of whole
definitions, and falls back to the compiled-in catalog when both tiers declare
zero layers. It is **not** the config files themselves.

_Avoid_: bare "catalog" when the distinction matters — say **declared layer
catalog** for the resolved `[[layers]]` entries alone, and **Launch catalog**
for those entries plus each one's resolved provisioning set plus the built-in
`shell` fallback. The bare word must never stand in for a config file.

## Layer

One validated catalog entry (`config::Layer`) in a `[[layers]]` section: a
`name`, a `layer` source — `{ builtin = "dsh"|"pi"|"codex"|"opencode"|"claude"|"copilot" }`
embedded from `images/tools/`, or `{ path = "…" }` anchored on the declaring
config file's directory — an optional `parent`, an optional guest `command`,
and the tool fields below. Every entry contributes to the image; an entry with a
`command` also offers a launch verb. Layers are **declared, never discovered**:
there is no `.agent-vm/layers/` convention, and `--layer DIR` injects one at the
command line. Stitch order is **derived from `parent`**; declaration order only
breaks ties among layers the graph does not order. Resolved by
`tool_layer::chain_root` → `tool_layer::materialize`. See
[ADR-0032](docs/adr/0032-one-layer-kind.md).

_Avoid_: tooling layer, step, chain — one kind of thing now replaces them.

## Tool

A **Layer** that has a `command`, and therefore a launch verb: `agent-vm
<name>` works because the resolved configuration declares it. A layer with no
`command` contributes to the image and offers no verb. A tool is **data**, not a
credential provider and not a command to execute on the host.

It also carries its default `argv`, a list of **credential providers**
(`credentials`, the requirement set), a list of **available tools** (`tools`,
driving the provisioning set), extra guest-HOME-relative `persist` paths, a
guest `env` map, an `interactive_shell` flag, and the **tool config tier** it
came from.

`env` is published into the guest **before** the launcher's own environment and
cannot override `PATH`, `IS_SANDBOX` or `LANG`; `HOME`/`USER`/`LOGNAME` are
**rejected** at the config seam in every mode. See
[ADR-0016](docs/adr/0016-tool-declared-guest-env.md). Decided, not yet built:
the same launcher-owned keys are rejected on layer declarations, and two
unrelated layers may not declare different values for one key
([ADR-0032](docs/adr/0032-one-layer-kind.md)).

### Launch catalog

The verbs a launch actually offers (`config::LaunchCatalog`): the resolved
merge result, plus the built-in `shell` appended when no declared tool claims
that name. The catalog resolves each entry's provisioning set before dispatch,
so `--help`, `doctor` and `run::launch` cannot disagree. One arm of
**Catalog**; see that entry for the declared-layer side.

### Tool config tier

One of the two ordered, optional config files resolved by `config::load`: the
**user** tier (`$HOME/.config/agent-vm/config.toml`) or the **project** tier
(`<cwd>/.agent-vm/config.toml`). Each is parsed and validated independently
before merging. Their merge is a **union of whole definitions**, not a field
overlay: the user tier is authoritative for every name it declares, the
project tier may only add names, and a differing project declaration yields a
`doctor` warning (user definition wins). Only when both tiers declare **zero**
layers do the compiled-in defaults apply.

A load failure is **deferred**, not fatal at startup: `doctor`, the built-ins,
and the in-guest `clipboard`/`_intercept-hook` keep working, and a launch verb
reports the config error rather than clap's "unrecognized subcommand".

## Composition root

The image a launch's layers build `FROM` — resolved by the pure
`tool_layer::chain_root`. It is one of: the **composed default image** booted
verbatim and with zero Docker calls, when no layer beyond the shipped set is
declared; the **base image** plus the declared layers, stitched locally, when
any layer beyond the shipped set is declared or `--base-image` is given; or a
`--image` value booted verbatim. It is what `--update-check` probes and
`agent-vm pull` fetches (always a published tag, never a local
`agent-vm-layer:<hash>`). See
[ADR-0019](docs/adr/0019-tool-free-base-and-per-tool-layers.md); renamed from
**Chain root** and extended to every layer by
[ADR-0032](docs/adr/0032-one-layer-kind.md).

_Avoid_: calling the composition root "the base image" — under the fast path it
is the composed default, not the base.

## Base image

The **tool-free** OCI base agent-vm composes from when a launch needs local
layers (`ghcr.io/wirenboard/agent-vm-base:latest`) — Debian 13 plus the docker
engine, diagnostic CLIs, and the tool-layer facilities, but **no agent CLI**.
Resolved via `--base-image` / `AGENT_VM_BASE_IMAGE` /
`defaults::DEFAULT_BASE_IMAGE_REF`. Distinct from the unqualified, Docker-local
`agent-vm-base:<hex>` links of **Base link**. See
[ADR-0019](docs/adr/0019-tool-free-base-and-per-tool-layers.md).

## Composed default image

The OCI **guest template** booted verbatim when the declared layer set equals
the shipped default (`ghcr.io/wirenboard/agent-vm-template:latest`): the base
plus the shipped layers **stitched** in the order their `parent` declarations
derive, published by CI and
never rebuilt locally. With no layer declared beyond the shipped set the launch
performs zero Docker calls.

## Parent

What a layer builds `FROM`: the **composition root**, or the one layer it
explicitly declares. Its **layer image**'s own layers are the ones above its
parent, which is what makes a layer's identity independent of its position and
what stitch order is derived from.
_Avoid_: predecessor (that is a chain position).

## Layer image

One layer built `FROM` its parent. Its identity covers its parent, its build
context and the build args passed (including its version), and does not depend
on its position or on which other layers a launch declares. See
[ADR-0030](docs/adr/0030-tool-versions-in-identity-and-current-tags.md) and
[ADR-0032](docs/adr/0032-one-layer-kind.md).

_Avoid_: tool image — the tool-image ADRs predate one-kind layers; say layer
image.

## Current tag

A movable name in the shared OCI layout for the tool image the upgrade command
last built for a tool. A layer that is not a tool has no current tag: version
resolution is a tool-image concept. A launch reads that image's version labels, not the image
itself, so the upgrade carries onto a new base. Dropped when the tool's shipped
build context changes. An exact `version` in the tool's config outranks it. See
[ADR-0030](docs/adr/0030-tool-versions-in-identity-and-current-tags.md).
_Avoid_: lockfile, latest tag.

## Stitching

Joining layer images into one composed image by appending each layer's own
layers onto the **composition root**'s, in the order the layers' `parent`
declarations derive, without building
anything. See
[ADR-0029](docs/adr/0029-compose-tool-images-by-layer-stitching.md).
_Avoid_: merge, flatten, squash.

## Composed tool image

The **composition root** plus one launch's layers, joined by stitching. The
**composed default image** is the composed image for the shipped layer set.

## Tool image contract

The clauses every **layer image** must satisfy against its **parent**, checked
once when it is built (T1–T7). A violation is a hard error, and the layer image
is never recorded. [ADR-0031](docs/adr/0031-tool-image-contract.md) is
canonical; [ADR-0032](docs/adr/0032-one-layer-kind.md) widens T2 to admit
non-`PATH` config (merged in stitch order, last wins) and exempts the launcher's
generated account layer from T3. The name is kept for continuity although it
govers every layer, not only tools.

_Avoid_: merged-image contract (nothing is merged).

## Stitch check

A check across the layers being stitched into one composed image: no file
written by two layers when neither is the other's parent (**S1**), no layer's
command shadowed by another's (**S2**), and — new in
[ADR-0032](docs/adr/0032-one-layer-kind.md) — no **S4** env collision, meaning
two unrelated layers may not declare different values for one config key. See
[ADR-0031](docs/adr/0031-tool-image-contract.md).

## Rebased composition

A composed image using a new base with existing installed layer artifacts,
retaining their original build-parent provenance. Its identity is distinct from
those artifacts and includes the destination base and the artifacts used; a
rebuild instead produces artifacts built against the new parent. See
[ADR-0033](docs/adr/0033-default-rebase-with-build-provenance.md).

## Image-owned Pi package

A pinned Pi extension the image installs as a real npm project root under
`/opt/agent-vm/pi-packages/` and activates with an explicit wrapper
`--extension` — as opposed to a bare `.js` file under
`/opt/agent-vm/pi-extensions/`, or a package Pi manages itself in per-project
guest state. Invisible to `pi list` / `pi update`. See
[ADR-0023](docs/adr/0023-image-owned-pi-extension-packages.md).

## Base link

The Docker-local name `agent-vm-base:<manifest-digest-hex>` for an msb-cached
base image — what buildx's step-0 `FROM` resolves, created by
`script/build/import-image.sh` at import time (or, for a registry base, by a
build-time `docker pull <repo>@<digest>` + `docker tag`). It is the *bridge*
between the two image stores, not a second identity: the manifest digest stays
step 0's hash input, and the link is never consulted on a cache-hit launch.

## Layer DAG

The graph a launch builds: the declared catalog's **layers**, each an
independent build `FROM` its **parent** (the **composition root**, or a layer it
declares), joined into the **derived image** by **stitching** in an order
**derived** from the `parent` relation — repeatedly place the earliest-declared
layer whose ancestors are all placed. Declaration order is therefore only a
**tie-break among layers the graph does not order** (roots, and siblings under
one parent), and a child may be declared above its parent. A `parent` naming a
layer outside the composition, or a cycle, is a hard error. Every layer image's
**tool image contract** is checked when it is built; the **stitch check**s run
across the set. `layer::plan_chain` computes the identities up front;
`layer::execute_chain` drives the builds. A launch that declares no layer beyond
the shipped set builds nothing and boots the composition root. A **`--layer
DIR`** step declares no parent, so it is a root and command-line order is its
tie-break; it carries no provenance into its identity. There is no discovery: a
leftover `.agent-vm/layers/` directory is a hard migration error naming the
entries to declare instead. See [ADR-0032](docs/adr/0032-one-layer-kind.md).

_Avoid_: chain, step, predecessor — they name the position model the DAG
replaced. An order-**dependent** layer is expressible by declaring `parent`.

## Derived image

The **composition root** plus every declared layer, stitched into one manifest
and tagged `agent-vm-layer:<project-slug>-<hash>`. It is the only image ingested
(**registry-lessly**, via `microsandbox_image::load_archive`) and the only one
booted whenever a layer is declared. Its identity is
`hash(composition root identity, ordered layer identities)` — order enters here
and only here, because order is the manifest's layer order. See
[ADR-0032](docs/adr/0032-one-layer-kind.md).

## Layer identity / hash

The content hash `layer::resolve` computes over a layer's `base_image_id` plus
its whole build-context directory tree (git-mode-normalized). `base_image_id`
is always the **parent's** identity — the **composition root**'s for a layer
that declares none — never a docker-assigned image id or the **Base link** tag.
A layer's identity is therefore independent of its position and of where it was
declared. The hash is computed, not read from the stitched manifest, so the tag
is itself the staleness check: there is no separate state file recording what
was last built, and a cache-hit launch needs no Docker. See
[ADR-0032](docs/adr/0032-one-layer-kind.md). Decided, not yet built: a layer
image's identity also covers the build args passed, so it names the versions
installed, not only the inputs' files
([ADR-0030](docs/adr/0030-tool-versions-in-identity-and-current-tags.md)).

## Declared account

A user or group a **Layer** declares in config (`users` / `groups`) instead of
its `Dockerfile` appending to `/etc/passwd`, `/etc/group` or `/etc/shadow`.
Declaring a user auto-creates a same-named group with its gid when nothing else
claims it. The launcher generates **one append-only account layer** carrying the
union of every declared account, placed in the **composition root** below every
layer, so an account exists both during a layer's own build (`sudo -u`, a
pre-warm) and in the booted guest. Collisions are hard errors — declared vs
declared and vs the runtime host identity at plan time, vs the base image inside
the generated stage's own build. Decided, not yet built
([ADR-0032](docs/adr/0032-one-layer-kind.md)).

## Layer image contract

**Retired name** ([ADR-0032](docs/adr/0032-one-layer-kind.md)). It named
[ADR-0003](docs/adr/0003-project-tooling-layers.md)'s eight clauses (C1–C8) for
project tooling layers, which no longer exist as a kind. Every layer image is
govered by the **tool image contract** instead. Kept here so older notes and
ADRs citing it still resolve.

## Boundary contract

A `verus!` block, in the module that owns a **pure** function whose decision is
a security boundary, a resource limit, or the parse of untrusted input,
carrying machine-checked `requires`/`ensures` and loop invariants. The rule for
when one is required, the **verified surface** (one row per site, naming what is
proved), the **trusted boundary** (what the proved code calls and trusts), and
the rule that a contract is obtained by **extracting the decision, not the
I/O**, are all
[ADR-0018](docs/adr/0018-machine-checked-boundary-contracts.md). A plain build
needs no Verus: the macro erases to ordinary Rust. CI verifies the contracts in
`.github/workflows/verus.yml`, gated and self-asserting (a run that verifies
nothing fails).

_Avoid_: "verified module" — the unit is the decision, not the module it lives
in; "contract test" — a test samples the input space, a contract is checked for
all inputs.

## Forked mount

A writable, project-scoped persistent mount initialized once from a host
**directory**. After initialization, the fork and source are independent; a
fork can omit entries while seeding (`:fork:exclude=REL`), never copies a
**Protected host file**, and files are never forked (a regular file is a
read-only bind). See
[ADR-0013](docs/adr/0013-add-forked-mounts.md) and
[ADR-0014](docs/adr/0014-narrow-fork-mounts-to-directories.md).

_Avoid_: "bind mount", which remains connected to the host path; "copy-on-write
mount", which implies lazy shared backing storage.

## Protected host file

One of the two host Pi files agent-vm must never hand to a guest —
`~/.pi/agent/auth.json` and `~/.pi/agent/models.json`. A live bind that would
expose one is refused; a fork omits it from the copy. Reachability is decided
by canonical **identity** (`(dev, ino)`) and component-wise canonical
**containment**, never lexical path matching alone. See
[ADR-0020](docs/adr/0020-protect-host-pi-credential-files.md).

_Avoid_: "masked file" — masks were removed by
[ADR-0014](docs/adr/0014-narrow-fork-mounts-to-directories.md) and nothing is
overlaid; "excluded" — `:exclude=REL` is a user-declared seed option, while
this is an unconditional launch invariant.
