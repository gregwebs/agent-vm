# CONTEXT.md — domain vocabulary

Terms used consistently across code, comments, docs, and commit messages in
this repo. When a term below conflicts with something already in the code,
the code is the bug — file it, don't silently reintroduce the old name.
Mechanism and rationale live in [ARCHITECTURE.md](ARCHITECTURE.md) and
[docs/adr/](docs/adr/); this file defines the terms.

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
nothing is installed or built for it (that is a **tooling layer**).

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

## Tool

A validated **declarative tool definition** (`config::Tool`): a guest
`command`, its default `argv`, an optional **tooling layer**, a list of
**credential providers** (`credentials`, the requirement set), a list of
**available tools** (`tools`, driving the provisioning set), extra
guest-HOME-relative `persist` paths, a guest `env` map, an `interactive_shell`
flag, and the **tool config tier** it came from. A tool is **data**, not a
credential provider and not a command to execute on the host.

A tool *is* the launch verb: `agent-vm <name>` works because the resolved
configuration declares it. `env` is published into the guest **before** the
launcher's own environment and cannot override `PATH`, `IS_SANDBOX` or `LANG`;
`HOME`/`USER`/`LOGNAME` are **rejected** at the config seam in every mode. See
[ADR-0016](docs/adr/0016-tool-declared-guest-env.md).

### Launch catalog

The verbs a launch actually offers (`config::LaunchCatalog`): the resolved
merge result, plus the built-in `shell` appended when no declared tool claims
that name. The catalog resolves each entry's provisioning set before dispatch,
so `--help`, `doctor` and `run::launch` cannot disagree.

### Tool config tier

One of the two ordered, optional config files resolved by `config::load`: the
**user** tier (`$HOME/.config/agent-vm/config.toml`) or the **project** tier
(`<cwd>/.agent-vm/config.toml`). Each is parsed and validated independently
before merging. Their merge is a **union of whole definitions**, not a field
overlay: the user tier is authoritative for every name it declares, the
project tier may only add names, and a differing project declaration yields a
`doctor` warning (user definition wins). Only when both tiers declare **zero**
tools do the compiled-in defaults apply.

A load failure is **deferred**, not fatal at startup: `doctor`, the built-ins,
and the in-guest `clipboard`/`_intercept-hook` keep working, and a launch verb
reports the config error rather than clap's "unrecognized subcommand".

## Chain root

The published image reference a launch's chain builds `FROM` and boots when no
project tooling layer is declared — resolved by the pure
`tool_layer::chain_root`. It is one of: the **composed default image**
verbatim (fast path), the **base image** (when the declared tool-layer
sequence differs, or `--base-image` is given — both compose locally), or a
`--image` value booted verbatim. It is what `--update-check` probes and
`agent-vm pull` fetches (always a published tag, never a local
`agent-vm-layer:<hash>`). See
[ADR-0019](docs/adr/0019-tool-free-base-and-per-tool-layers.md).

_Avoid_: calling the chain root "the base image" — under the fast path it is the
composed default, not the base.

## Base image

The **tool-free** OCI base agent-vm composes from when a launch needs local tool
layers (`ghcr.io/wirenboard/agent-vm-base:latest`) — Debian 13 plus the docker
engine, diagnostic CLIs, and the tool-layer facilities, but **no agent CLI**.
Resolved via `--base-image` / `AGENT_VM_BASE_IMAGE` /
`defaults::DEFAULT_BASE_IMAGE_REF`. Distinct from the unqualified, Docker-local
`agent-vm-base:<hex>` links of **Base link**. See
[ADR-0019](docs/adr/0019-tool-free-base-and-per-tool-layers.md).

## Composed default image

The OCI **guest template** booted verbatim when the declared tool set equals
the shipped default (`ghcr.io/wirenboard/agent-vm-template:latest`): the base
plus the shipped **tool layers** chained in declaration order, published by CI
and never rebuilt locally. With no project tooling layers the launch performs
zero Docker calls.

## Tool layer

One tooling layer a catalog `[[tools]]` entry declares via `layer`: either
`{ builtin = "dsh"|"pi"|"codex"|"opencode"|"claude"|"copilot" }` (embedded from
`images/tools/`) or `{ path = "…" }` (anchored on the declaring config file's
directory). Resolved by `tool_layer::chain_root` → `tool_layer::materialize`.
Distinct from **Tooling layer**. See
[ADR-0019](docs/adr/0019-tool-free-base-and-per-tool-layers.md).

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

## Tooling layer

A `Dockerfile` (plus its build context) that adds project-specific tools `FROM`
the previous step in the chain. Not necessarily project-owned: a step is either
a catalog **tool layer**, a `.agent-vm/layers/` subdirectory, or a `--layer
DIR` directory. Every step's built image must satisfy the **Layer image
contract**. There is no environment-variable override — `$AGENT_VM_LAYER` is
rejected outright if set. See
[ADR-0003](docs/adr/0003-project-tooling-layers.md).

## Layer chain

The chain a launch builds, in order: the catalog's **tool layers**, then the
project's `.agent-vm/layers/*` (immediate subdirectories, sorted
byte-lexicographically by name), then each `--layer DIR` in command-line order.
Each step builds `FROM` the previous step (the **chain root** for step 0); only
the **final** step is ingested into the msb cache. `layer::plan_chain` computes
the chain's identities up front; `layer::execute_chain` drives the build. An
empty chain boots the chain root with no build. A leftover singular
`.agent-vm/layer/` is a hard migration error naming the path. See
[ADR-0003](docs/adr/0003-project-tooling-layers.md).

## Derived image

Chain root + the **whole layer chain**, built one `docker buildx build` per
step, tagged `agent-vm-layer:<project-slug>-<hash>`, and booted in place of the
chain root whenever the project declares a chain. Ingested **registry-lessly**
via `microsandbox_image::load_archive`. Only the final step is the derived
image proper and only it is subject to the **Layer image contract**'s clause
C3 ("ends as root"); C1/C2/C4 apply to every built step.

## Layer identity / hash

The content hash `layer::resolve` computes over a step's `base_image_id` plus
that step's whole tooling-layer directory tree (git-mode-normalized). For chain
step 0, `base_image_id` is the base's resolved manifest digest; for every step
after it, the *previous step's* content hash — never a docker-assigned image id
or the **Base link** tag. The hash is transitive, so the tag itself is the
staleness check: there is no separate state file recording what was last built.
See [ADR-0003](docs/adr/0003-project-tooling-layers.md).

## Layer image contract

The eight clauses every **chain step**'s built image must satisfy. Four are
enforced at build time against the built image's OCI config: C1 (builds on its
predecessor), C2 (keeps `PATH` additive), C3 (ends as root, final step only),
C4 (targets the host platform). Four are documented-only: C5 (doesn't touch
agent-vm's own files), C6 (keeps `/bin/bash` and `/etc/passwd`/`/etc/group`
appendable), C7 (installs tools readable by any uid), C8 (advertises a
capability only when it works). A violation is a **hard error** (no opt-out),
and the offending image is discarded so the next launch rebuilds and re-checks.
[ADR-0003](docs/adr/0003-project-tooling-layers.md) is canonical.

_Avoid_: "Dockerfile contract" — only a layer's *final* stage is exported, and
the checks are on built images.

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
