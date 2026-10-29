# CONTEXT.md — domain vocabulary

Terms used consistently across code, comments, docs, and commit messages in
this repo. When a term below conflicts with something already in the code,
the code is the bug — file it, don't silently reintroduce the old name.
Mechanism and rationale live in [ARCHITECTURE.md](ARCHITECTURE.md) and
[docs/adr/](docs/adr/); this file defines the terms.


## Launcher

The **host-side** `agent-vm` process for a single launch: it resolves the
**catalog**, selects the **boot image**, acquires it, plumbs credentials and
mounts, builds the guest env and the in-guest prelude, then hands the sandbox
config to microsandbox and supervises the session (`run.rs`). It is the host
half of the pair whose other half is the **in-guest** side (`intercept_hook`,
agentd).

_Avoid_: using it for the image builder alone (the launcher consumes finished images; `agent-vm image` builds/imports
them without launching a tool); for the `agent-vm` binary in its non-tool-launching
verbs (`doctor`, `setup`, `image`), even though setup can boot a verification
guest; or for microsandbox.

## Launch option

An `agent-vm` flag that configures a launch (`--mount`, `--image`, `-p`,
`--no-config-mounts`, …).
Written before the route: `agent-vm --mount ~/ref pi`, or `agent-vm --mount
~/ref run make test`. The routes a launch option may precede are the catalog
tool verbs and the [direct command](#direct-command) runner (including its
top-level `--` spelling). Built-in verbs (`setup`, `doctor`, …) take their own
flags after the verb and accept no launch options. Nested image operations take
flags after the subcommand: `agent-vm image refresh --image REF`.

## Tool argument

An argv token after the tool verb. Forwarded to the tool verbatim — including
`--help` and `--` — and never interpreted by `agent-vm`.

## Direct command

A guest executable and its argv launched without a catalog entry:
`agent-vm [launch options] run PROGRAM [ARG...]`, or the equivalent
`agent-vm [launch options] -- PROGRAM [ARG...]`. The program name is looked up
in the guest (or used as an explicit path); its arguments are literal, with no
expansion, splitting, deduplication or catalog defaults. A direct command has
**no target entry**, so no catalog-declared command, environment, credential
request, network request or persist link applies. Distinct from a *shell
launch*: the `shell` fallback is a catalog entry with its own command and argv,
which a direct command neither selects nor inherits. Direct statuses: 127 for an
absent executable, 126 for a non-executable one, 125 for the launcher's own
ordinary failure.

## Direct terminal policy

Which I/O mode a direct command runs with, decided before boot: `Pty` (a guest
terminal — merged output, forwarded input and resizes, no detach mode, so
`Ctrl-]` is guest input) or `Stream` (separate guest stdout/stderr with
[reserved input](#reserved-input)). Auto selects a PTY only when **both** host
stdin and stdout are terminals; `--tty`/`-t` forces a PTY and requires terminal
stdin, `--no-tty`/`-T` forces streaming. Resolved once in dispatch and carried by
the launch target, because a bootstrap rendered for one mode must never be
executed by the other. Distinct from a *shell launch*, whose PTY choice, detach
escape and merged output are its own unchanged behavior.
_Avoid_: calling the policy a heuristic — it reads descriptors, never the command
name, `$TERM` or `/dev/tty`.

## Reserved input

A direct command's exclusive ownership of *streamed* input: the guest
bootstrap's setup and hooks see EOF, and the program receives the stream and its
EOF. Applies only to a streamed direct launch — which includes a terminal host
stdin that a redirected stdout or `--no-tty` selected into streaming, not just a
non-terminal one. A tool, shell or direct-PTY launch keeps the legacy `/dev/null`
behaviour, where a `shell` launch's seed hooks run before the redirect and a hook
that reads stdin can block there; under a direct PTY the launcher's own session
owns input instead of the pump.
_Avoid_: "stdin passthrough", which suggests setup shares the stream.

## Program guard

The rendered in-guest check immediately before `exec`: `ImageContract` (the
legacy catalog-tool guard, which reports a missing program against the boot
image) or `Direct` (the direct-launch guard, which searches the post-hook
`PATH`, preserves the looked-up pathname bytes and exits 127/126). Both are
rendered by `AgentShellLine`.

_Avoid_: "agent args", "trailing args".

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
guest as uid 0 with `HOME=/root`. Required for docker-in-VM; when the image
provides the Chrome DevTools capability, its MCP uses the `sudo -u chrome` path
only in this mode.

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

## Runtime pair

**msb + libkrunfw**, the executable VMM and firmware library used together.
A **Bundle** carries them beside agent-vm in `bin/` and `lib/`. A **Single
binary** embeds the pair and unpacks it on first use (opt-in release form).

**Unpacked runtime**: `<cache_root>/runtime/<id>/{bin,lib}`, derived only from
the binary, not launch state. **Cache root**: `$XDG_CACHE_HOME/agent-vm` or
`~/.cache/agent-vm`. Avoid "install" for unpacking. See
[ADR-0041](docs/adr/0041-single-binary-embedded-runtime.md).

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
the secret value, which can rotate without changing the source. Each YAML
entry selects exactly one source: omitted `source` selects the secret-store item
named by `service`; `source: env` selects the host variable named by `apiKey.name`,
captured and removed before a launch spawns any child process.

## Credential authorization

A user's permission to use a credential source at specified HTTPS destinations
and in specified request headers. It is host-wide, not project-scoped;
a project may request its use but cannot confer or broaden that permission.

_Avoid_: "grant", when referring to this permission.

## Credential request

A tool or project's declaration that it needs an authorized credential and where
its guest-facing placeholder should appear. A request is not authorization.

## Authorized credential

A **credential authorization** in effect: a **credential source**, the
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

The tool declarations a tool names in `tools = [...]`: the tools it wants
**available in its guest**. They name *tools*, never credential providers.
References stay within the declaring tool's **Tool reference scope**, including
definitions hidden from launch-verb selection. `["*"]` — which must be the sole
entry, and is the default for a tool named `shell` — means every tool in that
scope. An omitted `tools` is `[]` for every other name. Unknown names and
cross-tier references are hard config errors, reported with the declaring file,
declaration index, tool and field. Every definition's references are validated,
even one no launch verb reaches. The scope change is implemented (#395), and the mount half — named mount sets,
user-only tool-level `mounts`, and inheritance through the same closure — is
implemented too (#396/#397); see
[ADR-0048](docs/adr/0048-named-mount-sets-and-tier-local-tool-references.md) and
[USAGE.md](USAGE.md#tool-references-are-local-to-their-file) for the migration.

_Avoid_: "dependencies" — a named tool is provisioned, not required, and
nothing is installed or built for it.

### Provisioning set

Everything one launch provisions: the least fixed point of

    provisioning(t) = credentials(t) ∪ ⋃ { provisioning(u) | u ∈ tools(t) }

over the declaring tool's **Tool reference scope**, where a `"*"` entry expands
to that scope's tools. It is the **single** gate on every provider-owned facet.
The same tool closure also selects `persist` paths and that tool's **Config
mount** declarations, own and inherited; tool `env` and `network_requests` are
the launched tool's own and are deliberately not folded. A tool-reference cycle
is a fixed point, not an error; this differs from a **Mount set** reference
cycle, which is invalid. See
[ADR-0017](docs/adr/0017-tool-declared-provisioning.md), which is amended by the
implemented tier-local reference half of
[ADR-0048](docs/adr/0048-named-mount-sets-and-tier-local-tool-references.md).

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

The resolved, validated model of a configuration's declared **tools** — what
`config::load` produces, as one value so the catalog and a deferred
configuration error cannot disagree about which state the process is in:
`Catalog::Ready(LaunchCatalog)` or `Catalog::Broken(err)`. It is built from the
**tool config tiers** (user, then project), merged as a union of whole
definitions, and falls back to the compiled-in catalog when both tiers declare
zero tools. It is **not** the config files themselves.

_Avoid_: bare "catalog" when the distinction matters — say **Launch catalog**
for the resolved tools plus each one's provisioning set plus the built-in
`shell` fallback. The bare word must never stand in for a config file.

## Tool

A runtime declaration describing how to launch an already-installed program
in the **boot image**, including its command and runtime needs. Declaring a
tool neither installs software nor specifies how its image is built.

_Avoid_: using tool and **Layer** interchangeably (there is no longer a Layer
concept); a tool is not a credential provider or a command to execute on the
host.

It also carries its default `argv`, a list of **credential providers**
(`credentials`, the requirement set), a list of **available tools** (`tools`,
driving the provisioning set), extra guest-HOME-relative `persist` paths, a
guest `env` map, an `interactive_shell` flag, and the **tool config tier** it
came from. A **full user** tool may also declare `mounts`: those are **Config
mounts** selected for a launch of that tool, own plus inherited through its
`tools` closure, and a project or built-in tool may not declare them at all.
User-config defaults and named **Mount sets** are still selected per launch, and
either list accepts a set name. See
[USAGE.md](USAGE.md#tool-specific-config-mounts).

`env` is published into the guest **before** the launcher's own environment and
cannot override `PATH`, `IS_SANDBOX` or `LANG`; `HOME`/`USER`/`LOGNAME` are
**rejected** at the config seam in every mode. See
[ADR-0016](docs/adr/0016-tool-declared-guest-env.md).

### Launch catalog

The verbs a launch actually offers (`config::LaunchCatalog`): the resolved
merge result, plus the built-in `shell` appended when no declared tool claims
that name. The catalog resolves each entry's provisioning set before dispatch,
so `--help`, `doctor` and `run::launch` cannot disagree. One arm of
**Catalog**.

### Tool config tier

One of the two ordered, optional config files resolved by `config::load`: the
**user** tier (`$HOME/.config/agent-vm/config.toml`) or the **project** tier
(`<cwd>/.agent-vm/config.toml`). Each is parsed and validated independently
before merging. Their merge is a **union of whole definitions**, not a field
overlay: the user tier is authoritative for every name it declares, the
project tier may only add names, and a differing project declaration yields a
`doctor` warning (user definition wins). Only when both tiers declare **zero**
tools do the compiled-in defaults apply. The authority-bearing fields are
user-tier only: `[network]` ([persisted grant](#egress-authority)), `mounts`
([config mount](#config-mount)) and `[mount_sets]` ([mount
set](#mount-set)). A project or built-in declaration of any of them is refused,
even when empty, because presence is what asks for authority. A
definition hidden by whole-definition precedence still belongs to its own
**tool reference scope**, so the rest of its file keeps resolving it.

A load failure is **deferred**, not fatal at startup: `doctor`, the built-ins,
and the in-guest `clipboard`/`_intercept-hook` keep working, and a launch verb
reports the config error rather than clap's "unrecognized subcommand".

## Boot image

The finished image selected for a guest session, independently of **tool**
declarations and how the image was built. It contains the software used in the
guest; tool declarations do not install that software.

## Image refresh

Explicit native acquisition of the selected OCI image reference into the
**image cache**, checking whether the registry now serves different content,
without booting a guest. It is one of the two operations allowed to re-resolve a
mutable source; a changed **image pin** requires an **image approval** (the
terminal prompt or `--yes`). Configuration is unchanged: a refresh never changes
which reference is selected. A default-tier refresh keeps the existing
exception — a successful acquisition of an **absent** retained default
initializes it (success-before-adoption); it never replaces an existing record.

## Image cache

agent-vm's own microsandbox image cache (the ambient backend's cache dir,
including a persisted shared redirect) — the only place a launch looks before
a registry. `agent-vm image build` and `agent-vm image import` publish into it
under a mutable **result reference** — `--tag`, or for import the `--docker`
source when no tag is given — plus any names the archive carries. The Docker
daemon store is not it.

It is not an approval authority: publishing an alias, deleting the cache or
redirecting it never changes an **image pin**, and a pinned launch reacquires
the approved digest rather than trusting whatever an alias names.

_Avoid_: "local images" without saying which store.

## Default boot image

The **boot image** a session boots when neither the command line, nor the
environment, nor the user config, nor the project config selects another: the
**retained default boot image** when this host has one, otherwise the
launcher's **initial recommendation**. A user can select a custom boot image
instead.

## Boot image contract

What any boot image must provide for a session — host-architecture Linux, Bash
on `PATH`, the selected program executable by the guest user,
`/etc/passwd`/`/etc/group` — defined in
[USAGE.md#boot-image-contract](USAGE.md#boot-image-contract). Not a version
stamp. _Avoid_: image API, image-API version.

## Image selection

The one image a session boots, chosen independently of the launched tool:
`--image` (command line) > `AGENT_VM_IMAGE_TAG` (an empty value is unset) >
user config `image` > project config `image` > the **default boot image**. The
catalog is never an input, so changing a runtime tool declaration cannot change
the image. A config-file `image` must be an OCI reference; `--image`
additionally accepts whatever msb accepts (a local rootfs or disk image). No
launch builds an image. See
[USAGE.md#selecting-the-boot-image](USAGE.md#selecting-the-boot-image) and
[ADR-0035](docs/adr/0035-consume-user-owned-boot-images.md). Winning is not
authorization: every OCI source is recorded as an **image pin**, and a launch
consumes the approved child digest. Precedence only chooses which pin's source
is looked up. Local paths remain unpinned.

## Retained default boot image

The digest-pinned image a host keeps as its default after acquiring it, in the
user-scoped `$HOME/.config/agent-vm/default-image.json`. A *bookmark* naming
exact content, not a download cache: it is independent of the msb image cache,
`AGENT_VM_STATE_DIR` and any project, and it is written **only after** the image
was acquired (success-before-adoption). Automatic initialization is
insert-if-absent, so no failed or concurrent first launch overwrites it. The
default tier also has an **image pin**, so warm launches consume the approved
child without registry contact. A **deliberate `image set-default`** is
successful native acquisition, candidate approval and a journaled transaction
that replaces this retained fallback and its shared pin together; it affects
future default-image sessions only. The record holds a digest only — no source
tag, platform or tool metadata — so a bare `image refresh` reacquires that
digest rather than following a tag (issue #392). See
[USAGE.md#explicitly-setting-the-default](USAGE.md#explicitly-setting-the-default)
and [ADR-0047](docs/adr/0047-host-wide-oci-image-approval.md).
Distinguished from the **initial recommendation** below. See
[USAGE.md#the-retained-default](USAGE.md#the-retained-default). _Avoid_: cache
entry, default config, pinned layer.

## Image pin

One host-wide approval record: the canonical OCI reference plus the measured
host Linux platform (`linux/<arch>[/<variant>]`) of the **boot image**, mapped to
the approved host-platform manifest **child** digest and a monotonic revision.
Stored in the user-scoped `$HOME/.config/agent-vm/image-pins.json` (with
`image-pins.lock`), shared by every project and independent of the **image
cache**, `AGENT_VM_STATE_DIR` and the **retained default boot image**. A launch
or `setup` consumes `repo@child`, never the selected tag or index. Only
`image refresh` and `image set-default` re-resolve a source and request an
**image approval**. Local rootfs/disk launches are never pinned.

_Avoid_: "lock file"; "tag pin" (a pin names a child digest, not a tag); "cache
entry" (cache evidence is not approval).

## Image candidate

Content acquired and validated by a native operation but **not yet approved**:
the resolved host-platform child plus the measured guest content identity
(verified config digest and ordered layer diff IDs). A candidate exists only
long enough to be approved or declined, and it is frozen before any replacement
prompt, so a registry moving during the decision cannot substitute content.

_Avoid_: "pending image"; "download" (a candidate is validated, not merely
fetched).

## Image approval

The deliberate, candidate-scoped replacement of an **image pin**: the escaped
source, platform and full old/new digests are shown, the default answer is No,
and `--yes` (only on `image refresh` / `image set-default`) pre-authorizes
exactly that resolved candidate. Distinct from **credential authorization**
(which host credential may be injected) and from cache repair. Without a
terminal on stdin and stderr a changed pin is refused (status 1) without reading
input; a first pin or an unchanged digest needs no approval. An immutable
source that resolves to different content is an integrity failure, never an
approvable change.

_Avoid_: "confirmation prompt" (it is a recorded host decision); "update check"
(there is no launch-time probe); "cache approval".

## Initial recommendation

The immutable `@sha256:…` reference a launcher offers when no retained default
exists yet, compiled into the binary (the released v0.1.3 multiarch index; a
launcher release may change it). Reading it never writes; only a successful acquisition adopts it. A
release that changes this value changes what a *new* host is offered, never an
existing retained default. _Avoid_: default image (unqualified), tag default.

## Standard image

The maintained all-six-agent finished release product, distinct from the tool-free
base and from a user's retained selection. Sources belong to the independent
[image repository](https://github.com/gregwebs/agent-vm-images). The contributor
`vendor/agent-vm-images` gitlink records source provenance, not runtime image
identity; installed launchers need no source files.

## Base image

The tool-free foundation built from the image repository's sources, which the
**default boot image** and user-owned images can extend with ordinary Dockerfiles.
The launcher never builds it; it is local-only source content for image authors,
not a public release product.

## Image-owned Pi package

A pinned Pi extension the image installs as a real npm project root under
`/opt/agent-vm/pi-packages/` and activates with an explicit wrapper
`--extension` — as opposed to a bare `.js` file under
`/opt/agent-vm/pi-extensions/`, or a package Pi manages itself in per-project
guest state. Invisible to `pi list` / `pi update`. See
[ADR-0023](docs/adr/0023-image-owned-pi-extension-packages.md).

## Retired terms

These named a system the launcher no longer has; they are kept here so older
notes and ADRs still resolve. See
[ADR-0035](docs/adr/0035-consume-user-owned-boot-images.md).

**Base link** (the retired Docker-local import tag), **Layer**, **Composition root**, **Base selection**, **Composed default
image**, **Parent**, **Layer image**, **Current tag**, **Stitching**,
**Composed tool image**, **Tool image contract**, **Stitch check**, **Rebased
composition**, **Layer DAG**, **Derived image**, **Project image handle**,
**Layer identity / hash**, **Declared account**, **Layer image contract**.

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

## Config mount

A mount declaration the **user** tier selects: an entry of the top-level
`mounts` defaults, or of a full user `[[tools]]`'s own `mounts`, or a leaf of a
selected **Mount set**. The defaults apply to every launch; a tool's list applies
to a launch of that tool, own plus inherited through its `tools` closure. All of
it is suppressed for one launch by `--no-config-mounts`, which never touches an
explicit `--mount`. A config mount is parsed, claimed and prepared exactly like a
`--mount` (same grammar, guest-path rules, merge/refuse rule and protections); it
differs in host spelling (`~/` expands to the `$HOME` text, and no other relative
form is accepted) and in origin, which diagnostics report as `mounts[N] in
"<file>"`, `tools[N].mounts[I] in "<file>"` or `mount_sets["NAME"][I] in
"<file>"`. Its declarations are read only from a **verified file**: the presence
of any of those fields, not its contents, is what makes the user config
authority-bearing under ADR-0040's read policy. See
[ADR-0046](docs/adr/0046-verified-user-config-mounts.md).

An entry may also be a **Mount set** name, which selects that set's direct
declarations; the set's leaves are the config mounts, attributed to the set
entry rather than to the list that selected it.

_Avoid_: "default mount" — agent-vm's own project/state/home mounts are not
this, and a config mount can be read-only or forked; "persisted mount" — a
config mount is re-selected at each launch, not stored per project, and a fork
copy is persisted but is not a config mount.

## Mount set

A named list of mount declarations in the **user** `[mount_sets]` table,
selectable by its exact name from the top-level `mounts` defaults, from a full
user tool's own `mounts` list, or from `--mount NAME`. A set is a selector, never a mount mode, credential request,
tool or store: **declaring one mounts nothing**, and only a launch that selects
it grants filesystem access. Names are case-sensitive ASCII
(`[A-Za-z0-9_]` first, then `[A-Za-z0-9_.-]`), so a name can never look like a
flag, a path or a modifier, and tool/route words are not reserved. Sets compose:
a set's entries are direct declarations or other set names, forward references
resolve, and a set-reference **cycle** is invalid (a `tools` cycle is not). Each
declared set's transitive **closure** is validated at load — unknown names,
invalid definitions, cycles and a closure that claims one guest path twice with
different declarations are config errors even in an unused set and under
`--no-config-mounts` — with a bounded number of leaf visits, so a crafted file
cannot hang load. A set reference is bare: `agent:ro` is refused, and modes,
guest paths and exclusions belong to the leaves. Selection is deduplicated and
conflict-checked by the same claim rule as any other mount, and a set name,
nesting, config origin or traversal order never enters fork identity. Project
and built-in tiers may neither declare nor select one. Implemented in #397; see
[ADR-0048](docs/adr/0048-named-mount-sets-and-tier-local-tool-references.md) and
[USAGE.md](USAGE.md#named-mount-sets-user-config).

_Avoid_: "mount group" / "mount profile" — a set is a list of declarations, not
a policy; "enabled set" — declaration is not selection.

## Tool reference scope

The definitions in the one configuration file that declares a tool, within
which its `tools` references resolve — including definitions hidden from
launch-verb selection by another file. A name that only another file declares is
a config error, never an opt-in to crossing files. A tool defined in that scope
supplies its own credentials, requested names, `persist` paths and **Config
mount** declarations even when it has no verb, and only the **user** tier may
supply mounts at all; the synthesized fallback `shell` is not a declaration in
any file's scope, so it cannot be named either and inherits nothing. Implemented in #395; see
[ADR-0048](docs/adr/0048-named-mount-sets-and-tier-local-tool-references.md)
and [ADR-0017](docs/adr/0017-tool-declared-provisioning.md).

## Protected config directory

`~/.config/agent-vm`, where `credentials.yaml`, `[network]`, `mounts`,
`[mount_sets]` and a full tool's own `mounts` authorize launch secrets, egress,
config mounts, mount sets and tool config mounts respectively. This
directory is never
inside a writable live bind. Protection includes directories its lookup searches
and prospective directories reached through missing components, measuring raw
`$HOME` and the account home. Read-only binds and fork copies are exempt.
See [ADR-0038](docs/adr/0038-config-dir-exposure-guard.md) for the rule and gaps.

_Avoid_: "masked"; "protected host file", which means the Pi files.

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

## Egress authority

**Egress allowance**: a numeric IP/CIDR with optional transport and port.
Address-wide, never hostname-isolated; sharing an allowed address shares its
permission within those filters.

**Hostname allowance**: one exact ASCII DNS name (`api.example.com`, or a single
label such as `build`) authorized for **TLS on intercepted ports only** — SNI
and DNS-cache verified, never plain HTTP, never UDP. A bare name covers every
intercepted port of the launch; `tcp://HOST:PORT` pins one. This is the narrow
alternative to the internet grant; a hostname resolving to a private address
still needs a local or group allowance for answer eligibility. See
[ADR-0037](docs/adr/0037-hostname-egress-allowances.md).

**Intercepted port**: a port on which the runtime terminates guest TLS to
inspect the SNI. Interception is **per-port and global**: on an intercepted port
every destination needs a TLS ClientHello with SNI, and UDP/QUIC is dropped.
A hostname allowance's ports are the launch-wide `{443}` unioned with every
`tcp://HOST:PORT` port, so naming a port for one hostname widens every bare
hostname and makes that port TLS-only globally.

**Group grant**: internet = `Public`, LAN = `Private`, host = sandbox gateway.
Each is independent. Host includes host-resolver query authorization; internet
also authorizes DNS for any name. A hostname grant authorizes lookups of its
own name only, never arbitrary-name DNS. Numeric and LAN-only grants do not
authorize DNS.

**Network request**: a tool declaration's non-authoritative statement of a TLS
destination (exact name + port) it expects to contact; reported when unmet,
never a grant.

**Persisted grant**: user-authored host authority in a user-tier `[network]`
setting, read only from a verified file and merged per launch. CLI flags override
persisted Boolean values and add allowances for that launch; launches never
write grants back. The project tier refuses `[network]`.
See [ADR-0040](docs/adr/0040-persisted-user-network-authority.md).
See [ADR-0036](docs/adr/0036-default-deny-launch-egress.md) for DNS limitations and
[ADR-0037](docs/adr/0037-hostname-egress-allowances.md) for hostname allowances;
[ADR-0039](docs/adr/0039-non-authoritative-tool-network-requests.md) for requests.

_Avoid_: "saved policy" / "profile" for a persisted grant;
"requested allowance" and "tool allowance" for a network request
(a request is not an allowance); "domain allowance", "wildcard host" and
"host allowance" for a hostname grant — the unit is an exact name, not a suffix or a host; "allow list" for the
whole policy; "network profile" (the runtime's `from_profiles` abstraction,
deliberately not used for tool launches).
