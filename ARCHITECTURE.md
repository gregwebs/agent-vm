# agent-vm — ARCHITECTURE

How agent-vm is put together and *why*. Reading this top-to-bottom should tell
you what every nontrivial design choice in the codebase exists for.

This describes the system **as it is now**, organized by subsystem. It is not a
changelog: when a decision was superseded, only the decision that survived is
written down, and `git log` holds the rest. Individual decisions that needed
their own write-up live in [`docs/adr/`](docs/adr/) and are indexed
[at the end](#decision-record-index). What the features *do*, from a user's
side, is [USAGE.md](USAGE.md); outstanding work and known limitations are tracked
in [open issues](https://github.com/gregwebs/agent-vm/issues?q=is%3Aissue%20is%3Aopen).

## Contents

- [Shape of the system](#shape-of-the-system)
- [Sandboxes and sessions](#sandboxes-and-sessions)
- [The default boot image](#the-default-boot-image)
- [Credentials](#credentials)
- [Runtime and state](#runtime-and-state)
- [Host-side tools](#host-side-tools)
- [Decision record index](#decision-record-index)
- [Deliberate non-goals](#deliberate-non-goals)

## Shape of the system

```
crates/agent-vm/src/
├── main.rs                 # clap entry; pins MSB_PATH/MSB_HOME before the runtime
├── run.rs                  # launch(): build the sandbox, attach or stream-exec
├── teardown.rs             # exec teardown: one stop/kill/reap/remove order, ordinary or forced
├── launch_notice.rs        # launch notices: checked `emit`, detached notice for a forced end
├── direct_input.rs         # host stdin → direct-command stdin: detached reader, bounded pump
├── host_signals.rs         # SIGINT/SIGTERM supervision: handlers, arrival queue, grace rules (#401)
├── launch_target.rs        # lower a selected target once: catalog Tool or Direct command
├── session.rs              # project hash, state dirs, sandbox name, guest home
├── secrets.rs              # capture host credentials; write guest placeholders
├── credential_injection.rs # overlay host mappings + file-backed sources on the network plan
├── intercept_hook.rs       # hidden `_intercept-hook` subcommand: OAuth + GitHub policy
│   └── intercept_hook/
│       ├── http.rs         #   shared request parsing / response framing
│       └── oauth_refresh.rs#   OAuth validation, rotation, single-flight
├── egress_grammar.rs       # shared scheme/target/port grammar and allowance errors
├── egress_policy.rs        # allowance dispatch + launch egress authority (default-deny)
├── egress_hostname.rs      # hostname allowance acceptance, port scope, Domain rule assembly
├── dns_name.rs             # shared ASCII DNS label byte kernel (credential + egress)
├── network.rs              # published ports, proxy notice, launch Plan
├── network_requests.rs     # tool requests: parse, coverage report (never authority)
├── mount.rs                # --mount grammar and volume wiring
├── config_mounts.rs        # user-tier `mounts` + `[mount_sets]`: schema, `~/` expansion, load-time claim
│   └── sets.rs             #   the set graph: names, references, cycles, indexed bounded closures
├── mount_selection.rs      # one launch's declarations: verified user defaults, then argv (paths or names)
├── config_authority.rs     # ADR-0040 verified read, one gate for [network], mounts and mount_sets
├── boot_image.rs           # the one boot-image selection seam (CLI/env/config/default)
│   ├── default_selection.rs#   journal-aware logical default read (bounded shared lock)
│   └── upgrade.rs          #   set-default command shape: explicit typed target
├── image_pin.rs            # host-wide OCI approval: prepare before create, explicit update
│   ├── store.rs            #   strict HOME pin store, CAS kernel, journaled default transaction
│   └── approval.rs         #   candidate-scoped terminal consent (--yes or a real TTY)
├── image_acquire.rs        # shared boot-free acquisition: canonical target, validated token, barrier
│   ├── reference.rs        #   the one canonical OCI target (cache/acquisition key)
│   ├── receipt.rs          #   cache-only validated-content receipt (never approval)
│   └── barrier.rs          #   shared/exclusive cache publication flock
├── image_build.rs          # explicit user Dockerfile export
├── image_cmd.rs            # image verb group: read-only `show`, `refresh`, `set-default`, build/import
├── image_import.rs         # daemon/archive import
├── image_publish.rs        # staging, native publication, requested-reference rollback
├── image_miss.rs           # registry-failure import hint
├── msb_install.rs          # locate + version-verify the bundled msb; MSB_HOME
├── msb_preflight.rs        # fail fast on a forward-migrated msb.db
├── doctor.rs               # operator diagnostics and db recovery
├── pi_credential_inspection.rs # read-only structural report of guest Pi state (#93)
├── config.rs               # read-only tool config parse/merge/validate (doctor preview)
└── …                       # clipboard, setup, user, env_flag, …

vendor/agent-vm-images/      # contributor-only pinned independent image sources
vendor/microsandbox/        # git submodule: the runtime and its SDK
bin/agent-vm-ccusage        # host-side token/cost reporting across sandboxes
```

Shared allowance syntax sits below authority: policy imports hostname and
grammar; hostname imports grammar and `dns_name`, never policy. Requests retain
`Allowance` dispatch from policy and import grammar errors directly; saved-network
configuration likewise imports grammar errors without moving authority.

```text
policy ──> hostname ──> dns_name
  │           │
  └──> grammar <──┘
```

A launch is one pass, and the ordering is load-bearing:

0. `main` discovers and loads the tool config **before** parsing, because the
   resolved catalog determines which subcommands exist. `config::load` retains
   **every** definition from both tiers, records which definitions win their
   verb (the non-lossy winner IDs, from whole-definition user-wins precedence)
   together with the cross-tier conflicts, and checks `persist` ownership over
   all of those winners — but it binds no reference and folds no closure, so a
   reference error is not a load error. `ConfigReport::into_launch_catalog`,
   reached from `cli::parse_from` and from `doctor`, is what validates every
   retained definition's `tools` references, checks and folds each launch
   winner's closure — providers, requested names and `persist` paths over one
   visited mask — and only then discards the definitions hidden from the verb
   list, materializes one entry per winner and appends the isolated `shell`
   fallback. So a definition hidden from the verb list still supplies its own
   file's references, and selecting a verb stays lossy while recording the
   winners does not. `cli::parse_from` then **selects** the launch target: a
   catalog `Tool { entry, tool_args }` from that
   catalog, or a `Direct` command (`agent-vm … run PROGRAM`, or the equivalent
   top-level `--`). Selection is parse time: argv and catalog reads only, no side
   effect.
1. `main()` captures the target's requested credential names, before any child or
   worker exists.
2. `main()` resolves and version-verifies the bundled `msb`, then points
   `MSB_PATH`/`MSB_HOME` at it — **before** constructing the tokio runtime,
   because those are `setenv` calls and `setenv` is not thread-safe under POSIX.
3. `run::launch` **lowers** the target first thing (`target.into_parts()`) into
   the catalog facts the rest of the pipeline consumes (`CatalogGrant`) and the
   guest invocation (program, literal argv, guard). Lowering is therefore *not*
   before every side effect: `main` has already captured credentials and set up
   `msb`/the runtime. What it guarantees is that no later stage reads a catalog
   entry at multiple sites, and that a `Direct` target reads none at all.
4. Still inside `run::launch`, in order: image selection, the network plan,
   the launch's mount selection (`mount_selection::select`: the verified user
   config's `mounts` defaults unless `--no-config-mounts`, then argv `--mount`,
   whose bare names select a user `[mount_sets]` entry) and
   `mount::prepare` (which owns the side-effect-free topology rejection and the
   persisted guest-HOME collision, and publishes forks only after both pass),
   the guest-HOME links and the root-mode decision; `session` derives the project
   hash, state dir, and sandbox name from the cwd; then `ensure_msb_home` (which
   opens Microsandbox state), `msb_preflight` refusing a `msb.db` newer than the
   bundled schema, the socket-path fit check, the legacy Pi-home migration and
   the banner.
5. `main`'s deferred credential preflight resolves the requirements, then
   `secrets` captures the target's requested host credentials into host-only
   files and writes placeholder credentials into the guest state dir. A `Direct`
   target requests nothing, so nothing is captured or written for it.
6. The sandbox is built and created — image, mounts, guest user, PATH, network
   plan, then the credential-injection overlay.
7. The agent runs, attached to a PTY or through a streaming exec.
8. Teardown stops the sandbox, removes it, and re-checks the credential
   snapshot.

### Tool configuration drives the CLI and the guest-HOME links

`config.rs` reads two ordered **catalogs** — `$HOME/.config/agent-vm/config.toml`
and `<cwd>/.agent-vm/config.toml` — validates each strictly, and retains every
definition from both. Whole-definition user-wins precedence (`user`
definitions, then project-only names) decides only which names are **launch
verbs**; it is not a reference namespace. Each launch winner's closure is
resolved over the definitions that share its **declaring file** (#395), so a
project `helper` that names `pi` gets the project's `pi` even when the user's
`pi` owns the verb — and a name that only another file declares is a config
error. When both tiers declare zero tools it falls back to the seven
compiled-in defaults embedded from `default-tools.toml`; the synthesized `shell`
fallback is resolved from a scope holding only that one shipped definition, so
under a custom catalog it provisions nothing. The resolved catalog is what the
CLI builds its launch verbs from (#82), and `run::launch` reads back each
entry's provisioning set — the credential providers *and*, since #83, the
`persist` paths that become guest-HOME links (`guest_home.rs`) — so the verb
list and the guest state it provisions share one source of truth.
`agent-vm doctor` renders the same catalog read-only:

```
user file --------> parse + validate --+--> retained definitions ---> launch
project file -----> parse + validate --+    (every definition,         verbs
both empty? -> embedded defaults ------+     hidden losers too)          ^
                     |                                                   |
                     v                                                   |
   bind references by exact (declaring file, name)                        |
   resolve each launch winner's tier-local closure                        |
   validate each winner's closure persist ownership                       |
   fold providers + requested names + persist ----------------------------+
                     |
                     v
              LaunchCatalog --> CLI verbs
                     |             + run::launch
              doctor preview (read-only)
```

Persist ownership is checked twice on purpose: `load` keeps the historical
winner-wide check, and catalog construction adds one check per launch winner's
own closure. The second is what catches a conflict between two definitions
hidden from verb selection without rejecting two tiers' mutually exclusive
closures, which never link together in one launch. See
[ADR-0017](docs/adr/0017-tool-declared-provisioning.md) and
[ADR-0048](docs/adr/0048-named-mount-sets-and-tier-local-tool-references.md).

This module resolves declarative config only. It never builds an image: the
**boot image** is selected separately by `crates/agent-vm/src/boot_image.rs`
(one image per session, independent of the catalog), and no launch invokes
Docker or composes anything. Config warnings are never logged — doctor renders
them explicitly.
`doctor --reset-msb-db` never reads config, so a broken file cannot block db
recovery. There is still no arrow from this module to credential *capture*,
Docker, or guest state; it resolves the provisioning set and the launch
consumes it. See [USAGE](USAGE.md#tool-configuration) for the schema and
rules and [CONTEXT](CONTEXT.md) for the vocabulary.

### Why a git submodule for microsandbox

agent-vm depends on microsandbox primitives that are not merely API surface —
file-backed secrets and request interception decide whether a token can leak.
A submodule pinned to `gregwebs/microsandbox` makes the checkout
self-contained, makes the diff against upstream reviewable, and is honest about
the fact that the runtime is vendored.

`[patch.crates-io]` also works, but it splits the source-of-truth pointer
across `Cargo.lock` and a patch table, and hides the vendoring. A path
dependency on a sibling checkout works for one developer and for nobody else.

agent-vm builds against the stock crates.io `msb_krun*` cohort
([ADR-0006](docs/adr/0006-adopt-clean-v0.6.15-baseline.md)); what is vendored
is the microsandbox source itself, at a pinned version
([ADR-0027](docs/adr/0027-adopt-v0.7.4-fork-baseline.md) records the current
pin).

## Sandboxes and sessions

### Project-scoped identity

Each project directory gets:

- **A short hash** — the first 6 bytes of `SHA256(canonical(cwd))` as 12 hex
  chars. ~48 bits is plenty for "no two project dirs on one host collide", and
  it is short enough to fit in a hostname, which makes it visible from inside
  the guest when debugging.
- **A state directory**,
  `${AGENT_VM_STATE_DIR-${XDG_STATE_HOME-$HOME/.local/state}/agent-vm}/<hash>/`.
- **A sandbox name**, `agent-vm-<hash>-<pid>`.

The PID suffix is deliberate. An earlier design used a bare `agent-vm-<hash>`,
which made the name double as garbage collection: a second launch in the same
project would `.replace()` the first, giving it 10 s to exit and then killing
it. That is wrong once you want two agents in one project at once, so the name
became per-launch — at the cost of losing the implicit GC. `reap_stale_project_sandboxes`
(`run.rs`) restores it explicitly, removing leftover `agent-vm-<hash>-<pid>`
entries whose PID is no longer alive, so a launcher that crashed between create
and teardown does not leak its overlay, logs, and DB row forever. Liveness is
checked before removal, so a peer launcher running right now is never touched.

The launcher prints one banner (`==> <sandbox> in <cwd> (state: <dir>)`) so it
is always clear which project a VM belongs to.

### Mounts: one for the workspace, one for state

The guest gets exactly two bind mounts of its own:

- `cwd → ` the project's own host path (so in-guest paths match host paths).
- `<state-dir> → /agent-vm-state` — everything else.

Per-agent state is arranged *under* that single state mount rather than as
separate mounts:

- `$HOME/.claude → /agent-vm-state/claude`
- `$HOME/.local/share/opencode → /agent-vm-state/opencode`
- `$HOME/.pi → /agent-vm-state/pi`. Pi gets a symlink where codex gets an env
  var because it has no install prefix under `~/.pi` to shadow — its binary
  lives under `/opt/agent-vm/pi`
  ([agent-vm #96](https://github.com/gregwebs/agent-vm/issues/96),
  [ADR-0021](docs/adr/0021-project-scoped-pi-home-and-wrapper-parity.md)).
- Codex instead gets `CODEX_HOME=/agent-vm-state/codex`, because
  `<install-prefix>/.codex/packages/…` contains the codex binary itself and a
  symlink there would shadow it. That variable is declared by the `codex` (and
  `shell`) tool's own config `env`, not set on every launch
  ([agent-vm #119](https://github.com/gregwebs/agent-vm/issues/119),
  [ADR-0016](docs/adr/0016-tool-declared-guest-env.md)).

A state dir created before #96 may already hold a real `<state>/home/.pi`
directory. The launcher moves it into `<state>/pi` once, before provisioning,
in both guest modes, rather than refusing — see
[ADR-0021](docs/adr/0021-project-scoped-pi-home-and-wrapper-parity.md).

This shape originally fell out of a hard virtio-IRQ ceiling (below). The
ceiling is lifted and the shape stayed, because it is better on its own terms:
one virtio-fs server, a stable on-host layout, and a constant mount count no
matter how many agents are added later — which leaves the device budget for the
user's own `--mount` arguments.

Where those symlinks get created depends on the guest user, and the asymmetry
is easy to trip over. `.patch()` bakes into the rootfs upper overlay *before*
the VM boots, so it works for root mode's `/root/…` links (un-shadowed rootfs)
but is invisible for the non-root default, whose `HOME` lives under
`/agent-vm-state` — a *runtime* bind mount that shadows whatever the patch
wrote. Non-root links are therefore materialized host-side by
`ProjectSession::provision_guest_home`, dangling on the host and resolving once
mounted. Both paths draw from the same `credential_provider::guest_home_links()`
table.

### Extra and forked mounts: `ro`, `rw`, `fork`, `follow-links`

**Three declaration inputs, one seam.** `--mount` is not the only way a launch
can ask for a mount: a verified user config's top-level `mounts` selects
[mounts for every launch](docs/adr/0046-verified-user-config-mounts.md), and its
`[mount_sets]` table names reusable lists that either input may select by name
([ADR-0048](docs/adr/0048-named-mount-sets-and-tier-local-tool-references.md)).
`mount_selection::select` is the only place that decides *which sources* one
launch requests — the user config's defaults unless `--no-config-mounts`, then
argv in order, each entry classified as a path or an exact set name — and it does
no I/O, so an unselected declaration (or an unused set's missing source) can name
a path that does not exist without blocking a launch, `doctor` or `--help`.
`--no-config-mounts` removes the defaults only: an explicit `--mount NAME` still
selects its set, and every load-time check still runs. Everything after it is
shared: `mount::prepare` receives one ordered `MountRequests` whose elements carry
their origin, applies one claim rule (identical declarations at one guest path
merge; different ones are refused, config-versus-CLI included), and runs the same
protections and topology checks. Nothing downstream can tell a config
declaration from a CLI one except the origin string in a diagnostic.

**Sets are validated as a graph, not resolved at launch.** `config_mounts::sets`
parses the table, binds every reference by exact name (forward references
included), rejects unknown names and reference cycles with an explicit iterative
walk, and then compiles each set's transitive closure once, dependency-first,
against an indexed guest-path map — never `mount::claim`'s growing-vector scan.
Every declared set is validated, even unused and under the opt-out, so a
self-contradictory closure is a load error; two separately valid sets may still
disagree until a launch selects both, and that is the shared claim's refusal. The
whole walk is bounded by one global leaf-visit budget
(`MAX_MOUNT_SET_EXPANSION_WORK`), which turns a pathological config into a
value-free config error instead of a hang. `tools` reference cycles are a
different walker reaching a fixed point and stay legal.

```text
BEFORE                                       AFTER
config.toml ──read──> RawConfig              config.toml ──read──> RawConfig
  [network]? ─yes─> verify+parse (network)     triggers = {network?, mounts?, mount_sets?}  (presence)
  mounts ───no I/O claim                       any? ─yes─> config_authority::verify(read)  ONE check
                                                  ├─ [network]     → user_network::from_verified_table
                                                  └─ mounts/sets   → config_mounts::from_verified_value
                                                                      (~/ expansion, shared grammar,
                                                                       names → refs → cycles → closures,
                                                                       then defaults claim; NO source I/O)
argv --mount ──> parse_selector              mount_selection::select(user, policy, &args.mount)
             (path | exact set name)           → MountRequests [defaults…, cli…] with origins
                 └─ run.rs: persist check      → mount::prepare(requests, ctx{.., persisted_home})
                    AFTER prepare_forks            claim → protections → … → validate_plan
                                                   → persisted-HOME check → prepare_forks
```

**The persisted guest-HOME collision moved.** A mount that shadows a declared
`persist` path used to be refused in `run.rs` *after* `prepare` returned — that
is, after a fork could already have been published. The check now runs inside
`prepare`, after `validate_plan` and before `prepare_forks`, over the complete
normalized core + explicit + followed destinations, for `--mount` and config
declarations alike. Its message bytes and its unwrapped error are unchanged, so
the reading of a refusal does not depend on which source declared the mount
(ADR-0046 Decision 6).

`fork` is an eager, project-scoped copy rather than a live bind. `mount::prepare`
owns parsing, READY-first policy and topology validation, host-side copying, and
publication; `run` receives only typed prepared volumes and does not re-stat or
reinterpret them. That deep single interface matters: a READY fork is selected
before any source access, every deterministic policy/topology rejection happens
before the first state mutation, and launch never reclassifies a path after
policy has been decided.

```text
source directory
  └─ host-side staging (no-follow descriptors, exclusions skipped)
       └─ atomic rename -> READY data
            └─ ordinary writable directory bind -> /guest

live ro/rw directory and file-ro paths ── ordinary binds ──> /guest
```

Forks are directory-only (issue #113): a file fork root is rejected with a
directory-only diagnostic, and a regular file can only be a read-only bind. The
copy engine still copies nested regular files and, under `fork:follow-links`,
materializes followed file targets — only the root is constrained. The root is
opened with `O_DIRECTORY` at the descriptor actually copied from, so a root that
was a directory at policy time but is later swapped for a file or symlink fails
closed instead of publishing a file-root fork.

A versioned, length-delimited SHA-256 identity contains the source spelling,
normalized guest path, follow policy, and normalized exclusions. The store is a
sibling of the guest-visible state directory: `&lt;project-hash&gt;.mounts/{locks,staging,forks}`.
A per-fork exclusive lock serializes initializers; only a complete
`manifest.json` plus `data` is renamed into `forks/`. Staging is never mounted.
A malformed committed entry is a hard error with its reset path, never an
automatic reseed; a legacy v2 `kind: "file"` entry is an actionable unsupported
fork that names the exact directory to remove. This is process-crash atomicity,
not a power-loss durability or concurrently-mutating-source snapshot promise;
copy errors or a killed initializer can leave retryable staging.

Fork exclusions (`:exclude=REL`, fork-only) are omitted before traversal; they
are not a persistent guest access restriction, and an explicit child mount can
still populate an omitted path. Default fork traversal preserves nested link
text; `fork:follow-links` materializes link targets into owned data, so it never
creates a continuing external bind. See [ADR-0014](docs/adr/0014-narrow-fork-mounts-to-directories.md)
for the narrowed policy and [ADR-0013](docs/adr/0013-add-forked-mounts.md) for the
retained lifecycle and reset details.

**Authority directories must not be guest-writable.** `protected_config_dir.rs`
encapsulates the resolution walk, prospective anchor/name comparison and four
contracted kernels behind measurement and three checks. `mount::prepare` uses
it before state creation; run supplies raw authority HOME and the account home.
Unlike the Pi guard, it is unconditional, protects lookup directories, and
exempts read-only/fork sources. See [ADR-0038](docs/adr/0038-config-dir-exposure-guard.md).

**Host Pi credential files never reach the guest.** Which host files those are,
and whether a given mount is one of the ways they would, is one deep module:
`protected_host_files.rs` measures a route set per launch and answers three
questions — would this root expose one, where would it appear, and is this root
inside Pi's home. `mount::prepare` is the only caller; `run.rs` never sees a
`dev`/`ino`, a route, or Pi's layout.

Two responses, because the mount families differ in kind. A **live bind** —
core project/state/home binds, `ro`, `rw`, `follow-links`, and every bind
`follow-links` discovers — is a window onto host bytes written *after* boot, so
the launch is **refused**: `pi auth login` on the host can create `auth.json`
inside a bind that is already open, and no overlay can cover a path that does
not exist yet. A **fork** is a one-time copy made host-side under agent-vm's
control, so the copier simply does not create the node — no empty file and no
placeholder, because that would be a mask, and ADR-0014 removed mask
machinery. The copier consults the node's `fstat` identity *and* its
fork-root-relative path, so a hardlink under another name, a
`fork:follow-links` materialized target, and a file created between
measurement and the copy are all omitted. The copier resolves the root it is
about to open and measures Pi's home **at that point**, so a root spelled
through an alias the kernel folds decides identically: a route is a hit by
`(dev, ino)` identity as well as by pathname containment. That identity fold
holds only for an association the single measurement actually captured — a
Pi-home relationship lost between the root resolve and that measurement, or a
renamed alias of a Pi-home *subdirectory*, is outside it; ADR-0020's *Accepted
gaps* name both.

```text
prepare()
  measure protected route set (from MountContext.host_home)   [fail closed on EACCES/ELOOP]
  enforce core binds (project = canonicalized cwd)            [refuse: "run from a project dir"]
  normalize_guest / core collision / dedup                    [config-vs-CLI claim: merge or refuse]
  preflight_forks (READY forks repointed at owned data)
  expand_follow_links (live hosts canonicalized; targets appended)
  build volumes
  enforce_protected_files(expanded)                           [refuse a live bind; collect advisories]
  validate_plan
  persisted_home.refuse_conflicts(core + every volume)         [refuse a shadowed `persist` path]
  prepare_forks -> copy_root resolves the root, then copy_opened(NodePolicy { identities + relatives })  [omit, notice]
```

Both new passes run before `prepare_forks` — the first state mutation — so a
refused launch creates no fork store, no lock, no staging, and no session
state. Reachability is decided by canonical **identity** (`(dev, ino)`, which
folds macOS firmlinks, symlink/hardlink aliases and Linux bind mounts that
paths cannot) *and* component-wise canonical **containment** (the common path,
so the decision never depends on inode semantics; the case it alone decides is
a root whose canonical path *equals* a measured route's while `(dev, ino)`
differ). The containment half is `config::byte_path_contains`, one directional
kernel shared with the guest-path overlap predicate under a `verus!` contract.
The refusal's remedy is conditional on the root — `:fork` at or inside the Pi
home, a narrower path above it, nothing for a root that is the file itself.
Whether an exposure is a hard error or an advisory depends on whether `$HOME/.pi`
exists, so a user who has never installed Pi can keep mounting `$HOME`; an
unset `$HOME` still gets the check, because the launch's home falls back to the
account record. Forks alone carry the cost of moving: `IDENTITY_VERSION` is v3,
because a READY fork is reused without reading its source and a pre-#90 seed
may already hold a copy of a protected file. The two-file table, the accepted
gaps, and the rejected mask alternative are
[ADR-0020](docs/adr/0020-protect-host-pi-credential-files.md).

Live binds are ordinary mounts, each opting into per-bind root follow so a
user's symlinked source spelling resolves once. Core volumes (HOME, project,
state) keep root follow at its default `false` and are canonicalized only after
provisioning, once their sources exist; a fresh state root is still valid. The
dependency is pinned to microsandbox `main` (`f948475c`), which provides
`follow_root_symlinks` and a no-follow-root default; the descriptor-pinned
`nofollow`/ACL hardening is deferred to
[gregwebs/agent-vm#114](https://github.com/gregwebs/agent-vm/issues/114).

GitHub repo discovery scans the prepared roots' committed physical content:
forks contribute `data`, never the original source, and no logical exclusion
filter is applied. An excluded `.git`/`.gitmodules` is simply absent from the
copy, so it cannot contribute slugs.

`--mount HOST[:GUEST][:MODE]...` (`mount.rs`).

**Modes are a suffix list, not a flag.** `ro`/`rw` could have been separate
flags (`--mount-ro`), but the mode belongs to *that* mount, not to the launch.
`rw` is the default and is accepted only so a `--mount` line can say what it
means.

**`ro` and `follow-links` deliberately coexist.** `follow-links` *implies*
read-only, so they are not mutually exclusive — which is why the conflict
policy lives in one table in `mount.rs` rather than being spread across
per-pair checks that would each have to encode the exception.

**`follow-links` binds the real directories, not the links.** virtio-fs passes
a symlink through as a symlink, so a link pointing outside the bind is dangling
in the guest. The walk resolves links under `HOST` transitively and appends one
read-only bind per discovered target directory, with a depth cap on
*link-follow chains* specifically — not on ordinary directory nesting, which is
unbounded and fine. Discovered binds carry `follow_links: false`, so the walk
cannot re-expand its own output.

**Targets are bound at their literal guest path.** A discovered target is
reachable in the guest by the path the link text implies, which is not always
its canonicalized host path: canonicalization resolves symlinks *before*
applying a following `..`, so the two answers part company exactly there.
Binding at the canonical path would leave the guest resolving a link to a path
nothing is mounted at. The rejected alternative — rewriting link text inside
the guest — mutates the user's project.

### Split irqchip and the virtio-IRQ ceiling

`msb_krun` exposes `MachineBuilder::split_irqchip(bool)`. With it off, libkrun
uses KVM's in-kernel IOAPIC: hard-capped at 24 pins, and only IRQs 5..=15 go to
virtio-mmio — about 11 for the whole VM. Rootfs lower + rootfs upper +
virtio-net + virtio-vsock + virtio-console + two virtio-fs binds already
saturates that, so a single extra `--mount` tripped
`RegisterNetDevice(IrqsExhausted)` at boot.

With it on, `msb_krun` runs a userspace IOAPIC backed by an event-loop thread
it spawns automatically. The cost is one extra worker thread per VM and a
slightly hotter IRQ delivery path. The runtime enables it unconditionally
(`vendor/microsandbox/crates/runtime/lib/vm.rs`).

Resulting capacity is an **observed, host-specific property, not a portable
limit** — Linux x86_64 uses this IOAPIC path while Apple Silicon uses GIC — so
it is recorded as conservative per-platform test profiles rather than promised
as a CLI contract.

### Runtime provenance and platform profiles

Distinct from **runtime dependency provenance** below and from a signed
attestation, `agent-vm --version` embeds the source revision the launcher was
built from as build metadata (issue #335). It is measured once by
`crates/agent-vm/build.rs` and is not a runtime Git lookup; it names the built
artifact, not the source pins, and cannot prove the executable came from that
source. Treated as a provenance *record*, it lets the persisted-network harness
refuse a stale or dirty candidate before boot. See
[CONTRIBUTING.md](CONTRIBUTING.md#build-identity-in-agent-vm---version) for the
default/strict invalidation policy and its accepted blind spots.

`./script/check-runtime-provenance.sh` checks both independent Cargo roots (the
outer workspace and `vendor/microsandbox`) for the identical official crates.io
`msb_krun*` 0.1.39 cohort and checksum map, plus the pinned `vendor/libkrunfw`
gitlink, firmware version/ABI, and the x86 source-configuration contract. This
establishes **source identity**, not an attestation that a given executable came
from that source; release provenance is separate, unfinished work.

The public-CLI compatibility harness is `script/test/msb-krun-compat.sh`. It
keeps process, Docker, fixture, and guest-probe orchestration in shell, while
`crates/msb-krun-compat-evidence` parses and validates host-side evidence and
writes its JSON records. That evidence crate is a separate small workspace
member so the contract stays buildable ahead of the vendored `agentd` and the
agent-vm runtime dependencies; the static Python provenance checker stays
Cargo-independent for the same reason.

On Apple Silicon macOS/HVF the device-discovery proof uses the flattened device
tree plus guest sysfs and `virtiofs` mountinfo rather than an x86 command-line
proxy. A zero-user-bind baseline is compared against each case: every added
bind must add one `virtio,mmio` FDT node and one bound `virtiofs` device, and
selected low/boundary/final mounts must read their unique host marker and write
a unique value back.

The accepted Darwin profile is conservative test policy — boundary samples 4
and 64, high case 112, stress case 64 — and is **not** a capacity claim. The
measured host booted through 128 user binds; 256 was the first attempted
failure (`RegisterFsDevice(IrqsExhausted)`); 129–255 were never tested, so the
real maximum is unmeasured. Darwin's `/proc/cmdline` stayed around 202 bytes
because arm64 HVF describes virtio-mmio devices in the device tree, so the
pinned firmware's 16 KiB command-line setting and the >2 KiB trailing-
`virtio_mmio.device=` acceptance proof are Linux x86_64 KVM-only.

Linux x86_64 KVM still needs its own live `measure`, reviewed
boundary/high/cmdline/stress constants, command-line declaration
ordering/count proof, and split-irqchip/IOAPIC diagnostics. Darwin evidence
satisfies none of those.

### Launch targets: one pipeline, two lowerings

```text
                      agent-vm [launch options] <tool> [args…]
                                     │
                       run / top-level -- PROGRAM [arg…]
                                     │
              ┌──────────────────────┴───────────────────────┐
              ▼                                              ▼
   LaunchTarget::Tool { entry, tool_args }   LaunchTarget::Direct { command, terminal }
   inner_argv + ImageContract guard             literal argv + Direct guard
              └──────────────────────┬───────────────────────┘
                                     ▼
              CatalogGrant (snapshot adapter) + GuestInvocation
                                     ▼
        shared setup → hook → target guard → literal exec → teardown
```

`launch_target.rs` is a **snapshot adapter**, not a second pipeline and not an
authorization layer: its only decisiveness is that `Direct` holds no
`CatalogEntry` at all, so no catalog command, default args, environment,
credential requirement, network request, transitive tool or `persist`
declaration can be read for it. The credential resolver and network policy
remain the authority; `Direct` simply requests an empty name set, which makes
their decisions empty (ADR-0017). `GuestInvocation` carries the program, argv,
display text and a `ProgramGuard`; `AgentShellLine` branches in
`program_guard()` and in `GuestInput` (who owns streamed rather than reserved
stdin, #399), and the `GuestInput::DiscardWhenNotTerminal` rendering is
byte-identical for every existing tool, shell and direct-attach launch.

Shared state is unchanged: image selection, cwd, identity, mounts, HOME links,
default-deny network, GitHub policy, bootstrap and the project hook all still
apply to `Direct`. Image-capability furniture (the owned Chrome DevTools MCP
entry) is image-derived, not catalog-derived, so it is retained for a direct
launch too.

### Interactive attach vs. non-TTY streaming exec

`Sandbox::attach()` needs a real terminal on stdin and fails when stdin is a
pipe, a redirect, or CI. The raw-mode snapshot differs by session: the **direct
PTY** session (`direct_pty`, #400) owns its own guard over a duplicated terminal
descriptor and never touches fd 0 or a global tty, while the **legacy** session
(tool, `shell` and every pre-#400 caller) keeps the unchanged crossterm global
raw-mode guard inside `attach()`. Two launch kinds choose between a terminal and
streaming, and the choice is **not** one predicate:

```
launch target            decision                                  result
─────────────────────────────────────────────────────────────────────────────────────
tool / shell             stdin is a terminal (unchanged)            attach, legacy semantics
direct                   HostTerminals{stdin,stdout} + -t/-T        direct PTY session or stream (#400)
```

- **Legacy attach** → `attach_with(cmd, args)` with no options: the agent's TUI
  gets a full PTY, `Ctrl-]` detaches, output is best effort, and a session that
  ends without a guest exit returns `Ok(-1)`. This is the *only* remaining
  `attach()` caller.
- **Direct PTY** → `exec_stream_with(... tty(true).stdin_pipe())` driven by
  `direct_pty` (below), so the fork needs no SDK patch. A definite guest exit is
  required to report a status; before one arrives, a closed channel, an output or
  send failure, or a runtime that disappears is a failure (125) after the
  terminal is restored.
- **No terminal** → `exec_stream_with(...)`, which streams stdout/stderr as they
  are produced and forwards the exit code.

A direct launch's mode is resolved once, in `cli::direct_dispatch`, from the
parsed `-t`/`-T` and one `HostTerminals::detect()`, and travels
`LaunchTarget::Direct.terminal → GuestInvocation::direct_io() → ExecIo →
guest_input_for`. Nothing re-measures the host later: a bootstrap rendered for
one mode must never be executed by the other. Auto is a PTY only when both stdin
and stdout are terminals, so a redirected stdout streams with separate guest
channels instead of merging them into a file.

The streaming form matters: the SDK's buffer-until-exit `exec_with` makes a long
non-interactive run look hung.

The exec loop races the event stream against `Sandbox::wait()` so a VMM that
dies mid-stream produces a diagnostic rather than a hang on `recv()`; see
[Sandbox liveness](#sandbox-liveness-idle-detection-and-runtime-exits).

**Streamed stdin (#399).** A direct streamed launch is the only one that
requests the runtime's `stdin_pipe()`, and the lifecycle — not `launch()` —
takes the sink out of the handle it owns:

```
 fd 0 ─► std::thread "agent-vm-stdin" (detached) ─► 1-chunk channel ─► pump task ─► ExecStdin frames
          blocking read(2)                          (64 KiB)          cancellable      └ empty frame = EOF
```

Three resources with three lifetimes, and the differences are the design
([ADR-0052](docs/adr/0052-direct-command-input-ownership.md)):

- The reader is a **detached std thread**, never `tokio::io::stdin()`: the tokio
  form reads on the blocking pool, whose task cannot be cancelled, and
  `Runtime::drop` waits for it — so a launch that fails while a FIFO writer
  still holds stdin open would hang instead of reporting its status.
- The channel holds **one** chunk, so a stalled guest bounds launcher memory to
  about three chunks instead of the whole stream. This is a launcher-side bound
  only; the transport's own credit is the runtime's.
- EOF is an **empty** `ExecStdin` frame (`ExecSink::close`), which is why the
  chunk type cannot be empty: a zero-length write would close the guest's stdin
  early.
- A failed guest write arrives as a non-terminal `ExecEvent::StdinError`: EPIPE
  is the guest closing its read end (expected — stop the pump, keep its status),
  anything else is a forwarding failure (125).

`StdinMode::Null` does **not** by itself give the guest `/dev/null`: agentd
always hands a non-PTY child a pipe, so the guest bootstrap supplies the
redirect. Legacy and attach launches do it with `[ -t 0 ] || exec < /dev/null`;
a direct streamed launch instead runs setup, the project hook and the guard in
one `{ … } </dev/null` group and lets bash restore the real stdin for the
program's `exec`. That group is why setup children inherit no copy of the input,
and why a direct command's input is exclusive (`GuestInput`, ADR-0052).

The loop is a `biased;` select whose order is a correctness property: work a
previous step accepted (a frame on its way to the sink, a signal on its way to
the guest), then the pump outcome, then an expired transport-failure grace, then
host-signal supervision, then exec events. The pump ends at most once, so it
cannot starve anything, and an input failure that has already happened must beat
a ready `Exited` — stream loss is never a guest success. The grace and the
supervision arms sit ahead of the event stream so a continuously ready stdout
stream cannot hold either open. A guest frame is a **held branch**, not an await
in the loop body: the body would suspend the whole loop, so a host that stopped
reading its stdout used to hide interrupts, the grace and a lost runtime for as
long as the consumer stayed away (#401). The frame carries its own
bytes, offset and write outcome, and borrows the sink only while it is polled,
because a future that borrowed the sink cannot be stored in a slot every
iteration reuses. While a frame is in flight the event arm is gated — two frames
must not interleave on one sink — but the runtime arm is not: a stalled consumer
must never hide a dead VMM. `stream_exec_with_cleanup` has exactly one release
sequence for every outcome, including an input start-up failure: stop the pump,
drop the wait future, drop the handle, then tear down — in that order, because
the wait future may hold the child-handle mutex (#258) and a pending sink write
must not outlive the handle it writes through.

**Direct PTY session (#400).** `direct_pty::run(handle, sandbox.wait())` is one
owned future, not a spawned task, and it owns the whole host side of the session:

```
fd 0 (a terminal, no fallback) ─► duplicate ─► RawTerminal (exact snapshot)
                               └─► thread "agent-vm-pty-input" ─► 1-chunk queue ─► ExecSink
TIOCGWINSZ ─► handle.resize(rows, cols) at start, again per SIGWINCH
ExecHandle events ─► output (merged) ─► thread "agent-vm-pty-output" ─► duplicated fd 1
Sandbox::wait() ─► raced: a runtime exit without a guest exit is a failure
```

It selects on the handle's events, host input, `SIGWINCH`, its own pending
writes and the runtime wait, biased towards work already accepted so an exit
already observed never waits behind output backpressure. Each send that a peer
can stall — one guest frame to the output writer, one input chunk to the guest,
one resize to the agent — is held as a `select!` **branch**, never awaited in an
arm body: a pending body stops the macro polling its siblings, which would hide a
runtime exit, a writer failure or the end of the event stream for as long as a
stalled consumer kept the send waiting. A full queue still stalls the session (it
must), so the only difference from a native terminal is that the fault paths stay
observable. Every outcome leaves through one epilogue: restore the terminal,
abort the writer, stop the reader (a self-pipe wakes it), then drop the runtime
wait (releasing the child-handle mutex before the existing stop/wait/remove path
takes it). A `Ctrl-C` at a host terminal is never a signal here: `cfmakeraw`
clears `ISIG`, so it arrives as byte `0x03` and is forwarded to the guest as
input, exactly once. Host `SIGINT`/`SIGTERM` supervision (#401) is a separate,
explicitly signalled path — see [Host signal supervision](#host-signal-supervision-401).

Two properties come from choices `attach()` does not make. The raw guard saves
the **exact** attributes and restores that snapshot explicitly on both returns
(and best-effort from `Drop` for cancellation), reporting a restore failure
rather than swallowing it. And guest output is written by a dedicated thread
over a duplicated stdout descriptor with an 8 MiB outstanding-byte bound, because
a Tokio stdout write cannot be cancelled once dispatched and `Runtime::drop`
waits for blocking tasks: a session that failed while its consumer stopped
draining could otherwise never report its failure. A full queue waits for the
consumer (stalling the session, as a native terminal write would) and a frame
larger than one queue slot is split into ordered chunks, so the bound is bytes
rather than frames. An unwritable descriptor is always a session failure (125
after restoration and teardown), and so is a runtime lost **before** the guest
reports an exit — there the status is still unknown. Once the exit has been
observed the status *is* known, so the final flush is all that is left to lose:
the barrier still races that flush against the runtime wait (a consumer that
never drains must not be able to hang the launcher), but a runtime lost there
ends the drain and the session reports the guest's own status, truncating
whatever output was still queued. `abort` stops the writer instead of letting it
drain what a failed session had already queued, so nothing is written to the
operator's terminal after the terminal was restored.

One difference is an SDK limitation rather than a design choice: `exec_stream`
creates the guest PTY at a fixed 24x80 (`exec_stream_with_pty_size` is
`pub(crate)`), so the session's first frame after the handle exists is a
`resize` to the host's real `TIOCGWINSZ` size. `attach()` puts the real size in
the exec request itself.

`stream_exec_with_cleanup` owns that loop. It also owns the sink policy: a
catalog tool or the fallback shell keeps the legacy **best-effort** sink (a
write or flush error is dropped, so a broken pipe never changes its status), and
a direct command uses the **checked** policy (a write or flush failure becomes
the primary error and still tears the sandbox down). The exception is local and
deliberate — making the legacy path strict would change existing shell/tool
statuses. Teardown itself is generic over a private `ExecTeardown` adapter
implemented by `Sandbox`, so failure schedules are unit-testable without a
booted VM.

### Host signal supervision (#401)

A direct launch runs a command the operator can interrupt, so while it runs the
launcher must not die on the first interrupt: it forwards the signal to the
guest, keeps watching the guest for a **fixed five seconds**, and tears the
sandbox down itself — including when the interrupt is repeated, when the guest
ignores it, and when the guest's output has stopped being consumed. `host_signals`
owns all of that so the PTY session and the streaming session cannot drift apart.

```
SIGINT/SIGTERM ─► raw handler ─► 1 byte per arrival ─► self-pipe ─► std thread ─► unbounded queue
                                                                                      │
        first arrival: forward + start ONE deadline        second arrival or expiry: force
                                                                                      │
                          guest exit in the grace ──► its status        forced ──► 128 + N
```

| Outcome | Launcher exit |
|---|---|
| Guest reports a code (0, 126, 127, an unknown `-1`) | that code, so an unknown `-1` leaves the process as 255 |
| Guest status absent (the stream ended without one), no forced shutdown | today's failure (125) |
| **Forced shutdown** (grace expiry or second interrupt) with the guest still running | `128 + interrupted signal` |
| Transport loss, no definitive exit, no forced shutdown | 125 |
| Genuine cleanup failure during teardown | 125, overriding the above |

**The cause is never inferred.** Until #467 carries the guest's own signal
identity, `128 + N` exists only for a shutdown the launcher decided on: the grace
expired, or a second interrupt arrived. It is not derived from a `-1` status,
from a missing exit event, or from the last signal that was forwarded — a guest
that died of `SIGKILL` inside the VM, or a session whose transport died, would
then be reported as `143` because we once sent `SIGTERM`, which states a cause
nobody observed. Telling a guest's *own* signal death from its exit status needs
the runtime to carry `WIFSIGNALED`/`WTERMSIG`, which is #467 and not this change.
When both signals exist, the invariant is that the first one only starts the grace
and the one that *interrupts* is the one reported: `SIGINT` then `SIGTERM` exits
143, while a grace expiry after a single `SIGINT` exits 130. The interrupting
signal is not forwarded — it ends the session.

Three mechanism choices carry the rest:

- **Signal identity is a byte, not a flag.** `secret.rs`'s guard records an
  arrival in a per-signal `AtomicBool`, which answers "did it arrive". Supervision
  needs "how many times, in what order", because the first interrupt starts the
  grace and the second ends it. Each handler writes its own signal number to a
  non-blocking self-pipe, and a dedicated blocking thread turns bytes into
  arrivals on an **unbounded queue that exists before the first poll**, so an
  arrival during installation or before the session loop runs is neither lost nor
  coalesced.
- **Not `tokio::signal`.** Its registration is permanent: the process would keep
  swallowing `SIGINT`/`SIGTERM` for the rest of its life. The disposition is
  saved and restored instead, and the guard outlives the **teardown** as well as
  the session — a default disposition restored mid-cleanup would kill the
  launcher with the VM still running, which is the orphan-VM failure the teardown
  exists to prevent. A signal that arrives during teardown is therefore absorbed,
  bounded by the teardown's own timeouts. `SIGWINCH` keeps using `tokio::signal`;
  restoring `SIGINT`/`SIGTERM` does not disturb that separate registration.
  `SIGHUP`/`SIGQUIT` are not supervised: they keep their ordinary disposition,
  which a default-disposition termination does not let `Drop` restore the
  terminal for (unchanged from #400).
- **One pinned deadline.** It is created with the first forwarded signal and
  polled as a branch, never recreated per poll and never reset by a second
  arrival or by output activity, so a guest that keeps writing cannot extend the
  grace.

A forced end is reported as such to the caller, which tears down with
`cleanup_exec_sandbox_failures`'s explicit **forced** mode: no graceful stop (a
guest we have decided to kill must not get `EXEC_STOP_TIMEOUT` worth of asking,
and that skipped stop must not be recorded as a cleanup failure the shutdown
caused itself), then the same bounded kill → reap → remove. The ordinary mode is
unchanged and still records a failed stop that a later successful kill cannot
erase.

The launch installs the handlers before the session exists; the PTY session's
first resize is a held branch rather than an unsupervised await before the loop,
and its drain barrier races supervision as well, so an interrupt during a blocked
flush stops the drain **and keeps the status the guest did report** — the guest is
no longer running there, so `128 + N` would be a guess. The grace is a fixed
constant with no option and no environment override; the subprocess cases inject
a shorter duration so they assert the rule rather than waiting out the number.

### Guest `PATH`

`attach()` and `exec()` both spawn the command directly, so the child receives
only the environment carried by the exec request; the launcher must supply
`PATH` explicitly. After the sandbox boots, the launcher takes the resolved
`PATH` from the created sandbox's OCI config (the last `PATH` entry, matching
successive shell assignments across base and derived `ENV` layers) and sets it
per exec, on both the attach and streaming builders.
`FALLBACK_GUEST_PATH` applies only when the acquired image declares no `PATH` at
all — never merely because a cold launch had no cached metadata — and
microsandbox's agentd prepends its own script directory at exec time.

Agent binaries live under `/opt/agent` — a shared, world-readable prefix
(`chmod -R a+rX`) rather than `/root` — so the same `PATH` resolves identically
whether the guest runs non-root or as root. What the guest actually starts with
is part of the **[boot image contract](USAGE.md#boot-image-contract)**; this
section is orientation, not the contract.

### Guest user (non-root by default) / `--root`

Full rationale in
[ADR-0001](docs/adr/0001-non-root-guest-via-native-user.md) and
[ADR-0002](docs/adr/0002-mirror-host-home-and-username.md).

`launch()` resolves root-vs-non-root up front (`--root` or a truthy
`AGENT_VM_ROOT`). In the default non-root mode it passes `libc::getuid()`/
`getgid()` as `"{uid}:{gid}"` to `.user(...)` on the **attach/exec** builders —
not the sandbox builder, because `agentd` (PID 1) has to stay root in order to
`setuid` per exec. The guest gets an `/etc/passwd`+`/etc/group` entry for that
uid via `.patch().append(...)`, and its `HOME` under `/agent-vm-state/home`.

Matching the host uid is not only defense-in-depth: passthroughfs only grants
owner bits to a non-root guest uid when it equals the real host uid, so it is
what keeps the project and state binds writable.

`--root`/`AGENT_VM_ROOT` restores the legacy root guest. Docker-in-VM needs it,
and the Chrome MCP's `sudo -u chrome` path is root-mode-only.

`IS_SANDBOX=1` is set unconditionally. Claude Code refuses to run as root with
`--dangerously-skip-permissions` unless it is set; under the non-root default
that refusal never triggers anyway, and under `--root` this is exactly what the
variable is for. The microVM is the security boundary either way.

### Sandbox liveness: idle detection and runtime exits

A sandbox is a libkrun microVM: the launcher spawns a hidden `msb sandbox …`
child (the VMM) which runs the vendored runtime and never returns — libkrun
calls `_exit()` on shutdown. Three separate things decide when that ends, and
the division of labour between them is the whole design.
Background: [ADR-0007](docs/adr/0007-heartbeat-keep-alive-and-runtime-exit-reporting.md)
— but note that ADR proposes a staleness-budget design that is *not* what
ships; see [issue #86](https://github.com/gregwebs/agent-vm/issues/86).

**The heartbeat monitor only answers "is this sandbox idle?"** `agentd` writes
`/.msb/heartbeat.json` once a second and it appears host-side via virtiofs;
`HeartbeatReader::check` (`vendor/microsandbox/crates/runtime/lib/heartbeat.rs`)
polls it from a monitor task in `vm.rs` and returns exactly three decisions —
`PendingBoot`, `Active`, `Idle`.

A stale or missing heartbeat is deliberately **never, on its own, grounds to
kill a sandbox**. That is the lesson from a long-lived PTY session that got
reclaimed mid-use: under host load or virtiofs write latency `heartbeat_seq`
can stop advancing for seconds while the guest is perfectly healthy, so any
staleness budget kills exactly the busy-but-momentarily-quiet sessions it was
supposed to protect. A busy-but-quiet agent is a healthy agent. Two
consequences fall out:

- **An active exec session is never idle** — `active_exec_sessions > 0` short-
  circuits to `Active` before the idle timeout is even consulted.
- **No heartbeat seen at all is `PendingBoot`, not death.** The monitor has no
  opinion about a guest that never came up.

**Boot failure belongs to the relay, not the heartbeat.** The agent relay's
`wait_ready` owns the 180 s boot deadline: if it fails (or its task panics),
`vm.rs` stores `EXIT_REASON_AGENT_UNRESPONSIVE` and triggers exit. That reason
surfaces in the DB as `TerminationReason::AgentUnresponsive`.

**Idle shutdown is graceful; teardown is bounded.** An `Idle` decision calls
`request_guest_shutdown`, which is `request_guest_shutdown_with_timeout` at a
60 s default; the bounded variant exists for paths that must not wait that long.

**The launcher must never hang on a VMM that is already gone.** agent-vm's
streaming-exec loop (`next_exec_step` in `run.rs`) races the exec event stream
against `Sandbox::wait()` with `tokio::select!`. In the ordinary case the relay
socket closing when the VMM dies ends the event stream promptly (`recv()` →
`None`, handled as an actionable "stream ended without Exited" error rather
than being conflated with "the agent exited 1"). The race is the
belt-and-suspenders backstop for when that does not happen. Because the socket
EOFs essentially instantly on a real VMM kill, `recv() → None` wins the race
almost every time, so `next_exec_step` gives the `wait()` future a bounded
chance to finish *after* the stream closes rather than dropping it mid-flight.

## The default boot image

### What is in it

The independent [image repository](https://github.com/gregwebs/agent-vm-images)
owns ordinary tool-free base and standard Dockerfiles. The base supplies Debian
facilities; the standard extends it with all six agents using committed version
pins/locks and canonical shared installer helpers (not six copied contracts).
Only the standard is published, with independent versions and matching registry
and archive graphs. Its optional Pi wrapper/packages and seed hooks are image
content, not universal custom-image requirements.

```text
source gitlink (contributors only) → independent standard release
                                  → immutable index → native Linux child → msb cache
                                                     ↑
                        CLI/env/config or retained default selection
```

The compiled v0.1.3 initial recommendation names the multiarch **index**. Native
msb chooses the host child; successful first adoption keeps the index reference.
An explicit `image set-default` instead retains the resolved child digest. Installed binary
and runtime paths never read image sources. Chrome remains an optional
[user-Dockerfile example](https://github.com/gregwebs/agent-vm-images/tree/main/examples/layers/chrome-devtools)
in agent-vm-images, not standard content.

Three build-time subtleties are worth knowing:

- The image installs the tool recipes under `HOME=/opt/agent` and makes the
  tree world-readable, which is what lets the same `PATH` work for both
guest-user modes. The prefix
  itself is created by the base (`RUN mkdir -p /opt/agent && chmod 755
  /opt/agent`), so every layer inherits a `a+rX` (C7) starting point.
- The running guest symlinks `$HOME/.claude` onto persistent state, which
  **shadows** the LSP plugin tree baked at build time. The claude recipe
  therefore stashes the plugins to `/opt/agent-vm/claude-seed` and installs a
  first-boot seed hook at `/opt/agent-vm/seed.d/10-claude-plugins`; the launcher
  prelude (`RUN_IMAGE_SEED_HOOKS` in `run.rs`) runs every executable under
  `seed.d/` and also runs a supplied `/opt/agent-vm/seed-claude-plugins.sh` when
  present — tool-agnostic, optional supplied image content rather than a
  compatibility/lineage fallback. Both clauses run on every launch and must be
  idempotent; the launcher makes no claim that the released default supplies
  either (#258).
- The `pi` recipe installs Pi at `/opt/agent-vm/pi` but exposes it through an
  agent-vm-owned wrapper at `/usr/local/bin/pi` that makes three decisions plus
  the mandatory extension: it enforces `PI_SKIP_VERSION_CHECK=1` (agent-vm owns
  the binary, so Pi's update check is unactionable noise); it forwards a Pi
  subcommand verbatim (`pi list`, never `pi -e … list`, which would turn `list`
  into a prompt); it loads the image-owned `claude-bridge` extension only when
  that file is readable and `AGENT_VM_PI_NO_BRIDGE` is unset. It passes
  `--extension /opt/agent-vm/pi-extensions/guest-credential-warning.js` (an
  explicit path, so `--no-extensions` cannot silence it) and, when present,
  a further `--extension` argument for the bridge.
  Following the parity principle it injects no other default — no `--approve`
  and no `PI_TELEMETRY` — so `--approve`/`--no-approve` and telemetry are Pi's
  own and are forwarded untouched. The warning is gated on Pi's own `ctx.hasUI`
  — `true` for `tui`/`rpc`, `false` for `print`/`json` — so machine-readable
  output is byte-clean with no second suppression mechanism.
  [ADR-0044](docs/adr/0044-pi-reaches-host-codex-through-an-image-owned-provider.md)'s
  PR A contract adds a fourth wrapper decision: load the bare `agent-vm-codex`
  extension when readable. On an image carrying A, the warning also appends its
  host-import clause only when that provider registered. The pinned v0.1.3 image
  has neither this activation nor the registry-gated clause; PR B does not ship them.
  The installation and the extension directory are replaceable; the wrapper is
  not — see
  [ADR-0012](docs/adr/0012-stable-pi-image-customization-seam.md),
  [ADR-0021](docs/adr/0021-project-scoped-pi-home-and-wrapper-parity.md) and
  [ADR-0023](docs/adr/0023-image-owned-pi-extension-packages.md).

### Distribution: OCI references, not bind or disk images

microsandbox's `RootfsSource` supports an OCI reference, a host directory
(`Bind`), or a qcow2/raw/vmdk file. agent-vm uses the OCI path, booting the
selected image verbatim (see
[USAGE](USAGE.md#selecting-the-boot-image)).

```text
[CLI/env/config tiers] ─┐
                        ├─► boot_image::select ─► image_pin::prepare_selected ─► SandboxBuilder.image(repo@child)
[retained default] ─────┘       (lazy, fallible)               │                              │
   │  user/project config wins over it; an absent              │  no pin: acquire source      │ create (IfMissing)
   │  record falls back to the recommendation                  │  validate · commit first pin  ▼
   ▼                                                           │  with pin: consume child    guest
$HOME/.config/agent-vm/default-image.json ◄───────────────────┴─ (default-tier first pin only,
   (digest-only fallback, #392)                                    after acquisition success)
$HOME/.config/agent-vm/image-pins.json ◄────────────────────────── host approval, every OCI source
$HOME/.config/agent-vm/image-pins.lock
```

The **saved selection is not the image cache.** The record names exact content;
msb owns the bytes and may refetch a missing layer. It is also not a project or
launcher-version artifact: it lives with the user-scoped settings, so a new
project, a cleared cache or a new `AGENT_VM_STATE_DIR` leaves it alone. Reading
it is lazy and read-only, which is why `help` and `doctor` touch nothing;
automatic adoption happens only after a default-tier image is actually acquired,
and it happens for every successful default-tier preparation — not only a first
pin — while staying write-once, so an existing record is never moved by a launch.

**Approval is not cache evidence either.** Every OCI selection — from any tier —
is keyed by its canonical reference plus the host Linux platform in
`image-pins.json`. A launch or setup consumes the approved host child and never
resolves the selected tag; only `image refresh` and `image set-default`
re-resolve and ask. The store is host-wide (projects and state roots share it)
and holds no cache path, timestamp or launcher version: deleting the cache
reacquires the approved digest, and deleting the store is a deliberate approval
reset. Local rootfs/disk launches bypass this path with their text unchanged.
`agent-vm image show` is the one *disclosure* edge: it returns the selected
source and its provenance from the same selector (and the same single
journal-aware default observation), before runtime discovery, and creates or
acquires nothing. It does not print the approved child digest.
`agent-vm image import` observes the same selector after publishing, but decides
only whether to print guidance and never discloses the selection (#385).

```text
boot_image::inspect_selection ──► escaped "Image:/Source:/File:" report ──► stdout
   (same select(); default slot read only if the fallback wins; no runtime, cache, registry or write)
```

Explicit `image set-default` adds a separate edge:

```text
image set-default --image REF
  → canonical typed target (ambient selection ignored)
  → healthy pin/default snapshot → resolve current registry content ONCE
  → validated candidate → approval (first/unchanged: none; changed: prompt or --yes)
  → revalidate the frozen candidate under a fresh shared barrier
  → shared cache barrier → pin EX → default EX (journaled transaction)
      atomic pin store {old pins, pending_default}
      atomic default    {approved host child}
      atomic pin store {new pins, no intent}          ← commit
  → release; completion output is best-effort
```

One resolution per invocation: `AcquireMode::ResolveCurrent` preserves the
validated host child (and its receipt) itself, so a moving index cannot be
resolved twice and no duplicate derived pull is needed. The returned host
manifest digest, not an index digest or moving tag, is retained. Native auth/TLS, OCI integrity,
materialization and cache I/O are trusted runtime operations. The small platform
conjunction is proved; JSON decoding and platform comparisons are trusted.
Acquisition, the prompt and revalidation run outside the HOME locks. The host
transaction is a compare-and-swap on the revision and digest that were
displayed: same-pin replacement preserves bytes, a peer that moved the pin first
makes this operation fail, and automatic adoption stays insert-if-absent.
Interruption before the final pin write leaves the old pins plus a bounded
`pending_default` intent; the next mutating image command restores the old
logical default (idempotently) before doing its own work. Readers never recover,
clear or write: they observe the old logical state. No fsync/power-loss guarantee
is claimed, and older binaries do not participate in the journal. Old cache
artifacts and active sessions are never removed by set-default. See
[USAGE](USAGE.md#host-wide-approval-of-oci-image-content) for the operational details.

`image refresh` acquires without launching or replacing a retained record;
only a successful default-tier acquisition may initialize an absent record:

```text
image refresh [--image REF] [--yes]
  → the same boot_image selector and broken-config recovery
  → image_pin::update(Refresh) → resolve current registry content once
      → candidate approval (first/unchanged: none; changed: prompt or --yes)
      → revalidate the frozen candidate under a fresh shared barrier
      → journaled pin/default transaction (future launches consume the child)
  → a default-tier preparation also retains an absent record (write-once)
  → completion notice (best-effort; no policy work after commit)
```

No sandbox, guest disk, VM execution, Docker/buildx, curl/wget or alternate
download backend is on this path; a nonbootable OCI image with the right host
platform refreshes successfully. Layer reuse is native: an unchanged manifest
downloads no layer blob and never deletes old artifacts to force freshness.
Refresh is not a launch-time probe and records no marker: a launch makes no
registry request for content it has already approved.

### Canonical target, validated token, cache-only receipt

One spelling selects one cache entry. `image_acquire::reference` is the only
canonicalizer: it lowercases the DNS host, folds the unported Hub endpoints
(`docker.io`, `index.docker.io`, `registry-1.docker.io`) to `docker.io`, then
applies the Hub `library/` rewrite, validates a strict lowercase
sha256/384/512 digest and reparses its own output to prove identical components.
The canonical text keys native acquisition and the cache; the user's original
text survives only as provenance/display.

Native success returns an opaque `ValidatedImage` token rather than a raw
`PullResult`. It keeps the **source binding** (canonical source plus its stated
immutable digest) separate from the **acquired identity** (`repo@child`), and
only this module can mint one. After validation the acquired digest's canonical
metadata is preserved and read back complete.

Preservation is a repair this module performs, not a lock the loader honours: an
archive import that publishes a digest-spelled alias *does* replace that entry,
and the replacement persists until preparation restores validated metadata from
the child receipt, or an explicit immutable acquisition repairs it when no
receipt exists. What protects a launch is that it validates the cached entry
before the SDK consumes it (below): an entry that cannot be repaired and
validated is never silently booted content — it is reacquired from the
selection's stated digest, or the launch fails.

A **launch or setup** canonicalizes its selected reference once, then
`image_pin::prepare_selected` decides what the SDK may consume. An existing
approval is prepared as `repo@approved-child` and validated under the shared
barrier, before the SDK's `IfMissing` create reads anything: complete,
self-consistent digest, host-Linux platform, and the approved digest's own
content identity. The tag/index the user selected is never re-resolved. An
*absent* approval acquires cache-first (`CachedOrAcquire`), validates, and
commits the first pin before create — so a cold first launch does contact a
registry, but only to establish content it (or a concurrent peer) will approve.
A present entry that fails validation is a *miss* for this cache-first read,
which then reacquires the selection's **stated digest** — never its tag — so an
unusable entry can neither be booted nor used to re-resolve mutable content. The
one closed failure is an entry that contradicts its preserved receipt, because
relaxing that would boot content nothing measured. Every OCI consumer — launch,
setup, refresh, set-default — shares this path, so none can quietly consume
unapproved content.

A canonical-source cache hit never rewrites the source key: the entry is already
there and validated, and rewriting a *tag* from metadata read moments earlier
would revert a concurrent `image refresh` that moved the tag. A canonical miss
*(a first pin)* also tries the *original* (pre-canonical) spelling once, so a
cache an older launcher wrote under `registry-1.docker.io/...` or an uppercase
digest hex is reused: its validated metadata is republished under the acquired
child key (which is content-addressed, so it cannot revert a tag) and — only
while that key is still absent — under the canonical source key (tag, index or
direct digest), with guarded native readback. The absence is re-checked under
the canonical key's own guard, because a tag may have moved in the gap; a peer's
publication then wins, and is used when it validates this selection, and is a
miss — reacquiring the stated digest — when it does not; a peer's *pin* wins in
the same way and its frozen digest is prepared instead. The original spelling must still
be supplied for that first compatibility read; we do not scan arbitrary
historical spellings. A first launch after upgrade may reacquire if neither the
canonical key nor that original key has a validated, complete entry. After
migration, canonical-only warm launches need no registry for an approved pin.

A warm launch writes only what it repairs. A digest selection republishes its own
child key from the receipt only when the cache no longer holds that content there
anymore, and a readback that is still incomplete afterwards is the *completeness*
error (the entry exists but cannot back a launch), not a generic identity
failure — the two have different recoveries.

A strict, bounded, no-follow **receipt** lives under
`<cache>/agent-vm-content-metadata/`, never under HOME. It records the preserved
native metadata, platform, content identity (verified config digest plus ordered
layer diff IDs) and up to 256 source bindings, keyed by acquired child and host
platform. Several sources share one preserved metadata record, rather than
replicating metadata per source. Only a source that **states an immutable digest**
is ever bound, because that is the only case the association check consults: a
mutable tag would spend one of the bounded slots on evidence nothing reads, and
per-commit tags would exhaust it for no gain. Bindings are best-effort provenance,
never authority: a fresh acquisition adds its binding idempotently, and a full set
keeps every association it proves and leaves the new source unproven (a later
unequal cache association then reacquires that immutable source) rather than
evicting a proven one or failing content this process already validated. Conflicting
content for the same child is still an integrity error. A digest launch can
restore its own child key from this record even if that digest was never learned as
a source. Native readback checks complete artifacts before SDK consumption. Cache
completeness alone cannot prove that an immutable source resolves to a different
digest; only a successful native acquisition or a previously validated receipt can.
The receipt is not an approval store and deleting the cache deletes only receipts.

A present receipt that cannot be read, or that describes an identity other than
its own key, is a hard error — including on a warm tag launch, which would succeed
without consulting a receipt at all. That is the planned policy: a corrupt record
is never treated as absent, because ignoring it would boot content the cache
cannot account for. The rendered text names only cache-side recovery (restore the
image cache from a backup, or remove the receipt and re-acquire) and never
suggests deleting HOME approval records, a store acquisition does not touch.

### Host-wide approval: store, candidate and journal

`image_pin` is the only module that answers "may this content be consumed?".
It owns two small HOME files, separate from the retained-default record:

```json
{"version":1,
 "pins":[{"reference":"docker.io/library/alpine:latest",
           "platform":{"os":"linux","architecture":"arm64","variant":null},
           "manifest_digest":"sha256:<64 hex>","revision":1}],
 "pending_default":null}
```

`image-pins.json` is strict version-1 JSON: unknown, duplicate or missing fields,
duplicate canonical keys, unsupported versions, invalid/zero/overflow revisions,
non-canonical spellings, non-regular/symlink/oversized files and trailing bytes
are closed corruption errors. Only `ENOENT` means "absent". Bounds are 4 MiB,
4096 pins and 4096 source bytes, checked on read and before every write.
`image-pins.lock` is a stable private flock: a bounded shared snapshot for
lookups, one exclusive read-modify-write for a commit. A missing lock beside a
store is damage, not absence; a lock without a store is a valid first-writer
state. Platform entries for a foreign architecture are preserved verbatim but
never borrowed as native approval.

**Candidate-scoped consent.** `ValidatedCandidate` can only be minted from a
complete native acquisition; `Approval` binds that candidate's digest and the
predecessor revision/digest that were displayed. The prompt renders the escaped
source, the platform and both full digests, defaults to No, reads one bounded
line and never reprompts. `--yes` skips the read but not the rendering. Both
stdin and stderr must be terminals for an interactive replacement; otherwise the
operation refuses with status 1 without reading stdin. The mutation is a pure
decision on one measured under-lock snapshot (`insert only if expected and
current are absent`, `replace only for a mutable source with consent and a
matching predecessor`), so a concurrent writer cannot be overwritten and
`--yes` cannot authorize a different predecessor.

**Approval equivalence is guest content, not index identity.** Two manifests are
the same approval when their verified config digest and ordered layer diff IDs
match. An alternate digest algorithm, or index movement that changes only
unrelated platforms, therefore keeps the stored identity and revision; new guest
content needs a replacement approval. An immutable source that resolves to
different content is an integrity failure with no approval path.

**Why two files and a journal, rather than one record.** `set-default` updates
both the approval and the retained fallback. Writing either first and failing the
second would return an error with changed state, and rollback can itself fail. A
bounded `pending_default` intent (`previous`/`proposed` exact v1 bytes, each
≤16 KiB) records the logical pair across three atomic writes; a failure before
the final commit restores the previous fallback bytes (or their absence), and a
failed restoration leaves the old pins plus the intent authoritative as a
recovery-required error rather than a false "nothing changed". Recovery is
idempotent, verifies the physical fallback equals the intended side of the pair,
and only the next *write* performs it: an explicit image command, or a launch or
`setup` that has to record a first pin or retain an absent fallback. Readers —
launch of an approved selection, `image show`, `doctor`, import's
post-publication inspection — never recover, clear intent or create the lock;
they take the shared lock (2 s) and
observe the old logical state or the complete new one. A damaged store is never
treated as absent: re-pinning would authorize content nobody approved. Moving
it aside is a deliberate approval reset, never cache repair. This journal is
specifically for failed-operation preservation; it is not a durability claim
against power loss, and older binaries do not know about it.

**What stays outside approval.** The cache receipt is cache evidence: it proves
which child a digest-stated source was validated against and repairs metadata an
alias overwrote, and deleting the cache deletes only receipts. Native cache
publication from import/build takes the exclusive barrier but can never create or
replace a HOME pin or fallback (#391). Local rootfs/disk launches never enter
this module. See
[ADR-0047](docs/adr/0047-host-wide-oci-image-approval.md) for the decision and
its rejected alternatives.

### Same-cache publication barrier and reference guards

`<actual backend cache>/.agent-vm-publication.lock` is one stable `flock`:

- **shared** for acquisition/validation, canonical metadata and receipt writes,
  launch and setup through the SDK's cache consumption, and explicit refresh;
- **exclusive** for archive publication (import/build) from the requested-alias
  snapshot through the loader or its rollback.

Lock order is one hierarchy, never host→cache: publication barrier → reference
guards sorted by native metadata-key bytes → native per-reference pull lock →
native content locks. A second, derived reference guard is taken only after the
source guard is released, so two peers cannot invert the order. Warm unrelated
preparations share the barrier and proceed while a cold acquisition is stalled
in a registry stream; a shared holder never upgrades in place.

The HOME transaction is a **separate hierarchy entered after acquisition**, never
nested inside a cache reference guard: `image-pins.lock` (exclusive) → retained
`default-image.lock` (exclusive), held together for one bounded read-modify-write
(30 s combined), released before any completion output. A launch or setup first
pin commits while the preparation still holds the shared barrier, so validated
content cannot be republished away between validation and commit; an explicit
update revalidates its frozen candidate under a fresh shared barrier immediately
before the transaction. Network I/O and the human prompt
never run under a HOME lock; a shared cache holder therefore never blocks on a
human, and an EX cache publisher cannot starve a bounded reader beyond its
deadline.

The reference guard is a persistent sibling of the native reference metadata in
the **actual backend cache**, keyed by the canonical reference. It serializes
only callers of this helper — refresh, setup's acquisition, set-default — even
across state roots or `HOME`, and covers snapshot → native pull → validation →
rollback. Unmodified `msb pull`, direct SDK clients, cache deletion/GC and older
launchers do **not** take it; the barrier is what excludes archive publication
from a launch, not those writers. No fsync/power-loss or process-kill rollback
is claimed, and selection/adoption still happens strictly after successful
validation.

- **Standard OCI semantics.** microsandbox's layer cache, GC, snapshotting, and
  metadata DB all key off OCI references. Going through that path means getting
  all of it for free.
- **`Bind` would need overlay management.** It hands a host directory to the VM
  as the rootfs, so sharing one template across concurrent sandboxes would mean
  building copy-on-write on top. The layer cache already does this.
- **A disk image would mean building rootfs images ourselves** with
  `debootstrap` + `mkfs.ext4` — a slower, less familiar loop than
  `docker build`.

The binary and the image are not locked by any image-side stamp. What an image
must provide is the **[boot image contract](USAGE.md#boot-image-contract)**: a
host-architecture Linux image with Bash on `PATH`, the selected program
executable by the guest user, and a runtime-initializable `/etc/passwd`/
`/etc/group`. A breach is a clean launch-time diagnostic, not a mysterious in-VM
failure.

Image authoring and publication belong to the independent image owner and do
not recompile the launcher. Users explicitly build/import through
`agent-vm image build|import` (`image_build`/`image_import`, both publishing via
`image_publish`):

```text
main input preflight → MSB prologue → ambient cache → completed export/save/archive
  → exclusive publication barrier
  → native materialization → sequential tag/alias publication
                            → on failure: restore requested tag only
```

Failed exporters never import, even if complete bytes were emitted. Native
publication includes archive aliases, not just --tag; rollback restores only
the requested reference, which import infers from a `--docker` source when
`--tag` is omitted. Cache-only import avoids a fallible database persist after
publication; first launch persists cached metadata normally.

Import has one **advisory, post-publication** edge back into selection: after a
successful publication it observes the selection once, through the same
`boot_image` selector and environment rule as `image show`, so a result
reference the configuration already selects prints no launch guidance (#385).
Build consults no selection. Neither verb writes configuration, adopts a
default, boots or acquires anything; a failed observation leaves the completed
import successful and only adds the `image show` hint. See [the canonical user
contract](USAGE.md#explicit-builds-and-archive-import) for driver limitations,
archive workflows and host-build trust.

The Rust side does own the **verify** step (boot the pulled image, run the
agents' `--version`), because that is exactly the SDK call the launcher makes —
exercising it from `setup` catches image/SDK integration regressions before a
user session depends on them. `--no-verify` skips it for Dockerfile iteration;
`--image` / `AGENT_VM_IMAGE_TAG` / a config `image` selects an alternative
tag without touching `build.sh`.

## Credentials

The guarantee: **a real token never enters the VM, in any form.** Not in the
environment, not in a file the guest can read, not in the sandbox config, and
not in an OAuth response. The guest holds placeholders; the proxy substitutes
on the way out.

Current design of record:
[ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md).

### Values you store yourself (`agent-vm secret`)

Everything above reads a credential another tool wrote on the host. A credential
the *user* gives agent-vm directly — an API key no agent CLI owns a file for —
has its own home: agent-vm's namespace in the host OS credential store (macOS
Keychain, Linux Secret Service), managed by the three `agent-vm secret` verbs.
This is the **storage lifecycle**. Nothing here prints or renders a value; the
**one** thing that reads one back is an authorized launch, for a service the
user's `credentials.yaml` names *and* the launch requests
([ADR-0025](docs/adr/0025-yaml-credential-shielding.md)), and even that reads it
through agent-vm's own store and per-launch resolver (both host-side code) and
hands it to the runtime's resolver without writing it to any durable artifact.
Authorization and injection are separate host configuration
([ADR-0024](docs/adr/0024-host-secret-inventory.md)).

```text
  user ── hidden prompt / piped stdin ──▶ agent-vm secret set SERVICE
                                             │
                    host OS credential store │ dev.agent-vm.credentials / SERVICE
                    ◀── secret ls (names + storage status only) ───
                    ◀── secret rm (delete one entry) ─────────────
```

The store's namespace is host-wide, so its **names-only inventory** lives in the
user-scoped `~/.config/agent-vm/` rather than under the state dir — the OS
credential store exposes no portable enumeration API, so `ls` probes one name
per recorded entry. The inventory holds no bytes, which is what makes a listing
structurally incapable of printing a value. The write ordering (inventory first),
the `flock` around every mutation, the re-probe after a delete, and the closed
error classification are all [ADR-0024](docs/adr/0024-host-secret-inventory.md),
with the boundary predicates' machine-checked contracts in
[ADR-0018](docs/adr/0018-machine-checked-boundary-contracts.md)'s list.

### User-authorized YAML credentials (#161)

The second kind of shielded credential is one the user authorizes in
`~/.config/agent-vm/credentials.yaml`: a named credential source, the exact HTTPS
origin, and the exact request header the value may occupy. A tool's
`credentials = [...]` then *requests* it; the request cannot define or widen the
authorization. Injection is host-side, into that header only, and the guest
holds a non-secret placeholder (`sentinelEnv: true`) or nothing.

```text
  ~/.config/agent-vm/credentials.yaml ── authorization (origin + header) ──┐
  tool config `credentials = [...]`   ── request ────────────────────────┤
                                                                         ▼
                      launch resolution (phase 1: availability, value dropped)
                                                                         │
  host keychain or captured host env (`source: env`)
                └──▶ per-launch resolver (phase 2, at fork) ──▶ private fd ──▶ HTTPS header
                                                                         │
                              guest: placeholder or unset ◀──────────────┘
```

For a launch, environment sources are captured and removed in `main` before that
launch's children and Tokio workers exist; keychain sources retain their
two-phase reads.

The load path, the grammar, the guest-variable ownership rules and the exact
guarantee (application-level only; OS swap and same-uid inspection are out of
scope) are [ADR-0025](docs/adr/0025-yaml-credential-shielding.md). This path
does **not** use `<state_root>/<hash>.secrets/`: no plaintext value about it is
written to a file at all (the credential *reference* is durable in the sandbox
record, and the store creates only a lock file — neither carries the value).

**Precedence (#162).** A requested name is resolved against the user's YAML
first, then the compiled-in providers. A YAML entry named after a built-in
provider (`anthropic` / `openai` / `opencode-static` / `copilot`) completely
replaces that provider's **credential** handling — host capture, guest
placeholder, proxy injection, OAuth capture/refresh — with no fallback. Its
**configuration and persistence** (onboarding bypass files, `$HOME` links, state
dirs, Copilot's `trusted_folders`) are untouched. The decision is one fact, a
`ProviderSet` of replaced providers computed in `credential_resolver` and
consumed by one capture predicate in `secrets`; everything downstream follows
from `CredsState::wired()` being derived from the captured token files.

```text
  requested name N ──▶ authorized in credentials.yaml?
                          │ yes                     │ no
                          ▼                         ▼
            YAML path                       N a built-in provider?
            • N is "replaced"                 │ yes          │ no
            • suppress the built-in's         ▼              ▼
              credential facets          built-in path   --allow-missing-credentials?
              (capture, placeholder,     (unchanged,       │ yes        │ no
               proxy, OAuth)              incl. its       ▼            ▼
            • register the header         hard bail)   warn+skip    hard error
              credential host-side
            • no fallback if unavailable
```

The availability override is a host-only launch flag
(`--allow-missing-credentials`) selecting `MissingCredentialPolicy::Warn` for
phase-1 resolution. It moves the availability of a *YAML* credential only, and
cannot bypass a malformed authorization file, a rejected stored value, an
owner/mode integrity refusal, a guest-variable conflict, an image-`ENV`
collision, or a built-in provider's own missing-credential bail. `capture_decision
(provisioned, replaced) = provisioned && !replaced` carries the machine-checked
contract ([ADR-0018](docs/adr/0018-machine-checked-boundary-contracts.md)).

### Guest-managed Pi credentials

Pi is the one agent that can *create* a credential inside the guest (its normal
multi-provider `/login`), and since #96 that credential persists in the
project's state ([ADR-0011](docs/adr/0011-pi-mixed-credential-ownership.md),
[ADR-0021](docs/adr/0021-project-scoped-pi-home-and-wrapper-parity.md)). Any
process in that project's guest can read it, so
`pi_credential_inspection::inspect_project` reports it on **every** launch and
from `agent-vm doctor`:

```text
   [project state, untrusted guest-controlled files]
        pi/agent/auth.json    pi/agent/models.json
                 |
        no-follow, bounded, read-only acquisition
                 |
   [Pi credential inspection module]
     structure -> classification -> safe report
             /                    \
     launch notice (stderr)     doctor (stdout)
```

The module is a *structural classifier, not a resolver*: it never runs
`!command` values, expands environment references, refreshes OAuth, imports a
host credential, or writes/renames/removes anything. It reuses
`GuestStateDir`'s descriptor-anchored no-follow reader (`host_paths.rs`) and
returns only a validated provider ID, a closed kind (`api_key`/`oauth`/
`configuration`/`unknown`), closed field labels, and fixed reason labels — so
raw JSON, credential bytes, commands, environment names, model IDs and URLs
never cross the interface. Acquisition is bounded by
`MAX_GUEST_STATE_FILE_BYTES`, retained findings by `MAX_RETAINED_FINDINGS`
(128 + one truncation notice), each JSON container by `MAX_CONTAINER_ITEMS`
(4096 object members or array elements, past which the document is rejected),
and JSON is parsed with duplicate-member rejection (a `real key` followed by a
`placeholder key` must not read clean).

Reporting is **not** ownership authorization. "Contains no secret bytes" is
weaker than "this exact provider entry was generated by agent-vm": any code that
overwrote guest state would need a stronger, per-provider ownership predicate
rather than treating a clean report as permission to do so. (The native-Pi
host-import route this was written for, #94, has been closed as superseded by
[#164](https://github.com/gregwebs/agent-vm/issues/164), which imports *Claude
Code's* credential through the existing Anthropic provider instead; nothing
consumes this report as authorization.)

The host Pi files `~/.pi/agent/{auth,models}.json` are a *different* category:
ADR-0020's protected-host-file machinery refuses or advises on a host mount that
would expose them, and that behavior is unchanged here. #93 scans only the
project-scoped *guest* state, not the host home.

### The two-layer placeholder dance

Per **provisioned** provider, at every launch (capture is gated on the launch's
provisioning set — the tools the launched tool declares, transitively; see
[ADR-0017](docs/adr/0017-tool-declared-provisioning.md); `pi` is the one shipped
verb whose provisioning set is wider than its requirement set, through the
`pi -> claude` and `pi -> codex` edges):

1. **Host side.** agent-vm reads the host credential file
   (`~/.claude/.credentials.json`, `~/.codex/auth.json`,
   `~/.local/share/opencode/auth.json`, `gh auth token`), and writes the real
   bearer to a host-only file with 0600 perms via atomic-write-then-rename.
   Placeholder *constants* live in `secrets.rs`
   (`ANTHROPIC_ACCESS_PLACEHOLDER` and friends) — always prefer the constant
   over the literal so a rename cannot drift.
2. **Guest side.** A placeholder credentials JSON goes into the per-project
   state dir. Other fields (`expiresAt`, `scopes`, `account_id`, …) are copied
   from the host file so the in-VM agent sees a plausible shape.
3. **On the wire.** The TLS-intercept proxy sees
   `Authorization: Bearer msb-…-placeholder-…` going to an allowed host,
   splices in the real token, and forwards.

Placeholders are kept **short**: long ones (more than a few hundred bytes)
break sandbox boot at the runtime handshake with `handshake read id_offset:`.
Where a provider requires a JWT *shape*, the placeholder is a minimal
`alg:none` synthetic JWT rather than anything realistic.

Substitution is bound to an **exact host** per credential, so a placeholder
that reaches any other host is never swapped — and, because microsandbox
treats a placeholder heading somewhere unexpected as a violation, is blocked
and logged rather than leaked.

### Token files live outside the guest bind mount

The per-project `state_dir` is bind-mounted into the guest as a single mount,
which makes mount placement security-critical: **anything under `state_dir` is
readable from inside the VM.**

Real token files therefore live in a *sibling* host-only directory,
`${state_root}/<hash>.secrets/` (0700), derived from `state_dir` by
`secrets.rs` so the launcher and the hook agree on the path without passing it
around. The proxy reads them host-side, so they never need mounting at all.

A `token_files_live_outside_the_guest_mount` unit test pins the invariant.

### File-backed secrets and per-connection re-read

The launcher hands microsandbox a `SecretSource::File` path rather than a token
string. The proxy resolves it at **connection-setup** time, so every new TCP
connection re-reads the file and any host-side rotation — by our own refresh
hook, or by the user simply running `claude` on the host — is visible to the
very next request with no sandbox rebuild.

This is also why token bytes are never serialized into sandbox configuration:
the config carries a path, not a secret.

### The OAuth refresh MITM

The launcher registers an interceptor with per-route rules:

```rust
.intercept(|i| i
    .hook(["…/agent-vm", "_intercept-hook", "--state-dir", "…"])
    .rule("platform.claude.com", "POST", "/v1/oauth/token")
    .rule("auth.openai.com",     "POST", "/oauth/token"))
```

When the in-VM agent posts a refresh, the proxy buffers the request (2 MiB cap;
oversized OAuth and GitHub API requests are refused, while smart-HTTP dispatches
on headers and streams its body after the repository verdict), spawns the hook
with the bytes on stdin and the matched route in env vars, writes the hook's
stdout back to the guest under the forged TLS cert, and closes — **without ever
contacting the upstream server**.

The hook is the same binary in a hidden subcommand:

1. **Validate before acting.** Strict HTTP/1.1 framing, Host/SNI/authority,
   exact provider route, encoding, grant type, and the refresh placeholder are
   all checked before anything can take a lock, spawn a process, or touch a
   file.
2. **Inspect with a fresh clock.** A bearer comfortably above the serving floor
   is re-synced and served with **no host command spawned**. A missing,
   unreadable, or malformed credential never spawns one either — it is
   unavailable outright, and host `claude login` / `codex login` is what
   recovers it.
3. **Rotate only when due.** A bearer at or under the provider's serving margin
   takes a per-provider host-only lock (bounded, 20 s ceiling), re-reads under
   the lock, and — unless it is already fine or damped by a fresh 30-second
   attempt stamp — runs the host CLI (`claude -p hi --model sonnet`, or
   `codex exec --skip-git-repo-check 'Reply with OK'`) in an empty 0700 working
   directory with a cleared allow-listed environment, no bypass flags, and a
   bounded process-group reap. The CLI rotates the host credential file the
   ordinary way.
4. **Install under the lock.** Whether the CLI ran, failed, or was skipped, the
   hook re-reads the host file once more *while still holding the lock* and
   rewrites the host-only token file. Holding the lock through the install is
   what stops a launcher from re-capturing a stale host snapshot and clobbering
   a token this rotation just installed.
5. **Reply in placeholders only.** The response is a synthesized OAuth
   refresh-response JSON shaped like the upstream server's, with placeholder
   `access_token`/`refresh_token`. `scope` is always a bounded, RFC 6749
   `scope-token`-filtered, space-joined string that always contains
   `user:inference` — normalized, never passed through from host data. Every
   expected post-validation failure becomes a typed `503
   temporarily_unavailable` naming the host re-login command, never a raw error
   or a dropped connection.

Stdout is the interceptor protocol channel, not a logging sink; that is what
resolves the cleartext-logging concern without suppression.

**Why a subprocess and not a callback.** `Vec<Box<dyn RequestInterceptor>>` is
not serializable, and the network config is JSON-piped from the SDK to a
separate `msb` process, so anything configured SDK-side has to round-trip
through JSON. Refresh requests are rare — once an hour at worst — so
fork-per-request costs nothing against the host CLI invocation the hook makes
anyway. And a subprocess can dispatch on any logic without re-extending
microsandbox per provider.

**Single-flight.** Same-provider, same-project refreshes serialize on a
host-only `flock` held through final credential installation, with the
attempt-damping stamp so a late waiter skips a redundant CLI run. Cross-project
refreshes may still duplicate work and fall back on the provider CLI's own
locking.

### GitHub scoping

`gh`/`git` credentials are constrained to a per-launch repository allow-list,
built from the cwd's `git remote -v`, its `.gitmodules`, and any `--repo`
overrides.

Allow-listed REST routes receive the bearer; off-list, malformed, and unknown
REST routes get a synthesized 403. Off-list smart-HTTP alone may continue
**anonymously**, with `Authorization` stripped, so a public clone still works.
GraphQL mutations are denied outright until they can be bound soundly to an
allow-listed repository — a deliberate compatibility cost (see
[ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md)).

### Static provider keys and guest-state safety

OpenCode static API keys are captured only for OpenCode and `shell` launches,
each stored in its own 0600 sibling file and substituted only on its exact
provider host. They have no hook route and refresh on relaunch, not in session.
Copilot is file-backed the same way and likewise has no in-session refresh.

Guest state is writable by the guest uid, so it is never trusted through a
joined pathname after launch. Reads, create-if-absent defaults, and atomic
replacements all use descriptor-relative no-follow opens anchored under the
opened state root, portably across Linux and Darwin.

A launch whose Claude credential could not be captured **fails closed before
boot** rather than starting a signed-out agent — and `secrets::refresh` removes
any guest Claude placeholder left from an earlier successful launch, since a
stale placeholder would be sent verbatim as a bearer and the agent would look
signed in until every request 401'd.

### Host-credential security snapshot

At launch, `snapshot_host_creds` SHA-256s the three host credential files;
`verify_snapshot` re-hashes them on exit through a `SnapshotGuard` `Drop` and
prints one line naming any that changed.

**Non-fatal by design.** The refresh hook legitimately rewrites these files
mid-session, so a change is not proof of tampering — the value is that an
*unexpected* change becomes visible. Failing a launch on a legitimate refresh
would be worse than the warning.

**The `Drop` impl must never panic.** It has nowhere to propagate an error, and
`eprintln!` panics on a stderr write failure, which would convert a clean
launch failure into an abrupt exit-101. The notice is therefore a best-effort
`writeln!` with its result discarded.

Scope is those three files only; project-integrity checks are not implemented.

### Verified behaviour

The guarantee has been checked from inside a guest, not just reasoned about:

- `cat` of the guest credentials file shows the placeholder, not the token.
- `/proc/1/environ` contains no real token.
- A TLS-intercepted request shows the microsandbox CA on the server cert,
  confirming it goes through the substitution proxy.

And the refresh path end-to-end, against a real host `claude`:

```
Guest → POST https://platform.claude.com/v1/oauth/token
        {"grant_type":"refresh_token","refresh_token":"…PLACEHOLDER_REFRESH…"}

Guest ← HTTP 200 application/json
        {"access_token":"msb-anthropic-placeholder-a-v2",
         "refresh_token":"msb-anthropic-placeholder-r-v2",
         "expires_in":3499,"token_type":"Bearer",
         "scope":"user:file_upload user:inference"}
```

The hook ran, host `claude -p` rotated the host file, the new bearer landed in
`<state>.secrets/anthropic`, and the synthesized response reached the guest.
`expires_in: 3499` is the freshly derived seconds-until-expiry of the token that
was just rotated.

## Runtime and state

### `msb` is pinned via `MSB_PATH`

Every invocation resolves its bundled `msb` and confirms `msb --version`
reports exactly the official upstream version this build vendors
(`msb_install::verify_official_identity`), then sets `MSB_PATH` — the top of
microsandbox's resolution ladder — so a separately installed `msb` cannot
shadow it. Discovery prefers an explicit `MSB_PATH`, then an `msb` sibling in
an installed bundle, then the source artifact at
`vendor/microsandbox/build/msb`. The user's `~/.microsandbox/bin/msb` is never
touched, so other microsandbox tooling on the same host keeps working.

`agent-vm setup` does not build or refresh `msb`; it pulls and optionally boots
the selected image. Production of the vendored runtime belongs to
`script/build/macos.sh`, which drives the pinned macOS build sequence and
assembles the signed artifact with its firmware — so `just` is not a root build
prerequisite. On macOS, Cargo's raw `vendor/microsandbox/target/release/msb`
lacks the `com.apple.security.hypervisor` entitlement and is not a runnable
substitute.

One trap, recorded so nobody re-derives it: the real `msb` binary lives in the
`microsandbox-cli` crate. The `microsandbox` crate ships a *different* `msb`
binary that is a 5-line shim forwarding to `~/.microsandbox/bin/msb`. Building
the wrong target yields a ~389 KB shim that boots silently and then hangs at VM
init, with no VMM symbols in the binary to explain why.

### One shared `MSB_HOME`

agent-vm keeps its sandbox registry in a private `MSB_HOME` rather than the
user's `~/.microsandbox`, so a separately installed `msb ls` does not see
agent-vm's sandboxes and vice versa. It is a single flat directory shared by
every agent-vm build on the host, deliberately *not* namespaced per schema —
see [ADR-0004](docs/adr/0004-single-shared-msb-home.md), and note the macOS
socket-path length constraint that decision turns on.

### Forward-migration preflight

sea-orm migrations in microsandbox are one-way. If a newer, separately
installed `msb` opens agent-vm's private `msb.db`, it forward-migrates the
schema and the older bundled `msb` can never open it again.

`msb_preflight` detects this up front, on both the boot path and the `msb`
passthrough (any msb subcommand can open the db, so the guard cannot live only
in `launch`), and its error names the recovery command. Migration of genuine
0.5.7 state is a separate, supported path:
[ADR-0008](docs/adr/0008-migrate-0.5.7-state-to-v0.6.15.md).

### State operations: `msb` passthrough and `doctor`

**`agent-vm msb <args…>` is a verbatim passthrough** (`msb_cmd.rs`), not a
curated subset: it execs the pinned binary with `MSB_PATH`/`MSB_HOME` already
set, inherits stdio and environment, and maps the child's exit status through
(signal death → `128+signo`, so it can never read as success). Re-exposing a
chosen subset would mean tracking msb's CLI forever; the point is that `ls`,
`ps`, `stop`, `exec`, `logs` and the rest work exactly as documented upstream.
`disable_help_flag` lets `--help` reach msb instead of clap.

**`agent-vm doctor` is the operator surface** (`doctor.rs`) for two questions
the launcher cannot answer mid-failure: what credentials the host actually has
(present / absent / unusable, Claude token expiry, and which reached this
project — never token bytes), and whether the private db is recoverable. It
renders the same guest-managed Pi report described under
[Credentials](#credentials) without starting Pi (`inspect_project` is shared
with the launch notice).

Ordinary `doctor` is dispatched **before** microsandbox bootstrap (`main.rs`),
so it performs no initialization: it neither spawns `msb --version` nor creates
or rewrites `MSB_HOME`. It therefore works on a missing or unpatched `msb`, and
it reports computed paths rather than validating that binary. The only mutating
operation remains `--reset-msb-db`, below.

`--reset-msb-db` moves `MSB_HOME/db` aside to a timestamped sibling rather than
deleting it: reversible by construction, and the undo command is printed. That
command refuses — naming the path, with a nonzero exit — if a launch has
recreated `db/` since (ADR-0051). msb owns
that directory outright — no agent-vm code creates, opens, or writes it — so it
recreates it at the bundled schema on next boot and re-pulls images.

### Shared OCI image cache (opt-in)

`AGENT_VM_SHARE_MSB_CACHE` points msb's image cache at the
`~/.microsandbox/cache` a separately installed msb uses, instead of agent-vm's
private `MSB_HOME/cache`; `AGENT_VM_MSB_CACHE_DIR` overrides the location for a
non-default layout (`msb_install.rs`).

Off by default, because sharing a cache couples agent-vm's image state to a
binary it does not version-check. The value goes through the strict `env_flag`
parser, so a typo fails closed to the private cache rather than silently
enabling sharing.

## Host-side tools

### Clipboard exchange

`agent-vm clipboard {get,put}` (`clipboard.rs`) moves a string across the VM
boundary through a per-project file on the state mount (see
[USAGE](USAGE.md#clipboard)).

**Why a file and not a channel.** The guest already has the state mount; a file
needs no new device, no port, no protocol, and no guest-side agent-vm binary —
the agent just reads and writes a path. A vsock or HTTP channel would add a
second control plane for a feature whose entire job is handing over some text.

**Why the system clipboard is opt-in (`--sys`).** Reaching X11/Wayland/macOS
pasteboard means shelling out to whichever of `xclip` / `wl-copy` / `wl-paste`
/ `pbcopy` / `pbpaste` exists — a host-environment dependency. Without the
flag the command is pure stdio and works headless.

### `agent-vm-ccusage`

`bin/agent-vm-ccusage` unions the host's `~/.claude` session history with every
per-project agent-vm session dir under the state root and hands the combined
list to `ccusage` via `CLAUDE_CONFIG_DIR`, so token/cost reporting covers host
*and* sandbox sessions in one summary.

It *skips* any directory whose path contains a comma: `CLAUDE_CONFIG_DIR` is
comma-separated with no escape mechanism, so such a path would silently
mis-tokenize into two wrong directories. Skipping with a warning beats merging
directories the user never asked for. The state-root precedence is in
[USAGE](USAGE.md#token-usage-across-host-and-sandbox).

## Decision record index

| Decision | ADR |
|---|---|
| Non-root guest via a native user | [ADR-0001](docs/adr/0001-non-root-guest-via-native-user.md) |
| Mirroring the host `$HOME` and username into the guest | [ADR-0002](docs/adr/0002-mirror-host-home-and-username.md) |
| Project tooling layers (`.agent-vm/layers/`, plus any `--layer DIR`; superseded by ADR-0035) | [ADR-0003](docs/adr/0003-project-tooling-layers.md) |
| One shared `MSB_HOME`, not schema-namespaced | [ADR-0004](docs/adr/0004-single-shared-msb-home.md) |
| Deferring the sea-orm / sqlx major bump | [ADR-0005](docs/adr/0005-defer-sea-orm-sqlx-major-bump.md) |
| Adopting a clean microsandbox v0.6.15 baseline (dropping the libkrun fork; baseline superseded by ADR-0027) | [ADR-0006](docs/adr/0006-adopt-clean-v0.6.15-baseline.md) |
| Heartbeat keep-alive and runtime-exit reporting | [ADR-0007](docs/adr/0007-heartbeat-keep-alive-and-runtime-exit-reporting.md) |
| Migrating 0.5.7 state to v0.6.15 (target restated as the v0.7.4 schema by ADR-0027) | [ADR-0008](docs/adr/0008-migrate-0.5.7-state-to-v0.6.15.md) |
| Adopting `origin/main`'s network features (branch framing superseded by ADR-0027) | [ADR-0009](docs/adr/0009-adopt-origin-main-network-features.md) |
| Wiring file-backed credential injection | [ADR-0010](docs/adr/0010-wire-file-backed-credential-injection.md) |
| Pi uses mixed credential ownership (guest-managed report) | [ADR-0011](docs/adr/0011-pi-mixed-credential-ownership.md) |
| A stable wrapper around image-installed Pi | [ADR-0012](docs/adr/0012-stable-pi-image-customization-seam.md) |
| Forked mounts and opaque exclusions (superseded for file forks and live exclusions) | [ADR-0013](docs/adr/0013-add-forked-mounts.md) |
| Narrowing fork mounts to directories; files read-only | [ADR-0014](docs/adr/0014-narrow-fork-mounts-to-directories.md) |
| User-authorized YAML credentials (`credentials.yaml`) | [ADR-0025](docs/adr/0025-yaml-credential-shielding.md) |
| Accepting Basic auth in the header substitution scope (microsandbox 0.7.4) | [ADR-0026](docs/adr/0026-accept-basic-auth-in-header-substitution-scope.md) |
| Adopting the v0.7.4 fork baseline (supersedes in part ADR-0006's baseline, ADR-0008's target and evidence base, and ADR-0009's branch framing) | [ADR-0027](docs/adr/0027-adopt-v0.7.4-fork-baseline.md) |
| An explicit `--image`/`--base-image` overrides the other flag's environment variable (superseded by ADR-0035) | [ADR-0028](docs/adr/0028-explicit-image-flag-beats-the-other-environment-variable.md) |
| Compose tool images by layer stitching (superseded by ADR-0035) | [ADR-0029](docs/adr/0029-compose-tool-images-by-layer-stitching.md) |
| Tool versions in identity and current tags (superseded by ADR-0035) | [ADR-0030](docs/adr/0030-tool-versions-in-identity-and-current-tags.md) |
| The tool image contract and stitch checks (superseded by ADR-0035) | [ADR-0031](docs/adr/0031-tool-image-contract.md) |
| One layer kind — a tool is a layer with a command (superseded by ADR-0035) | [ADR-0032](docs/adr/0032-one-layer-kind.md) |
| Default to rebase, preserving build provenance (superseded by ADR-0035) | [ADR-0033](docs/adr/0033-default-rebase-with-build-provenance.md) |
| Versioned image releases instead of a continuously published registry (amended by ADR-0035) | [ADR-0034](docs/adr/0034-versioned-image-releases.md) |
| Consume user-owned boot images (supersedes ADR-0003/0019/0028–0033; amends ADR-0034/0015/0022) | [ADR-0035](docs/adr/0035-consume-user-owned-boot-images.md) |
| Default-deny launch egress and CLI-only authority | [ADR-0036](docs/adr/0036-default-deny-launch-egress.md) |
| Hostname egress allowances — TLS on intercepted ports only | [ADR-0037](docs/adr/0037-hostname-egress-allowances.md) |
| Authority config-directory exposure guard | [ADR-0038](docs/adr/0038-config-dir-exposure-guard.md) |
| Non-authoritative tool network requests | [ADR-0039](docs/adr/0039-non-authoritative-tool-network-requests.md) |
| Pi reaches host Codex through an image-owned provider | [ADR-0044](docs/adr/0044-pi-reaches-host-codex-through-an-image-owned-provider.md) |
| Host-wide OCI image approval and pinned consumption (#390) | [ADR-0047](docs/adr/0047-host-wide-oci-image-approval.md) |
| One dialect rule for a printed command (#434) | [ADR-0049](docs/adr/0049-one-dialect-rule-for-printed-commands.md) |
| One rule for a relative state root (#437) | [ADR-0050](docs/adr/0050-one-rule-for-a-relative-state-root.md) |
| The reset undo refuses a recreated db (#432) | [ADR-0051](docs/adr/0051-the-reset-undo-refuses-a-recreated-db.md) |
| Direct-command input ownership and the detached stdin reader (#399) | [ADR-0052](docs/adr/0052-direct-command-input-ownership.md) |

## Deliberate non-goals

Things that were considered and rejected, so they do not get re-proposed. These
are settled design positions, not the outstanding work tracked in
[open issues](https://github.com/gregwebs/agent-vm/issues?q=is%3Aissue%20is%3Aopen).

- **No proactive token-expiry timer.** The guest's own refresh attempt at
  401-time triggers the hook, which triggers the host-side refresh. If the user
  ran `claude` on the host between sessions, the file is already fresh and the
  per-connection re-read picks it up with no hook at all. A timer is
  belt-and-suspenders.
- **No replacing `~/.microsandbox/bin/msb`.** The `MSB_PATH` override is
  per-invocation, so other microsandbox SDK consumers on the same host keep
  using their own prebuilt.
- **No cross-project refresh single-flight.** The lock is per provider, per
  project. Different projects may duplicate a refresh and fall back on the
  provider CLI's own credential locking.
- **No proactive `try_wait()` polling from a timer.** The exec-stream race and
  the relay's EOF handling already surface a VMM death promptly for the paths
  that matter; a poll loop would duplicate that without covering a new case.
- **No heartbeat staleness budget.** Killing a sandbox because its heartbeat
  went quiet reclaims healthy, busy sessions; boot failure is the relay's job.
  See [Sandbox liveness](#sandbox-liveness-idle-detection-and-runtime-exits).
- **No stderr-tee task.** The VMM's stderr is redirected straight into
  `runtime.log` via `Stdio::from(...)`, so there is no separate task to drain
  or race in `wait()`.
- **No in-VM proxy.** microsandbox does the interception on the host side;
  there is nothing for `mitmproxy` or similar to do inside the guest.
- **No raw env-var forwarding.** Forwarding `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`
  from the host was the bootstrap approach and is gone: it cannot express host
  OAuth, and it puts a real secret in `/proc/$$/environ` inside the guest.
  `source: env` instead captures the value host-side and never publishes it (#163).
