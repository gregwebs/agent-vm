# Image composition: implementation handoff

Status: draft handoff; four source gaps must be resolved before `/breakdown`.
Not implemented. Source map:
[Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).
This consolidates the handoff for `/breakdown`, not an implementation plan or a
claim that these interfaces exist today. The source gaps below are explicit
prerequisites, not implementation discretion.

## Destination and authority

Compose a bootable guest from independently built **Layers**, stitch their OCI
layers without a merge build, key artifacts on their actual build inputs,
rebase on base-only changes, and distribute the composed default as a pinned
image release. Include migration, release CI, acquisition, and local cleanup.

Decisions and rationale remain canonical in the source ADRs and resolution
comments below. This document assembles their requirements and acceptance
criteria; it does not replace the tool image contract table or reopen settled
trade-offs. Later amendments override historical wording:

| Source | Governs |
| --- | --- |
| [ADR-0029](../adr/0029-compose-tool-images-by-layer-stitching.md) | Stitching, DAG driver, single-writer OCI layout, deterministic assembly |
| [ADR-0030](../adr/0030-tool-versions-in-identity-and-current-tags.md) | Version selection, exact installs, build-argument identity, current tags |
| [ADR-0031](../adr/0031-tool-image-contract.md) | Tool image contract T1–T7 and stitch checks S1–S3 |
| [ADR-0032](../adr/0032-one-layer-kind.md) | One layer kind, derived order, accounts, widened T2, S4, configuration migration |
| [ADR-0033](../adr/0033-default-rebase-with-build-provenance.md) | Default rebase, original build provenance, destination checks |
| [ADR-0034](../adr/0034-versioned-image-releases.md) | Release assets, pinned image version, shared composition entry point, `--build`, image-API migration |
| [Acquisition cost of a versioned image release](https://github.com/gregwebs/agent-vm/issues/212#issuecomment-5919942194) | Full download/ingest accepted; no repeated acquisition of a cached image |
| [Eviction and GC for the local image caches](https://github.com/gregwebs/agent-vm/issues/213#issuecomment-5920203490) | Explicit cleanup, retained roots, persistent selections, ownership and lifetime guards |

In particular, declaration order is **not** authoritative over parents, T2 is
**not** PATH-only, base changes do **not** always rebuild, CI does **not** resolve
latest, and cleanup does **not** reset tool-version selections. Older source
passages saying otherwise are superseded by the sources above.

Use [CONTEXT.md](../../CONTEXT.md)'s vocabulary. A **Tool** is a Layer with a
command, not a second layer kind. “Tool image contract” retains its historical
name but governs every layer image.

## Readiness blockers

Consolidation exposed four gaps not settled by later-decision precedence:

1. **[Acyclic composition root and identity boundaries](https://github.com/gregwebs/agent-vm/issues/214).** ADR-0032 puts layer identities in
   the root hash while making that root their default parent. That is recursive;
   its root/derived prose also risks counting layers twice. Decide whether the
   root is just base plus union accounts and every catalog layer belongs to the
   DAG above it. This preserves independent siblings but changes the historical
   claim that a tool bump has the same rebuild cost as an account change.
2. **[Selecting artifacts for a base-only rebase](https://github.com/gregwebs/agent-vm/issues/215).** New-parent identities miss the original build
   artifacts. Decide how a launch locates eligible old artifacts, establishes
   that only the base changed, and selects when both current-parent builds and
   older reusable artifacts exist. Retained project compositions are a possible
   lookup source; that policy has not been selected.
3. **[Cross-project reuse of identical compositions](https://github.com/gregwebs/agent-vm/issues/216).** ADR-0029 reuses artifacts across tool sets, while
   ADR-0032 says identical layers in two projects build twice on purpose despite
   keeping the project slug out of identity. Decide whether project-specific
   references are handles/retained roots only or deliberately require work.
4. **[Config merge fields and ancestor overrides](https://github.com/gregwebs/agent-vm/issues/217).** ADR-0032 widens T2 to “every other config key” but
   ADR-0031 S3 retains only `org.agent-vm.*` labels. Decide whether widening is
   Env-only or includes `User`, `WorkingDir`, `Entrypoint`, and `Cmd`; define
   S4's key domain and ancestor (not merely direct-parent) override rules.

Until these are answered, the identity/reuse/config sections below record
constraints, not an executable resolution of these gaps. Do not use the draft
as authority to invent the missing policies.

## Observable paths

```text
pinned release asset ── download ── load_archive ──────────── boot default
                          (only if not already cached)

embedded base recipe ── local base ── generated union accounts
                                          │
layer catalog + selected versions ──────── DAG builds
                                          │
                                     layer artifacts
                                          │
                                 contracts + stitching
                                          │
                                  composed OCI archive
                                    │              │
                         local load_archive    image release CI
                                    │          (no ingest or boot)
                                   boot

base-only change ── reuse artifacts + regenerate accounts
                     └─ destination checks ── rebased composition

retained project roots + selections + artifact provenance
                     └─ guarded cache prune ── unreachable private data
```

- The shipped default, without local-build selection, boots the exact released
  image with **zero Docker calls**. A cached image requires neither download
  nor ingest on ordinary launches.
- A locally composed launch uses local build artifacts, never the released
  default as a build parent. Only the final derived image is ingested into msb;
  intermediate artifacts live in the launcher's OCI layout.
- `--build`, also selectable persistently through config, builds the base and
  composes locally instead of downloading the default. There is no automatic
  fallback from failed acquisition to a multi-minute build.
- Existing explicit image selection remains a verbatim-image path; this effort
  does not make it an implicit local composition.

## Requirements

### 1. Catalog and graph

Use `[[layers]]` for every entry: `name`, `layer = { builtin = ... }` or
`{ path = ... }`, optional `parent`, optional `command`, and the existing tool
fields (`args`, `credentials`, `tools`, `persist`, `env`, `interactive_shell`,
`version`). Relative source paths remain anchored on their declaring config.
Retain existing config-tier precedence and provisioning semantics.

- A commandless entry contributes to the image but offers no launch verb. Help,
  dispatch, `doctor`, and `setup` must agree on the resolved launchable layers.
- Rename the embedded `default-tools.toml` to `default-layers.toml`; changing
  shipped membership is outside scope.
- Remove directory discovery. A leftover `.agent-vm/layers/` directory is a
  migration error naming the entries to declare. Retire the singular-directory
  guardrail. Do not silently accept the old `[[tools]]` section.
- Preserve repeatable, additive `--layer DIR` injection. Injected layers have no
  declared parent; command-line order breaks their ties. Moving an identical
  source from CLI injection to config must not itself change identity.
- Derive stitch order by repeatedly choosing the earliest-declared layer whose
  ancestors are placed. A child before its parent in config is valid. Reject
  missing parents and cycles before building.

### 2. Identity and selected versions

A built layer artifact is identified by `SCHEME_TAG`, its actual build-parent
identity, its build-context bytes, and sorted `name=value` for **every build
argument passed except `BASE_IMAGE`**. Context hashing retains existing
normalization rules. Position and declaration provenance do not enter artifact
identity. Bump `SCHEME_TAG` to v2 **once** for the combined change; no old-cache
contract grandfathering.

Composition identities cover their base/root, generated account layer where
present, and ordered participating artifacts as specified in ADR-0032, amended
by ADR-0033 for rebase. Compute the identity before building; a stitched manifest
digest is not a substitute for the pre-build cache key. Keep
`agent-vm-layer:<project-slug>-<hash>` handles, with the slug outside the hash.

A plain launch never queries upstream for a version. Precedence is:

1. Exact `version` in config (`"latest"` means no pin, not a launch-time lookup).
2. A valid tool **current tag**, read through its version labels.
3. The committed Dockerfile default, or committed lockfile for empty slots.

Current tags describe tool-version selections, not a non-tool layer upgrade
mechanism. Read their build-context hashes; invalidate a selection with a notice
when the shipped recipe changes. Selection survives a base change. Normal and
deep cleanup preserve selections and the metadata needed to interpret them.

Install the exact supplied version and check it against the tool's reported
version. Record `org.agent-vm.version.*` labels. Cover both slots for dsh and pi
when supplied; empty slots use committed locks without lookup. Preserve the
identity distinction for `AGENT_INSTALL_SOFT_FAIL` if passed; it never waives
contract violations or permits a failed image to be recorded as healthy.

For release/default builds, committed version defaults and lockfiles are the
inputs: **do not pass resolver-generated `AGENT_VERSION_*` overrides**. Config
pins or valid current selections still require their selected versions to be
represented in local build inputs. Converting `agent-versions.sh` into an
explicit developer bump tool is in scope; the upgrade verb's lookup policy is
not.

### 3. Build, storage, and stitching

Docker/buildx remains the builder. Generate bake targets only for missing
artifacts. Run one bake per independent group (a root and its declared
descendants), allowing independent groups to complete concurrently. Supply
parents through `target:` contexts when built in the group and `oci-layout://`
contexts when cached.

- The locally built **base must also reach the builder through an OCI-layout
  named context**, not solely a Docker-local tag. Support both `docker` and
  `docker-container` buildx drivers; a Base link is not an identity or ABI promise.
- Export each target to its own staging layout. agent-vm alone imports blobs
  into the shared content-addressed layout and updates its index; never let
  concurrent BuildKit exports write the shared layout directly.
- Strip only each artifact's verified parent prefix to obtain its own layers.
  Stitch those layers into the final manifest in derived order. No COPY merge,
  hand-maintained footprint table, or custom LLB frontend.
- Derive config and perform stitch checks under ADR-0031 as amended by
  ADR-0032. Use fixed timestamps and canonical serialization for assembly.
- If a build fails, fail the launch and name the layer. Independently completed,
  validated artifacts remain cached. Failed artifacts receive neither an index
  entry nor a current tag.
- Cache structural file information beside artifacts so a new composition need
  not decompress unchanged layers again. A missing acceleration record must be
  reconstructed before checks that require it.

Deterministic stitching means identical artifact inputs produce identical
assembly bytes. It does **not** mean rebuilding the floating Debian/apt base
reproduces a released image byte for byte.

### 4. Contract and account generation

Implement [ADR-0031's contract](../adr/0031-tool-image-contract.md), incorporating
ADR-0032's amendments rather than maintaining a second normative table here:

- Enforce T1 parent build/prefix, widened T2 additive PATH/config merge, strict
  T3 base-path protection, T4 host platform, and T5 command resolution and
  permissions for any uid. T5 applies when a command exists. T6 capability
  honesty and T7 other-file readability remain documented requirements.
- Enforce S1 unrelated-layer file collisions (only guest tmpfs prefixes exempt),
  S2 command shadowing, amended S3 derived config, and S4 conflicting config
  declarations by unrelated layers. Ancestor/descendant overrides are permitted
  where the contract allows them; identical values and additive PATH are not
  sibling conflicts.
- Reject layer declarations of launcher-owned `LANG`, `IS_SANDBOX`,
  `HOME`/`USER`/`LOGNAME`, and the `MSB_` prefix. Preserve the existing reserved
  guest-env rules rather than allowing a declaration to become partly effective.
- Violations are hard errors with no opt-out. Report the layer; for collisions,
  report both layers and the affected path/key. Validate artifacts before
  recording them. Ordinary cache hits may reuse prior validation, but new sets
  need stitch checks and newly rebased compositions need destination checks.

Declare accounts with `users`/`groups` on entries, not Dockerfile appends. A user
includes `name`, `uid`, `gid` (numeric or a declared group name), `home`, `shell`,
and supplementary `groups`. Auto-create the same-named group when unclaimed.

Generate **one append-only union account layer below every participating
layer**, visible at build time as well as boot. Generate locked shadow entries
with fixed `lastchg`, and create homes owned by their declared uid:gid. Leave
home contents, sudoers, trust stores, pre-warming, and capability markers in the
owning Dockerfile. Migrate `chrome-devtools` and other affected examples.

Reject declared identity collisions and host-identity collisions at plan time,
with both declaring layers identified where applicable. Check collisions with
base accounts via `getent` inside the generated stage. The pure account-collision
predicate requires a Verus boundary contract under ADR-0018. The TOML/I/O adapter
is outside that proof. Shipped account declarations, if any, must also be present
in the released default.

### 5. Rebase and rebuild boundary

When **only the base changes**, default to reusing installed artifacts and
re-stitching onto the destination. Warn that major base changes can cause runtime
incompatibility and recommend rebuild when needed; do not claim automatic major
change detection or ABI validation.

- Keep each reused artifact's original build-parent identity and provenance.
  Identify the rebased composition separately using the destination and reused
  artifacts in stitch order, including regenerated accounts.
- Regenerate the union account layer against the destination base. Never carry
  old base account files forward.
- Check destination base-file collisions, cross-layer collisions, command
  shadowing, and config conflicts even when source artifacts are cached.
- Source, version, declared-parent, and other input changes still cause normal
  builds. Explicit rebuild uses normal BuildKit caching and produces artifacts
  built against the destination, not falsely relabeled reused files.
- Do not introduce compatibility epochs, per-layer rebase opt-ins, a runtime/build
  base split, or runtime dependency management.

The sibling [Upgrade pattern for tool images](https://github.com/gregwebs/agent-vm/issues/190)
effort owns rebuild naming, option syntax, targeting semantics, and transactional
behaviour. Its interface must use resolved catalog layer names plus injected
`--layer` paths; the derived image is re-stitched, never itself a rebuild target.
Do not carry forward “everything above the named layer” chain semantics or
same-tag replacement from historical sibling resolutions.

### 6. Releases, acquisition, and migration

Release only the **composed default image** as an OCI archive per supported
architecture in this repo's separate image-release namespace. Do not publish
base or per-layer images. Retire the old GHCR packages (delete, do not freeze),
hourly publication, retention workflow, and moving-tag promotion gate.

- Embed `images/Dockerfile` alongside the layer recipes for local composition.
- Pin an exact image version in the launcher. Image versions are independent of
  launcher versions; code-only releases reuse the prior image version. No
  runtime alias or latest-version lookup.
- Use `images/min-agent-vm-version` as the artifact's minimum-launcher interface.
  A working pinned artifact must exist **before** releasing its launcher.
- Share the launcher's composition code with a non-launch release entry point:
  force local composition with the shipped catalog, bypass the final msb cache
  probe, and emit the OCI archive before ingest. Share all driver, contract,
  stitch, and manifest logic. CI must not consume user/project config or try to
  download the artifact it is producing.
- Turn `script/build/agent-versions.sh` into a reviewable local bump tool that
  writes exact Dockerfile defaults. Keep lockfile-pinned layers' existing bump
  scripts. CI consumes committed inputs, never resolves latest on a schedule.
- Download the pinned archive and ingest with registry-less `load_archive`.
  Verify artifact integrity under repo security standards before ingest. Accept
  the full download and full-blob ingest even on a warm-cache version change;
  no incremental protocol or runtime register-from-manifest API is required.
- Move `MIN_SUPPORTED_IMAGE_API` from 1 to 3 and remove the legacy `seed.d`
  fallback and its tests. No API-4 bump, dual-format window, or GHCR fallback.
- Keep `pull`/`--update-check` away from locally derived image tags. Update their
  release-facing references and messaging rather than restoring moving tags.

Update current user/contributor docs, examples, and test harnesses as the features
land. Do not rewrite current usage documentation now to imply future support.

### 7. Local cleanup and reporting

Provide explicit `agent-vm cache prune`, `--deep`, and `--dry-run`. No automatic
launch sweep, size limit, or time-based eviction in this implementation.

- Normal prune retains each project's last-used/current composition and required
  artifacts, even if its project directory is missing. Deep prune additionally
  releases inactive projects' retained image roots. Both preserve current
  tool-version selections and enough metadata to interpret them.
- Trace shared blobs from **all** retained roots. A retained derived image stays
  bootable even if its former base's standalone tag is removed. Keep structural
  metadata and original build provenance needed for later rebase; file-list
  acceleration may be removed with an evicted image and restored when needed.
- Own only the agent-vm OCI layout and **private** msb image cache. Shared msb
  caches are report-only; Docker/BuildKit stores are outside deletion ownership.
- Builds and running VMs hold shared lifetime guards. Cleanup obtains an
  exclusive store guard or refuses with a busy explanation. A dry-run preview
  does not permit subsequent deletion against stale roots.
- Establish actual roots and coordinate all participating store users. Do not
  equate msb database-only prune with complete GC or download locks with VM leases.
- `doctor` only reports usage, retained project-root space (including stale
  projects), and cleanup commands. Mention external/shared storage separately;
  reporting never deletes data.

## Acceptance criteria for `/breakdown`

These are observable completion checks, not preselected build slices. Each
implementation ticket should name which checks it delivers.

0. **Readiness:** resolve the four blockers above, amend their owning ADRs and
   glossary entries, and align this handoff before slicing implementation tickets.
1. **Config:** commandless and launchable layers resolve consistently; child-first
   declarations sort correctly; cycles/missing parents fail before Docker;
   injected-to-declared identical sources retain identity; legacy authoring gets
   an actionable migration error.
2. **Identity:** position alone does not change an artifact key; every passed
   build argument does (except `BASE_IMAGE`); defaults/lock bytes do; pins outrank
   current selections; recipe changes invalidate selections with a notice;
   launches perform no upstream lookup.
3. **Build reuse:** bumping an independent tool rebuilds only that artifact and
   declared dependents, then re-stitches; unrelated validated artifacts survive
   another group's failure. No cached build requires Docker merely to identify it.
4. **Builder portability:** compose successfully with `docker` and
   `docker-container`, including a cached declared parent and the local base,
   without a registry push workaround. Concurrent exports cannot corrupt the
   shared OCI index or blobs.
5. **Assembly:** identical existing inputs produce identical archive/manifest
   bytes. Own-layer extraction does not duplicate parent prefixes. Negative
   fixtures exercise T1–T5 and S1–S4, including symlink command resolution,
   restrictive directory modes, descendant overrides, whiteouts, and tmpfs-only
   overlap exemptions. Contract failures never become indexed healthy images.
6. **Accounts:** multiple declarations create one deterministic union visible
   during each build and in the guest. Locked shadow data is stable; collisions
   with declarations, base accounts, and host identity fail at their intended
   seams. Verify the pure predicate with Verus.
7. **Rebase:** base-only updates skip installers, preserve original provenance,
   regenerate accounts, warn, and run destination checks. A destination collision
   fails even with cached artifacts. Explicit rebuild produces new-parent build
   provenance. A structural pass makes no ABI guarantee.
8. **Fast path/acquisition:** a cold default launch downloads the pinned asset
   and ingests without Docker; a warm same-version launch does neither; an
   image-version change performs full acquisition successfully. Download failure
   never falls back to building. `--build` uses local composition.
9. **Release isolation:** hostile/local config cannot alter the release catalog;
   release mode neither probes msb nor ingests/boots/downloads itself. Artifact
   compatibility/integrity and existence are checked before its launcher release;
   code-only releases keep the image version. Asset size stays within GitHub's
   per-asset limit.
10. **Cleanup:** dry-run is non-destructive; normal prune protects missing-project
    roots; deep prune frees inactive image roots without resetting selections;
    shared blobs/provenance needed by retained images survive. Busy builds/VMs
    prevent deletion. Shared msb and builder caches are never deleted. `doctor`
    remains observational.
11. **End to end/migration:** boot default and custom compositions as the host
    guest user and in root mode; exercise migrated examples, declared parents,
    and image API 3. Old API/authoring paths fail as specified rather than invoking
    the deleted fallback. Adapt existing harnesses; boot-free tests cannot stand
    in for a real VM smoke test.

## Breakdown constraints and exclusions

Keep runtime composition and release composition one implementation. Build
artifact provenance, version-selection metadata, retained project roots, and
lifetime guards must be designed before a destructive cleanup slice can land.
Deliver and validate the pinned artifact before switching a released launcher
off GHCR. Configuration rename and the v2 cache scheme form one deliberate
migration; do not split them into competing supported models.

Outside this handoff: rebuild verb semantics (the sibling effort), shipped catalog
membership, credentials/secret handling, latest-version resolution APIs,
Nix/devenv, automatic ABI management, incremental acquisition, automatic cache
limits, shared/external cache deletion, and resetting tool-version selections.

Prototype evidence is linked from
[Prototype the full-fidelity composition](https://github.com/gregwebs/agent-vm/issues/210).
It established arm64 stitching/boot and exposed export races and bake sibling
cancellation; it did not validate every driver or implement the unified catalog,
rebase policy, release path, or GC. Its measurements are evidence, not performance
SLAs or substitutes for the acceptance tests above.
