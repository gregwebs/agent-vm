# ADR-0034: Versioned image releases instead of a continuously published registry

**Superseded by [ADR-0035](0035-consume-user-owned-boot-images.md) / #257;
source/distribution ownership cutover implemented by #265.** The original decision
below is historical, not supported behavior. Independent versioning and content
integrity remain useful principles.

| Withdrawn assumption | Current contract |
|---|---|
| same repo, embedded recipes, shared composer | independent image repo; contributor-only submodule; ordinary Dockerfiles |
| archive-only automatic acquisition | registry default plus explicit/manual corresponding archive import |
| launcher-fixed selection | retained fallback, explicit upgrade; new recommendation affects new hosts only |
| hourly/promotion-floor/retention or remote package deletion | retired without deleting user caches or published artifacts |

Accepted (decision), not yet implemented. Resolved by
[CI, published surface, and image-API migration](https://github.com/gregwebs/agent-vm/issues/209)
on [Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).
Acquisition and integrity amended by
[Release acquisition interfaces and artifact integrity](https://github.com/gregwebs/agent-vm/issues/220).
Local base selection amended by
[Local base identity, caching, and refresh policy](https://github.com/gregwebs/agent-vm/issues/219).

The image is **released**, not published. One artifact — the composed default
image — is cut as a versioned GitHub Release asset (an OCI archive, one per
architecture) and acquired by downloading it and ingesting it with the
registry-less `microsandbox_image::load_archive` the compose path already uses.
The GHCR packages `agent-vm-base` and `agent-vm-template`, the hourly publish,
and the retention and promotion jobs that served them are retired. A launcher
hardcodes the exact image version it was built against; image versions are their
own sequence, decoupled from the launcher's. Tool versions become committed
build inputs rather than something CI resolves, and a bump is an explicit,
reviewable act.

## Context

The continuous-publish pipeline was not delivering the design it was built for.
`defaults::DEFAULT_IMAGE_REF` points at `agent-vm-template:latest`, which is an
**image-API 1** image built 2026-09-15 whose layer history still installs
chromium, `chrome-devtools-mcp`, pip `black`/`isort` and a `codestyle` clone —
all of which ADR-0032 makes Layers, not Base. `agent-vm-base` is private and
401s to anonymous pulls, so every launch whose declared set differs from the
shipped default fails on the base pull. `check-image-promotion-gate.sh` requires
npm `main == x64 == arm64`, and `@wirenboard/agent-vm-linux-arm64` does not exist
on npm, so `:latest` could never be promoted; the pipeline pushed ~240 tags of
which the only user-visible one was stale. Separately, the owner's releases are
mostly Rust-only changes with no image change at all, so coupling the two
cadences was wrong on its own terms. The image CI jobs have been disabled.

Three facts made the alternative cheap:

- `images/tools/` is already compiled into the binary (`include_dir!`, with a
  test asserting the snapshot equals the sources CI builds from), and the tool
  layers are already rebuilt locally on the compose path. The registry's only
  unique contribution was the **Base image** and the zero-Docker-call fast path.
- The registry-less ingest path already exists: `load_archive` is what the
  compose path uses for the derived image. Acquisition, by contrast, is
  microsandbox's own registry pull (`PullPolicy`), so only acquisition changes.
- With versioned builds, the layer Dockerfiles carry exact version defaults, so
  **no `AGENT_VERSION_*` build args are passed at all**. That retires ADR-0019's
  "the launcher's compose path passes exactly one build arg (`BASE_IMAGE`)"
  constraint, and makes a CI build and a local build the same operation.

## Decisions

### One artifact, acquired without a registry

- **The published surface is exactly one artifact: the composed default image.**
  `agent-vm-base` and `agent-vm-template` stop being published, and the existing
  GHCR packages are deleted rather than frozen.
- **It is distributed as a GitHub Release asset**, one per architecture
  (`< 2 GiB` per asset, no total limit), and acquired by downloading it and
  calling `microsandbox_image::load_archive`. No registry pull, therefore no
  registry to operate, no retention job, no promotion gate, and no private
  package to make public.
- **The Base image is not published either.** A composer builds it locally from
  `images/Dockerfile`, which joins `images/tools/` in being embedded. This is
  affordable because the base is only ever needed by someone who is already
  composing, and therefore already running Docker.
- **The published surface lives in this repo**, as a separate release namespace
  and its own path-filtered workflow, not a separate repository. The image
  sources are compiled into the binary, so moving them out would mean a
  submodule and a two-step merge for every recipe change; the cadence problem
  this solves is a release-namespace problem, not an ownership one.

### Versioning

- **A launcher hardcodes the exact image version it was built against**, and a
  code-only release reuses the previous image version. Nothing is resolved at
  runtime and no alias moves. This is what makes "most releases have no image
  change" literally true: there is nothing to republish and nothing to look up.
- **Image versions are their own sequence**, decoupled from the launcher
  version. The two lineages have different cadences, so coupling them would
  force either visible skew or an image rebuild on every code release.
- **`images/min-agent-vm-version` becomes the cross-version interface**, now
  asserting "this artifact requires launcher ≥ X" rather than gating a moving
  tag.
- **Tool versions are committed inputs.** `script/build/agent-versions.sh` stops
  being a CI step and becomes a developer tool: resolve latest locally, write
  the exact versions into the **Layer** Dockerfiles' defaults (ADR-0030's
  "defaults are exact versions in each Dockerfile", now load-bearing rather than
  aspirational), commit, and cut an image version when a **Layer identity**
  actually changes. The lockfile-pinned layers keep their existing
  `upgrade-*.sh` scripts.

### Producing the artifact

- **The release pipeline runs the same composition code the launcher runs** —
  ADR-0029's "one implementation" taken literally — with three deliberate
  differences, which are the only things that make it a release run rather than
  a launch:
  1. **composition is forced and the catalog is pinned to the shipped default.**
     Otherwise `chain_root` returns `Template` and the launch tries to download
     the very artifact being produced, and resolving config from the working
     directory would compose the wrong set;
  2. **the cache probe is bypassed** — a release run is a cold composition
     (`final_is_cached` consults the msb cache, which CI does not have);
  3. **it stops before the msb ingest**, emitting the OCI archive rather than
     populating a boot cache.
  Everything else is shared: the DAG driver, the contract and stitch checks, the
  stitcher, and the manifest writer.
- **It is a separate entry point, not a launch verb**, because it launches
  nothing.

### Building instead of downloading

- **`--build` materialises the image by building rather than downloading**, and
  is sticky via config. For the shipped default set it builds the Base locally
  and composes the default Layers; a buildx user can therefore run agent-vm
  without ever downloading the artifact.
- **It produces a local composition, not a copy of the published image.** The
  Base is `FROM debian:13-slim` with unpinned apt packages, so it cannot be
  byte-identical to a published Base. `--build` is a composition choice, not
  release acquisition. Locally derived images are never acquisition targets.
- **There is no automatic fallback to building.** Silently replacing a verified
  published artifact with a from-scratch build is too much surprise for a
  multi-minute operation.
- **A prerequisite:** the Base must reach the builder driver-independently, as
  an OCI-layout named context — the mechanism ADR-0029 already uses for declared
  parents. Today `pin_docker_base` puts it in Docker's image store, which pins
  the whole compose path to the `docker` buildx driver and therefore excludes
  every user whose builder is `docker-container`, i.e. the default
  `docker buildx create` setup. That is a defect in the existing compose path,
  not only in `--build`.

### Local base selection and refresh

- **Retain a shared base selection**, keyed by the embedded base recipe and
  build-context bytes, target platform, and build arguments. It points to the
  successfully built and validated base's actual manifest digest in the local
  OCI layout. Matching projects share this selection. The recipe identity is
  a lookup key, not an image digest: floating Debian/apt inputs can produce
  different images from identical recipes.
- **A warm launch reads the selection without Docker or network calls.**
  Missing selection requires a local base build. If a selection exists but
  its base data is unavailable, rebuild with a notice: floating inputs may yield
  a different digest, which becomes the selection after success. This is cache
  recovery, not a routine refresh or a promise of exact digest recovery.
  A changed recipe/build input selects its own record rather than silently
  continuing to use the old recipe's base; reuse an available matching selection
  without probing upstream.
- **Refresh only for changed recipe/build inputs or an explicit refresh.**
  Ordinary launches do not check upstream, refresh apt, or expire a selection
  on a timer. Explicit refresh and recipe-triggered builds on a selection miss
  both pull upstream and rerun apt-bearing build steps; an ordinary cached Docker
  build is not sufficient to promise fresh packages. An available matching
  selection remains reusable after a recipe change. Command syntax remains with
  Upgrade pattern for tool images.
- **Publish the selected digest atomically after build and validation succeed.**
  A failed refresh preserves the previous selection. A successful refresh is
  adopted by matching projects on their next launch, not by changing running
  guests. If the digest is unchanged, no base transition occurs; if changed,
  ADR-0033's default base-only rebase policy applies when layer inputs are
  unchanged. Failed destination checks block the affected launch without
  replacing that project's retained working composition.

```text
recipe/context + platform + build args ── shared selection ── base digest
                                              │
                          explicit refresh ── build + validate
                                              │ success
                                     atomically select digest
                                              │ changed
                                    next launch: rebase checks
```

### Acquisition interfaces and trusted bytes

- **`agent-vm pull` prefetches only the launcher-pinned release**, independently
  of project catalog and local-build settings. It downloads, verifies and
  ingests without booting a VM; an already verified, successfully ingested and
  available image is a no-op. Remove `pull --image` and its image-selection env
  handling. Neither custom registry images nor locally derived images are
  targets of this verb.
- **Remove `--update-check` and `AGENT_VM_UPDATE_CHECK`**, including moving-tag
  probes and pulled-digest markers. No dedicated migration error or deprecation
  path is required. A launcher has no newer image to discover within its fixed
  selection; launcher-upgrade discovery is separate work.
- **Remove `--base-image`, `AGENT_VM_BASE_IMAGE` and
  `DEFAULT_BASE_IMAGE_REF`** from launch, pull and setup. Local composition uses
  the embedded base recipe. Explicit launch `--image` / `AGENT_VM_IMAGE_TAG`
  remains the separate verbatim boot-image path with its existing acquisition
  semantics, not a composition foundation or a pinned-release override.
- **The launcher pins an archive SHA-256 for every supported architecture
  alongside its exact image version.** The launcher release chain is the trust
  anchor; a checksum downloaded alongside a replaceable asset is not one.
  No separate image signing system is added by this decision. Verify downloaded
  archive bytes before `load_archive`, retaining OCI descriptor/diff-id checks
  during ingest. Wrong bytes are a hard error: no checksum override, registry
  fallback or automatic build fallback.
- **Warm launches trust a successful-ingest record bound to the pinned archive
  digest and cached image identity**, provided the cached image is available.
  They do not contact the network or rehash an archive. Without that record or
  available cache data, reacquire through the verified path. Publish success
  only after verification and ingest finish; failed download, verification or
  ingest must not overwrite a usable cached image or its success record.
- **Release publication is gated on the assets already existing.** Before
  publishing a launcher, download the published pinned asset for each supported
  architecture, compare it against that launcher's embedded SHA-256, validate
  architecture, image-API range (removed by #258 — see the amendment under
  Migration) and minimum-launcher compatibility, and smoke-test ingest and
  boot. Any missing asset or failed check blocks
  publication, including code-only releases that reuse an image version.
  Changed artifact bytes require a new image version, never replacement under
  an existing version. The digest pin still detects replacement if that policy
  is violated.

```text
launcher: image version + architecture-specific SHA-256
                       │
           matching successful ingest + available cache ── boot
                       │ miss
             download ── verify SHA-256 ── load_archive ── record success
                            │ mismatch
                         hard error
```

### Migration

- **No backwards compatibility, and no deprecation window.** No dual mechanism,
  no GHCR fallback, and no image-API 4: nothing in this rework changes what the
  launcher expects *inside* the image (declared accounts and stitching are
  launcher-side, and the composed layer list is unchanged). The only cost to an
  upgraded launcher is one re-download into the msb cache.
- **`MIN_SUPPORTED_IMAGE_API` moves 1 → 3 and ADR-0019 D11's legacy `seed.d`
  fallback is deleted.** D11 tied that removal to the `MIN` bump; it existed only
  so a freshly upgraded launcher could keep booting a cached API-2 template, and
  with a launcher-pinned versioned artifact there is no such template.

  _Amended by #258 (2026-10)._ The stamp and range are deleted outright; the
  launcher never reads `/etc/agent-vm-image-version`. A supplied
  `/opt/agent-vm/seed-claude-plugins.sh` (and `seed.d/*`) remains optional
  ordinary image content that runs each launch, with no lineage or retirement
  promise. See the [boot image contract](../../USAGE.md#boot-image-contract).
- **`.agent-vm/layers/` is not special.** Directories there are no longer
  discovered, per ADR-0032.
- **Ordering requirement:** because the image CI is off and `:latest` is frozen
  at API-1 content, a working pinned artifact must exist **before** the launcher
  release that references it. The acquisition release gate above replaces the
  old promotion gate and asserts existence, integrity, compatibility and boot.

## Considered options

- **Publish per-layer images.** Rejected by the owner while charting: Layers are
  ephemeral build intermediates, and ADR-0029's DAG means a shipped Layer is
  never another Layer's `FROM`, so there is nothing for a registry to serve.
- **Keep GHCR and only change the tag scheme.** Rejected: it retains the
  retention job, the promotion gate, the private-package problem and a moving
  alias, while the complaint was the publishing model itself.
- **Embed the Base and composed default in the binary**, the way the Layer
  recipes are. Rejected on size: the composed default is ~1 GB compressed
  against an npm tarball ceiling of roughly 193–210 MB, and the platform package
  is already 107 MB. It would only buy an offline first run, which is not a goal.
- **A separate image repository.** Rejected for now (see "One artifact"): it
  costs a submodule and a two-step merge because the sources are compiled in.
  Available later if the artifact ever needs its own maintainers or consumers.
- **A build/download channel or alias resolved by the launcher.** Rejected: it
  reintroduces the moving reference this ADR removes.
- **Publishing only the Base and building Layers on first run.** Rejected: it
  would make Docker mandatory for every user, including the default set, and
  delete ADR-0019's zero-Docker-call fast path.

## Consequences

- The fast path gets simpler than before: first run is one pinned download plus
  `load_archive` — no Docker, no registry, no moving tag.
- `load_archive` moves onto the first-run path, so its non-incremental behaviour
  (it re-reads every blob, ~18 s per 1 GB) becomes a first-run cost rather than
  a rebuild cost.
- Release assets are permanent, so the CI-side untagged-digit-accumulation
  problem disappears, while the local OCI layout and msb cache still hold
  compressed blobs twice with no eviction policy between them.
- Layer-level reproducibility is real — the same committed inputs give the same
  Layer identities — but whole-image reproducibility is not, because of the
  floating Base. Rebuilding the published artifact to verify it is not offered.
- The release pipeline depends on the same composition code as the launcher, so
  a composition regression is caught by the release build, but a release-only
  regression in the pinned-catalog or cold-cache path would not be.
