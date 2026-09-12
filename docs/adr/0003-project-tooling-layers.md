# ADR-0003: Project tooling layers — build, registry-less load, and boot

## Status

Accepted. The single-layer decision is superseded by ordered layer chains
(issue #79) — see "Amendment: ordered layer chains" below, which also
records the removal of `--layer` / `$AGENT_VM_LAYER`. A follow-on amendment,
"Amendment: `--layer` returns, additive and repeatable", redefines `--layer`
as a repeatable flag appended after the project's own chain and records that
`$AGENT_VM_LAYER` stays removed and is now rejected outright if set. A third
amendment, "Amendment: msb-owned base with a Docker base link (issue #98)",
supersedes only the way the base is *addressed by Docker* — the historical
direct digest-pinned `BASE_IMAGE` cannot name an archive-imported base. Every
other decision here (registry-less ingest, hash-as-staleness-check, hard-fail,
the Dockerfile contract) is unchanged and now applies per chain step; msb's
per-platform manifest digest remains the identity anchor for step 0's hash.

## Context

The base image (`ghcr.io/wirenboard/agent-vm-template:latest`, the "guest
template") carries Debian plus the in-VM coding agents, but not every
project's toolchain. A project that needs, say, a cross-compiler has no way
to add it short of hand-editing the running guest every launch.

`#12` (already merged on this branch) added *identity only*: a project-owned
`.agent-vm/layer/Dockerfile` is resolved (`layer::resolve_layer_dir`,
precedence `--layer` / `$AGENT_VM_LAYER` / default `.agent-vm/layer/`) and
content-hashed into a tag (`layer::resolve` → `LayerIdentity`), but nothing
is built or booted — the resolved identity was only logged at debug level.
This ADR covers the follow-up: actually building the derived image (base +
layer), loading it into the microsandbox image cache, and booting it in
place of the base.

### The registry-less ingest problem

microsandbox's runtime pulls images strictly **by reference** — there is no
"push a locally built image and boot it" primitive; `PullPolicy::IfMissing`
resolves a reference either from cache or by contacting a registry. The
sibling `claude-contained` project (this codebase's Go predecessor) worked
around the equivalent gap by running a local `registry:2` sidecar and
`docker push`ing the derived image to it before boot. We deliberately do not
reproduce that: a registry-per-launch is an extra long-lived process, an
extra port, and an extra thing that can be half-up when a launch races a
previous one's cleanup.

Instead, the vendored `microsandbox_image` crate exposes
`load_archive(cache_dir, input_tar, ImageLoadOptions { tags })`
(`vendor/microsandbox/crates/image/lib/archive/docker.rs`), which accepts
**either** a `docker save`-shaped archive or an OCI-layout archive
(auto-detected) and does more than stage blobs: it calls
`Registry::materialize_cached_layers_from_paths` →
`materialize_layers_and_fsmeta` (`registry/client.rs`), which materializes
the per-layer EROFS images **and generates fsmeta + VMDK**, entirely
offline. `options.tags` is applied to the first image in the archive.

This is the load-bearing invariant the whole design leans on: boot's
`PullPolicy::IfMissing` resolves entirely from cache (no registry contact)
iff image metadata exists, all layer EROFS are materialized, **and** fsmeta
+ VMDK are materialized (`resolve_cached_pull_result_async`,
`registry/client.rs`). Because `load_archive` produces all three in one
call, booting the registry-less `agent-vm-layer:<hash>` tag right after
loading it resolves purely from cache. If any of the three were missing,
`PullPolicy::IfMissing`'s fallback step would try to fetch a manifest from a
registry — which does not exist for this tag — and hard-fail.

Both `load_archive`'s metadata write and boot's `IfMissing` cache lookup key
off the same `microsandbox_image::Reference` normalization (both parse the
tag string through that type), so the two paths agree on what "this tag" is.
That agreement is also why the eviction failure mode below (F5) is fatal
without a guard, rather than merely "slow": there is no separate identity
space in which the registry-less tag could resolve some other way.

## Decision

### The base / tooling-layer / derived split (glossary — see CONTEXT.md)

- **Base image**: the guest template agent-vm boots today, unchanged.
- **Tooling layer**: the project's `.agent-vm/layer/Dockerfile` + build
  context.
- **Derived image**: base + layer, tagged `agent-vm-layer:<slug>-<hash>`,
  content-hash-identified. The hash — not a state file — is the staleness
  check: nothing to forget to write, nothing that can disagree with the
  image store. A hash hit reuses the ingested derived image with no rebuild
  and no prompt; a hash miss (new project, or an edited layer) prompts to
  build.

### Lazy build at run, with a hard confirm gate, and a hard fail on build error

Building is minutes-long and touches the network (pulling the base FROM the
registry, plus whatever the layer's Dockerfile itself fetches). It must be
explicit, not implicit:

- A hash miss prompts `Build project tooling layer '<tag>'? [y/N]` unless
  `--yes` / a truthy `$AGENT_VM_YES` is set.
- Non-interactive callers (no TTY, no `--yes`/env) get an actionable error
  instead of a hang on a `read_line` that will never receive input.
- Any build or load failure is a **hard fail** — `launch()` never silently
  falls back to booting the plain base. "A container that looks healthy
  while missing its toolchain" is exactly the failure mode this design
  exists to prevent; a build that failed halfway must not boot *something*
  anyway.
- A **stderr write error** while delivering the prompt (broken pipe, out
  of disk) fails the launch with that io error in context, instead of
  aborting the process from inside `eprint!`; the answer is never read
  after a failed delivery (issue #58) — and the layer's own progress
  notices (`==> Tooling layer present; pulling base …`, `==> Building
  tooling layer …`, etc.) share this same failure handling rather than
  panicking independently (issue #70). Two limits are deliberate: the
  Rust runtime reopens a closed std fd onto `/dev/null` before `main`
  runs, so under `2>&-` the prompt write *succeeds* into `/dev/null` and
  the failure is undetectable — it is not a failure at all; and a prompt
  redirected to a file (`agent-vm … 2>log`) is delivered successfully but
  invisibly, and still waits on stdin — requiring stderr to be a tty
  would break that legitimate workflow.

### Digest-pinned `BASE_IMAGE`

Docker resolves `FROM ${BASE_IMAGE}` by pulling the base **itself** from its
registry — it cannot read msb's EROFS cache, so it has no way to reuse what
msb already has cached. If the launcher passed a moving tag (`:latest`)
straight through, docker's independent resolution could race the registry
and build FROM a *different* base than the one `#12`'s content hash covers,
making the hash a lie. So the base is pinned to
`<registry>/<repository>@<manifest-digest>` — the exact digest msb already
resolved and cached — via `--build-arg BASE_IMAGE=repo@<digest>`
(`layer::digest_pinned_base`). The base is pulled first if not already
cached (there is otherwise no digest to pin to).

### `--output type=oci`, zstd-with-gzip-fallback, provenance/SBOM suppressed

`docker buildx build --output type=oci,dest=<tar>,compression=zstd
--provenance=false --sbom=false -f <Dockerfile> --platform linux/amd64
<layer-dir>`:

- **OCI output**, not `docker save`, because `load_archive` accepts either
  but OCI layout is the more direct match for what the image crate already
  materializes from.
- **zstd first, gzip fallback** — zstd layers dedup better against the
  blobs the msb cache already holds for the base; some older
  buildx/registries lack zstd support, and gzip is explicitly acceptable
  per the originating ticket. The retry is unconditional on any build
  failure (build stdout/stderr is inherited for live progress, so the
  specific "was it a zstd problem" text isn't captured to gate the retry) —
  the accepted cost is that a genuinely broken Dockerfile fails visibly
  once, then fails again identically with gzip.
- **`--provenance=false --sbom=false`** — buildx's default attaches
  provenance/SBOM attestation manifests, turning the OCI archive into a
  multi-image index. `load_archive`'s `tags` apply to "the first image in
  the archive", so an attestation index would make that ambiguous. We don't
  consume provenance/SBOM metadata, so suppressing it costs nothing here.
- **`--platform` derived from the host architecture** — via
  `layer::host_oci_platform()`, which mirrors
  `microsandbox_image::Platform::host_linux()`'s mapping
  (`std::env::consts::ARCH`: `x86_64` -> `amd64`, `aarch64` -> `arm64`).
  This MUST match the host, not be a fixed `linux/amd64`:
  `load_archive` materializes the archive's manifest for
  `Platform::host_linux()` (`Registry::new(Platform::host_linux(), cache)`,
  `vendor/microsandbox/crates/image/lib/archive/docker.rs`), i.e. the
  *running host's* arch. Verified live on an Apple Silicon (`aarch64`) host:
  an archive built with a hardcoded `--platform linux/amd64` fails to load
  (`manifest parse error: OCI layout contains no image manifests for the
  host platform`); building for the host arch makes the identical
  build+load+boot round-trip succeed. A fixed `amd64` would break every
  tooling-layer build on the Apple-Silicon hosts this project explicitly
  supports (README "Requirements", and `script/build/import-image.sh` which
  loads a `linux/arm64` base into the cache on macOS). Building for the host
  arch is also exactly the platform msb resolved and cached for the base
  image, so docker's digest-pinned `FROM` selects the same base manifest the
  layer hash covers. (This corrects the originating plan/ticket, which
  specified a literal `linux/amd64`; the correction was made after a live
  `aarch64` build+load reproduction — see the Consequences note below.)

### PATH sourced from the derived image's config (already wired by #12)

`#12` changed the launcher's guest `PATH` from a hardcoded literal to a read
of the *booted* image's OCI config `Env` (`image_config_path_and_digest` /
`path_from_config_env`, `run.rs`). This ADR is what makes that change
actually matter: once `launch()` reassigns `image` to the derived tag before
that PATH read, a layer's `ENV PATH=/opt/extra/bin:$PATH` merges into the
derived config and reaches the guest exec environment with no further
wiring.

**No-guard trade-off**: nothing enforces that a layer's `ENV PATH` stays
additive. A layer that *replaces* rather than extends `PATH` — dropping the
base's `/opt/agent/.local/bin`, `/opt/agent/.claude/local/bin`,
`/opt/agent/.opencode/bin`, `/usr/sbin` — breaks the in-VM agents (and, in
`--root` launches, dockerd's own PATH lookups for helper binaries) with no
launch-time error; it just silently produces broken tool resolution inside
the guest. This is a **Dockerfile contract requirement** (below), not a
launcher-enforced invariant.

### The layer Dockerfile contract

Each chain step's `Dockerfile` (`.agent-vm/layers/<NN-name>/Dockerfile`)
MUST:

- Start `ARG BASE_IMAGE=<default>` then `FROM ${BASE_IMAGE}` — the launcher
  overrides `BASE_IMAGE` via `--build-arg`, to the **base link**
  (`agent-vm-base:<msb-manifest-digest-hex>`, a local Docker name — not the
  digest-pinned registry ref this section originally described; see the
  issue-#98 amendment below) for step 0, and to the previous step's tag for
  every step after it (see the chain amendment below). This requirement is
  now doubly load-bearing: it is
  how steps chain, not only how the base is pinned. A Dockerfile that
  hardcodes `FROM ghcr.io/...` or `FROM <some other tag>` instead breaks
  both.
- Not touch `/etc/agent-vm-image-version` — that's the image-API-version
  contract check (`defaults::IMAGE_API_VERSION_PATH`), unrelated to tooling.
- Keep `ENV PATH` **additive** — retain
  `/opt/agent/.local/bin:/opt/agent/.claude/local/bin:/opt/agent/.opencode/bin:...:/usr/sbin`
  and prepend/append rather than replace (see the no-guard trade-off above).
- Install tools world-readable/executable (`a+rX`), not under a `0700` home
  — the guest runs as an arbitrary host uid (ADR-0001), not a fixed image
  account.
- Be architecture-agnostic (glibc) — the launcher builds for the host's
  own architecture (`layer::host_oci_platform()`, `linux/amd64` on x86_64
  hosts, `linux/arm64` on Apple Silicon), matching the base manifest msb
  cached and the platform `load_archive`/boot select. A Dockerfile that
  hardcodes `RUN`-installed x86_64-only binaries breaks on Apple Silicon;
  prefer arch-portable package installs.
- Keep `/bin/bash` present and `/etc/passwd`/`/etc/group` appendable — the
  non-root guest identity machinery (ADR-0001/0002) appends to both at
  launch.
- Expose environment via `ENV` (not an `env.d`-style file the base doesn't
  read).
- Leave `ENTRYPOINT`/`CMD` inert — agentd execs the agent directly, it never
  runs the image's entrypoint.

### Concurrent launches

Two launches in the same project that both hit a hash miss may both build.
`load_archive` takes per-image flocks (`registry/client.rs`), so the ingest
itself is serialized and idempotent — a double build wastes time but is not
unsafe. Accepted rather than de-duplicated with an extra lock file: rare in
practice (two concurrent first-launches of the same project), and the
existing per-image flock already prevents a torn cache write.

### Amendment: ordered layer chains (issue #79)

This ADR originally supported exactly one project tooling layer. That
blocked both per-tool layers and the ordinary case of combining a shipped
example layer (e.g. `examples/layers/chrome-devtools/`) with a project's own
toolchain. A project now declares an **ordered chain** of layers, each built
`FROM` the previous one, with only the final step registry-lessly ingested.

**Location.** `.agent-vm/layers/` is now the *only* location a chain can
live. Its immediate subdirectories are the chain, in byte-lexicographic
order by directory name (`10-toolchain` before `20-chrome`); each must hold
a `Dockerfile`. `layer::resolve_layer_dirs` replaces `layer::resolve_layer_dir`
(itself later renamed `layer::resolve_layer_chain` by the follow-on amendment
below, which also takes back part of this paragraph's claim).

**`--layer` and `$AGENT_VM_LAYER` are removed. There is no override.**
*(Superseded in part — see "Amendment: `--layer` returns, additive and
repeatable" below: `--layer` comes back as a repeatable, additive flag;
`$AGENT_VM_LAYER` stays removed.)* A chain expresses something a
single-directory *override* cannot (a whole ordered sequence of steps), and
a project's tooling layout is a property of the project's checkout, not of
an invocation — so there is nothing left for a flag to usefully *override*.
There is, however, still room for a flag to *add* to the chain, which is
exactly what the follow-on amendment does.

**No compatibility with the singular `.agent-vm/layer/`.** A leftover
`.agent-vm/layer/` — in any form, whether or not `.agent-vm/layers/` also
exists — is a hard error naming the path and the `git mv` to run, not a
deprecated alias. This is a deliberate migration guardrail, not backwards
compatibility: nothing about the old layout still works, and the error path
runs no build logic. The alternative (silently ignoring the leftover
directory) would let an un-migrated checkout boot looking healthy while
missing the toolchain the user believes they declared — precisely the
failure this whole design exists to prevent. The migration itself is a pure
rename with no rebuild cost: `canonical_stream` hashes a layer directory's
*contents* relative to that directory, and the tag's project slug comes from
the project directory, not the layer's location, so neither can see where
the directory lives on disk. A user running `git mv .agent-vm/layer
.agent-vm/layers/10-tools` keeps the exact same tag and their already-built
image is still a cache hit.

**Transitive identity by content hash, not docker image id.** Each step's
`base_image_id` (fed to `layer::resolve`) is step 0's msb-resolved *manifest
digest*, and every later step's is its *predecessor's content hash*
(`LayerIdentity::hash`) — never a docker-assigned image id, even though an
earlier draft of this design (and the originating issue) proposed exactly
that. Image-id chaining has three concrete defects that rule it out:

1. It puts docker on the cache-hit path of every launch. With image-id
   chaining, the final tag is not computable without walking the chain
   (`docker image inspect` once per intermediate) — even on a pure cache
   hit. Worse, `docker image inspect` exits non-zero both when an image is
   absent **and** when the daemon is unreachable, so an already-ingested
   chain would read as "not cached" and hard-fail whenever docker simply
   isn't running.
2. Docker config ids are not stable across `docker image prune` — a prune
   changes step 0's rebuilt id, which cascades into every later hash moving,
   which moves the final tag and forces a full re-ingest (the expensive
   EROFS+fsmeta+VMDK half) for a project not one byte of which changed.
3. Docker config ids are not reproducible across machines — two developers
   on the same commit would compute different final tags, exactly the
   failure `git_mode` already exists to prevent one level down.

Content-hash chaining has none of these problems: every step's tag is a pure
function of the checkout plus the base manifest digest, computable before
anything is built, stable across `docker image prune`, and identical on
every machine on the same commit. `SCHEME_TAG` is deliberately **not**
bumped for this change — chaining is additive to the hash's inputs
(`base_image_id` now sometimes carries a predecessor's hash rather than
always a base digest), not a change to the enumeration rules `SCHEME_TAG`
versions.

**`FROM` takes the previous step's tag, not its image id.** Verified live
(colima's docker, buildx v0.36.1, driver `docker`):

```
$ docker buildx build -t b --build-arg BASE_IMAGE="sha256:2544a6f5…" --output type=docker ./b
ERROR: failed to solve: sha256:2544a6f5…: failed to resolve source metadata for
docker.io/library/sha256:2544a6f5…: pull access denied, repository does not
exist or may require authorization
```

BuildKit parses a bare `sha256:<id>` as a *repository name*, not an image id
— `FROM sha256:<id>` cannot work through buildx. Passing the tag works and
chains correctly:

```
$ docker buildx build -t spike-a --output type=docker ./a          # loads into the store
$ docker buildx build -t spike-b --build-arg BASE_IMAGE="spike-a" --output type=docker ./b
$ docker run --rm spike-b ls /marker-a /marker-b                   # both exist
```

This is sound precisely because the registry-tag-race reasoning that
motivates this ADR's digest-pinned base (a *moving registry tag* can be
re-resolved independently by docker against a registry, racing what msb
cached) does not transfer to an intermediate chain tag:
`agent-vm-layer:<slug>-<hash>` is a local name in a repository agent-vm
owns, never pulled from a registry, whose text already embeds the content
hash of everything beneath it. Its only failure mode is a human manually
retagging it, out of scope in the same way hand-editing the msb cache is —
there is deliberately no re-assert-by-image-id step after an intermediate
build, since there is no expected id to compare a step found already present
in the store against.

**Two ingest paths, not one.** `digest_pinned_base` applies to step 0 only.
Intermediate steps (`0..n-1`) build with `--output type=docker`, landing in
docker's own local image store (`docker image inspect <tag>` is the
staleness check); only the **final** step emits an OCI archive and goes
through `load_archive` into the msb cache. Intermediates never boot and the
EROFS+fsmeta+VMDK materialization is the expensive half of ingest, so
ingesting them would be pure waste.

This requires the default `docker` buildx driver — `.github/workflows/chrome-layer-contract.yml`
already pins `driver: docker` (not the `docker-container` default) for the
same reason: only the `docker` driver's builds land in a store every later
build can see with a plain `FROM <tag>`. Under `docker-container`, an
isolated buildkit container can't see a previous build's `--load` output, so
the next step's `FROM <tag>` falls through to a Docker Hub pull of a tag
that does not exist there. Detected by post-build assertion
(`docker image inspect <tag>` after an intermediate build) rather than
parsing `docker buildx inspect` up front — a second output format to track,
which can false-positive on multi-node builders, when the post-hoc check
cannot be wrong.

**One prompt for the whole chain.** Rather than one confirmation per step,
`execute_chain` asks once, listing every step, its tag, and whether it's
pending or already cached. The hard-fail rule is unchanged and now matters
more: any step failing aborts the launch, and the msb cache is untouched
until the final step succeeds, so a partially-composed chain can never boot.

**Accepted consequence: growing a one-step chain rebuilds step 0 once.** A
project running a one-step chain (`.agent-vm/layers/10-a/` alone) that later
adds `20-b/` will rebuild step 0 once. Its image was produced with
`--output type=oci` (an archive), which does not populate docker's image
store, so `docker image inspect` misses even though the tag is unchanged and
still ingested in the msb cache. buildx's own build cache usually makes this
cheap. Rejected alternative: build *every* step with `type=docker`, then
`docker save` the final image into `load_archive` (which auto-detects
docker-archive as well as OCI layout) — rejected because it reverses three
of this ADR's own decisions at once (OCI layout over `docker save`, zstd for
blob dedup, `--provenance=false --sbom=false`) to save a one-time cost on an
uncommon transition.

### Amendment: `--layer` returns, additive and repeatable (issue #79, follow-on)

The previous amendment removed `--layer` / `$AGENT_VM_LAYER` outright,
reasoning that a chain has no single directory left for a flag to override.
After reviewing that, the user asked whether a flag could instead *add* a
layer not under `.agent-vm/layers/` — appended to whatever is already there,
repeatable — and approved doing so. So `--layer` comes back, but redefined:

- **`--layer DIR` is repeatable and additive**, never an override. Its
  directories are appended *after* `.agent-vm/layers/*`, in command-line
  order: `chain = .agent-vm/layers/*/ (sorted) ++ --layer DIR ... (as given)`.
  It works with no `.agent-vm/layers/` at all — the chain is then just the
  flag layers, restoring the "try a checked-in example" workflow
  (`agent-vm shell --layer examples/layers/chrome-devtools --yes`).
- **Still no environment variable.** The removed `$AGENT_VM_LAYER` stays
  removed as an input; any presence — including an empty value — is now a
  hard error pointing at `--layer`, raised as the first statement of
  `launch()`, before any state-dir provisioning or the msb-db preflight.
  Silently ignoring it would boot without the toolchain the user expects,
  which is exactly the failure this whole design exists to prevent.
- **Still no compatibility with `.agent-vm/layer/`** (singular). The legacy
  migration-guardrail error runs first and unconditionally, exactly as
  before; a `--layer` cannot reach the legacy directory by a side door,
  because the guardrail fires on the directory's mere presence, independent
  of any flag.

**Why append, not prepend.** Content-hash chaining is prefix-stable: step
`i`'s hash depends only on steps `0..i`, so appending after the project's own
steps leaves every one of their tags untouched — a project's chain stays a
pure cache hit whether or not any `--layer` is passed. Prepending would shift
every project step onto a new predecessor hash and invalidate the whole
chain every time a flag was added or removed.

**Provenance stays out of the hash.** A resolved chain step carries its
human-facing label used in prompts and errors — `.agent-vm/layers/10-a` for a
project step, `--layer <as typed>` for a flag step — alongside the identity
`layer::resolve` computes, not inside it, and nothing else about where it
came from. `resolve` and `LayerIdentity` are completely unchanged by this
amendment. That is what makes **try-then-adopt**
free: `agent-vm shell --layer examples/layers/chrome-devtools --yes` in a
project with no layers, followed by copying that same directory into
`.agent-vm/layers/20-chrome-devtools/`, produces the identical tag at the
same chain position — the adopted layer is a cache hit, not a rebuild.

**Validation.** Each `--layer` value is checked, in this fixed order (so the
right problem is always reported first): non-empty; exists and is a
directory (relative paths resolve against the project directory, the one
deliberate divergence from `--mount`'s absolute-only rule, because trying a
checked-in example by relative path is the point); not the project directory
or an ancestor of it (`plan_chain` hashes and would upload a step's whole
tree on every launch — pointing that at the project root would mean the
entire checkout); holds a `Dockerfile` (with a hint when the named directory
instead holds subdirectories that are themselves layers, e.g. `--layer
examples/layers`). Then the combined chain (project steps plus flag steps)
is checked for duplicates by canonical path, which also catches a flag
naming an already-declared project step and symlink aliasing.

**Accepted consequence: the first `--layer` re-exports the project's last
step.** This generalizes the single-step-chain consequence above. A project
chain's final step is built with `--output type=oci` and never lands in
docker's local image store; the first time a `--layer` is appended after it,
`execute_chain`'s backward walk finds that step absent from the store and
rebuilds it as an intermediate under its *unchanged* tag before building the
new final step. Correctness is unaffected (the tag is prefix-stable, so the
rebuild reproduces identical content); the cost is a one-time re-export,
usually fast off buildx's own build cache. Dropping the flag again afterward
is a pure cache hit, because the project's own final tag never left the msb
cache. Verified live (`e2e_a_final_step_can_be_rebuilt_as_an_intermediate_under_the_same_tag`):
build a one-step project chain (ingested, absent from docker's store), then
append a `--layer`; step 0 rebuilds under its original tag and lands in
docker's store, the flag step becomes the new final, and both steps' markers
are present in the ingested image.

Deferred as a follow-up, not part of this amendment: a live spike (buildx
v0.36.1, `docker` driver) confirmed that a single build can emit **both**
`--output type=docker` and `--output type=oci` exporters at once, which would
let every final build also land in docker's store and eliminate this
consequence entirely (and the equivalent one above). Not done here because it
changes the final-build path this amendment does not otherwise touch, needs
buildx ≥ 0.13, and the existing zstd→gzip retry logic would need to cover a
second exporter.

### Amendment: msb-owned base with a Docker base link (issue #98)

This ADR's "Digest-pinned `BASE_IMAGE`" decision assumed the base always
arrives from a registry, where msb's per-platform manifest digest is directly
pullable as `<repo>@<digest>`. That assumption breaks on the documented Apple
Silicon path: `script/build/import-image.sh` loads a local `docker save`
archive into msb, and msb *synthesizes* a manifest digest by re-serializing
the manifest itself. That digest is valid inside msb but exists in neither a
registry nor Docker's content-addressed namespace, so passing it straight to
buildx's `FROM` fails with "failed to resolve source metadata … pull access
denied". Pre-existing since issue #13; every layered project hit it.

**The split: msb owns base identity and launch; Docker executes builds.**

- **msb keeps the base identity unchanged.** The value fed to
  `layer::plan_chain` as step 0's `base_image_id` is still msb's resolved
  per-platform manifest digest — the same input as before, so no derived-image
  tag moves. The launch path stays **msb-only**: read base metadata → compute the
  chain hash → msb cache check → boot. A **cache-hit launch spawns no Docker
  process at all**, not even an `inspect`.
- **Docker gets a local bridge name, only at build time.** Step 0 builds
  `FROM agent-vm-base:<manifest-digest-hex>` — a Docker-local tag in a
  repository agent-vm owns. The link means "Docker's image under this tag is
  the same base whose manifest identity msb records"; it is *not* a second
  identity and never enters `plan_chain`'s hash input. `digest_pinned_base`
  is retained, repurposed to form the exact registry pull reference below.
- **`import-image.sh` creates the link at import time.** After `docker save |
  msb image load`, it reads the loaded destination's top-level manifest
  digest back (`msb image inspect --format json`, extracted structurally with
  `plutil` so the nested `config.digest` can't be mistaken for it) and runs
  `docker tag <source-image> agent-vm-base:<hex>`. Import is the one moment
  Docker's source image and msb's cached copy are known to be identical bytes
  — which is also why the renamed form
  (`import-image.sh my-local:dev agent-vm-template:dev`) links the *source*,
  not the destination.
- **Build-time resolution is lazy and ordered.** `execute_chain` calls
  `ChainRuntime::pin_base(base_ref, digest)` only when step 0 actually builds
  (after the final-cache check, the backward intermediate search, and the
  single chain confirmation):

  ```text
  cache-hit launch:   base metadata → chain hash → final msb cache hit → boot
                      Docker calls: ZERO

  build miss, step 0: plan_chain(..., msb-digest)          # identity is msb's
                      pin_base(base_ref, msb-digest):
                        agent-vm-base:<hex> present?  → use it
                        else docker pull <repo>@<digest>; docker tag → link
                        else hard-fail naming the ref + import-image.sh
                      buildx … --build-arg BASE_IMAGE=agent-vm-base:<hex>
  ```

**Accepted consequences.**

- **No multi-arch re-tag.** msb's per-platform manifest digest stays the hash
  input, so existing derived-image tags never move.
- **`import-image.sh` gains a Docker `tag` side effect** (and its fake-based
  tests cover it). Docker's source and msb's cache are linked at import time;
  a base that reached msb by some *other* offline route has no link and no
  pullable digest and **hard-fails**, naming the ref and
  `./script/build/import-image.sh` rather than booting the plain base.
- **A registry base's first build does one explicit `docker pull` + `docker
  tag`.** Later builds reuse the link; a cache-hit launch never gets here.
- **An existing `agent-vm-base:<hex>` link is trusted with no revalidation.**
  `pin_docker_base` / `pin_docker_base_with_runner` short-circuits on the
  presence probe, so a link left by an earlier import of *different* content
  under a colliding hex — or a manual retag — is used as-is. This is the one
  place the design can build `FROM` the wrong bytes. No revalidation probe
  was added: it would put an extra addressing/content call on a build path the
  design keeps deliberately lean, and import time is the *only* moment the
  two stores are known to hold identical bytes, so the link is established
  there (and re-established by rerunning the idempotent import).
- **Registry-less ingest and Docker-local intermediates are unchanged**: only
  the final step is ingested into msb; intermediates still live in docker's
  store.
- **Rejected: a persisted digest state file, or a Docker probe on the launch
  path.** Either can silently disagree with the image store — exactly the
  drift the hash-as-staleness-check design exists to prevent — and a probe
  would put Docker back on every cache hit.
- **Deferred: an explicit base-architecture guard.** Under containerd a
  multi-arch tag's identity is the *index* digest while `docker image inspect`
  reports whatever platform the tag currently resolves to, so a naive guard
  false-fails; genuine mismatches already hard-fail through buildx.

The older "Digest-pinned `BASE_IMAGE`" section above is retained as historical
context; its `<repo>@<digest>` reference now lives only inside `pin_base` as
the exact pull used to establish the link, not as buildx's step-0 `FROM`.

## Consequences

- **F5 — fsmeta/VMDK evicted while metadata survives.** If something ever
  garbage-collects the raw `fsmeta`/`vmdk` cache files but not the JSON
  metadata record, a naive "is this cached?" check that only looks at
  metadata would answer "yes", and the subsequent boot would fall through to
  `PullPolicy::IfMissing`'s registry step for a tag that has no registry —
  a hard failure, not a rebuild. **Mitigated in this PR, not deferred**:
  `layer::derived_is_cached` also asserts
  `GlobalCache::is_vmdk_materialized(manifest_digest)` after confirming
  metadata presence, so this state is treated as a cache miss and simply
  rebuilds. The residual, accepted case: both metadata and artifacts evicted
  together (the normal GC path) is indistinguishable from "never built" and
  correctly rebuilds either way.
- Tying registry-less boot to `load_archive` materializing fsmeta+VMDK is a
  dependency on `microsandbox_image` internals, not a stable public
  contract. An upstream change that stopped `load_archive` from
  materializing those artifacts would silently break tooling-layer boot.
  Guard with an e2e test (see the PR's test plan) rather than a compile-time
  check, since there is none available across a dynamic library boundary
  like this.
- A layered launch's opt-in registry update-check (`--update-check` /
  `$AGENT_VM_UPDATE_CHECK`) must keep probing the **base** image, never the
  reassigned derived tag — the derived tag has no registry to HEAD.
  `run.rs` keeps `base_image` as a binding separate from the (possibly
  reassigned) `image` for exactly this reason.
- Non-layer projects are unaffected: `resolve_boot_image_with_layer` returns
  `Ok(None)` when `.agent-vm/layers/` isn't declared and no `--layer` is
  given, and `launch()` boots `base_image` exactly as it did before this ADR.
- **Cross-arch correctness (resolved in this PR, after a live `aarch64`
  reproduction).** An earlier revision hardcoded `--platform linux/amd64`
  as the originating plan specified; a real `docker buildx build` +
  `load_archive` round-trip on an `aarch64` host proved that fails
  (`OCI layout contains no image manifests for the host platform`), because
  `load_archive` materializes the manifest for the *running host's* arch
  (`Platform::host_linux()`). The build platform is now derived from the
  host (`layer::host_oci_platform()`), keeping the built image, the
  `load_archive` materialization, and the boot in lockstep on both
  supported host families. Every other mechanism in this ADR —
  content-hash identity, cache-hit reuse, registry-less ingest, PATH
  propagation, edit-invalidates-cache — was verified working in that same
  round-trip once the platform matched.

### Optional image capabilities (API 2)

API 1 implicitly includes Chrome DevTools. Beginning with API 2, optional
features advertise an empty marker file after their layer's build-time sanity
checks pass. Chrome uses `/etc/agent-vm-capabilities/chrome-devtools-mcp`.
The launcher checks the booted sandbox after creation: this works on cold pulls,
unlike OCI cache metadata, and avoids treating layer directory names as a
capability protocol. New launchers retain API-1 Chrome compatibility; old
launchers reject the API-2 base through the image-version range check. Layers
may append their dedicated passwd/group entries while leaving both files
appendable for the launcher's guest identity machinery.
