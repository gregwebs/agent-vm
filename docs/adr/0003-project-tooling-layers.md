# ADR-0003: Project tooling layers — build, registry-less load, and boot

## Status

Accepted.

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

A `.agent-vm/layer/Dockerfile` MUST:

- Start `ARG BASE_IMAGE=<default>` then `FROM ${BASE_IMAGE}` — the launcher
  overrides `BASE_IMAGE` via `--build-arg` to the digest-pinned base; a
  Dockerfile that hardcodes `FROM ghcr.io/...` instead breaks the pin.
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
  `Ok(None)` when `.agent-vm/layer/` isn't declared, and `launch()` boots
  `base_image` exactly as it did before this ADR.
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
