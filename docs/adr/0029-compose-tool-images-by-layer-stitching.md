# ADR-0029: Compose tool images by layer stitching

## Status

**Superseded by [ADR-0035](0035-consume-user-owned-boot-images.md) (#257). The launcher DAG/current-tag/version-identity system was not implemented; committed recipe/version pins and source integrity checks are retained in the independent [image repository](https://github.com/gregwebs/agent-vm-images); source ownership moved by #265.**

Accepted (decision). Not yet implemented — the rest of the design is tracked by
the map [Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).
Supersedes [ADR-0019](0019-tool-free-base-and-per-tool-layers.md)'s chaining of
tool layers in declaration order, and removes tool layers from
[ADR-0003](0003-project-tooling-layers.md)'s layer chain. Where project layers
ended up was settled by [ADR-0032](0032-one-layer-kind.md): the layers/tools
distinction is removed, so **every** layer is an independent node in this ADR's
stitched DAG, and "project tooling layer" is no longer a kind of thing.

The order this ADR stitched in was amended by
[ADR-0032](0032-one-layer-kind.md): stitch order is now **derived** from the
declared `parent` graph, with declaration order demoted to a tie-break among
layers the graph does not order.

## Context

Today every tool layer builds `FROM` the previous one. A tool image is therefore
keyed by its position, so bumping one tool rebuilds every layer above it, and the
same tool is built again for every tool set it appears in. We prototyped the
obvious Docker fix (`spikes/generated-dockerfile/` on branch
`spike/generated-dockerfile`): independent per-tool stages combined by a
`COPY --link --from=<tool>` merge build. That fix needs every tool's filesystem
footprint. The hand-written footprint table was wrong twice for shipped tools
(codex writes to `/opt/agent/.codex`; copilot writes to `/usr/lib/node_modules`),
and a user's `layer = { path = … }` can't come with a trusted footprint at all.

## Decision

Build each tool layer `FROM` its **parent** — the base image, or one tool it
explicitly declares — and join the resulting tool images by **stitching**: write
a new OCI manifest whose layers are the base's layers followed by each tool's
own layers above its parent, in catalog order, with no merge build.

- **Config** is derived, not declared: each tool's `PATH` entries that the
  base doesn't have are prepended in stitch order. Any other config change is a
  contract violation ([ADR-0031](0031-tool-image-contract.md) T2, S3).
- **Overlaps**: a file written by more than one tool is detected at stitch time
  and is a hard error; shared directory entries and paths under the guest's
  tmpfs mounts are ignored ([ADR-0031](0031-tool-image-contract.md) S1).
- **Identity** is computed from inputs. A tool image = hash(parent identity,
  build context, build args passed; see
  [ADR-0030](0030-tool-versions-in-identity-and-current-tags.md) for how the
  version is chosen); it doesn't depend on the tool's position,
  so it is reused across tool sets. The composed image = hash(base digest,
  ordered tool identities), cached in msb and skipped when present. Stitching is
  deterministic (fixed timestamps, canonical JSON), so the same inputs give the
  same manifest digest.
- **Driver**: generated `docker buildx bake` files covering only the tools
  that aren't cached, **one bake process per independent group** (a root tool
  plus the tools that declare it as parent), run concurrently. A declared
  parent is passed as a `target:` context (same group) or an `oci-layout://`
  context (already cached). A single bake over every target won't do: when one
  target fails, bake cancels the others and their exports never land.
- **Storage**: one content-addressed OCI layout in agent-vm's cache, with
  **agent-vm as its only writer**. Each bake target exports to its own staging
  layout; agent-vm hardlinks the blobs in (skipping blobs already present) and
  writes `index.json` itself. Concurrent exports into one shared layout race in
  its `ingest/` directory when they share a blob. The stitcher reads blobs from
  the layout, and the result is ingested with `load_archive`, which reuses msb's
  per-`diff_id` EROFS layers.
- **Failure**: if one tool fails to build, the launch fails and names it;
  images already built stay cached.
- **One implementation**: CI produces the published composed default with the
  same stitching code.

## Considered Options

- **COPY-merge build** (the spike): uses only Docker tools, but it needs a
  footprint for every tool, or a disjoint-prefix convention that forces
  refactoring every installer and constrains user layers.
- **BuildKit MergeOp/DiffOp directly**: would need a custom LLB frontend.
- **Store tool images only in the msb cache**: msb has no API to read a blob
  back out, BuildKit can't use msb as a build context for a declared parent,
  and CI has no msb.

## Evidence

The prototype on branch `spike/tool-layer-stitching`
(`spikes/tool-layer-stitching/`, one command: `spike.sh`) stitches the six
builtin tools plus a user tool whose declared parent is claude. The result boots
in agent-vm with a project tooling layer on top. It shows that a codex bump
rebuilds one tool image (35 of 37 layers unchanged), that a different tool set
rebuilds nothing, and that the output is byte-for-byte reproducible. It is also
where the Driver and Storage corrections above came from.

## Consequences

- A one-tool bump rebuilds one tool image and re-stitches in seconds.
- The launcher owns a small OCI manifest writer. Docker/buildx still does every
  build.
- Compressed blobs are stored twice (the OCI layout and msb's cache), and
  neither store has garbage collection yet.
- Re-ingesting into msb isn't incremental at the archive level: after a
  one-tool bump, `load_archive` took about as long as the first ingest (~18 s
  for a 1 GB image), because it re-reads every blob and rebuilds the per-image
  metadata.
- [ADR-0033](0033-default-rebase-with-build-provenance.md) defaults to rebase
  when only the base changes, with an explicit rebuild option and a compatibility
  warning. Reused artifacts retain their build provenance; structural checks
  run against the destination, but runtime/ABI dependency management is excluded.
