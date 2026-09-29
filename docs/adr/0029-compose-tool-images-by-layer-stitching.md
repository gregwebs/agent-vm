# ADR-0029: Compose tool images by layer stitching

## Status

Accepted (decision). Not yet implemented — the rest of the design is tracked by
the map [Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).
Supersedes [ADR-0019](0019-tool-free-base-and-per-tool-layers.md)'s chaining of
tool layers in declaration order, and removes tool layers from
[ADR-0003](0003-project-tooling-layers.md)'s layer chain. Where project tooling
layers end up is still open on the map.

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
  contract violation (the clause wording is The composed tool image's
  contract).
- **Overlaps**: a path written by more than one tool is detected at stitch time
  and flagged unless it's on an allow-list (e.g. shared directory entries). Later
  tools still win, so the result is deterministic.
- **Identity** is computed from inputs. A tool image = hash(parent identity,
  build context, resolved version); it doesn't depend on the tool's position,
  so it is reused across tool sets. The composed image = hash(base digest,
  ordered tool identities), cached in msb and skipped when present. Stitching is
  deterministic (fixed timestamps, canonical JSON), so the same inputs give the
  same manifest digest.
- **Driver and storage**: one generated `docker buildx bake` file covering only
  the tools that aren't cached, with a declared parent passed as a
  `target:`/`oci-layout://` context. Bake exports into one content-addressed
  OCI layout in agent-vm's cache; the stitcher reads blobs from there, and the
  result is ingested with `load_archive`, which reuses msb's per-`diff_id`
  EROFS layers.
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

## Consequences

- A one-tool bump rebuilds one tool image and re-stitches in seconds.
- The launcher owns a small OCI manifest writer. Docker/buildx still does every
  build.
- Compressed blobs are stored twice (the OCI layout and msb's cache), and
  neither store has garbage collection yet.
- Rebasing onto a new base becomes a manifest edit, as long as tool diffs don't
  depend on the base (Rebasing tool layers onto an updated base).
