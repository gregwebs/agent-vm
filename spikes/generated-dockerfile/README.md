# SPIKE: single generated Dockerfile / plain-docker composition

**Throwaway.** This exists to answer one question before #194 commits to a
direction:

> Can a *single generated Dockerfile* — or a `buildx bake` DAG over the
> **existing, unmodified** per-tool Dockerfiles — replace the chained per-tool
> OCI layers, and stop a one-tool bump from cascading through every layer above
> it?

Run everything with one command:

```bash
spikes/generated-dockerfile/spike.sh
```

`generate` rewrites the real `images/tools/*/Dockerfile` bodies into three
composed build artifacts with no hand-editing of the per-tool files. `measure`
builds a tiny synthetic fixture (base `debian:13-slim`, four fake tools) twice
per shape and prints what re-ran after one tool's version was bumped.

## What it emits

| Artifact | Shape |
|---|---|
| `out/linear.Dockerfile` | `FROM base` + every tool body appended inline, in declaration order. Faithful to today's chain, but one file. |
| `out/multistage.Dockerfile` | One **independent** `FROM base AS tool_<t>` stage per tool, plus a `merged` stage that `COPY --from`s each tool's footprint and re-assembles `PATH`. |
| `out/merge.Dockerfile` | The merge stage expressed against **bake named contexts** — the tool bodies stay in `images/tools/*/Dockerfile`, unregenerated. |
| `out/docker-bake.hcl` | A DAG: one target per tool + a `merge` target that references them as `tool_<t>` contexts. `docker buildx bake merge` builds the whole thing; `docker buildx bake tool-codex` rebuilds just codex. |

The generator rewrites relative `COPY` and `--mount=type=bind,source=` paths to
`images/tools/<tool>/…` so the single context is the repo root. Nothing else in
the tool sources changes.

## The measured result (fixture: 4 tools, bump `opencode`)

```
linear           re-ran 3 tool install(s) / 6 step(s): opencode, claude, copilot
multistage       re-ran 1 tool install(s) / 5 step(s): opencode
multistage+link  re-ran 1 tool install(s) / 5 step(s): opencode
prefix+link      re-ran 1 tool install(s) / 5 step(s): opencode
```

**The headline win is real but the step count undersells it.** Linear re-executes
`claude`'s and `copilot`'s *installers* (network, minutes). Every multi-stage
shape re-runs only `opencode`'s installer; the other tools' work in the rebuild
is a handful of `COPY` instructions that complete in `0.0s`.

### Follow-up 1 -- does `COPY --link` remove the residual merge cascade?

**No change in step count, but the steps stop mattering.** With `--link`, the
merge COPYs still *execute*, but each is an independent content-addressed layer
(observed at `DONE 0.0s`), so none carries the parent's invalidation and they
can be parallelised. Without `--link` the merge stage is one linear snapshot
chain; a changed tool's COPY changes the snapshot the later COPYs build on. In
practice both are cheap; `--link` is the safer default for a built-in merge.

### Follow-up 2 -- does a disjoint per-tool prefix delete the footprint table?

**Yes.** The `prefix+link` fixture has every tool write only under
`/opt/tool-<name>`, so the merge is definitional — one `COPY` per tool, no
hand-maintained `COPY_ROOTS`. Applying this to the *real* tools is real work:
their installers hard-code `$HOME/.local`, `/opt/agent/.claude`, a private
`/opt/agent/.codex` prefix, npm's global `/usr/lib/node_modules`, etc. A phased
version would wrap each installer with `HOME=/opt/tool-<name>` and expose bins
through one symlink directory.

### Follow-up 3 -- real image: size and layer count

Building against the *published* base is blocked: `ghcr.io/wirenboard/agent-vm-base`
returns **403 for anonymous pulls** (the private-package release item ADR-0019
already records). A local `agent-vm-base:dev` and pre-built per-tool images were
available, so the merge was measured with the existing images as build contexts
(no reinstall, same filesystem content):

| image (linux/arm64) | layers | size |
|---|---|---|
| `agent-vm-base:dev` (tool-free) | 12 | 267 MB |
| current chain `agent-vm-template:dev` | 29 | 871 MB |
| merge, real independent stages (`out-real5`) | 27 | 766 MB |
| merge, existing images as build contexts | 23 | 731 MB |

The generated `out-real5/multistage.Dockerfile` (5 real tools, independent
stages + merge) **built end-to-end** against `agent-vm-base:dev`, and all five
tools resolve. The merge is *smaller and shallower* here, not larger, by either
route. (Not a controlled experiment: the local chain predates the `dsh` layer
and the two were not built from identical inputs. It is enough to reject
"merging inflates the image".)

`verify-merge.sh <image> cmd1,cmd2,...` is the smoke test that would have caught
the wrong-footprint bug below; it passes for the merged image:

```
$ ./verify-merge.sh agent-vm-spike-merge:existing claude,codex,opencode,pi,copilot
  ok    claude / codex / opencode / pi / copilot
```

## Findings (what the spike actually taught us)

1. **Independent stages kill the cascade.** A tool bump re-runs that stage only.
   The generators' `COPY_ROOTS` table is deliberately hand-written; that is the
   finding, not the bug (see #3).

2. **The merge stage is itself a linear prefix chain — a residual cascade.**
   `merged 4/5` and `5/5` re-ran even though `tool_claude`/`tool_copilot` were
   cache hits: once the `opencode` COPY changes the merged snapshot, every later
   COPY's parent differs. `COPY --link` (follow-up 1) did **not** reduce the step
   count, but made each COPY an independent content-addressed layer completing
   in `0.0s`. It's cheap either way; use `--link` as the safer default.

3. **Merge composition must know each tool's filesystem footprint, and the
   first guess was wrong.** The initial `COPY_ROOTS` put codex at
   `/opt/agent/.local` (it actually installs a private `/opt/agent/.codex`
   prefix) and copilot at `/usr/local/lib/node_modules` (this base's npm prefix
   is `/usr`, so it is `/usr/lib/node_modules`). A wrong entry is a silent
   missing tool. The chained-diff model got the footprint for free; the merge
   model must derive it (`prefix+link`) or maintain it.

4. **`bake` + named contexts needs no generated concatenation at all.**
   `docker buildx bake --print` resolves cleanly, each tool target builds from
   its own untouched Dockerfile, and `merge` references them by name. This is the
   most "use the existing docker tools" option: the only generated file is the
   tiny merge `FROM`/`COPY`s. Tool selection becomes `bake tool-x tool-y merge`.

5. **This does not resolve versions.** It's orthogonal: a manifest feeding
   `AGENT_VERSION_*` build args still needs the per-tool latest-version query
   (#195) and rebuild targeting (#198). What changes is that the composition
   layer stops being image algebra.

6. **Contract/architecture impact to weigh.**
   - C1 (diff-id prefix) no longer holds — the merged image is not a prefix
     stack. C2 becomes a generation concern (assemble `PATH`) rather than a
     checked image fact.
   - msb ingest is unaffected: the merged result is still one OCI image.
   - **Project tooling layers are unaffected**: they chain `FROM` the merged
     tools image exactly as today, preserving ADR-0003's arbitrary-Dockerfile
     customization. Only the *tool* chain is replaced.

## Suggested next steps

- Wire the winning shape into a real design: bake targets per tool + a `--link`
  merge, with `COPY_ROOTS` derived from a per-tool footprint declaration rather
  than hand-listed (see `prefix+link` for the end state).
- Make the base pullable (or use a local-base import) so the real generated
  Dockerfile can be built and diffed against the published template in CI.
- Decide whether the fast path stays "boot a published composed image verbatim"
  (yes, presumably — bake just changes how the non-default path is composed).
- Add a merged-image contract to replace the prefix-stack clauses: each declared
  tool's binary resolves, each PATH prefix is present, files stay world-readable.

## Caveats

- The fixture proves *composition mechanics*, not the real tools' install
  behavior. `out/*` uses the real bodies; building it needs a base image (the
  published one is private — 403 for anonymous pulls — so use `agent-vm-base:dev`).
- `out*/` dirs are generated and gitignored.
