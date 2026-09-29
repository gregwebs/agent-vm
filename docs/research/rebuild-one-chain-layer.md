# Rebuilding one chain layer without rebuilding the layers above it

**Research date:** 2026-09-29

**Question:** [#196](https://github.com/gregwebs/agent-vm/issues/196), part of map
[#194](https://github.com/gregwebs/agent-vm/issues/194). Can one step in the middle of a
**layer chain** (for example the `claude` **tool layer**) be rebuilt while every step above
it (for example `copilot`, then `.agent-vm/layers/*`) keeps its exact contents and versions?
This doc looks at two ways to do it:

- **A. Reuse the upper steps' existing layer diffs** on top of the rebuilt step
  (manifest rebasing).
- **B. Record each step's resolved tool version** and reinstall exactly that version
  above the rebuilt step.

For each, it asks whether the **layer image contract** (ADR-0003 C1–C8) stays checkable
per step, and how the approach fits the registry-less `load_archive` ingestion path.

**Local snapshot:** repo at `bb99445` ("Make every tool layer easy to version-upgrade
(#192)"), `vendor/microsandbox` at `4246606`. External sources were read on the research
date at go-containerregistry `0c8bedb`, regclient `43d2acb`, BuildKit `90b8639` and OCI
image-spec `ca68a05`. The experiments ran on macOS arm64 with Docker 29.5.2, buildx
v0.36.1 and a `docker`-driver builder (colima).

This is a record of facts, not a recommendation.

## Summary

| | A. Reuse upper diffs (rebase) | B. Reinstall recorded versions |
|---|---|---|
| Upper steps' files | Byte-identical: the same `diff_ids` are reused | Rebuilt. The same *version* is installed, but the bytes are new |
| Image config (`Env PATH`, `User`) | Copied from the **old** upper image. `${PATH}` was expanded when the old image was built, so a changed lower `PATH` is **not** picked up | Evaluated fresh by `docker buildx build` against the new predecessor |
| Build-time sanity RUNs (`--version` gates, `verify-*.sh`, C8 checks) | **Not re-run** against the new lower step | Re-run |
| Network / time | None for the upper steps (they are metadata plus blob copies) | Re-downloads every upper step: about 440 MB for `copilot` alone in the local chain measured below |
| Which steps it can cover | Any step, including arbitrary project layers, if the resulting image is sound | Only steps whose install can be pinned. Today that is `copilot` (build arg), `dsh` and `pi` (lockfiles). `codex`, `opencode` and `claude` would need Dockerfile changes. Project layers have no version record at all |
| Tooling available in agent-vm today | **None does it directly.** A Dockerfile can't express "apply this old diff" (`COPY --link` covers only `COPY`/`ADD`, and `ADD` of a layer tar does not honour whiteouts). `crane`/`regctl` are not dependencies. agent-vm would have to write an OCI/docker archive itself: the crates are in the build graph (`oci-spec`, `tar`, `sha2`), and `load_archive` accepts the result | Existing path: `docker buildx build` with more `--build-arg`s |
| Where upper blobs live | Intermediates are in Docker's image store. The final step exists **only** as per-layer EROFS in the msb cache; its OCI tar is deleted after ingest | Not needed |
| C1–C4 per step | C1, C3 and C4c can be checked from the composed config. C2 is checkable and is the clause that would **catch** a stale inherited `PATH` | Unchanged from today |
| C5–C8 | Still documented-only. C8's build-time checks are the RUN steps that are *not* re-run | Unchanged from today |

## How the chain works today

- `layer::plan_chain` hashes each step over its directory plus the previous step's hash
  (`crates/agent-vm/src/layer.rs:907-936`, `base_id = id.hash.clone()` at `:925`). "The
  hash is transitive, so the tag itself is the staleness check: there is no separate state
  file recording what was last built" (`CONTEXT.md:407-409`).
- `layer::execute_chain` walks backwards to the highest cached intermediate, then builds
  every step above it forward, one `docker buildx build` per step, each `FROM` the previous
  step's tag (`layer.rs:1045-1205`, backward walk at `:1083-1090`).
- The launcher passes exactly one build arg, `BASE_IMAGE=<from_ref>`
  (`layer.rs:1800-1804`). The installer layers therefore install whatever upstream calls
  latest at build time ([ADR-0019](../adr/0019-tool-free-base-and-per-tool-layers.md) D8).
- Intermediates go to Docker's store (`-t <tag> --output type=docker`). The final step goes
  to a temporary OCI tar (`--output type=oci`) that `load_archive` ingests
  (`layer.rs:1772-1863`). The tar is a `NamedTempFile` under the cache dir, removed on drop
  (`crates/agent-vm/src/run.rs:599-619`).
- **So any change to step N's hash changes the tag and the `FROM` of every step above N.**
  Docker's cache misses for all of them, and each floating installer re-resolves "latest".

## What a layer diff actually contains

The OCI image-spec defines a layer as a changeset. It contains "added and modified files and
directories **in their entirety**", and deletions are whiteout entries
(`.wh.<name>`, or `.wh..wh..opq` for an opaque directory)
([image-spec `layer.md`, Representing Changes / Whiteouts](https://github.com/opencontainers/image-spec/blob/ca68a05fad732be329ef67e713c3af60fb7d5f76/layer.md#representing-changes)).
When a changeset is applied over an existing path, a directory's attributes are replaced
by the entry's, and any other path is unlinked and recreated
([§ Changeset over existing files](https://github.com/opencontainers/image-spec/blob/ca68a05fad732be329ef67e713c3af60fb7d5f76/layer.md#changeset-over-existing-files)).
So an upper diff that modified a file a lower step also modifies carries its **whole old
copy** of that file. Replaying that diff over a rebuilt lower step silently reverts the
lower step's new version of the file.

The vendored msb ingester applies these semantics. `.wh.<name>` becomes a (0,0) char-device
whiteout and `.wh..wh..opq` becomes a `trusted.overlay.opaque` xattr
(`vendor/microsandbox/crates/image/lib/tar/ingest.rs:29-32`, `:645-700`).

### Experiment 1: does a no-op `chmod -R` pull lower files into a diff?

Every installer layer ends with `chmod -R a+rX /opt/agent`
(`images/tools/codex/Dockerfile:18`, `opencode/Dockerfile:24`, `claude/Dockerfile:17,70`).
`codex` and `claude` both install into `/opt/agent/.local/bin`. A throwaway build on
`alpine:3.20` did three things. It created `/opt/agent/.local/bin/codex` and ran
`chmod -R a+rX /opt/agent`. Then it added `claude` and ran the same `chmod`. Then it
removed `codex`. Exported with `--output type=oci`:

- the second layer contained only the parent directories and `claude`, **not** `codex`;
- the third layer contained `opt/agent/.local/bin/.wh.codex`.

So under this BuildKit, a `chmod` that changes no mode does not copy lower files into the
upper diff. A `chmod` that *does* change a mode would copy them. Parent directories are
always re-emitted, and by the image-spec rule above their attributes replace the lower
ones.

### Experiment 2: can a Dockerfile replay a diff with `ADD`?

`ADD` extracts a local tar with "the same behavior as `tar -x`", and the result is the
union of the destination and the archive
([Dockerfile reference, Adding local tar archives](https://github.com/moby/buildkit/blob/90b8639e6de8c679669a2700b12345a94577eae3/frontend/dockerfile/docs/reference.md#adding-local-tar-archives)).
`ADD`ing the layer blob from Experiment 1 over an image that still had `codex` left
**both** `codex` and a literal `.wh.codex` file in `/opt/agent/.local/bin`. `ADD` does not
apply whiteouts, so it cannot faithfully replay a layer diff.

### The real tool layers (read-only inspection of a local chain)

The user's Docker store holds `agent-vm-copilot:dev`, built on 2026-09-20 for arm64 by
`images/build.sh` (base → … → opencode → claude → copilot). Its last eight layers were
listed from a `docker save` of that image. The image was only read, not modified. Sizes are
from `docker history`.

| Step / RUN | Size | Paths in the diff |
|---|---|---|
| opencode `--version` gate | 65.5 kB | `/root/.cache/opencode/bin`, `/root/.local/share/opencode`, `/root/.local/state/opencode` |
| claude install | 237 MB | `/opt/agent/.local/bin/claude` (**not** codex's binary), `/opt/agent/.claude/…`, `/opt/agent/.claude.json`, `/opt/agent/.cache/claude`, `/opt/agent/.npm/_logs`, and 555 entries under `/tmp/node-compile-cache/v22.23.2-arm64-…/` |
| claude plugins | 11.5 MB | `/opt/agent/.claude/plugins/…`, `/opt/agent/.claude/settings.json` |
| claude stash | 11.5 MB | `/opt/agent-vm/claude-seed/…` |
| claude seed hook | 20.5 kB | `/opt/agent-vm/seed.d/10-claude-plugins` |
| copilot `npm install -g` | 275 MB | `/usr/lib/node_modules/@github/…`, `/usr/bin/copilot`, `/root/.npm/_cacache/…`, `/root/.npm/_logs/…`, **and one file under the same `/tmp/node-compile-cache/v22.23.2-arm64-…/` directory the claude layer created** |
| copilot `--version` gate | 165 MB | `/root/.cache/copilot/pkg/…`, `/tmp/node-compile-cache/v24.20.0-arm64-…/…` |

The config `PATH` of both `agent-vm-claude:dev` and `agent-vm-copilot:dev` is the literal
`/opt/agent/.local/bin:/opt/agent/.claude/local/bin:/opt/agent/.opencode/bin:/opt/agent/.local/bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin`.
`docker history` shows the claude step's `ENV` stored already expanded. BuildKit expands
`${PATH}` at build time
([Dockerfile reference, Environment replacement](https://github.com/moby/buildkit/blob/90b8639e6de8c679669a2700b12345a94577eae3/frontend/dockerfile/docs/reference.md#environment-replacement)),
and the OCI config's `Env` holds the result
([image-spec `config.md`](https://github.com/opencontainers/image-spec/blob/ca68a05fad732be329ef67e713c3af60fb7d5f76/config.md)).

## A. Reusing upper steps' diffs (rebasing)

### What existing tools do

- **`crane rebase`** (go-containerregistry). The core `mutate.Rebase` checks that the old
  base's layer digests are a prefix of the image's. It then builds a new image from **the
  original image's config** (only `Architecture`/`OS`/`OSVersion` come from the new base),
  the new base's layers and history, and the original's layers above the old base
  ([`pkg/v1/mutate/rebase.go:25-120`](https://github.com/google/go-containerregistry/blob/0c8bedb78437f791a02589e38272adb76111e64d/pkg/v1/mutate/rebase.go#L25-L120)).
  Its documentation says: "**This is not safe in general** … The tool has no visibility
  into what the specific contents of the resulting image, and has no idea what constitutes
  a 'valid' image … Rebasing arbitrary layers in an image is not a good idea." It also says
  rebasing should happen only at a boundary that "adhere[s] to some contract about what
  'base' layers can be expected to produce"
  ([`cmd/crane/rebase.md`](https://github.com/google/go-containerregistry/blob/0c8bedb78437f791a02589e38272adb76111e64d/cmd/crane/rebase.md)).
- **`regctl image mod --rebase` / `--rebase-ref old,new`** (regclient). This does the same
  splice. It validates that the old base's layers, history entries and `rootfs.diff_ids`
  are a prefix of the image's, then replaces them with the new base's. The rest of the
  image config, `Env` included, is kept
  ([`mod/manifest.go:623-860`](https://github.com/regclient/regclient/blob/43d2acb9fafd411acbe081bf6c4b6b82cadc6251/mod/manifest.go#L623-L860);
  flags at [`cmd/regctl/image.go:850-885`](https://github.com/regclient/regclient/blob/43d2acb9fafd411acbe081bf6c4b6b82cadc6251/cmd/regctl/image.go#L850-L885)).
  regclient can address a local OCI layout as well as a registry (`scheme/ocidir`).
- **BuildKit `COPY --link` / `ADD --link`.** These copy "into an empty destination
  directory" that is then "linked on top of your previous state", equivalent to building
  the `COPY` `FROM scratch` and "merging all the layers of both images together". This lets
  BuildKit "rebase your images when the base images receive updates, without having to
  execute the whole build again", in some backends by writing only a new manifest. The
  price is that a linked `COPY` "[is] not allowed to read any files from the previous
  state"
  ([Dockerfile reference, `COPY --link`](https://github.com/moby/buildkit/blob/90b8639e6de8c679669a2700b12345a94577eae3/frontend/dockerfile/docs/reference.md#copy---link)).
  It applies only to `COPY`/`ADD`. Every tool layer's install is a `RUN`, and a `RUN`
  always executes on the previous state.
- **BuildKit MergeOp / DiffOp** (LLB). `Merge` rebases states on top of each other.
  `Diff(lower, upper)` isolates what `upper` added, and on export reuses the existing
  layers when `lower` is in `upper`'s history. Deletions are "entities" that apply on
  merge, so a merged diff can delete files in the new lower state
  ([`docs/dev/merge-diff.md`](https://github.com/moby/buildkit/blob/90b8639e6de8c679669a2700b12345a94577eae3/docs/dev/merge-diff.md),
  §§ DiffOp Container Image Export, Deletions). These are LLB operations used through the
  Go client or a custom frontend. The Dockerfile frontend exposes MergeOp only through
  `--link`, and nothing in agent-vm generates LLB.
- **`docker buildx imagetools create`** "create[s] a new manifest list based on source
  manifests" that "must already exist in the registry"
  ([buildx docs](https://github.com/docker/buildx/blob/master/docs/reference/buildx_imagetools_create.md)).
  It composes indexes. It does not splice layers into an image manifest.

### Can it be done with what agent-vm already depends on?

- **With `docker buildx` alone: no.** No Dockerfile instruction applies an existing layer
  diff with whiteouts (Experiment 2), and `--link` does not cover `RUN`.
- **By writing an archive for `load_archive`: yes.** `load_archive` accepts a
  `docker save`-style archive (`manifest.json`) or an OCI layout
  (`vendor/microsandbox/crates/image/lib/archive/docker.rs:612-630`). It builds its own
  manifest from the archive's config and layers (`docker.rs:783-830`). The crates for
  writing such an archive are already in the build graph through `microsandbox-image`:
  `oci-spec` 0.10, `tar` 0.4, `flate2`, `zstd`, `sha2` (`Cargo.lock`; `cargo tree -i`).
  agent-vm itself depends directly only on `sha2` and `serde_json`
  (`crates/agent-vm/Cargo.toml:72-74`).
- **Blob availability.**
  - The rebuilt lower step and any **intermediate** upper steps are in Docker's store and
    can be exported with `docker save` (on this host `docker save` wrote an OCI layout
    with compressed blobs).
  - The **final** step's layers are not in Docker's store (ADR-0003 chain amendment,
    `docs/adr/0003-project-tooling-layers.md:361`), and its OCI tar is deleted after ingest
    (`run.rs:604-611`).
  - msb can regenerate tars from its per-layer EROFS with `save_archive`
    (`docker.rs:384-400`, `generate_layer_tar` at `:1522-1565`). The regenerated tar's
    digest becomes the new `diff_id` and the config is rewritten with it
    (`docker.rs:428-445`). That id is **not guaranteed** to equal the original.
- **`load_archive` needs every blob in the archive,** base layers included. A layer the
  manifest lists but the archive lacks is `docker archive missing layer`
  (`docker.rs:803-805`). EROFS work is skipped for any `diff_id` already materialized
  (`registry/client.rs:916`), and the uncompressed digest is verified against the config's
  `diff_id` (`client.rs:1030-1042`). So reused diffs cost archive I/O and hashing but no
  new EROFS. The fsmeta and VMDK are keyed per manifest digest (`cache/store.rs:241-297`)
  and are rebuilt for the new image.

### When a rebase is unsound, on the real layers

A rebase of upper step U over a rebuilt lower step L′ is exactly "Merge(L′, diff(U))" with
U's old config. It is unsound whenever U's diff or config encodes something derived from
the old L:

1. **Files both steps write.** U's diff holds whole copies (image-spec). Real cases:
   - `/etc/passwd`/`/etc/group`: C6 lets any layer *append* accounts (the base appends
     `chrome` this way). An upper layer that appends ships the whole file, so rebasing it
     drops any account a rebuilt lower layer added.
   - Shell profiles under `HOME=/opt/agent`. The opencode installer appends to the first
     existing `.bashrc`/`.bash_profile`/`.profile`
     ([opencode install](https://opencode.ai/install), `config_files` / `add_to_path`).
     The codex installer appends a marked block to a profile picked by `$SHELL`, unless
     `BIN_DIR` is already on `PATH`
     ([codex install.sh](https://github.com/openai/codex/releases/latest/download/install.sh),
     `pick_profile` / `add_to_path`). In the local chain inspected above no profile file
     appears in the claude/copilot diffs, but whether one does depends on the installer
     version and on `$SHELL`.
   - Shared caches: `/tmp/node-compile-cache/<node-ver>/` is written by both claude and
     copilot, and `/root/.npm/_cacache` by any `npm` step. These are caches, so a stale
     entry is a performance matter, not a correctness one, but they are real shared paths.
2. **Deletions.** A whiteout in U's diff deletes that path in L′ too (BuildKit
   merge-diff § Deletions). `dsh` runs `rm -rf /root/.npm` (`images/tools/dsh/Dockerfile:49`).
   Above a lower step that populated `/root/.npm`, that diff carries whiteouts that would
   also remove whatever L′ put there.
3. **Metadata-only changes.** A `chmod -R` that actually changes a mode copies lower
   files whole into U (Experiment 1 shows the no-change case stays clean). If L′ ships a
   new binary at that path, U's old copy wins.
4. **Image config derived from L.** U's `Env PATH` is L's `PATH` expanded at U's build
   time. If L′'s Dockerfile changed its `ENV PATH` line, the rebased image keeps the old
   list. For the shipped layers the `ENV PATH` lines are literals
   (`claude/Dockerfile:13`, `codex:13`, `opencode:13`; copilot/pi/dsh add none), so a
   **version-only** rebuild of a tool layer leaves `PATH` unchanged.
5. **Build-time checks and generated state computed against L.** The rebased U was never
   executed on L′:
   - U's `--version` gates and `verify-*.sh` (the C8-style "advertise only when it works"
     checks) are not re-run.
   - Anything U generated from L's contents is kept as-is. Examples: `claude plugin
     install` resolved against the old `claude` binary; the pi layer's
     `seed.d/20-pi-claude-bridge` points the bridge at `/opt/agent/.local/bin/claude`
     (`images/tools/pi/Dockerfile:34-59`); node compile caches are keyed by node version.

   In the default declaration order `dsh, pi, codex, opencode, claude, copilot`
   (`crates/agent-vm/src/default-tools.toml`), only `copilot` sits above `claude`. Its
   diff touches `/usr/lib/node_modules/@github`, `/usr/bin/copilot`, `/root/.npm`,
   `/root/.cache/copilot` and the shared compile cache. None of these are claude's files.
   Project layers above it are arbitrary.

### Contract and identity under A

- **C1** (diff_ids extend the predecessor's) holds by construction for a splice. It is
  exactly what `crane`/`regctl` validate, and it can be checked with the existing
  `check_builds_on_predecessor` (`crates/agent-vm/src/layer/contract.rs:394-437`) against
  the rebuilt predecessor's facts.
- **C2** (`PATH` ⊇ predecessor `PATH`, `contract.rs:465-500`) is checkable from the composed
  config. It is also the clause that **fails** in case 4 above: an old upper `PATH`
  missing a directory the rebuilt lower step added.
- **C3** (`User` of the final image) and **C4c** (exported platform) read the composed
  config, which is U's old config with the new base's `os`/`architecture` in `crane`'s
  implementation.
- **C5–C8** stay documented-only, as today (ADR-0003 D4). Rebasing specifically skips
  re-running C8's build-time sanity checks.
- **Identity.** `ImageFacts` (`contract.rs:127-151`) holds only `diff_ids`, `Env`, `User`
  and platform, so all of C1–C4 can be evaluated on a composed archive before
  `load_archive`, or on the `CachedImageMetadata` it returns, as for today's final step.
  A rebased U's content is no longer a function of (U's directory, predecessor hash)
  alone; it also depends on which old diff was reused. How the tag should name that is
  the identity ticket's question
  ([#197](https://github.com/gregwebs/agent-vm/issues/197)). Note too that rebuilding
  `claude` with an unchanged directory produces the **same** hash today, so a rebuild verb
  needs some new identity input under either approach.

## B. Recording and reinstalling exact versions

Which layers can install an exact version today, and how each upstream reports its
version, is covered in the sibling research
[`docs/research/tool-latest-releases.md`](https://github.com/gregwebs/agent-vm/blob/research/tool-latest-releases/docs/research/tool-latest-releases.md)
(#195). In short:

- `copilot` already installs `${AGENT_VERSION_COPILOT:-latest}`
  (`images/tools/copilot/Dockerfile:17`).
- `dsh` and `pi` are pinned by committed lockfiles.
- The `codex`, `opencode` and `claude` installers accept a version, but the Dockerfiles only
  use `AGENT_VERSION_*` as a cache key.

Facts relevant to the comparison:

- **Nothing records a resolved version today.** There is no state file (`CONTEXT.md:409`),
  and the launcher passes only `BASE_IMAGE` (`layer.rs:1800-1804`). Approach B needs a
  record, for example a build arg that becomes part of the step's identity or a value read
  back from the built image.
- **A version is not the whole step.**
  - The claude step also runs `claude plugin marketplace add` / `plugin install` against
    the marketplace repo's current state (`images/tools/claude/Dockerfile:62-70`), and
    even an exact claude install downloads the `latest` binary first (sibling doc, claude
    row).
  - The copilot `--version` gate writes 165 MB under `/root/.cache/copilot/pkg` (table
    above).
  - Reinstalling the same version therefore reproduces the version, not the bytes.
- **Project layers have no generic version.** A `.agent-vm/layers/*` or `--layer`
  Dockerfile is arbitrary (ADR-0003). An unpinned `apt-get install`, `curl …/latest` or
  `npm install -g pkg` in it resolves again at rebuild time, and agent-vm has no way to
  record what it resolved.
- **Cost.** Every upper step is re-executed and re-downloaded. In the local chain the copilot
  step alone is 275 MB + 165 MB (table above). Every rebuilt step then goes through
  `docker buildx` and, for the final step, a full `load_archive` with new EROFS for each
  new `diff_id`.
- **Contract.** Unchanged from today: each rebuilt step is built `FROM` its real predecessor
  and checked by `contract::check_built_image` (`contract.rs:321-335`). Its build-time
  sanity RUNs execute against the new lower step, and its config (`PATH`) is re-evaluated.
  It fits `load_archive` exactly as the current final step does.

## Sources

- Repo (`bb99445`): `crates/agent-vm/src/layer.rs`, `crates/agent-vm/src/layer/contract.rs`,
  `crates/agent-vm/src/run.rs`, `crates/agent-vm/src/default-tools.toml`,
  `images/tools/*/Dockerfile`, `CONTEXT.md`,
  [ADR-0003](../adr/0003-project-tooling-layers.md),
  [ADR-0019](../adr/0019-tool-free-base-and-per-tool-layers.md).
- `vendor/microsandbox` (`4246606`): `crates/image/lib/archive/docker.rs`,
  `crates/image/lib/registry/client.rs`, `crates/image/lib/tar/ingest.rs`,
  `crates/image/lib/cache/store.rs`.
- OCI image-spec `ca68a05`: [`layer.md`](https://github.com/opencontainers/image-spec/blob/ca68a05fad732be329ef67e713c3af60fb7d5f76/layer.md),
  [`config.md`](https://github.com/opencontainers/image-spec/blob/ca68a05fad732be329ef67e713c3af60fb7d5f76/config.md).
- BuildKit `90b8639`: [Dockerfile reference](https://github.com/moby/buildkit/blob/90b8639e6de8c679669a2700b12345a94577eae3/frontend/dockerfile/docs/reference.md),
  [`docs/dev/merge-diff.md`](https://github.com/moby/buildkit/blob/90b8639e6de8c679669a2700b12345a94577eae3/docs/dev/merge-diff.md).
- go-containerregistry `0c8bedb`: [`cmd/crane/rebase.md`](https://github.com/google/go-containerregistry/blob/0c8bedb78437f791a02589e38272adb76111e64d/cmd/crane/rebase.md),
  [`pkg/v1/mutate/rebase.go`](https://github.com/google/go-containerregistry/blob/0c8bedb78437f791a02589e38272adb76111e64d/pkg/v1/mutate/rebase.go).
- regclient `43d2acb`: [`mod/manifest.go`](https://github.com/regclient/regclient/blob/43d2acb9fafd411acbe081bf6c4b6b82cadc6251/mod/manifest.go),
  [`cmd/regctl/image.go`](https://github.com/regclient/regclient/blob/43d2acb9fafd411acbe081bf6c4b6b82cadc6251/cmd/regctl/image.go).
- buildx: [`imagetools create`](https://github.com/docker/buildx/blob/master/docs/reference/buildx_imagetools_create.md).
- Upstream installers fetched 2026-09-29: `https://opencode.ai/install`,
  `https://github.com/openai/codex/releases/latest/download/install.sh`,
  `https://claude.ai/install.sh`.
- Experiments 1–2: throwaway `alpine:3.20` builds exported with `--output type=oci` /
  `type=cacheonly` (no images tagged). The local-chain table comes from a read-only
  `docker save` of `agent-vm-copilot:dev`, deleted afterwards.
