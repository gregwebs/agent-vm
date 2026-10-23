# ADR-0035: Consume user-owned boot images

## Status

Accepted. Implementation decision for [agent-vm #259](https://github.com/gregwebs/agent-vm/issues/259),
slice 2 of [agent-vm #257](https://github.com/gregwebs/agent-vm/issues/257);
the retained-default decision below is [agent-vm
#261](https://github.com/gregwebs/agent-vm/issues/261), slice 4 (amended, see
*Decision*). Explicit replacement is implemented by [#262](https://github.com/gregwebs/agent-vm/issues/262).
Amended for **all-source host-wide approval** by [agent-vm
#390](https://github.com/gregwebs/agent-vm/issues/390) and
[ADR-0047](0047-host-wide-oci-image-approval.md): every OCI selection is now
pinned, a changed pin needs candidate-scoped consent, and launches consume only
approved child content.
Supersedes [ADR-0003](0003-project-tooling-layers.md),
[ADR-0019](0019-tool-free-base-and-per-tool-layers.md),
[ADR-0028](0028-explicit-image-flag-beats-the-other-environment-variable.md),
[ADR-0029](0029-compose-tool-images-by-layer-stitching.md),
[ADR-0030](0030-tool-versions-in-identity-and-current-tags.md),
[ADR-0031](0031-tool-image-contract.md),
[ADR-0032](0032-one-layer-kind.md) and
[ADR-0033](0033-default-rebase-with-build-provenance.md) and
[ADR-0034](0034-versioned-image-releases.md). Amends
[ADR-0015](0015-config-driven-tools.md) and
[ADR-0022](0022-dsh-tool-layer.md).

## Context

The image a session boots was a **consequence of the tool catalog**. Whenever a
catalog's declared tool-layer sequence differed from the shipped one — even one
custom tool with no `layer` — the launcher selected the tool-free base and
composed layers onto it, starting Docker builds and a confirmation prompt. A
runtime tool declaration could therefore change the image, and a project could
trigger multi-minute local builds. That coupling is the defect this ADR removes.

[#257](https://github.com/gregwebs/agent-vm/issues/257) states the ownership
boundary that resolves it: agent-vm owns launching and supervision, image
*selection*, acquisition and import, runtime tool declarations, credentials,
mounts, networking and state; users own their image's software, accounts and
updates. Under that boundary the launcher only ever **consumes** a finished
image.

The Layer DAG (ADR-0029–0033) was never implemented — no code ever composed a
DAG, stitched images, or maintained current tags. What *is* implemented is the
image production pipeline: committed recipe/version pins, lockfiles and the
source-integrity gates, now retained at the independent [image owner](https://github.com/gregwebs/agent-vm-images). #263/#264 implemented source maintenance/publication; #265 moves
the contributor gitlink and launcher recommendation, without a runtime source dependency.

## Decision

- **Ownership boundary.** agent-vm owns launch/supervision, image
  selection/acquisition/import, runtime tool declarations, credentials, mounts,
  networking and state. Users own their image's software, accounts and updates.
- **Tools are runtime declarations and never install software.** A tool names a
  guest command, its default argv, credential providers, available tools,
  persist paths and env — nothing about how the image is built.
- **`setup` verifies exactly the declared tools, and treats every one as
  required on any image.** The scope is the resolved configuration catalog (the
  shipped defaults only when both tiers declare zero tools, otherwise the
  declared tools); an undeclared command is not checked at all. The synthesized
  `shell` fallback is a launch affordance, not a declaration, so it is not a
  verification target. There is no per-command or per-image severity downgrade:
  a declared command is fatal on the default boot image and on any image the
  user selected.
- **One image per session**, chosen independently of the launched tool, by the
  precedence:
  `--image` > `AGENT_VM_IMAGE_TAG` (empty = unset) > user config `image` >
  project config `image` > the default boot image. `run`, `image refresh`, `setup` and
  `doctor` all resolve through one function (`boot_image::select`).
- **Every OCI selection is host-approved (#390, amended).** Selection precedence
  is unchanged, but winning is not authorization. Each of the six tiers is keyed
  by its canonical OCI reference plus the measured host Linux platform, and a
  launch or `setup` consumes the approved host-platform **child** digest
  (`repo@child`), never the selected tag or index. The first pin is established
  only after successful acquisition and validation and **before** the SDK create;
  a changed pin requires candidate-scoped consent (escaped source, full old/new
  digests, default No) from `--yes` on either `image refresh` or
  `image set-default`, or from an interactive terminal on both ends of either
  verb. The approval store is host-wide in
  `$HOME/.config/agent-vm/image-pins.json`, independent of projects, the cache
  and `AGENT_VM_STATE_DIR`. A digest selection keeps its stated identity —
  mismatching content is an integrity failure, never an approvable replacement —
  while a multiarch index may resolve to its verified child. Equivalence for “no
  replacement needed” is native guest content (verified config digest plus
  ordered layer diff IDs), so an alternate digest algorithm does not disturb the
  stored approval. See [ADR-0047](0047-host-wide-oci-image-approval.md).
- **The default is a retained, user-scoped selection (#261, this ADR).** The
  bootstrap/digest fallback is a **retained default**: an immutable OCI
  reference (`repo@sha256:…`) in the user-scoped
  `$HOME/.config/agent-vm/default-image.json` (a sibling of `config.toml`, not a
  key in it, so the user *config* tier cannot displace the project tier). A
  launcher carries an **initial recommendation** (a compiled-in immutable
  reference) offered only when no record exists; `select` reads the record
  lazily and writes nothing, and the record is **adopted only after the image
  was successfully acquired** (success-before-adoption), write-once under an
  exclusive `flock` so concurrent first launches cannot overwrite each other. The
  first pin follows the same success-before-adoption rule for every tier:
  acquisition success, not boot success, establishes it. A
  failed initial acquisition therefore leaves no record, so a later compatible
  recommendation (e.g. a multiarch release) can rescue the host instead of
  stranding it. A retained record is never silently replaced; replacing a
  *working* one requires explicit `image set-default --image REF [--yes]` (#262): native target
  acquisition, canonical manifest pin acquisition, complete pinned-cache and
  host-Linux config validation precede replacement/initialization under the same
  lock and journaled transaction. Same-pin success preserves record bytes. Only
  future default sessions change; overrides, running sessions and previous cache
  remain intact. A
  missing/corrupt/unreadable record fails the verbs that need the default with a
  fixed reason and an escaped path; it is never auto-reset. The record is not a
  download cache: msb owns the bytes, so cache loss, `AGENT_VM_STATE_DIR` or a
  new project does not move the selection. It also stays digest-only: the source
  tag is not retained here (#392).
- **Config-file images are OCI references only.** A config `image` that the SDK
  would classify as a host path (`/`, `./`, `../`, `.`, `..`) is rejected, so a
  repo-supplied `.agent-vm/config.toml` cannot boot the host root filesystem as
  a writable guest rootfs. `--image`/`AGENT_VM_IMAGE_TAG` keep their existing
  permissive pass-through (a local rootfs or disk image is still bootable from
  the command line, where the user typed it).
- **No launch ever invokes Docker/buildx**, and an acquisition failure never
  falls back to a build. A registry acquisition failure for an explicit mutable
  tag prints an import hint; it is text, never an action (ADR-0043).
- **No legacy detection or shims.** The removed `--layer`, `--base-image` and
  the *old* build/global `--yes`/`-y`, the removed `layer` config field,
  `.agent-vm/layers/` discovery and the
  `AGENT_VM_BASE_IMAGE`/`AGENT_VM_LAYER`/`AGENT_VM_YES` variables are gone, not
  migrated and never restored. #390 adds a different, nested `--yes` on exactly
  `image refresh` and `image set-default`; it is consent to replace one resolved
  digest, not a launch/build/composition flag, and no launcher build prompt
  returns. The opt-in launch update check (`--update-check`,
  `AGENT_VM_UPDATE_CHECK`) and its banner/marker were removed outright under the
  same no-shim rule: before the tool verb an unknown option is a usage error
  (status 2), after it the token is forwarded to the tool.
- **Ordinary Docker `FROM`/multistage is the customization mechanism.** A user
  extends the default boot image with a Dockerfile, imports it, and selects it
  with `--image`/`image =`.

## Consequences

- Removed: `--layer`, `--base-image`, the old build/global `--yes`/`-y`, the
  `layer` field,
  `.agent-vm/layers/` discovery, the legacy `.agent-vm/layer` check,
  `AGENT_VM_BASE_IMAGE`/`AGENT_VM_LAYER`/`AGENT_VM_YES`, `DEFAULT_BASE_IMAGE_REF`,
  the launcher's `include_dir!` image embed, the composition machinery
  (`layer.rs`, `layer/contract.rs`, `tool_layer.rs`), and (from #390) the
  launch-time update check with `--update-check`, `AGENT_VM_UPDATE_CHECK`, its
  banner and its pulled-digest marker. Importing over a tag does not approve it;
  explicit import approval remains #391.
- **`setup` verifies declared tools only, and is fatal on any image.** The
  verification targets are exactly the tools the configuration declares (the
  synthesized `shell` fallback is not among them); a command the configuration
  does not name is never checked. Every declared
  target is required, on the default boot image and on any image the user
  selected, because the configuration says the command must work and `setup`
  never installs software. `--version` stays the gate, and a failure is
  classified as no entry found on the guest `PATH` (a bare command name) or at
  the configured path (a command that names one), present but not a runnable
  executable (a non-executable file or a directory), or present-and-executable
  but `--version` failed. A presence/executability-only
  mode may be offered later as an alternative to the version probe; it is not
  implemented. `--no-verify` skips the step. Launch still fails for a missing
  program.
- A project can recommend an image but cannot override the user's selection
  (the user tier outranks the project tier, exactly as it does for tool
  declarations, ADR-0015). It still cannot bind host paths through `image`.
- Retained from ADR-0034: independent image versioning and integrity
  verification principles. Withdrawn by this ADR: same-repository image sources,
  archive-only distribution, a shared launcher composer, and a launcher-fixed
  image selection; release and distribution work moves to
  [#263–#265](https://github.com/gregwebs/agent-vm/issues/263).
- The committed recipe/version pins and source-integrity gates are retained
  in the independent image repository, not in launcher Cargo tests,
  independent of the unimplemented Layer DAG.
- **#261 fulfilled.** The default boot image is a retained, user-scoped,
  digest-pinned selection with success-before-adoption; the compiled-in value is
  the v0.1.3 multiarch standard index as of #265, pinned alongside contributor
  sources at `087f8bad3de624a5dad38f1669e7dea96996371a`. Native acquisition
  chooses the host child, but first adoption preserves the index ref. Real
  installed registry/archive joins are manual, not CI container evidence.
  #265 remains incomplete until native joins exist on both architectures;
  launcher release is held pending amd64 evidence and maintainer image
  promotion or explicit risk acceptance. Merge is not image promotion.
- **#262 fulfilled.** Explicit replacement remains separate from write-once
  automatic adoption, and from #390 on it is a revision-checked
  compare-and-swap with candidate consent. See
  [USAGE](../../USAGE.md#explicitly-setting-the-default).
- **#390 fulfilled.** Every OCI tier is pinned host-wide; warm launches are
  registry-free; cache loss reacquires the approved digest; refresh/set-default
  are the only movement checks. The retained default stays digest-only (#392)
  and import/build cannot silently approve content (#391). Native behaviour and
  live-guest observations are manual evidence; boot-free checks cannot prove
  guest execution. See
  [USAGE](../../USAGE.md#host-wide-approval-of-oci-image-content).
- Follow-up evidence: [#265](https://github.com/gregwebs/agent-vm/issues/265)
  (native installed consumption on both architectures).

## Alternatives

- **Finish the Layer DAG** (ADR-0029–0033). Rejected: it keeps the image a
  consequence of the catalog, which is the defect, and none of it was built.
- **Keep `--base-image` as a development knob.** Rejected: it preserves a second
  image-selection system and a local-build path on every launch.
- **Let the project tier outrank the user tier for `image`.** Rejected: a cloned
  repository could then silently replace the user's chosen image, and the
  tool-config merge already makes the user tier authoritative.
- **Allow local paths in the config `image`.** Rejected as a sandbox escape: a
  repo-supplied `image = "/"` would boot the host root filesystem.
- **Keep image-provenance-based `setup` severity.** Rejected: provenance cannot
  tell a user what must work. The configuration declares the required commands,
  so the declared set — not which tier named the image — is the honest scope,
  and a declared command is fatal on every image.

## Accepted explicit build/import decision (#260)

`agent-vm image build` explicitly runs a user-owned Dockerfile with bounded native
buildx arguments, exports one anonymous host-Linux image with attestations off,
then imports the completed archive under one mutable result reference. Docker
owns semantics and caching; launch still consumes finished images only.
The ambient SDK backend supplies the cache, including persisted redirects.
Native materialization precedes sequential reference publication. The loader
also publishes archive-supplied names; on failure only the requested tag is
restored (amended by [ADR-0043](0043-image-command-group-and-daemon-import.md)).
No separate catalog persistence follows the native import. First launch normally
persists cached metadata into the catalog. Build never selects/adopts a default
or writes tool configuration. The obsolete standalone importer/base-link tag is
removed, without deleting existing user cache or Docker data.

OCI driver support and daemon-only parent visibility are native limitations,
not automatic parent transport/push/fallback mechanisms. Finished Docker-save/OCI
archives and Docker-daemon images are imported with
`agent-vm image import` (ADR-0043); `msb image load` remains a passthrough.
See [USAGE](../../USAGE.md#explicit-builds-and-archive-import) for the canonical
option surface and trust boundary. Docker, async ingestion and I/O are not
formally proved by the small result-reference acceptance kernel.
