# ADR-0035: Consume user-owned boot images

## Status

Accepted. Implementation decision for [agent-vm #259](https://github.com/gregwebs/agent-vm/issues/259),
slice 2 of [agent-vm #257](https://github.com/gregwebs/agent-vm/issues/257);
the retained-default decision below is [agent-vm
#261](https://github.com/gregwebs/agent-vm/issues/261), slice 4 (amended, see
*Decision*). Explicit replacement is implemented by [#262](https://github.com/gregwebs/agent-vm/issues/262).
Supersedes [ADR-0003](0003-project-tooling-layers.md),
[ADR-0019](0019-tool-free-base-and-per-tool-layers.md),
[ADR-0028](0028-explicit-image-flag-beats-the-other-environment-variable.md),
[ADR-0029](0029-compose-tool-images-by-layer-stitching.md),
[ADR-0030](0030-tool-versions-in-identity-and-current-tags.md),
[ADR-0031](0031-tool-image-contract.md),
[ADR-0032](0032-one-layer-kind.md) and
[ADR-0033](0033-default-rebase-with-build-provenance.md). Amends
[ADR-0034](0034-versioned-image-releases.md),
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
source-integrity gates in `images/` and `.github/workflows/`. Those stay.

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
  project config `image` > the default boot image. `run`, `pull`, `setup` and
  `doctor` all resolve through one function (`boot_image::select`).
- **The default is a retained, user-scoped selection (#261, this ADR).** The
  bootstrap/digest fallback is a **retained default**: an immutable OCI
  reference (`repo@sha256:…`) in the user-scoped
  `$HOME/.config/agent-vm/default-image.json` (a sibling of `config.toml`, not a
  key in it, so the user *config* tier cannot displace the project tier). A
  launcher carries an **initial recommendation** (a compiled-in immutable
  reference) offered only when no record exists; `select` reads the record
  lazily and writes nothing, and the record is **adopted only after the image
  was successfully acquired** (success-before-adoption), write-once under an
  exclusive `flock` so concurrent first launches cannot overwrite each other. A
  failed initial acquisition therefore leaves no record, so a later compatible
  recommendation (e.g. a multiarch release) can rescue the host instead of
  stranding it. A retained record is never silently replaced; replacing a
  *working* one requires explicit `upgrade --image REF` (#262): native target
  acquisition, canonical manifest pin acquisition, complete pinned-cache and
  host-Linux config validation precede replacement/initialization under the same
  lock and record. Same-pin success preserves record bytes. Only future default
  sessions change; overrides, running sessions and previous cache remain intact. A
  missing/corrupt/unreadable record fails the verbs that need the default with a
  fixed reason and an escaped path; it is never auto-reset. The record is not a
  download cache: msb owns the bytes, so cache loss, `AGENT_VM_STATE_DIR` or a
  new project does not move the selection.
- **Config-file images are OCI references only.** A config `image` that the SDK
  would classify as a host path (`/`, `./`, `../`, `.`, `..`) is rejected, so a
  repo-supplied `.agent-vm/config.toml` cannot boot the host root filesystem as
  a writable guest rootfs. `--image`/`AGENT_VM_IMAGE_TAG` keep their existing
  permissive pass-through (a local rootfs or disk image is still bootable from
  the command line, where the user typed it).
- **No launch ever invokes Docker/buildx**, and an acquisition failure never
  falls back to a build.
- **No legacy detection or shims.** The removed `--layer`, `--base-image` and
  `--yes` flags, the removed `layer` config field, `.agent-vm/layers/` discovery
  and the `AGENT_VM_BASE_IMAGE`/`AGENT_VM_LAYER`/`AGENT_VM_YES` variables are
  gone, not migrated.
- **Ordinary Docker `FROM`/multistage is the customization mechanism.** A user
  extends the default boot image with a Dockerfile, imports it, and selects it
  with `--image`/`image =`.

## Consequences

- Removed: `--layer`, `--base-image`, `--yes`/`-y`, the `layer` field,
  `.agent-vm/layers/` discovery, the legacy `.agent-vm/layer` check,
  `AGENT_VM_BASE_IMAGE`/`AGENT_VM_LAYER`/`AGENT_VM_YES`, `DEFAULT_BASE_IMAGE_REF`,
  the launcher's `include_dir!` image embed, and the composition machinery
  (`layer.rs`, `layer/contract.rs`, `tool_layer.rs`).
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
  (now exercised by `crates/agent-vm/tests/image_sources.rs` and the
  `script/` gates), independent of the unimplemented Layer DAG.
- **#261 fulfilled.** The default boot image is a retained, user-scoped,
  digest-pinned selection with success-before-adoption; the compiled-in value is
  only an interim initial recommendation, and
  [#265](https://github.com/gregwebs/agent-vm/issues/265) owns pinning and
  validating the production multiarch recommendation against real artifact
  consumption. The interim value is Linux/amd64-only, which is safe precisely
  because a failed acquisition retains nothing.
- **#262 fulfilled.** Explicit replacement remains separate from write-once
  automatic adoption. See [USAGE](../../USAGE.md#explicitly-upgrading-the-default).
- Follow-ups: [#265](https://github.com/gregwebs/agent-vm/issues/265) (production
  recommendation), #263–#264 (image repo, release).

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

`agent-vm build` explicitly runs a user-owned Dockerfile with bounded native
buildx arguments, exports one anonymous host-Linux image with attestations off,
then imports the completed archive under one mutable result reference. Docker
owns semantics and caching; launch still consumes finished images only.
The ambient SDK backend supplies the cache, including persisted redirects.
Native materialization precedes atomic reference publication; no fallible
catalog persistence or validation follows that commit. First launch normally
persists cached metadata into the catalog. Build never selects/adopts a default
or writes tool configuration. The obsolete standalone importer/base-link tag is
removed, without deleting existing user cache or Docker data.

OCI driver support and daemon-only parent visibility are native limitations,
not automatic parent transport/push/fallback mechanisms. Finished Docker-save
and OCI archives retain the existing `msb image load --input` workflow.
See [USAGE](../../USAGE.md#explicit-builds-and-archive-import) for the canonical
option surface and trust boundary. Docker, async ingestion and I/O are not
formally proved by the small result-reference acceptance kernel.
