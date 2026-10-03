# ADR-0035: Consume user-owned boot images

## Status

Accepted. Implementation decision for [agent-vm #259](https://github.com/gregwebs/agent-vm/issues/259),
slice 2 of [agent-vm #257](https://github.com/gregwebs/agent-vm/issues/257).
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

**Proposed, pending maintainer confirmation:** the `setup` severity change for a
user-selected image (D6 below) is implemented, but the maintainer has not yet
confirmed the exit-status policy. It is recorded here as a proposal that the
implementation follows, not as an accepted decision.

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
- **One image per session**, chosen independently of the launched tool, by the
  precedence:
  `--image` > `AGENT_VM_IMAGE_TAG` (empty = unset) > user config `image` >
  project config `image` > the default boot image. `run`, `pull`, `setup` and
  `doctor` all resolve through one function (`boot_image::select`).
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
- **`setup` severity follows image ownership (proposed, pending maintainer
  confirmation).** A missing shipped command is fatal only when the verified
  image is the default boot image; for any user-selected image every missing
  command warns. The user owns the image, and `setup` never installs software.
  Launch still fails for a missing program.
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
- Follow-ups: [#260](https://github.com/gregwebs/agent-vm/issues/260) (explicit
  build/import CLI and the base-link import tag),
  [#261](https://github.com/gregwebs/agent-vm/issues/261) (retained/default
  selection), [#262](https://github.com/gregwebs/agent-vm/issues/262) (upgrade),
  #263–#265 (image repo, release, consumption).

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
- **Keep a marker-based "supplied tool" downgrade in `setup`.** Rejected: with
  no composition there is no layer to supply a command, so D6 keys severity on
  image ownership instead.
