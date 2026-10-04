# ADR-0031: The tool image contract and stitch checks

## Status

**Superseded by [ADR-0035](0035-consume-user-owned-boot-images.md) (#257). The launcher DAG/current-tag/version-identity system was not implemented; committed recipe/version pins and source integrity checks are implemented and retained.**

Accepted (decision). Not yet implemented — tracked by the map
[Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).
Replaces [ADR-0003](0003-project-tooling-layers.md)'s layer image contract
(C1–C8) for **tool images**. ADR-0003's table was retired outright by
[ADR-0032](0032-one-layer-kind.md), which makes layers and tools one kind: the
table below governs **every** layer image, widened by that ADR — T2 admits
non-`PATH` environment variables merged in stitch order, T3 keeps its strictness but exempts
the launcher's generated append-only account layer, and a new **S4** forbids
sibling env collisions. Fills in the clause wording that
[ADR-0029](0029-compose-tool-images-by-layer-stitching.md) deferred.

[ADR-0033](0033-default-rebase-with-build-provenance.md) adds the rebase case:
original T1 checks establish artifact build provenance, but fresh structural
checks against the destination base are required for a newly rebased
composition. The cache-hit exemption below does not waive these checks.

## Context

C1 ("builds on its predecessor") and C2 ("keeps `PATH` additive") assume a chain
where each step builds on the one before it. Under stitching, each tool image
builds on its **parent**, and the composed tool image is written by the stitcher
rather than built, so those two clauses no longer describe anything real. Two
facts change what is worth enforcing:

- The stitcher already reads each tool image's layer file list (path, type,
  mode, link target) to detect overlaps. ADR-0003 kept C5–C7 documented-only
  because checking them meant decompressing layers. That cost is now paid anyway.
- Stitching creates a failure mode a chain doesn't have. Two tools that each
  write the same file (for example, both appending an account to `/etc/passwd`)
  silently lose one tool's version, because the later tool's copy wins.

## Decision

Config scope and transitive overrides were clarified by
[Config merge fields and ancestor overrides](https://github.com/gregwebs/agent-vm/issues/217).
The T2/S3/S4 wording below incorporates ADR-0032's amendments; its earlier
“every other config key” wording is narrowed to environment variables.

This table is the only normative copy of the contract. **T** clauses are checked
once per tool image, when it is built, against its parent. **S** clauses are
**stitch checks**, run across the tool images being stitched.

For S3/S4, a layer's own Env/label changes are entries added or changed relative
to its actual build parent's config, not its complete inherited config. Use this
same attribution for merging and collision checks; unchanged inherited entries
neither overwrite a composed value nor count as declarations. Retain these
parent-relative changes with artifact provenance for rebase; do not recompute
them against the destination root. An explicit assignment equal to the parent's
value is indistinguishable from inheritance and contributes no change.

For example, with root `X=0`, A setting `X=1`, and unrelated B merely inheriting
`X=0`, stitching retains `X=1` without an S4 collision. The same principle
prevents inherited labels from undoing another layer's label changes.

| # | Clause | Checked |
|---|---|---|
| **T1** | **Builds on its parent.** The Dockerfile's final `FROM` resolves `${BASE_IMAGE}` (text check before the build), and the parent's `rootfs.diff_ids` are a prefix of the built image's. The stitcher identifies a tool's own layers by cutting off that prefix, so T1 is what makes stitching valid. | tool build |
| **T2** | **Changes only environment variables and adds labels.** `PATH` keeps every directory the parent has and may add new ones. Other `Env` variables may be added or overridden. Labels may be added (ADR-0030 requires `org.agent-vm.version.<name>`). All other config fields, including `User`, `WorkingDir`, `Entrypoint` and `Cmd`, must remain unchanged from the parent. "Ends as root" (C3) follows, because `User` stays the base's. Launcher-owned env declarations remain forbidden under ADR-0032. | layer build |
| **T3** | **Never replaces or deletes a base path.** The tool's own layers contain no whiteout, opaque marker or non-directory entry for any path that exists in the base. This covers `/etc/agent-vm-image-version`, `/bin/bash`, `/etc/passwd`/`/etc/group` and the base's files under `/opt/agent` (formerly C5/C6). A layer may change files introduced by any declared ancestor, including transitive ancestors, but never files from the base or generated union account layer. Only that launcher-generated append-only account layer may write protected account files. | tool build |
| **T4** | **Targets the host platform.** C4a/C4b/C4c from ADR-0003, unchanged, applied to each tool image. | tool build |
| **T5** | **Its command runs for any uid.** The tool's `command` resolves on the tool image's own `PATH`, following symlinks. The resolved file must be executable by any uid, and every directory on the path to it must be enterable by any uid. | tool build |
| **T6** | **Advertises a capability only when it works** (C8). | documented |
| **T7** | **Installs everything else readable by any uid** (the rest of C7). | documented |
| **S1** | **No cross-tool file overlaps.** No non-directory path may be written by two tool images when neither is the other's ancestor (direct or transitive). Paths under the guest's tmpfs mounts (`TMPFS_GUEST_PREFIXES`: `/tmp`, `/run`, `/dev/shm`, `/var/run`) are ignored, since no running guest can see them. There is no other allow-list. | stitch |
| **S2** | **No command shadowing.** Each tool's `command` resolves in the composed image to the same file it resolves to in its own tool image. | stitch |
| **S3** | **Derived config.** Start with the composition root's config. Derive `PATH` as an additive union in stitch order; merge only each layer's own changes to other environment variables in that order, last wins subject to S4. Preserve base labels and merge only layers' own changes to `org.agent-vm.*` labels in stitch order, last wins; discard other layer labels. All non-Env, non-label config fields remain the root's. | stitch (by construction) |
| **S4** | **No unrelated-layer env collisions.** Two layers with neither a direct nor transitive ancestor relationship may not contribute own changes with different values for the same environment variable. Identical values are allowed, `PATH` is exempt, and descendants may override ancestors. Labels and other config fields are not S4's key domain. | stitch |

_Amended by #258 (2026-10)._ The base no longer writes
`/etc/agent-vm-image-version` and the launcher never reads it, so that path is
no longer among the examples T3 protects; T3's rule itself (and every other
clause here) is unchanged. Compatibility is the
[boot image contract](../../USAGE.md#boot-image-contract).

- **A violation is a hard error with no opt-out** (ADR-0003 D2/D6). The error
  names the layer, and for S1/S4 both layers and the path/environment key.
- **A failing tool image is never recorded.** It is not written into the OCI
  layout's `index.json` and gets no current tag, which replaces ADR-0003 D7's
  discard step. Tool images that already passed stay cached.
- **A cache hit checks nothing.** A tool image's checks run once, when that
  identity is built. Its file list is kept beside it in the layout, so stitch
  checks on a new tool set don't re-read unchanged layers. A cached composed
  image skips the stitch checks.
- **No grandfathering.** ADR-0030's `SCHEME_TAG` v2 starts tool images from an
  empty cache.

## Considered Options

- **Amend ADR-0003's table** with an "applies to" column. Rejected: the two
  contracts are checked at different moments, against different predecessors
  (parent vs. previous step), and project layers' own contract was still open.
  ADR-0032 removed the second kind, so there is now one table and this option is
  moot.
- **Enforce C7 on every file.** Rejected: it would reject stray private files
  that nothing reads. T5 enforces the one case every user hits: the tool's own
  command. Every other build-time check, including ADR-0030's version check,
  runs as root and can't see that failure.
- **Treat overlaps as warnings, or let catalog order win.** Rejected: either
  silently drops a file from one tool.
- **Forbid `/tmp` content in tool images.** Rejected: all 554 overlaps the
  stitching prototype found are Node's `/tmp/node-compile-cache`, which the guest
  never sees. Forbidding it would make every npm-based installer add a tmpfs
  mount and gain nothing at runtime.
- **Let tool layers append accounts** (C6's allowance). Rejected: under
  stitching, two appenders lose one account. Accounts belong in the base or in a
  project layer. (ADR-0032 removed the "project layer" escape hatch by making
them one kind, and replaced the allowance with **declared accounts** — a
  generated, append-only account layer carrying the union below every layer, so
  there is exactly one appender.)

## Consequences

- T3 is the file-level precondition that Rebasing tool layers onto an updated
  base relies on. It says nothing about whether a tool's binaries depend on base
  libraries.
- T5 may fail on shipped tools whose installers leave the command with a
  restrictive mode. Run the checks against the shipped set before turning them
  on.
- The stitcher gains a file-list reader and a symlink resolver over layer
  entries. Neither needs a container run.
