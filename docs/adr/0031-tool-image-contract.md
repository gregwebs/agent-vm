# ADR-0031: The tool image contract and stitch checks

## Status

Accepted (decision). Not yet implemented — tracked by the map
[Map: tool image composition architecture](https://github.com/gregwebs/agent-vm/issues/203).
Replaces [ADR-0003](0003-project-tooling-layers.md)'s layer image contract
(C1–C8) for **tool images**. ADR-0003's table still governs project tooling
layers until Project tooling layers in the build DAG decides otherwise. Fills in
the clause wording that [ADR-0029](0029-compose-tool-images-by-layer-stitching.md)
deferred.

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

This table is the only normative copy of the contract. **T** clauses are checked
once per tool image, when it is built, against its parent. **S** clauses are
**stitch checks**, run across the tool images being stitched.

| # | Clause | Checked |
|---|---|---|
| **T1** | **Builds on its parent.** The Dockerfile's final `FROM` resolves `${BASE_IMAGE}` (text check before the build), and the parent's `rootfs.diff_ids` are a prefix of the built image's. The stitcher identifies a tool's own layers by cutting off that prefix, so T1 is what makes stitching valid. | tool build |
| **T2** | **Changes only `PATH` in the config.** `PATH` keeps every directory the parent has and may add new ones. Labels may be added (ADR-0030 requires `org.agent-vm.version.<name>`). Any other change is a violation: other `Env`, `User`, `WorkingDir`, `Entrypoint`, `Cmd`, and so on. "Ends as root" (C3) follows, because `User` stays the base's. | tool build |
| **T3** | **Never replaces or deletes a base path.** The tool's own layers contain no whiteout, opaque marker or non-directory entry for any path that exists in the base. This covers `/etc/agent-vm-image-version`, `/bin/bash`, `/etc/passwd`/`/etc/group` and the base's files under `/opt/agent` (formerly C5/C6). A tool with a declared parent may change its parent's files. | tool build |
| **T4** | **Targets the host platform.** C4a/C4b/C4c from ADR-0003, unchanged, applied to each tool image. | tool build |
| **T5** | **Its command runs for any uid.** The tool's `command` resolves on the tool image's own `PATH`, following symlinks. The resolved file must be executable by any uid, and every directory on the path to it must be enterable by any uid. | tool build |
| **T6** | **Advertises a capability only when it works** (C8). | documented |
| **T7** | **Installs everything else readable by any uid** (the rest of C7). | documented |
| **S1** | **No cross-tool file overlaps.** No non-directory path may be written by two tool images when neither is the other's parent. Paths under the guest's tmpfs mounts (`TMPFS_GUEST_PREFIXES`: `/tmp`, `/run`, `/dev/shm`, `/var/run`) are ignored, since no running guest can see them. There is no other allow-list. | stitch |
| **S2** | **No command shadowing.** Each tool's `command` resolves in the composed image to the same file it resolves to in its own tool image. | stitch |
| **S3** | **Derived config.** The composed config is the base's config plus the derived `PATH` and each tool's `org.agent-vm.*` labels. Other labels are dropped. | stitch (by construction) |

- **A violation is a hard error with no opt-out** (ADR-0003 D2/D6). The error
  names the tool, and for S1 both tools and the path.
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
  (parent vs. previous step), and project layers' own contract is still open.
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
  project layer.

## Consequences

- T3 is the file-level precondition that Rebasing tool layers onto an updated
  base relies on. It says nothing about whether a tool's binaries depend on base
  libraries.
- T5 may fail on shipped tools whose installers leave the command with a
  restrictive mode. Run the checks against the shipped set before turning them
  on.
- The stitcher gains a file-list reader and a symlink resolver over layer
  entries. Neither needs a container run.
