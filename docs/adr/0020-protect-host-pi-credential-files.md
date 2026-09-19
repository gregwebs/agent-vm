# ADR-0020: Keep host Pi credential files out of every mount mode

## Status

Accepted. Implementation decision for [agent-vm #90](https://github.com/gregwebs/agent-vm/issues/90). Builds on Pi's mixed credential ownership — ADR pending in another workstream; see [#91](https://github.com/gregwebs/agent-vm/issues/91)/[#94](https://github.com/gregwebs/agent-vm/issues/94) — narrows what [ADR-0013](0013-add-forked-mounts.md) and [ADR-0014](0014-narrow-fork-mounts-to-directories.md) left possible, and adds a contract to the surface [ADR-0018](0018-machine-checked-boundary-contracts.md) governs. Blocks [agent-vm #96](https://github.com/gregwebs/agent-vm/issues/96) (`agent-vm pi`).

## Context

Pi supports many model providers, so its credential ownership is split (#91/#94): a credential **imported from the host** stays host-side and reaches the guest only as a request-scoped placeholder, while a credential **created inside** the guest stays guest-managed in project state (warned about on every launch). That split is defeated the moment a host file reaches the guest as a file — a mount that put the host's real `~/.pi/agent/auth.json` in front of the guest hands a hostile dependency or a prompt-injected agent a working credential, and no placeholder discipline applies.

`agent-vm` gives the guest three core binds (a per-project guest `$HOME`, the project, `<state> → /agent-vm-state`) plus whatever `--mount` asks for. Guest `$HOME` is *not* the host `$HOME`, but the **project** bind is the canonicalized cwd with no guard, so `cd ~ && agent-vm shell` writable-binds the host `$HOME`. Host Pi files therefore arrive by two routes: an explicit `--mount`, and the project bind itself.

Issue #90 was written against `VolumeRole::Mask` — "automatically mask either file whenever exposed by a mount". ADR-0014 had already **deleted** all of it: the alias-piercing analysis that proved no nested or symlink mount could reveal a masked path "was the largest and most fragile part of `mount.rs`", and `:exclude=REL` became fork-seed-only. So #90's mechanism no longer existed, and the plan had to choose a replacement.

Two forces decide the shape:

- **A live bind is a window, not a snapshot.** `pi auth login` run *on the host* during a session creates `auth.json` inside a bind that is already open. A mask cannot be placed over a path that does not exist yet: agentd would have to create the mountpoint, which inside a read-only bind it cannot do, and inside a writable one would write to the host.
- **A fork is a copy, made host-side under agent-vm's control.** It is a point-in-time decision with a descriptor already in hand, so it needs no overlay machinery at all — it can simply not copy the file.

## Decision

### The two protected files

`~/.pi/agent/auth.json` (provider credentials) and `~/.pi/agent/models.json` (provider/endpoint configuration). `ProtectedFile::home_relative` is the single place they are spelled; a future host-Pi resolver in #93/#94 imports that table rather than re-spelling them. The path table assumes no `PI_HOME`/XDG override; if a pinned Pi release introduces one, the resolver changes in this one place.

### Detection: identity **and** canonical containment

Per launch, `protected_host_files::measure` records the **physical route set** of each file: the ancestor chain of the path its `$HOME`-relative spelling resolves to, deepest first. Resolving as the walk descends is what makes `~/.pi -> /Volumes/ext/pi` protected at the target *and* at the target's parents, while correctly **not** recording `$HOME` — the guest resolves a `~/.pi` symlink in guest space, where it dangles. `ENOENT` stops the descent and leaves the literal remainder on the last existing ancestor, so a Pi home whose `auth.json` appears only later is still protected; any other error (`EACCES`, `ELOOP`, `ENOTDIR`) fails the launch closed with "cannot determine whether a mount would expose …".

A mount root is **exposing** iff the root's own `(dev, ino)` equals a route's, **or** the root's canonical path component-wise contains a route's. The two detectors are not symmetric in what they contribute:

- **Identity** folds aliases that paths cannot: `canonicalize` does not fold macOS firmlinks — measured: `stat -f '%d %i' /Users/$USER /System/Volumes/Data/Users/$USER` reports `16777236 150914274` for both — nor Linux host bind mounts, which were measured the same way in a Linux container: `mount --bind /a /b` then `stat -c '%d %i' /a /b` reports `42 21445` for both, so the alias is an identity hit. A symlink alias, a hardlink under another name, and (on Linux) a bind alias all hit it.
- **Canonical containment** is the ordinary case, and it is what keeps the common decision from depending on `(dev, ino)` semantics at all. Because `measure` records a route for *every* canonical ancestor up to `/`, a root that is a proper ancestor of a route is itself a route and matches by identity anyway; the case containment alone decides is a root whose canonical path **equals** a route's while the two `(dev, ino)` differ — a filesystem that synthesizes or churns inodes between the two stats. The comparison is component-wise (`/a/pistachio` is not inside `/a/pi`) and lives in `config::byte_path_contains` (`config.rs`), machine-checked per ADR-0018 and shared with the guest-path overlap predicate.

### Refuse a live bind; omit a fork's copy

| mount family | response |
|---|---|
| core project/state/home binds, `ro`, `rw`, `follow-links`, and every bind `follow-links` discovers | **refuse the launch**, fail closed |
| `fork`, `fork:follow-links` | **omit the file from the copy**, warn, copy the rest |

The refusal happens in `mount::prepare` — the single boundary allowed to inspect mount sources — **before** `prepare_forks`, the first state mutation, so a refused launch creates no fork store, lock, staging, or session state. A `follow-links`-discovered bind is an ordinary bind and is refused too, with the message naming the declaration it came from (when the attribution is unambiguous — two `:follow-links` declarations can discover the same bind).

`agent-vm`'s own binds are checked exactly like an explicit mount (`MountContext::core_host_sources`), because the project bind is the canonicalized cwd: a launch from `$HOME`, `~/.pi`, `~/.pi/agent`, or any ancestor of them is refused with the remedy named in the terms of the bind that actually is exposed (the cwd for the project bind, `AGENT_VM_STATE_DIR` for state, and the state directory again for the guest home). A bind elsewhere inside `~/.pi` — `~/.pi/extensions`, the writable project bind a `cd ~/.pi/extensions` launch creates — exposes no protected file, so it is allowed and **warned** about: it is a live window onto host Pi state that `:fork` cannot be recommended for, and the extensions/packages under it may be platform-specific.

**The refusal's remedy is conditional on the root**, because `:fork` is not always a remedy at all:

- root is a regular file (the credential itself, or a hardlink to it) → there is no remedy to name; a `:fork` source must be a directory.
- root is at or inside the Pi home (including, when `~/.pi` is a symlink, its canonical target) → `:fork` is exactly right: it copies the rest and omits these two files.
- root is an ancestor **above** the Pi home (`$HOME`, `/`) or on an unrelated branch → the message leads with *mount a narrower path* and says plainly that forking that root would copy everything under it into project state, which is a worse exposure than the live bind being refused.

The fork copier omits a node by **three signals** before creating anything at its destination — no empty file, no placeholder: the node's `fstat` identity (catching the file, a hardlink to it under any name, and a `:fork:follow-links` materialized target); its fork-root-relative path from the **measured routes** (catching a protected file the route set placed under the root); and its fork-root-relative path from the **static path table**, which needs no measurement at all. The containing directory survives.

The omitting snapshot is taken **under the per-fork lock** and **unioned with the launch's first measurement**, never a replacement: a fork root renamed away and recreated, or an atomic `auth.json` replacement that leaves a hardlink holding the old bytes, would otherwise make the copier forget an inode or a route the launch had positively identified. The fresh half still matters — it is what sees a fork root or credential created since that first measurement (`--mount ~/.pi:fork` with `~/.pi` created in between).

The lock, however, only coordinates fork **initializers**. It is not synchronization with host Pi writers, so a host process can rename the fork root away between the top-of-`prepare` measurement and the copier's re-measurement and recreate it — with a credential — before the copy. In that ordering the measured routes contain no entry for the root (their last existing ancestor was `$HOME`), so the *root-relative* route list alone is empty. The **static path table** is what closes it: it positions the two protected files under the configured/normalized root from the path spelling alone, so `agent/auth.json` and `agent/models.json` are still omitted. It supplements, and does not replace, the measured signals: a **symlinked credential target**, a hardlink under another name, or a mount alias is named by no path table entry, so a host writer who recreates such an alias between the copier's re-measurement and the copy remains a residual gap (the same class of unbounded-walk gap named in *Accepted gaps*); and the copy itself is still a window the launcher cannot hold open against a host writer.

### Severity depends on whether `~/.pi` exists

`$HOME/.pi` **exists** → exposure is a hard error, whatever the files' own existence. `$HOME/.pi` **absent** → the same route is an advisory naming the residual risk, because otherwise every user who mounts `$HOME` or `/` — including users who never installed Pi — would get a hard error about Pi credentials.

### `$HOME` unset

`$HOME` unset does **not** mean the home is unknown — only that this process was not told. `run.rs` resolves the launch's home as `$HOME` when it is set and non-empty, otherwise the account record's `pw_dir` (`getpwuid_r(geteuid())`, the same lookup `user.rs` already uses for the guest username). A daemon, CI, `env -i`, or `--root` launch therefore still locates the Pi home and gets the same core-bind protection as any other. `ProtectedHostFiles::require_home` refuses a launch that declares a `--mount` only when **both** sources fail (no passwd entry for the uid, or an empty `pw_dir`): then there is no home to reason from and the launch cannot be decided.

### `IDENTITY_VERSION` v3, and the orphan it leaves

A fork seeded by a pre-#90 build may already contain a copied `auth.json`, and a **READY fork is reused without reading its source**, so no source-side check could catch it. `agent-vm-fork-identity-v2` → `…-v3` makes every reusable fork one that was seeded *under* protection: a structural invariant instead of a runtime scan. The cost is that every existing fork re-copies once; when the v2 directory exists it is **printed** at launch ("A fork from an earlier agent-vm build is no longer used: … It may contain a copy of a host credential file — remove it"), never deleted. Forks had never shipped in a release (last tag `v0.1.26`; `#100` and `#115` both post-date it), so this was the free moment to move. `MANIFEST_VERSION` stays 2 — the format is unchanged and ADR-0014's `kind: "file"` fail-closed message is retained.

### Trusted boundary

Verified code calls into, and trusts: all syscalls (`fs::metadata`, `fs::symlink_metadata`, `canonicalize`, the `st_dev`/`st_ino` measurement), `std::fs::canonicalize`'s resolution semantics, `Path::strip_prefix`'s component-wise prefix test for the static fork-omission signal, the route ↔ index mapping, and the invariant that `measure` emits a route's ancestors deepest-first. `Path` → bytes is the trusted adapter; both paths are canonical (absolute, no trailing `/`, no `.`/`..`). The static signal's root is the fork root's canonical path when it exists, or its own absolute spelling when it does not.

### What the two contracts do **not** prove

- `exposing_index` proves that the identity decision **is** the first-match comparison — no false negative and the index is the first (most specific) match. It does not prove that a mount root's `(dev, ino)` means what the caller believes.
- `byte_path_contains` (in `config.rs`, shared with the guest-path overlap predicate) proves that containment **is** "equal or a component-wise separator-prefixed ancestor". It does not prove that a canonical path is the path the guest will resolve. Its strict-prefix half is a generality the current route set does not exercise: because `measure` records every canonical ancestor, a root that strictly contains a route is itself a route and already matches by identity, so only the equality half can decide a verdict today.
- Neither proves the *policy* (refuse vs. omit, severity, which files) — that is ordinary code, guarded by tests and the reasoning above.

## Consequences

- **The `--mount` contract and the cwd contract are deliberately breaking** for a user with a host Pi home: `--mount $HOME:ro` (or any ancestor, or `/`) stops working, and agent-vm cannot be launched *from* `$HOME`. The error names the remedy the root actually admits — a narrower path for a broad root, a different cwd or `AGENT_VM_STATE_DIR` for one of agent-vm's own binds, and `:fork` only where a fork would help. Users without a host Pi home are unaffected except for one advisory line.
- **Acceptance criterion 4 of #90 is knowingly unmet for `ro`/`rw`.** #90 asked for the non-sensitive Pi files to keep the requested mount mode while the sensitive two were masked. An exposing `ro`/`rw` mount is refused, so its non-sensitive siblings are not mounted at all. This is the deviation's real cost; `:fork` does meet it literally.
- **Accepted gaps**, each named rather than implied: a filesystem with unreliable `(dev, ino)` where the alias is also not a canonical containment — two NFS/SMB mounts of one export report the same `ino` with different `st_dev`, and they are at unrelated paths, so containment cannot help either; a hardlink to a protected file inside an otherwise-unrelated *live* bind (`~/backup/x.json`) needs an unbounded walk of every bind root — the fork copier's per-node `fstat` does catch it; a host writer who recreates a *symlinked* credential target, a hardlink alias, or a mount alias between the fork copier's under-lock re-measurement and the copy — the static path table names only the two `$HOME`/Pi-home spellings, so those alias forms still depend on the measured identity/route signals; a copy the user made themselves (`cp ~/.pi/agent/auth.json ~/project/`); the `Severity::Advise` window in which Pi is installed *and* logged into during a live session; a launch whose `$HOME` is unset *and* whose account record cannot be read: it declares no `--mount` and gets no core-bind protection at all, because there is no home to measure from; and `inside_pi_home` being path-based, so an aliased Pi-home spelling outside those two names can miss a *warning* — never a refusal.
- **Guest-side Pi credentials in project state remain #93's job.** This decision is about host files reaching the guest, not about what the guest writes.
- A v2 fork whose source is gone errors on the reseed (source missing); the orphan path printed at launch is what the user removes.

## Alternatives

- **Re-introduce a narrow `VolumeRole::Mask` limited to these two files.** Rejected. It reverses ADR-0014 days after it landed and keeps the alias-piercing machinery for a *weaker* guarantee, because it cannot cover the file that does not exist at boot (reason 1 in *Context*), and it needs new runtime behaviour: mask-file materialization, staging, and a nested-overmount ordering dependency on the pinned microsandbox baseline.
- **Mask when the ancestor exists, refuse otherwise.** Rejected: its failure mode is perverse — `--mount ~:ro` would work for users *with* Pi installed and fail for users *without* it — for all of the machinery and none of the guarantee.
- **Enumerate and bind the Pi home's siblings individually.** Rejected: unbounded volume count, and non-atomic against a concurrent change.
- **A `protection` field in the fork manifest.** Rejected: same user-visible effect as the identity bump, plus permanent compatibility logic in `validate_ready`.
- **Scan committed fork data for a stale protected copy on every launch.** Rejected: a copy's bytes cannot be matched by identity, and the scan would be permanent.
- **For a READY fork, canonicalize the source and `stat(<data>/<remainder>)` instead of bumping the identity.** Weaker: one syscall per fork per launch, but blind to a copied *hardlink* under another name and to a moved/renamed source. The identity bump is structural and available now.
- **Refuse a `:fork` of a Pi home instead of omitting the files.** Rejected: it would break the recommended remedy named in the live-bind refusal, and a copy can be made safe without giving up everything else the user asked for.

## References

- Pi's mixed credential ownership — the host/guest split this protects — is an ADR in another workstream; see [#91](https://github.com/gregwebs/agent-vm/issues/91) and [#94](https://github.com/gregwebs/agent-vm/issues/94).
- [ADR-0013](0013-add-forked-mounts.md), [ADR-0014](0014-narrow-fork-mounts-to-directories.md) — fork identity, store, locking, publication, and the removal of opaque masks.
- [ADR-0018](0018-machine-checked-boundary-contracts.md) — the `verus!` contract rule, the verified surface, and the trusted-boundary convention.
- `crates/agent-vm/src/protected_host_files.rs`, `crates/agent-vm/tests/mount_protected_pi.rs`.
