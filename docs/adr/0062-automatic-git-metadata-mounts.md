# ADR-0062: Automatic Git metadata mounts for a linked worktree

## Status

Accepted for [#535](https://github.com/gregwebs/agent-vm/issues/535), release `0.7.37`.
Builds on [ADR-0046](0046-verified-user-config-mounts.md) (mount authority) and
[ADR-0018](0018-machine-checked-boundary-contracts.md) (verified boundary contracts).
Leaves [ADR-0014](0014-narrow-fork-mounts-to-directories.md),
[ADR-0020](0020-protect-host-pi-credential-files.md) and
[ADR-0038](0038-config-dir-exposure-guard.md) unchanged: an automatic bind is an
ordinary live bind and every one of their checks applies to it.

## Context

A linked worktree (`git worktree add`) keeps its source in the new directory and its
Git metadata in the main checkout: `.git` in the worktree is a **pointer file**
naming `<main>/.git/worktrees/<id>`, and that directory's `commondir` file names
`<main>/.git`. A guest sees only what is bind-mounted, and the project bind carries
the worktree's source, so `.git` names a directory that does not exist in the guest.
`git log` in the guest answers `fatal: not a git repository`.

The user's workaround today is `--mount <main>/.git`, which has three problems: it
is manual, it is easy to spell as the main checkout (handing over someone else's
source), and nothing checks that the directory really is *this* worktree's
registration rather than any directory a `.git` file happens to name. A guest path
is a read-only bind at a path the guest can navigate, so accepting a pointer on
sight would turn a hand-written `.git` file into a bind of an arbitrary host
directory.

## Decision

### D1 — Scope: the launch directory's own root, and nothing else

Discovery reads exactly `<launch dir>/.git`. It does not walk ancestors, does not
look at a worktree subdirectory, and does not inspect extra mounts. A launch from
`<worktree>/sub` is an ordinary launch at `sub` and gets nothing — the same rule
that already gives a subdirectory its own project-state identity.

### D2 — A relationship is accepted only when Git would open it as this worktree

The pointer file is a claim. The claim is accepted only if all of the following
hold, each measured with `symlink_metadata`, a bounded no-follow read, `read_link`
or `canonicalize` — never by running a Git process (which would execute repository
config such as `core.fsmonitor`):

| Step | Fact | Refusal when it fails |
| --- | --- | --- |
| 1 | `.git` is a regular file (not a directory, symlink, fifo, or absent) | not linked — unchanged plan |
| 2 | it is a `gitdir: ` line, ≤ `PATH_MAX`+64 bytes, no control byte inside the path | `MalformedPointer` |
| 3 | the named directory exists and is a directory | `MissingGitDir` |
| 4 | it has a `commondir` file — or, when it does not, a linked-layout mark (a `gitdir` back-pointer, or a canonical parent named `worktrees` whose parent passes the common-directory contract) | `MissingCommonDirFile` when the mark is present, not linked when it is not |
| 5 | `commondir` is a one-line path and resolves (a `..` above `/` is **refused**, not clamped) | `MalformedCommonDir` |
| 6 | the common directory exists | `MissingCommonDir` |
| 7 | the common directory passes the contract below | `CommonNotAGitDirectory` |
| 8 | the per-worktree directory has a valid `HEAD` | `WorktreeNotAGitDirectory` |
| 9 | the per-worktree directory is `<common>/worktrees/<id>` | `NotRegistered` |
| 10 | its `gitdir` back-pointer names `<launch dir>/.git` | `BackPointerMismatch` |
| 11 | the guest resolves the same relationship the host does | `SymlinkedLayout` |
| 12 | the metadata directory contains no other checkout: not the launch directory, and none of the checkouts registered under its `worktrees/` | `ContainsCheckout` |

**The Git-directory validity contract.** Mirrors Git's own `is_git_directory`
acceptance plus two stricter storage rules. Per-work-tree: `HEAD` is a valid head
ref, and `commondir`/`gitdir` are regular files. Common: `objects/` and `refs/` are
directories, `HEAD` is a valid head ref, `config` is a regular file (presence only,
never interpreted), and no `.git` entry exists (a Git directory never contains one;
a checkout root does — which is what keeps the project bind's own directory out).
**Valid head ref** is Git's `validate_headref` over the first ≤255 bytes: a symlink
whose target text starts `refs/`, or bytes starting `ref:`, then Git's
`sane_ctype` space set, then `refs/`, or 40 leading hex digits (the SHA-1 width,
also the first 40 of a SHA-256 id). Reftable repositories pass. A bare repository
passes and is bound whole: it is all metadata. Discovery never decides bare vs
non-bare from `config`, which is attacker-writable text.

**Why stricter than Git.** A common directory that is a *checkout root* contains a
`.git` entry and is refused, so the project bind's own directory (or an ancestor of
it) can never be mounted. Requiring a valid common `HEAD` and a regular `config`
is stricter than Git, which tolerates their absence once a repository has been
opened; every repository `git init`/`git clone` creates satisfies both. A
hand-built directory that does not is refused, and that is deliberate: it is the
cheapest fact a forger would have to fabricate.

**Why step 12 is measured on host paths.** The `.git`-entry rule answers a
question about a *checkout root*, and a bare repository is not one: its directory
is all metadata, so it is bound whole. `git worktree add <bare>/other` is ordinary
Git, not a forgery, and the bind would then carry `other/`'s **source** — which no
metadata mount needs. So the containment is measured on the canonical host paths,
never on the guest spelling (a symlinked alias of the bare directory hides both),
and it reads the registrations Git wrote: each `<common>/worktrees/<id>/gitdir`
with a bounded no-follow read, compared canonically when it resolves and by its
spelling when the entry is stale. The residual is a checkout no registration
names.

**The same rule covers agent-vm's own binds.** D6's core-mount refusal is decided
from the *guest* spelling, and a spelling is exactly what a symlink can hide: with
`$HOME/core-alias -> $HOME/b`, a bare repository at `$HOME/b` whose only worktree
is outside it, and `AGENT_VM_STATE_DIR=$HOME/b/s`, nothing in the guest says the
automatic bind would enclose the launcher's own state. So the core volumes'
**host** sources are measured too, canonicalizing the deepest ancestor that exists
(these directories are created after discovery, and on macOS `$TMPDIR` is already
a symlink). The project source is deliberately left to step 12, which has the
refusal that names a checkout.

**Guest-spelling consistency (step 11).** The guest path is the *lexically
resolved* host spelling, and it is accepted only when its canonical path equals the
one Git resolves on the host. That is what makes a symlinked spelling (bind at
`/s/link/.git`, host `/r/main/.git`) expressible and a `..` that crosses a symlink
(`/a/l/wt/../..` → `/a`, while the host resolves `/r/main/.git`) a refusal.

**Linked-layout evidence (step 4).** Measured: `git submodule add` and
`git init --separate-git-dir` leave neither mark. Treating every missing
`commondir` as "not linked" would silently disable the feature for a worktree whose
`commondir` was deleted — the case `git worktree repair` exists for — so the two
marks distinguish "damaged linked worktree" (refuse) from "a different kind of
gitfile" (unchanged).

### D2b — What validation does not prove

- **Not that the user may read the target.** A directory forged to satisfy every
  one of Git's rules is accepted: a complete registration (both `HEAD`s, `objects/`,
  `refs/`, `config`, a back-pointer naming this launch directory) proves that Git
  would open it as this worktree's repository, nothing more. Such a forgery
  requires prior write access to the target directory. This is the accepted
  trade-off the spec records.
- **Not a stable tree.** Canonicalization is an observation, not a pin. A host able
  to repoint a spelling between discovery and binding can substitute another
  directory at a valid destination; [ADR-0038's stable-tree
  assumption](0038-config-dir-exposure-guard.md) covers this, and #322 re-opens
  explicit binds with root symlink following. `GitMetadataReport::verify_prepared`
  *narrows* the first window — `prepare` canonicalizes each live bind again, and a
  prepared volume whose canonical host differs from the one discovery validated is
  refused as a race — and claims nothing beyond that. A repoint after `prepare`, or
  at bind time, is the accepted residual.

### D3 — `ro` is automatic, distinct from ADR-0046's authority

`ro` adds no prompt, no approval store and no persisted setting. It is not verified
user config authority: it is a narrow, deterministic, read-only source that makes
Git's own history readable. The bind is read-only, which is exactly what a reader
needs and never what lets a guest change a repository.

### D4 — `rw` is per launch, with no environment variable and no config key

`--git-mount=rw` chooses write access for one launch. There is deliberately no
`AGENT_VM_*` variable and no config field: write access to a repository — including
the `hooks` and `config` that later run and are read on the host — must be chosen at
the command line, per launch. The `--no-config-mounts` precedent (`run.rs`) is the
model for reading the flag exactly once.

### D5 — Appended after argv, origin-attributed, existing claims and protections

`git_metadata::discover` runs after `mount_selection::select`, and its requests are
appended to the argv ones. `mount::claim` keeps the first-seen declaration at a
guest path, so an equivalent `--mount <metadata>:ro` or a `mounts` entry **merges**
into one bind and keeps its own origin in every diagnostic; a differing one is
refused naming both origins, with `--git-mount=off` as the remedy the automatic side
offers. Every protection (host Pi credential files, the writable config directory,
core collisions, declared `persist` links, the topology plan) runs unchanged,
because the new origin is diagnostics only: it never reaches `same_declaration`,
`fork_id` or a claim decision.

### D5b — An enclosing declaration governs; an automatic bind never shadows it

The automatic requests are appended *after* the user's (D5), and the runtime mounts
a parent before its child, so an automatic bind below a route the user declared
would silently outrank it: `--mount ~/repos` then leaves `~/repos/main/.git`
read-only, and `--git-mount=rw` under `--mount ~/repos:ro` makes part of a declared
read-only route writable. Neither is a conflict `claim` can see — the guest paths
differ — so discovery decides it, before `prepare`:

| The declaration, for a metadata guest path it encloses | Outcome |
| --- | --- |
| a plain live bind whose canonical source joined with the guest suffix is the canonical metadata directory | **merge**: no automatic request, in either mode; the declaration's access governs, and a notice says the metadata is reachable through it |
| anything else — a different host directory, `:fork`, `:follow-links` | **refuse** before boot, naming both origins and `--git-mount=off` |

A source that cannot be canonicalized is left to `prepare`, which canonicalizes it
too and refuses a missing one, so the launch fails either way and the pre-existing
error is the one the reader gets. Core binds are not consulted: the guest-HOME bind
enclosing `$HOME/…/.git` is the intended nesting, and a core collision is a
different refusal.

### D6 — Unmountable topologies are refused, not skipped

| Fact | Refusal |
| --- | --- |
| the project is remapped (`/workspace`) | relative pointers would resolve against the wrong base |
| the metadata path is under a guest tmpfs prefix | it would be wiped at boot |
| the metadata directory contains one of agent-vm's own mounts — by guest spelling **or** by canonical host source | it would cover, or enclose, a core bind |
| the metadata directory contains another checkout (D2 step 12) | it would carry that checkout's source |
| an enclosing explicit/config declaration does not map this path to the same host directory (D5b) | the automatic child would shadow part of that route |
| the metadata directory nests inside the project bind only through a symlink | the guest spelling and the host path would disagree inside one bind |
| the two directories nest in a way no pair of binds reproduces | the guest would look inside a bind for a directory that is elsewhere |

A metadata directory that is already **inside** the project bind is *skipped*
(not refused): it is already exposed by the writable project bind, and an `ro` bind
there would make part of the project read-only. Cost of the refusal rule: a Linux
worktree under `/tmp` now needs `--git-mount=off`.

### D7 — Automatic binds are not GitHub repository scans

`repo_scan_roots` excludes them. The worktree they belong to is already a scan root,
so scanning the metadata could only widen the allow-list towards a repository nobody
asked for; `--no-git` keeps its own scope. An equivalent explicit declaration keeps
its own origin and is still scanned.

## Accepted trade-offs

- `ro` is not repository-wide write protection and not confidentiality: the
  bind is read-only, the repository is not. Any other writable route still writes,
  and the guest can read shared history, refs and other worktrees' records. Recorded
  as native row `GM-N4`, never as an enforcement failure.
- `rw` exposes shared `hooks` and `config`, which run and are read on the host
  afterwards. That is what `rw` means, and D4 is why it is per launch.
- A forged, fully Git-valid registration is accepted and binds **read-only** (D2b);
  supplying it takes prior write access *inside* the target Git directory, so it
  grants nothing the forger did not already have, and the mode the user chose is
  still the mode of the bind. Pinned by `T18b` in
  `crates/agent-vm/tests/git_metadata_mounts.rs`: hardening `git_dir_contract` past
  this boundary fails a row, so it cannot become an undocumented change.
- A checkout inside the common directory that Git does not register is not
  detected (D2 step 12). The registered case is refused.
- The discovery-to-bind window is narrowed, not closed (D2b).

## Alternatives

- **Mount the main checkout** so `.git` resolves on its own. Rejected: the guest
  would get another checkout's *source*, which the spec puts out of scope and which
  no metadata mount needs.
- **Discover from ancestors or subdirectories.** Rejected: it would silently change
  what a launch from a random directory exposes, and it collides with the
  project-state identity rule (`session.rs`).
- **An environment variable or config key for `rw`.** Rejected (D4).
- **Rewrite `.git` in the guest** (or in the project bind) so it names a mounted
  path. Rejected: it mutates the user's repository, breaks the host's own Git, and
  makes the plan depend on a write.
- **Skip with a notice on an unmountable layout.** Rejected: a silent skip means the
  user's `git log` fails with no explanation of why the feature did not apply.
- **Run `git rev-parse` to validate.** Rejected: it executes repository config
  (`core.fsmonitor`, hooks) during discovery, before any of the protections that are
  supposed to guard a bind have run.
- **Accept on `objects/` + `refs/` alone.** Rejected: that accepts a forged
  non-repository, and it says nothing about *which* directory this is.
- **Treat every missing `commondir` as not-linked.** Rejected (D2, B5): it silently
  disables the feature for a damaged worktree.

## Verification

Boot-free real-CLI rows `T0`–`T20` in `crates/agent-vm/tests/git_metadata_mounts.rs`
(each drives the compiled binary against a real Git worktree and reads the
`SandboxConfig` it would have booted); kernel tables and oracles `U1`–`U6` plus
`automatic_bind_is_the_same_declaration_as_an_explicit_mount`,
`verify_prepared_refuses_a_changed_host`, `off_reads_nothing` in
`crates/agent-vm/src/git_metadata/tests.rs`; `mount.rs` pins
`git_metadata_claim_errors_are_pinned` and `git_metadata_binds_are_not_scan_roots`;
(`T2b`, `T6(c)`, `T12b`, `T12c`, `T14b` cover the checkout-containment, two-bind,
unmountable-layout, in-project and enclosing-declaration paths);
mutation controls `git-*` in `script/test/egress-mutations.py` (including
`git-checkout-in-common-bound{,-proof,-launch}`); native rows `GM-N1`–`GM-N4` in
the config-mounts live run — **passed** 2026-11-08 on macOS arm64 with the
candidate and image pinned in the spec's Testing Decisions; a missing prerequisite
is still recorded as BLOCKED when the image has no `git`, never as a pass — with
host-only controls and the row-logic self-check in
`script/test/config-mounts-contract.sh`. See
[`docs/specs/git-worktree-metadata-mounts.md`](../specs/git-worktree-metadata-mounts.md)
for the requirements and the row-to-requirement mapping.

`T12d` (D6's remap arm) and `T12e` (its tmpfs arm) are real-CLI rows, and the
platform hides both arms from the ordinary spelling, which is worth stating rather
than assuming: a *canonical* host path is never under a guest tmpfs prefix on macOS
(`/tmp` is a symlink to `/private/tmp`), and a control character in the launch
directory is refused by the pointer parser before any placement is measured. So
`T12e` spells the metadata through the `/tmp` symlink — the guest path the refusal
is actually about, and the byte-identical layout a Linux host writes — and `T12d`
takes the control-character remap with a back-pointer spelled through a symlink
that resolves to the same `.git`. Neither row patches the prefix list or a decision
table: each asserts the arm's own reason, `--git-mount=off` still launching, and no
launch state, and `T12e` also shows the same directory *binding* when its guest
spelling is the canonical one. `T18b` characterizes the accepted forgery boundary
described above.
