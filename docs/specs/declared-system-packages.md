# Declared system packages: implementation handoff

Status: handoff ready for `/breakdown` — **except** the three open questions in
[Open questions](#open-questions), which must be resolved before the affected
requirements can be built. Not implemented. Source:
[ADR-0035](../adr/0035-declared-system-packages.md). Ticket:
[#255](https://github.com/gregwebs/agent-vm/issues/255).

This consolidates ADR-0035's requirements and acceptance criteria. Decisions and
rationale remain canonical in the ADR; this document does not reopen them.

## Destination and authority

Stop layers from running package managers. A layer **declares** the system
packages it needs; the launcher resolves the union once, in one generated
foundation layer, against an immutable archive snapshot, so that a composition's
foundation is deterministic, the base is never overwritten by a tool layer, and
unrelated layers stop colliding over shared toolchain files.

The change exists because [ADR-0031](../adr/0031-tool-image-contract.md)'s
**T3** forbids a layer from writing any path that exists in the base, and
`apt-get install` cannot comply. Measured, the shipped six tools are clean
precisely because none of them runs `apt`, while every apt-based example violates
T3 — with ~305 of those findings per development recipe being genuine base-binary
replacement, not bookkeeping.

| Source | Governs |
| --- | --- |
| [ADR-0035](../adr/0035-declared-system-packages.md) | Declared packages, the union package layer, snapshot pinning, the T3 ownership rule |
| [ADR-0031](../adr/0031-tool-image-contract.md) | Contract T1–T7 and stitch checks S1–S4; **T3 is amended by ADR-0035** |
| [ADR-0032](../adr/0032-one-layer-kind.md) | One layer kind, derived order, declared accounts, the union account layer |
| [ADR-0033](../adr/0033-default-rebase-with-build-provenance.md) | Default rebase, build provenance, destination checks |
| [ADR-0034](../adr/0034-versioned-image-releases.md) | Release assets, pinned image version, image-API migration |
| [CP0 evidence record](../research/image-composition-cp0-evidence.md) | The measurements above, and the soundness audit of the checker that produced them |

Use [CONTEXT.md](../../CONTEXT.md)'s vocabulary. A **Layer** is a tool or a
building block; the **root** is base plus generated foundation layers. In
particular: a layer has **no** package-installation step, `packages` is
declaration data like `users`/`groups`, and T3's exemption is by **ownership**
(which layer wrote it), not by path.

## Readiness

Settled: declaration is data on the entry; one generated union package layer
below every participating layer, ordered before the union account layer; apt
sources pinned to an immutable snapshot date which is the reproducibility lock;
`Check-Valid-Until` disabled for snapshot sources; tool layers never resolve; T3's
exemption is an ownership rule; the index is not retained in the image.

Measured before deciding (see the CP0 record): apt-in-layer violation counts per
recipe; the forced `libc6` upgrade mechanism; that the live pool 404s superseded
`.deb`s while an immutable snapshot serves them; that snapshot pinning requires
disabling `Valid-Until`; and a reproduction showing a layer installs from an
inherited index without refreshing and without forcing an upgrade.

## Observable paths

```text
entries declare packages ──┐
                           ├─► deterministic union ──► union package identity ──┐
snapshot date (base recipe)┘                                                    │
                              base digest ──────────────────────────────────────┤
                                                                    root identity
                                                                                │
                                            ┌───────────────────────────────────┘
                                            ▼
                     generated union package layer   ← the ONLY apt invocation
                     (snapshot-pinned sources)         (update + install + discard index)
                                            │
                     generated union account layer   ← ordered AFTER packages
                                            │
                     tool layers, each building on the foundation
                     (own files only; no package-manager writes)
                                            │
                                     stitch → archive → ingest → boot
```

Contrast with today: each apt-based layer runs its own `apt-get update` against
the live archive and installs for itself, which (a) writes base paths, (b) is
forced to upgrade base libraries, and (c) makes unrelated layers collide over the
same toolchain files.

## Requirements

### Declaration

**R1.** An entry declares its system packages as data (`packages`). A layer must
not run a package manager in its build recipe. This is the package analogue of
`users`/`groups` under ADR-0032.

**R2.** Declarations are normalized deterministically before use (name ordering,
whitespace, and any version qualification), so that two spellings of the same
intent produce the same identity.

**R3.** Declarations are available for both catalog entries and local/injected
layer sources. A local layer declares through metadata in its own layer
directory; it must not need a catalog entry to declare packages.

**R4.** A layer that runs a package manager in its build is rejected — its
artifact is not recorded as validated. Whether this is detected pre-build,
post-build, or by T3's ownership rule is an implementation choice; the outcome is
not.

### Union

**R5.** The foundation installs the **deterministic set-union** of the declared
packages of all participating layers in the composition.

**R6.** Repeated declarations of the same package by different layers are **not**
conflicts. This is the point of the union.

**R7.** Explicit version qualifications that **disagree** across layers are a
plan-time error naming both declaring layers. This is the package analogue of
ADR-0032's account identity-collision rejection.

**R8.** The union is computed **before any build**, and contributes to root
identity.

### The generated union package layer

**R9.** The launcher generates **exactly one** union package layer per
composition, placed **below every participating layer**.

**R10.** It is ordered **before** the union account layer, so package
postinst-created users exist before declared accounts are reconciled against
them.

**R11.** The generated layer performs the **only** package-manager invocation in
the composition: a single `apt-get update` followed by a single install of the
union. It then discards the index.

**R12.** It is the **sole writer** of package-manager state. Under ADR-0035's
amended T3, its writes to package-manager paths and to package-owned base files
are permitted because the launcher owns it. A tool layer performing an equivalent
write is a **hard error with no opt-out**.

### Snapshot pinning

**R13.** The build sources point at an **immutable snapshot date** rather than a
live archive. The date is recorded in the base recipe and participates in
identity.

**R14.** `Check-Valid-Until` is disabled for snapshot sources. Snapshot serves the
original Release file, whose validity window has necessarily passed; without this
the build fails hard.

**R15.** Changing resolved versions requires **bumping the snapshot date** and
nothing else. Layer recipes must not be able to influence resolution.

**R16.** A snapshot bump produces a **new** composition identity. It must never
silently mutate an existing retained composition.

**R17.** Sources with no snapshot archive (currently `cli.github.com` and
`deb.nodesource.com`) remain **base-only**. The drift is accepted. A layer must
not depend on a non-snapshotted source.

### Identity

**R18.** Root identity is `base digest + union package identity + union account
identity`. Union package identity covers the normalized declared set and the
snapshot date.

**R19.** Identity is computed **before** the foundation build. The snapshot date
is what makes a pre-build identity predict post-build bytes.

**R20.** Adding a declared package invalidates the affected composition's tool
layers, because they build on the foundation. This invalidation is **intentional
and must be observable** — the plan must attribute the rebuild to the changed
root rather than presenting it as an unexplained miss.

### Rebase

**R21.** On a base change, the union package layer is **regenerated against the
destination base** and never carried forward, mirroring ADR-0032's rule for the
union account layer.

**R22.** Destination checks apply to the regenerated foundation, not only to the
reused tool artifacts.

### Accounts interaction

**R23.** A declared account that collides with a user created by an installed
package is a **plan-time error naming both causes**, extending the existing
account collision rejection.

**R24.** The migrated examples must reconcile their currently hand-written
account appends (chrome-devtools appends to `/etc/group`, `/etc/passwd`,
`/etc/shadow`) with declared accounts.

### Verification

**R25.** The T3/S1 checker implements ADR-0035's **ownership** rule, and must not
be built as a path allow-list.

**R26.** The checker must also close the deletion-aware gaps found in CP0's
soundness audit: root whiteouts and opaque markers, sibling-added subtree
deletions, and file/directory prefix collisions.

**R27.** The shipped set is re-verified with the corrected checker **before**
enforcement is turned on.

**R28.** The produced image retains no apt index.

## Acceptance criteria for `/breakdown`

Observable checks, not preselected slices. Each implementation ticket should name
which checks it delivers.

1. **Declaration works.** A layer declaring packages yields a composition whose
   foundation has them installed, confirmed by `dpkg -s` inside the booted guest.
2. **One resolution.** Two layers declaring overlapping packages cause exactly
   one package-manager invocation, and **no S1 collision** on those paths.
3. **Determinism.** The same declaration set and snapshot date produce
   **identical** foundation manifest bytes when rebuilt at two different times.
4. **The snapshot date is the only lever.** Bumping only the snapshot date
   changes resolved versions deterministically and produces a new composition
   identity; no other layer-side change can alter resolution.
5. **Ownership is enforced.** A tool layer writing package-manager state is a hard
   error with no opt-out, and the error names the layer and the path.
6. **Package-manager layers are rejected.** A layer running a package manager at
   build time is not recorded as a validated artifact.
7. **Conflicts fail early.** Incompatible version qualifications across layers fail
   at plan time naming both layers.
8. **No index ships.** The image contains no retained apt index.
9. **`chrome-devtools` migrates.** It boots with a working `chromium`, uses
   declared packages and declared accounts, and produces **no T3 findings**.
10. **The development examples migrate.** `go-dev`, `rust-dev` and
    `wirenboard-cpp` produce no T3 findings, with the ~305-file base-replacement
    class gone rather than exempted.
11. **Rebase regenerates.** A base-only change regenerates the foundation against
    the destination base and carries no old package layer forward.
12. **Accounts reconcile.** Package-created users and declared accounts coexist in
    the migrated examples without collision errors.
13. **Unrelated layers stop colliding.** Two layers with disjoint private content
    but a shared toolchain dependency no longer produce S1 overlaps, because the
    shared content now lives in the foundation.

## Breakdown constraints and exclusions

**In scope:** declaration syntax and normalization including local layers;
deterministic union, duplicate tolerance and version-conflict rejection; the
generated union package layer and its ordering; snapshot pinning and bumping; the
T3 ownership rule and its checker, including the CP0 soundness fixes; root
identity; regeneration on rebase; reconciliation with declared accounts; and
migration of the four affected examples.

**Out of scope:** pinning `cli.github.com` / `deb.nodesource.com` (accepted
drift, base-only); `build_packages` (open, below); non-Debian package managers;
resolved-version lockfile machinery (ADR-0035 rejected it as unnecessary given the
snapshot date); allowing individual layers to run package managers for ad-hoc
installs; and any change to the account model itself.

**Sequencing constraint:** the T3 checker is CP3's deliverable. This work must
land, or at minimum be decided, **before CP3**, or CP3 will enforce the rule
ADR-0035 amends. CP2 is unaffected — it implements T1b only.

## Open questions

These block the requirements noted. The rest of the handoff is decision-complete.

1. **Is `build_packages` needed?** Affects R1 and R5. A compiler needed only to
   produce an artifact arguably should not land in the foundation, and
   wirenboard-cpp's purpose *is* building, so the split is not clean-cut. Options:
   a single `packages` list (simplest, may bloat foundations), or a separate
   build-only list discarded after the artifact is produced.
2. **Version-conflict policy.** R7 requires *that* conflicting qualifications fail,
   but not how a compatible pin is expressed or how transitive version drift
   within the snapshot is bounded.
3. **Where the collision predicate's Verus boundary sits.** R7 and R23 are
   predicates the specification already requires a Verus contract for, by analogy
   with ADR-0032's account collision predicate under ADR-0018.
