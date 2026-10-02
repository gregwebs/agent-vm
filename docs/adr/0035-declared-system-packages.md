# ADR-0035: Declared system packages, resolved once in the generated foundation

## Status

Accepted (decision). **Not yet implemented** — tracked by
[Implement declared system packages](https://github.com/gregwebs/agent-vm/issues/255),
with requirements in
[the declared-system-packages specification](../specs/declared-system-packages.md).

Amends [ADR-0031](0031-tool-image-contract.md)'s **T3** by replacing its implied
path allow-list with an **ownership** rule. Extends
[ADR-0032](0032-one-layer-kind.md)'s declared-account model (declaration → union
→ one launcher-generated layer) to system packages. Depends on the rebase and
provenance rules of [ADR-0033](0033-default-rebase-with-build-provenance.md).
Relates to [ADR-0034](0034-versioned-image-releases.md) (release acquisition) and
[ADR-0029](0029-compose-tool-images-by-layer-stitching.md) (stitched DAG).

Supersedes the implicit assumption in
[the image-composition specification](../specs/image-composition.md) that a layer
which needs system packages can simply run `apt-get install`.

## Context

### T3 forbids what apt fundamentally does

ADR-0031's **T3** is absolute:

> **Never replaces or deletes a base path.** The tool's own layers contain no
> whiteout, opaque marker or non-directory entry for any path that exists in the
> base. […] A layer may change files introduced by any declared ancestor,
> including transitive ancestors, but never files from the base or generated
> union account layer. Only that launcher-generated append-only account layer
> may write protected account files.

And the specification makes violations non-negotiable: *"Violations are hard
errors with no opt-out."*

`apt-get install` cannot satisfy that. Measured evidence (CP0 — see
[the CP0 evidence record](../research/image-composition-cp0-evidence.md)):

| Recipe | T3 findings | of which: upgraded base package files |
|---|---:|---:|
| `images/tools/*` — all six shipped tools | **0** | 0 |
| `probe-apt-min` — installs only `tree` | 9 | 0 |
| `examples/layers/chrome-devtools` | 36 | 0 |
| `examples/layers/go-dev` | 336 | **305** |
| `examples/layers/rust-dev` | 337 | **305** |
| `examples/layers/wirenboard-cpp` | 363 | **305** |

The six shipped tools are clean **because none of them runs `apt`** (verified:
`grep -ln 'apt-get' images/tools/*/Dockerfile` matches nothing). They install via
curl/npm/tarballs into `/opt/agent`. Every violating recipe violates *because it
runs apt in its own layer*.

### Two distinct violation classes

**1. Bookkeeping state.** dpkg/apt databases (`/var/lib/dpkg/status`,
`status-old`, `dpkg/lock`, `triggers/{File,Lock}`, `/var/lib/apt/extended_states`),
package-manager logs (`/var/log/dpkg.log`, `/var/log/apt/*`), debconf caches,
`ldconfig` caches, and PAM state. Unavoidable for any apt run — even a
byte-identical rewrite of `/var/lib/dpkg/lock` is flagged, since *"identical
contents are not an exception."* This is a scoping problem: the contract treats
tooling bookkeeping as if it were foundation identity.

**2. Base content replacement.** 305 package files per development recipe, from
a real library upgrade:

```
Unpacking libc6:arm64 (2.41-12+deb13u4) over (2.41-12+deb13u3) ...
Unpacking libc-bin     (2.41-12+deb13u4) over (2.41-12+deb13u3) ...
```

This is **not** state. It is a genuine overwrite of the foundation, exactly what
T3 exists to prevent. No exemption for "package-manager state" can cover it.

### Why class 2 happens

The base deletes its own apt index (`rm -rf /var/lib/apt/lists/*` appears **five
times** in `images/Dockerfile`). So every apt-using layer *must* refresh:

```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
```

The refresh reveals a newer archive than the base's vintage. `build-essential`
pulls in `libc6-dev`, whose `deb13u4` build depends on `libc6 (= 2.41-12+deb13u4)`
— a strict-equality dependency. The base carries `deb13u3`. apt therefore has no
choice but to replace the base's libc. The upgrade is **forced**, not gratuitous.

### The account precedent

Accounts already solve the structurally identical problem. The specification:

> Declare accounts with `users`/`groups` on entries, not Dockerfile appends. […]
> Generate **one append-only union account layer below every participating
> layer**, visible at build time as well as boot.

Declaration as data → union across participating layers → one launcher-generated
layer below every participating layer → that layer is the **sole writer** of the
protected surface. T3 already grants it exactly that monopoly.

### Freezing the index against the live archive does not work

Measured: Debian's pool **prunes superseded versions**.

```
live  pool/main/g/glibc/libc6_2.41-12+deb13u3_arm64.deb  -> HTTP 404
live  pool/main/g/glibc/libc6_2.41-12+deb13u4_arm64.deb  -> HTTP 200
```

A base shipping an index frozen against `deb.debian.org` already points at files
that no longer exist, and the problem grows as each package is superseded. The
archive must be frozen **with** the index, not merely read once. An immutable
snapshot serves both:

```
snap  archive/debian/20260901T000000Z/pool/main/g/glibc/libc6-dev_...deb13u3...  -> served
```

## Decision

**1. Layers declare system packages; a layer never runs apt.**
Entries carry a `packages` list. This mirrors `users`/`groups` exactly: intent is
data on the entry, not a command in a Dockerfile.

**2. The launcher generates one union package layer, below every participating
layer.** It is the sibling of the union account layer and performs the **only**
`apt-get install` in the system, for the union of declared packages. It is
ordered *before* the union account layer, so package postinst-created users land
first and the declared accounts can be reconciled against them by the existing
collision rejection.

**3. The foundation's apt sources are pinned to an immutable Debian snapshot
date.** The snapshot date **is** the reproducibility lock: it freezes the index
and the pool together, so the same declaration resolves to the same versions
indefinitely and no `.deb` can 404. The foundation's single `apt-get update`
against a snapshot is **idempotent** — it always yields the same index — which is
precisely what makes resolution deterministic. Refreshing is therefore harmless
*inside the foundation* and only harmful *outside* it, where the archive is live.

**4. `Acquire::Check-Valid-Until` is disabled for snapshot sources.** Snapshot
serves the *original* Release file, whose validity window has necessarily passed.
This is safe and principled: the snapshot is immutable and the Release remains
signed, so the expired window carries no information. `Valid-Until` exists to
prevent replay of a stale live mirror, not an intentionally frozen archive.
(Measured: without this, `apt-get update` exits 100 on the frozen
`trixie-updates` and `trixie-security` suites.)

**5. Layers never refresh. Changing resolved versions is a deliberate
snapshot-date bump in the base recipe** — a reviewed change, not a per-layer
accident.

**6. T3's exemption becomes an ownership rule, not a path allow-list.** Only
launcher-generated foundation layers may write the foundation's package-manager
state and package-owned base files. Tool layers may not. This *preserves* T3's
guarantee ("a tool layer can never overwrite the foundation") rather than trading
it away, and it is the same shape T3 already uses for accounts.

**7. Accounts are unchanged.** They remain declared, unioned, and generated. The
only new interaction is ordering and reconciliation with package-created users.

**8. The apt index is not retained in the image.** Because layers never run apt,
only the foundation resolves, and it does so in a single step before discarding
the lists. Retention (~21 MB) is required *only* by the rejected variant in which
downstream layers install for themselves.

The root becomes `base digest + union package identity + union account identity`,
extending the specification's existing `base + generated union accounts`.

### Supporting experiment

Ran on macOS/arm64, Docker 29.5.2, `colima` builder. The recipe is short enough to
reproduce without local artifacts:

```dockerfile
# base: pin apt to a snapshot, retain the index
FROM debian:13-slim
RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
 && printf '%s\n' 'Types: deb' \
      'URIs: http://snapshot.debian.org/archive/debian/20260901T000000Z/' \
      'Suites: trixie trixie-updates' 'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
#  ^ deliberately no `rm -rf /var/lib/apt/lists/*`

# L1: install with NO refresh   -> libc6 stays deb13u3
RUN apt-get install -y --no-install-recommends build-essential

# L2: refresh live, then install -> libc6 becomes deb13u4
RUN apt-get update && apt-get install -y --no-install-recommends build-essential
```

The base built at **`libc6 = 2.41-12+deb13u3`** — deliberately the vintage that
reproduces the CP0 violation. The two layers above then installed
`build-essential` from that base:

| Image | `libc6` | `libc6-dev` | Outcome |
|---|---|---|---|
| base (snapshot, index kept) | `2.41-12+deb13u3` | — | index retained |
| **L1 — no refresh** | **`2.41-12+deb13u3`** | `2.41-12+deb13u3` | **no upgrade; base paths intact** |
| **L2 — refreshed to live archive** | **`2.41-12+deb13u4`** | `2.41-12+deb13u4` | **base path replaced — reproduces the violation** |

Also measured:

- L1 fetched the `deb13u3` `.deb` **from the snapshot** at the same moment the
  live pool returned **404** for it — the archive freeze is what keeps installs
  working, not merely the index freeze.
- A snapshot-pinned source *requires* decision 4; without it `apt-get update`
  fails hard (exit 100) on expired `trixie-updates` / `trixie-security`.
- Cost of retaining the index: 21 MB — relevant to the rejected variant only.

**What this proves:** a package set can be resolved from a frozen snapshot without
forcing upgrades, against a pool the live archive has already pruned.
**What it does not prove:** the launcher-side union layer, the layer-generation
machinery, or behaviour for non-Debian sources. Those are decided above, not
measured here.

## Considered Options

**(a) A broad T3 path allow-list for package-manager state.** *Rejected as
insufficient.* It would clear class 1 but leave ~305 genuine base-path
replacements per development recipe (measured). It also weakens T3's universality,
which is the precondition the rebase path (ADR-0033) relies on.

**(b) Move system packages into the base recipe.** *Rejected.* The base recipe
documents the opposite decision, with reasons:

> The WB C/C++ build-essentials family and armhf/arm64 cross toolchains live as an
> opt-in example tooling layer at `examples/layers/wirenboard-cpp/` instead of in
> this base image

It also cannot express a composition-dependent package set — one published base
for all users — and bloats every user's foundation with packages only some need.

**(c) Narrow what T3 protects.** *Rejected.* Loses the universal
no-base-overwrite precondition that makes rebase safe, and critical changes
(libc, accounts) can still fall inside almost any narrower set.

**(d) Keep apt in layers with a frozen index against the live archive.**
*Rejected.* Pool pruning makes it fail (measured above).

**(e) A lockfile of resolved versions instead of a snapshot date.** *Viable, but
more machinery.* A lock pins versions while still reading a live archive; the
snapshot date achieves the same reproducibility by construction for Debian. A
lock would still be required for sources that have no snapshot — see
Consequences.

**(f) Keep T3 strict and forbid layers from installing packages at all.**
*Rejected.* Makes the specification's own requirement — *"Migrate
`chrome-devtools` and other affected examples"* — unsatisfiable. Under the
current contract, chrome-devtools' `apt-get install chromium fonts-liberation
sudo libnss3-tools` is illegal and has no available remedy.

## Consequences

**Positive**

- T3's guarantee is preserved *and* becomes provable: package-manager state has
  exactly one writer, and it is a generated layer the launcher owns.
- **S1 collisions dissolve structurally.** The 5,251-path overlap between go-dev
  and rust-dev exists because both layers run apt and both create the same libc
  and toolchain files. With one union layer installing once, those become shared
  foundation content rather than unrelated sibling writes. S1 needs no exemption.
- Resolution becomes deterministic: the snapshot date pins it, so rebuilding from
  a declaration yields the same bytes.
- The examples become migratable by declaration, and the relative size/order of
  the base image stops being a policy question.
- The base stays slim; `build-essential` and the cross toolchains stop being
  candidates for every user's foundation.
- The image does not grow: the rejected variant's 21 MB index retention is not
  needed once layers stop resolving.

**Negative / costs**

- **A new cache dimension.** Root identity now varies with the package union, so
  each distinct union needs its own foundation build. Compositions sharing a
  union share it.
- **Churn is more frequent than for accounts.** Changing any declared package
  changes the root, hence every tool layer's parent identity, hence a full
  rebuild of the composition. Accounts already have this property and the
  specification accepts it (*"account changes affect the whole foundation"*), but
  package needs change far more often. This interacts directly with the
  descendant-propagation design.
- **Foundation builds require the network.** A resolution step joins what was
  otherwise a local build, and the snapshot archive becomes an operational
  dependency and a single point of failure for foundation builds.
- **Third-party sources are not covered.** `cli.github.com` and
  `deb.nodesource.com` have no snapshot archive. They supply `gh` and `nodejs`
  in the base today. **The drift is accepted**; they remain base-only. Any future
  layer-level use of a non-snapshotted source would need a vendored `.deb` or a
  lock instead.
- **PAM and account writes remain T3 findings** for any apt run
  (chrome-devtools: 11 PAM, 8 account). The account class is already resolved by
  declared accounts; PAM state falls under decision 6's ownership rule.

**Open questions**

- Is a separate `build_packages` concept needed? Accounts have no build/runtime
  split, but a compiler needed only to produce an artifact should arguably not
  land in the foundation. wirenboard-cpp's purpose *is* building, so the
  distinction is not clean-cut.
- Version-conflict policy: two layers declaring incompatible versions of the
  same package. Accounts reject identity collisions; packages need the analogous
  rule, presumably at plan time.
- Where the collision predicate's Verus boundary sits. The specification already
  requires one for account collisions under ADR-0018; the package analogue would
  live at the same boundary.
- Whether installing with no refresh is *itself* gated by an expired `Release`
  when a cached index is read — moot given decision 4, but unmeasured.

**Sequencing.** CP3 implements the T3 checker. This ADR must land, or at minimum
be decided, **before CP3 starts**, or the checker will enforce the rule this ADR
amends.
