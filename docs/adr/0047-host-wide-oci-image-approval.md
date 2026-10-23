# ADR-0047: Host-wide OCI image approval

## Status

Accepted. Implements [agent-vm #390](https://github.com/gregwebs/agent-vm/issues/390)
and completes the model begun in
[ADR-0035](0035-consume-user-owned-boot-images.md) (whose retained-default
decision this ADR extends). Builds on the acquisition infrastructure of #389
([ADR-0043](0043-image-command-group-and-daemon-import.md) places the verbs).
Follow-ups #391 (explicit import approval) and #392 (default source-reference
retention) are deliberately not decided here; the staging boundary below records
what stays open.

## Context

ADR-0035 pinned only the **retained default**. A config, environment or CLI
selection named a tag, and a launch handed that tag to the SDK: a moved tag, a
cleared cache or a shared-cache alias publication could change guest content with
no approval. The retained default itself was safer but still had two gaps —
adoption after acquisition was write-once, not coordination against a concurrent
resolver, and a *changed* explicit replacement was last-writer-wins.

Issue #390 asks for the same guarantee for every OCI selection: one approval per
normalized reference and host platform, host-wide; automatic establishment after
successful acquisition; and explicit, candidate-scoped consent before replacing
existing approved content. Selection precedence, digest-only retention and the
local rootfs/disk workflow must not change. Refresh/set-default already existed
as boot-free native operations (#389) and are the natural approval surface.

Two facts constrain the design:

- OCI registries serve **moving tags** and **multiarch indexes**. The content a
  host boots is the host-platform *child* manifest, and the native acquisition
  layer already validates that child, preserves its metadata and records a
  cache-only receipt.
- `$HOME` is the only location that is simultaneously user-scoped, present for
  every verb, independent of project/state/cache roots, and unavailable to a
  repository checkout. A cache entry is evidence that bytes exist, not that a
  human accepted them.

## Decision

**One authority, one preparation path.** `image_pin` owns
`$HOME/.config/agent-vm/image-pins.json` plus a stable `image-pins.lock`. A pin
binds a canonical OCI reference and the measured host Linux platform
(`linux/<arch>[/<variant>]`) to the approved host-platform manifest **child**
digest and a monotonic revision. Launches and `setup` call only
`prepare_selected`; `image refresh` and `image set-default` call only `update`
with `ApprovalMode::Ask | Yes`. No consumer holds an acquisition path of its own,
so no consumer can consume content the others would refuse.

**Approval is per child, not per index.** A tag or index selection resolves to
its verified host child; the approval names that child and a launch hands the SDK
`repo@child`. Index identity is not approval identity: moving a tag so that an
unrelated platform changes does not disturb the approval. Approval equivalence
compares the validated native content — verified config digest plus ordered layer
diff IDs — so an alternate digest algorithm (sha256/384/512) or an equivalent
re-materialization keeps the stored record, identity and revision. A **digest the
user stated** keeps its own binding: if it resolves to different content that is
an integrity failure, never an approvable replacement (a multiarch index may
still resolve to its verified child, which is what gets approved).

**Authority lives in HOME, not in TOML or the cache.** Pins are never written
into config files, the retained record, the cache, or project state. The store is
host-wide across projects and independent of cache location, shared-cache
redirects and `AGENT_VM_STATE_DIR`; deleting the cache reacquires the approved
digest, and deleting the store is a deliberate approval reset. The retained
record stays digest-only (#392) and the two are changed together transactionally.

**Acquisition success, before create, is the first-pin trigger.** A first pin is
acquired, validated and committed before any SDK create, so a later builder,
credential or runtime failure leaves a valid approval and no launch ever consumes
unmeasured bytes. This is success-before-adoption generalized to every tier:
adoption of an absent retained record still happens only after its own
default-tier acquisition succeeds — and it happens for **every** successful
default-tier preparation, not only a first pin, because an explicitly pinned
selection (an `image refresh`) has no fallback of its own. Adoption stays
write-once: an existing retained record is never moved by a launch. A first pin,
an unchanged digest or an unchanged fallback prompts for nothing; only a changed
pin needs consent.

**Candidate-scoped consent.** The exact validated candidate is frozen *before* a
replacement prompt; the displayed source (escaped) and full old/new digests bind
the approval. The prompt defaults to No, reads one bounded canonical line, and
never reprompts. `--yes` — nested only on `image refresh`/`image set-default` —
authorizes exactly that candidate and still renders the change. Without a
terminal on both stdin and stderr, a changed pin refuses with status 1 without
reading stdin. The subsequent mutation is one pure compare-and-swap against the
revision and digest that were displayed, so a concurrent writer is never
overwritten and a stale consent cannot authorize a different predecessor.

**A bounded journal exists for failed-operation preservation.** `set-default`
updates both the approval and the retained fallback. Two independent atomic
writes cannot make that pair all-or-nothing, and rollback can fail, so a bounded
`pending_default` intent records the exact logical previous/proposed fallback
bytes across three atomic writes. A precommit failure restores the previous
fallback; a failed restoration leaves the old pins plus the intent authoritative
and reports recovery-required. Only the next *write* recovers — an explicit image
command, or a launch/`setup` establishing a first pin or retaining an absent
fallback; readers observe the old logical state or the complete new one. This is
specifically a failed-operation guarantee — not power-loss durability, and not a
transaction an older binary participates in.

**Coordination boundaries.** Lookups take a bounded shared lock (2 s) and create
nothing; mutations take pin EX then default EX for one bounded read-modify-write
(30 s combined). Network acquisition and the human prompt never run under a HOME
lock. The cache keeps its shared/exclusive publication barrier: shared across
launch/prepare/validate and the SDK create, exclusive across import/build
publication. Import/build can publish cache aliases but can never create or
replace a HOME pin or fallback (#391). Local rootfs/disk launches bypass approval
entirely.

**Corruption is closed.** Malformed, oversized, unreadable, symlinked or
lock-less stores are hard errors, never "no approvals yet"; re-pinning would
authorize content nobody approved. Recovery is restoring the file or deliberately
moving it aside, and documentation never suggests deleting approvals to repair a
cache.

**The update advisory disappears.** A launch never checks a mutable tag. There is
no launch-time flag, environment variable, banner, marker or deprecation hint;
`image refresh` and `image set-default` are the only movement checks. The
removed `--update-check` follows the existing CLI rule: unknown before the tool
verb (status 2), forwarded verbatim after it.

## Consequences

- Every OCI launch, `setup`, `refresh` and `set-default` now depends on a small,
  strict HOME store. A damaged store therefore fails an OCI launch that used to
  work; the recovery is explicit, and non-OCI local-path launches are unaffected.
- `image show`, `doctor` and import's post-publication inspection depend on
  pin-store health **only when the default tier is the observed source**, because
  the journal defines the logical fallback. They remain offline, read-only and
  bounded, and never create, recover or clear anything.
- Warm approved launches make zero registry requests, including with inherited
  obsolete environment variables; a cold cache reacquires the approved digest and
  fails rather than adopting the current tag.
- A moved tag is invisible until an explicit operation; that is the intended
  trade — reproducibility over implicit freshness — and the verbs for moving are
  discoverable in `image --help` and USAGE.
- Import/build can no longer silently redirect a pinned launch, so an iterating
  user must approve explicitly with `image refresh --image REF`. A daemon-only
  image may not be registry-refreshable; that limitation is documented rather
  than papered over with automatic import approval (#391).
- The retained default keeps digest-only storage, so a bare refresh cannot follow
  the source tag it was originally chosen from (#392).
- Older launchers and direct `msb` clients do not consult the store; a binary
  rolled back keeps its old tag-consuming behaviour. The cache receipt remains
  cache evidence and repairs metadata aliases overwrite, but it is not approval.
- The pin module adds a small set of machine-checked decision kernels (source
  and record bounds, platform and variant acceptance, the compare-and-swap
  decision, content equivalence, journal observation, and the prompt's terminal
  and answer rules) with their trusted I/O adapters recorded in
  [ADR-0018](0018-machine-checked-boundary-contracts.md). Registry auth/TLS, OCI
  integrity, locking, JSON and terminal I/O remain trusted.

## Alternatives

- **Make `config.toml`, the retained record or the image cache the authority.**
  Rejected: TOML is user/project *selection* input and a project file must never
  authorize content; the retained record is one default-tier bookmark, not every
  source; the cache is evidence that bytes exist and is routinely deleted,
  redirected or written by import.
- **Trust a cache alias as approval** (a digest-spelled tag, a receipt binding,
  or "the alias points at the same child"). Rejected: alias publication is
  exactly the writer #390 must not let change launch content.
- **Pin after a successful create.** Rejected: it records boot success instead of
  measured content, leaves every failed create having consumed unapproved bytes,
  and repeats the pre-#390 ordering hazard for the most important operation.
- **Prompt first, then resolve.** Rejected: the user would approve an unnamed
  digest; a registry moving between prompt and commit could substitute content
  under the same answer. The candidate is resolved and frozen first.
- **Compare index digests for approval equivalence.** Rejected: an index can move
  for an unrelated architecture without changing what this host boots, and an
  index digest is not what the SDK consumes. Equivalence is host-child content.
- **Write pin and fallback separately without a journal.** Rejected: the second
  write can fail after the first, returning an error with changed state, and
  rollback can itself fail. The bounded intent makes failed-operation preservation
  explicit and recoverable.
- **Hold the HOME lock across acquisition or the prompt.** Rejected: a slow
  registry stream or a human would block every other selection on the host, and a
  lock held across an unbounded wait is a denial-of-service surface.
- **Take the cache's exclusive publication lock for every approved launch.**
  Rejected: it would serialize unrelated warm launches behind one another and
  behind any publication, removing the concurrency the shared barrier exists to
  provide.
- **Lock every archive-supplied alias during import/build.** Rejected: an archive
  can name an unknown set of references, and a multi-alias lock set invites
  ordering deadlocks; the shared/exclusive barrier plus the still-documented
  partial-rollback limitation is the honest boundary.
- **Approve import/build results silently.** Rejected: it would let an alias
  publication replace established approval without a candidate shown to a human —
  the defect #390 removes. #391 may add an explicit import approval surface; it
  is not assumed here.
