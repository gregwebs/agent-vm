# ADR-0063: Project-scoped OCI image approval

## Status

Accepted and implemented in **0.7.39**
([#532](https://github.com/gregwebs/agent-vm/issues/532) slice S1). Amends
[ADR-0047](0047-host-wide-oci-image-approval.md): approval authority is scoped
to a **project**, and the store format is version 2. Later slices of #532
(S2 project defaults, S3 active image set, S4 refresh over the active set, S5
build inputs) are not decided here.

**S2 implemented by [ADR-0067](0067-project-default-boot-image.md) (0.7.47):**
Decision 7 is superseded — `image set-default` no longer pins and no longer
changes any project's default, because each project now has its own (stored in
the same version-2 file, whose `defaults` field ADR-0067 adds). Decision 2's
entry points are now launch, `setup`, `image refresh`, `image set-default`,
`image build`, `image import`, `image show`, `doctor`, `clipboard` and `access`
(`access` was missing from this list since S1). Decision 6: refresh renders
"in this project" but no longer asks (ADR-0067).

**Superseded in part** by #532's review round 4 (recorded there as
_Supersedance — the upgrade blocks stop reconstructing authority_). Decision 5's
clause that the procedure "finishes an interrupted `set-default` as the old
binary would" is withdrawn: the blocks no longer replay `pending_default`, and
no longer validate a store or a default against the old reader's grammar. The
reason and the replacement are recorded under Decision 5; the rest of the
decision stands.

## Context

ADR-0047 made one host-wide table answer "may this content be consumed?": the
canonical reference plus the host Linux platform mapped to the approved manifest
child. That closed the moved-tag hole for one host, and deliberately shared one
approval between every project and every state root.

The cost is cross-project leakage in the other direction. Two projects (two
worktrees of one repository, say) that select the same tag share one approval,
so `image refresh --yes` in one of them changes what the other boots. Cached
bytes should be shared; approval should not be, because approving content is a
decision about what *that* project runs.

[#532](https://github.com/gregwebs/agent-vm/issues/532) agreed the boundary
through a design interview: a project is the canonical command working
directory, matching the identity session state already uses; pins stay
host-managed authority (never repository files, never under
`AGENT_VM_STATE_DIR`); and upgrade from the old state is an explicit, documented,
tested archive/reset rather than an inheritance or a compatibility layer.

## Decision

1. **A pin is keyed by (project, canonical reference, host Linux platform).**
   The record still maps to the approved host-platform manifest child digest and
   a monotonic revision; revisions are per key. Store keys are unique per
   (project, reference, platform), so a reference may appear once per project and
   every reader selects by project **and** reference.
2. **The project is captured once per command.** Each entry point — launch,
   `setup`, `image refresh`, `image set-default`, `image build`, `image import`,
   `doctor` and `clipboard` — captures the canonical working directory exactly
   once as a `ProjectDir` and passes that value to session state and to every pin
   operation; no consumer re-reads the cwd. An external `rename` needs no
   `chdir` to change what `getcwd` returns, so two reads could name two projects
   within one command. The identifier is the lowercase hex SHA-256 of the
   captured path's bytes; session's 12-hex state-directory name is that digest's
   prefix, so existing state stays reachable and the two consumers cannot
   disagree.
3. **One file, strict version 2.** `$HOME/.config/agent-vm/image-pins.json`
   gains a required `project` field per record. `pending_default`, the bounds
   (4 MiB, 4096 records, 4096 source bytes), the stable `image-pins.lock`, the
   lock order and the retained-default record (`default-image.json`) are
   unchanged. A malformed scope is the existing "damaged" error; a store present
   without its lock is damage on both the observation and the mutation path.
4. **A version-1 store is refused, never read.** It is the host-wide format this
   agent-vm no longer reads, and guessing which project each approval belonged to
   would authorize content nothing measured. The refusal names the file, says
   archiving resets approvals, says mutable tags may then resolve to newer
   content, and points at the USAGE upgrade section; it precedes every
   approval-authority write, registry acquisition, cache publication, Docker run
   and SDK create. `--yes` does not change it. Local rootfs/disk launches bypass
   approval and keep working meanwhile.
5. **Upgrade and rollback are one tested operator procedure in
   [USAGE](../../USAGE.md#upgrading-from-host-wide-approvals).** The text is the
   program: it archives the exact `(image-pins.json,
   default-image.json)` pair, refuses an interrupted `set-default` untouched and
   hands it back to the release that owns the journal, and is fail-fast,
   quiescent, non-overwriting and resumable; the rollback restores the archived
   pair byte-for-byte, so a default changed by version 2 cannot fail the old
   reader's journal check. A contract test executes those marked blocks
   verbatim, including injected failures.

   _Superseded in part (round 4), and the withdrawal is the decision._ This
   decision first had the procedure "finish an interrupted `set-default` as the
   old binary would" by replaying the store's `pending_default` journal in shell,
   and validate stores and defaults against the old reader's grammar and bounds.
   Three review rounds showed a `jq` approximation of that reader cannot converge:
   it accepts bytes the reader rejects (duplicate object members, a second JSON
   document, a reference regex that admits `INVALID@@sha256:…`) and rejects bytes
   the reader accepts (SHA-512 and SHA-384 defaults, references past 200
   characters), so each hardening round traded one false accept for a false refuse
   — and a false refuse locks a user out of their own approvals. What remains
   exactly computable in shell is copying bytes, refusing what cannot be copied
   exactly, and naming the format version, so that is all the blocks do. A store
   carrying a journal is refused with the digest it already holds and the command
   that finishes it (`agent-vm image set-default --image <digest>`, run under
   0.7.38, which needs network access), or with the hand-archive route, which now
   archives the pair and which the rollback refuses to restore a journal-bearing
   store without. Nothing here derives an approval, digest or default from JSON,
   so the requirement's "nominal intent cases" are narrowed to refusal.
6. **Rendering names the scope.** The replacement prompt says "in this project"
   and a build/import approval says "for this project", so a consent recorded on
   a terminal is unambiguous about whose approval it changes.
7. **`image set-default` is unchanged until S2.** It still commits a pin for its
   typed target in the invoking project *and* rewrites the host retained default
   that every project's default tier follows. S1's isolation therefore covers
   explicitly selected references; S2 closes the default-tier coupling.

## Consequences

- **A first pin in a new project behaves exactly as a first pin did.** It is
  cache-first, needs no prompt and commits before create. Another project's
  approval for the same reference is never consulted or borrowed, so with one
  shared cache a new project reuses whatever the cache alias holds at that
  moment — resolution afresh, not inherited approval.
- **Approvals accumulate per project** until S3 introduces in-use tracking. The
  4096-record bound still applies to the whole file, and reaching it at commit
  is reported as a full store (archive it to reset), not as damage.
- **Rollback is possible but bounded**: the archived version-1 pair restores the
  old binary, at the cost of discarding approvals made since the upgrade.
- A version-1-pin-aware binary meeting a version-2 store reports it as damaged
  and refuses it: closed, never misread. Binaries older than ADR-0047 ignore the
  file entirely.
- The store's order change is limited to `begin`'s lockless check, which now
  precedes its pre-read: a lockless store is damage on both paths, as a
  version-1 binary already reported for it.

## Alternatives

- **Per-project files** (`image-pins/<project>.json`). Isolates corruption too,
  but adds directory management, a second journal home and much larger test
  churn for a property the issue does not ask for.
- **Store the scope under `AGENT_VM_STATE_DIR`.** Rejected: it violates
  ADR-0047's independence from a user-controlled redirect, so clearing
  `AGENT_VM_STATE_DIR` or pointing two launches at different state roots would
  change who may approve content.
- **Inherit old host-wide approvals** (the superseded #532 suggestion). Guessing
  a project for each record would authorize content nothing measured, and it
  would need a migration layer that never ends.
- **Nest records per project** (`{"projects": {id: [...]}}`). Equivalent in
  meaning, but every reader would need a new traversal and the flat record
  already carries the scope as one more column.
- **Key by the 12-hex session hash.** Approval authority must not depend on a
  truncated hash; the prefix stays a pure function of the full digest.
- **Read the cwd per operation instead of capturing it once.** An external
  rename splits one command across two projects, so one command could approve
  content under a path the user never ran in.
- **Refuse a version-1 store by treating it as absent.** That would silently
  re-pin every reference on the first launch — the opposite of an explicit reset.
