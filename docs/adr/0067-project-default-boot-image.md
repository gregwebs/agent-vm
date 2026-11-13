# ADR-0067: Project default boot image

## Status

Accepted and implemented in **0.7.47**:
[#541](https://github.com/gregwebs/agent-vm/issues/541), slice S2 of
[#532](https://github.com/gregwebs/agent-vm/issues/532). Amends
[ADR-0063](0063-project-scoped-oci-image-approval.md) Decision 7 (superseded:
`image set-default` no longer pins and no longer changes any project's default),
[ADR-0047](0047-host-wide-oci-image-approval.md) (the journal is no longer
written; the failed-operation guarantee is narrowed; the retained record becomes
a starting choice; the prompt and `--yes` are removed) and
[ADR-0043](0043-image-command-group-and-daemon-import.md) (refresh is its own
consent, so build, import **and** refresh approve a replacement prompt-free).
Requires the store format of ADR-0063 (version 2).

## Context

Two questions have two different records in `$HOME/.config/agent-vm/`:

- *Which image does a session boot?* — **selection**: the command line, then
  `AGENT_VM_IMAGE_TAG`, then the user config, then the project config, then the
  **default tier**.
- *What exact content may that reference be?* — **approval**: one pin per
  (project, canonical reference, host platform) in `image-pins.json`
  (ADR-0063).

After ADR-0063 the only shared state left on the default tier was the **retained
default** itself: `image set-default` rewrote `default-image.json`, which every
project's default tier read. A host-wide operation therefore still moved every
project, and ADR-0063 Decision 7 recorded that as the remaining leak. `image
set-default` also wrote an approval for the *typed* target in the invoking
project — a per-project side effect of a host operation. And a changed mutable
tag could only be approved through a terminal prompt or `--yes`, so a bare
non-interactive refresh that found changed content failed when it could not ask.
A reference with no approval for that project was a first pin and needed no
prompt, so S1 did not make every established project's refresh refuse.

```text
BEFORE (S1)                                   AFTER (S2)

 project P ─┐                                  project P ── defaults[P] = A ──┐
 project Q ─┼─► default-image.json = X         project Q ── defaults[Q] = A ──┤ (each independent)
 project R ─┘   (set-default rewrites X        project R ── (none) ───────────┴─► default-image.json = X
                 → every project moves)                     (starting choice only; set-default
                                                             rewrites X → only R-like projects see it)
```

## Decision

**1. A project's default is recorded with its approvals.** The version-2 store
gains an optional top-level `defaults` array of `{project, image}` records: at
most one per project, `image` a canonical reference that states its digest.
Absent means "no project has an established default" and decodes exactly like
`[]`; writers omit it when empty. The version stays 2, so an ADR-0063 store is a
valid ADR-0067 store with no project established — which is literally true,
because under S1 every project's default *was* the host record. No migration, no
reset.

**2. Selection stays lazy and read-only.** The default tier reads, in order, the
project's established default, the host's retained default, and the initial
recommendation. The host record is read only when the project has none. A
damaged host record therefore does not break an established project's launch,
`setup` or `image show`.

**3. Establishment is write-once, per project.** A successful default-tier
preparation (launch, `setup`, `image refresh`) records the selected immutable
reference as the project's default when it has none, after acquisition success.
Establishing and its first pin are **one** save, because both records live in
the same file. Launch and `setup` never move an established default; nothing
establishes one from a selection made while the tool configuration was
unreadable, because the configured tiers are then unknown and the selection is
provisional.

**4. The host record is initialized only from the initial recommendation.** A
selection that came from the host record or from the project's own default never
writes it. A release that changes the recommendation changes what a *new* host is
offered, never an existing retained default or an established project's default.

**5. `image set-default` writes only the host record.** It resolves and validates
its target as before, then replaces `default-image.json` with the validated host
child. It writes no pin and no project default in any project, prompts for
nothing, and has no `--yes`. Its notice says whether the invoking project keeps
its own default, and how to adopt the new one.

**6. Explicit `image refresh` is its own consent.** Invoking the command
authorizes exactly the candidate it resolves: a first pin, a replaced approval
for a moved **mutable** reference, and adoption of the host's retained default.
Nothing is asked and no input is read, on a terminal or not. What is kept: every
change of approved content is rendered on stderr before it is committed (escaped
source or the fixed default-tier label, platform, both full digests), and a
render that cannot be written commits nothing; the candidate is resolved once and
frozen; the commit is a compare-and-swap on the revision and digest that were
displayed; an immutable reference that resolves to different content is an
integrity failure with no approval path. `--yes` is removed from both update
verbs (ADR-0035's no-shim rule), so passing it is an ordinary usage error. What
is given up: the user can no longer refuse at the terminal. The digests are still
shown; keeping an approval now means not refreshing that reference, or selecting
it by digest.

**7. Adoption on an explicit refresh, only from an existing record.** In a
project whose selection is its established default D:

| Host record | Result |
|---|---|
| exists, names a different reference H | refresh resolves H once, approves its content for this project (a first pin, or the same digest), and moves `defaults[P]` from D to H, in one compare-and-swap save. Old/new digests are rendered when they differ. D is not re-resolved. |
| exists, names D | today's refresh of D; nothing else changes. |
| absent | today's refresh of D; nothing else changes. The initial recommendation never moves an established project, so a launcher upgrade never does. |
| damaged | refresh fails before any registry request, and nothing is written. |

Adoption never touches another project's records. The offer is a *selection*
fact, so the selector computes it and the approval authority decides and writes.

**8. A bare refresh with an unreadable configuration is an error.** Falling
through to the default tier would establish a project default from a state the
user never chose. `image refresh --image REF` and an
`AGENT_VM_IMAGE_TAG`-selected refresh still work (they warn): they never select
through the default tier, so they establish nothing.

**9. The `pending_default` journal is no longer written, and still read.** It
made a pin and the host record all-or-nothing. Nothing pairs them any more:
`set-default` writes only the host record (one atomic save), a project default
and its first pin are one file, and the only two-file write left — a
recommendation-sourced first default-tier use — has no invariant tying its halves
together. The host record is written **first**. This **narrows ADR-0047's
failed-operation guarantee**: a failed recommendation-sourced first launch may
leave the host starting choice initialized with measured content. That is
acceptable because no invariant pairs the files any more, the content written was
acquired and validated, and the host record is a starting choice this failed
launch would have written anyway on success. The alternative weighed was pin
store first: a failure after it would leave "project established, host record
absent", and that project would then select its own default forever, so the host's
starting choice would stay missing until some other fresh project initialized it.
The reader stays because version 2 *means* "a non-null journal names the logical
default as `previous`"; dropping it would misread a 0.7.39–0.7.46 store
mid-recovery. It is the format's existing meaning, not a compatibility layer; a
release that bumps the store version may drop it.

**10. Concepts get their own module.** The project-default concepts and flows
live in `image_pin/project_default.rs`, a child of the approval authority, which
gains only the schema and transactions that must share a save with the pins.
`image_pin` never calls back into selection, and the selector never writes.

## Consequences

- `image set-default` no longer changes what any **established** project boots,
  including the invoking one. An established project adopts the new host choice
  by running `image refresh` (behavior change B1 in USAGE). A project that has
  not booted the default tier yet is not established, so the new host choice is
  its starting choice and its next default-tier use boots and establishes it
  (B6; AC3).
- A bare `image refresh` in an established project adopts the host record (B2).
  Re-verifying the project's own default is `image refresh --image <its ref>`.
- Refresh never asks (B3), and `--yes` is removed from both verbs (B4).
- `image set-default` no longer approves its typed tag in the invoking project
  (B5); `agent-vm image refresh --image repo:b` does that.
- A project that has not yet booted the default tier is not established, so a
  `set-default` still changes its starting choice (B6).
- The first default-tier use of each project writes `image-pins.json`, so a
  launch that 0.7.46 ran read-only can now fail if the store is unwritable (B7).
- `image show` may print `Source: project default`, and `doctor` prints a
  `project default:` row (B8).
- A bare refresh with an unreadable configuration fails; `setup` still warns and
  falls through but establishes nothing (B9).
- Two new notices: the two-sentence `set-default` notice and the adopting
  refresh's `==> this project now uses the host's default boot image` (B10).
- #392 (retaining the host default's source tag) becomes moot: adoption covers
  the need, so it can be closed.
- The host record is now only a starting choice. ADR-0047's "failed-operation
  preservation" is narrowed as described in Decision 9; ADR-0043's consent
  surfaces gain refresh.
- **No rollback compatibility is designed or documented.** A 0.7.39–0.7.46
  binary rejects a store that records a project default as damaged; nothing in
  this change works around that. See behavior changes B1–B10 in USAGE for the
  user-facing consequences.

## Alternatives

| Alternative | Why not |
|---|---|
| A separate project-default file beside `image-pins.json` | It would need no journal (every project default is an immutable `repo@digest`), but it costs a second strict schema, a second lock and lock order, and two saves where one atomic save now establishes a project and its first pin together. |
| Store project defaults under `AGENT_VM_STATE_DIR` | The authority must not follow a user redirect (ADR-0063). |
| Keep `set-default` pinning the typed tag | It is the one remaining per-project side effect of a host operation. |
| Store version 3 | Forces a second reset or a migration. |
| Launches stop initializing the host record at all | Breaks the new-host promise for no benefit here. |
| Keep the prompt and `--yes` | A prompt CI cannot answer made a bare non-interactive refresh fail whenever it found changed approved content. Designing S2 around a prompt would have made adoption refuse in every established project, which is the hypothetical this slice deliberately does not build: S1's set-default did not itself imply a refusal, since a new immutable default reference first-pinned without asking. |
| Keep `--yes` as a hidden no-op | ADR-0035's no-shim rule. |
| Offer the initial recommendation for adoption when the host has no record | A launcher upgrade alone would then move established projects. |
| Refresh re-resolves D before offering adoption | Strands a project whose old default vanished upstream. |
| Let a broken-config refresh fall through to the default tier | Permanently establishes the project from a transient state. |
| Refuse every refresh with an unreadable configuration, including `--image`/env | They never select through the default tier, so refusing them only removes a working recovery path. |
| Let `setup` (or any preparation) establish from an unreadable configuration | The same permanent-establishment hazard. |
| Withhold host-record initialization too while the configuration is unreadable | The host record only ever receives the recommendation, which cannot capture the transient state. |
| Retain the source tag (#392) | Not required by #532; adoption-on-refresh covers the need. |

## References

- [CONTEXT.md](../../CONTEXT.md) — *Default boot image*, *Retained default boot
  image*, *Image refresh*, *Image pin*, *Image approval*.
- [USAGE.md](../../USAGE.md) — *Project default boot images*, *Behavior changes in
  0.7.47*.
