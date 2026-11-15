# ADR-0068: The active image set

## Status

Accepted and implemented in **0.7.51**:
[#542](https://github.com/gregwebs/agent-vm/issues/542), slice S3 of
[#532](https://github.com/gregwebs/agent-vm/issues/532). Extends the version-2
store of [ADR-0063](0063-project-scoped-oci-image-approval.md) with optional
state and supersedes its "approvals accumulate until S3" consequence. Amends
[ADR-0067](0067-project-default-boot-image.md) (role/sequence metadata and
metadata-only writes, without changing selection or establishment),
[ADR-0043](0043-image-command-group-and-daemon-import.md) and
[ADR-0047](0047-host-wide-oci-image-approval.md) (published output is atomic with
its named-result approval; revisions are global tokens; post-commit reporting
issues are success warnings, not "approval was not updated"). Adds contracts to
[ADR-0018](0018-machine-checked-boundary-contracts.md).

S4 targeting/reporting is implemented in **0.7.55** (#543), slice S4 of #532;
D10 supersedes D6's single-selection/arbitrary-target behavior.

S4b presentation is implemented in 0.7.56 (#609).

## Context

S1 made approvals per project. S2 made the default image per project. Neither
recorded which approvals a project **still needs**: every reference it ever used
stayed pinned, and a displaced boot selection or superseded build output kept its
approval forever. "Which references are in use" has three different answers that
were being conflated:

```text
selection   ── chooses a reference per invocation ──┐
approval    ── fixes the approved child content ────┼─► validated prepared image
active roles ── records successful uses ────────────┘
```

A naive role on the pin record cannot express the third: *no held role* is not
evidence that nothing needed the record, because a project that has only ever
built images has never resolved a boot selection, and vice versa. Deleting such
records on the first claim of the other role would discard an approval the next
launch must still honour — an approval escape, not a retirement.

## Decision

### D1. Roles are per-pin; resolution is per project/platform scope

`PinRecord` gains an optional `roles` mask (`boot`, `output`,
`boot-and-output`), omitted when it holds none. `PinFile` gains optional
`scopes`, each `{project, platform, resolved}` with a nonempty mask of the same
spellings, and an optional positive `sequence` (D8). The scope is (project,
measured Linux platform, including variant), so a foreign platform's approval is
never retired by this host's successful acquisition.

A role is **unresolved** until a successful claim of that role occurs in the
scope. Missing scope resolution means *unknown*, not absent. Every resolved role
has exactly one holder in its scope, every holder requires its role resolved,
and every scope is unique — validated on every read, not inferred by writers.

### D2. Claim, and retire iff both roles are known-absent

One successful claim of role `r` on target `T` (in one proposed snapshot):

1. resolves `r` for the whole scope,
2. makes `T` its sole holder,
3. removes `r` from the scope's other records,
4. deletes exactly the scope's records whose **both** roles are now known-absent.

The other role's resolution and holder are preserved, as are all foreign
projects, platforms and variants. The pure kernel is:

```text
held(P,r)         = P.roles contains r
unknown(P,r)      = scope(P).resolved does not contain r
known_absent(P,r) = scope(P).resolved contains r AND NOT held(P,r)
may_retire(P)     = known_absent(P,Boot) AND known_absent(P,Output)
```

Claiming Output on an old record does not erase its unknown Boot; displacing its
Output later keeps the record until Boot is claimed once in that scope. The
symmetric rule holds. A first claim can retire no-role records by resolving the
final unknown role: that is affirmative single-slot evidence, not pruning by
field absence. There is no sweep, migration or eviction of unresolved approvals.

### D3. Every ordinary OCI preparation claims Boot

A launch, `setup`, one-off `--image` override and provisional setup acquire and
validate first, then claim Boot for the selected canonical reference in one
atomic pin save before returning the prepared image to the SDK. A warm claim
verifies the exact consumed approval tuple (key, digest, revision). Failed
acquisition, a stale predecessor or a failed save preserves prior roles and
prevents create. Guest or create failure after the save does not undo it.
Local paths and `--dockerfile` launch builds bypass the store entirely.

### D4. Build and import share one Output slot

A successful explicit `image build`/`image import` claims Output for its named or
inferred result reference, in the same save as its approval. Neither changes
Boot, selection, project bookmark or host choice, and archive aliases confer no
role. No build-input role is added (deferred to #544/#545). A displaced output
can remain protected by unknown Boot: retained authority, not a second slot.

### D5. Committed success is a typed outcome

The atomic rename is the commit. After it, a debug test checkpoint, advisory
selection or completion-notice failure cannot produce a nonzero exit or
"approval was not updated". Store transactions return a typed
`Completion { value, report }`; the command boundary emits fixed,
reference-free success warnings and exits 0. Pre-commit failures stay ordinary
errors with the existing diagnostics. Process death may leave no status; no
rollback after rename is promised.

### D6. Refresh preserves knowledge

Refresh follows D10's in-use worklist, preserving S2 prompt-free consent, frozen
candidates, CAS and eligible default actions. It never claims or resolves a role
and never retires. A new refresh record holds no role; an unresolved slot
protects it until that slot's first claim. With both slots resolved it is
known-inactive and the next successful claim in the scope can retire it. Default
adoption moves the bookmark; the launch records the newly acquired boot choice.

### D7. Retirement creates fresh authority, not restored bytes

Retirement removes approval authority, not shared cached bytes: no tombstones,
no cache deletion. The next use follows lookup-absent → cache-first acquisition
→ validation → new approval/claim. It can return the same digest (cache hit),
changed content (moved cache alias) or resolve the current source (miss). Digest
identity and retained-child cache-loss behaviour are unchanged.

### D8. One HOME-wide write sequence, and global revision tokens

`PinFile` gains optional positive `sequence`: the HOME-wide monotonic high-water
of allocated approval revisions. Every **real** pin save — including metadata,
default-only and journal-clearing saves — reserves `high_water + 1` under the pin
EX lock and persists it atomically; no-op and failed saves persist nothing. An
old file's effective high-water is its maximum live revision (0 when empty),
read without a write. Insertion and content replacement use the reservation as
the approval `revision`; role/scope/default-only writes keep existing revisions.
Decode requires every present sequence to be positive and at least every live
revision; old duplicate per-key revisions remain valid. Exhaustion fails closed
with a distinct error, never a wrap, reset or "damage".

This prevents retire/reinsert ABA: reinserting the same digest draws a new
global allocation, so a suspended operation holding the old tuple is stale.
Metadata-only saves do not change that tuple. The store stays version 2; no
migration, reset or backward-reader machinery is added.

### D9. Bounds and honest growth

4096 pins, independently 4096 project defaults and 4096 scope records, within
the existing shared 4 MiB encoded file; references keep the 4096-byte limit.
Final state is checked after justified retirement. Because unresolved roles
protect records, S3 does **not** bound a project to two retained pins: until both
slots resolve, first-use-only histories can accumulate; after both resolve,
claims retire known-inactive records, and refresh can add unheld
ambient/adoption pins pending the next claim. Full or byte-exceeding proposed saves fail closed as `full()`;
unresolved records are never evicted.

### D10. Refresh the invocation's in-use references independently

`image refresh` refreshes exactly the invocation's in-use OCI references for the
canonical captured command directory and the measured host Linux platform. One
read-only scope snapshot (one `observe_slot(HostRead::Never)`) is taken before any
registry work; the whole file is still decoded and validated, so a malformed
foreign role join is damage rather than something to filter away. The worklist
is frozen from that snapshot plus one ambient decision:

- the ambient next-launch operation (env > user > project > default), even when
  no approval exists for it, and
- every record holding a Boot/Output role in exactly this project/platform scope,

deduplicated by canonical reference. Cache aliases, foreign scopes and
uncertainty-retained no-role approvals are excluded. The worklist is not a role
claim or lease.

On default adoption the ambient operation acquires H instead of unheld D
(ADR-0067 D7); held D remains an independent target and H is deduplicated if
already held. `--image REF` filters the original ambient-reference/held-reference
union and never grants adoption or establishment; a nonmember is refused before
any registry request, naming no value. `AGENT_VM_IMAGE_TAG` is the ambient
selection, not a filter; an empty value is unset and a non-Unicode value is a
typed failure.

An unfiltered selection/offer/initial-health error refuses before freeze, registry
work or writes; it is not a failed-key placeholder. After freeze, each operation
resolves its source once, renders any replacement, revalidates only its frozen
child and commits through the existing CAS with `RoleClaim::Keep` and its own
atomic save: failure preserves only that transaction, successful siblings remain
and may change effective defaults/content, and exit 1 can accompany a committed
adoption. ADR-0067 D9's host-first recommendation seed remains the sole
host-authority exception. Adoption carries H's snapshot observation to the
existing CAS: an observed but vanished H is stale, genuinely absent H permits
Insert, and live equal content reconciles under S3. No tracked-input role exists
in S4.

Reporting is one ordered row per operation plus a summary on stdout, with fixed
role/default labels and full digests; a closed report sink is a bounded warning,
never a failed approval, while a consent render failure remains precommit-fatal
for its own operation with an operation-scoped reason. USAGE's "Refreshing
in-use images" is the user-facing contract.

## Serialized shape

```json
{
  "version": 2,
  "pins": [
    {
      "project": "<64 hex>",
      "reference": "docker.io/library/app:dev",
      "platform": {"os": "linux", "architecture": "arm64", "variant": null},
      "manifest_digest": "sha256:...",
      "revision": 8,
      "roles": "boot"
    },
    {
      "project": "<64 hex>",
      "reference": "docker.io/library/app@sha256:...",
      "platform": {"os": "linux", "architecture": "arm64", "variant": null},
      "manifest_digest": "sha256:...",
      "revision": 11,
      "roles": "output"
    }
  ],
  "pending_default": null,
  "defaults": [{"project": "<64 hex>", "image": "docker.io/library/app@sha256:..."}],
  "scopes": [
    {"project": "<64 hex>", "platform": {"os": "linux", "architecture": "arm64", "variant": null},
     "resolved": "boot-and-output"}
  ],
  "sequence": 12
}
```

A store with no roles/scopes/sequence decodes as "both roles unknown" and is
re-encoded without the new fields until a real save.

## Transitions

| Before | Successful operation | After | Why X survives/retires |
|---|---|---|---|
| old X; ∅ | publish X=A | Output resolved; X holds Output | Claiming Output says nothing about Boot. |
| preceding | publish Y | Y holds Output; X unheld | X survives unknown Boot. |
| preceding | prepare Z | Z Boot; Y Output; X deleted | Both roles now resolved; X is known-absent. |
| old X; ∅ | prepare X, then Y | Y Boot; X unheld | X survives unknown Output. |
| preceding | publish Z | X deleted | The missing slot resolved. |
| both resolved; X both | publish Y | X Boot; Y Output | Shared Boot protects X. |
| preceding | prepare Y | Y both; X deleted | X lost its last role. |
| both resolved; B Boot/O Output | `AGENT_VM_IMAGE_TAG=U` refresh | U unheld | Refresh claims and prunes nothing; a `--image U` refresh would be refused as a nonmember. |
| preceding | prepare B | B Boot; U deleted | A same-target claim retires known-inactive records. |

## Alternatives rejected

- **Claiming any role clears all uncertainty** (the original design): silently
  authorizes content the old boot or output still needs.
- **Permanently protect every unclaimed record**: never converges; a store only
  grows and cannot express affirmative absence.
- **Per-record unknown bits**: duplicates scope knowledge N times and permits
  contradictory states after one missed update.
- **Top-level slot pointers or per-key high-water history**: duplicate canonical
  identity / unbounded retired-key history and a second identity to forget.
- **Per-key revision arithmetic, reset-to-1, or max-live-revision after S3**:
  forgets retired maxima and reopens retire/reinsert ABA.
- **New store version, migration or reset**: owner-forbidden; optional fields
  appear only on an actual save.
- **Migrating old records to concrete roles**: invents evidence.
- **Refresh with its own permanent role**: contradicts single-holder evidence.

## Consequences

- First warm claims, scope resolution and justified cleanup need the store
  writable; a complete no-op remains read-only and byte-identical.
- Revisions are opaque global tokens; exact per-key 1, 2, 3 expectations no
  longer hold, and gaps are expected because metadata saves allocate too.
- A committed build/import may warn about unreported checkpoint/notice but still
  exits 0; the warning must not be retried as a failed publication.
- `image show` continues to report the ambient next-launch selection, not
  the last acquisition. In 0.7.56, `image pins` is the explicit offline,
  read-only private-reference disclosure surface: one tab-separated row per
  invoking-project approval, across all platforms, sorted by canonical
  reference bytes then rendered platform bytes. Its header is `REFERENCE`,
  `PLATFORM`, `DIGEST`, `REVISION`, `ROLES`, `UNRESOLVED`; fields are separated
  by TAB and rows by LF. Digest and revision are the approved full child and
  its global token. ROLES projects Present knowledge; UNRESOLVED projects
  Unknown knowledge from the scope join, in boot/output order. Each column
  uses `boot`, `output`, `boot+output` or `none`, not the stored mask spelling.
  Legacy records with no held role display `none` with unresolved slots,
  never "unclaimed, safe to drop". Unclaimed means neither role is Present;
  retirement still requires both Absent. Missing/empty state prints the
  header only; unavailable/damaged state prints no listing and exits 1;
  extra arguments exit 2. The existing regular coordination file is required
  for a present authority but is never opened, locked or created by this
  projection. No schema change or migration is introduced. Doctor adds one
  count-only, reference/digest-free `active images:` row after `project
  default:` on the host platform: recorded/not-recorded Boot and Output,
  unclaimed count and escaped store path. It reports safe error/unknown
  states even when configuration is broken; located authority damage fails
  the diagnostic. The invalid-environment early return has no project-default
  row and prints active images directly after its environment refusal; it
  returns no active failure on that branch so the unchanged invalid-env
  diagnostic keeps stderr precedence and exit 1, including with damaged
  authority. Absolute non-UTF-8 HOME remains supported by the existing path
  policy. Host-default-only damage does not prevent the listing or the
  available active-images row. See USAGE's "Inspecting approved
  images" for the literal output and escaping contract.
- S5a (#544) pinned build inputs and S5b
  (#545) Dockerfile coverage remain separate; no placeholders are added.

## Verification

The knowledge transition, retirement predicate and checked-next allocation are
machine-checked (ADR-0018). Trusted adapters — strict decode, the scope join,
the max-legacy fold and the sealing/CAS tuple propagation — are covered by
concrete tests: 36-row knowledge and 9-pair retirement tables, literal old-v2
byte fixtures for both legacy-role sequences, four independently valid
count/byte/scope capacity fixtures (the byte-bound one is a metadata-only claim
whose only added bytes are the role mask, the resolution and the sequence digit),
global-allocation and exhaustion tests, recovery allocation, and retire/reinsert
ABA on every path that has one: refresh and publication (changed content, gated
before the pin lock), the warm claim (gated before the pin lock, and again
between the consumed tuple and the claim), and the store fixture where the
retired record holds the high-water revision. The CLI tests cover one-off Boot
switching, a warm changed-alias return, an archive alias after retirement that
supplies the next pin, committed-success warnings on both reporting failures, a
first pin that must not fall back to a peer's winner, a failed Boot-claim save,
and a literal old-v2 claim followed by a byte-identical no-op.

Publication CAS keeps `commit_decision`'s existing contract (R9): a candidate
whose digest equals the live record's claims the role on that live lifetime
(`AlreadyApproved`) without allocating a token. A warm Boot claim compares the
complete predecessor tuple and a *changed-content* refresh needs
`predecessor_matches`; an equal-digest refresh reconciles on the live record just
like a publication, because both go through the same `candidate_equal` /
`commit_decision` seam (a refresh passes `RoleClaim::Keep`). The asymmetry is
the spec's: AC21 scopes the publication ABA to changed content, and AC22 makes
warm verification revision-exact. So an equal-digest publication is
byte-identical to one that started after that state existed — which is also why
it is not a lifetime-exact freshness promise.

S4 adds the refresh worklist proof obligations: the `refresh_member` kernel is
machine-checked (ADR-0018) over its facts, and the adapters — the strict read-only
scope snapshot, canonical reference equality, the exact project/platform/variant
scope and the held mask — have concrete tests, including an unheld ambient
selection, a retained-but-unheld exclusion and both foreign-scope controls. The
named membership, adoption-substitution, observed-H retirement, absent-H insert,
damaged-selection refusal, partial-progress and closed-pipe CLI rows are listed in
the S4 plan (§7).
