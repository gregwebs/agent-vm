# ADR-0065: The project allowance record (read side)

## Status

Accepted and implemented in **0.7.44**
([#557](https://github.com/gregwebs/agent-vm/issues/557) slice 2, PR 1, the
read-only half). This release **reads** the record and never writes it. PR 2
adds the writer (`record`/`forget` under `allowances.lock`, archival, the
preservation of other projects' records), protocol v2 on the slice-1 control
socket, the runtime policy swap, session allowances, and the verbs
`access allow|allowances|revoke`; those are **not** decided here.

Amends [ADR-0038](0038-config-dir-exposure-guard.md) (its Decision 2 one-link
check covers one more file) and annotates
[ADR-0064](0064-read-only-refusal-feed.md) (recorded coverage is this ADR's;
applied coverage is PR 2's).

## Context

[ADR-0064](0064-read-only-refusal-feed.md) made a sandbox refusal something a
user can read: a row per destination, with the reason nothing could be done.
Every network-denial row says `no grant in this version`. The next question is
the natural one — *can this destination be allowed for this project, permanently,
without widening every launch?*

Three things had to be settled together, because each constrains the others:

1. **Where the authority lives, and whose it is.** A grant that belongs to a
   project must not follow the project's *contents*: a moved, copied or cloned
   directory is a different project, or an untrusted copy of one. The existing
   project identity — the full SHA-256 of the captured path's bytes
   ([ADR-0063](0063-project-scoped-oci-image-approval.md) D2) — is the only
   identity in the codebase with that property, and it is already what state
   directories and image approvals use.
2. **What a broken store means.** An authority store that heals authorizes
   content nothing measured ([ADR-0047](0047-host-wide-oci-image-approval.md)).
   But a store on the *launch* path that refuses would turn a hand-edit mistake
   into "agent-vm no longer starts", which is a worse failure than losing the
   grant. The two rules pull in opposite directions, and the resolution is that a
   broken record **degrades**: it is not applied, it is named once, and the
   launch keeps exactly the authority it configured.
3. **What `access` may claim about a record.** A record on disk is not evidence
   that a *specific past session* had it in force. Claiming application would be
   a lie the command cannot check, and the version that can check part of it
   (PR 2's runtime revisions) is not this one.

## Decision

1. **The store.** `$HOME/.config/agent-vm/allowances.json` is
   `{"v":1,"records":[{"project","path","destination","recorded_ms"}]}` — one
   flat record per (project, destination), each carrying its own project column,
   as `image-pins.json` does (ADR-0063 D3). Unknown fields are refused: a
   restricting field an older build silently ignored would widen authority, so
   any later field bumps `v`. `destination` is canonical **config-grammar** text
   (`Allowance`'s own `parse`/`Display`), never a structured copy, so the record
   and a `--allow-egress` entry cannot mean different things.

2. **One identity, and `path` only to find orphans.** `project` is the full
   SHA-256 of the canonical project path's bytes; `path` is that digest's
   preimage and must hash to `project`, or the file is damaged. A project whose
   path is not UTF-8 matches no record — no conversion happens anywhere on the
   read path, so it gets an empty view without an error.

3. **Trust is ADR-0040's, unchanged.** The file is read under the proved kernel
   `config_authority::authority_refusal`: the directory is owned by the euid and
   is not group- or other-writable; the file is not a symlink, is owned by the
   euid, is not group- or other-writable, and has exactly one link. A symlink is
   *untrusted*, never "damaged"; mode `0644` is trusted, as ADR-0040 always said.

4. **Coverage has three levels, kept apart in code and in words.**
   - **Recorded** — a usable record for this project names the entry's
     destination. This is the only level this release computes.
   - **Admissible** — the runtime's own evaluator would admit the flow under a
     policy containing that record. Never computed in production; it is the
     tests' oracle.
   - **Applied** — this session's runtime had the record in force and allowed a
     matching flow. Unknowable here; PR 2's revisions give part of it.

   `ProjectAllowances::covers` is a **conservative, syntactic, record-level
   query**: protocol, port, CIDR membership, exact name, and the runtime's own
   site/name-source vocabulary, compared only like-for-like (`Cidr`↔address,
   `Domain`↔name). It errs towards "not recorded" wherever it cannot be exact,
   and every conservative negative below has a named test.

5. **A broken store never fails a launch.** Absent, empty, undecodable, an
   unknown field, a wrong digest, a duplicate, a directory/FIFO/socket at the
   name, a symlink, over 1 MiB, an older `v`, a foreign owner, a
   group/other-writable file or directory, and an unreadable file each produce
   **one** notice and leave the configured authority in force. A newer `v` is
   `Newer`, not damage: nothing is applied and `doctor` counts it. A path
   replaced between `open` and `fstat` is retried (`nlink == 0` is a healthy
   rename, never distrust), at most three attempts, then `Unsettled`.

6. **The guard's one-link check covers the record.** In every measured home
   (ADR-0038 Decision 2), `allowances.json` with `nlink != 1` refuses the
   **launch** (E1), and so does a file the guard cannot `lstat` for any reason
   other than `NotFound` (E2). E2 fails closed rather than deferring to the
   reader: declining to apply the file now would not stop a guest laundering it
   into the *next* launch through a second name removed before that read, which
   is the reason the check exists at all. Both exceptions are the only launch
   refusals this feature adds; `mount::prepare` runs before the reader, so they
   pre-empt any notice.

7. **The record joins one computation, at boot.** `run::launch` reads the store
   **after** `LiveSession::start` (ADR-0064 AC9) and **before** the egress
   notices, and hands the set to `EgressAuthority::set_recorded`, which replaces
   the recorded set and recomputes `effective = configured ∪ recorded`. Every
   derived view — rules, intercepted ports, the TLS on/off decision, request
   coverage, notices — reads `effective`, so a recorded entry behaves exactly
   like the same `--allow-egress` entry.

## The guarantee

A record reaches the launch of **its own project only**, and only when the file
and its directory are the user's own, singly named and not group- or
other-writable. Every derived view of that launch equals the view of a launch
whose configured set also contained the record. Nothing a guest can write
decides what a launch allows, and no read path creates, modifies, renames or
locks anything in the authority directory.

## Consequences

- **A recorded hostname has a configured hostname's *global* interception
  effects.** [ADR-0037](0037-hostname-egress-allowances.md) made TLS interception
  host-wide: an intercepted port routes TCP through the TLS proxy and drops UDP.
  So on a launch where the only hostname is a recorded one, plain TCP to an
  *address* on 443 must now be TLS with an SNI, and UDP to 443 is dropped —
  including for flows the record does not name. The launch's TLS-interception
  notice states this. "Adding rules only widens" is a claim about the **rule
  vector** (`default_egress` is `Deny` and every emitted rule is `Allow`); it is
  *not* a claim about sandbox behaviour, and this is the case that shows why.
- **A host HTTP proxy skips hostname records.** The runtime resolves those names
  on the host, so the sandbox never sees an SNI it could verify. A *configured*
  hostname refuses the launch; a **recorded** one must not (decision 5), so it is
  skipped with one notice and its address records still apply.
- **`access` says `recorded …; not confirmed for this session`.** A covered row
  names the record and when it was made, and never claims the session applied it.
  Divergences the query cannot see — no DNS binding, rebinding protection, a
  session that started before the record, a skipped hostname under a proxy, an
  address on a port another hostname intercepts — are listed in USAGE, not
  compressed into the cell: every conditional clause there would itself be a
  claim the query cannot check.
- **`doctor` reports the store and exits nonzero when it is not in use.** The
  section prints the file's state, this project's records, other projects,
  orphans (a record whose project path is gone) and uninspectable paths; the
  failure is returned after every later section has printed, so a broken store
  costs the exit status, not the report.
- **No writer means no way to create a record in this release.** USAGE says the
  file is machine-written by a later release and must not be edited by hand.

## Conservative negatives

These are the shapes where a flow would be admitted and this query still says
"not recorded". Each is a named test, because each is a deliberate refusal to
claim more than can be checked syntactically:

| Case | Why `covers` says no |
|---|---|
| An address admitted by a hostname record through the DNS cache | the record names a name, the entry an address |
| A hostname admitted by a CIDR record over its last IP | a `Cidr` rule ignores the name source |
| An address denied at `tls-sni`/`tcp-hostname` | the site gate: the name, not the address, was decided |
| A NAT64 projection | the runtime projects a v6 destination onto its embedded v4 |
| A bare recorded name on a port only a *configured* entry intercepts | the recorded port set decides, not the launch's |
| A `dns-resolver` refusal | that site decides on the resolver's address |
| A `tls-sni` refusal whose first name source is an HTTP `Host` | that name was not the one TLS verified |

## Alternatives rejected

- **A host-wide record, or one keyed by the project's contents.** A grant that
  follows a copied directory is a grant that follows a `git clone` an agent made.
- **A record that heals, like the refusal log.** Healing authorizes content
  nothing measured (ADR-0047); the refusal log heals precisely because it
  authorizes nothing.
- **Refuse the launch on any damaged record.** One hand-edit would make agent-vm
  unusable, and the failure would arrive with no way to see what the policy is.
- **Apply nothing when the file is newer.** A newer file is not broken — and
  "replace it" is the writer's decision, which PR 2 must make *before* the size
  and trust classifications can reset it.
- **Read the store through a lock.** A lock is a write. Readers of an
  atomic-rename store need none, and a read path that creates its own lock would
  let "ask what this project allows" manufacture authority.
- **A structured destination in the schema.** Two grammars for one grant is how a
  record and a flag come to mean different things.
- **Let `access` filter out covered rows.** A refusal stays evidence of what the
  guest attempted; hiding it would make the table disagree with the log.

## Verification

The schema, the trust matrix, the reopen rule (with a checkpoint between `open`
and `fstat`), every read state, the two policy-computation views and the notice
goldens are unit-tested against the runtime's own evaluator as an oracle, with
`Recorded ⇒ Admissible` as a property over mixed sets and exactness
(`⇔`) asserted only for address-only sets and DNS queries. The launch path is
proved twice: `network`'s unit tests for the applied policy and TLS decision, and
a real binary driven to `builder.build()` under `$HOME`/`AGENT_VM_STATE_DIR`
isolation. The guard has unit cases with an injected `lstat` and CLI cases for a
hard link; `access` is tested in process and as a process; `doctor`'s section and
its exit status are tested through the real binary. The end-to-end case
(`PA1`/`PA1x` in `script/test/lib/egress-fixtures.py`) hands `tcp://{lan}:18080`
to one project by record and the same record to another project's digest, and
the boot-free dispatch contracts prove both before any VM boots.
