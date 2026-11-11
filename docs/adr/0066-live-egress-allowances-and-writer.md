# ADR-0066: Live egress allowances, protocol v2, and the writer's no-reset guarantee

## Status

Accepted and implemented in **0.7.45**
([#557](https://github.com/gregwebs/agent-vm/issues/557) slice 2, PR 2, the
writing and live half). It completes
[ADR-0065](0065-project-allowance-record.md), whose read side shipped in
`0.7.44`, and inherits every decision there: one store, one project identity, an
authority store that refuses rather than heals.

Amends [ADR-0018](0018-machine-checked-boundary-contracts.md) (one more proved
kernel, `config_authority::authority_dir_refusal`), and annotates
[ADR-0037](0037-hostname-egress-allowances.md) (intercepted ports stay fixed at
launch; a live change may only narrow) and
[ADR-0064](0064-read-only-refusal-feed.md) (the applied level is this ADR's).

## Context

ADR-0065 answered *where a project's durable egress authority lives*. It left
four questions that cannot be answered one at a time:

1. **Who may write it, and what happens when it is broken.** A writer is a second
   reader with an opinion. If it "repairs" a file it cannot decode, it decides
   authority on content nobody measured, and a launch that used to degrade now
   starts with a different policy.
2. **How a running VM's policy changes.** The runtime's `NetworkPolicy` is
   replaceable (`Sandbox::update_network_policy`); its TLS interception and UDP
   drop ports are not. A grant that adds an intercepted port would emit a
   `Domain` rule on a port nothing intercepts — a rule the user reads as "this
   hostname is allowed" and the guest cannot reach, or worse, a plain-TCP path
   the rule does not cover.
3. **What a revoke guarantees.** The ticket's promise (#299) is that after a
   successful revoke, new matching connections are refused. A store delete is not
   that promise: a running sandbox keeps its policy until something replaces it.
4. **What an older runtime does.** A runtime without `network_policy_update`
   cannot swap a policy. Treating that as a failure would fail a command whose
   durable half — the record — still works.

## Decision

### 1. One writer, one lock, and a refusal instead of a repair

`allowances::record` and `allowances::forget` are **one whole-file
read-modify-write** under a stable, never-unlinked
`~/.config/agent-vm/allowances.lock` (`flock`, bounded wait `store::LOCK_WAIT`,
`on_contention` observable), replacing `allowances.json` atomically at mode
`0600`. The directory is verified through the Verus-proved
`config_authority::authority_dir_refusal` **before** the lock is opened and again
**under** it, because the directory could be replaced while the writer waited.

The writer refuses every state other than `Absent` and `Current` (`v == 1`):
`Newer`, `Damaged`, `Untrusted`, `Unreadable`, `Unsettled`. In all of them the
file keeps its exact bytes, inode, mode and mtime. Writes are idempotent by
bytes, inode and mtime: re-recording an existing `(project, destination)` and
forgetting an absent one call no write at all. Every other record keeps its
decoded field values, including a `destination` this build cannot parse and
another project's rows. `Full` is decided before anything is replaced
(`store::MAX_RECORDS` or `store::MAX_BYTES`), and a non-UTF-8 project path is refused before a lock
is opened.

### 2. No reset, and why "reset only narrows" is false here

ADR-0065 Constraint 4 asked for this to be re-argued rather than assumed. It is
false at the sandbox level: on the **next launch**, a recorded hostname turns on
TLS interception and UDP dropping for its port. Deleting that record ("resetting"
a damaged file) would leave a guest that still holds a numeric or group grant
able to reach that port over plain TCP and UDP. A writer that resets therefore
*widens* reachability while looking like it restored a default. **No reset, no
archival, no `.damaged` replacement**: the writer reports the state and changes
nothing. The user decides, with the message's own remedy ("move it aside to start
over").

### 3. Protocol v2 on the existing socket

`<state root>/<hash>.sessions/<sid>.sock` speaks protocol **v2**:
`SUPPORTED_VERSIONS = &[1, 2]`, adding `grant`, `revoke` and `allowances` to the
existing `list` and `subscribe`. The peer-UID check, the 4 KiB request cap, and
the connection/subscriber budgets are unchanged.

* A **lenient** `VersionProbe { v }` is decoded *before* the strict request, so an
  unknown version that carries a later version's extra fields is answered
  `unsupported-version` with `supported: [1, 2]`, never `bad-request`.
* `v: 1` keeps `list` and `subscribe` with `v: 1` replies, so an older client sees
  byte-identical answers; a `v: 1` mutation is refused.
* The client uses `session_control::MUTATION_TIMEOUT` for `grant`/`revoke` and
  `session_control::EXCHANGE_TIMEOUT` for `list`/`subscribe`/`allowances`. The
  mutation timeout exists to **outlive the runtime's own control-request deadline**
  plus the store's lock wait plus write slack: a client timeout shorter than the
  runtime's would race a swap that is still going to commit. There is deliberately
  **no** launcher-side wrapper timeout around the swap.

### 4. One policy computation, and a swap that can only narrow

Every live change computes `session ∪ project` (deduplicated by canonical value)
and passes it to `network::LivePolicyPlan::derive_for`, which clones the launch's
`EgressAuthority`, calls `set_recorded`, checks that no hostname is present when a
host HTTP proxy is in use, requires
`candidate.intercepted_ports() ⊆ launch_intercepted_ports`, and returns
`EgressAuthority::policy()`. No second copy of rule assembly exists: a live
policy is the launch's own computation over a different recorded set.

The subset rule is the whole of the port story. **Removing** hostnames — including
the last one — narrows within the launch's fixed ports and is allowed: the TLS
listener and UDP drop stay in place, so only `Domain` rules disappear.
**Adding** a port outside the launch's set is refused for a session grant and
recorded for the next launch when the grant is `--project`. `launch_intercepted_ports`
is captured once and carried unchanged through every derivation.

### 5. Confirm-before-record, and demotion when the store fails

For a live `--project` grant the order is
`derive_for → update_network_policy().await → store.record`. No record is written
before the runtime confirms a revision, so a socket that cannot answer leaves the
store untouched and the command exits non-zero.

If `store.record` fails **after** the runtime confirmed `Ok(rev)`, the allowance is
in force in the sandbox and cannot be un-applied honestly. It is therefore
**demoted in memory to session scope** with `not_recorded_error`, never kept as a
project row. The immediate reply and every later `agent-vm access` /
`agent-vm access allowances` render the same sentence:

```text
applied session allowance <dest> (<when>); applied to this session only (rev <rev>), not recorded for the project: <escaped error>
```

### 6. Applied coverage needs a revision after the refusal

`Coverage` gains `Applied { scope, destination, recorded_ms, revision,
not_recorded_error }`. A row is `Applied` only when a confirmed revision satisfies
`revision > entry.last_revision`: a record in force at boot (`rev 1`) did not
apply to a flow the runtime refused at `rev 1`, and `None` never confirms. The
port set for a hostname probe is computed over **every confirmed hostname in both
tables first**, because the runtime's interception is host-wide.

### 7. Revoke's conditional guarantee

`agent-vm access revoke <DEST> [--project | --session-only]` deletes the project
record whenever the scope includes the project, **before** the command can exit on
a session failure, and leaves it untouched for `--session-only`. Inside the
launcher, entries are removed from memory only when the runtime confirms
`Ok(rev)`; a `None` revision (queued before boot) needs no swap.

* Confirmed: new connections are refused at the new revision; connections already
  open keep running, which is what a policy replacement does.
* Unconfirmed (`SandboxStarting`, `RuntimeUnsupported`, `RuntimeFailed`,
  `PolicyNotDerivable`, `BootPending`, or a socket that does not answer): the
  record is still deleted, memory is unchanged, the session is named with its
  state, the command says that stopping the session is the guaranteed hard cut,
  and it exits `1`.
* `still_effective` is a fact about the **derived policy**, so a launch's own
  `--allow-egress` (or the user `[network]`) grant is never claimed revoked: a
  destination no allowance names, and that nothing else admits, is reported as
  *not an allowance of this session* — never as "not in force" — and with no
  revision, because no swap was made.
* A revoke that needs a swap is refused while the boot queue is still pending
  (`BootPending`): a swap then would carry entries the flush has not confirmed,
  and the flush is the only writer of that policy.

### 8. An older runtime gets a next-launch record

When `update_network_policy` returns `Unsupported`, the destination is written as
a next-launch project record (with or without `--project`), one sentence says so,
and the command exits `0`. A store failure there exits `1`; the command is never a
silent no-op.

### 9. Session allowances are memory, and every change is target-only

`SessionAllowance` lives only in the launcher's `LiveAllowances` and vanishes at
teardown; it is never written to `allowances.json`, `refusals.json` or any other
file. Every live change targets **one** session. Sibling sessions are named with
their state (`running`, `running (no control socket)`, `not responding`, `ended`,
`ended (unclean)`) before and after the change, and told that only a relaunch
changes them. There is no `--all-sessions` and no broadcast; that is #558.

A grant that arrives between `LiveSession::start` and `follow(&sandbox)` — and any
grant or revoke that needs a swap while the queue is still pending — is
**queued or deferred** (`revision: None`) and reported with wording that promises
nothing before the flush runs. `follow` attaches the runtime synchronously and
flushes the queue: success promotes the entries to the runtime's revision; failure
drops every queued entry and restores the plan the runtime last **accepted** (not
the boot plan, which an intervening accepted swap would make a lie), and prints one
notice per destination saying it was not applied and whether a project record still
carries it to the next launch. Because no swap may carry an unconfirmed entry, a
failed flush can never leave memory denying an allowance the sandbox enforces.

## Alternatives rejected

* **Reset or archive a damaged/untrusted store on write.** Rejected in Decision 2:
  it can widen guest plain-TCP/UDP reachability at the next launch, and it decides
  authority on unmeasured content (ADR-0047, ADR-0065 Constraint 3).
* **A second, smaller policy builder for live changes.** Rejected: two rule
  constructions drift, and the drift is invisible until a grant means something
  different from a flag.
* **Allow a live hostname on a port the launch did not intercept.** Rejected: the
  runtime would emit a `Domain` rule for a port with no TLS listener, and the
  alternative (turning interception on live) is not in the runtime's API.
* **Write the project record first, then apply it.** Rejected: an unresponsive
  socket would leave a durable grant for a change the session never accepted
  (R9).
* **Keep a failed store write as a project row.** Rejected: later reads would say
  "applied project allowance" and lose the failure; Ruling 2's demotion keeps the
  sandbox truth and the store truth separately legible.
* **Broadcast a grant/revoke to every running session.** Deferred to #558 by D4;
  a broadcast makes the reply's exit status a summary rather than a fact.
* **A launcher-side timeout around the swap.** Rejected: a timeout below the
  runtime's 30 s deadline abandons an in-flight swap that may still commit.

## Consequences

* The writer needs the directory's trust twice (before and under the lock), and
  every write is one small file replacement at `0600`.
* A live change is a full policy replacement; a very large record set costs a
  policy rebuild per change, not an incremental update.
* Live grants cannot add a TLS-intercepted port. A user who needs one relaunches
  with the hostname, or records it with `--project` and gets it at the next launch.
* Every live change is per session. Making a project-wide change to running
  sessions is a deliberate relaunch (or #558).
* `access` can now say *applied*, and only when a confirmed revision is later than
  the refusal it names.
