# ADR-0077: Pinned configuration sources

## Status

Accepted for [#736](https://github.com/gregwebs/agent-vm/issues/736), the fifth
of ten stacked children of [#732](https://github.com/gregwebs/agent-vm/issues/732).
Amends [ADR-0038](0038-config-dir-exposure-guard.md),
[ADR-0040](0040-persisted-user-network-authority.md) and
[ADR-0076](0076-sources-tables-trust-and-allow.md). Bumps the workspace version
to **0.8.4** inside the unreleased 0.8.x line.

Amended by [ADR-0078](0078-project-config-writer.md): `image set-default` writes
only the project config's root `image`; it does not take `pins.lock`, review,
reset, write or record source pins. A valid config with an unapproved source can
therefore receive that narrow edit and still fail to load under this ADR.

## Context

A `trust = false` source is repository-controlled input. Its pathname may be
stable while its bytes change with a branch, checkout or symlink target. Reading
and decoding those bytes before consent lets a changed file change the catalog
or authority fields. Refusing `allow = true` alone was insufficient: an
`allow = false` file can become relevant later, and treating it differently
would make the two booleans an accidental approval boundary.

The project store is already host-managed. It can retain a reviewable content
history without putting approval state in a repository file. The launch path
must still remain non-interactive when it has no foreground terminal.

## Decision 1: every untrusted source is content-pinned

Every `trust = false` entry is pin-checked, regardless of `allow`. The
`config::read_source_tier` pipeline in `crates/agent-vm/src/config.rs` route-reads
once, charges the shared source-byte budget, rejects a self-source by opened
identity, hashes that exact buffer, and looks it up before UTF-8 or TOML
decoding. A pending buffer is not parsed, cataloged, recorded as inert or
adopted. An approved `allow = false` source remains inert; an approved
`allow = true` source may adopt its top-level fields.

`PinsContentPolicy::check_untrusted_source` in
`crates/agent-vm/src/config_pins.rs` can mint `ApprovedSourceContent` only with
the private `match_witness::ApprovedHashMatch`. The witness comes only from a
`Current` approved-set lookup for the normalized source path and the hash of
those bytes. Code cannot pair arbitrary bytes with an approval token.

A relative spelling is checkout-scoped. If its route leaves that scope, the
read is refused and the outside file must be named with an absolute or `~/`
spelling. A relative `..` may still move within an enclosing worktree boundary.
An absolute or `~/` spelling outside the checkout is an external source —
unless the captured root no longer resolves to the identity captured for it,
which is refused as a replaced root whatever spelling reaches it. This is a
source-path dialect, not a claim that an outside file is hostile.

## Decision 2: the project store is the approval authority

Each host-managed project store is
`~/.config/agent-vm/projects/<project-id>/`, beside `config.toml`.
`config_pins.rs` defines its strict version-1 `pins.json` manifest: a generated
store id, reset epoch, normalized source-path keys, approved SHA-256 digests and
one recorded `active` digest per key. `Current` validates and canonically
encodes that state. Snapshots contain the exact UTF-8 approved text and are
named `pin-<32hex>-<64hex>.toml`; the store id makes a snapshot from a reset or
recreated store unreachable.

`config_pins/store.rs::PinStore` reads and writes through directory descriptors.
At that boundary it applies [ADR-0040](0040-persisted-user-network-authority.md)'s
owner/mode policy directory-first: it opens and verifies `projects/`, then the
project store, before admitting a directly reached regular `pins.json` with the
same owner/mode rules and exactly one link. The project-config read path now
also checks `projects/` this way (B7); that deliberate tightening applies even
when the project config already existed. `pins.lock` is a permanent coordination
inode, never an authority file and never unlinked.

This relies on ADR-0040's stable-outer-ancestry assumption. It also accepts the
cost of refusing a hard-linked source reached after the route enters the
checkout. Shared locks protect a diff's manifest and snapshot baseline;
exclusive locks serialize commits. Snapshot publication precedes the atomic
manifest replacement. Rename makes that replacement atomic; it is not a
power-loss-durability claim. Post-commit cleanup or lock-header finalization may
warn but does not undo a committed approval.

The baseline is the key's recorded `active` hash read under that same shared
lock and its snapshot is re-hashed before the lock is released. `active` is a
recorded diff baseline, not evidence that a VM booted. It is not a file mtime or
the pending reason observed before acquiring the lock. A snapshot is review
material, not approval authority. An approved but inactive version launches
without a new review; `pins_cmd::record_active` then best-effort records it as
active through `PinStore::update_recording`. That recording waits at most one
second on the lock, is nonfatal, and does not retry on the launch path.

## Decision 3: approval is a bounded foreground review

`pins_cmd::gate` in `crates/agent-vm/src/pins_cmd.rs` prompts only when all
three facts hold: `config::load` returned typed `UnapprovedSources`, the real
`cli::preflight_unapproved_route` accepts a direct or tool launch, and
`StdTerminal::detect()` finds stdin and stderr on this process's foreground
terminal. `doctor`, help, version, built-ins, invalid routes, `agent-vm config
…`, redirected stdin or stderr, and other non-interactive runs refuse without
writing. Redirected stdout alone does not make a launch ineligible.

The review renders the exact pending bytes against the recorded baseline. If a
render limit is crossed, it refuses rather than truncating and never offers
`[y/N]`. A yes commits the reviewed batch, then reloads once. If a source has a
still-unapproved hash, that reload refuses it normally; it does not open a
second prompt. Concurrent approval can instead leave nothing to ask, followed
by that one reload. Two reviewers may review concurrently, but the commit
rechecks the live generation under the exclusive lock.

### Review flow and alternatives

```text
load → pin check → review → commit → reload → dispatch
                  │                    │
                  └─ no eligible terminal: refuse
```

The manifest retains an approved set, rather than one digest, so returning to an
already approved digest does not require another review. The review compares
with the recorded active hash, rather than a snapshot mtime, because the active
hash is the baseline selected under the shared lock. These are separate choices:
retention decides approval; `active` decides comparison.

The refusal advises `agent-vm config diff` and `agent-vm config approve` for a
future non-interactive workflow. Those subcommands do **not** exist until #739;
the advice is not an available command today.

## Decision 4: review text is not secret-safe input

No resolved credential is fetched, interpolated or printed during pinning.
`config_pins/diff.rs::render_review` renders the review transcript without a
debug, error or log path; pending and snapshot bytes never enter one. The review
diff intentionally displays raw configuration text, however, and the snapshot
intentionally stores it under the protected project store. A source therefore
must not contain secrets. General redaction is deliberately absent: it would
make exact review unreliable.

## Decision 5: the guard measures protected pin files without wedging siblings

`protected_config_dir::project_store_file_links` in
`crates/agent-vm/src/protected_config_dir.rs` treats `pins.json` and every
case-insensitive matching snapshot name as protected pin files. It refuses a
hard link on `pins.json`; a matching snapshot must also be regular, user-owned,
not group- or other-writable, and singly linked. The current project's store
must be a directory; an entry that cannot be classified as one is refused rather
than skipped.

`pins.lock`, pin temporary files and non-snapshot names are deliberately not
admitted as snapshots. They still count as directory entries; a sibling also
spends its enumeration work, but they do not consume snapshot-stat work.

`ProtectedConfigDir::measure` receives the current store from the captured
project and authority HOME. It measures that store directly and first, matching
later siblings by directory or `pins.json` identity rather than spelling. The
current store receives its full 2,048-entry reservation. Every other project
store shares one 8,192-unit `MAX_SIBLING_SNAPSHOT_WORK` budget across every
measured HOME; enumeration and a matching snapshot stat each cost one unit.
A sibling cut short by either limit emits a warning that its scan was bounded;
its exact `config.toml`, `pins.json` and route remain fail-closed.

## Accepted gaps and policies

- The bounds have separate purposes: `MAX_DECLARED_SOURCES = 32` limits project
  declarations; `MAX_SOURCE_BYTES_TOTAL = 4 MiB` limits every load's source
  reads, including pending bytes; `MAX_PINNED_KEYS = 64` limits retained
  approval keys; `MAX_PROJECT_STORE_ENTRIES = 2048` limits one store scan; and
  `MAX_SIBLING_SNAPSHOT_WORK = 8192` bounds all sibling snapshot work. They are
  not interchangeable budgets.
- `trust = true` sources remain outside this pin store. They use ADR-0076's
  verified route/read policy instead.
- Pinning approves a source buffer, not its other repository files, runtime
  mounts or a successful VM boot. A digest not already approved needs approval;
  returning to an approved digest does not.
- The store verifies snapshots when they are used for a diff. An unavailable
  snapshot yields an explicitly unavailable empty baseline rather than new
  authority.
- Approval serialization is at commit, not at the prompt. There is no global
  prompt mutex.
- `pins.lock` is never removed. For a stuck lock header or interrupted rotation,
  quiesce the project and restore the store's `pins.json` and snapshots from
  backup; do not delete the lock. For an over-cap store scan, quiesce the
  project, remove only confirmed orphan snapshots and abandoned temporaries,
  and keep `pins.json` and `pins.lock`.
- The replaced-root check names the captured root's own entry in the parent
  descriptor the walk already holds, so every spelling of that root — relative,
  absolute, case or normalization variant — is decided by the same `(dev,
  ino)`, and no name comparison decides a replacement. The root's authority in
  the checkout boundary comes from that capture rather than from a second look
  at the path; enclosing worktrees are still discovered from the path, which can
  only widen the boundary and so can only add a refusal. Every step then stats
  its own name and requires the descriptor it opens to carry the identity that
  stat saw, which turns a swap between those two syscalls into a refusal instead
  of a read; a symlink step pairs its `readlinkat` with a second stat for the
  same reason. Around the captured root the checkpoint also requires the parent
  directory's `mtime` and `ctime` to be unchanged between the check and the
  open, which catches a swap that both the step's stat and its open agree on.
- Three limits are stated rather than closed. The directory-stamp guard assumes
  a filesystem whose timestamps separate two renames inside one step — true on
  APFS and ext4, not guaranteed on a coarser one. The same guard refuses a
  legitimate read when *anything* renames a name in the project directory's
  parent during that step: it is fail-closed and a rerun works, but a script
  churning its parent will see refusals, not successes. And a symlink step reads
  its link *text* by name between two stats, so a swap that starts and ends
  around that one `readlinkat` can change which path the walk follows next: the
  bytes come from the descriptor that step stat'ed and opened, the checkout and
  escape rules still apply, and a persistent link swap gives the identical
  outcome, so it grants nothing a writer of the repository did not already have.
  The guards were exercised by a `RENAME_SWAP` race on a case-insensitive
  filesystem with a case-variant alias spelling: thousands of runs per state at
  each stage, leaks at every stage before the stat/open agreement plus the parent
  stamp, and none after, at a resolution of a few 10⁻⁴ per run.

## Consequences

- A branch switch cannot silently change a `trust = false` source's parsed or
  adopted configuration.
- A launch with a foreground terminal can review one bounded batch; unattended
  and administrative commands fail closed without creating pin state.
- `doctor` reports an approved source as `pin=approved sha256:<hex>` in its
  existing source row. It does not claim that the active snapshot is available.
- Users must keep secrets out of sourced configuration and use the direct
  project-config path until #739 provides the advertised batch commands.
