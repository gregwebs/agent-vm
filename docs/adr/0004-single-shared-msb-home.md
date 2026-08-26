# ADR-0004: Keep one shared `MSB_HOME`; detect-and-recover, don't namespace

## Status

Accepted.

## Context

`d6ac848` (#35) namespaced the private Microsandbox home by the bundled
schema id — `<state_root>/msb-home-<schema_id>` instead of a flat
`<state_root>/msb-home` — so that agent-vm builds vendoring different,
incompatible microsandbox schemas could never share one mutable
`msb.db` and brick it via a one-way sea-orm forward migration.

That suffix pushed the derived relay socket path
(`<MSB_HOME>/run/agent/<hash>.sock`) past macOS's 104-byte
`sockaddr_un.sun_path` limit for this project's default state root,
breaking `agent-vm shell`/`run` out of the box for every macOS user on
the default install (#36).

An initial plan considered here (never merged) kept schema-namespacing
but shortened it — an opaque hash of the schema id, a marker file for
identity, and a patch to the vendored microsandbox fork to expose its
private relay-socket-path derivation for a live length check. That plan
technically fixes #36, but reintroduces real engineering cost (a fork
patch to track forward, a new on-disk naming scheme, adoption logic for
existing long-form directories, collision handling) to protect against
a scenario re-examined here.

**What #31/#35 was actually protecting against**, concretely: two
different `agent-vm` *builds* — differently vendored microsandbox
schemas — sharing one state root. In practice this is almost
exclusively a **development-time** scenario: multiple worktrees or
branches of agent-vm itself, built and run against the same default
`$HOME/.local/state/agent-vm`. A released end user runs one build at a
time; they only hit it by deliberately rolling back to an older
version after a newer one has touched the shared DB — rare, and
already fully recoverable.

The recovery path already exists and predates namespacing: #30
(`msb_preflight.rs`) fails fast with a named, actionable error the
moment an older build detects a DB a newer build already forward-
migrated, and #28 (`agent-vm doctor --reset-msb-db`) moves the stale DB
aside non-destructively so the next run recreates it at the bundled
schema. Verified: reverting `d6ac848` leaves both fully intact and
already tested (`msb_preflight.rs`, `tests/preflight_boot.rs`,
`tests/doctor_reset.rs`, `tests/msb_passthrough.rs` all pass unchanged),
because nothing was built on top of `d6ac848` — it was the tip of its
line of history.

## Decision

**Revert `d6ac848` outright.** `MSB_HOME` goes back to a single flat
`<state_root>/msb-home`, unconditionally. This fixes #36 directly (the
default path is well under the socket-path limit again) with no new
naming scheme, no fork patch, and no adoption logic to maintain.

**Rely on #30 + #28 as the collision safety net, not prevention.** A
cross-build DB-ahead collision remains possible, but it is never
silent: `msb_preflight`'s guard turns it into a named, hard stop before
any command touches the DB — never a raw sea-orm error, never quiet
corruption — with a one-command, non-destructive recovery.

**Make the guard's message self-diagnosing for the cross-build case.**
`ahead_message` (`msb_preflight.rs`) now names *this build's own*
bundled schema (`msb_schema::bundled_schema_version`, otherwise unused
after the revert) alongside the offending migrations, and explains the
mechanism plus the fix: set `$AGENT_VM_STATE_DIR` to a distinct path
per build when running agent-vm builds with different vendored
microsandbox schemas side by side (e.g. developing across worktrees).
The goal: nobody should have to *debug* this collision to understand
it — the error should explain itself the first time it fires.

**Document the isolation convention for developers.** `AGENTS.md` now
tells agents working across worktrees to set `AGENT_VM_STATE_DIR` per
worktree when building/running agent-vm itself, closing the gap that
made this collision a live risk in the first place (this repo's own
workflow is worktree-heavy).

## Addendum (agent-vm issue #40 / ADR-0006)

The "the default path is well under the socket-path limit again" claim
in the Decision above held only for short home directories — as little
as ~21 bytes of headroom remained under macOS's 104-byte `sun_path` for
the flat `<state_root>/msb-home` default, not a real margin for every
user. Issue #40 shortened the macOS default further (`$HOME/.agent-vm-msb`
instead of `$HOME/.local/state/agent-vm/msb-home`) and added a preflight
that fails closed — never truncates — on any path, default or
overridden, that would still overflow. See ADR-0006 for the full
context. This ADR's core decision (one flat, un-namespaced `MSB_HOME`,
detect-and-recover via #30/#28 rather than prevent via namespacing) is
unaffected.

## Consequences

- End users get a materially better outcome than either the pre-#36
  state (crash, misleading remediation) or the shortened-namespacing
  plan (silent side-by-side coexistence, more moving parts to get
  subtly wrong): a rollback-triggered collision is rare, and when hit,
  is a named error with a one-command, non-destructive fix.
- Developers running multiple schema-divergent agent-vm builds against
  the *default* (unset) `$AGENT_VM_STATE_DIR` will hit the guard and
  pay a `--reset-msb-db` (re-pull images, no project-data loss) each
  time they cross that boundary, until they set a per-worktree
  `AGENT_VM_STATE_DIR` as `AGENTS.md` now instructs. Accepted: this is
  the documented "hack that works well enough for the dev flow" this
  ADR deliberately chose over building general-purpose prevention
  machinery.
- `msb_schema::bundled_schema_version()` (#29) is retained — its
  namespacing consumer is gone, but it is now the source of the schema
  id surfaced in the guard's message.
- Should the frequency of dev-time collisions become a real drag even
  with the `AGENT_VM_STATE_DIR` convention documented, revisit
  namespacing then, informed by the shortened-naming design this ADR
  supersedes rather than starting over.
