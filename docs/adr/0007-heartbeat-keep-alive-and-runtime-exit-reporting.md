# ADR-0007: Heartbeat keep-alive grace window and runtime-exit reporting

## Status

Accepted.

## Context

The v0.6.15 baseline's `HeartbeatReader` (issue #40 / ADR-0006) is
purely an idle-timeout signal: `check(idle_timeout)` returns
`PendingBoot`, `Active`, or `Idle`, and its doc comment is explicit
that "a stale or missing heartbeat is never, on its own, grounds to
kill the sandbox." That's correct for idle reclamation, but it drops a
capability the pre-migration `gw` fork had: a genuinely wedged
`agentd` — heartbeat never advances again, no crash, no clean exit —
had no detection path at all once the guest was past boot. The relay's
`wait_ready` timeout only ever covers the *boot* window.

Issue #41 was filed against the opposite failure mode: a long-lived
PTY exec session got reclaimed because `heartbeat_seq` momentarily
stopped advancing (virtiofs write latency / host load) while the
session was still healthy and running. A naive single-deadline
staleness check (kill as soon as `stale_for >= S`) would fix "detect a
truly wedged agent" but reintroduce exactly the bug the ticket reports
if `S` is short, or fail to catch a wedged agent in reasonable time if
`S` is long enough to tolerate real-world hiccups. Both requirements
have to hold with the *same* budget value.

## Decision

**Two-window confirmation, not a single deadline.** Crossing the
stale budget `S` once only enters a grace state (`Active`); the
decision only flips to `AgentUnresponsive` once staleness has been
*continuously* observed for a second full `S` window with no fresh
`heartbeat_seq` in between (`HeartbeatReader::check_at`,
`stale_confirmed_at`). Any fresh sequence value — even after entering
the grace state — resets the confirmation clock immediately. This
means a real hiccup bounded by `S` never triggers the unresponsive
path at all, and a truly dead agent is still caught in at most `2S`.

**`S = 5s`, `HEARTBEAT_BOOT_GRACE = 180s`.** These are the values
carried over from the pre-migration `gw` fork's mature implementation
(`vendor/microsandbox` branch `gw` @ `c296b30`), chosen there from
observed virtiofs write latency under load; #41 re-adopted them rather
than re-deriving new constants, since no regression against them was
reported in the fork's lifetime. Both are named constants in `vm.rs`
(`STALE_HEARTBEAT_TIMEOUT`, `HEARTBEAT_BOOT_GRACE`) specifically so a
future report of either being too aggressive or too loose is a
one-line tuning change, not a logic change.

**`AgentUnresponsive` reuses the existing `EXIT_REASON_AGENT_UNRESPONSIVE`
/ `TerminationReason::AgentUnresponsive` rather than adding a new
reason.** The v0.6.15 baseline already added this pair for the relay's
own boot-failure path (`wait_ready` timing out). The heartbeat
monitor's post-boot "stopped responding" case and the relay's
pre-boot "never responded" case are the same underlying fact —
agentd isn't there — so they share one reported reason rather than
forcing every downstream consumer (DB queries, `agent-vm doctor`,
logs) to special-case two.

**The confirmed-unresponsive shutdown push is bounded and short
(1s via `AGENT_UNRESPONSIVE_SHUTDOWN_PUSH_TIMEOUT`), not the normal
60s idle-shutdown default.** An agent already confirmed unresponsive
for a full `2S` window is unlikely to service a graceful shutdown
request either; reusing the 60s default here would mean the "detect a
wedged agent quickly" guarantee this ADR exists for is immediately
undermined by a 60s wait on the same wedged agent.

**Runtime-exit reporting (child supervision) is a separate but
related fix, landed in the same issue.** If the VMM child dies
outright (crash, OOM-kill, external `SIGKILL`) rather than merely
going quiet, that's not a heartbeat problem at all — it's a process
supervision problem. `ProcessHandle::wait()` (SDK) now classifies and
records an abnormal exit once per handle to `msb-exit.log` before any
cleanup can remove the evidence, and `agent-vm`'s exec loop
(`next_exec_step` in `crates/agent-vm/src/run.rs`) races the exec
event stream against `Sandbox::wait()` so the launcher can never block
forever on a VMM that's already gone. See `ARCHITECTURE.md`'s "Phase
5" section for the full mechanism.

## Consequences

- A brief virtiofs/host-load hiccup on an active exec session no
  longer risks reclaiming the sandbox — the literal AC the issue was
  filed for — verified by
  `heartbeat::tests::brief_heartbeat_staleness_does_not_kill_active_session`.
- A genuinely wedged `agentd` (heartbeat stops for good, post-boot) is
  now caught within `2S` (10s at current constants) instead of never,
  closing the "no truly-wedged signal after boot" gap the migration
  temporarily reopened.
- Tuning `S` or the boot grace later is a one-line constant change in
  `vm.rs`; both are covered by the unit tests in `heartbeat.rs`'s
  `#[cfg(test)]` module (`check_at` is the pure seam), so a future
  tuning change gets an immediate correctness signal without booting a
  VM.
- `msb-exit.log` is a crash-only record (nothing is written for a
  clean exit) — a lifecycle audit log was explicitly not the goal, and
  writing one line per ordinary shutdown would dilute the file's
  usefulness as a "did the VMM crash" post-mortem.
