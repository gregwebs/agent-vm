# ADR-0053: Guest exit-signal identity

## Status

Accepted. Implements [agent-vm #467](https://github.com/gregwebs/agent-vm/issues/467)
(slice 2 of #401) in the vendored microsandbox fork. Amends the status table
published by [the direct-command spec](../specs/direct-command-launch.md); the
supervision rules of #401 are unchanged.

## Context

Slice 1 (#401) supervises a host `SIGINT`/`SIGTERM` for a direct launch and
reports `128 + N` in exactly one situation: the launcher itself forced the
shutdown, because the grace expired or a second interrupt arrived. A guest exit
inside the grace was passed through as the code the guest gave, and that code was
all the launcher had — the guest's own terminating signal was not available at
all, because `waitpid`'s status was collapsed to a bare code at the source:

```rust
fn exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 }
}
```

Every signal death became `-1`, so it was reported as an unknown status (the
process exits 255): a guest that killed itself and a guest that died of `SIGTERM`
after we forwarded `SIGINT` were indistinguishable. The launcher never inferred a
signal death from the signal it had sent, so neither case could become 130 or
143 — instead of a wrong signal number, there was no number at all. This patch
supplies the missing guest identity; it does not replace a host-signal fallback,
because there never was one.

Two constraints shaped the fix. The protocol change must be additive in both
directions (a new SDK with an old runtime, and the reverse). And the Rust SDK's
`ExecEvent::Exited { code }` must keep its exact shape: the ticket asks for the
signal "without breaking existing matchers", and adding a field to that variant
breaks every exhaustive pattern and every constructor in downstream code.

## Decision

### 1. One decoded value, from `waitpid` to the frame

`ProcessExit { code, signal }` in agentd's process module is the only place the
guest kernel's wait status is interpreted: `code` keeps `exit_code`'s existing
contract (the exit code for a normal exit, `-1` otherwise — which is still the
answer every legacy caller reads) and `signal` is
`WIFSIGNALED(status).then(|| WTERMSIG(status))`. That
value travels unchanged through `ProcessExitWatcher`, both session readers, the
pending-exit drain handshake and both frame producers in `agent.rs`. No later
layer re-derives it, and nothing else in the tree calls `libc` wait macros.

A stopped or continued status is neither a normal exit nor a signal death and
decodes as `{ code: -1, signal: None }`.

### 2. Additive wire metadata

```rust
pub struct ExecExited {
    pub code: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
}
```

`None` is omitted, so an old-format frame is byte-identical to what a pre-#467
agentd sent and decodes as `None`; a new signal-bearing map key is ignored by an
old reader. No new message type, flag, generation or capability negotiation.

### 3. The matcher-preserving accessor, not an event field

`ExecEvent::Exited { code }` is untouched. The event mapper publishes the
reported signal on a per-`ExecHandle` `Arc<AtomicI32>` (`0` = none) **before** it
delivers `Exited`, and consumers read it with:

```rust
pub fn termination_signal(&self) -> Option<i32>
```

Contract: valid once `Exited` has been observed on that handle, including after
`wait`/`collect`; `None` means an ordinary exit *or* a producer that reports no
identity, never a host-signal inference. The state is allocated per exec, never
reused or cleared by channel closure, and a lost transport establishes no
terminal result through it.

The rejected alternative was an additive field on the variant
(`Exited { code, signal }`). It is a smaller change inside the SDK but a source
break for every exact pattern and constructor — including this launcher, the CLI,
SSH and the language bindings — and would have needed an explicit exception to
the ticket's requirement. The accessor keeps all of those matchers valid; its
cost is one documented observation contract and a private launcher trait method
so the streaming lifecycle can read the same value through its test seam.

Non-Rust bindings are deliberately unchanged: their event and code schemas keep
exposing the exit code only. `code` is not deprecated by this change — it stays
the status for every normal exit, and `-1` for a signal death — so those bindings
lose nothing they had. Their native bridges already bind `{ code }` and need no
edit.

### 4. Policy stays where it was: `SessionEnd`

`SessionEnd::Guest(i32)` became `SessionEnd::Guest { code, signal }` and
`exit_status()` maps a reported signal to `128 + N`, a reported code to itself,
and a forced shutdown to `128 + host signal`. The mapping lives in one place for
both direct modes.

`signal` is `Option<GuestSignal>`, not `Option<i32>`. The number is guest-supplied
(it arrives as an `i32` from the guest kernel through agentd and the SDK), and
`128 + N` is arithmetic on a process exit status, so it is parsed **once**, where
the SDK value enters the launcher, into a `NonZeroU8` restricted to `1..=127`. A
reported `0` (the SDK's "no identity" placeholder), a negative number or anything
above 127 becomes `None`, which the table already reads as "no identity": the raw
code passes through and no arithmetic happens. Before this, `Some(-128)` reported
success and `Some(i32::MAX)` panicked in a debug build.

Only a **direct** launch reports guest identity. The streaming lifecycle is shared
with legacy catalog launches, so `ExecContext.direct` gates the field: a catalog
launch keeps its code-only status even when the runtime reports identity. Legacy
`attach()` reports a bare code and becomes `signal: None`.

A guest end is an ordinary teardown (`stop`, `remove`); a forced end keeps its
`kill`, `reap`, `remove` path, and cleanup failure still outranks both at 125.

## Consequences

- A guest that signals itself now reports `128 + N`; a guest that dies of
  `SIGTERM` after a forwarded `SIGINT` reports 143, where slice 1 reported the
  unknown status 255 (and never 130: it did not infer signal death from a signal
  it had sent).
- A guest code is never reinterpreted: `exit 143` stays 143 without claiming
  signal death.
- An older runtime omits the field, so every status keeps its pre-#467 value,
  including the unknown `-1` → 255. A patched SDK with an old embedded agentd is
  therefore honest, not broken — and it is not evidence about the mapping.
- The native relay matrix grows nine rows — `pty-self-sigterm`,
  `stream-self-sigterm`, `pty-forwarded-unhandled`,
  `stream-forwarded-unhandled`, `pty-guest-signal-wins`,
  `stream-guest-signal-wins`, `pty-legacy-self-unknown`,
  `stream-legacy-self-unknown` and `stream-legacy-unknown-after-signal` (that last
  one is stream-only, because a legacy status after a forwarded signal is one
  terminal-mode case fewer) — and the manual VM rows for the previously pending
  `unhandled` outcomes become required. A row proves an ordinary teardown as well
  as the number, because status alone cannot distinguish a guest end from a
  forced shutdown that produced the same value.
- The fake-relay rows model guest identity; they prove neither the fork's
  `waitpid` decoding nor guest frame construction. That evidence is the Linux
  agentd tests and rebuilt-runtime VM rows.
