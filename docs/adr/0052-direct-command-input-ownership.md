# ADR-0052: Direct-command input ownership

## Status

Accepted. Implements [agent-vm #399](https://github.com/gregwebs/agent-vm/issues/399)
for the direct launch target added by #398. Leaves #400 (terminal policy) and
#401 (signals while input is pending) open. Extends the #258 release invariant
recorded in `ARCHITECTURE.md`.

## Context

A direct launch (`agent-vm run PROGRAM`, `agent-vm -- PROGRAM`) is not a
bash-free launch: the guest still runs a launcher-owned bootstrap that strips
IPv6 nameservers, runs image seed hooks, sources the project's
`.agent-vm.runtime.sh` and then `exec`s the program. Setup and the program share
one guest stdin, and the streamed branch never asked for a stdin pipe, so
`printf hello | agent-vm run cat` printed nothing and nothing in the system
could tell a command that had EOF from one that would never get its input.

Giving the program the host's stdin is therefore not one decision but four,
each with a cheaper-looking alternative that is wrong:

1. **How to read host stdin.** `tokio::io::stdin()` reads on the blocking pool,
   whose task cannot be cancelled. `main.rs` builds the runtime by hand and, on
   the error path, drops it before reporting status 125 — and `Runtime::drop`
   waits for blocking tasks. A launch that fails while a FIFO writer still holds
   stdin open would hang there instead of reporting its error.
2. **How much to buffer.** Copying the whole stream (or letting an unbounded
   channel grow) turns the launcher into a copy of the input whenever the guest
   stops reading: `yes | agent-vm run head -c 4` would consume memory without
   bound.
3. **Who reads the guest's stdin.** Every bootstrap step shares fd 0. Anything
   that reads before the program steals its input. Leaving a copy of the
   descriptor open does **not** delay the program's EOF — only an extra *write*
   endpoint keeps a pipe open; an extra *read* descriptor is a leak that keeps
   consuming bytes behind the program's back. Both are prevented for the same
   reason here: no setup child may hold the input at all.
4. **What a failed guest write means.** agentd reports a failed stdin write as a
   non-terminal event. EPIPE is the guest closing its read end — expected, and
   the guest's status must stand. Anything else is a genuine forwarding failure,
   and reporting the guest's status would describe a command that ran on
   truncated input.

## Decision

### 1. A detached std thread reads, a cancellable task pumps, one chunk buffers

`direct_input` (a deep module; nothing else owns these resources) spawns a named,
**detached** `std::thread` for the blocking `read(2)`, a `tokio::sync::mpsc`
channel of exactly **one** 64 KiB chunk, and a pump task that turns chunks into
`ExecStdin` frames.

The reader thread is never joined. `InputPump::stop()` stops the **pump**; a
reader parked in `read(2)` stays parked until the process exits or a byte or EOF
arrives. That is safe precisely because the thread is detached: neither
`Runtime::drop` nor `process::exit` waits for it. The accepted cost is that a
run which stops early may have read ahead — at most about three chunks (192 KiB:
one in the reader's hand, one queued, one in a pending write) — and those bytes
are lost to any later reader of the same stdin file description.

That 192 KiB is a **launcher-side** bound, not an end-to-end loss bound. The
host's 64 KiB chunk is a read/backlog unit: the bundled SDK subframes each write
at `stdin_chunk_size` (16 KiB by default), with a 64 KiB per-exec credit window.
`ExecStdinAck` replenishes credit after delivery into the guest stdin pipe, not
consumption by the program. A completed `ExecSink::write` means the frames were
accepted, not that the program read them; an early-closing guest can still leave
input unread in the pipe or downstream of the launcher. The unit bound remains
the launcher's memory; the native `large` row checks the end-to-end transfer,
not a loss bound.

### 2. EOF is an empty frame, and only `close()` may send one

The runtime's EOF is `ExecStdin { data: [] }`. `InputChunk` cannot be empty, and
the pump calls `close()` exactly once when the reader reports EOF. A host read
error, a vanished reader (a panic) and a transport error are all distinguished
from EOF, because turning truncation into silent success is the one failure this
feature must never have.

### 3. The bootstrap runs all setup in one `{ … } </dev/null` group

For a direct streamed launch the rendered line is

```sh
{
<ipv6 strip>
<seed hooks>
<project hook>
<program guard>
} </dev/null; exec -- PROGRAM ARGS…
```

A **group, not a subshell**: a hook's exports, `cd` and `exit` keep their
meaning, so hook exports still reach the program. Bash saves fd 0 for the group
close-on-exec and undoes the redirection before `exec`, so no setup child
inherits a copy of the input. This was measured with an externally calibrated
descriptor probe on bash 3.2.57 and 5.2.37 (a concurrent-builtin probe reports
descriptors bash itself created, and so cannot be trusted). **No reserved
descriptor is used**, and no minimum bash version is required: the boot-image
contract stays "Bash on the image's `PATH`".

Rejected shapes, each measured:

- reserve fd 9 (`exec 9<&0 … 9<&- … exec 0<&9`): on bash 3.2 the saved copy sits
  at fd 10, is not close-on-exec, and setup children consume the input;
- the same on fd 19 (above bash's save base): same residue on 3.2;
- pass the restore to the program's own `exec` (`exec -- prog 0<&9 9<&-`): leaks
  an extra descriptor on 3.2;
- a subshell: isolates stdin but loses every hook export.

Consequences, recorded as contract rather than bugs: a hook's own descriptor
keeps its **legacy lifetime** (fd 9 opened by a hook outlives the hook and is
inherited by the program), and a descriptor that collides with bash's saved slot
(fd 10) is closed when the group ends, so a hook should not use fds ≥ 10. If a
future bash is found where this shape leaks, the answer is a new shape or an
explicit contract change — never an accepted residue.

### 4. The guarantee has a stated limit

Runtime hooks are **trusted code inside the bootstrap's own shell process**. The
protection covers ordinary reads of stdin and unintended inherited descriptors
(a hook that merely runs `cat`, `head`, `read`, or redirects its own fd 0). It is
not an isolation boundary against a hook that deliberately names bash's internal
saved descriptor: `cat <&10` reads the command's input on both measured bashes.
Preventing that would require keeping the input outside the shell process — a
runtime change (deferred stdin attach) outside this ticket's scope. The limit is
documented in `USAGE.md` and pinned by a test that asserts the theft still
happens, so it cannot later be mistaken for isolation.

### 5. The stream lifecycle owns every resource, with one release order

`stream_exec_with_cleanup` owns the exec handle, the pinned runtime-wait future,
the sink and the pump from the moment `launch()` hands them over.
`ExecEventSource::take_stdin` exists so the lifecycle — not `launch()` — takes
the sink out of the handle it already owns. One epilogue serves every outcome
(success, an input start-up failure, any loop break):

1. `pump.stop().await` (abort and join the pump; the sink is dropped);
2. drop the runtime-wait future;
3. drop the handle;
4. only then teardown, or return the guest status.

The order is load-bearing in both directions: the wait future may hold the
child-handle mutex (#258), and a pump still blocked in a guest write must not
outlive the handle it writes through. No `?` or early `return` exists between
taking ownership and step 1.

The loop is a `biased;` select: **pump outcome → expired transport-failure grace
→ exec events**. The pump ends at most once, so it cannot starve anything, and
an input failure that already happened must beat a ready `Exited`, because
stream loss is never a guest success. The grace arm sits ahead of the event
stream deliberately: a continuously ready stdout stream must not be able to hold
the bounded failure return open (a regression test fails if the arm is moved
back). Legacy launches take no pump and keep their behaviour exactly, including
ignoring `StdinError`.

## Consequences

- `printf hello | agent-vm run cat` prints `hello` and exits 0; `: | agent-vm
  run wc -c` prints `0`; binary and NUL bytes round-trip.
- Setup and hooks see EOF for a non-terminal *direct* launch, while a terminal
  launch (attach) still gives them terminal input. A legacy `shell` launch keeps
  the old ordering — its seed hooks run before the `/dev/null` redirect — so a
  hook that reads stdin can block there.
- A guest that closes stdin early is not an error; a guest that exits while host
  input is still open returns its own status promptly, because the reader is
  detached.
- Host read errors, a vanished reader, a spawn failure and non-EPIPE write
  failures are launcher failures: status 125 with the primary error first and
  any cleanup failure appended.
- Launcher memory is bounded to about three chunks ahead of a stalled guest.
  Up to 192 KiB read ahead may be lost to a later reader of the same stdin; what
  the runtime already accepted is queued beyond that, so a guest that closes
  early can discard more than 192 KiB and no total loss bound is promised.
- Hooks must keep their descriptors below 10, and must not be written as though
  the input were secret from them.

## Alternatives rejected or deferred

- `tokio::io::stdin()` with a blocking-pool read: cannot be cancelled, and
  `Runtime::drop` waits for it (decision 1).
- Unbounded buffering or a whole-stream copy: unbounded memory for exactly the
  case (`yes | head`) that must stay cheap.
- Sending empty data frames instead of `close()`: indistinguishable from EOF and
  closes the guest's stdin early.
- Reserving and restoring a descriptor for setup, or running setup in a
  subshell: measured leaks on bash 3.2, or lost exports.
- Treating EPIPE as a failure, or any other errno as guest closure: both invert
  the contract in a way the user sees.
- Keeping the input outside the shell process (deferred stdin attach): the only
  way to defeat a deliberately hostile hook, and it needs a runtime change.
- Signals while a read or write is pending: **#401**, which this shape leaves
  possible (the loop can gain a signal arm; `ExecHandle::control()` is still
  available and the pump is stoppable at every await point).

## Verification

Boot-free, on every bash the host has (`/bin/bash` 3.2.57 and Homebrew 5.2.37 on
macOS; the runner's bash on Linux):

- the legacy rendering is **the complete line** byte-identical to `main`'s
  output for both `ImageContract` and direct attach, and the reserved rendering
  is one group with a single `exec --`;
- setup and the hook see EOF while the program receives every byte, as a pipe
  and as a regular file, with the hook's export visible to the program;
- a calibrated descriptor probe shows setup children inherit nothing and consume
  nothing, and the program inherits **exactly** no descriptor — with the negative
  controls that keep the probe honest (a reserved fd, and the rev-1 fd-10 leak on
  bash 3, each required to show both the visible descriptor and consumption of
  the command's own bytes), plus the deliberate-theft limit above, pinned by the
  bytes the stealing hook captured;
- a hook's descriptor keeps its legacy lifetime; a failing hook keeps its status.

Unit and lifecycle tests (no VM): 320 KiB in five distinguishable 64 KiB chunks
forwarded byte-for-byte with one write receipt per chunk and exactly one close; empty input is one close and no writes; EINTR
retry; a host read error never fabricates EOF; a vanished reader is not EOF; a
stalled guest bounds the reader; `stop()` cancels a pending write and returns
while a read is parked, and a subprocess proves a parked reader does not delay
`Runtime::drop` (with a negative control that must catch the rejected
blocking-pool design); EPIPE versus genuine failure; both-ready precedence and
the grace-arm order (each with a recorded mutant); incremental output under a
pending read and a pending write; start-up failures sharing the one release
order.

Native rows live in `script/test/e2e.sh` (`custom-image`, rows
`custom-image-direct-stdin-*`, each in both direct syntax forms except the final
legacy-shell row): exact small output, zero-length input (as `/dev/null` and as
an empty FIFO), a binary file through `cat` and `sha256sum`, a 256 MiB hash plus
a 64 MiB round trip with a calibrated launcher-RSS comparison, an image seed hook
and a project hook that both read, an early-closing guest, a live handshake that
observes stdout and stderr before input ends, simultaneous 4 MiB streams on two
channels, a guest that exits while host input remains open, an EOF waiter, and an
unchanged `shell` launch. The harness has its own boot-free controls for every
helper and oracle it uses.

The rows are manual acceptance evidence, not a CI VM gate: they need an Apple
Silicon VM host, Docker/buildx and the built runtime. Which rows have been run
for a given revision, with their identities and logs, belongs in that revision's
verification artifact; this ADR records what is verifiable and how, not a
standing claim that every row was run.

## Amendment (2026-02, #400)

#400 widens **when** a direct launch streams; it does not change who owns the
input. A launch now streams not only for non-terminal stdin but also when a
redirected stdout or `--no-tty`/`-T` selects streaming despite a terminal stdin
(`CONTEXT.md` → *Direct terminal policy*). The streamed path is unchanged: one
reader thread, one bounded queue, one pump, one EOF frame, and the same failure
distinctions.

The **PTY** half of that ownership is the launcher's too, in `direct_pty`. A
direct PTY launch drives the stock SDK's
`exec_stream_with(... tty(true).stdin_pipe())` and owns the host terminal, the
input reader, the output writer and the guest's status itself, so the vendored
runtime carries no patch. The choices recorded above are reproduced there rather
than replaced: a detached std thread for the blocking read (a `poll(2)` on the
terminal with a self-pipe wake, so it stops reading the operator's keyboard when
the session ends), one bounded output queue with blocking backpressure rather
than failure, and the same EPIPE-versus-failure rule — the one
`direct_input::classify_stdin_error` implements, called rather than copied.

Terminal policy only selects a PTY when stdin is a terminal, so `direct_pty`
never falls back to `/dev/tty`: a forced PTY with a redirected stdin is refused
before boot instead of silently attaching to the operator's keyboard. A session
whose peer stops reading for long enough to fill a queue still polls the
runtime's own end and the output writer's failure, so a lost runtime restores the
terminal instead of leaving the launcher hung. Whether it is also a *failure*
depends on when it happens: before the guest reports an exit the status is
unknown and the session exits 125, while after it the status is known, so a
runtime lost with the last output still queued only truncates that output and the
session reports the guest's own status (`ARCHITECTURE.md` → *Direct PTY session
(#400)*).

The supervision seam #400 leaves for #401 is the owned session future: a direct
PTY session is `direct_pty::run(handle, runtime_wait)`, so signal handling can
later cancel that future and escalate teardown without redesigning input
ownership. #400 itself adds no signal forwarding, grace period or 128+N status.
