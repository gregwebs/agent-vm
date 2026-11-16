# ADR-0069: An in-terminal access prompt for a direct launch

## Status

Accepted and implemented in **0.7.57**
([#501](https://github.com/gregwebs/agent-vm/issues/501) slice 3, reach A).

Amends [ADR-0018](0018-machine-checked-boundary-contracts.md) (four kernels added
to its tables). Annotates [ADR-0064](0064-read-only-refusal-feed.md) (the hint is
unchanged in text and still fires once; on a prompt-eligible PTY launch it is
written through the relay's writer) and
[ADR-0066](0066-live-egress-allowances-and-writer.md) (a second in-process caller
of the grant path, `grant_unless_answered`, and the answers wakeup).

## Context

#494 settled the shape of the answer ("hold, don't pause the VM"), #317 the keys
and the typing guard, #301 first-answer-wins, and the operator chose "A then B":
the prompt reaches only the launches the launcher already relays —
`LaunchTarget::Direct` resolved to `DirectIo::Pty`. `agent-vm claude`,
`agent-vm pi`, other catalog tools and `agent-vm shell` keep `attach_with` and get
today's behaviour byte for byte; moving them is slice 3b.

Three constraints shaped the design:

1. **One writer.** Guest output, the hint, prompt frames and any emergency restore
   all reach one descriptor. A second descriptor for the emergency restore raced a
   blocked writer and could replay a leave (the plan's revision 1). So the writer
   thread owns a *ledger*: what reached the descriptor, and whether a prompt may be
   on screen now.
2. **The terminal is the only witness.** A raw read does not prove a human pressed
   a key, and "the bytes were written" does not prove the terminal drew them. So
   visibility is the terminal's own reply to a cursor-position request, and an
   answer needs a single-byte read that started after the prompt's input flush.
3. **The guest's state must come back.** The tracker follows the parse state and
   the mode fields the prompt changes, and *declines* the takeover wherever
   emulators disagree rather than restoring a guess.

## Decision

### Reach and eligibility

Prompt only for `DirectIo::Pty`, and only when `AGENT_VM_NO_ACCESS_PROMPT` does not
turn it off, `TERM` is set and not `dumb`, stdout is a terminal **and the same
terminal as stdin** (`st_rdev`), and the session has a live refusal feed.
`AGENT_VM_NO_ACCESS_PROMPT` is read once per launch through
`env_flag::read`; an unrecognised value keeps the documented default (on) and
prints one launch warning.

### One writer and its ledger (`direct_pty/ledger.rs`)

`owed = Some(g)` from the moment `Enter(g)` is **admitted** until every byte of
`Leave(g)` is written. While it is set, an abnormal end owes the host restore, and
the writer itself writes it — only the writer knows what reached the descriptor.
The admission table is proved (`ledger::admit`): `Data` always while running,
`Enter` only when nothing owns the terminal, `Redraw`/`Leave` only for the
generation that owns it, nothing after the writer stops. The host restore is
correct from every byte prefix of an enter or a leave, so no progress state is
needed; it contains no erase, so a second copy keeps the main screen. The epilogue
waits at most 250 ms for it, after which the writer starts no write it had not
already passed its check for (at most one more `syscall`, as after today's abort).

### The relay lifecycle (`access_prompt/relay.rs`)

`Idle → Cutting(g) → Entering(g) → Confirming(g) → Asking(g) → Granting(g) →
Lingering(g) → Restoring(g) → Idle`. A takeover starts only at a safe boundary; if
none is reached within 0.5 s the launcher queues `CAN` and the prompt. Host input
is consumed from `Entering` to the confirmation of `Leave`; guest output is held
(up to 256 KiB, one more SDK event may take it past) and forwarded only behind the
leave. One question per takeover, at least 2 s of guest time between questions, at
most 8 waiting.

### The safe-boundary parser (`access_prompt/vt.rs`)

A subset of the DEC/ECMA-48 parser (Williams' VT500 model), proved total, with
`CAN`/`SUB` returning to ground from every state. A *safe boundary* is a point at
ground. The modes the prompt changes are tracked as `Known`/`Unknown`; a takeover
is declined while any is unknown or left/right margin mode is on. The rules and
their evidence:

| rule | evidence |
|---|---|
| any mouse-mode reset clears tracking; any set selects that mode | xterm's `set_mousemode`; tmux 3.8 `r3` probes T7, and the oracle's mixed-mouse case |
| `RIS` on the alternate screen returns to main in xterm, stays in tmux | tmux 3.8 probe (`alternate_on` after `ESC c`), oracle `the_states_the_tracker_cannot_know_decline_rather_than_guess` |
| `DECSTR` resets origin mode and charsets in xterm, nothing in tmux | both behaviours leave a field already at its default there, so only non-default fields become unknown |
| a guest cursor restore (`ESC 8`, `CSI u`, `?1048l`, `?1049l`) restores origin and charsets, but which slot differs | the sticky `saved_nondefault` bit: unknown unless no save could have stored a non-default value |
| a CSI with more than 16 parameters may act on the dropped ones | tmux acts on a 17th parameter (`CSI_17th_parameter` probe) |
| `?1049l` restores neither origin mode nor the character set | tmux 3.8 probes (`T13`–`T16`), hence origin re-set before the restore and the designations re-emitted after it |

### The frames

Main-screen guest: `?1049h` … `?1049l` (the terminal saves and restores cursor and
SGR). Alternate-screen guest: `ESC 7` … `ESC 8` (xterm and tmux restore cursor, SGR,
charset and origin mode; `?1049h` would clear the guest's screen and `?1049l` would
drop it to the main one), then a one-column resize nudge so the guest redraws.
During the prompt: mouse tracking off, a synchronized update ended, origin mode off,
kitty keyboard flags pushed to 0, ASCII character set, SGR reset, bracketed paste
**off** (#494; operator decision D4 proposes on). Autowrap, insert mode, cursor
visibility, focus reporting, mouse encodings, scroll margins and keypad modes are
left alone. Every row is absolute, erased first, printable ASCII, at most
`cols − 1` wide; there is no clipping path — a question that does not fit is
declined.

### Visibility and the typing guard

The enter frame ends by placing the cursor at a fixed position and asking for it.
The first reply naming exactly that position, after the writer confirmed the frame,
makes the prompt visible; with no reply within 1 s visibility is the write plus
1 s and the session stops asking. At visibility the terminal's pending input is
flushed and the reader's read-start counter is snapshotted. A key answers only if
its `read(2)` started after that snapshot, returned exactly one byte, was read at
least 0.7 s after the later of visibility and the previous input, and is not inside
a bracketed paste. The decision is a proved kernel (`guard::answer_of`).

### Granting

The prompt calls `LiveAllowances::grant_unless_answered`: the same handler the
control socket uses, under the same operation lock, with one extra precondition —
a destination this session already holds or has recorded for the next launch is
reported as answered elsewhere instead of granted again. That is what stops a
queued `p` from promoting a CLI `s`. The grant is spawned and waited for at most
40 s; it is never cancelled, so an authorised project record can appear late, and
if it does the prompt says the change was not confirmed (R29).

### The setting

An environment variable, not a config key (operator decision D2 proposes the
variable only): the right answer differs per terminal — a tmux pane, an SSH session,
GNU screen — which an environment variable scopes naturally.

The hint is routed through the relay when stderr is the *same terminal as stdout*.
That is not stricter than R26: eligibility (R2) already requires stdout to be
stdin's terminal, so "stderr is stdout's terminal" is exactly what the specification
calls "the same terminal".

## Consequences

### Not guaranteed (stated, per the specification's *Restore limits*)

- An alternate-screen guest's own saved cursor is overwritten by the prompt's save.
- A terminal without the alternate screen shows, and clears, the main screen;
  after a forced end the prompt's text stays on it.
- A forced end in the instant before the prompt's screen save moves a main-screen
  guest's cursor to its last screen save; the host restore pops one kitty keyboard
  entry, which can only remove an enhancement.
- A panic restores `termios`; the host restore is written only if the writer thread
  runs before the process exits.
- Terminal replies and focus reports that arrive during a takeover are consumed;
  a paste or reply split across a takeover's start or end is split the same way.
- Read times are sampled just after `read(2)` returns, so a descheduled reader
  makes a key look quieter by that delay.
- Inside tmux, visibility is tmux's confirmation, not the outer terminal's; a
  terminal that never answers cursor-position requests gets a 1 s margin, which a
  slow link can exceed.
- With bracketed paste off, a one-character paste is indistinguishable from a key.
- A guest exit queued behind a full hold is observed when the takeover ends.
- A late authorised grant can survive a concurrent CLI `access revoke --project`,
  because the CLI deletes the record before the session sees the revoke.
- Backpressure during the hold needs a guest agent that supports output credit.

### Deliberately rejected

- Pausing the VM (#494's measurements).
- Option C: prompting on stderr for `attach` launches without holding output.
- A socket client inside the launcher.
- A second descriptor for the emergency restore (revision 1: it raced the writer).
- Tracking SGR and the cursor ourselves instead of using the terminal's save.
- Holding until a safe boundary forever (no `CAN`).
- A config-file setting.

### Deviation recorded for the plan's §10.2

`access_prompt::last_safe_cut` is a plain loop transcribing the proved spec
function `last_ground`, not a proved loop. Three proof attempts (an `Option`
invariant; a ghost `int` plus an exec mirror; a branch-assigned ghost) did not
discharge the loop invariant's ghost/exec relation within a reasonable time. The
kernel (`next`, `run`, `last_ground`) is proved, and the loop is checked against a
brute-force scan at every carried-in state in `access_prompt/vt/tests.rs`.

The tmux oracle **does not** cover this loop: its byte-prefix sweep writes prefixes
of the enter and leave frames followed by the host restore, and never cuts a guest
stream at a `last_safe_cut` boundary.

## References

- The specification and plan: `#501` slice 3, revision 5 (`spec.md`,
  `implementation-plan.md` in the work artefacts).
- tmux 3.8 probes: `r3/vt-probe-r3*.py`, `rereview/vt-independent.py`, and the
  automated oracle `script/test/access-prompt-tmux-oracle.sh`.
- ADR-0018 for the kernels, ADR-0064 for the feed and the hint, ADR-0066 for the
  live grant path.
