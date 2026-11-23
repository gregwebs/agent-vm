# ADR-0073: A macOS notification helper for refused egress

## Status

Accepted and implemented in **0.7.80**
([#501](https://github.com/gregwebs/agent-vm/issues/501) slice 4). Annotates
[ADR-0064](0064-read-only-refusal-feed.md) (its hint seam carries a second line)
and [ADR-0069](0069-in-terminal-access-prompt.md) (the prompt's transitions feed
the banner's grace, and an answer is a submitted line). Builds on
[ADR-0041](0041-single-binary-embedded-runtime.md), which is untouched.

## Context

A direct launch that does not relay its terminal — a piped `run`, `-T`, an
`attach`, a catalog tool — has only two ways to say "the sandbox refused this":
ADR-0064's once-per-session stderr line and `agent-vm access` afterwards. Neither
reaches an operator who has walked away from the terminal, which is the case the
ticket is about (#316). A banner can, if something is alive to post it: the
launcher is a CLI process that exits with its session, so the poster has to be a
separate, long-lived macOS application that the launcher feeds.

That splits the work along a seam, because almost none of it is macOS-specific:
*what* a banner says and when it may be replaced is a pure function of the
refusals and the prompt's signals, and only *delivery* needs AppKit.

## Decision

### A Swift bridge and Rust everything else

`macos/notifier/Notifier.swift` is one file of AppKit and `UserNotifications`,
compiled by `script/build/macos.sh` with
`swiftc -swift-version 5 -O -target arm64-apple-macosx12.0` (the 12.0 floor is
`UNNotificationContent.interruptionLevel`). It is a bridge and nothing more: it
speaks the NDJSON v1 wire, posts, removes, and spawns the click.

Everything else is Rust, testable on Linux CI:

| Rust | owns |
|---|---|
| `notify/coalesce.rs` | the pure banner state machine (clock injected, no I/O) |
| `notify/helper.rs` | the NDJSON v1 codec, sibling discovery, the one owning driver |
| `notify/terminal.rs` | the `_notify-click` script, its directory and the `open` argv |
| `notify.rs` | settings, eligibility (`should_notify`), the session's `NotifierHandle` |

Two reasons, in order. **The click is a security boundary**: it validates
operands, creates an executable file under `$HOME`, quotes shell words and
escapes diagnostics, and every one of those rules is testable on both platforms
where Swift is not. **And there is nothing to gain from Swift elsewhere**: Xcode
CLT is already required for bundles, and keeping the logic in Rust adds no
`objc2` dependency to the workspace.

The Swift side must not invent a field, a tag or a version. The Rust side is
authoritative, and it tolerates unknown *events* so an older launcher survives a
newer helper — never the other way round. Swift derives the sibling
`../../bin/agent-vm` from `Bundle.main.bundleURL` and spawns it through
`Foundation.Process` with literal argv and isolated stdio: it never calls
`execve`, and a click never replaces the process that is serving banners.

### Sibling-only discovery

`notify::resolve_notifier` has exactly one candidate:
`<resolved exe>/../../lib/AgentVMNotifier.app/Contents/MacOS/AgentVMNotifier`,
and only when the executable's parent is named `bin`. There is deliberately no
fallback from `target/debug/agent-vm` to `target/macos-dev/lib/…`, because
pairing a launcher with a callback from a different build is worse than posting
no banner. A missing bundle — bare `cargo run`, `--single-binary`, Linux — is
`None`, and the launch silently keeps ADR-0064's hint and `agent-vm access`.

### Publication: a versioned generation behind a symlink

`<bundle>/lib/AgentVMNotifier.app` is a relative symlink to
`.AgentVMNotifier.gen-<n>.app`, a direct sibling, so `../../bin/agent-vm` keeps
the same depth whether or not the path is resolved (Phase 0 confirmed both the
identity and the sibling lookup survive the symlink).

The build stages the helper at the per-PID `lib/.AgentVMNotifier.stage.$$`,
validates it there — `plutil -lint`, arm64-only, `codesign --verify --deep
--strict`, and `--version` answering `agent-vm-notifier <version>` — and only
then publishes. Selection, move, swap, retirement and registration run under a
`mkdir` publication lock (`mkdir` is atomic on BSD and GNU, needs no new tool,
and the holder's PID is recorded so a build that died can be told from one that
is working). The swap itself is one rename of the symlink, which is what
replaced the destructive `rm -rf` of a live bundle.

**This is not bundle-wide atomicity, and the ADR says so.** `agent-vm`, `msb`,
`libkrunfw.5.dylib` and the helper are renamed one at a time after shared
pre-commit validation; there is no cross-file transaction. What makes an
interrupted publish survivable is that NDJSON v1 tolerates unknown fields in
both directions, so a half-updated pair still speaks a protocol: the failure
mode is a launcher that ignores an event, not a session that breaks. Two
concurrent builds of one bundle are serialized by the lock, and the last writer
wins per artifact.

A first-time publish over a pre-generation layout renames the real directory
aside, swaps, and restores it on failure, so the error's claim that the previous
helper is still in place is true in both layouts. After the swap, the build
asserts `readlink` names the generation it just built; otherwise nothing is
registered or retired.

**Retirement precedes registration.** Older generations are *renamed* into
`lib/.AgentVMNotifier.retired.$$` before `lsregister -f` and deleted after,
because Phase 0 measured that with two generations registered LaunchServices
launches the **older** one: a failed prune is then a stale binary rather than a
stale path, and a retired generation is never missing while still registered.

Two residuals are accepted and written down. A lock directory observed before
its `pid` file is written is treated as stale, so the loser may delete the
winner's lock — the winner then fails loudly instead of publishing
unserialized. And the three runtime artifacts stage through fixed `*.next`
names, so a kill between `install` and `mv` leaves a file the next build
overwrites.

### One identity for every copy

Every copy — release, `--dev`, relocated — carries
`CFBundleIdentifier = dev.agent-vm.notifier` (`Info.plist.in`) and an ad-hoc
signature stamped with the same identifier
(`codesign --force --sign - --identifier dev.agent-vm.notifier`), with
`LSUIElement` set so the helper has no Dock icon. System Settings therefore shows
one "agent-vm" toggle. The identifier is passed explicitly on every build
precisely because without it each build would look like a different app.

**LaunchServices routes a cold click to whichever copy registered most recently,
and a mixture of registered copies can therefore answer with an older build.**
That is acceptable rather than ignored: the banner's `userInfo` carries the
exact `--session`, `--project`, `--state-dir` and `--terminal` over the stable
`_notify-click` interface, so any compatible copy still opens the clicked
session in its own project and state root. A stale copy is a stale *binary*,
never a misroute. Registration failure after a committed publish warns instead
of aborting, because the files are already in place and an unregistered record
self-heals — Phase 0 watched a pruned, unregistered generation disappear from
`lsregister -dump` and the next launch go to the new one.

### What a banner says, and when (`PromptSignal`)

The prompt publishes sequenced signals — `Baselined`, `Queued`, `Cutting`,
`Shown`, `Declined`, `AlreadyAnswered`, `Answered`, `InputEnded` — each carrying
`(entry_id, count, observed_at)` and, for the answer signals, the `Allowance`
named. The coalescer is a pure state machine over them, with the clock passed
in, so the rules under argument are testable without a helper, a socket or
Tokio:

- **Immediate** when there is no prompt (piped, `-T`, `attach`, streaming,
  `AGENT_VM_NO_ACCESS_PROMPT=1`, or an entry the prompt could not ask about):
  the first sight of a refusal posts.
- **Otherwise 5 s after the question becomes visible** (`Shown`, the
  cursor-position reply or the 1 s fallback). Typing does not delay it; the
  500 ms settle window is inside the 5 s.
- **5 s in `Cutting`** is the backstop, so a stalled writer cannot hold a
  refusal back for ever. `Queued` has no timer at all, so an item can never age
  into a visible one across the prompt's 2 s release gap.
- **An answer disposes of the attempt it names, whenever it is observed.** The
  plan compared the answer's instant against the attempt's deadline; that made
  the outcome depend on whether the driver drained the signal before or after
  the poll that posted. Here the count scopes an answer and the clock decides
  nothing, so both orders agree. The dissenting review held that the 5 s promise
  should be absolute; the reason it is not is that the banner is the fallback
  route for attempts the terminal did *not* answer, and under a late poll the
  absolute rule posts for an attempt that stopped mattering 20 s earlier.
- **An answer is a submitted line.** `s`/`session`, `p`/`project`, `d`/`deny`, an
  empty line, Esc and Ctrl-C are answers; `n`/`never` additionally suppresses
  that canonical `Allowance` for the session. Typing, Backspace, an
  unrecognised line, `s` where the session grant is not on offer, and anything
  inside the settle window are not answers and emit nothing (ADR-0069's
  amendment, which the coalescer inherits rather than re-derives).
- **Signals act only on an equal count.** An entry the guest has retried past
  keeps its newer attempt: a count-1 `Shown` may not start attempt 2's grace at
  attempt 1's visibility, and a count-1 `Declined` may not post attempt 2 with
  none.
- **One banner per session** (`agent-vm.<hash>.<sid>`), grouped per project
  (`agent-vm.<hash>`), replaced in place. A repeat while a banner is up posts
  `.passive` (`willPresent` answers `[.list]`) unless it names a destination the
  banner has not carried yet, which is news and pops (`[.banner, .list]`). Posts
  are at most one per 3 s window; the session's end is the one explicit
  exception, and a teardown never removes a banner.
- **Banners are silent.** No `content.sound`, and authorization asks for `.alert`
  alone, so the permission prompt does not imply otherwise. A banner may arrive
  every 3 s while a guest retries a blocked host; an audible one would make the
  noise the operator is trying to be free of. `script/test/notifier-contract.sh`
  pins both source lines, since silence is not observable without a GUI session.

Out-of-order arrival is handled rather than assumed away: a signal for an entry
the feed has not reported yet is buffered per entry and replayed, because a
lagging refusal feed must not turn a `Declined` into 5 s of waiting or lose an
answer.

### The notifications-off line is a second ADR-0064 hint

When macOS reports notifications denied, the operator gets one line, through the
machinery that already exists:

```text
==> macOS notifications are off for agent-vm; run `agent-vm access` to see refusals (shown once per session)
```

It is a second `refusal::feed::Hint`, so it is once per session, goes to stderr,
and takes the relay's route when the prompt owns the terminal — deferred to
`Phase::Idle` at a safe boundary so it cannot land inside a question, and
printed by the epilogue after the restore if it is still owed. Answering the
question claims only the refusal hint: an answer says nothing about
notifications. `HintRelay::bytes()` is derived from the hint's own line rather
than a fixed frame, which is what keeps the two lines from swapping sentences.

Posting stops for the session at that point. The refusal feed is never blocked
on it.

### Teardown order: `close_socket()`, then the notifier

`LiveSession::finish` closes the session to policy changes first
(`allowances.end_mutations()`), then stops the follower, drains, persists, and
finally runs `close_socket().await` **before**
`finish_notifier(snapshot, final_status)`.

The gate comes first because the persist takes a bounded but real time: without
it, a concurrent `agent-vm access allow` could commit against a session whose
persisted record already said it ended, and the record and the session would
disagree about what was allowed. Closing the socket earlier is not the fix —
`live.ended()` needs the runtime to answer. `end_mutations` takes the same
operation lock a grant takes, so every grant is wholly before the gate or wholly
after it, and one after it is refused with `SessionEnding` and recorded nowhere.
The prompt's own answer is exempt: it is spawned as the guest exits, and an answer
the operator already gave is not cancelled by the session ending.

The order is also the banner's guarantee: a final banner can never offer a grant
this session would refuse, because `agent-vm access --session <ID>` classifies the
session `ended` from `refusals.json` the moment the banner exists, and offers only
`--project`.

The final post is sent only when the final write **persisted**. A failed or
timed-out persist suppresses it — a banner may not claim durability the log does
not have — and the helper is quit without a `remove`, so a delivered banner
stays clickable as a record of an ended session. What that click then shows is
the honest answer to the same question: the last persisted snapshot, or
`no session <ID> in this project's running sessions or refusal log` and an
interactive shell, if the entry never reached the file.

A click approves nothing. It opens one host terminal in the session's project and
state root running `agent-vm access --session <ID>`, with the bundle's `bin` on
`PATH`, and leaves the shell open for an `access allow` the operator types.

### The authorization gate fails open

`auth` is emitted twice: immediately with the current status (`notDetermined`
while the first-run dialog is pending) and again when it settles. The dialog is
human-paced, so no timeout can be right; while the driver sees `notDetermined` it
sends no post and therefore starts no acknowledgement timer, counts no failure,
suppresses the idle exit (quitting would take the dialog down), and reports no
deadline. Owed entries stay in the coalescer, so nothing is lost. Settled
`authorized` releases them; `denied` fires the line above and stops posting.

Only an explicit `notDetermined` frame gates anything: a helper that never sends
`auth`, and a helper that died, gate nothing. A silent helper must not be able to
silence notifications.

### `--single-binary` is excluded

`swiftc` is required by `preflight_bundle` only, i.e. for the default and `--dev`
bundles. `--single-binary` checks nothing, touches neither bundle, and by
construction has no sibling `lib/`, so discovery returns `None` and the launch
falls back to the hint. ADR-0041's packaging is unchanged.

## Consequences

- **What the ticket asked for, on one platform.** A piped or prompt-less launch
  that hits a blocked host gets a banner; a terminal launch gets it 5 s after a
  question nobody answered; a click opens the session's own report. Everything
  else — SSH (any of the three variables ssh sets), `sudo`/root, Linux,
  `--single-binary`, bare `cargo run` — gets ADR-0064's hint and `agent-vm
  access`, and no warning.
- **A banner is not a notification centre.** One per session, replaced in place,
  removed when the last entry it speaks for is answered; the flood interval is 3 s
  because a retrying guest would otherwise be a banner storm.
- **Not proven by CI.** GitHub's runners are headless, so nothing automated shows
  that Aqua delivers a banner or that a click opens a terminal. The build proves
  structure, architecture, signature and `--version`; the merge gates in §9.3 of
  the plan prove the rest on a real desktop, and they are what the release claim
  rests on.
- **Three processes on a click**: LaunchServices (or the serving helper) starts
  the helper, which starts `_notify-click`, which opens the terminal. A click
  therefore works after the launcher has exited, which is the point, and costs a
  helper start.
- **The permission toggle's survival across a rebuild is an identity question**,
  not a build one: it depends on macOS keeping the grant for an ad-hoc signed
  app whose cdhash changed. That is why the identifier is stable, why the
  question is recorded in `macos-build.md` rather than answered there, and why
  gate M7 exists.
- **Recorded, not recorded elsewhere**: the coalescer's revision token on
  `on_post_acked`; the 3 s `NOTIFY_FINISH_WAIT`; the 32-operation helper intake
  bound with `queue_full`; the two failure cap; the `$HOME`-following nuance in
  the click root walk; the suppression of `cd`'s stderr in the click script.
  These are implementation details the diary holds, not decisions.

## Alternatives rejected

- **Post from the launcher process.** It exits with the session, and a banner
  must outlive it.
- **A launch agent or a `launchd` job.** A per-session, per-project stream from
  a per-launch child is less host state than a daemon to install, keep alive and
  revoke.
- **`osascript`/`terminal-notifier`.** Both are a shell-out on the click path,
  and neither survives a cold click.
- **`renamex_np(RENAME_SWAP)` for the bundle.** Phase 0 showed LaunchServices
  accepts a symlinked `.app` and the sibling lookup resolves through it, so a
  host helper compiled at build time buys nothing.
- **A `config.toml` key for the terminal.** A click is not an interactive
  command, so there is no flag to override per launch; the choice is host
  presentation, and the environment scopes it (ADR-0069's *The setting*, same
  reasoning).
- **Re-installing the helper next to `target/debug/agent-vm`.** A launcher paired
  with another build's callback is worse than no banner.
- **A second output path for the notifications-off line.** A parallel relay, a
  new `OutputItem` variant and an epilogue were all rejected in favour of the
  hint seam's second slot.
- **Holding the banner while a line is typed but not submitted.** It would need a
  keystroke signal and would undo #494's fixed 5 s; the cost of not holding it is
  one banner that Enter removes.

## Verification

The coalescer is unit- and `proptest`-tested with an injected clock, including
out-of-order arrival, retry counts and the answer-versus-deadline race. The
driver is tested against an injected backend on a virtual clock, and the
production `ChildHelperBackend` against `harness fake-notifier` over real pipes
(`#[ignore]` child-contract tests on the units shard) with negative controls. The
click script is executed by a real `/bin/sh`. `script/test/notifier-contract.sh`
compiles the Swift helper on macOS and proves `--version`, `--check-bundle`,
arm64-only and a verifying signature, positive and negative. `macos-build.md`
records the inspect commands.

The end-to-end evidence — a banner on a real desktop, a live and a cold click, a
rebuild while a banner is in Notification Center, a denied toggle — is §9.3's
M1–M8, run on an Apple Silicon Mac and recorded in the PR body, never claimed
from a headless run.

## References

- The plan and its per-phase reviews: `#501` slice 4 (`implementation-plan.md`,
  `pr2-diary.md`, `phase0-gate.md` in the work artefacts).
- [#316](https://github.com/gregwebs/agent-vm/issues/316) for the wording and the
  experience, [#494](https://github.com/gregwebs/agent-vm/issues/494) for the 5 s
  and the prompt's hold, [#500](https://github.com/gregwebs/agent-vm/issues/500)
  for the helper direction.
- ADR-0064 for the feed, the hint and the control socket, ADR-0069 and its
  amendment for the prompt and the submitted line, ADR-0041 for
  `--single-binary`, ADR-0049 for the printed commands a click shows.
