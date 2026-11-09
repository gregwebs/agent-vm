# ADR-0064: A read-only refusal feed on a session control socket

## Status

Accepted and implemented in **0.7.42**
([#501](https://github.com/gregwebs/agent-vm/issues/501) slice 1). Amends
[ADR-0038](0038-config-dir-exposure-guard.md): two more host-only stores join the
measured set, and the `.sessions` directory gains a rule the writable-bind guard
cannot express. Grants, revokes, `access allow|allowances|revoke`, `--project`,
`--all-sessions`, the TTY review mode, the in-terminal prompt, the macOS
notification helper and connection listing are **not** decided here.

## Context

The runtime records every refused egress decision in
`<MSB_HOME>/sandboxes/<name>/logs/network.log`: one JSON line per refusal, with
the site, the layer, the protocol, the destination, guest-supplied name evidence
and the tenant policy revision. The file rotates at 10 MiB with four retained
siblings and **dies with the sandbox**, so it cannot answer the question a user
actually has after a run: what did it refuse, and why can nothing be done about
it yet?

Three questions had to be settled together, because each one constrains the
others:

1. **Who keeps the record?** A file under the project's state root, written by
   the launcher, is the only place that outlives the VM. That makes the launcher
   a writer of host state on the launch path, which every other agent-vm store
   treats as a boundary it must not cross casually (ADR-0047, ADR-0063).
2. **How does `agent-vm access` see a *live* session?** Listing the runtime's
   database or calling `pid_alive` were both rejected by
   [#301](https://github.com/gregwebs/agent-vm/issues/301): `pid_alive` always
   returns false on macOS, and the msb DB is the runtime's, not the launcher's.
   A socket the launcher owns is the only answer that also serves a future GUI.
3. **What can the guest reach?** A writable bind of an ancestor of `MSB_HOME`
   lets a guest forge or erase any sandbox's `network.log`, and a bind of
   `<hash>.sessions` names the refusal artefacts themselves. ADR-0038's guard
   refuses a writable bind that *is or contains* the authority directory and
   deliberately exempts `:ro`/`:fork`; it does not cover a guest-writable
   `MSB_HOME`, and it cannot express "this bind is *inside* the store".

## Decision

1. **The launcher keeps one bounded, host-only project refusal log.** It lives at
   `<state root>/<hash>.sessions/refusals.json` — a sibling of the guest-visible
   `<state root>/<hash>`, like `<hash>.secrets` and `<hash>.mounts`. The file is
   `{"v":1,"evicted_sessions":n,"sessions":[…]}` where each session is one
   `SessionSnapshot`: identity, revision, timestamps, three counters and at most
   512 entries. The whole log is bounded at 2,048 entries and 2 MiB, and a
   session with no activity for 30 days is pruned.

2. **It may self-heal, unlike an authority store.** `refusals.json` decides
   nothing: an authority store that heals would authorize content nothing
   measured (ADR-0047's rule), while a display log that refuses to heal would
   leave a user with no way to see refusals. So a damaged file is renamed
   `refusals.json.damaged` and rewritten, and a file whose `v` is *greater* than
   this build's is never overwritten — it is read, and one warning says so. The
   locking and replacement mechanics are ADR-0047/0063's: one `flock` on
   `refusals.lock`, one read-modify-write, `atomic_write` at mode 0600 in a
   directory that must be a real 0700 directory owned by this euid. Anything else
   is not adopted: one notice names it and the session runs without a feed.

3. **Writers are serialized and eviction is deterministic.** Every write is a
   whole read-modify-write under the lock, so two sessions in one project cannot
   lose each other's update to a race. Eviction drops whole *other* sessions —
   ended first, then socketless, then live, oldest activity first, ties by
   session ID — and counts each one, so the footer can say how many. An evicted
   live session is restored whole by its owner's next write, which is what makes
   evicting it safe. The writer's own session is never evicted.

4. **A session ID is reserved under that same lock.** Eight lowercase hex from
   the kernel CSPRNG, drawn under `flock` with the socket bound inside the
   critical section; a candidate already in the log or already bound is redrawn
   (up to four attempts). Unique-within-a-project is then a property, not a
   probability. The ID is stored in the log and never recomputed.

5. **The feed is one task and the file is one thread.** `follow` opens
   `LogSource::Network` from the beginning, follows it, and folds each record
   into one entry per `(kind, destination)`. Every change bumps a revision and is
   published as an *absolute* `Update` — the entry that moved plus all three
   counters — so a client needs no state machine and a client that missed
   something is corrected by the next update. The persister is one thread holding
   at most one pending job; it keeps the newest, drops a job older than what it
   has written, and treats the final snapshot as terminal. File I/O never runs on
   the runtime.

6. **A missed rotation is a gap, not a watermark.** `MissedRotation` and an
   `InvalidCursor` both mean the file being read has left the retention chain, so
   every retained file is *newer*: the feed reopens from the beginning without
   double counting and marks a gap whose size is unknown. Any other error resumes
   from the last cursor, three times a second apart, then stops following. The
   session continues either way.

7. **The control socket is `<state root>/<hash>.sessions/<sid>.sock`.** Directory
   0700, socket 0600, the peer's UID must equal the euid, and there is no TCP
   listener — `--allow-host` exposes host loopback, so a TCP one would be
   reachable from the guest. It is bound **before** `Sandbox::create`, so a
   session that is still starting cannot miss a change aimed at it
   ([#301](https://github.com/gregwebs/agent-vm/issues/301)). Over the platform's
   `sun_path` budget: one notice, `socket = false`, and the launch continues.

8. **Protocol v1 is revisioned NDJSON, and the handoff is race-free.**
   `list` answers with the whole session and closes; `subscribe` answers with a
   snapshot followed by absolute updates, a fresh snapshot after the subscriber
   lags, and `ended` at finish. The snapshot and the subscription are taken under
   the *ingest* lock, so an update can be neither lost between them nor delivered
   twice into the snapshot. A client ignores any `rev` at or below its last. A
   semaphore of 16 connections reserves four of them for non-subscribers, so `list`
   always has room, and a subscriber that stops reading is dropped rather than
   allowed to slow the feed.

9. **Discovery lists the directory; it reads no database.** Only
   `[0-9a-f]{8}.sock` entries that `lstat` shows are euid-owned sockets are used;
   symlinks are never dialled or removed. A refused connection is a stale socket:
   it is unlinked and the session is reported from the log. A timeout is a session
   that is alive but busy: it is reported as `not responding`. Queries run
   concurrently under a total deadline, so one hung session cannot delay the rest.

10. **One teardown hook, so the order is fixed.** `ExecTeardown` gains
    `before_remove`, called once by `cleanup_exec_sandbox_failures` after the
    stop/kill/reap block and before `remove`, in both modes and whatever the
    earlier steps did. The order is therefore **producer stop → drain → persist →
    remove** on every path that removes this session's sandbox. After an ordinary
    stop the runtime has flushed its log at VM exit; after a forced or escalated
    kill the unflushed tail is lost, and that is deliberate rather than
    discovered. `LiveSession`'s own `Drop` is nonblocking, so a launch that errors
    before `create` still stops following and leaves no socket.

11. **The guest cannot write any refusal artefact.** ADR-0038's measured set gains
    two stores — `<hash>.sessions` and `MSB_HOME` — through its existing
    predicates (`R1`), and a new rule refuses a bind in **any** mode whose root is
    `.sessions` or lies inside it (`R2`), because a `:ro` bind of
    `refusals.json`, `refusals.lock` or a socket names one artefact whatever its
    mode says. D3's `:ro`/`:fork` exemption is about *ancestors* and stands. The
    accepted gaps are ADR-0038's, plus: a hard link to `refusals.json` names a
    stale copy (the file is replaced by rename), a link to `refusals.lock` is only
    possible for the host user, and a guest cannot take a host `flock` at all
    (msb_krun_devices answers `setlk` with `ENOSYS`).

12. **Wording, once.** One hint per session, at the first refusal, delivered
    detached so a stalled stderr delays nothing:

    ```text
    ==> The sandbox refused a guest network request; run `agent-vm access` to see refusals (shown once per session)
    ```

    Framed `\r…\r\n` on a terminal so a half-written guest line cannot swallow it.
    No guest text appears in it. The row's action column says why nothing can be
    done in this version: `no grant in this version; relaunch with
    --allow-egress` for a network denial, `can't be allowed: platform policy` for
    the platform floor, `can't be allowed here: credential policy` for a secret
    violation, and `can't be allowed: built-in rule <site>` for any other engine
    rule.

13. **Nothing here can fail a launch.** No directory, no lock, no socket path, no
    disk, no follower and no client may turn into a launch failure. Each degrades
    to a notice and a smaller feature: no log, no live view, or no feed.

## The guarantee

A guest bind cannot write `<hash>.sessions`, anything in it, or any
`network.log` under agent-vm's `MSB_HOME` (`R1`, `R2`, and the fork's own guard
inside `MSB_HOME/sandboxes`). This is **integrity, not confidentiality**: a
`:ro`/`:fork` bind of a strict ancestor (for example `~:ro`) can read the
records, which D3 accepts because they hold no payloads, and an older launcher
installs no guard at all.

## Consequences

- **Breaking for some state roots.** A state root inside the project, or under a
  writable `--mount`, is now refused (D2). On Linux that includes
  `MSB_HOME = <state root>/msb-home`; on macOS the default
  `~/.agent-vm-msb` is reachable only through `$HOME`, which was already refused.
  USAGE documents the move to a new state root, and that an existing `.sessions`
  is adopted only when it is a real 0700 directory owned by the user.
- **At most about 3 s** is added to teardown: a 1 s lock wait plus I/O for the
  final write, a 2 s bound on the drain, and 500 ms for open connections.
- **Entries keep `last_revision`** even though slice 1 decides nothing with it, so
  coverage filtering ("already covered by an allowance drops out") can be added
  without a second pass over the runtime's records.
- 403s synthesized by `_intercept-hook` are not runtime records and never appear;
  sandboxes created through `agent-vm msb` passthrough are not this launcher's
  sessions; `doctor` reports neither.

## Alternatives rejected

- **Read the runtime's `network.log` from `access` directly.** It dies with the
  sandbox, so it cannot answer "what did the session that just ended refuse".
- **Discover sessions with `pid_alive` or the msb database.** `pid_alive` always
  returns false on macOS; the database is the runtime's.
- **A TCP control socket.** `--allow-host` exposes host loopback to the guest.
- **Journal the log like an authority store.** A display store that will not heal
  leaves the user with nothing; the journal exists to protect authority from a
  partial write, and eviction already destroys information on purpose.
- **Filter by an eviction *entry* rather than session.** An entry-level eviction
  would let a reader watch a row change under them; whole sessions also restore.
- **Count a missed rotation.** The number of records in a file that rotated out of
  the chain is not recoverable, and a fabricated count is worse than "unknown".
- **One hint per refusal, rate-limited.** A refusal storm would become a notice
  storm; the ticket asks for once per session.
- **A second `run_with_timeout` copy for the CLI's integration test.** The command
  is async and takes its sinks, so the whole command runs in process (#514).

## Verification

`refusal`'s coalescing and ID derivation are golden-vector tested; the log's
concurrency, eviction, damage and reservation are unit-tested; the feed is tested
against a fake stream **and** against the real SDK log engine over a hand-written
`network.log` with no VM, which is what pins rotation, the drain and the
persistence deadline; the protocol, the peer check and discovery are tested over
real sockets; `access` is tested in process against a real server and log; the
guard has unit and CLI cases. The end-to-end case (`RF1` in
`script/test/lib/egress-fixtures.py`) runs a default-deny guest, checks the live
rows and the hint during the run, checks the same IDs afterwards as `ended`, and
repeats with `kill -9` for `ended (unclean)`.
