# ADR-0050: One rule for a relative state root

## Status

Accepted. Resolves
[agent-vm #437](https://github.com/gregwebs/agent-vm/issues/437), found while
fixing #433 (PR #436).

## Context

`host_paths::state_root` returned `AGENT_VM_STATE_DIR` and `XDG_STATE_HOME`
verbatim, so either could leave every state path relative to whatever cwd
`agent-vm` happened to run in. `session.rs` carried a second copy of the same
precedence. `host_paths::cache_root_from`, one screen below, already took the
opposite position for `XDG_CACHE_HOME`: a relative value is invalid and
ignored, as the XDG basedir spec requires.

The state root is not just a directory to open. It holds the per-project state
directories keyed by the project hash, it is printed in `doctor`'s undo
instruction, and its paths are persisted in records, so a value that depends on
the cwd is a trap inherited by every future site. #433 was the first one to be
noticed: the undo command `doctor` asked the operator to paste later worked only
from the directory `doctor` ran in. #436 made that one printing site resolve to
absolute, which fixed the symptom, not the source.

`AGENT_VM_STATE_DIR` and `XDG_STATE_HOME` are not the same kind of variable,
which is why one rule for both would be wrong:

- `XDG_STATE_HOME` is the [XDG base directory
  spec's](https://specifications.freedesktop.org/basedir-spec/latest/): "all
  paths set in these environment variables must be absolute. If an
  implementation encounters a relative path in any of these variables it should
  consider the path invalid and ignore it." The spec says what to do, and
  `cache_root_from` already does it.
- `AGENT_VM_STATE_DIR` is agent-vm's own override, and the documented way to
  give each worktree its own state root (ADR-0004, ADR-0024, CONTRIBUTING.md).
  A typo there silently relocating every state path is worse than a refused
  launch; `$HOME` already gets that treatment in `config::host_home_dir`.

## Decision

**`host_paths::state_root` is the one implementation, and it can only hand out
an absolute root.** Its doc states the rule; the pure core `state_root_from`
applies it and is what the tests exercise.

| Source | A relative value | Why |
|---|---|---|
| `AGENT_VM_STATE_DIR` | error naming the value and the remedy | agent-vm's own override; falling back would move all state somewhere the operator did not ask for, silently |
| `XDG_STATE_HOME` | ignored; the next source is used, with one stderr notice | the XDG spec says to ignore it; `cache_root_from` already does the same for `XDG_CACHE_HOME` |
| `$HOME` (default) | error, via `config::host_home_dir`'s existing discipline | so the documented default is absolute too, not only under a launch |

Consequences of putting it at construction:

- `state_root()` returns `Result<Option<PathBuf>>`: `None` still means only
  "$HOME is unset", and an `Err` is a refused value, never a path that would
  have been used anyway.
- `session.rs`'s duplicate precedence is deleted; it calls `host_paths`.
- `msb_install`'s macOS short-root check (`state_root_overridden`) follows the
  same rule: a relative `XDG_STATE_HOME` was ignored, so it must not count as
  an override, or macOS would skip its short default for a value never used.
- `doctor` no longer calls `std::path::absolute` on `MSB_HOME` (#436); the
  invariant now comes from the root itself. The resolver's branch tests establish
  that every value it accepts is absolute; the undo test separately executes the
  printed command from a directory `doctor` never saw.
- `bin/agent-vm-ccusage`, which resolves the root in shell and claims to mirror
  the launcher, applies the same rules: `$HOME` validated, a relative override
  refused with the remedy, a relative `XDG_STATE_HOME` ignored with one notice
  naming the value and the root used. It renders an environment value through
  `printf '%q'`, because a newline in one must not forge a second diagnostic
  line. `crates/agent-vm/tests/ccusage_wrapper.rs` covers that matrix with a stub
  `npx` on `PATH`, so no VM or download is involved.

The stderr notice exists because ignoring a value is not a no-op: the state root
moves. It is one line on stderr, printed once per process and best-effort — a
closed stderr must not turn a valid fallback into a panic — so no
machine-readable output gains a line and no failure is invented. It names the
*state root*, which is the value `XDG_STATE_HOME` contributes to; on macOS
`MSB_HOME` can be the shorter default instead, and the report of whatever moved
names that path itself.

## Rejected alternatives

**Ignore a relative `AGENT_VM_STATE_DIR` too** — uniform with the XDG rule and
the smallest change. Rejected because an explicit override that is silently
discarded leaves the operator looking for state in a directory agent-vm never
used. The variable has no spec that says to ignore it; `$HOME`'s hard error is
the closer precedent.

**Reject a relative `XDG_STATE_HOME` as well** — consistent with the row above,
but the spec explicitly says to ignore an invalid value, and a variable shared
with other applications should not fail agent-vm's launch.

**Accept it and make it absolute at construction** (the issue's option 2) —
honors what the operator typed and still hands every caller an absolute path.
Rejected because a relative value would then keep meaning "relative to wherever
I ran", which is exactly the cwd-dependent behaviour that produced #433: two
worktrees sharing one spelling stay two roots, and nothing tells the operator.
Making the value explicit at construction is the right fix for a value that is
*supposed* to be relative; this one is not.

**An absolute-path newtype at the boundary** — parse-don't-validate, and it
would make the invariant a compile-time one for every caller. Rejected for now:
there is a single producer and the `Result` already forces each of the three
call sites to handle a refused value; a newtype would wrap the same `PathBuf`
and add mechanical conversions without removing a reachable mistake. The
absolute guarantee is a documented invariant of the one function, covered by a
unit test per branch.

## Consequences

- A relative `AGENT_VM_STATE_DIR` now fails the launch with a message naming the
  value; it no longer "works from this directory". Anyone relying on the old
  behaviour sets an absolute path, which CONTRIBUTING.md's example already did.
- A relative `XDG_STATE_HOME` is ignored where it used to be honoured; the
  stderr notice says so and names the root actually used.
- `state_root` can fail, so `doctor`, `session`, `msb_install` and the git
  identity cache each have a defined answer. The cache treats a refused root as
  "do not cache": the launch has already failed by then.
- The ordinary `doctor` header (`MSB_HOME:` and the `db:` line derived from
  it) prints absolute paths for the same reason, so it needed no change of its
  own (#438); a CLI test pins the header for both an ignored
  `XDG_STATE_HOME` fallback and an absolute override.
- The printed `doctor` undo instruction is absolute because the root is, not
  because that one site repairs it, so the site's `absolute()` call is gone. The
  guarantee is split across two kinds of test, because they catch different
  regressions: the resolver's branch tests and the CLI refusal tests reject
  relative input, while the undo test only supplies an already absolute root and
  proves the printed command runs from an unrelated directory. A resolver that
  started accepting relative values again would fail the first pair, not the undo
  test.
