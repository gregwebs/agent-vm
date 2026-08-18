# ADR-0002: Mirror the host `$HOME` path and username into the non-root guest

## Status

Accepted.

## Context

ADR-0001 made the default guest run as the invoking host user's `uid:gid`
(non-root), but stopped short of two cosmetic-but-meaningful pieces of
identity:

- **Username** was hardcoded `agent` — in the `/etc/passwd` append and the
  `USER`/`LOGNAME` exec env. So `whoami`, `$USER`, the shell prompt, and
  any tool that derives an author/identity from the username all said
  `agent`, not the real host user.
- **`$HOME`** was `/agent-vm-state/home`, an internal state path, not the
  host's actual home. This diverged from the guest's existing philosophy
  of mirroring the host **project** path exactly (so `file:line` output
  and `$HOME`-relative paths are interpretable on the host).

Neither is the *access-control* identity — that's still the numeric
`uid:gid` from ADR-0001, unaffected by this change. This ADR only changes
what `whoami`/`$USER`/`$HOME` report.

## Decision

In non-root mode, the guest's username and `$HOME` mirror the host's:
`$HOME=/Users/claude`, `USER=claude` on a host where `whoami`'s real
uid is 502, for example. Root mode is unchanged (`/root`, `USER` unset →
root).

### HOME is a real bind mount, at the literal host path, not a symlink

The guest's `$HOME` is set to the literal host `$HOME` string (e.g.
`/Users/claude`), even inside the Linux guest — consistent with how the
project directory is already mirrored at its real host path rather than
some internal alias.

It is mounted there as a **real virtiofs bind** of the existing writable,
host-owned `<state_dir>/home` — not a symlink to it. A symlink would let
the kernel canonicalize a nested project cwd (see below) into the state
dir, breaking exact-host-path mirroring for the project; a bind mount at
the real path has no such canonicalization effect.

### The load-bearing mechanic: nested-mount ordering

When the project lives *inside* `$HOME` on the host (e.g.
`/Users/claude/code/agent-vm` under `/Users/claude`), the project bind
nests inside the HOME bind at the guest-visible paths too. `agentd`'s
`apply_dir_mounts` (`vendor/microsandbox/crates/agentd/lib/init.rs`)
mounts virtiofs dir specs in list order, with no depth sort, and each
`mount_dir` does `create_dir_all(guest_path)` as root before mounting.
`MSB_DIR_MOUNTS` is `;`-joined in `.volume()` insertion order — confirmed
no sort anywhere in the pipeline, from `SandboxBuilder::volume()` pushing
into a plain `Vec<Mount>` through to the env-var join.

Consequence: if the **HOME volume is emitted before the project volume**,
agentd mounts HOME first, then `create_dir_all`s the project mountpoint
*inside* the already-mounted, writable HOME virtiofs, then mounts the
project over it — no pre-created mountpoint needed. When the project is
*not* under HOME, the two are unrelated siblings and order is irrelevant,
so emitting HOME first is unconditionally safe. `run.rs`'s
`core_dir_volumes` encodes this ordering (HOME, then project, then
`/agent-vm-state`) as a pure, unit-tested function, precisely because
`SandboxBuilder`'s internal mount list has no public read accessor to
assert against directly.

### Username is resolved env-first

Order: `$USER` → `$LOGNAME` → the passwd-DB name for the uid
(`getpwuid_r`) → the numeric uid as a string. Each non-numeric candidate
is checked against a safe `/etc/passwd` charset
(`^[A-Za-z_][A-Za-z0-9_-]*$`) and skipped (not truncated or escaped) on
failure — a `:`, space, newline, or non-ASCII byte in a candidate would
corrupt the appended `/etc/passwd` line.

Env-first, not passwd-first: on this project's reference dev host,
`getpwuid(uid)` returns no entry at all for the real host uid, while
`$USER` is reliably set. Passwd-first would silently fall through to the
bare numeric uid on exactly that host, which is a worse user experience
than reading the readily-available env var.

This mirrors how `$HOME` is resolved directly from the host's own
`$HOME` env var rather than reused from `session::state_root`'s `$HOME`
read — that one is a fallback for the unrelated *session state root*
(`~/.local/state/agent-vm`), not guest identity.

## Consequences

- `$HOME` unset on the host now surfaces as a `launch()` error in
  non-root mode (`resolve_host_home`'s `Context` message), rather than
  silently booting a guest with a broken `$HOME` — previously `$HOME` was
  a hardcoded literal, so it always "worked" regardless of host env.
  `--root` mode is unaffected: it never calls `resolve_host_home`.
- **Host-uid collision with a base-image passwd entry** is an accepted
  risk: if the host uid ever matched an image user (it doesn't today —
  the image has only `chrome:9999`/root), `getpwuid` would return the
  image's entry instead of nothing, and username resolution would still
  produce a plausible (if wrong) name. A prepend to `/etc/passwd` instead
  of an append could mitigate this if it ever bites.
- Git author identity, group *names* (only the numeric gid matters to
  agentd), and non-`/Users/...` host `$HOME` shapes are out of scope.
- Builds on ADR-0001's `bind_identity_map`/numeric-uid mechanism — this
  ADR only changes the *cosmetic* username/`$HOME` reporting, not the
  access-control identity.
