# Add forked mounts

## Status

Accepted. Superseded by [ADR-0014](0014-narrow-fork-mounts-to-directories.md) for file-root forks and live exclusions; the identity, store, locking, publication, and fail-closed recovery decisions remain applicable.

## Context

A live bind mount is useful for a working tree but unsuitable for a reusable
writable import: it leaves guest and host coupled. Users need to seed
configuration once, then let project state evolve independently. They also need
to hide mount-local paths without allowing a nested mount to reveal them again.

## Decision

Add `:fork` to `--mount`. A fork is keyed by a versioned identity over its exact
source spelling, normalized guest path, follow policy, and normalized exclusion
list. Its first successful launch copies a regular file or directory into
host-managed project state; later launches mount the committed `data` entry and
do not inspect the source.

`exclude=REL` is repeatable on all valid modes. `REL` is a nonempty normal
relative path. Live exclusions use readonly opaque masks: an empty tmpfs masks a
directory and a shared readonly zero-byte regular file masks a file. Fork
initialization omits excluded content. The complete mount plan rejects a core,
explicit, or followed mount that would pierce a mask.

Nested symlinks are copied as links by default. `:fork:follow-links` explicitly
materializes their targets in owned fork data instead of adding a live external
bind. The declaration root is resolved once on its first seed and must resolve
to a regular file or directory.

The mount store is a sibling of guest-visible project state. It contains
no-follow private `locks`, `staging`, and `forks` directories. An exclusive
per-identity lock spans the READY recheck, copy, manifest write, and same
filesystem rename:

```text
ABSENT -- lock --> COPYING (staging) -- atomic rename --> READY
                         | failure/process death
                         v
                    unmounted stale staging; next holder cleans and retries
```

A READY entry requires a matching versioned manifest and correctly typed,
non-symlink `data`. It fails closed if malformed; agent-vm never auto-reseeds
what may be valuable guest state. This guarantees process-crash atomic
publication, not power-loss durability or an atomic snapshot of a source that
changes during copying.

## Consequences

Forks consume space equivalent to their initial copy and deliberately do not
synchronize in either direction. A user resets one by stopping every launch
using it, removing the exact reset directory printed by the launcher, and
launching the same declaration again. Changing an identity input creates a new
fork. File and directory exclusions on a live mount require existing regular
file/directory targets and are rejected through unresolved symlink ancestors.
