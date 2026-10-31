# ADR-0054: Omit nodes a fork seed cannot carry

## Status

Accepted. Implementation decision for [agent-vm #483](https://github.com/gregwebs/agent-vm/issues/483).
Amends the copy-engine decisions of
[ADR-0013](0013-add-forked-mounts.md) and
[ADR-0014](0014-narrow-fork-mounts-to-directories.md); the directory-only root,
identity, store, locking and publication decisions there are unchanged.

## Context

`copy_opened` decided what a nested node was by opening it: the walk read a
child's type with `statat`, then opened it, then read the type again from
`fstat` and refused anything that was neither a regular file nor a directory.
`open(2)` on a UNIX socket fails — `EOPNOTSUPP` on Darwin, `ENXIO` on Linux —
so the refusal never ran for the case it looked written for. The seed died at
the open instead, and the error carried no child context:

```
Error: preparing mounts (including mounts from "…/config.toml"; --no-config-mounts skips them)
Caused by:
    0: initializing fork from "/Users/claude/.pi"
    1: Operation not supported on socket (os error 102)
```

A running Pi keeps live sockets under `~/.pi` (`dashboard/gateway-*.sock`,
`remote/locks/*.sock`), so the shipped `["agent", "~/.pi:fork"]` mount set
failed on every first seed. A FIFO, by contrast, reaches the refusal with a
clear message, because `O_NONBLOCK` lets its open succeed (unless its own mode
forbids reading).

## Decision

Refusal becomes omission, and the classification moves before the open.

- **Classify before opening.** The walk already knows the child's type from its
  own `statat`; a socket, FIFO, character device or block device is recorded and
  skipped without an `openat` — so a socket that is standing there is never
  opened, which is the whole failure. The `:fork:follow-links` path stats the
  followed target for the same reason: the `openat` that would materialize it
  fails on a socket exactly as the walk's own open does.
- **A snapshot cannot carry these nodes.** A copied socket is a dead path that
  stops the guest's own process from binding it, and a copied device node needs
  privileges the copier does not have. So a seed the copier can observe writes
  nothing in their place and does not fail on them — the same "write nothing at
  all" rule the protected-file omission already follows (ADR-0014 removed mask
  machinery). A node whose own *open* fails is still refused — except a socket,
  whose open always fails; that case is the re-read bullet below.
- **One notice per omission**, in the shape `==> Omitted socket
  dashboard/gateway-9999.sock from the fork of <spelling>`, sharing the
  protected-file notice's path escaping (#419). `CopyReport` therefore carries
  two omission kinds: a protected host file (ADR-0020) and a node with no data
  to copy.
- **The type is re-read when a socket's open fails anyway.** A live source can
  grow a socket between the walk's `statat` and its `openat`, and that open then
  fails with the error this ADR is about. The node is read once more and omitted
  if it is by then a socket **and** the error is one a socket's open answers
  with (`EOPNOTSUPP` on Darwin, `ENXIO` on Linux). One re-read, never a retry
  loop, and no claim that the interval is closed: a fork seed is still not an
  atomic snapshot of a source that changes while copying. The narrow gate is
  deliberate — see the next bullet.
- **A failed open keeps its error.** The gate is one kind and two errors — a
  socket cannot be opened on any platform (`EOPNOTSUPP` on Darwin, `ENXIO` on
  Linux) — so only that pair recovers. Every other failure is the open's own
  (`EACCES`/`EPERM`, `EMFILE`, `EIO`, `ELOOP`, `ENOENT`) and is reported as
  before. The gate is not a proof of what the node became: a device node answers
  `NXIO` too, so a node that changed twice — device, then socket — is omitted on
  an error a device raised. That narrow ambiguity is accepted rather than
  widening the recovery, because the alternative is converting an unreadable
  regular file's `EACCES` into a silent omission. The visible cost is a seed that
  refuses where it could have omitted, which is the cheaper error.
- **Omission needs the type, never the bytes.** A node the walk classifies is
  never opened, so its own mode cannot stop a seed: a mode-`000` FIFO standing in
  the source is omitted like any other, because the decision needs its type and
  not its contents.
- **A special node whose open succeeds is omitted at its descriptor.** A FIFO
  the copier may read opens under `O_NONBLOCK`, as a readable device node may, so
  the copier still classifies the descriptor it was handed and omits those there.
  That is the same decision, taken at the second place a node can be observed.
- **What stays refused.** An unreadable regular file or directory, a symlink
  cycle, an over-long follow chain, a fork root that is not a directory, and a
  node whose type this build does not recognize (`FileType::Unknown`) all still
  fail the seed: omission is a decision about four known kinds, not a general
  "copy what you can". Links are not among them — the default policy copies a
  nested link as a link, and `:fork:follow-links` classifies the target instead.
  A special node whose open fails for a reason other than a socket's own is a
  refusal too, not an omission (the failed-open bullet).
- **`:exclude=REL` stays silent.** An excluded node is not an omitted one: the
  walk never inspects it, so nothing is reported.

## Consequences

- A `:fork` of a live state tree seeds. The documented workaround
  (`:exclude=` the directory holding the socket) is no longer required.
- A fork can silently lack a socket, FIFO or device node that its source had.
  The notice names each one, and the rule is stable: a fork carries data, not
  endpoints.
- The FIFO copy-refusal test in `mount.rs` (`a_fork_copy_*_escapes_the_measured_name`)
  now asserts the escaping on the omission notice it produces, because that node
  is no longer refused.
