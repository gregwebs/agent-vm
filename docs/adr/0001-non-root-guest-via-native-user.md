# ADR-0001: Non-root guest via microsandbox native user support

## Status

Accepted.

## Context

Historically the agent-vm guest process ran as root (uid 0) inside the
microVM. The original motivation attributed to that choice — "a root guest
would write root-owned files onto the host" — is **false** under
microsandbox's default stat-virtualization: its virtiofs daemon
(passthroughfs) runs on the host as the unprivileged launching user and
cannot `chown(2)` a physical file. It instead stores the guest's requested
uid/gid in a per-file `user.containers.override_stat` xattr while the
physical file stays owned by the launching user. So host-side ownership of
guest-created files is already correct today, regardless of the in-guest
uid — there is no uid *map* to get right, only a guest-visible xattr
overlay.

Two things this correction surfaces:

- **Pre-existing bind files carry no override xattr.** The project dir and
  the state dir are bind-mounted, not guest-created, so the guest sees
  their *real* host uid. passthroughfs's access check only grants owner
  bits when the guest uid equals the host uid on that file; root bypasses
  the check entirely, a non-root uid does not. So a non-root guest can only
  read/write the binds if its uid *matches* the host uid — this is a
  functional requirement, not cosmetics.
- The **surviving justification** for changing the default is the
  non-root security posture inside the guest — defense-in-depth on top of
  the microVM boundary itself — not file-ownership parity.

## Decision

agent-vm runs the in-guest agent as the invoking host user (`uid:gid`) by
default, using microsandbox's native `.user("uid:gid")` support on the
per-exec attach/exec builders. `agentd` (the guest's PID 1) natively
`initgroups`+`setgid`+`setuid`s before each exec, so this needs no gosu, no
image `dev` user, and no root-then-drop entrypoint — unlike the sibling
`claude-contained` project, which uses Apple's `container` runtime and
therefore *does* need a gosu-style entrypoint to drop root.

`.user(...)` is set on the attach/exec builders, **not** on the sandbox
builder — PID 1 (`agentd`) must stay root so it can `setuid` per exec.

Because `/agent-vm-state` is a *runtime bind mount* that shadows the
rootfs upper layer where `.patch()` writes (patches bake into `upper.ext4`
before the VM boots; the bind mount then covers whatever a patch wrote at
that path), the non-root guest's `HOME=/agent-vm-state/home` and its
dotfile symlinks are provisioned **host-side**, in the project's state
dir, not via `.patch()`. Root mode is unaffected: its `/root/...` symlinks
target un-shadowed rootfs, so `.patch()` remains correct there. Only
`/etc/passwd`/`/etc/group` (real rootfs, not under the bind) are still
patched, to give the appended uid a resolvable passwd entry.

`--root` / `AGENT_VM_ROOT` restores the legacy root guest for cases that
need it.

## Consequences

- Matching the host uid is **required**, not optional, for a non-root
  guest to keep write access to the project/state bind mounts.
- Docker-in-VM needs root (dockerd needs root), so it requires `--root`.
- The Chrome MCP wrapper runs chromium directly as the agent user in
  non-root mode instead of `sudo -u chrome` — the sudoers rule only grants
  `root -> chrome`, so a non-root agent has no sudo path to that user
  anyway, and a non-root uid already satisfies chromium's user-namespace
  sandbox precondition on its own.
- Agent binaries relocate to a shared, world-readable prefix
  (`/opt/agent`, `chmod -R a+rX`) so both guest-user modes resolve them at
  the same PATH entries, and `/root` (mode 0700) stays private. This also
  moves codex's `packages/` tree out of root's home — codex resolves
  `packages/` relative to its install location, not via the runtime
  `CODEX_HOME` env, so leaving it under `/root/.codex` would make it
  unreadable to a non-root guest even though `CODEX_HOME` itself points
  elsewhere for config/auth.
