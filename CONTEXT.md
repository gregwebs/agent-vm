# CONTEXT.md — domain vocabulary

Terms used consistently across code, comments, docs, and commit messages in
this repo. When a term below conflicts with something already in the code,
the code is the bug — file it, don't silently reintroduce the old name.

## Guest user

The identity the in-guest agent process runs as (the uid/gid `.user(...)`
resolves to on the microsandbox `attach`/`exec` builders — see
`docs/adr/0001-non-root-guest-via-native-user.md`).

- **Default: the host user.** The uid/gid of whoever invoked `agent-vm`
  (`libc::getuid()`/`getgid()`), so the guest agent runs non-root inside the
  microVM — defense-in-depth on top of the microVM boundary itself, and
  required to keep write access to the host-uid-owned project/state bind
  mounts (a non-root guest uid gets owner bits from passthroughfs only when
  it matches the real host uid).
- **`--root` / `AGENT_VM_ROOT`** restores the legacy **root guest** (uid 0)
  — see below.

_Avoid_: "dev user", "container user" — this isn't a fixed image account,
it's whichever uid launched `agent-vm`.

## Root mode

The opt-out, enabled by the `--root` flag or a truthy `AGENT_VM_ROOT` env
var (same `1|true|yes|on` convention as `AGENT_VM_UPDATE_CHECK`). Runs the
guest as uid 0 with `HOME=/root` — the pre-non-root-default behavior.
Required for docker-in-VM (dockerd needs root); the Chrome MCP uses its
`sudo -u chrome` path only in this mode.

_Avoid_: "privileged mode" — the microVM boundary applies identically in
both modes; root mode only changes the *in-guest* uid.

## Guest HOME

The in-guest `$HOME` for the current guest user mode:

- **Non-root mode (default):** `/agent-vm-state/home` — a directory inside
  the host-owned `/agent-vm-state` state bind, provisioned host-side by
  `ProjectSession::provision_guest_home` (`crates/agent-vm/src/session.rs`).
- **Root mode:** `/root` — dotfile symlinks baked into the rootfs by
  `run.rs`'s `.patch()` block, as before this change.

Both modes share one symlink mapping,
`session::GUEST_HOME_LINKS`, so the two provisioning paths can't drift.
