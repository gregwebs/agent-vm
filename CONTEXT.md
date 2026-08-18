# CONTEXT.md — domain vocabulary

Terms used consistently across code, comments, docs, and commit messages in
this repo. When a term below conflicts with something already in the code,
the code is the bug — file it, don't silently reintroduce the old name.

## Guest user

The identity the in-guest agent process runs as (the numeric `uid:gid`).
`.user(...)` is set in **two** places, both load-bearing, for different
reasons (see `docs/adr/0001-non-root-guest-via-native-user.md`):

- On the **sandbox builder** (`run.rs`, before `Sandbox::create`): drives
  agentd's `InitResolved.default_user`, which the host installs as
  passthroughfs's `BindIdentityMap` — this is what makes bind-mounted
  files (HOME/project/state) stat with owner bits matching the guest's
  real uid instead of uid 0.
- On the **per-exec attach/exec builders**: governs the actual `setuid`
  of the exec'd process (PID 1 / agentd stays root so it *can* `setuid`
  per exec).

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

## Guest username

The **cosmetic** name attached to the guest user's numeric uid — what
`whoami`/`$USER`/the shell prompt show. Distinct from the "Guest user"
above (the access-control identity): a username mismatch doesn't change
what files the guest can access, it just makes `whoami` say something
misleading.

Resolved env-first (`resolve_guest_username`/`choose_guest_username` in
`run.rs`): `$USER` → `$LOGNAME` → the passwd-DB name for the uid
(`getpwuid_r`) → the numeric uid as a string, each non-numeric candidate
checked against a safe `/etc/passwd` charset and skipped on failure.
Env-first because on this project's reference dev host `getpwuid(uid)`
returns no entry at all for the real host uid while `$USER` is reliably
set. Default in non-root mode: the host user's own username (`agent`
no more). See `docs/adr/0002-mirror-host-home-and-username.md`.

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

- **Non-root mode (default):** the **mirrored host `$HOME` path** (e.g.
  `/Users/claude`) — a real bind mount (not a symlink) of the host-owned
  `<state_dir>/home`, provisioned host-side by
  `ProjectSession::provision_guest_home` (`crates/agent-vm/src/session.rs`)
  and mounted at the host path by `run.rs`'s `core_dir_volumes`. Mirroring
  the literal host path (not `/agent-vm-state/home`) is consistent with
  the guest's project-path mirroring, so `$HOME`-relative paths stay
  interpretable on the host. See
  `docs/adr/0002-mirror-host-home-and-username.md` for the bind-vs-symlink
  rationale and the nested-mount ordering this depends on when the
  project lives inside `$HOME`.
- **Root mode:** `/root` — dotfile symlinks baked into the rootfs by
  `run.rs`'s `.patch()` block, unchanged.

Both modes share one symlink mapping,
`session::GUEST_HOME_LINKS`, so the two provisioning paths can't drift.
