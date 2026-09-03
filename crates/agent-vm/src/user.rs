//! Guest user identity: root vs. non-root mode, and — in non-root mode —
//! the numeric uid:gid access-control identity plus the cosmetic
//! host-mirrored username/`$HOME` (see
//! `docs/adr/0001-non-root-guest-via-native-user.md` and
//! `docs/adr/0002-mirror-host-home-and-username.md`). [`resolve_guest_identity`]
//! is the single entry point `run.rs`'s `launch()` calls for the
//! consolidated identity; everything else here is either a private
//! implementation detail or a small pure formatter/ordering helper
//! `launch()` also calls directly (`core_dir_volumes`,
//! `passwd_append_line`, `group_append_line`, `guest_identity_env`).

use std::{
    env,
    ffi::CStr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

/// Safe-for-`/etc/passwd`-field username charset: a leading letter or
/// underscore, then any run of letters/digits/underscore/hyphen.
/// Anything else in a resolved username candidate (`:`, space, newline,
/// non-ASCII, …) would corrupt the appended `/etc/passwd` line, so a
/// candidate that fails this check is discarded outright by
/// `choose_guest_username`, never truncated or escaped in place.
fn is_safe_passwd_username(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Pure precedence + sanitization core of [`resolve_guest_username`],
/// split out so the fallback order and charset guard are unit-testable
/// without mutating process env or touching NSS (`getpwuid_r`) — mirrors
/// how [`should_run_root`] takes its env value as a parameter instead of
/// reading it internally.
///
/// Order: `user_env` (`$USER`) → `logname_env` (`$LOGNAME`) →
/// `passwd_name` (the passwd-DB name for `uid`) → the numeric `uid` as a
/// string. Env-first, not passwd-first: on this project's reference dev
/// host, `getpwuid(uid)` returns no entry at all for the real host uid
/// while `$USER` is reliably set — passwd-first would silently fall
/// through to the numeric uid on exactly that host. Each of the first
/// three candidates must pass [`is_safe_passwd_username`]; the numeric
/// fallback is used unchecked because it's synthesized (not external
/// input) and inherently `/etc/passwd`-safe.
fn choose_guest_username(
    user_env: Option<String>,
    logname_env: Option<String>,
    passwd_name: Option<String>,
    uid: u32,
) -> String {
    [user_env, logname_env, passwd_name]
        .into_iter()
        .flatten()
        .find(|c| is_safe_passwd_username(c))
        .unwrap_or_else(|| uid.to_string())
}

/// `getpwuid_r(uid).pw_name` as UTF-8, or `None` on any lookup failure,
/// missing entry, or non-UTF-8 name. SAFETY: `buf` is a fixed 16 KiB
/// stack buffer, well above any real system's
/// `sysconf(_SC_GETPW_R_SIZE_MAX)`; `getpwuid_r` only writes within
/// `buf`/`pwd` and retains no pointers into either after it returns, so
/// reading `pwd.pw_name` through `buf` once it returns `0` with a
/// non-null `result` is sound.
fn passwd_name_for_uid(uid: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; 16 * 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_str()
        .ok()
        .map(str::to_string)
}

/// Resolve the non-root guest's cosmetic username — see
/// [`choose_guest_username`] for the precedence/sanitization rules.
/// Thin, impure entry point: reads `$USER`/`$LOGNAME` and does the NSS
/// lookup; the actual logic lives in the pure core so it's testable.
fn resolve_guest_username(uid: u32) -> String {
    choose_guest_username(
        env::var("USER").ok(),
        env::var("LOGNAME").ok(),
        passwd_name_for_uid(uid),
        uid,
    )
}

/// Host `$HOME`, validated non-empty. Pure core of [`resolve_host_home`]
/// — takes the already-read env value as a parameter so the empty/unset
/// guard is unit-testable without mutating process env.
///
/// Deliberately **not** a reuse of `session::state_root`'s own `$HOME`
/// read (`session.rs:225`): that one is a fallback for the *session
/// state root* (`~/.local/state/agent-vm`) and has nothing to do with
/// guest identity mirroring.
fn host_home_from_env(env_val: Option<String>) -> Result<String> {
    env_val.filter(|h| !h.is_empty()).context(
        "$HOME is not set — required in non-root mode to mirror the guest's \
         HOME (pass --root to run as root instead, which doesn't need it)",
    )
}

/// Resolve the host's `$HOME`, mirrored verbatim as the non-root guest's
/// own `$HOME`. Thin wrapper around [`host_home_from_env`].
fn resolve_host_home() -> Result<String> {
    host_home_from_env(env::var("HOME").ok())
}

/// Whether the guest runs as root (uid 0) instead of the default non-root
/// (host-uid) mode. Enabled by the `--root` flag OR a truthy `AGENT_VM_ROOT`
/// env var. `env_val` is the raw value of that variable (`None` when
/// unset), so this stays pure and unit-testable — mirrors `run.rs`'s
/// `should_check_update` flag-or-truthy-env shape and the same shared
/// `env_flag` truthiness convention (`1|true|yes|on`).
pub fn should_run_root(flag: bool, env_val: Option<&str>) -> bool {
    flag || env_val.is_some_and(crate::env_flag::is_truthy)
}

/// The non-root guest's full identity: the numeric access-control uid/gid
/// (see ADR-0001) plus the cosmetic host-mirrored username/`$HOME` (see
/// ADR-0002). `None` in root mode. A single flat struct — not the
/// previous three parallel `Option`s (`guest_identity`/`guest_user`/
/// `guest_host_identity`) that were always Some/None together — so
/// there's one `Option`, not three that can (in principle) drift out of
/// sync, and one `.expect()` at the non-root call sites instead of two.
pub struct GuestIdentity {
    pub uid: u32,
    pub gid: u32,
    /// "uid:gid", formatted once for microsandbox's `.user()` builder calls.
    pub user_spec: String,
    /// Cosmetic — NOT the access-control identity (that's `uid`/`gid`
    /// above). `whoami`/`$USER`/the shell prompt only.
    pub username: String,
    /// The literal host `$HOME` string, mirrored verbatim as the guest's
    /// `$HOME`.
    pub host_home: String,
}

/// Resolve the guest's full identity for the given root-mode gate —
/// `None` in root mode, `Some` in non-root mode. The single entry point
/// `launch()` calls; wraps [`resolve_guest_username`] and
/// [`resolve_host_home`].
pub fn resolve_guest_identity(root_mode: bool) -> Result<Option<GuestIdentity>> {
    if root_mode {
        return Ok(None);
    }
    // SAFETY: getuid()/getgid() are argument-free libc calls with no
    // preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    Ok(Some(GuestIdentity {
        uid,
        gid,
        user_spec: format!("{uid}:{gid}"),
        username: resolve_guest_username(uid),
        host_home: resolve_host_home()?,
    }))
}

/// Format the non-root guest's `/etc/passwd` append line. `username` is
/// assumed already sanitized — this function does not re-validate it.
pub fn passwd_append_line(username: &str, uid: u32, gid: u32, host_home: &str) -> String {
    format!("{username}:x:{uid}:{gid}::{host_home}:/bin/bash\n")
}

/// `/etc/group` append line for the guest's gid, or `None` when the gid
/// falls in the system-reserved range (Debian/most distros: 0-999) —
/// where a base image's own groups already live (e.g. Debian's
/// dialout=20, also macOS's default primary group staff=20, a real
/// collision risk since this repo is developed on macOS). A duplicate
/// line there would only be cosmetic (agentd resolves the numeric gid
/// directly regardless of whether a name is attached to it), but
/// skipping keeps `/etc/group` sane.
///
/// This is a heuristic, not a literal "does this gid already exist"
/// check: `PatchBuilder` (`vendor/microsandbox/sdk/rust/lib/sandbox/types.rs:495`)
/// only exposes write operations — there's no read API to inspect the
/// base image's `/etc/group` from here. The system-reserved-range
/// convention is stable across Debian/Ubuntu/most distros and covers
/// every group the current base image defines; a future base image
/// adding a >= 1000 group would at worst produce a cosmetic duplicate.
pub fn group_append_line(gid: u32) -> Option<String> {
    (gid >= 1000).then(|| format!("agent:x:{gid}:\n"))
}

/// One virtiofs dir-bind volume, in the exact order it must reach
/// `SandboxBuilder::volume()`.
pub struct DirVolume {
    pub guest_path: String,
    pub host_path: PathBuf,
}

/// Ordered list of the sandbox's core dir-bind volumes: HOME (non-root
/// mode only) **first**, then the project, then `/agent-vm-state`. HOME
/// must precede the project (see "The load-bearing mechanic" in
/// `docs/adr/0002-mirror-host-home-and-username.md`) — mounting HOME
/// first is unconditionally safe whether or not the project actually
/// nests under it.
pub fn core_dir_volumes(
    guest_home: Option<(&str, PathBuf)>,
    project_guest_path: &str,
    project_dir: &Path,
    state_dir: &Path,
) -> Vec<DirVolume> {
    let mut volumes = Vec::new();
    if let Some((host_home, guest_home_source)) = guest_home {
        volumes.push(DirVolume {
            guest_path: host_home.to_string(),
            host_path: guest_home_source,
        });
    }
    volumes.push(DirVolume {
        guest_path: project_guest_path.to_string(),
        host_path: project_dir.to_path_buf(),
    });
    volumes.push(DirVolume {
        guest_path: "/agent-vm-state".to_string(),
        host_path: state_dir.to_path_buf(),
    });
    volumes
}

/// The non-root guest's identity-mirroring exec-env pairs: `HOME` (the
/// mirrored host `$HOME`), `USER`/`LOGNAME` (the resolved username).
pub fn guest_identity_env(identity: &GuestIdentity) -> [(&'static str, String); 3] {
    [
        ("HOME", identity.host_home.clone()),
        ("USER", identity.username.clone()),
        ("LOGNAME", identity.username.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_mode_is_off_by_default_and_opt_in() {
        // Default: non-root guest.
        assert!(!should_run_root(false, None));
        assert!(!should_run_root(false, Some("")));
        assert!(!should_run_root(false, Some("0")));
        assert!(!should_run_root(false, Some("false")));
        assert!(!should_run_root(false, Some("garbage")));
        // Flag opt-in.
        assert!(should_run_root(true, None));
        // Env opt-in (repo truthy set).
        assert!(should_run_root(false, Some("1")));
        assert!(should_run_root(false, Some("true")));
        assert!(should_run_root(false, Some("yes")));
        assert!(should_run_root(false, Some("on")));
        // Either input enables (flag OR env).
        assert!(should_run_root(true, Some("0")));
    }

    #[test]
    fn is_safe_passwd_username_accepts_typical_names_rejects_unsafe_chars() {
        assert!(is_safe_passwd_username("claude"));
        assert!(is_safe_passwd_username("_claude"));
        assert!(is_safe_passwd_username("claude-2"));
        assert!(is_safe_passwd_username("claude_2"));
        assert!(is_safe_passwd_username("C"));

        assert!(!is_safe_passwd_username(""));
        assert!(!is_safe_passwd_username("2claude")); // leading digit
        assert!(!is_safe_passwd_username("claude:x")); // would corrupt /etc/passwd
        assert!(!is_safe_passwd_username("claude user")); // space
        assert!(!is_safe_passwd_username("claude\n")); // newline
        assert!(!is_safe_passwd_username("cläude")); // non-ASCII
    }

    #[test]
    fn choose_guest_username_prefers_user_env_over_logname_and_passwd() {
        let chosen = choose_guest_username(
            Some("claude".to_string()),
            Some("logname_user".to_string()),
            Some("passwd_user".to_string()),
            502,
        );
        assert_eq!(chosen, "claude");
    }

    #[test]
    fn choose_guest_username_falls_through_precedence_on_unsafe_candidates() {
        // $USER is unsafe -> falls through to $LOGNAME.
        let chosen = choose_guest_username(
            Some("bad:user".to_string()),
            Some("logname_user".to_string()),
            Some("passwd_user".to_string()),
            502,
        );
        assert_eq!(chosen, "logname_user");

        // $USER and $LOGNAME both unsafe -> falls through to the passwd name.
        let chosen = choose_guest_username(
            Some("bad user".to_string()),
            Some("also bad".to_string()),
            Some("passwd_user".to_string()),
            502,
        );
        assert_eq!(chosen, "passwd_user");

        // All three absent/unsafe -> falls all the way to the numeric uid.
        let chosen = choose_guest_username(None, None, None, 502);
        assert_eq!(chosen, "502");
    }

    #[test]
    fn choose_guest_username_rejects_empty_string_candidates() {
        let chosen = choose_guest_username(
            Some(String::new()),
            Some(String::new()),
            Some(String::new()),
            502,
        );
        assert_eq!(chosen, "502");
    }

    #[test]
    fn host_home_from_env_rejects_unset_or_empty() {
        assert!(host_home_from_env(None).is_err());
        assert!(host_home_from_env(Some(String::new())).is_err());
        assert_eq!(
            host_home_from_env(Some("/Users/claude".to_string())).unwrap(),
            "/Users/claude"
        );
    }

    #[test]
    fn passwd_append_line_formats_mirrored_identity() {
        assert_eq!(
            passwd_append_line("claude", 502, 20, "/Users/claude"),
            "claude:x:502:20::/Users/claude:/bin/bash\n"
        );
    }

    #[test]
    fn group_append_line_skips_system_reserved_range() {
        assert_eq!(group_append_line(20), None); // macOS staff / Debian dialout
        assert_eq!(group_append_line(999), None);
        assert_eq!(group_append_line(1000), Some("agent:x:1000:\n".to_string()));
    }

    #[test]
    fn guest_identity_env_mirrors_host_home_and_username() {
        let identity = GuestIdentity {
            uid: 502,
            gid: 20,
            user_spec: "502:20".to_string(),
            username: "claude".to_string(),
            host_home: "/Users/claude".to_string(),
        };
        let env = guest_identity_env(&identity);
        assert_eq!(
            env,
            [
                ("HOME", "/Users/claude".to_string()),
                ("USER", "claude".to_string()),
                ("LOGNAME", "claude".to_string()),
            ]
        );
    }

    #[test]
    fn core_dir_volumes_orders_home_before_project_when_project_nests_under_home() {
        let volumes = core_dir_volumes(
            Some(("/Users/claude", PathBuf::from("/state/home"))),
            "/Users/claude/code/agent-vm",
            Path::new("/Users/claude/code/agent-vm"),
            Path::new("/state"),
        );
        assert_eq!(volumes.len(), 3);
        assert_eq!(volumes[0].guest_path, "/Users/claude");
        assert_eq!(volumes[0].host_path, PathBuf::from("/state/home"));
        assert_eq!(volumes[1].guest_path, "/Users/claude/code/agent-vm");
        assert_eq!(
            volumes[1].host_path,
            PathBuf::from("/Users/claude/code/agent-vm")
        );
        assert_eq!(volumes[2].guest_path, "/agent-vm-state");
        assert_eq!(volumes[2].host_path, PathBuf::from("/state"));
    }

    #[test]
    fn core_dir_volumes_home_still_first_when_project_is_not_nested_under_home() {
        let volumes = core_dir_volumes(
            Some(("/Users/claude", PathBuf::from("/state/home"))),
            "/srv/project",
            Path::new("/srv/project"),
            Path::new("/state"),
        );
        assert_eq!(volumes.len(), 3);
        assert_eq!(volumes[0].guest_path, "/Users/claude");
        assert_eq!(volumes[1].guest_path, "/srv/project");
        assert_eq!(volumes[2].guest_path, "/agent-vm-state");
    }

    #[test]
    fn core_dir_volumes_root_mode_has_no_home_entry() {
        let volumes = core_dir_volumes(
            None,
            "/srv/project",
            Path::new("/srv/project"),
            Path::new("/state"),
        );
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0].guest_path, "/srv/project");
        assert_eq!(volumes[1].guest_path, "/agent-vm-state");
    }
}
