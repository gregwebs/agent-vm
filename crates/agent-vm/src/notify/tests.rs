//! The facade's four decisions: settings, eligibility, discovery and the line.
//!
//! Nothing here runs the driver (that is `helper::tests`): every rule below is a
//! pure function of measured facts or of a real directory tree, so Linux CI can
//! pin the macOS gate, the root/SSH refusals and the sibling-only discovery.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use super::*;
use crate::env_flag::FlagValue;

fn facts(disabled: FlagValue, is_macos: bool, euid: u32, ssh: bool) -> Facts {
    Facts {
        disabled,
        is_macos,
        euid,
        ssh_session: ssh,
    }
}

#[test]
fn eligibility_refuses_the_flag_a_non_macos_host_root_and_ssh() {
    let allowed = facts(FlagValue::Unset, true, 501, false);
    assert!(should_notify(&allowed));
    // `0`/`false`/`no`/`off` leave the documented default (on) alone, and an
    // unrecognised value is treated the same way: this knob's default is on.
    assert!(should_notify(&facts(FlagValue::Off, true, 501, false)));

    // Every clause refuses on its own, with the others satisfied.
    for (refused, why) in [
        (facts(FlagValue::On, true, 501, false), "the opt-out"),
        (facts(FlagValue::Unset, false, 501, false), "non-macOS"),
        (facts(FlagValue::Unset, true, 0, false), "root"),
        (facts(FlagValue::Unset, true, 501, true), "an SSH session"),
    ] {
        assert!(!should_notify(&refused), "{why} must refuse");
    }
}

#[test]
fn no_ambient_variable_bypasses_the_eligibility_checks() {
    // R7: the *only* environment value eligibility reads is the documented
    // opt-out, and it can only turn notifications off. A plausible "force" or
    // "dev" switch must not change what is measured — in any build, so there is
    // no `#[cfg(debug_assertions)]` hatch anywhere in this path.
    let mut env = crate::test_env::guard();
    for name in ["SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"] {
        env.remove_var(name);
    }
    let before = Facts::measure(FlagValue::Unset);
    assert!(!before.ssh_session, "no SSH variables are set");
    for name in [
        "AGENT_VM_NOTIFY_FORCE",
        "AGENT_VM_TEST_NOTIFY",
        "AGENT_VM_FORCE_NOTIFICATIONS",
        "AGENT_VM_DEV",
    ] {
        env.set_var(name, "1");
    }
    assert_eq!(
        Facts::measure(FlagValue::Unset),
        before,
        "no ambient variable may change the measured facts"
    );
    for name in [
        "AGENT_VM_NOTIFY_FORCE",
        "AGENT_VM_TEST_NOTIFY",
        "AGENT_VM_FORCE_NOTIFICATIONS",
        "AGENT_VM_DEV",
    ] {
        env.remove_var(name);
    }

    // And a host that fails one of the four clauses stays refused whatever the
    // environment says.
    assert!(!should_notify(&Facts {
        euid: 0,
        ..before.clone()
    }));
    assert!(!should_notify(&Facts {
        is_macos: false,
        ..before.clone()
    }));
    assert!(!should_notify(&Facts {
        ssh_session: true,
        ..before
    }));
}

#[test]
fn read_settings_reads_both_variables_with_the_warnings_a_typo_deserves() {
    let mut env = crate::test_env::guard();
    env.remove_var(NO_NOTIFICATIONS_SETTING);
    env.remove_var(terminal::TERMINAL_SETTING);
    let settings = read_settings();
    assert_eq!(settings.notifications, FlagValue::Unset);
    assert_eq!(settings.terminal, TerminalChoice::Terminal);
    assert!(settings.warnings.is_empty(), "{:?}", settings.warnings);

    env.set_var(NO_NOTIFICATIONS_SETTING, "maybe");
    env.set_var(terminal::TERMINAL_SETTING, "kitty");
    let settings = read_settings();
    assert_eq!(
        settings.notifications,
        FlagValue::Unrecognized("maybe".to_owned())
    );
    // The default survives a typo: guessing a terminal would open one the
    // operator did not ask for.
    assert_eq!(settings.terminal, TerminalChoice::Terminal);
    assert_eq!(settings.warnings.len(), 2, "{:?}", settings.warnings);
    assert!(
        settings.warnings[0].contains(NO_NOTIFICATIONS_SETTING),
        "{:?}",
        settings.warnings
    );
    assert!(
        settings.warnings[1].contains(terminal::TERMINAL_SETTING),
        "{:?}",
        settings.warnings
    );

    env.set_var(NO_NOTIFICATIONS_SETTING, "1");
    env.set_var(terminal::TERMINAL_SETTING, " GhostTy ");
    let settings = read_settings();
    assert_eq!(settings.notifications, FlagValue::On);
    assert_eq!(settings.terminal, TerminalChoice::Ghostty);
    assert!(settings.warnings.is_empty(), "{:?}", settings.warnings);
}

#[test]
fn discovery_accepts_only_a_sibling_bin_layout() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join("bundle");
    let bin = bundle.join("bin");
    let helper = bundle.join(NOTIFIER_RELATIVE);
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(helper.parent().unwrap()).unwrap();
    std::fs::write(&helper, b"not a real helper").unwrap();
    let exe = bin.join("agent-vm");
    std::fs::write(&exe, b"").unwrap();

    // `<bundle>/bin/agent-vm` → `<bundle>/lib/AgentVMNotifier.app/...`.
    assert_eq!(
        resolve_notifier(&ExeLocation::resolve(exe)),
        Some(helper.canonicalize().unwrap())
    );

    // A parent that is not `bin` names no layout at all: there is deliberately no
    // second candidate to fall back to.
    let sbin = bundle.join("sbin");
    std::fs::create_dir_all(&sbin).unwrap();
    let elsewhere = sbin.join("agent-vm");
    std::fs::write(&elsewhere, b"").unwrap();
    assert_eq!(resolve_notifier(&ExeLocation::resolve(elsewhere)), None);

    // `bin/` without the bundle beside it: silent fallback, no scan for another
    // build's copy.
    let bare = root.path().join("bare/bin");
    std::fs::create_dir_all(&bare).unwrap();
    let bare_exe = bare.join("agent-vm");
    std::fs::write(&bare_exe, b"").unwrap();
    assert_eq!(resolve_notifier(&ExeLocation::resolve(bare_exe)), None);

    // A path that cannot be canonicalized still uses the reported layout.
    assert_eq!(
        resolve_notifier(&ExeLocation::resolve(PathBuf::from(
            "/nonexistent/bin/agent-vm"
        ))),
        None
    );
}

#[test]
fn click_user_info_refuses_non_utf8_and_relative_paths() {
    let session = SessionId::parse("3f9a12c4").unwrap();
    let project = PathBuf::from("/Users/me/proj");
    let state = PathBuf::from("/Users/me/.local/state/agent-vm");
    assert_eq!(
        helper::ClickUserInfo::try_from_paths(&session, &project, &state, "ghostty"),
        Some(helper::ClickUserInfo {
            session: "3f9a12c4".to_owned(),
            project: "/Users/me/proj".to_owned(),
            state_dir: "/Users/me/.local/state/agent-vm".to_owned(),
            terminal: "ghostty".to_owned(),
        })
    );

    // Relative paths are resolved against whatever directory the helper happens
    // to run in, so they are never sent.
    assert_eq!(
        helper::ClickUserInfo::try_from_paths(&session, Path::new("proj"), &state, "terminal"),
        None
    );
    assert_eq!(
        helper::ClickUserInfo::try_from_paths(&session, &project, Path::new("state"), "terminal"),
        None
    );

    // A non-UTF-8 path cannot survive JSON, and a lossy conversion would name a
    // directory that does not exist.
    let raw = OsStr::from_bytes(b"/Users/me/pr\xffoj");
    assert_eq!(
        helper::ClickUserInfo::try_from_paths(&session, Path::new(raw), &state, "terminal"),
        None
    );
    let raw_state = OsStr::from_bytes(b"/state/\xfe");
    assert_eq!(
        helper::ClickUserInfo::try_from_paths(&session, &project, Path::new(raw_state), "terminal"),
        None
    );
}

#[test]
fn wire_terminal_round_trips_through_the_click_parser() {
    // The helper hands this spelling back to `_notify-click --terminal`, so the
    // two tables cannot drift.
    for choice in [
        TerminalChoice::Terminal,
        TerminalChoice::Ghostty,
        TerminalChoice::WezTerm,
        TerminalChoice::Alacritty,
    ] {
        assert_eq!(
            TerminalChoice::parse(wire_terminal(choice)),
            Some(choice),
            "{choice:?}"
        );
    }
}

#[test]
fn the_notifications_off_line_is_terminal_safe() {
    // It is printed between two carriage returns on a terminal, so it must contain
    // no framing byte of its own, and it names no guest text.
    assert!(NOTIFICATIONS_OFF.is_ascii());
    for banned in ['\r', '\n', '\u{1b}', '\u{7}'] {
        assert!(
            !NOTIFICATIONS_OFF.contains(banned),
            "{NOTIFICATIONS_OFF:?} contains {banned:?}"
        );
    }
    assert!(NOTIFICATIONS_OFF.starts_with("==> "));
    assert!(NOTIFICATIONS_OFF.contains("agent-vm access"));
    // The same property the refusal hint's byte constant asserts.
    assert!(crate::refusal::feed::HINT.is_ascii());
}
