//! Terminal policy for a direct command launch (issue #400).
//!
//! It is a **pure mapping** from a typed preference and the host's terminal
//! facts to the resolved [`DirectIo`] the launch will use. It is decided once, in
//! CLI dispatch, before any runtime setup, and travels with the launch target so
//! the guest bootstrap and the exec request cannot disagree.
//!
//! Nothing here measures a host descriptor except [`HostTerminals::detect`], and
//! nothing here starts a session: the PTY session a `Pty` selection ends in lives
//! in [`crate::direct_pty`], and the streaming one in `run`'s exec lifecycle.
//! Keeping the mapping separate is what makes every combination testable without
//! a launch.

/// What the user asked for on the command line.
///
/// `Auto` is the default, so an existing invocation keeps working without the
/// new options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TerminalPolicy {
    #[default]
    Auto,
    ForcePty,
    ForceStream,
}

/// The resolved I/O mode of one direct launch.
///
/// Resolved in dispatch and frozen: nothing re-measures the host's descriptors
/// later, so a bootstrap cannot be rendered for one mode while the exec request
/// uses another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectIo {
    /// A guest PTY: merged output, resize forwarding, guest-owned lifetime.
    Pty,
    /// Separate guest channels with streamed input (#399).
    Stream,
}

/// The host facts selection depends on.
///
/// Deliberately no stderr field: a redirected or piped stderr changes nothing
/// about which mode a direct command needs, and a field no rule reads would only
/// invite one to be invented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostTerminals {
    pub(crate) stdin: bool,
    pub(crate) stdout: bool,
}

impl HostTerminals {
    /// Measure this process's real descriptors — not `$TERM`, not `/dev/tty`,
    /// not the command's name and not the parent shell's interactivity.
    pub(crate) fn detect() -> Self {
        use std::io::IsTerminal;
        Self {
            stdin: std::io::stdin().is_terminal(),
            stdout: std::io::stdout().is_terminal(),
        }
    }
}

/// `--tty` (-t) with input that is not a terminal: refused before boot, because
/// a PTY cannot give the guest input the user never had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForcedPtyNeedsTerminal;

impl std::fmt::Display for ForcedPtyNeedsTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "--tty (-t) requires terminal stdin; omit --tty or use --no-tty (-T) for piped or \
             file input",
        )
    }
}
impl std::error::Error for ForcedPtyNeedsTerminal {}

/// Both force options were supplied.
///
/// clap rejects that spelling, but a manually constructed [`crate::run::Args`]
/// must not silently pick a winner either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalFlagConflict;

impl std::fmt::Display for TerminalFlagConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("--tty and --no-tty cannot be used together")
    }
}
impl std::error::Error for TerminalFlagConflict {}

impl TerminalPolicy {
    /// The whole selection contract, in one place.
    ///
    /// Auto uses a PTY only when **both** descriptors are terminals, so a
    /// redirected stdout keeps stdout and stderr separate instead of merging
    /// them into a file. Forcing a PTY additionally requires terminal stdin,
    /// because a guest terminal session with no host input would be a session the
    /// user cannot drive.
    pub(crate) fn select(self, host: HostTerminals) -> Result<DirectIo, ForcedPtyNeedsTerminal> {
        match self {
            Self::ForcePty if !host.stdin => Err(ForcedPtyNeedsTerminal),
            Self::ForcePty => Ok(DirectIo::Pty),
            Self::ForceStream => Ok(DirectIo::Stream),
            Self::Auto if host.stdin && host.stdout => Ok(DirectIo::Pty),
            Self::Auto => Ok(DirectIo::Stream),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::FromRawFd as _;

    use super::*;

    /// An independently written copy of the truth table, so a change in the
    /// implementation has to disagree with a second statement of the contract.
    ///
    /// (policy, stdin, stdout) → expected result, or `None` for the forced-PTY
    /// refusal. stderr has no column because it has no effect.
    const TABLE: &[(TerminalPolicy, bool, bool, Option<DirectIo>)] = &[
        (TerminalPolicy::Auto, false, false, Some(DirectIo::Stream)),
        (TerminalPolicy::Auto, false, true, Some(DirectIo::Stream)),
        (TerminalPolicy::Auto, true, false, Some(DirectIo::Stream)),
        (TerminalPolicy::Auto, true, true, Some(DirectIo::Pty)),
        (TerminalPolicy::ForcePty, false, false, None),
        (TerminalPolicy::ForcePty, false, true, None),
        (TerminalPolicy::ForcePty, true, false, Some(DirectIo::Pty)),
        (TerminalPolicy::ForcePty, true, true, Some(DirectIo::Pty)),
        (
            TerminalPolicy::ForceStream,
            false,
            false,
            Some(DirectIo::Stream),
        ),
        (
            TerminalPolicy::ForceStream,
            false,
            true,
            Some(DirectIo::Stream),
        ),
        (
            TerminalPolicy::ForceStream,
            true,
            false,
            Some(DirectIo::Stream),
        ),
        (
            TerminalPolicy::ForceStream,
            true,
            true,
            Some(DirectIo::Stream),
        ),
    ];

    #[test]
    fn every_policy_and_descriptor_combination_matches_the_table() {
        for (policy, stdin, stdout, expected) in TABLE {
            let host = HostTerminals {
                stdin: *stdin,
                stdout: *stdout,
            };
            match (policy.select(host), expected) {
                (Ok(io), Some(expected)) => assert_eq!(
                    io, *expected,
                    "{policy:?} with stdin={stdin} stdout={stdout}"
                ),
                (Err(error), None) => assert_eq!(error, ForcedPtyNeedsTerminal),
                (actual, expected) => {
                    panic!("{policy:?} stdin={stdin} stdout={stdout}: {actual:?} vs {expected:?}")
                }
            }
        }
        assert_eq!(TABLE.len(), 12, "12 combinations, stderr excluded");
    }

    #[test]
    fn the_default_policy_is_auto_and_needs_both_descriptors() {
        assert_eq!(TerminalPolicy::default(), TerminalPolicy::Auto);
        // Auto is not "stdin or stdout", and not "stdin only".
        let stdin_only = HostTerminals {
            stdin: true,
            stdout: false,
        };
        assert_eq!(
            TerminalPolicy::Auto.select(stdin_only),
            Ok(DirectIo::Stream)
        );
        let both = HostTerminals {
            stdin: true,
            stdout: true,
        };
        assert_eq!(TerminalPolicy::Auto.select(both), Ok(DirectIo::Pty));
    }

    /// Env token that turns this test binary into a one-shot measurement child.
    const DETECT_TOKEN: &str = "AGENT_VM_DIRECT_TERMINAL_DETECT_CASE";

    /// The production `detect()` and `select()`, measured in a child process.
    ///
    /// `HostTerminals::detect()` reads the *process's* descriptors, so it can only
    /// be exercised where those are the ones under test: changing fd 0 or 1 in
    /// the shared Cargo test process would corrupt every other test in the binary.
    /// Without the token this is an ordinary passing test.
    #[test]
    fn terminal_detection_child() {
        let Ok(case) = std::env::var(DETECT_TOKEN) else {
            return;
        };
        let host = HostTerminals::detect();
        let mode = TerminalPolicy::Auto
            .select(host)
            .map(|io| format!("{io:?}"))
            .unwrap_or_else(|error| error.to_string());
        // The receipt goes to stderr: stdout is one of the descriptors under
        // test, so a case where it is a terminal must still be observable. The
        // measurement itself never reads stderr.
        eprintln!(
            "{case}: stdin={} stdout={} mode={mode}",
            host.stdin, host.stdout
        );
    }

    /// Every combination of host stdin/stdout kinds resolves through the
    /// production adapter, not just through the pure mapping.
    ///
    /// A pure test cannot catch a wrongly wired `detect()` (say, measuring stdout
    /// twice); this one assigns the child's descriptors itself and reads what the
    /// production code measured.
    #[test]
    fn terminal_detection_reads_the_assigned_descriptors() {
        use std::process::Stdio;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Kind {
            Tty,
            Pipe,
            File,
            Null,
        }

        fn wired(kind: Kind, dir: &std::path::Path) -> (Stdio, Option<std::os::fd::OwnedFd>) {
            match kind {
                Kind::Tty => {
                    let pty = open_pty().expect("allocate a test PTY");
                    // The master is kept by the caller for the duration.
                    (Stdio::from(pty.slave), Some(pty.master))
                }
                Kind::Pipe => (Stdio::piped(), None),
                Kind::File => {
                    let path = dir.join("descriptor.txt");
                    let file = std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .read(true)
                        .write(true)
                        .open(path)
                        .unwrap();
                    (Stdio::from(file), None)
                }
                Kind::Null => (Stdio::null(), None),
            }
        }

        let dir = tempfile::tempdir().expect("a scratch case directory");
        let mut checked = 0usize;
        for stdin_kind in [Kind::Tty, Kind::Pipe, Kind::File, Kind::Null] {
            for stdout_kind in [Kind::Tty, Kind::Pipe] {
                let (stdin, keep_in) = wired(stdin_kind, dir.path());
                let (stdout, keep_out) = wired(stdout_kind, dir.path());
                let output =
                    std::process::Command::new(std::env::current_exe().expect("this binary"))
                        .args([
                            "--exact",
                            "direct_terminal::tests::terminal_detection_child",
                            "--test-threads=1",
                            "--nocapture",
                        ])
                        .env(DETECT_TOKEN, format!("{stdin_kind:?}/{stdout_kind:?}"))
                        .stdin(stdin)
                        .stdout(stdout)
                        .stderr(Stdio::piped())
                        .output()
                        .expect("run the measurement child");
                drop(keep_in);
                drop(keep_out);
                let text = String::from_utf8_lossy(&output.stderr);
                let expected_stdin = stdin_kind == Kind::Tty;
                let expected_stdout = stdout_kind == Kind::Tty;
                let expected_mode = if expected_stdin && expected_stdout {
                    "Pty"
                } else {
                    "Stream"
                };
                let line = text
                    .lines()
                    .find(|line| line.contains("stdin="))
                    .unwrap_or_else(|| {
                        panic!("{stdin_kind:?}/{stdout_kind:?}: no measurement in {text:?}")
                    });
                assert!(
                    line.contains(&format!("stdin={expected_stdin}")),
                    "{stdin_kind:?}/{stdout_kind:?}: {line}"
                );
                assert!(
                    line.contains(&format!("stdout={expected_stdout}")),
                    "{stdin_kind:?}/{stdout_kind:?}: {line}"
                );
                assert!(
                    line.contains(&format!("mode={expected_mode}")),
                    "{stdin_kind:?}/{stdout_kind:?}: {line}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 8, "every stdin/stdout kind combination");
    }

    /// A fresh PTY pair through libc: the crate has no other PTY dependency, and
    /// a test terminal is the one thing `openpty` cannot be replaced with.
    fn open_pty() -> std::io::Result<PtyPair> {
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if master == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(master) };
            return Err(error);
        }
        let name = unsafe { libc::ptsname(master) };
        if name.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(master) };
            return Err(error);
        }
        let path = unsafe { std::ffi::CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        Ok(PtyPair {
            master: unsafe { std::os::fd::OwnedFd::from_raw_fd(master) },
            slave,
        })
    }

    struct PtyPair {
        master: std::os::fd::OwnedFd,
        slave: std::fs::File,
    }

    #[test]
    fn the_refusal_text_names_the_remedy_and_carries_no_host_value() {
        let text = ForcedPtyNeedsTerminal.to_string();
        assert!(text.contains("--tty"));
        assert!(text.contains("--no-tty"));
        assert!(text.contains("piped"));
        // Fixed text: nothing measured, no path, no descriptor number.
        assert_eq!(
            text,
            "--tty (-t) requires terminal stdin; omit --tty or use --no-tty (-T) for piped or \
             file input"
        );
        assert_eq!(
            TerminalFlagConflict.to_string(),
            "--tty and --no-tty cannot be used together"
        );
    }
}
