//! Bounded host CLI children: one environment allow-list, one process-group
//! kill and one reap ceiling, shared by OAuth rotation
//! ([`crate::intercept_hook::oauth_refresh`]) and the macOS keychain reader
//! ([`crate::host_credential`], #492).
//!
//! The program is resolved on `PATH` rather than as an absolute path because
//! that is also the tests' seam — a fake binary earlier on `PATH` stands in for
//! `claude`, `codex` and `security`. It adds no authority: whoever can shadow
//! `PATH` can already edit the host credential file directly.
//!
//! **Every** return after a successful spawn goes through [`finalize`]: the
//! child's process group is killed, the child is reaped, and both collectors get
//! a bounded chance to finish. That is not only about the timeout path — a
//! non-zero exit, a wait error and a *successful* exit whose descendants still
//! hold a pipe all used to return without it, leaking one process group (and a
//! blocked collector thread) per lookup, and the OAuth hook retries lookups.
//!
//! The `timeout` these functions take is a **polling budget**: it is checked only
//! while the child has not exited, so a child that answers late but answers is
//! still a success, and the cleanup after it is bounded by [`REAP_CEILING`] plus
//! [`STDERR_GRACE`] rather than by the budget.

use std::{
    io::Read,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

pub(crate) const POLL_OVERSHOOT: Duration = Duration::from_millis(50);
/// How long a killed child gets to be reaped before the deadline is declared
/// spent anyway.
pub(crate) const REAP_CEILING: Duration = Duration::from_secs(2);
/// How long to wait for a collector thread to finish once the child has exited.
pub(crate) const STDERR_GRACE: Duration = Duration::from_millis(100);

/// Everything a host CLI child may inherit. Cleared first: a vendor CLI does
/// not need agent-vm's own environment, and a credential must never reach it
/// by accident.
const ENV_ALLOW_LIST: [&str; 17] = [
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

/// Why a bounded child produced nothing usable. Never carries child output:
/// stderr is drained unread and stdout is returned only on success.
#[derive(Debug)]
pub(crate) enum Failure {
    Spawn(std::io::ErrorKind),
    /// A non-zero exit, or a signal death (`None`) — including the child we can
    /// no longer wait on, which nothing distinguishes from one killed by a
    /// signal.
    ///
    /// Only the macOS keychain reader classifies the status (its 44 means "no
    /// such item", which is not a failure). The field stays a field rather than
    /// being dropped so that the `Some(44)`/`None` distinction remains visible
    /// in a `Debug` line on every target, so it is expected to be unread on a
    /// build with no reader — the Linux CI leg, where a plain `dead_code` would
    /// fail `-D warnings`.
    Exit(
        #[cfg_attr(
            not(any(target_os = "macos", test)),
            expect(
                dead_code,
                reason = "the exit status is classified only by the macOS keychain reader"
            )
        )]
        Option<i32>,
    ),
    TimedOut,
    Oversized,
    /// The direct child exited but a descendant still holds the pipe.
    StdoutUnavailable,
}

pub(crate) fn run_discarding_stdout(
    program: &str,
    args: &[&str],
    cwd: &Path,
    timeout: Duration,
) -> Result<(), Failure> {
    run_bounded(program, args, cwd, timeout, None).map(drop)
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn run_capturing_stdout(
    program: &str,
    args: &[&str],
    cwd: &Path,
    timeout: Duration,
    max_bytes: u64,
) -> Result<Vec<u8>, Failure> {
    run_bounded(program, args, cwd, timeout, Some(max_bytes))
}

fn run_bounded(
    program: &str,
    args: &[&str],
    cwd: &Path,
    timeout: Duration,
    stdout_cap: Option<u64>,
) -> Result<Vec<u8>, Failure> {
    run_bounded_with(program, args, cwd, timeout, stdout_cap, peek_exit)
}

/// Has the direct child exited, **without reaping it**?
///
/// [`Child::try_wait`] is the obvious primitive and it reaps. Reaping frees the
/// pid, and that pid is also the child's process-group id, so between that reap
/// and [`kill_group`]'s `kill(-pid)` the number could be recycled: the kill would
/// then either miss the descendants (`ESRCH`, which the old code read as "the
/// group is already gone") or, worse, signal an unrelated new group. `waitid`
/// with `WNOWAIT` peeks at the zombie instead — the pid stays allocated, and with
/// it the group id — so the kill happens while the number is still ours and the
/// reap comes after it. That ordering is the whole point of this function.
fn peek_exit(child: &mut Child) -> std::io::Result<Option<std::process::ExitStatus>> {
    use std::os::unix::process::ExitStatusExt as _;

    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let (pid, status, code) = unsafe { waitid_ended(&info) };
    if pid == 0 {
        return Ok(None);
    }
    // `waitid` reports how the child ended in two parts; `ExitStatus` takes the
    // `waitpid` status word, which packs them the POSIX way: the exit code in
    // the high byte, or the signal plus a core-dump flag in the low one.
    let raw = match code {
        libc::CLD_EXITED => status << 8,
        libc::CLD_DUMPED => status | 0x80,
        _ => status & 0x7f,
    };
    Ok(Some(std::process::ExitStatus::from_raw(raw)))
}

/// `siginfo_t`'s wait-related fields: the child, its status and how it ended.
/// Linux reaches them through accessors rather than fields because the kernel
/// struct is a union; the BSD-shaped targets name them directly.
///
/// # Safety
/// `info` must have been filled by a successful `waitid` call.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn waitid_ended(info: &libc::siginfo_t) -> (libc::pid_t, libc::c_int, libc::c_int) {
    unsafe { (info.si_pid(), info.si_status(), info.si_code) }
}

/// See the Linux variant of [`waitid_ended`].
///
/// # Safety
/// `info` must have been filled by a successful `waitid` call.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
unsafe fn waitid_ended(info: &libc::siginfo_t) -> (libc::pid_t, libc::c_int, libc::c_int) {
    (info.si_pid, info.si_status, info.si_code)
}

/// [`run_bounded`] with its wait primitive injectable, because an OS wait error
/// cannot be manufactured reliably from a test and that path still has to clean
/// up. Production always passes [`Child::try_wait`].
fn run_bounded_with<W>(
    program: &str,
    args: &[&str],
    cwd: &Path,
    timeout: Duration,
    stdout_cap: Option<u64>,
    mut wait: W,
) -> Result<Vec<u8>, Failure>
where
    W: FnMut(&mut Child) -> std::io::Result<Option<std::process::ExitStatus>>,
{
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    if stdout_cap.is_some() {
        command.stdout(Stdio::piped());
    } else {
        command.stdout(Stdio::null());
    }
    for name in ENV_ALLOW_LIST {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // Its own process group, so the kill below reaches grandchildren that
        // inherited the pipes; a plain `Child::kill` would orphan them.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|error| Failure::Spawn(error.kind()))?;
    let pid = child.id() as libc::pid_t;
    let stderr = child.stderr.take().expect("stderr is always piped");
    let (drained, drain) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::BufReader::new(stderr), &mut std::io::sink());
        let _ = drained.send(());
    });
    let stdout = match (child.stdout.take(), stdout_cap) {
        (Some(stdout), Some(cap)) => Some((collect_capped(stdout, cap), cap)),
        _ => None,
    };
    let start = Instant::now();
    let outcome = loop {
        match wait(&mut child) {
            Ok(Some(status)) if !status.success() => break Err(Failure::Exit(status.code())),
            Ok(Some(_)) => {
                // A successful exit says nothing about the collectors: a
                // descendant can still hold either pipe, and then the child's
                // own success must not be reported as a healthy run.
                break match stdout.as_ref() {
                    None => Ok(Vec::new()),
                    Some((received, cap)) => match received.recv_timeout(STDERR_GRACE) {
                        Ok(bytes) if bytes.len() as u64 > *cap => Err(Failure::Oversized),
                        Ok(bytes) => Ok(bytes),
                        Err(_) => Err(Failure::StdoutUnavailable),
                    },
                };
            }
            Ok(None) if start.elapsed() >= timeout => break Err(Failure::TimedOut),
            Ok(None) => std::thread::sleep(POLL_OVERSHOOT),
            Err(_) => break Err(Failure::Exit(None)),
        }
    };
    // Every post-spawn return goes through here. Before this was centralised, a
    // non-zero exit, a wait error and a success whose descendants still held a
    // pipe all returned without touching the group: one leaked process group
    // (and a blocked collector thread) per lookup, which the hook repeated for
    // every rotation attempt. `wait` never reaps, so nothing has released the pid
    // by the time the kill runs.
    finalize(
        pid,
        &mut child,
        stdout.as_ref().map(|(received, _)| received),
        &drain,
    );
    outcome
}

/// Kill anything left in the child's process group, *then* reap the direct child,
/// and give both collectors their bounded chance to finish.
///
/// The kill is unconditional, including after a clean exit: the direct child has
/// exited in every case this runs, so anything still in its group is a
/// descendant that inherited a pipe — the only reason to keep one alive would be
/// to read from it, and nothing here does. Both collectors then end at EOF
/// because the group is gone; the waits are still bounded so a pipe nobody owns
/// cannot hang the caller.
///
/// The kill must precede the reap (see [`peek_exit`]): up to this call the direct
/// child is an unreaped zombie, which is what keeps its pid — and the process
/// group id that is that pid — from being recycled under `kill(-pid)`.
fn finalize(
    pid: libc::pid_t,
    child: &mut Child,
    stdout: Option<&mpsc::Receiver<Vec<u8>>>,
    stderr_drained: &mpsc::Receiver<()>,
) {
    kill_group(pid, child);
    let _ = stderr_drained.recv_timeout(STDERR_GRACE);
    if let Some(received) = stdout {
        let _ = received.recv_timeout(STDERR_GRACE);
    }
}

/// Collect at most `cap` bytes plus one: the extra byte is what proves the cap
/// was exceeded, and draining the rest keeps a chatty child from blocking on a
/// full pipe until the deadline kills it.
fn collect_capped(mut stdout: std::process::ChildStdout, cap: u64) -> mpsc::Receiver<Vec<u8>> {
    let (sent, received) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = (&mut stdout).take(cap + 1).read_to_end(&mut bytes);
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        let _ = sent.send(bytes);
    });
    received
}

fn kill_group(pid: libc::pid_t, child: &mut Child) {
    unsafe {
        if libc::kill(-pid, libc::SIGKILL) == -1
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            let _ = child.kill();
        }
    }
    let reap_start = Instant::now();
    while matches!(child.try_wait(), Ok(None)) && reap_start.elapsed() < REAP_CEILING {
        std::thread::sleep(POLL_OVERSHOOT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_executable_script(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Sleep until a descendant that touches its marker one second after spawn
    /// would have done so, plus slack for the write itself. Marker-based death
    /// checks are only meaningful after the scheduled write time.
    fn wait_past_the_scheduled_marker(since: Instant) {
        std::thread::sleep(
            Duration::from_secs(2)
                .saturating_sub(since.elapsed())
                .saturating_add(Duration::from_millis(500)),
        );
    }

    #[test]
    fn capture_returns_stdout_and_never_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("chatty");
        write_executable_script(
            &script,
            "#!/bin/sh\nprintf 'STDOUT-PAYLOAD'\nprintf 'STDERR-CANARY' >&2\n",
        );
        let bytes = run_capturing_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            64,
        )
        .unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), "STDOUT-PAYLOAD");
    }

    #[test]
    fn capture_over_the_cap_is_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("flood");
        write_executable_script(
            &script,
            "#!/bin/sh\nprintf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n",
        );
        let failure = run_capturing_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            16,
        )
        .unwrap_err();
        assert!(matches!(failure, Failure::Oversized), "{failure:?}");
    }

    #[test]
    fn capture_kills_the_group_on_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let script = dir.path().join("slow");
        // The grandchild holds the stdout pipe, which is the case a
        // parent-only kill would leak.
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\n(sleep 1; touch '{}') &\nsleep 30\n",
                marker.display()
            ),
        );
        let start = Instant::now();
        let failure = run_capturing_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_millis(200),
            64,
        )
        .unwrap_err();
        let elapsed = start.elapsed();
        assert!(matches!(failure, Failure::TimedOut), "{failure:?}");
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        std::thread::sleep(
            Duration::from_secs(1).saturating_sub(elapsed) + Duration::from_millis(500),
        );
        assert!(
            !marker.exists(),
            "the whole process group must die with the deadline"
        );
    }

    /// A direct child that exits at once while a descendant keeps the pipe open
    /// never completes the collector. That is `StdoutUnavailable`, and the
    /// descendant must be dead afterwards — an elapsed-time assertion cannot
    /// prove it, so the descendant touches a marker instead.
    #[test]
    fn a_descendant_holding_stdout_after_exit_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let script = dir.path().join("forks");
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\n(sleep 1; touch '{}') &\nexit 0\n",
                marker.display()
            ),
        );
        let failure = run_capturing_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            64,
        )
        .unwrap_err();
        assert!(matches!(failure, Failure::StdoutUnavailable), "{failure:?}");
        std::thread::sleep(Duration::from_secs(2));
        assert!(
            !marker.exists(),
            "the descendant holding stdout must be killed"
        );
    }

    #[test]
    fn capture_failure_debug_never_contains_child_output() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("failing");
        write_executable_script(&script, "#!/bin/sh\necho 'SECRET-STDERR' >&2\nexit 1\n");
        let failure = run_capturing_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            64,
        )
        .unwrap_err();
        assert!(matches!(failure, Failure::Exit(Some(1))), "{failure:?}");
        assert!(!format!("{failure:?}").contains("SECRET-STDERR"));
    }

    /// A missing program is a spawn failure, before any group exists.
    #[test]
    fn a_missing_program_is_spawn_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let failure = run_capturing_stdout(
            dir.path().join("absent").to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            64,
        )
        .unwrap_err();
        assert!(
            matches!(failure, Failure::Spawn(std::io::ErrorKind::NotFound)),
            "{failure:?}"
        );
    }

    /// F01: a non-zero exit used to return before the group was touched, so the
    /// descendant outlived the lookup. The status is still reported, output-free.
    #[test]
    fn a_nonzero_exit_still_kills_the_descendants() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let script = dir.path().join("failing");
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\n(sleep 1; touch '{}') &\nexit 1\n",
                marker.display()
            ),
        );
        let start = Instant::now();
        let failure = run_capturing_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            64,
        )
        .unwrap_err();
        assert!(matches!(failure, Failure::Exit(Some(1))), "{failure:?}");
        wait_past_the_scheduled_marker(start);
        assert!(
            !marker.exists(),
            "a non-zero exit must still reap the group"
        );
    }

    /// F01: the exit-44 lookup is retried with a bare query, doubling the leak
    /// the non-zero exit used to cause. Both attempts must leave nothing behind.
    #[test]
    fn the_account_then_bare_retry_leaves_no_survivor_either_time() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("miss");
        // One script, two invocations with a marker name each: that is the
        // reader's account-qualified query followed by its bare retry.
        write_executable_script(
            &script,
            "#!/bin/sh\ntouch \"$1\"\n(sleep 1; touch \"$1.descendant\") &\nexit 44\n",
        );
        let first = dir.path().join("first-attempt");
        let second = dir.path().join("second-attempt");
        let start = Instant::now();
        for marker in [&first, &second] {
            let failure = run_capturing_stdout(
                script.to_str().unwrap(),
                &[marker.to_str().unwrap()],
                dir.path(),
                Duration::from_secs(5),
                64,
            )
            .unwrap_err();
            assert!(matches!(failure, Failure::Exit(Some(44))), "{failure:?}");
        }
        wait_past_the_scheduled_marker(start);
        assert!(first.exists() && second.exists(), "both attempts ran");
        assert!(
            !dir.path().join("first-attempt.descendant").exists()
                && !dir.path().join("second-attempt.descendant").exists(),
            "each attempt must reap its own group"
        );
    }

    /// F01, the case A's probe demonstrated: the descendant inherits only
    /// stderr, the parent exits 0, and the success was reported while the
    /// descendant survived. It must die; the result stays a success.
    #[test]
    fn a_descendant_holding_only_stderr_after_a_successful_exit_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let script = dir.path().join("stderr-only");
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\nprintf 'PAYLOAD'\n( exec 1>/dev/null; sleep 1; touch '{}' ) &\nexit 0\n",
                marker.display()
            ),
        );
        let start = Instant::now();
        let bytes = run_capturing_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            64,
        )
        .unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), "PAYLOAD");
        wait_past_the_scheduled_marker(start);
        assert!(
            !marker.exists(),
            "a stalled stderr drain must not be ignored just because stdout arrived"
        );
    }

    /// F01: a descendant that closes both collected pipes before lingering is
    /// invisible to both collectors, so only the group cleanup can kill it.
    #[test]
    fn a_descendant_that_closed_both_pipes_before_lingering_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let script = dir.path().join("closed-pipes");
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\nprintf 'PAYLOAD'\n( exec 1>/dev/null 2>/dev/null; sleep 1; touch '{}' ) &\nexit 0\n",
                marker.display()
            ),
        );
        let start = Instant::now();
        let bytes = run_capturing_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            64,
        )
        .unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), "PAYLOAD");
        wait_past_the_scheduled_marker(start);
        assert!(
            !marker.exists(),
            "a descendant the collectors cannot see must still be killed"
        );
    }

    /// F01: the discarding path is the one OAuth rotation uses, and it used to
    /// return on success without touching the group either.
    #[test]
    fn discard_mode_kills_a_descendant_holding_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let script = dir.path().join("discard");
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\n( exec 1>/dev/null; sleep 1; touch '{}' ) &\nexit 0\n",
                marker.display()
            ),
        );
        let start = Instant::now();
        run_discarding_stdout(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
        )
        .unwrap();
        wait_past_the_scheduled_marker(start);
        assert!(!marker.exists(), "discard mode must reap its group too");
    }

    /// F01: a wait error is the one path no test can reach through the OS, so it
    /// is driven through the private seam. It must still kill the group.
    #[test]
    fn a_wait_error_still_finalizes_the_group() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let script = dir.path().join("unwaitable");
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\n(sleep 1; touch '{}') &\nsleep 30\n",
                marker.display()
            ),
        );
        let start = Instant::now();
        let failure = run_bounded_with(
            script.to_str().unwrap(),
            &[],
            dir.path(),
            Duration::from_secs(5),
            Some(64),
            |_child: &mut Child| Err(std::io::Error::other("injected wait error")),
        )
        .unwrap_err();
        assert!(matches!(failure, Failure::Exit(None)), "{failure:?}");
        wait_past_the_scheduled_marker(start);
        assert!(!marker.exists(), "a wait error must still kill the group");
    }

    /// N7: the peel must not reap. An unreaped zombie still holds its pid, and
    /// that pid is the process-group id the kill targets, so nothing can recycle
    /// the number between the exit check and the group kill. A reaping peek (the
    /// previous `Child::try_wait`) fails this: the raw `waitpid` below would
    /// answer `ECHILD` instead of the pid.
    #[test]
    fn peeking_at_the_exit_leaves_the_child_unreaped() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("quick");
        write_executable_script(&script, "#!/bin/sh\nexit 7\n");
        let mut child = Command::new(script.to_str().unwrap())
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        let status = loop {
            match peek_exit(&mut child).unwrap() {
                Some(status) => break status,
                None => std::thread::sleep(POLL_OVERSHOOT),
            }
        };
        assert_eq!(status.code(), Some(7));
        let mut raw: libc::c_int = 0;
        let reaped = unsafe { libc::waitpid(pid, &mut raw, libc::WNOHANG) };
        assert_eq!(reaped, pid, "the peek must leave the zombie in place");
    }

    /// The signal half of the `waitid` → `ExitStatus` translation: a child that
    /// died of a signal has no exit code, so it must not be reported as one.
    #[test]
    fn a_signalled_child_has_no_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("signalled");
        write_executable_script(&script, "#!/bin/sh\nkill -9 $$\n");
        let mut child = Command::new(script.to_str().unwrap())
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let status = loop {
            match peek_exit(&mut child).unwrap() {
                Some(status) => break status,
                None => std::thread::sleep(POLL_OVERSHOOT),
            }
        };
        assert!(!status.success());
        assert_eq!(status.code(), None);
        let _ = child.wait();
    }
}
