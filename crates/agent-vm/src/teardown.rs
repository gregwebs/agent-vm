//! Tearing a sandbox down after an exec session: one order, two modes.
//!
//! Teardown mechanics live here; *when* a session ends and what status it earns is
//! `run.rs`'s `after_session`/`forced_after_session`. The split keeps the one
//! ordered stop/kill/reap/remove schedule in a single small module, because
//! everything that runs it — the ordinary end, the forced end (#401) and the
//! failure path — must not be able to drift.

use anyhow::Result;
use microsandbox::Sandbox;

use std::time::Duration;

/// The teardown operations the exec lifecycle performs.
///
/// A seam, not a new lifecycle: [`Sandbox`]'s adapter delegates to the current
/// SDK calls and keeps their error display, so a test can drive the *production*
/// failure schedule (stop/kill/reap/remove errors and timeouts) without a booted
/// VM or a fake `msb`. Bounded timeouts stay in
/// [`cleanup_exec_sandbox_failures`], the one owner of the order.
pub(crate) trait ExecTeardown: Sync {
    async fn stop_and_wait(&self) -> Result<()>;
    async fn kill_with_timeout(&self, timeout: Duration) -> Result<()>;
    async fn wait(&self) -> Result<()>;
    async fn remove(&self) -> Result<()>;

    /// Run once, after the producer has stopped and before `remove`.
    ///
    /// One hook, not one per caller: every path that removes *this session's*
    /// sandbox goes through [`cleanup_exec_sandbox_failures`], so "producer
    /// stopped → drain what it wrote → persist it → remove" cannot differ
    /// between the ordinary end, the forced end (#401) and a failure (#258).
    /// The default is a no-op so the trait's existing implementors — the
    /// `Sandbox` adapter and the test stubs — need no change.
    async fn before_remove(&self) {}
}

impl ExecTeardown for Sandbox {
    async fn stop_and_wait(&self) -> Result<()> {
        Sandbox::stop_and_wait(self)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::new)
    }
    async fn kill_with_timeout(&self, timeout: Duration) -> Result<()> {
        Sandbox::kill_with_timeout(self, timeout)
            .await
            .map_err(anyhow::Error::new)
    }
    async fn wait(&self) -> Result<()> {
        Sandbox::wait(self)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::new)
    }
    async fn remove(&self) -> Result<()> {
        Sandbox::remove(self.name())
            .await
            .map_err(anyhow::Error::new)
    }
}

/// Bounded teardown deadlines for the exec lifecycle. Named and local: a wedged
/// VMM must not hang the launcher, and a failed graceful stop must still reap
/// and remove rather than leaking a hidden VM (#258).
pub(crate) const EXEC_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const EXEC_KILL_TIMEOUT: Duration = Duration::from_secs(5);
const EXEC_REAP_TIMEOUT: Duration = Duration::from_secs(5);
const EXEC_REMOVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The backstop for [`ExecTeardown::before_remove`], the only teardown step whose
/// own work has several bounded parts.
///
/// A backstop, not a budget: `before_remove` bounds each of its own steps
/// (a 2 s drain, a 2 s wait for the final write, a 2.5 s close) and this only
/// fires if one of those bounds is itself broken — a wait tokio cannot cancel, or
/// a blocking call on a worker thread. Without it the step was the one teardown
/// operation with no deadline at all, in both modes, including the one a user
/// reaches by pressing Ctrl-C twice.
pub(crate) const EXEC_RECORD_TIMEOUT: Duration = Duration::from_secs(7);

/// Which teardown a session's end demands.
///
/// One owner, two modes: this is not a second teardown path, it is the same order
/// with the graceful step deliberately skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TeardownMode {
    /// The guest produced its own status: stop gracefully, escalate on failure.
    Ordinary,
    /// The launcher stopped waiting (#401): a grace expiry or a second interrupt.
    /// Go straight to the bounded kill, reap and remove.
    Forced,
}

/// Attempt every teardown step, collecting failures instead of swallowing them
/// (CODING_STANDARDS: errors are returned, not logged and ignored). The
/// graceful stop is tried first; only its failure escalates to a bounded
/// kill+reap. The sandbox is removed either way, so a failed launch never
/// leaves a hidden VM behind (#258).
///
/// In [`TeardownMode::Forced`] the stop is skipped for the reason given on that
/// variant; the ordinary record of a failed stop is deliberately **not** relaxed
/// anywhere it still applies, because a stop that failed on its own is a genuine
/// cleanup failure that a later successful kill must not erase.
pub(crate) async fn cleanup_exec_sandbox_failures(
    teardown: &impl ExecTeardown,
    mode: TeardownMode,
) -> Vec<String> {
    let mut failures: Vec<String> = Vec::new();
    let stopped = match mode {
        TeardownMode::Forced => false,
        TeardownMode::Ordinary => {
            match tokio::time::timeout(EXEC_STOP_TIMEOUT, teardown.stop_and_wait()).await {
                Ok(Ok(_)) => true,
                Ok(Err(error)) => {
                    failures.push(format!("stop: {error}"));
                    false
                }
                Err(_) => {
                    failures.push(format!("stop: timed out after {EXEC_STOP_TIMEOUT:?}"));
                    false
                }
            }
        }
    };
    if !stopped {
        // Cancelling the timed-out stop future released the child-handle lock
        // before this kill/reap runs: the outer timeout on `kill_with_timeout`
        // bounds the dispatch itself, not just the kill it performs.
        match tokio::time::timeout(
            EXEC_KILL_TIMEOUT,
            teardown.kill_with_timeout(EXEC_KILL_TIMEOUT),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("kill: {error}")),
            Err(_) => failures.push(format!("kill: timed out after {EXEC_KILL_TIMEOUT:?}")),
        }
        // Reap even if the kill failed, so no wedged process is left owned.
        match tokio::time::timeout(EXEC_REAP_TIMEOUT, teardown.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => failures.push(format!("reap: {error}")),
            Err(_) => failures.push(format!("reap: timed out after {EXEC_REAP_TIMEOUT:?}")),
        }
    }
    // Between the reap and the remove: the producer has stopped, so whatever it
    // wrote is on disk to be read, and the sandbox's log directory still exists.
    //
    // A timeout here is deliberately **not** a teardown failure: the refusal feed
    // cannot fail a launch (AC14), so the record being late is a lost record and
    // never a refused remove. The remove below still runs, which is the whole
    // point of bounding this step.
    if tokio::time::timeout(EXEC_RECORD_TIMEOUT, teardown.before_remove())
        .await
        .is_err()
    {
        tracing::warn!(
            "recording the session's last refusals did not finish within {EXEC_RECORD_TIMEOUT:?}; removing the sandbox anyway"
        );
    }
    match tokio::time::timeout(EXEC_REMOVE_TIMEOUT, teardown.remove()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(format!("remove: {error}")),
        Err(_) => failures.push(format!("remove: timed out after {EXEC_REMOVE_TIMEOUT:?}")),
    }
    failures
}

/// [`cleanup_exec_sandbox_failures`] as a `Result`: `Ok` only when every
/// teardown step succeeded, otherwise one error listing the failures in
/// operation order. A successful forced cleanup never hides a failed graceful
/// stop.
pub(crate) async fn cleanup_exec_sandbox(teardown: &impl ExecTeardown) -> anyhow::Result<()> {
    let failures = cleanup_exec_sandbox_failures(teardown, TeardownMode::Ordinary).await;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{}", failures.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A teardown that records the order of its own steps.
    struct Recorder {
        steps: Mutex<Vec<&'static str>>,
        stop_fails: bool,
    }

    impl Recorder {
        fn new(stop_fails: bool) -> Self {
            Self {
                steps: Mutex::new(Vec::new()),
                stop_fails,
            }
        }
        fn step(&self, name: &'static str) -> Result<()> {
            self.steps.lock().unwrap().push(name);
            Ok(())
        }
        fn recorded(&self) -> Vec<&'static str> {
            self.steps.lock().unwrap().clone()
        }
    }

    impl ExecTeardown for Recorder {
        async fn stop_and_wait(&self) -> Result<()> {
            self.step("stop")?;
            if self.stop_fails {
                anyhow::bail!("the guest refused to stop");
            }
            Ok(())
        }
        async fn kill_with_timeout(&self, _timeout: Duration) -> Result<()> {
            self.step("kill")
        }
        async fn wait(&self) -> Result<()> {
            self.step("reap")
        }
        async fn remove(&self) -> Result<()> {
            self.step("remove")
        }
        async fn before_remove(&self) {
            self.steps.lock().unwrap().push("before_remove");
        }
    }

    /// ADR-0064: the hook runs once, after the producer has stopped and before
    /// the sandbox is removed, and it runs in both modes and whatever the earlier
    /// steps did. Ordering it anywhere else would drain a file the runtime has not
    /// flushed, or drain one that no longer exists.
    #[test]
    fn before_remove_runs_between_reap_and_remove_in_every_mode() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        for (mode, stop_fails, expected) in [
            (
                TeardownMode::Ordinary,
                false,
                vec!["stop", "before_remove", "remove"],
            ),
            (
                TeardownMode::Ordinary,
                true,
                vec!["stop", "kill", "reap", "before_remove", "remove"],
            ),
            (
                TeardownMode::Forced,
                false,
                vec!["kill", "reap", "before_remove", "remove"],
            ),
        ] {
            let recorder = Recorder::new(stop_fails);
            let failures = runtime.block_on(cleanup_exec_sandbox_failures(&recorder, mode));
            assert_eq!(
                recorder.recorded(),
                expected,
                "mode {mode:?}, stop_fails={stop_fails}"
            );
            if stop_fails && mode == TeardownMode::Ordinary {
                assert_eq!(failures.len(), 1, "the failed stop is still reported");
            } else {
                assert!(failures.is_empty(), "{failures:?}");
            }
        }
    }

    /// The record step is the only teardown operation whose own work has several
    /// parts, and it used to be the only one with no deadline. A step that never
    /// returns must not stop the sandbox being removed — in either mode.
    #[test]
    fn a_wedged_record_step_is_cut_off_and_the_sandbox_still_removed() {
        struct Wedged(Mutex<Vec<&'static str>>);
        impl ExecTeardown for Wedged {
            async fn stop_and_wait(&self) -> Result<()> {
                self.0.lock().unwrap().push("stop");
                Ok(())
            }
            async fn kill_with_timeout(&self, _t: Duration) -> Result<()> {
                self.0.lock().unwrap().push("kill");
                Ok(())
            }
            async fn wait(&self) -> Result<()> {
                self.0.lock().unwrap().push("reap");
                Ok(())
            }
            async fn remove(&self) -> Result<()> {
                self.0.lock().unwrap().push("remove");
                Ok(())
            }
            async fn before_remove(&self) {
                // The failure mode: a blocking wait that no bound inside the step
                // can cancel.
                futures::future::pending::<()>().await
            }
        }
        for mode in [TeardownMode::Ordinary, TeardownMode::Forced] {
            let wedged = Wedged(Mutex::new(Vec::new()));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async {
                tokio::time::pause();
                let started = tokio::time::Instant::now();
                let failures = cleanup_exec_sandbox_failures(&wedged, mode).await;
                // The remove still ran, and a late record is not a failure of the
                // teardown: the feed may never fail a launch (AC14).
                assert!(failures.is_empty(), "{mode:?}: {failures:?}");
                assert!(
                    started.elapsed() <= EXEC_RECORD_TIMEOUT + EXEC_REMOVE_TIMEOUT,
                    "{mode:?}: {:?}",
                    started.elapsed()
                );
            });
            assert!(
                wedged.0.lock().unwrap().ends_with(&["remove"]),
                "{mode:?}: {:?}",
                wedged.0.lock().unwrap()
            );
        }
    }

    /// A forced teardown whose earlier steps did nothing still runs the hook: a
    /// kill that errored must not also cost the session its refusals.
    #[test]
    fn before_remove_runs_even_when_every_earlier_step_failed() {
        struct Failing(Mutex<Vec<&'static str>>);
        impl ExecTeardown for Failing {
            async fn stop_and_wait(&self) -> Result<()> {
                anyhow::bail!("no")
            }
            async fn kill_with_timeout(&self, _t: Duration) -> Result<()> {
                anyhow::bail!("no")
            }
            async fn wait(&self) -> Result<()> {
                anyhow::bail!("no")
            }
            async fn remove(&self) -> Result<()> {
                anyhow::bail!("no")
            }
            async fn before_remove(&self) {
                self.0.lock().unwrap().push("before_remove");
            }
        }
        let recorder = Failing(Mutex::new(Vec::new()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let failures = runtime.block_on(cleanup_exec_sandbox_failures(
            &recorder,
            TeardownMode::Ordinary,
        ));
        assert_eq!(failures.len(), 4, "every step reported: {failures:?}");
        assert_eq!(recorder.0.lock().unwrap().as_slice(), ["before_remove"]);
    }
}
