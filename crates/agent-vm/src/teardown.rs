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
