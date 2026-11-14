//! What a committed transaction may still fail to *report* (ADR-0068, R6).
//!
//! The atomic rename **is** the commit. Everything after it — the debug test
//! checkpoint, the advisory selection, the completion notice — can fail for
//! reasons that do not undo committed authority. Those failures cross this typed
//! seam as a report, are handled once at the command boundary, and never become
//! an `anyhow::Error` that would make a successful command exit nonzero or claim
//! "approval was not updated".
//!
//! # Why warning text is fixed and reference-free
//!
//! A post-commit warning may be reached before any output policy has rendered a
//! private reference, so it states only what happened and what not to do. The
//! retry instruction matters: a user who reads a failure here would repeat a
//! publication that already succeeded.

use std::io::Write;

/// Whether the post-rename test checkpoint could be reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitReport {
    Complete,
    CheckpointUnavailable,
}

/// A committed value plus how its post-commit reporting went. Constructed only
/// after a successful rename (or a complete no-op), so its presence is the
/// commit's proof at the call site.
pub(super) struct Completion<T> {
    pub(super) value: T,
    pub(super) report: CommitReport,
}

const PUBLICATION_CHECKPOINT_WARNING: &str = "warning: image publication succeeded and active image state was committed, but the post-commit test checkpoint could not be reported; do not retry it as a failed publication";
const PUBLICATION_NOTICE_WARNING: &str = "warning: image publication succeeded and active image state was committed, but its completion notice could not be written; do not retry it as a failed publication";
const PREPARATION_CHECKPOINT_WARNING: &str = "warning: image approval/selection was committed, but the post-commit test checkpoint could not be reported; do not retry it as a failed preparation";

/// Finish a committed build/import: report the checkpoint issue, attempt the
/// already-computed completion notice once, and return the successful exit code.
///
/// A fixed, reference-free warning is attempted on stderr for each reporting
/// problem. If stderr is unwritable too, the command still succeeded: bounded
/// failed warning delivery is part of committed success, not a false failure.
pub(crate) fn finish_publication(report: CommitReport, notice: Option<String>) -> i32 {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    finish_publication_with(report, notice, &mut stdout, &mut stderr)
}

fn finish_publication_with(
    report: CommitReport,
    notice: Option<String>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> i32 {
    let mut warnings = Vec::new();
    if report == CommitReport::CheckpointUnavailable {
        warnings.push(PUBLICATION_CHECKPOINT_WARNING);
    }
    if let Some(notice) = notice
        && writeln!(stdout, "{notice}").is_err()
    {
        warnings.push(PUBLICATION_NOTICE_WARNING);
    }
    for warning in warnings {
        let _ = writeln!(stderr, "{warning}");
    }
    0
}

/// The same policy for a committed launch/setup/refresh preparation: its
/// selection report cannot fail the command, and its warning names no reference.
pub(super) fn finish_preparation(report: CommitReport) {
    if report == CommitReport::CheckpointUnavailable {
        let _ = writeln!(std::io::stderr(), "{PREPARATION_CHECKPOINT_WARNING}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every byte a caller could write, available or not, so a sink failure is
    /// deterministic rather than an environment accident.
    struct Sink {
        writable: bool,
        written: String,
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.writable {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            self.written.push_str(&String::from_utf8_lossy(bytes));
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn run(
        report: CommitReport,
        notice: Option<&str>,
        stdout: bool,
        stderr: bool,
    ) -> (i32, String, String) {
        let mut out = Sink {
            writable: stdout,
            written: String::new(),
        };
        let mut err = Sink {
            writable: stderr,
            written: String::new(),
        };
        let code = finish_publication_with(report, notice.map(str::to_owned), &mut out, &mut err);
        (code, out.written, err.written)
    }

    #[test]
    fn committed_gate_issue_finishes_zero_with_success_warning() {
        let (code, stdout, stderr) = run(
            CommitReport::CheckpointUnavailable,
            Some("done"),
            true,
            true,
        );
        assert_eq!(code, 0);
        assert_eq!(stdout, "done\n");
        assert_eq!(stderr, format!("{PUBLICATION_CHECKPOINT_WARNING}\n"));
        assert!(!stderr.contains("approval was not updated"));
        assert!(!stderr.contains("nothing was approved"));
    }

    #[test]
    fn notice_io_failure_finishes_zero() {
        let (code, _, stderr) = run(CommitReport::Complete, Some("done"), false, true);
        assert_eq!(code, 0);
        assert_eq!(stderr, format!("{PUBLICATION_NOTICE_WARNING}\n"));
    }

    #[test]
    fn both_reporting_failures_warn_once_each_in_a_fixed_order() {
        let (code, _, stderr) = run(
            CommitReport::CheckpointUnavailable,
            Some("done"),
            false,
            true,
        );
        assert_eq!(code, 0);
        assert_eq!(
            stderr,
            format!("{PUBLICATION_CHECKPOINT_WARNING}\n{PUBLICATION_NOTICE_WARNING}\n")
        );
    }

    #[test]
    fn warning_sink_failure_still_zero() {
        let (code, _, _) = run(CommitReport::CheckpointUnavailable, None, true, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn a_clean_commit_prints_only_its_notice() {
        let (code, stdout, stderr) = run(CommitReport::Complete, Some("notice"), true, true);
        assert_eq!(code, 0);
        assert_eq!(stdout, "notice\n");
        assert_eq!(stderr, "");
    }
}
