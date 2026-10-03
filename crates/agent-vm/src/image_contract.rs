//! The boot-image contract (see `USAGE.md#boot-image-contract`): what any image
//! selected for a session must provide, and the launch diagnostics for one that
//! does not. agent-vm never installs software, substitutes another image, or
//! runs the guest command on the host, so a breach is a launch failure naming
//! the image and the missing piece.

use microsandbox::protocol::exec::{ExecFailed, ExecFailureKind};

use crate::config::escape_str;

/// The guest program every launch execs (the prelude runs in it); the only
/// program the contract fixes.
pub(crate) const LAUNCH_SHELL: &str = "bash";

/// Bash's own "command not found" status, kept so callers testing for it can
/// share one name instead of a bare literal.
pub(crate) const MISSING_PROGRAM_EXIT: u8 = 127;

/// What the guest prelude prints when the selected program is not on `PATH`.
pub(crate) fn missing_program_message(image: &str, command: &str) -> String {
    format!(
        "agent-vm: boot image {} has no runnable external program `{}` on the guest PATH or at \
         the configured path. agent-vm does not install software: add it to the image or select \
         an image that provides it (USAGE.md#boot-image-contract).",
        escape_str(image),
        escape_str(command),
    )
}

/// The contract diagnostic for a failed spawn of [`LAUNCH_SHELL`], or `None`
/// when the failure is not the image's (bad cwd, resource limits, …) and the
/// caller's existing message stands.
pub(crate) fn launch_shell_spawn_diagnostic(image: &str, failure: &ExecFailed) -> Option<String> {
    let problem = match failure.kind {
        // ENOENT also covers an ELF whose dynamic loader is absent.
        ExecFailureKind::NotFound => "has no runnable `bash` on its guest PATH",
        ExecFailureKind::NotExecutable => {
            "has a `bash` this host cannot execute (wrong CPU architecture or a corrupt binary)"
        }
        ExecFailureKind::PermissionDenied => "has a `bash` the guest user may not execute",
        _ => return None,
    };
    Some(format!(
        "boot image {} {problem}. agent-vm runs every launch through Bash, so the image must \
         provide it (USAGE.md#boot-image-contract). Spawn error: {}",
        escape_str(image),
        escape_str(&failure.message),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(kind: ExecFailureKind, message: &str) -> ExecFailed {
        ExecFailed {
            kind,
            errno: None,
            errno_name: None,
            message: message.to_string(),
            stage: None,
        }
    }

    #[test]
    fn not_found_names_the_missing_bash() {
        let diagnostic = launch_shell_spawn_diagnostic(
            "alpine:3.22",
            &failed(ExecFailureKind::NotFound, "no such file"),
        )
        .expect("NotFound must map to a contract diagnostic");
        assert!(diagnostic.contains("has no runnable `bash` on its guest PATH"));
        assert!(diagnostic.contains("alpine:3.22"));
        assert!(diagnostic.contains("USAGE.md#boot-image-contract"));
        assert!(diagnostic.contains("no such file"));
    }

    #[test]
    fn not_executable_and_permission_denied_map() {
        let not_executable = launch_shell_spawn_diagnostic(
            "img",
            &failed(ExecFailureKind::NotExecutable, "bad ELF"),
        )
        .expect("NotExecutable must map");
        assert!(not_executable.contains("wrong CPU architecture or a corrupt binary"));

        let denied = launch_shell_spawn_diagnostic(
            "img",
            &failed(ExecFailureKind::PermissionDenied, "EACCES"),
        )
        .expect("PermissionDenied must map");
        assert!(denied.contains("guest user may not execute"));
    }

    #[test]
    fn non_image_failures_keep_the_callers_message() {
        for kind in [
            ExecFailureKind::BadCwd,
            ExecFailureKind::ResourceLimit,
            ExecFailureKind::UserSetupFailed,
            ExecFailureKind::OutOfMemory,
            ExecFailureKind::PtySetupFailed,
            ExecFailureKind::BadArgs,
            ExecFailureKind::Other,
        ] {
            assert!(
                launch_shell_spawn_diagnostic("img", &failed(kind, "x")).is_none(),
                "{kind:?} is not an image-contract breach"
            );
        }
    }

    #[test]
    fn diagnostics_escape_control_bytes_from_image_and_spawn_text() {
        let diagnostic = launch_shell_spawn_diagnostic(
            "img\u{1b}[31mred",
            &failed(ExecFailureKind::NotFound, "boom\u{1b}[0m"),
        )
        .unwrap();
        assert!(
            !diagnostic.contains('\u{1b}'),
            "raw terminal-control bytes must not reach the terminal: {diagnostic:?}"
        );
        assert!(
            diagnostic.contains("\\u{1b}")
                || diagnostic.contains("\\x1b")
                || diagnostic.contains("\\033")
        );

        let message = missing_program_message("img\u{1b}[31m", "cmd\u{7}");
        assert!(!message.contains('\u{1b}'));
        assert!(!message.contains('\u{7}'));
        assert!(message.contains("`cmd\\x07`"));
        assert!(message.contains("img\\x1b[31m"));
    }
}
