//! `agent-vm doctor` — diagnostic / maintenance operations for agent-vm's
//! private microsandbox state.
//!
//! ## `--reset-msb-db`
//!
//! sea-orm migrations in microsandbox are one-way: once a newer `msb` opens
//! `MSB_HOME/db/msb.db` it forward-migrates the schema, and an older bundled
//! `msb` (the one agent-vm ships) can never open that db again — every
//! subsequent `agent-vm` command that talks to the db dies. The only fix
//! today would be a manual `mv` of the `db` dir, which is undiscoverable.
//!
//! This command moves `MSB_HOME/db` aside to a timestamped sibling rather
//! than deleting it: reversible by construction (undo is the reverse
//! `mv`, which we print), and it never destroys state outright. The next
//! `agent-vm shell`/`run` then finds no `db/`, and msb (which owns that
//! directory entirely — no agent-vm code creates, opens, or writes it)
//! recreates it fresh at the bundled schema and re-pulls images on first
//! boot.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

#[derive(ClapArgs)]
pub struct Args {
    /// Move MSB_HOME/db aside (non-destructive) so the next agent-vm
    /// shell/run recreates it at the bundled schema. Use this to recover
    /// from a db forward-migrated by a newer microsandbox that the
    /// bundled msb can no longer open.
    #[arg(long)]
    reset_msb_db: bool,
}

/// Result of attempting to reset the private msb db. Kept as data so the
/// filesystem logic ([`reset_msb_db_in`]) and the user-facing text
/// ([`render`]) are independently testable.
#[derive(Debug, PartialEq, Eq)]
enum ResetOutcome {
    Moved { from: PathBuf, to: PathBuf },
    NothingToMove { checked: PathBuf },
}

pub fn run(args: Args) -> Result<()> {
    if !args.reset_msb_db {
        println!("==> agent-vm doctor: available operations");
        println!("      --reset-msb-db   move MSB_HOME/db aside (reversible) so the next");
        println!("                       agent-vm shell/run recreates it at the bundled schema");
        return Ok(());
    }

    let msb_home = crate::msb_install::msb_home_dir()?;
    let ts = timestamp_suffix(SystemTime::now());
    let outcome = reset_msb_db_in(&msb_home, &ts)?;
    println!("{}", render(&outcome));
    Ok(())
}

/// Move `msb_home/db` aside to a unique `db.reset-<ts>` sibling. Pure over
/// its inputs: no env reads, so it is directly unit-testable against a
/// tempdir. Never deletes anything — worst case on a failed rename is the
/// original `db/` untouched.
fn reset_msb_db_in(msb_home: &Path, ts: &str) -> Result<ResetOutcome> {
    let db = msb_home.join("db");
    // symlink_metadata: don't follow, and treat a broken symlink as
    // present so we still move it aside rather than silently no-op.
    if std::fs::symlink_metadata(&db).is_err() {
        return Ok(ResetOutcome::NothingToMove { checked: db });
    }

    let target = unique_target(msb_home, ts);
    std::fs::rename(&db, &target)
        .with_context(|| format!("moving {} -> {}", db.display(), target.display()))?;
    Ok(ResetOutcome::Moved { from: db, to: target })
}

/// `msb_home/db.reset-<ts>`, disambiguated with `.2`, `.3`, ... if that
/// path is already taken, so a prior reset (e.g. a same-second re-run) is
/// never clobbered.
fn unique_target(msb_home: &Path, ts: &str) -> PathBuf {
    let base = msb_home.join(format!("db.reset-{ts}"));
    if std::fs::symlink_metadata(&base).is_err() {
        return base;
    }
    for n in 2.. {
        let candidate = msb_home.join(format!("db.reset-{ts}.{n}"));
        if std::fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
    }
    unreachable!("unbounded loop above always returns")
}

/// Epoch-seconds suffix: dependency-free (no chrono), sortable,
/// unambiguous. Not calendar-formatted on purpose — this is a rarely-run
/// recovery command, and human readability comes from the printed
/// absolute path, not the suffix.
fn timestamp_suffix(now: SystemTime) -> String {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

/// User-facing text for a [`ResetOutcome`]. Pure so the AC wording lives in
/// one testable place.
fn render(outcome: &ResetOutcome) -> String {
    match outcome {
        ResetOutcome::Moved { from, to } => format!(
            "==> Moved microsandbox db aside (nothing was deleted)\n\
             from: {}\n\
             to:   {}\n\
             The database will be recreated at the bundled schema on the next \
             `agent-vm shell`/`run`, and images will be re-pulled on first boot.\n\
             To undo: mv \"{}\" \"{}\"",
            from.display(),
            to.display(),
            to.display(),
            from.display(),
        ),
        ResetOutcome::NothingToMove { checked } => format!(
            "==> No microsandbox db to reset — nothing was moved.\n\
             checked: {}\n\
             A fresh database will be created on the next `agent-vm shell`/`run`.",
            checked.display(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn write_file(path: &Path, contents: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn reset_moves_db_dir_with_all_files() {
        let home = tempfile::tempdir().unwrap();
        let db = home.path().join("db");
        write_file(&db.join("msb.db"), b"schema-bytes");
        write_file(&db.join("msb.db-wal"), b"wal-bytes");
        write_file(&db.join("msb.db-shm"), b"shm-bytes");
        write_file(&db.join("msb.db.lock"), b"lock-bytes");

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();

        let expected_to = home.path().join("db.reset-123");
        assert_eq!(
            outcome,
            ResetOutcome::Moved {
                from: db.clone(),
                to: expected_to.clone(),
            }
        );
        assert!(!db.exists(), "db/ should be gone after the move");
        assert!(expected_to.is_dir());
        assert_eq!(
            std::fs::read(expected_to.join("msb.db")).unwrap(),
            b"schema-bytes"
        );
        assert_eq!(
            std::fs::read(expected_to.join("msb.db-wal")).unwrap(),
            b"wal-bytes"
        );
        assert_eq!(
            std::fs::read(expected_to.join("msb.db-shm")).unwrap(),
            b"shm-bytes"
        );
        assert_eq!(
            std::fs::read(expected_to.join("msb.db.lock")).unwrap(),
            b"lock-bytes"
        );
    }

    #[test]
    fn reset_is_reversible() {
        let home = tempfile::tempdir().unwrap();
        let db = home.path().join("db");
        write_file(&db.join("msb.db"), b"schema-bytes");

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();
        let ResetOutcome::Moved { from, to } = outcome else {
            panic!("expected Moved");
        };

        std::fs::rename(&to, &from).expect("undo rename must succeed");
        assert!(from.is_dir());
        assert_eq!(std::fs::read(from.join("msb.db")).unwrap(), b"schema-bytes");
        assert!(!to.exists());
    }

    #[test]
    fn reset_noop_when_db_absent() {
        let home = tempfile::tempdir().unwrap();

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();

        assert_eq!(
            outcome,
            ResetOutcome::NothingToMove {
                checked: home.path().join("db"),
            }
        );
        let entries: Vec<_> = std::fs::read_dir(home.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries.is_empty(),
            "no db.reset-* should have been created on no-op"
        );
    }

    #[test]
    fn reset_never_clobbers_existing_reset() {
        let home = tempfile::tempdir().unwrap();
        let pre_existing = home.path().join("db.reset-123");
        write_file(&pre_existing.join("marker"), b"do-not-touch");
        write_file(&home.path().join("db").join("msb.db"), b"fresh-db");

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();

        let expected_to = home.path().join("db.reset-123.2");
        assert_eq!(
            outcome,
            ResetOutcome::Moved {
                from: home.path().join("db"),
                to: expected_to.clone(),
            }
        );
        assert_eq!(
            std::fs::read(pre_existing.join("marker")).unwrap(),
            b"do-not-touch",
            "pre-existing reset dir must be untouched"
        );
        assert_eq!(
            std::fs::read(expected_to.join("msb.db")).unwrap(),
            b"fresh-db"
        );
    }

    #[test]
    fn reset_moves_a_symlinked_db_without_touching_its_target() {
        // Unusual but possible: db/ is a symlink rather than a plain dir.
        // symlink_metadata must treat it as present (so it's still moved
        // aside, not silently skipped), and the rename must move the link
        // itself, not dereference it and move/delete the target.
        let home = tempfile::tempdir().unwrap();
        let real_target = tempfile::tempdir().unwrap();
        write_file(&real_target.path().join("msb.db"), b"real-target-bytes");

        let db = home.path().join("db");
        std::os::unix::fs::symlink(real_target.path(), &db).unwrap();

        let outcome = reset_msb_db_in(home.path(), "123").unwrap();

        let expected_to = home.path().join("db.reset-123");
        assert_eq!(
            outcome,
            ResetOutcome::Moved {
                from: db.clone(),
                to: expected_to.clone(),
            }
        );
        assert!(
            std::fs::symlink_metadata(&expected_to)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the moved entry must still be a symlink, not a dereferenced copy"
        );
        assert_eq!(
            std::fs::read_link(&expected_to).unwrap(),
            real_target.path(),
            "the moved symlink must still point at the original target"
        );
        assert!(!db.exists(), "db/ symlink should be gone from its old spot");
        assert_eq!(
            std::fs::read(real_target.path().join("msb.db")).unwrap(),
            b"real-target-bytes",
            "the symlink target's contents must be completely untouched"
        );
    }

    #[test]
    fn render_moved_mentions_repull_and_paths() {
        let outcome = ResetOutcome::Moved {
            from: PathBuf::from("/state/msb-home/db"),
            to: PathBuf::from("/state/msb-home/db.reset-123"),
        };

        let text = render(&outcome);

        assert!(text.contains("/state/msb-home/db"));
        assert!(text.contains("/state/msb-home/db.reset-123"));
        assert!(text.contains("re-pulled"));
        assert!(text.contains("next"));
        assert!(text.contains("To undo"));
    }

    #[test]
    fn render_noop_mentions_nothing_moved() {
        let outcome = ResetOutcome::NothingToMove {
            checked: PathBuf::from("/state/msb-home/db"),
        };

        let text = render(&outcome);

        assert!(text.contains("No microsandbox db"));
        assert!(text.contains("nothing was moved"));
        assert!(text.contains("/state/msb-home/db"));
    }

    #[test]
    fn timestamp_suffix_is_stable_and_numeric() {
        let fixed = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(timestamp_suffix(fixed), "1700000000");
    }

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn args_parse_reset_msb_db_flag() {
        let cli = TestCli::try_parse_from(["t", "--reset-msb-db"]).unwrap();
        assert!(cli.args.reset_msb_db);

        let cli = TestCli::try_parse_from(["t"]).unwrap();
        assert!(!cli.args.reset_msb_db);
    }
}
