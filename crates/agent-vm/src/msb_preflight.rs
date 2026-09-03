//! Fail-fast guard for a forward-migrated private `msb.db`.
//!
//! sea-orm migrations are one-way: once a newer microsandbox opens
//! `MSB_HOME/db/msb.db` it forward-migrates the schema by inserting rows
//! into `seaql_migrations`. When agent-vm's older bundled msb (or the SDK
//! it links) later opens that same DB, sea-orm's migration status check
//! finds an applied migration whose file it doesn't have and fails with
//! an opaque "Migration file ... is missing, this migration has been
//! applied but its file is missing" error (a returned `DbErr`, surfaced
//! by the SDK) on every command that touches the DB.
//!
//! This module reads the applied migration names with a plain `SELECT`
//! (which does not trip that check) and compares them against the bundled
//! `Migrator`'s known set via [`crate::msb_schema::db_ahead_of_bundle`].
//! If the DB is ahead, it bails with a message naming the offending
//! migration(s), this build's own bundled schema, and pointing at
//! `agent-vm doctor --reset-msb-db` (#28), before agent-vm hands the DB
//! to msb at all — closing the loop between #30 (detect) and #28
//! (recover). Called from both the boot path (`run::launch`) and the
//! `agent-vm msb` passthrough (`msb_cmd::run`).
//!
//! `MSB_HOME/db` is *not* schema-namespaced (see #36 and
//! `docs/adr/0004-single-shared-msb-home.md`): every agent-vm build on a
//! host shares one private db under a given `$AGENT_VM_STATE_DIR`. This
//! guard is what makes that safe rather than silently corrupting —
//! it's a hard, named stop instead of an opaque sea-orm error, and its
//! message is the one place that tells a user (or an agent bouncing
//! between worktrees with differently-schema'd builds) to set
//! `AGENT_VM_STATE_DIR` per build if the collision becomes a recurring
//! annoyance.
//!
//! ## This is the first named stop, not the only one (issue #42)
//!
//! This guard is deliberately narrow: it only ever distinguishes "DB is
//! ahead of this build" from "DB could not be read for some other reason,"
//! and always fails *open* on the latter (see [`read_applied_migrations`]).
//! That other-reason bucket includes a DB another process currently holds
//! locked — this module does not attempt to detect or wait out a lock
//! itself (there is no separate "locked" test here beyond the generic
//! missing-table/corrupt-file cases below, which exercise the same
//! `.ok()?` fail-open branches a lock error would also hit). Probing the
//! lock explicitly here was considered and rejected: the vendored SDK's own
//! migration lock is a distinct flock file
//! (`db/msb.db.migration.lock`, taken in `connect_and_migrate`'s
//! `acquire_migration_lock`), not a lock on `msb.db` itself, so an
//! agent-vm-side probe would race the SDK's own lock rather than observe
//! it, and could produce a false block on a transient, benign contention.
//!
//! Two other fail-closed states from issue #42's matrix — **locked**
//! (`acquire_migration_lock`) and **partial** (`refuse_incomplete_self_downgrade`,
//! `refuse_if_install_exclusive_held`) — are therefore owned entirely by
//! the SDK's `connect_and_migrate`
//! (`vendor/microsandbox/sdk/rust/lib/backend/local/mod.rs:669`), which
//! this guard runs strictly *before*. When the SDK's own guards fire they
//! return named errors (`self_downgrade_recovery_required: ...`,
//! `database schema is newer than this msb binary; ...`, migration-lock
//! contention) instead of the opaque sea-orm "Migration file ... is
//! missing" error this module exists to preempt for the **ahead** case —
//! so this preflight is the first named stop on the boot path, not the
//! only one. See `docs/adr/0008-migrate-0.5.7-state-to-v0.6.15.md` for the
//! full four-state matrix and which layer owns each.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sea_orm::{ConnectionTrait as _, DatabaseBackend, Statement};

// Resolve MSB_HOME/db/msb.db from the same source of truth boot uses.
fn private_db_path() -> Result<PathBuf> {
    Ok(crate::msb_install::msb_home_dir()?
        .join("db")
        .join("msb.db"))
}

/// Read applied migration names from `seaql_migrations`. `Some(names)`
/// when the table was read (possibly empty). `None` when it could not be
/// read for a reason that is NOT "DB is ahead" (missing table,
/// locked/corrupt DB, connect error): the caller then fails open so an
/// unrelated hiccup never becomes a spurious block. This is the AC's
/// "distinguish DB-is-newer from unrelated failures" requirement.
async fn read_applied_migrations(db_path: &Path) -> Option<Vec<String>> {
    let url = format!("sqlite://{}?mode=rw", db_path.display());
    let db = sea_orm::Database::connect(&url).await.ok()?;
    let rows = db
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT version FROM seaql_migrations".to_owned(),
        ))
        .await
        .ok()?; // "no such table" (fresh/pre-migration DB) lands here -> None -> fail open
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(r.try_get::<String>("", "version").ok()?);
    }
    Some(out)
}

// Human-facing block message. Single source of truth so boot and
// passthrough print identical text. Names >=1 offending migration, this
// build's own schema (so cross-build collisions are self-diagnosing —
// see the AGENT_VM_STATE_DIR paragraph below), and the #28 reset command.
fn ahead_message(report: &crate::msb_schema::DbAheadOfBundle, db_path: &Path) -> String {
    let offenders = report.extra_migrations.join(", ");
    format!(
        "agent-vm private microsandbox database is NEWER than this build of agent-vm.\n\
         This build understands schema {}, but a newer microsandbox already forward-\n\
         migrated {}\n\
         with migration(s) this build does not have: {}\n\
         The bundled msb cannot open a forward-migrated database (migrations are one-way).\n\
         \n\
         This usually means two different agent-vm builds share one state root\n\
         ($AGENT_VM_STATE_DIR, default $HOME/.local/state/agent-vm) — e.g. switching\n\
         between worktrees or branches that vendor different microsandbox versions.\n\
         Set AGENT_VM_STATE_DIR to a distinct path per build to stop them colliding.\n\
         \n\
         Recover with:\n\n    agent-vm doctor --reset-msb-db\n\n\
         That moves the database aside (nothing is deleted) so the next run recreates it\n\
         at this build's schema. Or upgrade agent-vm to a build with the newer microsandbox.",
        crate::msb_schema::bundled_schema_version(),
        db_path.display(),
        offenders,
    )
}

// Inner decision seam (pure over the db path) so tests need not mutate
// env or go through msb_home_dir()/MSB_HOME.
async fn ensure_db_path_not_ahead(db_path: &Path) -> Result<()> {
    if !db_path.exists() {
        return Ok(()); // AC: absent -> proceed unchanged, never create it
    }
    let Some(applied) = read_applied_migrations(db_path).await else {
        return Ok(()); // unrelated read failure -> fail open
    };
    if let Some(report) = crate::msb_schema::db_ahead_of_bundle(&applied) {
        bail!("{}", ahead_message(&report, db_path));
    }
    Ok(())
}

/// Boot-path guard (async; called from `run::launch` before any SDK DB
/// open, and from `setup::run`/`pull::run`, which also reach
/// `connect_and_migrate`).
pub async fn ensure_db_not_ahead() -> Result<()> {
    ensure_db_path_not_ahead(&private_db_path()?).await
}

/// Passthrough guard (sync; called from `msb_cmd::run` before spawning
/// the child msb). Only builds a runtime when the DB file exists, so the
/// common no-DB passthrough (and the fake-msb integration tests) pay
/// nothing.
pub fn ensure_db_not_ahead_blocking() -> Result<()> {
    let db_path = private_db_path()?;
    if !db_path.exists() {
        return Ok(());
    }
    // point_at_msb/point_at_msb_home already ran (env set before any
    // runtime), so building a runtime now is sound (no setenv race). A
    // current-thread runtime is cheap for one quick query and preserves
    // msb_cmd's deliberate avoidance of the multi-thread runtime.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime for msb.db preflight")?;
    rt.block_on(ensure_db_path_not_ahead(&db_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUTURE_MIGRATION: &str = "m29990101_000001_future_thing";
    const BUNDLED_MIGRATION: &str = "m20260305_000001_create_image_tables";

    /// Build a real SQLite file at `path` with a `seaql_migrations` table
    /// holding `versions`. Uses sqlx directly (not sea-orm) so the fixture
    /// construction path is independent of the code under test.
    async fn seed_sqlite_db(path: &Path, versions: &[&str]) {
        use sqlx::Row as _;
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&url)
            .await
            .expect("connect to fixture db");
        sqlx::query(
            "CREATE TABLE seaql_migrations (version VARCHAR NOT NULL PRIMARY KEY, applied_at BIGINT NOT NULL)",
        )
        .execute(&pool)
        .await
        .expect("create seaql_migrations table");
        for v in versions {
            sqlx::query("INSERT INTO seaql_migrations (version, applied_at) VALUES (?, 0)")
                .bind(*v)
                .execute(&pool)
                .await
                .expect("insert migration row");
        }
        // Sanity: prove the fixture really has the rows we think it does.
        let count: i64 = sqlx::query("SELECT COUNT(*) AS c FROM seaql_migrations")
            .fetch_one(&pool)
            .await
            .expect("count rows")
            .get("c");
        assert_eq!(count as usize, versions.len());
        pool.close().await;
    }

    #[tokio::test]
    async fn ahead_db_is_rejected_with_offender_and_reset_command() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        seed_sqlite_db(&db_path, &[BUNDLED_MIGRATION, FUTURE_MIGRATION]).await;

        let err = ensure_db_path_not_ahead(&db_path)
            .await
            .expect_err("ahead db must be rejected");
        let msg = err.to_string();
        assert!(msg.contains(FUTURE_MIGRATION), "message: {msg}");
        assert!(
            msg.contains("agent-vm doctor --reset-msb-db"),
            "message: {msg}"
        );
        assert!(msg.contains("NEWER than this build"), "message: {msg}");
        // #36: MSB_HOME is a single shared home across every agent-vm build
        // (docs/adr/0004-single-shared-msb-home.md), so the message must be
        // self-diagnosing for the cross-build-collision case rather than
        // requiring the reader to already know that mechanism.
        assert!(
            msg.contains(&crate::msb_schema::bundled_schema_version()),
            "message must name this build's own bundled schema: {msg}"
        );
        assert!(
            msg.contains("AGENT_VM_STATE_DIR"),
            "message must point at the per-build isolation override: {msg}"
        );
    }

    // The next two tests exercise `read_applied_migrations`'s two
    // `.ok()?` fail-open branches (connect failure, then query failure).
    // Issue #42's "locked" fail-closed state — another process holding
    // the SDK's separate migration-lock flock while this guard's plain
    // `SELECT` runs — lands on the SAME branches: SQLite would return a
    // "database is locked" error from the query, which is exactly the
    // "could not read for a reason that is NOT ahead" case these tests
    // already cover generically (see this module's doc comment). A
    // dedicated lock simulation would need to hold a real SQLite-level
    // lock open across the assertion and would only be testing the
    // default `busy_timeout` retry/give-up behavior already owned by
    // sqlx/SQLite, not agent-vm logic — these two suffice.
    #[tokio::test]
    async fn db_without_seaql_migrations_table_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        // A valid SQLite file with no seaql_migrations table at all —
        // read_applied_migrations must return None (not panic/error out).
        let url = format!("sqlite://{}?mode=rwc", db_path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&url)
            .await
            .unwrap();
        pool.close().await;

        assert_eq!(read_applied_migrations(&db_path).await, None);
        ensure_db_path_not_ahead(&db_path)
            .await
            .expect("missing table must fail open, not block");
    }

    #[tokio::test]
    async fn corrupt_non_sqlite_file_fails_open() {
        // Distinct failure branch from `db_without_seaql_migrations_table_
        // fails_open` above: that test's file is a *valid* SQLite database
        // (connect succeeds, the SELECT then fails). Here the file at
        // `db_path` isn't a SQLite database at all, so `Database::connect`
        // itself fails. Both must land on the same fail-open outcome —
        // never a spurious block — but they exercise different `.ok()?`
        // short-circuits in `read_applied_migrations`.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        std::fs::write(&db_path, b"not a sqlite file, just garbage bytes").unwrap();

        assert_eq!(read_applied_migrations(&db_path).await, None);
        ensure_db_path_not_ahead(&db_path)
            .await
            .expect("corrupt/non-sqlite file must fail open, not block");
    }

    #[tokio::test]
    async fn behind_or_in_sync_db_proceeds_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        seed_sqlite_db(&db_path, &[BUNDLED_MIGRATION]).await;

        ensure_db_path_not_ahead(&db_path)
            .await
            .expect("subset of bundled migrations must proceed");
    }

    #[tokio::test]
    async fn nonexistent_path_proceeds_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("does-not-exist").join("msb.db");

        ensure_db_path_not_ahead(&db_path)
            .await
            .expect("absent db must proceed unchanged");
        assert!(!db_path.exists(), "guard must never create the db file");
    }
}
