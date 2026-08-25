//! Read-only inspection of microsandbox migration metadata.
//!
//! Callers deliberately choose their own policy for an unreadable database:
//! active-home preflight fails open, while legacy-home adoption retains it.

use std::{path::Path, time::Duration};

use sqlx::{
    Row as _,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

const INSPECTION_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const INSPECTION_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(crate) enum SchemaCompatibility {
    Compatible,
    Ahead(crate::msb_schema::DbAheadOfBundle),
    Unreadable { error: anyhow::Error },
}

pub(crate) async fn inspect_schema(db_path: &Path) -> SchemaCompatibility {
    // `exists()` hides permission failures and dangling symlinks. Only a
    // definitely absent entry is safe to treat as a database with no history.
    match std::fs::symlink_metadata(db_path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => {
            return SchemaCompatibility::Unreadable {
                error: anyhow::anyhow!("database path {} is not a regular file", db_path.display()),
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return SchemaCompatibility::Compatible;
        }
        Err(error) => {
            return SchemaCompatibility::Unreadable {
                error: anyhow::Error::from(error)
                    .context(format!("reading metadata for {}", db_path.display())),
            };
        }
    }

    match inspect_schema_inner(db_path).await {
        Ok(status) => status,
        Err(error) => SchemaCompatibility::Unreadable { error },
    }
}

async fn inspect_schema_inner(db_path: &Path) -> anyhow::Result<SchemaCompatibility> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(SQLITE_BUSY_TIMEOUT);
    let connect = SqlitePoolOptions::new()
        .max_connections(1)
        .acquire_timeout(INSPECTION_CONNECT_TIMEOUT)
        .connect_with(options);
    let pool = tokio::time::timeout(INSPECTION_CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| {
            anyhow::anyhow!("timed out connecting to SQLite after {INSPECTION_CONNECT_TIMEOUT:?}")
        })??;

    // Do not put an outer timeout around this function: cancellation could
    // skip `close()` after a pool has spawned SQLite's connection worker.
    let result = tokio::time::timeout(INSPECTION_QUERY_TIMEOUT, inspect_schema_with_pool(&pool))
        .await
        .map_err(|_| {
            anyhow::anyhow!("timed out reading SQLite schema after {INSPECTION_QUERY_TIMEOUT:?}")
        })?;
    pool.close().await;
    result
}

async fn inspect_schema_with_pool(pool: &sqlx::SqlitePool) -> anyhow::Result<SchemaCompatibility> {
    let has_migrations: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'seaql_migrations'",
    )
    .fetch_optional(pool)
    .await?;
    if has_migrations.is_none() {
        return Ok(SchemaCompatibility::Compatible);
    }
    let rows = sqlx::query("SELECT version FROM seaql_migrations")
        .fetch_all(pool)
        .await?;
    let versions = rows
        .iter()
        .map(|row| row.try_get::<String, _>("version"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::msb_schema::db_ahead_of_bundle(&versions)
        .map(SchemaCompatibility::Ahead)
        .unwrap_or(SchemaCompatibility::Compatible))
}

pub(crate) fn inspect_schema_blocking(db_path: &Path) -> anyhow::Result<SchemaCompatibility> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)?;
    Ok(runtime.block_on(inspect_schema(db_path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn sqlite(path: &Path, sql: &str) {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query(sql).execute(&pool).await.unwrap();
        pool.close().await;
    }

    #[tokio::test]
    async fn absent_database_is_compatible_without_creating_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.db");
        assert!(matches!(
            inspect_schema(&path).await,
            SchemaCompatibility::Compatible
        ));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn database_without_migration_table_is_compatible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.db");
        sqlite(&path, "CREATE TABLE unrelated (id INTEGER)").await;
        assert!(matches!(
            inspect_schema(&path).await,
            SchemaCompatibility::Compatible
        ));
    }

    #[tokio::test]
    async fn future_migration_is_ahead() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ahead.db");
        sqlite(&path, "CREATE TABLE seaql_migrations (version TEXT)").await;
        sqlite(
            &path,
            "INSERT INTO seaql_migrations VALUES ('m29990101_000001_future_thing')",
        )
        .await;
        assert!(matches!(
            inspect_schema(&path).await,
            SchemaCompatibility::Ahead(_)
        ));
    }

    #[test]
    fn locked_database_is_unreadable_within_the_inspection_bound() {
        use sqlx::{Connection as _, Executor as _, SqliteConnection};
        use std::time::Instant;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.db");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut lock = runtime.block_on(async {
            sqlite(&path, "CREATE TABLE seaql_migrations (version TEXT)").await;
            let options = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(false);
            let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
            connection.execute("BEGIN EXCLUSIVE").await.unwrap();
            connection
        });

        let started = Instant::now();
        let status = inspect_schema_blocking(&path).unwrap();
        assert!(
            started.elapsed() < INSPECTION_CONNECT_TIMEOUT + INSPECTION_QUERY_TIMEOUT,
            "locked inspection exceeded its configured bounds"
        );
        assert!(matches!(status, SchemaCompatibility::Unreadable { .. }));

        runtime.block_on(async {
            lock.execute("ROLLBACK").await.unwrap();
            lock.close().await.unwrap();
        });
    }

    #[tokio::test]
    async fn corrupt_database_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.db");
        std::fs::write(&path, "not sqlite").unwrap();
        assert!(matches!(
            inspect_schema(&path).await,
            SchemaCompatibility::Unreadable { .. }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn database_symlink_is_unreadable() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.db");
        sqlite(&target, "CREATE TABLE seaql_migrations (version TEXT)").await;
        let path = dir.path().join("symlink.db");
        symlink(&target, &path).unwrap();
        assert!(matches!(
            inspect_schema(&path).await,
            SchemaCompatibility::Unreadable { .. }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dangling_database_symlink_is_unreadable() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dangling.db");
        symlink(dir.path().join("missing.db"), &path).unwrap();
        assert!(matches!(
            inspect_schema(&path).await,
            SchemaCompatibility::Unreadable { .. }
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn non_utf8_database_path_is_unreadable_not_absent() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(OsString::from_vec(b"db-\xff.sqlite".to_vec()));
        std::fs::write(&path, b"not sqlite").unwrap();
        // sqlx currently rejects non-UTF-8 SQLite filenames. The important
        // adoption invariant is conservative: retain it rather than calling
        // it an absent, compatible database.
        assert!(matches!(
            inspect_schema(&path).await,
            SchemaCompatibility::Unreadable { .. }
        ));
    }
}
