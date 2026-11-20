//! The private msb catalog, read the way the launch supervisor needs it (#692).
//!
//! Ported from `script/test/lib/egress-fixtures.py` (`catalog_rows` and
//! `_catalog_query`). This is the fixture's own observation of the private state
//! directory: the sandbox rows (name, config, status) and their runs (pid,
//! status). `OwnedLaunch` joins those against the launcher's identity receipt,
//! so cleanup stops and removes the sandboxes the launch actually created.
//!
//! The contract is subtler than a `SELECT`, and every rule here is load-bearing:
//!
//! * No `db/msb.db` yet is `[]`, not an error.
//! * A **missing table** is `[]` too: a fresh private state's file exists for a
//!   few milliseconds before the first migration commits its tables (#449), so
//!   an absent table is "not yet initialized" and the 50 ms observer polls
//!   again. A table that exists with the *wrong* columns is a hard error, since
//!   that is a format change the journal join depends on.
//! * Every driver error is retried inside a 1 s bound and then surfaced. A
//!   read-only connection to a WAL database transiently fails with "unable to
//!   open database file" while the runtime holds or rotates `-wal`/`-shm`
//!   (~1 in 700 polls), and that is not absence evidence.
//! * The connection is read-only: a fixture must never be able to write the
//!   catalog it is inspecting.
//!
//! `rusqlite` links the workspace's existing `libsqlite3-sys` with no `bundled`
//! feature, so this is the same SQLite the launcher uses (ADR-0072).

use std::{
    path::Path,
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, types::Value as Sql};
use serde_json::Value;

/// One joined `sandbox`/`run` row. `pid` and the run columns are optional
/// because the join is a LEFT JOIN: a sandbox with no run row yet has neither.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogRow {
    pub name: String,
    pub config: String,
    pub status: String,
    /// The run's own id, kept as stored: the launcher's schema types it TEXT,
    /// and the supervisor only ever uses it as a map key.
    pub run_id: Option<Sql>,
    pub pid: Option<i64>,
    pub run_status: Option<String>,
}

/// The columns each table must have before the join is asked for anything.
const TABLES: [(&str, [&str; 4]); 2] = [
    ("sandbox", ["id", "name", "config", "status"]),
    ("run", ["id", "sandbox_id", "pid", "status"]),
];

const QUERY: &str = "SELECT s.name, s.config, s.status, r.id AS run_id, r.pid, \
                     r.status AS run_status FROM sandbox s LEFT JOIN \"run\" r ON s.id=r.sandbox_id";

/// Why one read attempt failed. `NotYetInitialized` is an answer, not an error.
enum Attempt {
    Rows(Vec<CatalogRow>),
    NotYetInitialized,
    /// The database could not be read right now; try again inside the bound.
    Retry(String),
    /// A format the journal join depends on, which retrying cannot fix.
    Fatal(String),
}

/// The private catalog's rows, or `[]` when it has not been initialized yet.
pub fn catalog_rows(root: &Path) -> Result<Vec<CatalogRow>, String> {
    let database = root.join("db/msb.db");
    if !database.exists() {
        return Ok(Vec::new());
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match attempt(&database, deadline) {
            Attempt::Rows(rows) => return Ok(rows),
            Attempt::NotYetInitialized => return Ok(Vec::new()),
            Attempt::Fatal(error) => return Err(error),
            Attempt::Retry(error) => {
                if Instant::now() >= deadline {
                    return Err(format!("private catalog is unreadable: {error}"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn attempt(database: &Path, deadline: Instant) -> Attempt {
    let connection = match open(database) {
        Ok(connection) => connection,
        Err(error) => return Attempt::Retry(error),
    };
    // The Python interrupted a long query from its progress handler; the same
    // 100-op tick with the same deadline keeps a pathological query bounded.
    connection.progress_handler(100, Some(move || Instant::now() >= deadline));
    for (table, columns) in TABLES {
        match observed_columns(&connection, table) {
            Ok(observed) if observed.is_empty() => return Attempt::NotYetInitialized,
            Ok(observed) => {
                for column in columns {
                    if !observed.iter().any(|name| name == column) {
                        return Attempt::Fatal(format!("private catalog schema mismatch: {table}"));
                    }
                }
            }
            Err(error) => return Attempt::Retry(error),
        }
    }
    match rows(&connection) {
        Ok(rows) => Attempt::Rows(rows),
        Err(error) => Attempt::Retry(error),
    }
}

/// A read-only connection to the WAL database.
///
/// The Python used a `file:…?mode=ro` URI; `OpenFlags::SQLITE_OPEN_READ_ONLY`
/// is the same guarantee without a URI to build and percent-encode. The 200 ms
/// busy timeout is the Python's `timeout=0.2`.
fn open(database: &Path) -> Result<Connection, String> {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| error.to_string())?;
    connection
        .busy_timeout(Duration::from_millis(200))
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

/// `PRAGMA table_info("table")`'s column names, empty when the table is absent.
fn observed_columns(connection: &Connection, table: &str) -> Result<Vec<String>, String> {
    let sql = format!("PRAGMA table_info(\"{table}\")");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| error.to_string())?;
    let mut rows = statement.query([]).map_err(|error| error.to_string())?;
    let mut names = Vec::new();
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        // cid, name, type, notnull, dflt_value, pk
        names.push(row.get::<_, String>(1).map_err(|error| error.to_string())?);
    }
    Ok(names)
}

fn rows(connection: &Connection) -> Result<Vec<CatalogRow>, String> {
    let mut statement = connection
        .prepare(QUERY)
        .map_err(|error| error.to_string())?;
    let mut cursor = statement.query([]).map_err(|error| error.to_string())?;
    let mut collected = Vec::new();
    while let Some(row) = cursor.next().map_err(|error| error.to_string())? {
        collected.push(CatalogRow {
            name: row.get(0).map_err(|error| error.to_string())?,
            config: row.get(1).map_err(|error| error.to_string())?,
            status: row.get(2).map_err(|error| error.to_string())?,
            run_id: row
                .get::<_, Option<Sql>>(3)
                .map_err(|error| error.to_string())?,
            pid: row
                .get::<_, Option<i64>>(4)
                .map_err(|error| error.to_string())?,
            run_status: row
                .get::<_, Option<String>>(5)
                .map_err(|error| error.to_string())?,
        });
    }
    Ok(collected)
}

/// The run id as a string key, whatever SQLite's storage class turned out to be.
pub fn run_key(row: &CatalogRow) -> Option<String> {
    match row.run_id.as_ref()? {
        Sql::Integer(value) => Some(value.to_string()),
        Sql::Real(value) => Some(value.to_string()),
        Sql::Text(text) => Some(text.clone()),
        Sql::Blob(bytes) => Some(
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        ),
        Sql::Null => None,
    }
}

/// The row's `config` as JSON, which is where the effective deployment profile
/// lives. A malformed config is the launcher's finding, not this reader's, so it
/// is reported rather than guessed at.
pub fn config_profile(row: &CatalogRow) -> Option<String> {
    let config: Value = serde_json::from_str(&row.config).ok()?;
    config
        .get("spec")
        .and_then(|spec| spec.get("deployment_profile"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "harness-catalog-{label}-{}",
            crate::egress_fixtures::monotonic_nanos()
        ));
        std::fs::create_dir_all(path.join("db")).expect("a scratch database directory");
        path
    }

    /// Build a database the way the launcher's first migration would, with the
    /// writer connection closed before the read so nothing is held open.
    fn initialize(root: &Path, sandbox_config: &str) {
        let connection = Connection::open(root.join("db/msb.db")).expect("a writer");
        connection
            .execute_batch(
                "CREATE TABLE sandbox (id TEXT PRIMARY KEY, name TEXT, config TEXT, status TEXT);\
                 CREATE TABLE \"run\" (id TEXT PRIMARY KEY, sandbox_id TEXT, pid INTEGER, status TEXT);",
            )
            .expect("the launcher's tables");
        connection
            .execute(
                "INSERT INTO sandbox VALUES ('s1', 'agent-vm-abc-42', ?1, 'Running')",
                [sandbox_config],
            )
            .expect("a sandbox row");
        connection
            .execute(
                "INSERT INTO \"run\" VALUES ('r1', 's1', 4242, 'Running')",
                [],
            )
            .expect("a run row");
    }

    #[test]
    fn an_absent_database_is_an_empty_catalog() {
        let root = scratch("absent");
        assert_eq!(catalog_rows(&root).expect("absence is not an error"), []);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_table_is_not_yet_initialized_and_a_wrong_column_is_fatal() {
        let root = scratch("missing-table");
        // The file exists, its migrations have not committed a table yet (#449).
        Connection::open(root.join("db/msb.db")).expect("an empty database");
        assert_eq!(catalog_rows(&root).expect("not initialized"), []);
        let _ = std::fs::remove_dir_all(&root);

        // A table with the wrong columns is a format change, not absence.
        let root = scratch("wrong-columns");
        let connection = Connection::open(root.join("db/msb.db")).expect("a writer");
        connection
            .execute_batch("CREATE TABLE sandbox (id TEXT, name TEXT, config TEXT);")
            .expect("an outdated sandbox table");
        drop(connection);
        let error = catalog_rows(&root).expect_err("a schema mismatch must be surfaced");
        assert!(
            error.contains("private catalog schema mismatch: sandbox"),
            "{error}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_join_reads_the_fields_the_supervisor_needs() {
        let root = scratch("join");
        initialize(&root, r#"{"spec": {"deployment_profile": "multi-tenant"}}"#);
        let rows = catalog_rows(&root).expect("the catalog reads");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "agent-vm-abc-42");
        assert_eq!(rows[0].status, "Running");
        assert_eq!(run_key(&rows[0]).as_deref(), Some("r1"));
        assert_eq!(rows[0].pid, Some(4242));
        assert_eq!(rows[0].run_status.as_deref(), Some("Running"));
        assert_eq!(
            config_profile(&rows[0]).as_deref(),
            Some("multi-tenant"),
            "the effective profile comes from the row's config"
        );
        // A row's config the launcher writes is not this reader's business to fix.
        assert_eq!(
            config_profile(&CatalogRow {
                config: "not json".to_owned(),
                ..rows[0].clone()
            }),
            None
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_sandbox_without_a_run_row_still_appears() {
        let root = scratch("left-join");
        let connection = Connection::open(root.join("db/msb.db")).expect("a writer");
        connection
            .execute_batch(
                "CREATE TABLE sandbox (id TEXT PRIMARY KEY, name TEXT, config TEXT, status TEXT);\
                 CREATE TABLE \"run\" (id TEXT PRIMARY KEY, sandbox_id TEXT, pid INTEGER, status TEXT);\
                 INSERT INTO sandbox VALUES ('s1', 'agent-vm-abc-42', '{}', 'Stopped');",
            )
            .expect("the launcher's tables");
        drop(connection);
        let rows = catalog_rows(&root).expect("the catalog reads");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run_id, None);
        assert_eq!(rows[0].pid, None);
        assert_eq!(rows[0].run_status, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_reader_cannot_write_the_catalog_it_inspects() {
        let root = scratch("read-only");
        initialize(&root, "{}");
        // The same flags the reader uses, exercised directly: a fixture that
        // could write the catalog it polices would be able to fake its evidence.
        let connection = open(&root.join("db/msb.db")).expect("a read-only connection");
        let written = connection.execute("DELETE FROM sandbox", []);
        assert!(
            written.is_err(),
            "a read-only connection must refuse a write"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
