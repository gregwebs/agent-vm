//! Group A integration tests for issue #42 ("Migrate existing Microsandbox
//! state safely"): prove the vendored forward migration from the 0.5.7
//! schema (an exact 11-migration prefix of v0.6.15's 24) to the bundled
//! v0.6.15 head is safe, idempotent across repeated restarts, and preserves
//! representative image/sandbox/volume/snapshot state (AC 1-3, 6).
//!
//! Drives `microsandbox_migration::Migrator::up` directly against a
//! temp-file SQLite DB. That is the exact call the SDK's boot path makes
//! (`connect_and_migrate`, vendor/microsandbox/sdk/rust/lib/backend/local/mod.rs:692)
//! -- but it is NOT the full boot gate: `connect_and_migrate` runs
//! `refuse_schema_ahead` -> `schema_metadata::canonical_applied_prefix`
//! (mod.rs:691) *before* `Migrator::up`, and that set-based prefix check is
//! the real arbiter of whether a behind 0.5.7 DB is even allowed to
//! forward-migrate. The `canonical_applied_prefix_*` tests below exercise
//! that gate directly, so a green `Migrator::up` test here cannot mask a
//! red production boot.
//!
//! AC-6 (tests never touch the user's real state): every DB here lives
//! under a fresh `tempfile::tempdir()`, and this file never calls
//! `msb_install::msb_home_dir()` or reads `MSB_HOME`/`AGENT_VM_STATE_DIR`.

use std::path::Path;

use microsandbox_migration::{Migrator, MigratorTrait, schema_metadata};
use sea_orm_migration::sea_orm::{
    ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, ExecResult, Statement, Value,
};

/// The exact 11 migration ids that shipped in the 0.5.7 release (commit
/// `4dbb712b`), name-identical to and an exact prefix of the vendored
/// v0.6.15 `Migrator`'s 24 (`crates/migration/lib/lib.rs`). Hand-pinned
/// (mirroring `msb_schema.rs`'s pinned-literal-with-drift-guard style) so a
/// future re-ordering or insertion ahead of this prefix in the vendored
/// migration set is caught by `migration_ids_0_5_7_matches_the_bundled_prefix`
/// below, rather than silently changing what `up(Some(11))` builds.
const MIGRATION_IDS_0_5_7: [&str; 11] = [
    "m20260305_000001_create_image_tables",
    "m20260305_000002_create_sandbox_tables",
    "m20260305_000003_create_storage_tables",
    "m20260305_000004_create_sandbox_images_table",
    "m20260410_000001_erofs_image_schema",
    "m20260501_000001_create_snapshot_index",
    "m20260517_000001_drop_sandbox_metric",
    "m20260527_000001_migrate_oci_rootfs_source",
    "m20260531_000001_create_sandbox_labels",
    "m20260531_000002_index_sandbox_labels_key_value",
    "m20260606_000001_named_volume_kinds",
];

const IMAGE_REFERENCE: &str = "docker.io/library/ubuntu:22.04";
const MANIFEST_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LAYER_DIFF_ID: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const LAYER_BLOB_DIGEST: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SNAPSHOT_DIGEST: &str =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const A_TIMESTAMP: &str = "2026-06-01 00:00:00";

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

async fn connect_temp_db(db_path: &Path) -> DatabaseConnection {
    let url = format!("sqlite://{}?mode=rwc", db_path.display());
    Database::connect(&url)
        .await
        .expect("connect to temp sqlite db")
}

/// Applied `seaql_migrations` versions, deterministically ordered so
/// consecutive calls can be compared directly for "unchanged since last
/// restart" assertions.
async fn applied_versions(conn: &DatabaseConnection) -> Vec<String> {
    let rows = conn
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT version FROM seaql_migrations ORDER BY version".to_owned(),
        ))
        .await
        .expect("read seaql_migrations");
    rows.into_iter()
        .map(|r| r.try_get_by_index::<String>(0).expect("version column"))
        .collect()
}

fn bundled_migration_names() -> std::collections::HashSet<String> {
    Migrator::get_migration_files()
        .iter()
        .map(|m| m.name().to_string())
        .collect()
}

async fn exec(conn: &DatabaseConnection, sql: &str, values: Vec<Value>) -> ExecResult {
    conn.execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        sql,
        values,
    ))
    .await
    .unwrap_or_else(|e| panic!("seed fixture: {sql}: {e}"))
}

async fn sandbox_config_json(conn: &DatabaseConnection, name: &str) -> serde_json::Value {
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT config FROM sandbox WHERE name = ?",
            vec![name.into()],
        ))
        .await
        .expect("query sandbox config")
        .unwrap_or_else(|| panic!("sandbox {name:?} must survive the upgrade"));
    let config: String = row.try_get_by_index(0).expect("config column");
    serde_json::from_str(&config).expect("sandbox config must remain valid JSON")
}

async fn read_all_sandbox_configs(conn: &DatabaseConnection) -> Vec<(String, String)> {
    let rows = conn
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name, config FROM sandbox ORDER BY name".to_owned(),
        ))
        .await
        .expect("read sandbox configs");
    rows.into_iter()
        .map(|r| {
            (
                r.try_get_by_index::<String>(0).expect("name column"),
                r.try_get_by_index::<String>(1).expect("config column"),
            )
        })
        .collect()
}

/// Row identities the post-migration assertions need to look up by id
/// rather than by a stable natural key (digest/name).
struct Fixture {
    manifest_digest: String,
    web_oci_sandbox_id: i32,
}

/// Seed one representative row per family (image catalog, two sandboxes,
/// a named volume + attachment, a snapshot) directly against the
/// post-`up(Some(11))` schema, in the REAL 0.5.7 value shapes the three
/// `affects_user_data` migrations (`m20260708_000001_migrate_bind_rootfs_source`,
/// `m20260710_000001_migrate_root_disk`,
/// `m20260723_000001_snapshot_artifact_transition`) actually consume --
/// not a minimal-to-satisfy-constraints shape, which those migrations'
/// `up()`s would silently skip, leaving AC-3 vacuously green (see the
/// implementation plan's reviewer-fold note).
///
/// `image`/`index`/`sandbox_image` (the tables migration #1/#4 created) no
/// longer exist by this point: migration #5
/// (`m20260410_000001_erofs_image_schema`, itself part of the 0.5.7 prefix)
/// already dropped and replaced them with the EROFS-era
/// `manifest`/`image_ref`/`config`/`layer`/`manifest_layer`/`sandbox_rootfs`
/// tables this function seeds instead -- that IS the true 0.5.7 image
/// catalog shape, since a real 0.5.7 release already carries migration #5.
async fn seed_representative_0_5_7_rows(conn: &DatabaseConnection) -> Fixture {
    // -- image catalog: one pulled OCI image (manifest/image_ref/config/layer) --
    let manifest_id = exec(
        conn,
        "INSERT INTO manifest (digest, media_type, config_digest, architecture, os, layer_count, total_size_bytes, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            MANIFEST_DIGEST.into(),
            "application/vnd.oci.image.manifest.v1+json".into(),
            CONFIG_DIGEST.into(),
            "amd64".into(),
            "linux".into(),
            1i32.into(),
            30_000_000i64.into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await
    .last_insert_id() as i32;

    exec(
        conn,
        "INSERT INTO image_ref (reference, manifest_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
        vec![
            IMAGE_REFERENCE.into(),
            manifest_id.into(),
            A_TIMESTAMP.into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await;

    exec(
        conn,
        "INSERT INTO config (manifest_id, digest, env, cmd, working_dir, user, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        vec![
            manifest_id.into(),
            CONFIG_DIGEST.into(),
            r#"["PATH=/usr/bin"]"#.into(),
            r#"["/bin/bash"]"#.into(),
            "/root".into(),
            "root".into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await;

    let layer_id = exec(
        conn,
        "INSERT INTO layer (diff_id, blob_digest, media_type, compressed_size_bytes, erofs_size_bytes, created_at, last_used_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        vec![
            LAYER_DIFF_ID.into(),
            LAYER_BLOB_DIGEST.into(),
            "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            15_000_000i64.into(),
            30_000_000i64.into(),
            A_TIMESTAMP.into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await
    .last_insert_id() as i32;

    exec(
        conn,
        "INSERT INTO manifest_layer (manifest_id, layer_id, position) VALUES (?, ?, ?)",
        vec![manifest_id.into(), layer_id.into(), 0i32.into()],
    )
    .await;

    // -- sandbox exercising m20260710_000001_migrate_root_disk: the real
    // 0.5.7 shape is `image.Oci.upper_size_mib` (the OUTPUT shape of
    // m20260527_000001_migrate_oci_rootfs_source, which has already run as
    // part of up(Some(11)) -- this fixture row is inserted post-hoc, so it
    // must already be in that migration's output shape, not its input).
    let web_oci_config = format!(
        r#"{{"name":"web-oci","image":{{"Oci":{{"reference":"{IMAGE_REFERENCE}","upper_size_mib":4096}}}}}}"#
    );
    let web_oci_id = exec(
        conn,
        "INSERT INTO sandbox (name, config, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        vec![
            "web-oci".into(),
            web_oci_config.into(),
            "stopped".into(),
            A_TIMESTAMP.into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await
    .last_insert_id() as i32;

    exec(
        conn,
        "INSERT INTO sandbox_rootfs (sandbox_id, manifest_id, mode, upper_fstype, created_at) \
         VALUES (?, ?, ?, ?, ?)",
        vec![
            web_oci_id.into(),
            manifest_id.into(),
            "oci".into(),
            "ext4".into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await;

    // -- sandbox exercising m20260708_000001_migrate_bind_rootfs_source:
    // the real 0.5.7 shape is a bare `image.bind` string -- no 0.5.7-vintage
    // migration ever touches it (the {path, follow_root_symlinks} object
    // shape is a v0.6 addition).
    exec(
        conn,
        "INSERT INTO sandbox (name, config, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        vec![
            "web-bind".into(),
            r#"{"name":"web-bind","image":{"bind":"/srv/rootfs"}}"#.into(),
            "stopped".into(),
            A_TIMESTAMP.into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await;

    // -- named volume + attachment: already at its final 0.5.7 shape as of
    // migration #11 (m20260606_000001_named_volume_kinds); no migration
    // after the prefix touches `volume`/`volume_attach` at all.
    let volume_id = exec(
        conn,
        "INSERT INTO volume (name, quota_mib, kind, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        vec![
            "data".into(),
            1024i32.into(),
            "dir".into(),
            A_TIMESTAMP.into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await
    .last_insert_id() as i32;

    exec(
        conn,
        "INSERT INTO volume_attach (volume_id, sandbox_id, pid, mode, created_at) VALUES (?, ?, ?, ?, ?)",
        vec![
            volume_id.into(),
            web_oci_id.into(),
            12345i32.into(),
            "rw".into(),
            A_TIMESTAMP.into(),
        ],
    )
    .await;

    // -- snapshot exercising m20260723_000001_snapshot_artifact_transition:
    // the pre-transition `snapshot_index` descriptor shape (no `scope`
    // column yet -- that is itself added by a later forward migration,
    // m20260714_000001_add_snapshot_scope, before the transition runs).
    exec(
        conn,
        "INSERT INTO snapshot_index (digest, name, parent_digest, image_ref, image_manifest_digest, format, fstype, artifact_path, size_bytes, created_at, indexed_at, child_count) \
         VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            SNAPSHOT_DIGEST.into(),
            "web-oci-base".into(),
            IMAGE_REFERENCE.into(),
            MANIFEST_DIGEST.into(),
            "raw".into(),
            "ext4".into(),
            "/snapshots/web-oci-base/upper.ext4".into(),
            5_000_000i64.into(),
            A_TIMESTAMP.into(),
            A_TIMESTAMP.into(),
            0i32.into(),
        ],
    )
    .await;

    Fixture {
        manifest_digest: MANIFEST_DIGEST.to_string(),
        web_oci_sandbox_id: web_oci_id,
    }
}

/// Build a temp DB at the pinned 0.5.7 schema, seed representative rows,
/// then run the forward migration under test once. Shared by the tests
/// below so each only has to state its own assertions.
async fn upgraded_seeded_db(db_path: &Path) -> (DatabaseConnection, Fixture) {
    let conn = connect_temp_db(db_path).await;

    Migrator::up(&conn, Some(MIGRATION_IDS_0_5_7.len() as u32))
        .await
        .expect("build the 0.5.7 schema (up(Some(11)))");
    let after_11: std::collections::HashSet<String> =
        applied_versions(&conn).await.into_iter().collect();
    assert_eq!(
        after_11,
        MIGRATION_IDS_0_5_7.iter().map(|s| s.to_string()).collect(),
        "up(Some(11)) must build exactly the pinned 0.5.7 migration set -- a drift here \
         means the vendored Migrator was re-ordered ahead of the 0.5.7 prefix, and this \
         fixture no longer represents a real 0.5.7 database"
    );

    let fixture = seed_representative_0_5_7_rows(&conn).await;

    Migrator::up(&conn, None)
        .await
        .expect("forward-migrate 0.5.7 -> the bundled v0.6.15 head");

    (conn, fixture)
}

// --------------------------------------------------------------------------
// AC-1 / AC-6: a copy of representative 0.5.7 state migrates successfully once
// --------------------------------------------------------------------------

#[tokio::test]
async fn fresh_0_5_7_db_forward_migrates_once_to_bundled_head() {
    // AC-6: the db lives under a fresh tempdir for the duration of this
    // process and is never derived from msb_install::msb_home_dir() /
    // MSB_HOME -- see this file's module doc comment.
    let dir = tempfile::tempdir().unwrap();
    let (conn, _fixture) = upgraded_seeded_db(&dir.path().join("msb.db")).await;

    let applied: std::collections::HashSet<String> =
        applied_versions(&conn).await.into_iter().collect();
    assert_eq!(
        applied.len(),
        24,
        "AC-1: exactly the bundled 24 migrations must be applied after one upgrade"
    );
    assert_eq!(
        applied,
        bundled_migration_names(),
        "AC-1: the applied set must equal the vendored Migrator's full migration set"
    );
}

// --------------------------------------------------------------------------
// AC-2: two subsequent restarts perform no destructive or duplicate migration
// --------------------------------------------------------------------------

#[tokio::test]
async fn repeated_restarts_are_noops() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, _fixture) = upgraded_seeded_db(&dir.path().join("msb.db")).await;

    let after_first_upgrade = applied_versions(&conn).await;
    assert_eq!(after_first_upgrade.len(), 24);
    let sandboxes_after_first_upgrade = read_all_sandbox_configs(&conn).await;

    for restart in 2..=3 {
        Migrator::up(&conn, None).await.unwrap_or_else(|e| {
            panic!("restart {restart}: up(None) must be a no-op on an in-sync db, got {e}")
        });

        let applied_now = applied_versions(&conn).await;
        assert_eq!(
            applied_now.len(),
            24,
            "restart {restart}: AC-2 -- no destructive or duplicate migration"
        );
        assert_eq!(
            applied_now, after_first_upgrade,
            "restart {restart}: AC-2 -- applied migration set must not change"
        );
        assert_eq!(
            read_all_sandbox_configs(&conn).await,
            sandboxes_after_first_upgrade,
            "restart {restart}: representative rows must not be re-transformed on a no-op restart"
        );
    }
}

// --------------------------------------------------------------------------
// AC-3: images, sandbox records, snapshots, and volumes remain usable
// --------------------------------------------------------------------------

#[tokio::test]
async fn representative_state_survives_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, fixture) = upgraded_seeded_db(&dir.path().join("msb.db")).await;

    // Images: the erofs-era catalog rows (see seed_representative_0_5_7_rows)
    // are untouched by any of the 13 forward migrations and must still be
    // present, joined, and readable.
    let manifest_row = conn
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT r.reference, l.diff_id FROM manifest m \
             JOIN image_ref r ON r.manifest_id = m.id \
             JOIN manifest_layer ml ON ml.manifest_id = m.id \
             JOIN layer l ON l.id = ml.layer_id \
             WHERE m.digest = ?",
            vec![fixture.manifest_digest.clone().into()],
        ))
        .await
        .expect("query image catalog")
        .expect("AC-3: image catalog rows (manifest/image_ref/layer) must survive the upgrade");
    assert_eq!(
        manifest_row.try_get_by_index::<String>(0).unwrap(),
        IMAGE_REFERENCE
    );
    assert_eq!(
        manifest_row.try_get_by_index::<String>(1).unwrap(),
        LAYER_DIFF_ID
    );

    // sandbox_rootfs: the root_disk_kind column added post-hoc by
    // m20260710_000001_migrate_root_disk must have landed on the existing
    // row via its column default, not left the row missing the data.
    let root_disk_kind = conn
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT root_disk_kind FROM sandbox_rootfs WHERE sandbox_id = ?",
            vec![fixture.web_oci_sandbox_id.into()],
        ))
        .await
        .expect("query sandbox_rootfs")
        .expect("sandbox_rootfs row must survive the upgrade")
        .try_get_by_index::<String>(0)
        .unwrap();
    assert_eq!(root_disk_kind, "managed");

    // m20260710_000001_migrate_root_disk: the real 0.5.7
    // `image.Oci.upper_size_mib` must have been rewritten to the structured
    // `root_disk` shape -- the ACTUAL post-transform result, not merely
    // "row still present" (the vacuous-AC-3 risk the plan's reviewer fold
    // calls out).
    let web_oci_config = sandbox_config_json(&conn, "web-oci").await;
    assert_eq!(web_oci_config["image"]["Oci"]["reference"], IMAGE_REFERENCE);
    assert_eq!(
        web_oci_config["image"]["Oci"]["root_disk"]["kind"],
        "managed"
    );
    assert_eq!(
        web_oci_config["image"]["Oci"]["root_disk"]["size_mib"],
        4096
    );
    assert!(
        web_oci_config["image"]["Oci"]
            .get("upper_size_mib")
            .is_none(),
        "legacy upper_size_mib must be gone after the transform, not merely accompanied by root_disk: {web_oci_config}"
    );

    // m20260708_000001_migrate_bind_rootfs_source: the real 0.5.7 bare
    // `image.bind` string must have been rewritten to the
    // {path, follow_root_symlinks} object shape.
    let web_bind_config = sandbox_config_json(&conn, "web-bind").await;
    assert_eq!(web_bind_config["image"]["bind"]["path"], "/srv/rootfs");
    assert_eq!(
        web_bind_config["image"]["bind"]["follow_root_symlinks"],
        false
    );

    // Volume + attachment: no forward migration touches `volume`/
    // `volume_attach` after the 0.5.7 prefix; both must be exactly unchanged.
    let volume_row = conn
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT kind, quota_mib FROM volume WHERE name = 'data'".to_owned(),
        ))
        .await
        .expect("query volume")
        .expect("volume row must survive the upgrade");
    assert_eq!(volume_row.try_get_by_index::<String>(0).unwrap(), "dir");
    assert_eq!(volume_row.try_get_by_index::<i32>(1).unwrap(), 1024);

    let attach_count = conn
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) FROM volume_attach".to_owned(),
        ))
        .await
        .expect("count volume_attach")
        .expect("count query always returns a row")
        .try_get_by_index::<i64>(0)
        .unwrap();
    assert_eq!(
        attach_count, 1,
        "volume attachment must survive the upgrade"
    );

    // m20260723_000001_snapshot_artifact_transition: the pre-transition
    // snapshot_index descriptor must have been projected into the new
    // schema-1 shape -- checking the POST-transform columns the migration
    // actually writes (state_kind/locality/availability/migration_state),
    // not merely that the row still exists.
    let snapshot_row = conn
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT name, scope, state_kind, locality, availability, migration_state, \
                    checkpoint_manifest_digest, artifact_path, image_ref, size_bytes, child_count \
             FROM snapshot_index WHERE digest = ?",
            vec![SNAPSHOT_DIGEST.into()],
        ))
        .await
        .expect("query snapshot_index")
        .expect("AC-3: snapshot row must survive the upgrade");
    assert_eq!(
        snapshot_row.try_get_by_index::<String>(0).unwrap(),
        "web-oci-base"
    );
    assert_eq!(snapshot_row.try_get_by_index::<String>(1).unwrap(), "disk");
    assert_eq!(snapshot_row.try_get_by_index::<String>(2).unwrap(), "file");
    assert_eq!(
        snapshot_row.try_get_by_index::<String>(3).unwrap(),
        "embedded"
    );
    assert_eq!(snapshot_row.try_get_by_index::<String>(4).unwrap(), "ready");
    assert_eq!(
        snapshot_row.try_get_by_index::<String>(5).unwrap(),
        "canonical"
    );
    assert_eq!(
        snapshot_row.try_get_by_index::<Option<String>>(6).unwrap(),
        None,
        "no checkpoint has been taken; checkpoint_manifest_digest must stay NULL"
    );
    assert_eq!(
        snapshot_row.try_get_by_index::<String>(7).unwrap(),
        "/snapshots/web-oci-base/upper.ext4"
    );
    assert_eq!(
        snapshot_row.try_get_by_index::<String>(8).unwrap(),
        IMAGE_REFERENCE
    );
    assert_eq!(snapshot_row.try_get_by_index::<i64>(9).unwrap(), 5_000_000);
    assert_eq!(snapshot_row.try_get_by_index::<i32>(10).unwrap(), 0);
}

// --------------------------------------------------------------------------
// Reviewer fold: the real boot-time acceptance gate is
// `canonical_applied_prefix`, not `Migrator::up` -- exercise it directly.
// --------------------------------------------------------------------------

#[test]
fn migration_ids_0_5_7_matches_the_bundled_prefix() {
    let bundled_prefix: Vec<String> = schema_metadata::migration_ids()
        .take(MIGRATION_IDS_0_5_7.len())
        .map(str::to_string)
        .collect();
    assert_eq!(
        bundled_prefix,
        MIGRATION_IDS_0_5_7.to_vec(),
        "the pinned 0.5.7 id list must equal the bundled Migrator's first 11 ids"
    );
}

#[test]
fn canonical_applied_prefix_accepts_the_0_5_7_prefix_and_every_leading_subset() {
    // `connect_and_migrate` runs `refuse_schema_ahead` ->
    // `canonical_applied_prefix` BEFORE `Migrator::up`
    // (vendor/microsandbox/sdk/rust/lib/backend/local/mod.rs:691-692). A
    // green `Migrator::up` test elsewhere in this file cannot prove a
    // behind 0.5.7 db is even allowed to reach `up()` in production -- this
    // proves it directly against the same pure function the SDK calls.
    for len in 0..=MIGRATION_IDS_0_5_7.len() {
        let applied = &MIGRATION_IDS_0_5_7[..len];
        let prefix = schema_metadata::canonical_applied_prefix(applied.iter().copied());
        assert!(
            prefix.is_some(),
            "a {len}-migration leading subset of the 0.5.7 set must be accepted as a valid prefix"
        );
        assert_eq!(prefix.unwrap().len(), len);
    }
}

#[test]
fn canonical_applied_prefix_rejects_a_0_5_7_db_carrying_an_unknown_migration() {
    let mut applied: Vec<&str> = MIGRATION_IDS_0_5_7.to_vec();
    applied.push("m29990101_000001_future_thing");
    assert!(
        schema_metadata::canonical_applied_prefix(applied).is_none(),
        "an unknown (ahead) migration id must never be accepted as part of a valid prefix"
    );
}
