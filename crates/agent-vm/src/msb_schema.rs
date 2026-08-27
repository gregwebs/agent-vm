//! Identifier for the schema version the bundled (vendored)
//! microsandbox understands.
//!
//! Derived from the compiled-in sea-orm migration set
//! rather than a hand-maintained constant, so it can never drift
//! from the migrations it names. It is the highest migration id,
//! e.g. m20260824_000001.
//!
//! Used by `msb_preflight`'s ahead-of-bundle guard to compare against an
//! on-disk database, and named in that guard's block message so a user
//! (or an agent debugging across worktrees) can see which schema this
//! particular build expects.

use microsandbox_migration::{Migrator, MigratorTrait};

pub fn bundled_schema_version() -> String {
    Migrator::get_migration_files()
        .iter()
        .map(|m| schema_id(m.name()).to_string())
        .max()
        .expect("bundled microsandbox migration set must be non-empty")
}

/// Report that the on-disk DB carries migrations the bundled Migrator
/// lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbAheadOfBundle {
    /// Applied migration names present in the DB but absent from the
    /// bundled migration set, sorted ascending. Non-empty by
    /// construction.
    pub extra_migrations: Vec<String>,
}

/// Compare the DB's applied `seaql_migrations` names against the
/// bundled `Migrator`'s known migration names. `Some(report)` iff the
/// DB is ahead (carries at least one migration the bundle does not
/// know).
///
/// Pure: callers pass the already-read applied names, so #31 can reuse
/// this for its legacy-adoption check without any DB access. Compares
/// full `.name()` strings (not the `m<date>_<seq>` id) to match
/// sea-orm's own set difference exactly, so this fires in precisely
/// the cases that would otherwise crash.
pub fn db_ahead_of_bundle(applied_versions: &[String]) -> Option<DbAheadOfBundle> {
    let bundled: std::collections::HashSet<String> = Migrator::get_migration_files()
        .iter()
        .map(|m| m.name().to_string())
        .collect();
    let mut extra: Vec<String> = applied_versions
        .iter()
        .filter(|v| !bundled.contains(*v))
        .cloned()
        .collect();
    extra.sort();
    extra.dedup();
    if extra.is_empty() {
        None
    } else {
        Some(DbAheadOfBundle {
            extra_migrations: extra,
        })
    }
}

/// Extract the schema-id prefix (m<date>_<seq>) from a full migration
/// name like m20260824_000001_mount_owner_config giving m20260824_000001.
/// The id is the first two underscore-delimited fields. If a name
/// somehow has fewer than two underscores, the whole name is returned.
fn schema_id(name: &str) -> &str {
    match name.match_indices("_").nth(1) {
        Some((idx, _)) => &name[..idx],
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_is_max_of_registered_migration_set() {
        let ids: Vec<String> = Migrator::get_migration_files()
            .iter()
            .map(|m| schema_id(m.name()).to_string())
            .collect();
        assert!(!ids.is_empty(), "vendored migration set is empty");
        let expected = ids.iter().max().unwrap();
        assert_eq!(&bundled_schema_version(), expected);
    }

    #[test]
    fn identifier_matches_pinned_bundled_schema() {
        assert_eq!(
            bundled_schema_version(),
            "m20260824_000001",
            "bundled microsandbox schema id changed; if intended, \
             update this pinned value (see #31 for MSB_HOME namespacing)"
        );
    }

    #[test]
    fn schema_id_extracts_date_seq_prefix() {
        assert_eq!(
            schema_id("m20260824_000001_mount_owner_config"),
            "m20260824_000001"
        );
        assert_eq!(
            schema_id("m20260305_000001_create_image_tables"),
            "m20260305_000001"
        );
        assert_eq!(schema_id("m20260606"), "m20260606");
    }

    #[test]
    fn schema_id_ignores_underscores_in_description() {
        // The extraction takes the first two underscore-delimited fields
        // regardless of how many underscores follow in the description, so
        // a hypothetical next migration whose description itself contains
        // underscores (e.g. m20260606_000002_add_foo_bar_baz) still yields
        // a clean id distinct from today's pinned m20260824_000001.
        assert_eq!(
            schema_id("m20260606_000002_add_foo_bar_baz"),
            "m20260606_000002"
        );
    }

    #[test]
    fn max_over_empty_ids_panics_with_expected_message() {
        // Mirrors bundled_schema_version()'s max().expect(..) pattern
        // against an empty set, matching the panic documented in the
        // implementation plan's failure-mode section, without touching the
        // real vendored migration set (which is never empty at build time).
        let empty: Vec<String> = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            empty
                .iter()
                .cloned()
                .max()
                .expect("bundled microsandbox migration set must be non-empty")
        }));
        let payload = result.expect_err("expected a panic on an empty migration set");
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        assert!(
            msg.contains("must be non-empty"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn db_ahead_of_bundle_is_none_for_empty_input() {
        assert_eq!(db_ahead_of_bundle(&[]), None);
    }

    #[test]
    fn db_ahead_of_bundle_is_none_when_applied_is_subset_of_bundled() {
        let applied = vec!["m20260305_000001_create_image_tables".to_string()];
        assert_eq!(db_ahead_of_bundle(&applied), None);
    }

    #[test]
    fn db_ahead_of_bundle_reports_unknown_future_migration() {
        let applied = vec![
            "m20260305_000001_create_image_tables".to_string(),
            "m29990101_000001_future_thing".to_string(),
        ];
        assert_eq!(
            db_ahead_of_bundle(&applied),
            Some(DbAheadOfBundle {
                extra_migrations: vec!["m29990101_000001_future_thing".to_string()],
            })
        );
    }

    #[test]
    fn db_ahead_of_bundle_sorts_and_dedups_multiple_extras() {
        let applied = vec![
            "m29990101_000002_future_two".to_string(),
            "m29990101_000001_future_one".to_string(),
            "m29990101_000001_future_one".to_string(),
        ];
        assert_eq!(
            db_ahead_of_bundle(&applied),
            Some(DbAheadOfBundle {
                extra_migrations: vec![
                    "m29990101_000001_future_one".to_string(),
                    "m29990101_000002_future_two".to_string(),
                ],
            })
        );
    }

    #[test]
    fn db_ahead_of_bundle_full_bundled_set_is_not_ahead_of_itself() {
        let applied: Vec<String> = Migrator::get_migration_files()
            .iter()
            .map(|m| m.name().to_string())
            .collect();
        assert_eq!(db_ahead_of_bundle(&applied), None);
    }

    #[test]
    fn all_migration_ids_are_well_formed() {
        for m in Migrator::get_migration_files() {
            let id = schema_id(m.name());
            let rest = id.strip_prefix("m").expect("id starts with m");
            let parts: Vec<&str> = rest.splitn(2, "_").collect();
            assert_eq!(parts.len(), 2, "id has date and seq fields");
            assert_eq!(parts[0].len(), 8, "date field is 8 digits");
            assert_eq!(parts[1].len(), 6, "seq field is 6 digits");
            assert!(parts[0].bytes().all(|b| b.is_ascii_digit()));
            assert!(parts[1].bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
