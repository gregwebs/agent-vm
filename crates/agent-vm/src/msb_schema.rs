//! Identifier for the schema version the bundled (vendored)
//! microsandbox understands.
//!
//! Derived from the compiled-in sea-orm migration set
//! rather than a hand-maintained constant, so it can never drift
//! from the migrations it names. It is the highest migration id,
//! e.g. m20260606_000001.
//!
//! No runtime behavior depends on this yet. It exists so #31 can
//! version-namespace the private MSB_HOME and so a schema-compat
//! preflight can compare it against an on-disk database.

use microsandbox_migration::{Migrator, MigratorTrait};

// Not yet called from any command/boot path (see #31, which will consume
// this to version-namespace MSB_HOME). Exposed now as a prefactor per #29.
#[allow(dead_code)]
pub fn bundled_schema_version() -> String {
    Migrator::get_migration_files()
        .iter()
        .map(|m| schema_id(m.name()).to_string())
        .max()
        .expect("bundled microsandbox migration set must be non-empty")
}

/// Extract the schema-id prefix (m<date>_<seq>) from a full migration
/// name like m20260606_000001_named_volume_kinds giving m20260606_000001.
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
            "m20260606_000001",
            "bundled microsandbox schema id changed; if intended, \
             update this pinned value (see #31 for MSB_HOME namespacing)"
        );
    }

    #[test]
    fn schema_id_extracts_date_seq_prefix() {
        assert_eq!(
            schema_id("m20260606_000001_named_volume_kinds"),
            "m20260606_000001"
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
        // a clean id distinct from today's pinned m20260606_000001.
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
