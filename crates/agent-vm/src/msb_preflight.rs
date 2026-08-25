//! Fail-fast guard for a forward-migrated private `msb.db`.
//!
//! Inspection is shared with legacy-home adoption. This caller only blocks a
//! confirmed newer database; unreadable metadata must not turn a transient IO
//! failure into a permanent startup failure.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

fn private_db_path() -> Result<PathBuf> {
    Ok(crate::msb_install::msb_home_dir()?
        .join("db")
        .join("msb.db"))
}

fn ahead_message(report: &crate::msb_schema::DbAheadOfBundle, db_path: &Path) -> String {
    format!(
        "agent-vm private microsandbox database is NEWER than this build of agent-vm.\n\
         A newer microsandbox forward-migrated {}\n\
         with migration(s) this build does not have: {}\n\
         The bundled msb cannot open a forward-migrated database (migrations are one-way).\n\
         Recover with:\n\n    agent-vm doctor --reset-msb-db\n\n\
         That moves the database aside (nothing is deleted) so the next run recreates it\n\
         at this build's schema. Or upgrade agent-vm to a build with the newer microsandbox.",
        db_path.display(),
        report.extra_migrations.join(", "),
    )
}

async fn ensure_db_path_not_ahead(db_path: &Path) -> Result<()> {
    match crate::msb_db::inspect_schema(db_path).await {
        crate::msb_db::SchemaCompatibility::Compatible => Ok(()),
        crate::msb_db::SchemaCompatibility::Ahead(report) => {
            bail!("{}", ahead_message(&report, db_path))
        }
        crate::msb_db::SchemaCompatibility::Unreadable { error } => {
            tracing::debug!(db_path = %db_path.display(), error = %error, "could not inspect msb database during preflight; proceeding");
            Ok(())
        }
    }
}

pub async fn ensure_db_not_ahead() -> Result<()> {
    ensure_db_path_not_ahead(&private_db_path()?).await
}

pub fn ensure_db_not_ahead_blocking() -> Result<()> {
    let db_path = private_db_path()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime for msb.db preflight")?;
    rt.block_on(ensure_db_path_not_ahead(&db_path))
}
