//! `agent-vm image …` — inspect the selected boot image, or explicitly publish
//! a finished one into agent-vm's own image cache.
//!
//! `show` selects nothing new and boots nothing: it reports the image a launch
//! here would select, so it is dispatched before runtime discovery and setup
//! (see `main`). `build`/`import` are the explicit user-owned publication verbs
//! from ADR-0043; only they may invoke Docker. `import` additionally *observes*
//! the selection after publishing (#385) — it never changes it.

use anyhow::{Context as _, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use crate::config::ConfiguredImages;

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    cmd: ImageCmd,
}

impl Args {
    /// Whether this is the read-only inspection verb, which `main` dispatches
    /// before any MSB/runtime/cache work.
    pub(crate) fn is_show(&self) -> bool {
        matches!(self.cmd, ImageCmd::Show)
    }

    /// Post-parse validation of values clap accepts but a verb cannot act on:
    /// currently only import's result reference, which may be inferred from
    /// `--docker` and must be refused before any state exists. Input-only — no
    /// file is stat'ed and no configuration is resolved here.
    pub(crate) fn validate_result_reference(&self) -> Result<()> {
        match &self.cmd {
            ImageCmd::Import(args) => args.result_reference().map(|_| ()),
            ImageCmd::Show | ImageCmd::Build(_) => Ok(()),
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum ImageCmd {
    /// Print the boot image a launch in this project would select, and where
    /// that selection came from.
    ///
    /// Reports the full reference and its provenance without a --image
    /// override. Read-only and offline: no cached image, Docker, msb, registry
    /// or runtime is consulted, and nothing is built, imported or booted.
    Show,
    /// Explicitly build a Dockerfile and import the result into agent-vm's image cache.
    Build(crate::image_build::Args),
    /// Import a finished image from the local Docker daemon or an archive into agent-vm's image cache.
    Import(crate::image_import::Args),
}

/// Input-only checks `main` runs before the MSB prologue. Only `import` has any.
pub(crate) fn preflight(args: &Args) -> Result<()> {
    match &args.cmd {
        ImageCmd::Show => Ok(()),
        ImageCmd::Build(_) => Ok(()),
        ImageCmd::Import(args) => crate::image_import::preflight(args),
    }
}

/// Write the selected boot-image inspection report to stdout.
///
/// Selection happens before this call so a failure produces no stdout at all;
/// the report is written in one `write_all` for the same reason, and the
/// reference is never logged.
pub(crate) fn show(configured: &ConfiguredImages) -> Result<()> {
    use std::io::Write as _;
    let report = crate::boot_image::inspect_selection(configured)?;
    std::io::stdout()
        .lock()
        .write_all(report.as_bytes())
        .context("writing selected boot-image inspection")
}

pub(crate) async fn run(args: Args, configured: Result<&ConfiguredImages>) -> Result<i32> {
    match args.cmd {
        // `main` routes `show` before the runtime exists; reaching here means
        // the early dispatch was bypassed, which is a wiring error, not input.
        ImageCmd::Show => bail!("image show must be dispatched before runtime setup"),
        ImageCmd::Build(args) => crate::image_build::run(args).await,
        ImageCmd::Import(args) => crate::image_import::run(args, configured).await,
    }
}
