//! `agent-vm image …` — the image-cache verbs. Docker may be invoked; nothing
//! is selected or booted.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    cmd: ImageCmd,
}

#[derive(Subcommand)]
pub(crate) enum ImageCmd {
    /// Explicitly build a Dockerfile and import the result into agent-vm's image cache.
    Build(crate::image_build::Args),
    /// Import a finished image from the local Docker daemon or an archive into agent-vm's image cache.
    Import(crate::image_import::Args),
}

/// Input-only checks `main` runs before the MSB prologue. Only `import` has any.
pub(crate) fn preflight(args: &Args) -> Result<()> {
    match &args.cmd {
        ImageCmd::Build(_) => Ok(()),
        ImageCmd::Import(args) => crate::image_import::preflight(args),
    }
}

pub(crate) async fn run(args: Args) -> Result<i32> {
    match args.cmd {
        ImageCmd::Build(args) => crate::image_build::run(args).await,
        ImageCmd::Import(args) => crate::image_import::run(args).await,
    }
}
