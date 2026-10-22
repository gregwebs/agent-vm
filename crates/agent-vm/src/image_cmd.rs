//! `agent-vm image …` — inspect the selected boot image, acquire the selected
//! OCI reference, explicitly retain a default, or publish a finished image into
//! agent-vm's own image cache.
//!
//! `show` selects nothing new and boots nothing: it reports the image a launch
//! here would select, so it is dispatched before runtime discovery and setup
//! (see `main`). `refresh` acquires bytes natively and never boots. `build`/
//! `import` are the explicit user-owned publication verbs from ADR-0043; only
//! they may invoke Docker. `import` additionally *observes* the selection after
//! publishing (#385) — it never changes it.

use anyhow::{Context as _, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use crate::config::{Catalog, ConfiguredImages};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) cmd: ImageCmd,
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
            ImageCmd::Show
            | ImageCmd::Build(_)
            | ImageCmd::Refresh(_)
            | ImageCmd::SetDefault(_) => Ok(()),
        }
    }

    /// Bind `refresh`'s own `--image` to clap's value source.
    ///
    /// Only `refresh` carries a launch-image selection, and only its *own*
    /// subcommand matches are authoritative. Reconciling against the group or
    /// top-level matches would lose the origin and the empty-environment rule
    /// (issue #189), silently turning `AGENT_VM_IMAGE_TAG=` into a present value
    /// or a typed flag into an environment one.
    pub(crate) fn reconcile_image_args(&mut self, image_matches: &clap::ArgMatches) {
        if let ImageCmd::Refresh(args) = &mut self.cmd
            && let Some(refresh) = image_matches.subcommand_matches("refresh")
        {
            args.image.reconcile(refresh);
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
    /// Acquire the selected OCI image into the image cache without booting a VM.
    ///
    /// Re-resolves the reference and reuses valid cached layers; it creates no
    /// sandbox, temporary disk or running guest, and never changes an existing
    /// retained default.
    Refresh(crate::pull::Args),
    /// Acquire an OCI image and retain it as the default for future sessions.
    ///
    /// The target is required and explicit: an ambient launch image, an image
    /// option outside this subcommand, a broken catalog or the current
    /// recommendation never chooses it. Overrides and running sessions are
    /// unchanged.
    SetDefault(crate::boot_image::upgrade::Args),
    /// Explicitly build a Dockerfile and import the result into agent-vm's image cache.
    Build(crate::image_build::Args),
    /// Import a finished image from the local Docker daemon or an archive into agent-vm's image cache.
    Import(crate::image_import::Args),
}

/// Input-only checks `main` runs before the MSB prologue.
pub(crate) fn preflight(args: &Args) -> Result<()> {
    match &args.cmd {
        ImageCmd::Show | ImageCmd::Build(_) | ImageCmd::SetDefault(_) => Ok(()),
        ImageCmd::Refresh(args) => crate::pull::preflight(args),
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

pub(crate) async fn run(args: Args, catalog: Catalog, images: ConfiguredImages) -> Result<i32> {
    match args.cmd {
        // `main` routes `show` before the runtime exists; reaching here means
        // the early dispatch was bypassed, which is a wiring error, not input.
        ImageCmd::Show => bail!("image show must be dispatched before runtime setup"),
        ImageCmd::Refresh(args) => {
            // Refresh forwards the *original* carried configuration so its
            // documented broken-config recovery still applies.
            crate::pull::run(args, catalog, images).await?;
            Ok(0)
        }
        ImageCmd::SetDefault(args) => {
            crate::boot_image::upgrade::run(args).await?;
            Ok(0)
        }
        ImageCmd::Build(args) => crate::image_build::run(args).await,
        ImageCmd::Import(args) => {
            // Only import observes the selection after publishing, and it must
            // keep its existing behaviour for each catalog state: a ready
            // catalog exposes its tiers, a broken one is reported to import as
            // a failure it tolerates after a successful publication. Refresh and
            // set-default above never see this derived value, so neither
            // silently loses broken-config recovery.
            let configured = match &catalog {
                Catalog::Ready(_) => Ok(&images),
                Catalog::Broken(error) => Err(anyhow::anyhow!("{error:#}")),
            };
            crate::image_import::run(args, configured).await
        }
    }
}
