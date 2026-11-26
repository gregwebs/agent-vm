//! `agent-vm image …` — inspect the selected boot image or this project's
//! approvals, acquire the selected OCI reference, save this project's boot image
//! reference, or publish a finished image into agent-vm's own image cache.
//!
//! `show` selects nothing new and boots nothing: it reports the image a launch
//! here would select, so it is dispatched before runtime discovery and setup
//! (see `main`). `pins` is the other read-only inspection verb: it reports the
//! approvals this project already holds, across platforms, and needs no
//! configuration, catalog, runtime or cache either. `pull` acquires bytes
//! natively and never boots. `build`/`import` are the explicit user-owned
//! publication verbs from ADR-0043; only they may invoke Docker. `pull`,
//! `build` and `import` are each their own consent and none asks (#391,
//! ADR-0067): each approves exactly what it resolved or published. `import`
//! additionally *observes* the selection after publishing (#385) — it never
//! changes it. `set-default` is the one verb that writes configuration rather
//! than approvals: it acquires its target and splices it into this project's
//! `config.toml` through the verified writer (#737, ADR-0078).

use anyhow::{Context as _, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use crate::config::{Catalog, ConfiguredImages};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) cmd: ImageCmd,
}

impl Args {
    /// Whether this is the read-only selection inspection verb, which `main`
    /// dispatches before any MSB/runtime/cache work.
    pub(crate) fn is_show(&self) -> bool {
        matches!(self.cmd, ImageCmd::Show)
    }

    /// Whether this is the read-only approvals listing, which `main` dispatches
    /// on its own branch: unlike `show` it refuses nothing when the carried
    /// catalog is broken, because approvals do not depend on configuration.
    pub(crate) fn is_pins(&self) -> bool {
        matches!(self.cmd, ImageCmd::Pins)
    }

    /// Post-parse validation of values clap accepts but a verb cannot act on:
    /// currently only import's result reference, which may be inferred from
    /// `--docker` and must be refused before any state exists. Input-only — no
    /// file is stat'ed and no configuration is resolved here.
    pub(crate) fn validate_result_reference(&self) -> Result<()> {
        match &self.cmd {
            ImageCmd::Import(args) => args.result_reference().map(|_| ()),
            ImageCmd::Show
            | ImageCmd::Pins
            | ImageCmd::Build(_)
            | ImageCmd::Pull(_)
            | ImageCmd::SetDefault(_) => Ok(()),
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
    #[command(
        about = "List this project's approved OCI images and recorded roles",
        long_about = "List this project's image approvals across all platforms, including full references, child digests, revision tokens, held roles and unresolved slots. Read-only and offline: no configuration, runtime or cache is required, and nothing is created. This explicit listing may disclose private references."
    )]
    Pins,
    #[command(
        about = "Pull this project's in-use OCI references without booting a VM",
        long_about = "Re-resolve and approve the ambient boot operation and all recorded boot/output holders without asking. When adopting the host default, that operation acquires it instead of the old unheld project default; a held old default is pulled independently. Use --image REF to pull one in-use reference without changing selection or adopting a default. Keep successful approvals if another target fails; exit 1 if any target fails."
    )]
    Pull(crate::pull::Args),
    /// Acquire an OCI image and save it as this project's boot image.
    ///
    /// Writes `image = "REF"` to this project's host-managed config
    /// (`$HOME/.config/agent-vm/projects/<project-id>/config.toml`), seeding the
    /// default `home` source when that file is absent and keeping every other
    /// setting and comment. The target is required and explicit: an ambient launch
    /// image, an image option outside this subcommand, a broken catalog or the
    /// current recommendation never chooses it. No approval is written or
    /// replaced; if this project already approves the reference at different
    /// content the command refuses instead of promising a boot it cannot deliver.
    /// Overrides, approvals, other projects and running sessions are unchanged.
    SetDefault(crate::boot_image::upgrade::Args),
    /// Explicitly build a Dockerfile, import the result into agent-vm's image
    /// cache and approve it for its `--tag`.
    Build(crate::image_build::Args),
    /// Import a finished image from the local Docker daemon or an archive into
    /// agent-vm's image cache and approve it for its result reference.
    Import(crate::image_import::Args),
}

/// Input-only checks `main` runs before the MSB prologue, and the one verb here
/// whose refusals must precede any state creation: `set-default` reads the
/// project config it is about to edit and the approval store it must not cross
/// before the MSB prologue redirects state or a registry is contacted.
pub(crate) fn preflight(args: &Args, project: &Result<crate::project::ProjectDir>) -> Result<()> {
    match &args.cmd {
        ImageCmd::Show | ImageCmd::Pins | ImageCmd::Build(_) => Ok(()),
        ImageCmd::SetDefault(args) => crate::boot_image::upgrade::preflight(args, project),
        ImageCmd::Pull(args) => crate::pull::preflight(args),
        ImageCmd::Import(args) => crate::image_import::preflight(args),
    }
}

/// Write the selected boot-image inspection report to stdout.
///
/// Selection happens before this call so a failure produces no stdout at all;
/// the report is written in one `write_all` for the same reason, and the
/// reference is never logged.
pub(crate) fn show(
    configured: &ConfiguredImages,
    project: &Result<crate::project::ProjectDir>,
) -> Result<()> {
    use std::io::Write as _;
    // Selection needs to know which project's default it would read, so it
    // consumes `main`'s capture (ADR-0073 D2). A capture failure has already
    // failed the config load and is fatal here before this call; the capture is
    // passed as data because a higher explicit source resolves first whenever
    // the config did load. Nothing is created, so the read-only, offline
    // contract holds.
    let report = crate::boot_image::inspect_selection(configured, project)?;
    std::io::stdout()
        .lock()
        .write_all(report.as_bytes())
        .context("writing selected boot-image inspection")
}

/// Write this project's approved-image listing to stdout.
///
/// Unlike `show`, a project this command cannot identify has no lower-precedence
/// source to fall back to: every row is that project's own approval, so a
/// capture failure is fatal rather than being rendered as a fictional empty
/// project. The whole report is prepared before one `write_all`, so damage never
/// leaves a partial listing on stdout, and neither the report nor its rows are
/// logged.
pub(crate) fn pins(project: &Result<crate::project::ProjectDir>) -> Result<()> {
    use std::io::Write as _;
    // `main`'s one capture (ADR-0073 D5), borrowed because the early dispatch
    // happens before the capture is consumed.
    let project = project.as_ref().map_err(|error| {
        anyhow::anyhow!("capturing the invoking project for image pins: {error:#}")
    })?;
    let report = crate::image_pin::pins_report(project)?;
    std::io::stdout()
        .lock()
        .write_all(report.as_bytes())
        .context("writing image pin inspection")
}

pub(crate) async fn run(
    args: Args,
    catalog: Catalog,
    images: ConfiguredImages,
    project: Result<crate::project::ProjectDir>,
) -> Result<i32> {
    match args.cmd {
        // `main` routes `show` before the runtime exists; reaching here means
        // the early dispatch was bypassed, which is a wiring error, not input.
        ImageCmd::Show => bail!("image show must be dispatched before runtime setup"),
        // Same wiring rule, and the stronger reason: a runtime path would also
        // create the state this listing promises not to create.
        ImageCmd::Pins => bail!("image pins must be dispatched before runtime setup"),
        ImageCmd::Pull(args) => {
            // Pull forwards the *original* carried configuration so its own
            // broken-config rules apply: a known ambient selection or a proven
            // in-use target can recover, a bare pull cannot (R8).
            crate::pull::run(args, catalog, images, project).await
        }
        ImageCmd::SetDefault(args) => {
            crate::boot_image::upgrade::run(args, project).await?;
            Ok(0)
        }
        ImageCmd::Build(args) => crate::image_build::run(args, project).await,
        ImageCmd::Import(args) => {
            // Only import observes the selection after publishing, and it must
            // keep its existing behaviour for each catalog state: a ready
            // catalog exposes its tiers, a broken one is reported to import as
            // a failure it tolerates after a successful publication. Pull and
            // set-default above never see this derived value, so neither
            // silently changes how it reads a broken configuration.
            let configured = match &catalog {
                Catalog::Ready(_) => Ok(&images),
                Catalog::Broken(error) => Err(anyhow::anyhow!("{error:#}")),
            };
            let project = project?;
            crate::image_import::run(args, configured, &project).await
        }
    }
}
