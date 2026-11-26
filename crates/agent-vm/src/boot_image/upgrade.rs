//! Deliberate selection of one explicit boot image for **this project**, saved as
//! the root `image` of its host-managed project config. The acquisition path and
//! the approval authority belong to [`crate::image_pin`], the bytes of the edit to
//! [`crate::project_config_writer`]: this module owns the command's argument shape,
//! the order of the three stages, and the words it prints.
//!
//! # What this command promises
//!
//! It saves a **reference**, not an approval (ADR-0078 D3). The seed is written for
//! a project with no `config.toml`; an existing file keeps every other byte, and an
//! unrelated setting that still needs fixing does not block the narrow edit
//! (D8). It writes neither `image-pins.json` nor the retained
//! `default-image.json`, so a `trust = false` source is neither approved nor
//! consulted, and another project is untouched.
//!
//! The success notice therefore promises the saved reference only: a tag, an
//! approval or the configuration can change before the next launch, so no output
//! here claims which digest that launch boots.
//!
//! Every path into the file — including one that plans no edit — publishes through
//! the writer's compare-and-publish. `Unchanged` is the writer's answer about a
//! snapshot it re-checked under the lock (D1), never this command's inference from
//! the plan, which would let a no-op print success over a file a peer replaced.
//!
//! # Why the target is validated before anything exists
//!
//! [`preflight`] runs synchronously in `main` *before* the MSB prologue redirects
//! state and before any registry request: an unsafe project config, a target this
//! command cannot save, or a damaged approval store refuses there, leaving even the
//! redirected MSB state directories absent. [`run`] repeats the same checks for a
//! direct caller and then re-plans against the snapshot it will publish.

use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use super::ImageRef;
use crate::image_acquire::{OciTarget, OciTargetError};
use crate::project::ProjectDir;
use crate::project_config_writer::{
    ConfigSave, ConfigSnapshot, ImageEditPlan, ProjectConfigStore, plan_image_edit,
};
use anyhow::{Result, anyhow, bail};

/// The fixed refusal for a local rootfs/disk `--image` target. Names no value:
/// the rejected text is user input.
const TARGET_REASON: &str = "set-default targets must be OCI image references (tag or digest); launch a local rootfs with agent-vm --image PATH <tool>";

/// The fixed refusal for `--image` text that is not a usable OCI reference at
/// all. It must not suggest a local launch for a malformed reference.
const INVALID_REFERENCE_REASON: &str =
    "set-default needs a valid OCI image reference, e.g. ghcr.io/owner/name:tag or repo@sha256:…";

/// The fixed refusal for an argument shaped like `<alias>:image` (ADR-0078 D8).
///
/// In a project config that spelling is a **source delegation**, not an image
/// tagged `image`: saving it would make the root `image` delegate to a sourced
/// file instead of naming content. The advice is value-free — the rejected text is
/// user input — and the qualified example shows the shape that works.
const SOURCE_DELEGATION_REASON: &str = "set-default saves image = \"REF\" in the project config, where <alias>:image selects a \
     sourced file's image instead of naming one; spell an OCI image tagged \"image\" with \
     its registry (for example docker.io/library/NAME:image)";

#[derive(clap::Args)]
pub(crate) struct Args {
    /// OCI image to acquire and set as this project's boot image in its project
    /// config.
    ///
    /// Writes image = "REF" to
    /// $HOME/.config/agent-vm/projects/<project-id>/config.toml, seeding the
    /// default home source when that file is absent and keeping every other
    /// setting. Overrides, approvals and other projects are unchanged.
    #[arg(long = "image", value_name = "REF", value_parser = SetDefaultTargetParser)]
    target: SetDefaultTarget,
}

#[derive(Clone)]
struct SetDefaultTarget(ImageRef);

impl SetDefaultTarget {
    fn parse(raw: &str) -> std::result::Result<Self, &'static str> {
        // A `<alias>:image` delegation is refused with its own advice even though
        // the OCI grammar accepts the text: the other verbs' grammar is unchanged,
        // and only this command saves a value whose project-config meaning differs
        // from its image meaning.
        if is_source_delegation(raw) {
            return Err(SOURCE_DELEGATION_REASON);
        }
        // The same acceptance rule the acquisition itself will apply, so a
        // target clap accepts cannot be refused later for a different reason.
        OciTarget::parse(raw).map_err(target_reason)?;
        ImageRef::from_config(raw)
            .map(Self)
            .map_err(|_| INVALID_REFERENCE_REASON)
    }
}

/// Does `raw` have the project config's `<alias>:image` delegation shape?
///
/// The loader's own shape rule ([`crate::config_sources::image_alias`]), reused
/// rather than restated: a value the loader would read as a source delegation is
/// exactly a value this command must not save as an image reference. No second
/// grammar, so the two cannot drift.
fn is_source_delegation(raw: &str) -> bool {
    crate::config_sources::image_alias(raw).is_some()
}

impl FromStr for SetDefaultTarget {
    type Err = &'static str;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

/// This command's value-free reason for a rejected `--image` target.
fn target_reason(error: OciTargetError) -> &'static str {
    match error {
        OciTargetError::LocalPath => TARGET_REASON,
        OciTargetError::InvalidReference => INVALID_REFERENCE_REASON,
    }
}

/// Set-default's own clap value parser.
///
/// clap's stock `FromStr` wrapper renders the rejected value in its error, and a
/// private target is still the user's own input, so every refusal is a raw
/// fixed-reason clap error instead (non-Unicode input included).
#[derive(Clone)]
struct SetDefaultTargetParser;

impl clap::builder::TypedValueParser for SetDefaultTargetParser {
    type Value = SetDefaultTarget;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        let reason = match value.to_str() {
            Some(text) => match SetDefaultTarget::parse(text) {
                Ok(target) => return Ok(target),
                Err(reason) => reason,
            },
            // Non-Unicode text cannot be an OCI reference; never echo it.
            None => INVALID_REFERENCE_REASON,
        };
        Err(clap::Error::raw(
            clap::error::ErrorKind::ValueValidation,
            reason,
        ))
    }
}

/// The synchronous, read-only, pre-network half of this command.
///
/// Runs in `main` before the MSB prologue redirects state (so a refusal leaves even
/// a redirected `MSB_HOME` absent), and again from [`run`] for a direct caller. It
/// creates nothing: it reads the project config through the writer's verified walk
/// and computes the same edit the write stage will publish, so an unsafe file or a
/// file this command cannot edit narrowly refuses before any registry request. The
/// approval check is [`crate::image_pin::preflight_project_default`], which honours a
/// pending journal and fails closed on damage without recovering anything.
pub(crate) fn preflight(args: &Args, project: &Result<ProjectDir>) -> Result<()> {
    let project = project.as_ref().map_err(|error| {
        anyhow!("capturing the invoking project for image set-default: {error:#}")
    })?;
    let home = required_home()?;
    preflight_with(&home, project, &args.target.0)
}

fn preflight_with(home: &Path, project: &ProjectDir, reference: &ImageRef) -> Result<()> {
    let store = ProjectConfigStore::for_project(home, project);
    let existing = store.existing_bytes()?;
    plan(&store, existing.as_deref(), reference)?;
    crate::image_pin::preflight_project_default(reference, project)
}

pub(crate) async fn run(args: Args, project: Result<ProjectDir>) -> Result<()> {
    let project = project?;
    let home = required_home()?;
    preflight_with(&home, &project, &args.target.0)?;
    crate::msb_preflight::ensure_db_not_ahead().await?;
    crate::image_log_guard::activate();
    // Acquisition first, then the approval comparison, then the write (ADR-0078
    // D3): the pin lock is never held across `config.lock`, and no cache or OCI
    // lock is taken from inside it. The barrier this returns keeps the validated
    // content published until after the commit.
    let prepared = crate::image_pin::acquire_for_project_default(&args.target.0, &project).await?;
    let store = ProjectConfigStore::for_project(&home, &project);
    // The snapshot, not the preflight read: this is the base the save must still
    // match. Like the preflight read it creates nothing; `publish` is the one
    // transition that may bootstrap our own absent store, its lock, or the first
    // lock in a store that already exists.
    let snapshot = store.snapshot()?;
    let plan = plan(&store, snapshot.bytes(), &args.target.0)?;
    let saved = publish(&store, &snapshot, &plan)?;
    // A base that moved under us is an ordinary refusal, never a panic and never
    // reported as success: the file that carries the selection is not the file this
    // command read.
    let ConfigSave::Refused(conflict) = saved else {
        let notice = notice(store.config_path());
        // The edit is committed: output failure cannot turn success into error.
        let _ = writeln!(std::io::stderr(), "{notice}");
        drop(prepared);
        return Ok(());
    };
    bail!(
        "config: {}: {}",
        crate::one_line::path(store.config_path()),
        conflict.reason()
    )
}

/// `$HOME`, from the same single read the config loader uses, with this command's
/// context. A writer that guessed a different home than the loader read would write
/// a different project's file.
fn required_home() -> Result<std::path::PathBuf> {
    crate::config::host_home_dir()?.ok_or_else(|| {
        anyhow!(
            "config: $HOME is unset, so the project config store for image set-default cannot be located"
        )
    })
}

/// The plan, with the writer's fixed reason turned into this command's message.
fn plan(
    store: &ProjectConfigStore,
    existing: Option<&str>,
    reference: &ImageRef,
) -> Result<ImageEditPlan> {
    plan_image_edit(existing.map(str::as_bytes), reference).map_err(|refusal| {
        anyhow!(
            "config: {}: {refusal}",
            crate::one_line::path(store.config_path())
        )
    })
}

/// Compare-and-publish the plan against the snapshot the command measured.
///
/// The planner's [`ImageEditPlan::Unchanged`] decides only that the bytes need no
/// edit; it does not license a success notice. A no-op therefore takes the same
/// snapshot-checked publication as an edit, handing [`ProjectConfigStore::save`] the
/// snapshot's own bytes, and `Unchanged` is returned only when the writer found that
/// snapshot still live under the lock.
fn publish(
    store: &ProjectConfigStore,
    snapshot: &ConfigSnapshot,
    plan: &ImageEditPlan,
) -> Result<ConfigSave> {
    let bytes: &[u8] = match plan.bytes() {
        Some(bytes) => bytes,
        None => snapshot.bytes().map(str::as_bytes).ok_or_else(|| {
            anyhow!(
                "config: {}: an unchanged plan has no measured bytes to compare and publish against",
                crate::one_line::path(store.config_path())
            )
        })?,
    };
    store.save(snapshot, bytes)
}

/// What the user is told, on success, in every published state.
///
/// Two claims and no third (ADR-0078 D3): the **reference** is saved where
/// `image show` will report it (`Source: project config`, this `File:`), and
/// overrides and approvals are unchanged. It deliberately does not say the next
/// launch boots the digest this command acquired — a tag can move, an approval can
/// be replaced, and the config can be edited before then.
fn notice(config: &Path) -> String {
    format!(
        "Project boot image reference saved to the project config at {}. \
         Overrides and approvals are unchanged.",
        crate::one_line::path(config)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_image::ImmutableImageRef;
    use crate::project_config_writer::ConfigConflict;

    #[test]
    fn derived_child_is_canonical_and_immutable() {
        let child = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        for (input, expected) in [
            ("localhost:1234/a:tag", "localhost:1234/a@"),
            ("alpine:latest", "docker.io/library/alpine@"),
            (
                "localhost:1234/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "localhost:1234/a@",
            ),
        ] {
            let target = OciTarget::parse(input).unwrap();
            let pinned = target
                .canonical()
                .with_digest(&crate::image_acquire::ValidatedDigest::parse(child).unwrap())
                .unwrap();
            assert_eq!(pinned.whole(), format!("{expected}{child}"));
            assert!(ImmutableImageRef::parse(&pinned.whole()).is_ok());
        }
    }

    #[test]
    fn targets_are_oci_only_with_set_default_specific_safe_advice() {
        for raw in [
            "alpine:latest",
            "localhost:1234/a:release",
            "repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(raw.parse::<SetDefaultTarget>().is_ok());
        }
        for raw in ["", "Foo/Bar:tag", "repo:bad tag", "repo@sha256:short"] {
            let error = raw.parse::<SetDefaultTarget>().err().unwrap();
            assert_eq!(error, INVALID_REFERENCE_REASON);
            assert!(!error.contains("agent-vm --image PATH <tool>"));
        }
        for raw in ["/private/path", "./rootfs", "../rootfs", ".."] {
            let error = raw.parse::<SetDefaultTarget>().err().unwrap();
            assert_eq!(error, TARGET_REASON);
            assert!(error.contains("agent-vm --image PATH <tool>"));
        }
    }

    /// D8: a *new argument* shaped like the config grammar's `<alias>:image`
    /// delegation is a persistence error with value-free advice, while a
    /// registry-qualified reference that merely ends in `:image` is still an image.
    #[test]
    fn an_alias_shaped_target_is_refused_as_a_delegation() {
        for raw in [
            "home:image",
            "a:image",
            "base_image:image",
            "a-b:image",
            "alpine:image",
        ] {
            assert!(is_source_delegation(raw), "{raw}");
            let error = raw.parse::<SetDefaultTarget>().err().unwrap();
            assert_eq!(error, SOURCE_DELEGATION_REASON);
            assert!(error.contains("docker.io/library/NAME:image"));
            // Value-free: the refused text itself is user input.
            assert!(!error.contains("my.alias"), "{error}");
        }
        for raw in [
            "docker.io/library/alpine:image",
            "localhost:5000/images:image",
            "repo:image@sha256:abcd",
            "alpine:latest",
        ] {
            assert!(!is_source_delegation(raw), "{raw}");
        }
    }

    /// The notice promises the saved reference and nothing about the next launch.
    #[test]
    fn the_notice_promises_only_the_saved_reference() {
        let path = Path::new("/home/user/.config/agent-vm/projects/abc/config.toml");
        let text = notice(path);
        assert!(
            text.contains("Project boot image reference saved"),
            "{text}"
        );
        assert!(
            text.contains("Overrides and approvals are unchanged"),
            "{text}"
        );
        assert!(text.contains("config.toml"), "{text}");
        for promoted in ["boots", "next launch", "digest", "will start"] {
            assert!(
                !text.contains(promoted),
                "the notice must not say {promoted:?}: {text}"
            );
        }
    }

    /// `ConfigConflict`'s reasons are the ordinary refusal text; the command must
    /// never report one as success.
    #[test]
    fn published_conflicts_are_refusals_with_the_writers_reason() {
        for conflict in [ConfigConflict::Stale, ConfigConflict::Displaced] {
            assert!(!conflict.reason().is_empty());
        }
    }

    /// Every command path enters compare-and-publish, the no-op included.
    ///
    /// The plan is `Unchanged` in both halves: the snapshot already spells the
    /// requested reference. The writer is what decides whether that is still true,
    /// so the no-op that a peer overwrote is a refusal, not a success notice over a
    /// file that no longer carries the reference.
    #[test]
    fn an_unchanged_plan_still_compares_and_publishes_against_a_live_snapshot() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let project = ProjectDir::from_path_for_tests(project.path()).unwrap();
        let store = ProjectConfigStore::for_project(home.path(), &project);
        let reference = ImageRef::from_config("example.com/app:1").unwrap();
        let config = store.config_path().to_path_buf();
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            config.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(&config, "image = \"example.com/app:1\"\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let planned = plan(&store, snapshot.bytes(), &reference).unwrap();
        assert!(
            matches!(planned, ImageEditPlan::Unchanged),
            "the snapshot already spells the requested reference: {planned:?}"
        );
        // The control: the live snapshot publishes nothing, through the same path.
        assert_eq!(
            publish(&store, &snapshot, &planned).unwrap(),
            ConfigSave::Unchanged
        );

        // The reproducer: a peer writes a different image after the snapshot and
        // before the command commits, and the plan is still `Unchanged`.
        let peer = "image = \"example.com/peer:2\"\n";
        std::fs::write(&config, peer).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            publish(&store, &snapshot, &planned).unwrap(),
            ConfigSave::Refused(ConfigConflict::Stale),
            "a no-op whose base moved is a stale refusal, never a success"
        );
        assert_eq!(std::fs::read(&config).unwrap(), peer.as_bytes());
    }
}
