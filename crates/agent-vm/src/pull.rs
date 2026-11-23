//! `agent-vm image pull` — re-resolve and approve the OCI references this
//! project is actually using, without booting anything.
//!
//! Acquisition is native ([`crate::image_acquire`]): `Registry` with
//! `PullPolicy::Always` and `force: false`, so each target's current manifest is
//! re-resolved and valid cached layers are reused rather than re-downloaded. No
//! sandbox, VM, temporary disk, Docker or alternate download backend is
//! involved, and nothing about a project or a running guest changes.
//!
//! # What is pulled
//!
//! The worklist is the invocation's in-use set for this project on this host
//! platform (ADR-0068 D10): the ambient next-launch operation plus every record
//! holding a Boot/Output role, deduplicated by canonical reference. It is frozen
//! before any registry work by [`crate::image_pin::plan_refresh`]; this module
//! only decides *which* ambient selection and default offer feed that plan, then
//! reports what each operation committed.
//!
//! `--image REF` **filters** that set. It is not a boot-selection override and it
//! never establishes or adopts a default, so pulling a reference can no
//! longer approve an arbitrary new one: `setup --image REF --no-verify` acquires
//! a new boot reference, and build/import approve their own output.
//! `AGENT_VM_IMAGE_TAG` stays an ambient boot-selection input — it chooses the
//! operation, it does not restrict the worklist.
//!
//! # Consent and failure
//!
//! Running this command is the consent for every change it makes (ADR-0067):
//! a first pin, a replaced approval for a moved mutable source, or adoption of
//! the host's retained default. Nothing is asked and no input is read, on a
//! terminal or not. Each operation owns its candidate and its save; a failure
//! preserves only that operation's approval, roles and project-default
//! transaction, and the remaining operations still run. A pre-worklist refusal —
//! an unreadable selection, a damaged host offer or a `--image` value that is not
//! in use — happens before any registry request and prints no result rows.

use std::io::Write;

use anyhow::{Result, anyhow};
use clap::Args as ClapArgs;

use crate::boot_image::{self, ConfiguredTiers, EnvOverride};
use crate::config::{Catalog, ConfiguredImages};
use crate::image_acquire::{OciTarget, OciTargetError};
use crate::image_pin::{
    self, AmbientRefresh, ApprovalDelta, ProjectDefaultChange, RefreshRequest, RefreshSuccess,
};
use crate::project::ProjectDir;

/// The fixed refusal for a pull target that is a local rootfs or disk path.
/// Names no value: the rejected text is user input.
pub(crate) const TARGET_REASON: &str = "`agent-vm image pull` acquires OCI image references (tag or digest) only; \
     it never boots, formats or reads a local rootfs — launch a local rootfs or disk image with \
     agent-vm --image PATH <tool> instead";

/// The fixed refusal for a target that is not a usable OCI reference at all.
/// A malformed reference is not a local path, so it must not be told how to
/// launch one; the value itself is never echoed.
pub(crate) const INVALID_REFERENCE_REASON: &str = "`agent-vm image pull` needs a valid OCI image reference, \
     e.g. ghcr.io/owner/name:tag or repo@sha256:…";

/// The fixed refusal for a bare pull whose configuration could not be read
/// and which has no known ambient selection to fall back on.
pub(crate) const BROKEN_CONFIG_REASON: &str = "configured image settings could not be read; image pull does not fall back to the \
     default boot image while the configuration is unreadable, so nothing was acquired or \
     approved; fix it (agent-vm doctor reports what is wrong), set AGENT_VM_IMAGE_TAG to the \
     intended boot reference, or pass --image REF for a recorded in-use reference";

/// The one warning an allowed broken-configuration recovery prints, before any
/// result row.
pub(crate) const BROKEN_CONFIG_WARNING: &str = "==> WARNING: configured image settings could not be read; pulling only references \
     proven in use, without establishing or adopting a project default";

/// The exact text the loader reports for a non-Unicode `AGENT_VM_IMAGE_TAG`.
pub(crate) const ENV_NOT_UNICODE_REASON: &str = "AGENT_VM_IMAGE_TAG is set but is not usable as an image override; \
     a Unicode value is required";

/// The one postcommit warning a report-sink failure attempts.
pub(crate) const REPORT_SINK_WARNING: &str = "warning: image pull outcomes could not all be written; completed \
     approvals remain committed; do not retry it as a failed approval";

/// Render this command's value-free refusal for a rejected target.
pub(crate) fn target_error(error: OciTargetError) -> anyhow::Error {
    match error {
        OciTargetError::LocalPath => anyhow!(TARGET_REASON),
        OciTargetError::InvalidReference => anyhow!(INVALID_REFERENCE_REASON),
    }
}

#[derive(ClapArgs)]
pub struct Args {
    /// Pull one in-use OCI reference without changing boot selection.
    #[arg(
        long = "image",
        value_name = "REF",
        help_heading = "Image",
        long_help = "Pull one OCI reference currently in use by this project on the host platform, without changing boot selection or adopting a default.\n\nWithout --image, pull the ambient boot operation and all recorded boot/output holders. When adopting the host default, that operation supersedes the old unheld project default; a held old default is pulled independently. AGENT_VM_IMAGE_TAG selects the ambient boot reference; it does not restrict the pull to one target. An empty value counts as unset. A reference outside this set is refused; use setup --image REF --no-verify to acquire a new boot reference. See USAGE.md \u{2192} \"Pulling in-use images\"."
    )]
    image: Option<String>,

    /// The ambient `AGENT_VM_IMAGE_TAG`, captured once at parse time.
    ///
    /// It is **not** clap's value source for `--image`: a filter and a boot
    /// selection are different inputs, and clap's env binding would collapse
    /// them into one. Capture also keeps the empty-is-unset and non-Unicode
    /// rules in one place ([`boot_image::read_env_override`]).
    #[arg(skip = boot_image::read_env_override())]
    ambient: EnvOverride,
}

impl Args {
    /// This invocation's `--image` filter, if any.
    ///
    /// Value-free refusals live here so the same predicate serves the preflight
    /// and the command: an empty value, a local path and a malformed reference
    /// are all rejected before any state exists.
    pub(crate) fn filter(&self) -> Result<Option<OciTarget>> {
        let Some(raw) = self.image.as_deref() else {
            return Ok(None);
        };
        let reference = boot_image::ImageRef::from_override(raw.to_string())?;
        OciTarget::parse(reference.as_str())
            .map(Some)
            .map_err(target_error)
    }

    /// The ambient boot selection this invocation carries, if any.
    pub(crate) fn ambient_override(&self) -> Result<Option<boot_image::ImageOverride>> {
        match &self.ambient {
            EnvOverride::Unset => Ok(None),
            EnvOverride::Present(override_) => Ok(Some(override_.clone())),
            EnvOverride::Invalid => Err(anyhow!(ENV_NOT_UNICODE_REASON)),
        }
    }

    /// A test-only constructor: no clap parser, no process environment.
    #[cfg(test)]
    pub(crate) fn for_test(image: Option<&str>, ambient: EnvOverride) -> Self {
        Self {
            image: image.map(str::to_owned),
            ambient,
        }
    }
}

pub async fn run(
    args: Args,
    catalog: Catalog,
    images: ConfiguredImages,
    project: Result<ProjectDir>,
) -> Result<i32> {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    run_with(args, catalog, images, project, &mut stdout, &mut stderr).await
}

/// [`run`] with the report sinks supplied, so the exact rows, the once-only
/// sink warning and the exit status are testable without a process.
async fn run_with(
    args: Args,
    catalog: Catalog,
    images: ConfiguredImages,
    project: Result<ProjectDir>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<i32> {
    let filter = args.filter()?;
    let ambient_override = args.ambient_override()?;
    // Unwrapped after argv validation, so an argument error keeps its precedence
    // over a cwd that could not be captured.
    let project = project?;
    // The whole authority is decoded and validated here, before any selection,
    // registry request or write: damage is a command-level failure.
    let snapshot = image_pin::observe_refresh_scope(&project)?;
    let ambient = ambient_selection(
        &filter,
        ambient_override,
        &catalog,
        &images,
        &project,
        &snapshot,
        stdout,
    )?;
    let offer = match (&filter, &ambient) {
        (None, AmbientRefresh::Selected(boot)) => boot_image::adoption_offer(boot)?,
        _ => None,
    };
    let plan = image_pin::plan_refresh(
        RefreshRequest {
            ambient,
            filter,
            offer,
        },
        &project,
        snapshot,
    )?;
    // The native pull reaches the shared microsandbox state (its cache and
    // registry configuration), so it can hit the same forward-migrated-DB crash
    // as the boot path. See src/msb_preflight.rs and issue #30.
    crate::msb_preflight::ensure_db_not_ahead().await?;
    let targets = plan.into_targets();
    let total = targets.len();
    let mut report = Report::default();
    let mut sinks = Sinks { stdout, stderr };
    let mut failures = 0usize;
    for (index, target) in targets.into_iter().enumerate() {
        // Only the report metadata is cloned out of the target; the worker then
        // owns the operation (and its non-`Clone` authority) outright.
        let label = target.label().clone();
        let platform = target.platform_label().to_owned();
        let row = Row {
            position: index + 1,
            total,
            label: &label,
            platform: &platform,
        };
        match image_pin::refresh_target(target, &project).await {
            Ok(success) => report.succeeded(&mut sinks, &row, &success),
            Err(error) => {
                failures += 1;
                report.failed(&mut sinks, &row, &error);
            }
        }
    }
    report.summary(&mut sinks, total - failures, failures);
    Ok(i32::from(failures > 0))
}

/// Decide the ambient operation, warning once when a broken configuration is
/// recovered from a proven in-use reference.
///
/// The order is the contract: a held `--image` target needs no selection and no
/// default read, an unfiltered invocation always needs a real one, and a
/// selection error is kept (as [`AmbientRefresh::Unavailable`]) instead of being
/// turned into a fabricated target.
fn ambient_selection(
    filter: &Option<OciTarget>,
    ambient_override: Option<boot_image::ImageOverride>,
    catalog: &Catalog,
    images: &ConfiguredImages,
    project: &ProjectDir,
    snapshot: &image_pin::RefreshScopeSnapshot,
    stdout: &mut impl Write,
) -> Result<AmbientRefresh> {
    if let Some(target) = filter
        && snapshot.has_held_target(target)
    {
        // A proven holder is enough evidence; it also means the broken
        // configuration is being recovered rather than read.
        if matches!(catalog, Catalog::Broken(_)) {
            let _ = writeln!(stdout, "{BROKEN_CONFIG_WARNING}");
        }
        return Ok(AmbientRefresh::NotNeeded);
    }
    let tiers = match catalog {
        Catalog::Ready(_) => ConfiguredTiers::Read(images),
        Catalog::Broken(_) if ambient_override.is_some() => {
            // The warning is part of the allowed recovery, and it is best effort
            // like every other non-consent write.
            let _ = writeln!(stdout, "{BROKEN_CONFIG_WARNING}");
            ConfiguredTiers::Unreadable
        }
        // Without a known ambient selection nothing can qualify a target. A bare
        // pull refuses the command; a filtered one is refused as a nonmember
        // by the planner without inventing a selection.
        Catalog::Broken(_) if filter.is_some() => {
            return Ok(AmbientRefresh::Unavailable(anyhow!(
                image_pin::NOT_A_MEMBER_REASON
            )));
        }
        Catalog::Broken(_) => return Err(anyhow!(BROKEN_CONFIG_REASON)),
    };
    Ok(match boot_image::select(ambient_override, tiers, project) {
        Ok(boot) => AmbientRefresh::Selected(boot),
        Err(error) => AmbientRefresh::Unavailable(error),
    })
}

/// One result row per planned operation, in worklist order.
///
/// Every write is fallible and every failure is bounded: a closed stdout must
/// not turn an operation that committed into a reported failure, and it must not
/// stop the operations that have not run yet. Consent rendering is the one write
/// that stays fatal — for its own operation, before its save.
#[derive(Default)]
struct Report {
    /// The warning is attempted once per invocation, on the first sink failure.
    sink_warned: bool,
}

/// The notice that precedes an adoption's own result row.
const ADOPTION_NOTICE: &str = "==> this project now uses the host's default boot image";

/// The two report sinks, borrowed for one invocation.
struct Sinks<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
}

/// One row's safe report metadata: where it is in the worklist and what the
/// operation may be called. Never authority or candidate data.
struct Row<'a> {
    position: usize,
    total: usize,
    label: &'a boot_image::ImageLabel,
    platform: &'a str,
}

impl Report {
    fn succeeded(&mut self, sinks: &mut Sinks<'_>, row: &Row<'_>, success: &RefreshSuccess) {
        if success.project_default == ProjectDefaultChange::Adopted {
            self.write(sinks, ADOPTION_NOTICE);
        }
        let outcome = match &success.approval {
            ApprovalDelta::Approved(digest) => format!("approved none -> {digest}"),
            ApprovalDelta::Unchanged(digest) => format!("unchanged {digest}"),
            ApprovalDelta::Changed { old, new } => format!("changed {old} -> {new}"),
        };
        let default = match (success.project_default, &success.adopted) {
            (ProjectDefaultChange::Adopted, Some((old, new))) => {
                format!("default=adopted {old} -> {new}")
            }
            (ProjectDefaultChange::Adopted, None) => "default=adopted".to_owned(),
            (ProjectDefaultChange::Established, _) => "default=established".to_owned(),
            (ProjectDefaultChange::Unchanged, _) => "default=unchanged".to_owned(),
        };
        self.write(
            sinks,
            &format!(
                "==> pull [{}/{}] {} ({}): {outcome}; {default}",
                row.position,
                row.total,
                row.label.text(),
                row.platform
            ),
        );
    }

    fn failed(&mut self, sinks: &mut Sinks<'_>, row: &Row<'_>, error: &anyhow::Error) {
        let reason = crate::config::escape_str(&format!("{error:#}"));
        self.write(
            sinks,
            &format!(
                "==> pull [{}/{}] {} ({}): failed {reason}",
                row.position,
                row.total,
                row.label.text(),
                row.platform
            ),
        );
    }

    fn summary(&mut self, sinks: &mut Sinks<'_>, ok: usize, failed: usize) {
        self.write(
            sinks,
            &format!("==> image pull: {ok} succeeded, {failed} failed"),
        );
    }

    fn write(&mut self, sinks: &mut Sinks<'_>, row: &str) {
        if writeln!(sinks.stdout, "{row}").is_err() && !self.sink_warned {
            self.sink_warned = true;
            // Best effort, and never a target failure: the approvals this row
            // described are already committed.
            let _ = writeln!(sinks.stderr, "{REPORT_SINK_WARNING}");
        }
    }
}

/// Reject an unusable pull target from input alone.
///
/// Runs before `main`'s MSB prologue, so a CLI/env local rootfs or disk target
/// cannot create state, read configuration again, select a fallback or stat the
/// path. Every configured/default reference already satisfies the OCI policy;
/// only the two explicit inputs can be a local path or malformed, and neither
/// masks the other.
pub(crate) fn preflight(args: &Args) -> Result<()> {
    args.filter()?;
    if let Some(ambient) = args.ambient_override()? {
        OciTarget::parse(ambient.reference().as_str()).map_err(target_error)?;
    }
    Ok(())
}

/// Decide whether the registry needs `--insecure` (plain HTTP).
///
/// Two ways to get a `true`:
/// 1. `AGENT_VM_INSECURE_REGISTRY=1` env var — opt-in escape hatch
///    for airgapped/intranet plain-HTTP registries
///    (`registry.corp.example:5000`, `192.168.1.10:5000`, etc.) that
///    the heuristic can't recognise from the ref alone.
/// 2. Hostname is unambiguously local: `localhost`, `127.0.0.1`,
///    `0.0.0.0`, `*.local`, `*.localhost`.
///
/// The microsandbox SDK's `.insecure()` switches to plain HTTP, so
/// applying it to ghcr.io or any other public HTTPS registry would
/// break the pull. The heuristic stays narrow for safety; the env
/// var is the operator-blessed override.
///
/// IPv6 literal hosts are not supported here (rare for local dev
/// registries; bracketed form would need a real parser). Use
/// `localhost` or `127.0.0.1` instead.
pub(crate) fn is_plain_http_registry(image_ref: &str) -> bool {
    if crate::env_flag::enabled("AGENT_VM_INSECURE_REGISTRY") {
        return true;
    }
    // First path segment is the registry host (with optional :port).
    // If there's no `/` in the ref OR the first segment has no `.` /
    // `:` / `localhost`, the ref points at docker.io's default
    // registry and we never want insecure for that.
    let first = image_ref.split('/').next().unwrap_or("");
    // Strip the port suffix to get just the host.
    let host = first.split(':').next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "0.0.0.0")
        || host.ends_with(".local")
        || host.ends_with(".localhost")
}

/// Whether the SDK create must turn on `.insecure()` (plain-HTTP registry) for
/// this image.
///
/// Never for a **launch build** (ADR-0061): its internal `agent-vm.invalid/…`
/// name is a cache key, not a registry, and `PullPolicy::Never` forbids the
/// fetch that would need the plain-HTTP reading. Extracted from the create chain
/// so the decision is one named, testable predicate (ADR-0018's "new pure
/// function that decides a security boundary"); [`is_plain_http_registry`] keeps
/// owning what "plain HTTP" means.
pub(crate) fn registry_is_insecure(cache_only: bool, image_ref: &str) -> bool {
    !cache_only && is_plain_http_registry(image_ref)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_image::EnvOverride;

    #[test]
    fn local_registries_are_plain_http() {
        let _guard = crate::test_env::guard();
        assert!(is_plain_http_registry("localhost:5000/standard:test"));
        assert!(is_plain_http_registry("127.0.0.1:5000/x"));
        assert!(is_plain_http_registry("0.0.0.0:8080/x"));
        assert!(is_plain_http_registry("dev.local/x"));
        assert!(is_plain_http_registry("foo.localhost:5000/x"));
    }

    #[test]
    fn public_registries_are_not_plain_http() {
        let _guard = crate::test_env::guard();
        assert!(!is_plain_http_registry(
            "ghcr.io/gregwebs/agent-vm-standard:v0.1.3"
        ));
        assert!(!is_plain_http_registry("docker.io/library/debian:13"));
        assert!(!is_plain_http_registry("registry.example.com/x"));
        // Docker Hub short form has no `/` in the registry part.
        assert!(!is_plain_http_registry("nginx:latest"));
    }

    // Single test exercising the env-var escape hatch in both directions —
    // the heuristic says "secure" for `registry.corp.example` but a truthy
    // env override wins, while a falsy/unrecognised value must not (the
    // fail-closed direction, issue #65). Both directions live in one test
    // (rather than two) because `test_env::guard()` serializes across the
    // whole crate on a single mutex — splitting them would just make two
    // tests take turns for no benefit.
    #[test]
    fn env_override_forces_plain_http() {
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_INSECURE_REGISTRY", "1");
        assert!(is_plain_http_registry("registry.corp.example:5000/x"));
        assert!(is_plain_http_registry(
            "ghcr.io/gregwebs/agent-vm-standard:v0.1.3"
        ));
        env.remove_var("AGENT_VM_INSECURE_REGISTRY");
        // After cleanup the heuristic resumes its normal behaviour.
        assert!(!is_plain_http_registry("registry.corp.example:5000/x"));

        // Fail-closed direction: an explicit falsy value (or a typo that
        // isn't in `env_flag::TRUTHY`) must not be coerced into "insecure"
        // — the widened accepted set only adds new spellings of an opt-in,
        // never a new way to opt in by accident.
        for falsy in ["0", ""] {
            env.set_var("AGENT_VM_INSECURE_REGISTRY", falsy);
            assert!(
                !is_plain_http_registry("registry.corp.example:5000/x"),
                "{falsy:?} must not force plain HTTP"
            );
        }
        env.remove_var("AGENT_VM_INSECURE_REGISTRY");
    }

    /// A sink that can be closed, recording every byte it accepted.
    #[derive(Default)]
    struct Sink {
        writable: bool,
        written: String,
    }

    impl Sink {
        fn open() -> Self {
            Self {
                writable: true,
                written: String::new(),
            }
        }
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.writable {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            self.written.push_str(&String::from_utf8_lossy(bytes));
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn digest(algorithm: &str, byte: char) -> crate::image_pin::ManifestDigest {
        let hex = byte
            .to_string()
            .repeat(if algorithm == "sha256" { 64 } else { 96 });
        crate::image_pin::ManifestDigest::parse(&format!("{algorithm}:{hex}")).unwrap()
    }

    fn success(
        approval: crate::image_pin::ApprovalDelta,
        project_default: ProjectDefaultChange,
        adopted: Option<(
            crate::image_pin::ManifestDigest,
            crate::image_pin::ManifestDigest,
        )>,
    ) -> RefreshSuccess {
        RefreshSuccess {
            approval,
            project_default,
            adopted,
        }
    }

    /// The exact result rows: every approval outcome, every default suffix, the
    /// explicit escaped label and every fixed holder label, a newline-bearing
    /// error escaped onto one line, the platform variant, and the summary.
    #[test]
    fn pull_report_format_covers_all_outcomes() {
        use crate::image_pin::ApprovalDelta;
        use boot_image::ImageLabel;

        let mut report = Report::default();
        let mut stdout = Sink::open();
        let mut stderr = Sink::open();
        let mut sinks = Sinks {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        let explicit = ImageLabel::for_result_reference("example.com/team/app:dev");
        let holder = ImageLabel::for_refresh_holder(boot_image::HolderRoles::Output);
        // The default tier's fixed label, as `BootImage::label` renders it.
        let default = ImageLabel::for_tests("the default boot image");

        let old = digest("sha256", 'a');
        let new = digest("sha384", 'b');
        report.succeeded(
            &mut sinks,
            &Row {
                position: 1,
                total: 5,
                label: &explicit,
                platform: "linux/arm64/v8",
            },
            &success(
                ApprovalDelta::Approved(new.clone()),
                ProjectDefaultChange::Established,
                None,
            ),
        );
        report.succeeded(
            &mut sinks,
            &Row {
                position: 2,
                total: 5,
                label: &holder,
                platform: "linux/arm64",
            },
            &success(
                ApprovalDelta::Changed {
                    old: old.clone(),
                    new: new.clone(),
                },
                ProjectDefaultChange::Unchanged,
                None,
            ),
        );
        report.succeeded(
            &mut sinks,
            &Row {
                position: 3,
                total: 5,
                label: &default,
                platform: "linux/arm64",
            },
            &success(
                ApprovalDelta::Unchanged(old.clone()),
                ProjectDefaultChange::Adopted,
                Some((old.clone(), new.clone())),
            ),
        );
        report.failed(
            &mut sinks,
            &Row {
                position: 4,
                total: 5,
                label: &holder,
                platform: "linux/arm64",
            },
            &anyhow!("line one\nline two"),
        );
        report.failed(
            &mut sinks,
            &Row {
                position: 5,
                total: 5,
                label: &default,
                platform: "linux/arm64",
            },
            &anyhow!("pulling the default boot image: unavailable"),
        );
        report.summary(&mut sinks, 3, 2);

        assert_eq!(
            stdout.written,
            concat!(
                "==> pull [1/5] example.com/team/app:dev (linux/arm64/v8): approved none -> sha384:",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; default=established\n",
                "==> pull [2/5] the latest output image (linux/arm64): changed sha256:",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -> sha384:",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; default=unchanged\n",
                "==> this project now uses the host's default boot image\n",
                "==> pull [3/5] the default boot image (linux/arm64): unchanged sha256:",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; default=adopted sha256:",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -> sha384:",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                "==> pull [4/5] the latest output image (linux/arm64): failed line one\\x0aline two\n",
                "==> pull [5/5] the default boot image (linux/arm64): failed pulling the default boot image: unavailable\n",
                "==> image pull: 3 succeeded, 2 failed\n",
            )
        );
        assert_eq!(stderr.written, "");
    }

    #[test]
    fn pull_report_acquisition_errors_have_one_failed_verb() {
        use crate::image_acquire::{
            AcquireError, AcquireStage, ReferenceStage, RollbackOutcome, ValidationError,
        };
        use crate::image_pin::{Rendering, render_failure};

        let redacted = boot_image::ImageLabel::for_refresh_holder(boot_image::HolderRoles::Boot);
        let explicit = boot_image::ImageLabel::for_result_reference("example.com/team/app:dev");
        let reference = "example.com/team/app:dev";
        let rows = [
            (
                &redacted,
                render_failure(
                    &redacted,
                    Rendering::Selection,
                    reference,
                    AcquireError::Native {
                        stage: AcquireStage::Pull,
                        source: microsandbox_image::ImageError::Io(std::io::Error::other(
                            "record-sourced native failure",
                        )),
                    },
                ),
                "==> pull [1/1] the recorded boot image (linux/arm64): failed pulling the recorded boot image: the registry may be unreachable or the content unavailable\n",
            ),
            (
                &explicit,
                render_failure(
                    &explicit,
                    Rendering::Selection,
                    reference,
                    AcquireError::Native {
                        stage: AcquireStage::Pull,
                        source: microsandbox_image::ImageError::ManifestParse(
                            "explicit native failure".to_string(),
                        ),
                    },
                ),
                "==> pull [1/1] example.com/team/app:dev (linux/arm64): failed acquiring the image: manifest parse error: explicit native failure\n",
            ),
            (
                &redacted,
                render_failure(
                    &redacted,
                    Rendering::Selection,
                    reference,
                    AcquireError::ReferenceState {
                        stage: ReferenceStage::Snapshot,
                        source: anyhow!("record-sourced metadata failure"),
                    },
                ),
                "==> pull [1/1] the recorded boot image (linux/arm64): failed snapshotting cached reference metadata: did not complete\n",
            ),
            (
                &redacted,
                render_failure(
                    &redacted,
                    Rendering::Selection,
                    reference,
                    AcquireError::PostValidation {
                        source: ValidationError::Identity,
                        rollback: RollbackOutcome::Restored,
                    },
                ),
                "==> pull [1/1] the recorded boot image (linux/arm64): failed image cache post-acquisition validation: the previous reference metadata was restored; retry the image acquisition\n",
            ),
            (
                &explicit,
                render_failure(
                    &explicit,
                    Rendering::Selection,
                    reference,
                    AcquireError::Native {
                        stage: AcquireStage::Pull,
                        source: microsandbox_image::ImageError::Registry(
                            std::io::Error::other("explicit registry failure").into(),
                        ),
                    },
                ),
                concat!(
                    "==> pull [1/1] example.com/team/app:dev (linux/arm64): failed acquiring example.com/team/app:dev from its registry\\x0a\\x0a",
                    "hint: an image that exists only in your local Docker daemon is not visible to\\x0a",
                    "agent-vm until it is imported into agent-vm's own image cache:\\x0a",
                    "  agent-vm image import --docker example.com/team/app:dev --tag example.com/team/app:dev\\x0a",
                    "A completed OCI or Docker-save archive works too:\\x0a",
                    "  agent-vm image import --input <FILE> --tag example.com/team/app:dev\\x0a",
                    "The imported reference must match the --image value exactly.: acquiring the image: registry error: explicit registry failure: explicit registry failure\n",
                ),
            ),
        ];

        for (label, error, expected) in rows {
            let mut report = Report::default();
            let mut stdout = Sink::open();
            let mut stderr = Sink::open();
            let mut sinks = Sinks {
                stdout: &mut stdout,
                stderr: &mut stderr,
            };
            report.failed(
                &mut sinks,
                &Row {
                    position: 1,
                    total: 1,
                    label,
                    platform: "linux/arm64",
                },
                &error,
            );
            assert_eq!(stdout.written, expected);
            assert_eq!(stderr.written, "");
        }
    }

    /// A closed report sink is a bounded warning, never a target failure and
    /// never a panic: the next operation still runs and the exit status follows
    /// the operations alone.
    #[test]
    fn pull_report_sink_failure_keeps_committed_success() {
        use crate::image_pin::ApprovalDelta;

        let mut report = Report::default();
        let mut stdout = Sink::default();
        let mut stderr = Sink::open();
        let mut sinks = Sinks {
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        let label = boot_image::ImageLabel::for_result_reference("example.com/team/app:dev");
        let row = |position| Row {
            position,
            total: 2,
            label: &label,
            platform: "linux/arm64",
        };
        for position in [1, 2] {
            report.succeeded(
                &mut sinks,
                &row(position),
                &success(
                    ApprovalDelta::Unchanged(digest("sha256", 'a')),
                    ProjectDefaultChange::Unchanged,
                    None,
                ),
            );
        }
        report.summary(&mut sinks, 2, 0);
        // Exactly one warning, attempted once, naming what not to do.
        assert_eq!(stderr.written, format!("{REPORT_SINK_WARNING}\n"));
        assert!(
            stderr
                .written
                .contains("do not retry it as a failed approval")
        );
        assert!(!stderr.written.contains("nothing was approved"));
        // Failed warning delivery is ignored rather than propagated.
        let mut closed = Sink::default();
        let mut also_closed = Sink::default();
        let mut sinks = Sinks {
            stdout: &mut closed,
            stderr: &mut also_closed,
        };
        report.summary(&mut sinks, 2, 0);
    }

    fn args_with(value: Option<&str>, ambient: EnvOverride) -> Args {
        Args::for_test(value, ambient)
    }

    #[test]
    fn preflight_refuses_local_targets_and_accepts_oci_references() {
        assert!(preflight(&args_with(None, EnvOverride::Unset)).is_ok());
        assert!(preflight(&args_with(Some("alpine:latest"), EnvOverride::Unset)).is_ok());
        for local in ["/abs/rootfs", "./rootfs", "..", "/tmp/img.disk"] {
            let error = preflight(&args_with(Some(local), EnvOverride::Unset)).unwrap_err();
            assert_eq!(error.to_string(), TARGET_REASON);
            assert!(error.to_string().contains("agent-vm --image PATH <tool>"));
            assert!(!error.to_string().contains(local));
        }
        // A malformed reference is not a local launch target and must get the
        // reference-shape refusal instead of local-launch advice.
        for malformed in ["Foo/Bar:tag", "repo:bad tag", "repo@sha256:short"] {
            let error = preflight(&args_with(Some(malformed), EnvOverride::Unset)).unwrap_err();
            assert_eq!(error.to_string(), INVALID_REFERENCE_REASON);
            assert!(!error.to_string().contains("agent-vm --image PATH <tool>"));
            assert!(!error.to_string().contains(malformed));
        }
    }

    #[test]
    fn preflight_refuses_a_typed_empty_target() {
        let error = preflight(&args_with(Some(""), EnvOverride::Unset)).unwrap_err();
        assert!(error.to_string().contains("must not be empty"), "{error}");
    }

    /// The exact conjunction behind `.insecure()`, over all four combinations.
    /// A cache-only selection (a launch build) is never plain-HTTP, whatever the
    /// reference looks like.
    ///
    /// Takes the env guard for the same reason as its siblings: the predicate
    /// reads `AGENT_VM_INSECURE_REGISTRY`, which another test in this module sets.
    #[test]
    fn insecure_needs_a_non_cache_only_plain_http_reference() {
        let _guard = crate::test_env::guard();
        for (cache_only, reference, expected) in [
            (false, "registry.local:5000/app:1", true),
            (false, "ghcr.io/o/app:1", false),
            (true, "registry.local:5000/app:1", false),
            (true, "ghcr.io/o/app:1", false),
        ] {
            assert_eq!(
                registry_is_insecure(cache_only, reference),
                expected,
                "cache_only={cache_only} reference={reference}"
            );
        }
    }
}
