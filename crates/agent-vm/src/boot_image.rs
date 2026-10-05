//! Selects the one **boot image** a session uses.
//!
//! The image is a property of the *session*, not of the launched tool: a tool
//! is a runtime declaration describing how to launch software the image already
//! contains (see CONTEXT.md → *Tool* / *Boot image*). This module owns the one
//! precedence order every verb shares —
//!
//! ```text
//! --image  >  AGENT_VM_IMAGE_TAG (empty = unset)  >  user image  >  project image  >  default
//! ```
//!
//! — so `run`, `pull`, `setup` and `doctor` cannot disagree about which image a
//! session boots. The **catalog is deliberately not an input**: changing the
//! runtime tool declaration must never change the image (issue #259).
//!
//! # The default slot: a recommendation, then a retained selection
//!
//! The last slot is not a compiled-in string. It is a persisted, user-scoped
//! **retained default** ([`default_selection`]) with a fallback: an **absent**
//! record is offered the **initial recommendation**, and only a launch that
//! actually *acquires* that reference's content records it. A record that
//! exists but is unreadable, non-regular or invalid is a **hard error**, never a
//! reset to the recommendation (that would silently discard the user's choice).
//! Two consequences are deliberate and load-bearing (#261):
//!
//! * selection is lazy and read-only — `help` and a launch that a higher source
//!   wins evaluate no record and write nothing; `doctor` reads the record once,
//!   *observationally*, to report it (it still creates nothing);
//! * a failed initial acquisition leaves the record **absent**, so a later,
//!   compatible recommendation (e.g. a future multiarch release) can rescue the
//!   user instead of stranding them on bytes their host cannot boot.
//!
//! # The default tier is not display data
//!
//! The default reference is record-sourced (or the launcher's recommendation on
//! an uninitialized host) and may name a private registry. [`BootImage::label`]
//! is therefore the one place that turns a selection into user-facing text: an
//! explicit source is its escaped reference plus origin, but the default tier is
//! a fixed label. The actual [`ImageRef`] still goes to the SDK unchanged; only
//! *display* redacts it.
//!
//! # Config-file images are OCI-only
//!
//! A `--image`/`AGENT_VM_IMAGE_TAG` value is passed through as-is (non-empty,
//! NUL-free), preserving today's ability to boot a local rootfs directory or a
//! disk image. A config-file `image` is stricter: it must be an OCI reference.
//! The reason is a security boundary, not a convenience — the SDK treats a
//! leading `/`, `./`, `../`, `.` or `..` as a **host rootfs bind or disk
//! image** (`ImageSource::into_rootfs_source`), so a repo-supplied
//! `.agent-vm/config.toml` with `image = "/"` would otherwise boot the host
//! root filesystem as a writable guest rootfs. The config acceptance decision is
//! the contracted [`config_image_is_acceptable`] kernel; the OCI parser, the
//! SDK's path predicate and the Unicode character measurement are the trusted
//! adapters that feed it. The command-line/env pass-through has its own, smaller
//! contracted kernel, [`override_image_is_acceptable`], so that "the parse of
//! untrusted input" is machine-checked on both boundaries (ADR-0018).
//!
//! A third boundary is the **immutable reference**: every reference this module
//! *stores* or *recommends* (the retained record and the initial recommendation)
//! must be pinned by digest, so exact content — not a moving tag — is what a
//! user retains. [`immutable_image_is_acceptable`] is that contraction.

use std::fmt;
use std::path::PathBuf;

use anyhow::{Result, bail};
use vstd::prelude::*;

use crate::config::ConfiguredImages;

mod default_selection;

/// A boot-image reference, validated at its boundary.
///
/// The two constructors encode the two policies: [`ImageRef::from_override`]
/// is the permissive command-line/env pass-through; [`ImageRef::from_config`]
/// is the OCI-only config-file rule. The text is stored **exactly** as given —
/// never trimmed or normalized — so what the user typed is what boots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageRef(String);

impl ImageRef {
    /// `--image` / `AGENT_VM_IMAGE_TAG`: whatever msb accepts today (an OCI
    /// reference, a local rootfs directory, or a disk image). Non-empty and
    /// NUL-free; nothing else, so a user who today boots `--image ./rootfs` is
    /// not regressed.
    pub(crate) fn from_override(raw: String) -> anyhow::Result<Self> {
        let empty = raw.is_empty();
        let facts = OverrideImageFacts {
            nonempty: !empty,
            has_nul: raw.contains('\0'),
        };
        if !override_image_is_acceptable(facts) {
            // The kernel rejected; report which measured fact failed.
            if empty {
                bail!("image reference must not be empty");
            }
            bail!("image reference must not contain NUL");
        }
        Ok(Self(raw))
    }

    /// A config-file `image`: an OCI reference only. The error is a fixed
    /// reason that names no value, because the supplied text is untrusted
    /// config input and must not be echoed (config.rs's diagnostics policy).
    pub(crate) fn from_config(raw: &str) -> Result<Self, &'static str> {
        let facts = ConfigImageFacts {
            oci_valid: raw.parse::<microsandbox_image::Reference>().is_ok(),
            sdk_local_path: microsandbox_utils::looks_like_local_path_text(raw),
            characters_ok: !raw.is_empty()
                && !raw
                    .chars()
                    .any(|character| character.is_whitespace() || character.is_control()),
        };
        if config_image_is_acceptable(facts) {
            Ok(Self(raw.to_string()))
        } else {
            Err(
                "must be an OCI image reference (e.g. ghcr.io/owner/name:tag or \
                 repo@sha256:…); a local path is not accepted here — use --image for a local \
                 rootfs",
            )
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A boot-image reference whose *identity is exact content*: an OCI reference
/// carrying a digest.
///
/// This is the type every reference agent-vm **persists or recommends** must
/// cross, so a moving tag can never be mistaken for a retention: `repo:tag`
/// names whatever the registry serves next, `repo@sha256:…` names bytes. It is
/// deliberately not constructible from a `String` — the only entry point is
/// [`ImmutableImageRef::parse`], which reuses the config-image policy and then
/// requires the OCI parser to see a digest.
///
/// It is *never* display data: `Debug` redacts the reference (only
/// [`BootImage::label`] decides what user-facing text may say).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ImmutableImageRef(ImageRef);

impl fmt::Debug for ImmutableImageRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImmutableImageRef(<redacted reference>)")
    }
}

impl ImmutableImageRef {
    /// Parse `raw` as an immutable OCI reference, or reject it with a fixed
    /// reason that names no value (the text is untrusted input).
    ///
    /// The text is retained **exactly** as given. `repo:tag@sha256:…` is
    /// accepted because the digest still fixes identity; a tag *without* a
    /// digest is not. Digest grammar is the OCI parser's own — narrower than
    /// the permissive `microsandbox_image::Digest::from_str`.
    pub(crate) fn parse(raw: &str) -> Result<Self, &'static str> {
        let config_acceptable = ImageRef::from_config(raw).is_ok();
        let has_digest = raw
            .parse::<microsandbox_image::Reference>()
            .map(|reference| reference.digest().is_some())
            .unwrap_or(false);
        let facts = ImmutableImageFacts {
            config_acceptable,
            has_digest,
        };
        if immutable_image_is_acceptable(facts) {
            Ok(Self(ImageRef(raw.to_string())))
        } else {
            Err("must be an immutable OCI image reference pinned by digest \
                 (e.g. registry.example/name@sha256:…); a moving tag or a local path cannot be \
                 retained as a default")
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn into_image_ref(self) -> ImageRef {
        self.0
    }
}

/// Where the selected image came from. The file-backed variants carry the
/// declaring config path so diagnostics can name it without a second,
/// same-typed parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ImageSource {
    /// `--image`.
    CommandLine,
    /// `AGENT_VM_IMAGE_TAG`.
    Environment,
    /// `image` in `$HOME/.config/agent-vm/config.toml`.
    UserConfig(PathBuf),
    /// `image` in `<cwd>/.agent-vm/config.toml`.
    ProjectConfig(PathBuf),
    /// The compiled-in default boot image ([`default_image`]).
    Default,
}

impl ImageSource {
    /// The source as rendered after the reference, e.g. `command line` or
    /// `user config /home/dev/.config/agent-vm/config.toml`.
    pub(crate) fn describe(&self) -> String {
        match self {
            ImageSource::CommandLine => "command line".to_string(),
            ImageSource::Environment => "AGENT_VM_IMAGE_TAG".to_string(),
            ImageSource::UserConfig(file) => {
                format!("user config {}", crate::config::escape_path(file))
            }
            ImageSource::ProjectConfig(file) => {
                format!("project config {}", crate::config::escape_path(file))
            }
            ImageSource::Default => "default".to_string(),
        }
    }
}

/// The image selected for one session.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BootImage {
    reference: ImageRef,
    source: ImageSource,
}

impl BootImage {
    pub(crate) fn reference(&self) -> &ImageRef {
        &self.reference
    }

    pub(crate) fn source(&self) -> &ImageSource {
        &self.source
    }

    /// True when no user source chose the image.
    pub(crate) fn is_default(&self) -> bool {
        matches!(self.source, ImageSource::Default)
    }

    /// The safe, user-facing name for this selection.
    ///
    /// An explicit source (CLI/env/user/project) is the user's own input and is
    /// rendered as its escaped reference and origin. The default tier is
    /// record- or recommendation-sourced, so it is a fixed label: this is the
    /// one seam every notice, progress line, debug dump and acquisition failure
    /// goes through, rather than each caller re-deciding. The actual reference
    /// still reaches the SDK via [`BootImage::reference`].
    pub(crate) fn label(&self) -> ImageLabel {
        if self.is_default() {
            ImageLabel {
                text: "the default boot image".to_string(),
                origin: None,
                redacted: true,
            }
        } else {
            ImageLabel {
                text: crate::config::escape_str(self.reference.as_str()),
                origin: Some(self.source.describe()),
                redacted: false,
            }
        }
    }
}

impl fmt::Display for BootImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.label())
    }
}

impl fmt::Debug for BootImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootImage")
            .field("label", &self.label().text())
            .field("source", &self.source.describe())
            .finish()
    }
}

/// [`BootImage::label`]'s result: the safe text plus whether the underlying
/// reference was redacted. Callers that build sanitized diagnostics (the debug
/// config dump, progress rendering, acquisition-error chains) use `redacted` to
/// decide whether to drop the reference-carrying data; the text is what a user
/// may see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ImageLabel {
    /// The reference text for an explicit source, or the fixed label for the
    /// default tier. Always safe to render on its own.
    text: String,
    /// The escaped origin, for the `"… (from …)"` form. `None` for the default
    /// tier, whose label stands alone.
    origin: Option<String>,
    redacted: bool,
}

impl fmt::Display for ImageLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.origin {
            Some(origin) => write!(formatter, "{} (from {})", self.text, origin),
            None => formatter.write_str(&self.text),
        }
    }
}

impl ImageLabel {
    /// The reference for an explicit source or the fixed label for the default
    /// tier — without the `(from …)` origin.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// A plain explicit label, for unit tests that exercise a caller's message
    /// shape without building a whole selection.
    #[cfg(test)]
    pub(crate) fn for_tests(text: &str) -> Self {
        Self {
            text: text.to_string(),
            origin: None,
            redacted: false,
        }
    }

    /// True when the selected reference came from the default tier and must not
    /// be rendered, logged or chained into an error.
    pub(crate) fn is_redacted(&self) -> bool {
        self.redacted
    }

    /// Map an image-bearing failure to a fixed, stage-specific reason when the
    /// reference is redacted, discarding the source chain (which embeds the
    /// reference in registry URLs). `stage` names what was being attempted, so
    /// the failure stays useful without the reference. Explicit sources keep
    /// their error unchanged.
    pub(crate) fn redact_error(&self, stage: &str, error: anyhow::Error) -> anyhow::Error {
        if self.redacted {
            anyhow::anyhow!(
                "{stage} {} failed; the registry may be unreachable or the content unavailable",
                self.text
            )
        } else {
            error
        }
    }
}

/// An explicit per-invocation override (CLI or env), already reconciled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageOverride {
    reference: ImageRef,
    source: OverrideSource,
}

impl ImageOverride {
    pub(crate) fn reference(&self) -> &ImageRef {
        &self.reference
    }

    #[cfg(test)]
    pub(crate) fn source(&self) -> OverrideSource {
        self.source
    }
}

/// Which per-invocation slot supplied an [`ImageOverride`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverrideSource {
    CommandLine,
    Environment,
}

impl From<OverrideSource> for ImageSource {
    fn from(source: OverrideSource) -> Self {
        match source {
            OverrideSource::CommandLine => ImageSource::CommandLine,
            OverrideSource::Environment => ImageSource::Environment,
        }
    }
}

/// The `--image` argument, flattened into `run::Args`, `pull::Args` and
/// `setup::Args` so the flag, its env binding and its help text exist once.
#[derive(clap::Args, Debug, Default)]
pub(crate) struct ImageArgs {
    /// Boot this image instead of the configured one.
    ///
    /// Precedence: this flag (or `AGENT_VM_IMAGE_TAG`), then the user config
    /// `image`, then the project config `image`, then the default boot image.
    /// See USAGE.md → "Selecting the boot image".
    #[arg(
        long = "image",
        env = "AGENT_VM_IMAGE_TAG",
        value_name = "REF",
        help_heading = "Image"
    )]
    image: Option<String>,

    /// Filled by `cli` from clap's value source; never a command-line argument.
    #[arg(skip)]
    origin: Option<OverrideSource>,
}

impl ImageArgs {
    /// Record whether the value came from the command line or the environment,
    /// and apply ADR-0028's surviving rule: an **empty** `AGENT_VM_IMAGE_TAG`
    /// counts as unset. A typed `--image ''` stays present (and fails at the
    /// override boundary), because the user wrote it.
    pub(crate) fn reconcile(&mut self, matches: &clap::ArgMatches) {
        self.origin = match matches.value_source("image") {
            Some(clap::parser::ValueSource::CommandLine) => Some(OverrideSource::CommandLine),
            Some(clap::parser::ValueSource::EnvVariable) => {
                if self.image.as_deref() == Some("") {
                    self.image = None;
                    None
                } else {
                    Some(OverrideSource::Environment)
                }
            }
            // Default value (none) or not supplied.
            _ => None,
        };
    }

    /// The override this invocation requested, if any. `Err` for a typed value
    /// that is empty or NUL-bearing, and — because the two fields are set
    /// together — for a value clap filled but `reconcile` never normalized.
    /// That last case is an internal wiring bug, and rejecting it here keeps a
    /// missing reconciliation from silently looking like an absent flag.
    pub(crate) fn requested(&self) -> anyhow::Result<Option<ImageOverride>> {
        match (&self.image, self.origin) {
            (Some(raw), Some(source)) => Ok(Some(ImageOverride {
                reference: ImageRef::from_override(raw.clone())?,
                source,
            })),
            // reconcile clears `image` together with `origin` for an empty env,
            // so this pair is the absent case.
            (None, None) => Ok(None),
            (Some(_), None) => bail!(
                "internal error: a supplied --image/AGENT_VM_IMAGE_TAG was not reconciled; \
                 refusing to drop it"
            ),
            (None, Some(_)) => bail!("internal error: an image origin has no image value"),
        }
    }
}

/// `doctor` has no `--image`; it reads the env through the same
/// empty-is-unset rule so it cannot disagree with a launch's environment slot.
pub(crate) fn env_override(value: Option<&str>) -> anyhow::Result<Option<ImageOverride>> {
    match value {
        None | Some("") => Ok(None),
        Some(raw) => Ok(Some(ImageOverride {
            reference: ImageRef::from_override(raw.to_string())?,
            source: OverrideSource::Environment,
        })),
    }
}

/// `doctor`'s read of `AGENT_VM_IMAGE_TAG`, distinguishing an **unset** variable
/// from one that is present but not valid Unicode. Every other verb binds the
/// variable through clap's `String` argument and fails on a non-Unicode value;
/// using `std::env::var(..).ok()` here would make `doctor` the one verb that
/// silently reports an invalid override as absent and then prints a selection
/// no launch would make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnvOverride {
    Unset,
    Present(ImageOverride),
    Invalid,
}

/// Read `AGENT_VM_IMAGE_TAG` for `doctor` through [`EnvOverride`].
pub(crate) fn doctor_env_override() -> EnvOverride {
    match std::env::var("AGENT_VM_IMAGE_TAG") {
        Ok(value) => match env_override(Some(&value)) {
            Ok(Some(override_)) => EnvOverride::Present(override_),
            Ok(None) => EnvOverride::Unset,
            // A present value rejected by the override boundary (not currently
            // reachable: an env var cannot carry NUL) is still not absent.
            Err(_) => EnvOverride::Invalid,
        },
        Err(std::env::VarError::NotPresent) => EnvOverride::Unset,
        Err(std::env::VarError::NotUnicode(_)) => EnvOverride::Invalid,
    }
}

/// The sole selection owner: first present source wins. Fallible because the
/// default slot's retained record is host state that can be corrupt, and a
/// fallback to the initial recommendation can itself be malformed. The default
/// slot is read lazily: [`select_with`] evaluates its thunk only when every
/// higher slot is absent, so `--image`/env/user/project never touch the record.
pub(crate) fn select(
    requested: Option<ImageOverride>,
    configured: &ConfiguredImages,
) -> Result<BootImage> {
    select_with(requested, configured, default_slot)
}

/// [`select`] with the default slot supplied as a thunk, so the precedence
/// table is testable without touching host state. The thunk runs only on the
/// last branch; every higher-precedence branch returns `Ok` without calling it.
fn select_with(
    requested: Option<ImageOverride>,
    configured: &ConfiguredImages,
    default: impl FnOnce() -> Result<ImageRef>,
) -> Result<BootImage> {
    if let Some(requested) = requested {
        return Ok(BootImage {
            reference: requested.reference,
            source: requested.source.into(),
        });
    }
    if let Some(image) = configured.user() {
        return Ok(BootImage {
            reference: image.reference().clone(),
            source: ImageSource::UserConfig(image.file().to_path_buf()),
        });
    }
    if let Some(image) = configured.project() {
        return Ok(BootImage {
            reference: image.reference().clone(),
            source: ImageSource::ProjectConfig(image.file().to_path_buf()),
        });
    }
    // The default tier's reference must not reach lower-level (dependency)
    // tracing; arm the process-level guard before any acquisition.
    crate::image_log_guard::activate();
    Ok(BootImage {
        reference: default()?,
        source: ImageSource::Default,
    })
}

/// The default slot's reference: the retained user selection when a record
/// exists, otherwise the initial recommendation. Read-only — neither branch
/// writes, so an absent record stays absent until a launch acquires content.
fn default_slot() -> Result<ImageRef> {
    match default_selection::load()? {
        Some(retained) => Ok(retained.into_image_ref()),
        None => Ok(default_selection::initial_recommendation()?.into_image_ref()),
    }
}

/// Record the selected default image as the user's retained default.
///
/// A no-op unless `image` came from the default tier, and a first-writer-wins
/// no-op inside [`default_selection::adopt`] when a valid record already
/// exists. Callers invoke this **after** the image content is acquired:
/// retaining a reference whose bytes were never obtained would strand the user
/// on an unbootable default.
pub(crate) fn adopt_default_selection(image: &BootImage) -> Result<()> {
    if !image.is_default() {
        return Ok(());
    }
    // Only the default tier reaches here, and [`default_slot`] produced its
    // reference through [`ImmutableImageRef::parse`]; a rejection is an
    // internal invariant break, not user input.
    let reference = ImmutableImageRef::parse(image.reference().as_str())
        .map_err(|reason| anyhow::anyhow!("selected default image cannot be retained: {reason}"))?;
    default_selection::adopt(&reference)
}

/// One read-only snapshot of the default slot, for diagnostics.
///
/// `doctor` needs both "what is retained?" and "what would be selected?" from
/// the *same* read, so a concurrent writer cannot make the two rows disagree.
///
/// `Debug` redacts the reference in [`DefaultObservation::Retained`] and
/// [`DefaultObservation::Uninitialized`]: a debug print is still an output sink.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum DefaultObservation {
    /// A valid record selects `reference`.
    Retained {
        reference: ImmutableImageRef,
        path: PathBuf,
    },
    /// No record yet; `reference` is the offered initial recommendation.
    Uninitialized {
        recommendation: ImmutableImageRef,
        path: PathBuf,
    },
    /// The record or recommendation could not be used. `message` is a safe,
    /// contextual diagnostic: a fixed reason and an escaped path, never the
    /// record's bytes or a rejected value.
    Unavailable { message: String },
}

impl fmt::Debug for DefaultObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retained { path, .. } => formatter
                .debug_struct("Retained")
                .field("reference", &"<redacted reference>")
                .field("path", path)
                .finish(),
            Self::Uninitialized { path, .. } => formatter
                .debug_struct("Uninitialized")
                .field("recommendation", &"<redacted recommendation>")
                .field("path", path)
                .finish(),
            Self::Unavailable { message } => formatter
                .debug_struct("Unavailable")
                .field("message", message)
                .finish(),
        }
    }
}

/// The default slot's state plus the effective selection, from one snapshot.
#[derive(Debug)]
pub(crate) struct BootImageObservation {
    pub(crate) default: DefaultObservation,
    pub(crate) selected: Result<BootImage>,
}

/// Observe selection without mutating anything: no directory, no lock, no
/// record. A valid higher source can still yield `Ok(selected)` alongside an
/// [`DefaultObservation::Unavailable`] default — the damage is reported, but it
/// did not decide this session's image.
pub(crate) fn observe(
    requested: Option<ImageOverride>,
    configured: &ConfiguredImages,
) -> BootImageObservation {
    let snapshot = default_selection::record_path()
        .and_then(|path| default_selection::load().map(|selection| (path, selection)));
    let (default, slot) = match snapshot {
        Ok((path, Some(retained))) => {
            let slot = Ok(retained.clone().into_image_ref());
            (
                DefaultObservation::Retained {
                    reference: retained,
                    path,
                },
                slot,
            )
        }
        Ok((path, None)) => match default_selection::initial_recommendation() {
            Ok(recommendation) => {
                let slot = Ok(recommendation.clone().into_image_ref());
                (
                    DefaultObservation::Uninitialized {
                        recommendation,
                        path,
                    },
                    slot,
                )
            }
            // The store's errors are already the safe adapter's output: a
            // fixed reason plus an escaped path, with no source chain. `{:#}`
            // and `{}` are therefore the same text and carry nothing unsafe.
            Err(error) => (
                DefaultObservation::Unavailable {
                    message: format!("{error:#}"),
                },
                Err(error),
            ),
        },
        Err(error) => (
            DefaultObservation::Unavailable {
                message: format!("{error:#}"),
            },
            Err(error),
        ),
    };
    let selected = select_with(requested, configured, move || slot);
    BootImageObservation { default, selected }
}

verus! {

/// The two already-measured facts [`ImageRef::from_override`] decides on: the
/// text is non-empty and carries no NUL. Named fields rather than adjacent
/// `bool` parameters, so an argument swap cannot invert a decision.
pub(crate) struct OverrideImageFacts {
    pub(crate) nonempty: bool,
    pub(crate) has_nul: bool,
}

/// The `--image`/`AGENT_VM_IMAGE_TAG` acceptance decision, contracted
/// (ADR-0018): accept **iff** the text is non-empty and NUL-free. Total over all
/// four Boolean combinations; accepting never bypasses a check.
pub(crate) fn override_image_is_acceptable(facts: OverrideImageFacts) -> (accepted: bool)
    ensures
        accepted == (facts.nonempty && !facts.has_nul),
        accepted ==> facts.nonempty && !facts.has_nul,
{
    facts.nonempty && !facts.has_nul
}

/// The three already-measured facts [`ImageRef::from_config`] decides on. Named
/// fields rather than adjacent same-typed `bool` parameters, so an argument
/// swap cannot silently invert a security check.
pub(crate) struct ConfigImageFacts {
    pub(crate) oci_valid: bool,
    pub(crate) sdk_local_path: bool,
    pub(crate) characters_ok: bool,
}

/// The config-image acceptance decision, contracted (ADR-0018): accept **iff**
/// the OCI parser accepts the text, the SDK does not classify it as a host
/// path, and the local character policy holds. Total over all eight Boolean
/// combinations; accepting never bypasses a check.
pub(crate) fn config_image_is_acceptable(facts: ConfigImageFacts) -> (accepted: bool)
    ensures
        accepted == (facts.oci_valid && !facts.sdk_local_path && facts.characters_ok),
        accepted ==> facts.oci_valid && !facts.sdk_local_path && facts.characters_ok,
{
    facts.oci_valid && !facts.sdk_local_path && facts.characters_ok
}

/// The two already-measured facts [`ImmutableImageRef::parse`] decides on: the
/// text is acceptable as a config image and the OCI parser saw a digest. Named
/// fields rather than adjacent `bool` parameters, so an argument swap cannot
/// invert "this reference names exact content".
pub(crate) struct ImmutableImageFacts {
    pub(crate) config_acceptable: bool,
    pub(crate) has_digest: bool,
}

/// The immutable-reference acceptance decision, contracted (ADR-0018): accept
/// **iff** the text is an acceptable config image and carries a digest. Total
/// over all four Boolean combinations; accepting never bypasses a check.
pub(crate) fn immutable_image_is_acceptable(facts: ImmutableImageFacts) -> (accepted: bool)
    ensures
        accepted == (facts.config_acceptable && facts.has_digest),
        accepted ==> facts.config_acceptable && facts.has_digest,
{
    facts.config_acceptable && facts.has_digest
}

} // verus!

#[cfg(test)]
mod tests {
    use super::default_selection::initial_recommendation;
    use super::*;
    use crate::config::{ConfiguredImage, ConfiguredImages, ImageTierFixture};
    use crate::defaults;
    use proptest::prelude::*;

    fn configured_user(reference: &str) -> ConfiguredImages {
        ConfiguredImages::for_test(ImageTierFixture {
            user: Some(ConfiguredImage::for_test(
                reference,
                "/home/u/.config/agent-vm/config.toml",
            )),
            project: None,
        })
    }

    fn override_for(reference: &str, source: OverrideSource) -> ImageOverride {
        ImageOverride {
            reference: ImageRef::from_override(reference.to_string()).unwrap(),
            source,
        }
    }

    /// The tuple table is clearer than a struct with five same-shaped fields;
    /// the type-complexity lint is not useful for a literal truth table.
    #[allow(clippy::type_complexity)]
    #[test]
    fn precedence_table_first_present_source_wins() {
        // (requested, user, project) -> (reference, source)
        let cases: Vec<(
            Option<OverrideSource>,
            Option<&str>,
            Option<&str>,
            &str,
            SourceCase,
        )> = vec![
            (
                Some(OverrideSource::CommandLine),
                Some("localhost:1/u:latest"),
                Some("localhost:1/p:latest"),
                "localhost:1/c:latest",
                SourceCase::CommandLine,
            ),
            (
                Some(OverrideSource::Environment),
                Some("localhost:1/u:latest"),
                Some("localhost:1/p:latest"),
                "localhost:1/e:latest",
                SourceCase::Environment,
            ),
            (
                None,
                Some("localhost:1/u:latest"),
                Some("localhost:1/p:latest"),
                "localhost:1/u:latest",
                SourceCase::User,
            ),
            (
                None,
                None,
                Some("localhost:1/p:latest"),
                "localhost:1/p:latest",
                SourceCase::Project,
            ),
            (
                None,
                None,
                None,
                "localhost:1/d:latest",
                SourceCase::Default,
            ),
        ];
        for (requested_source, user, project, expected, source) in cases {
            let configured = ConfiguredImages::for_test(ImageTierFixture {
                user: user.map(|r| ConfiguredImage::for_test(r, "/u/config.toml")),
                project: project.map(|r| ConfiguredImage::for_test(r, "/p/.agent-vm/config.toml")),
            });
            let requested = requested_source.map(|s| override_for(expected, s));
            let boot = select_with(requested, &configured, || {
                Ok(ImageRef::from_override("localhost:1/d:latest".to_string()).unwrap())
            })
            .unwrap();
            assert_eq!(boot.reference().as_str(), expected);
            match source {
                SourceCase::CommandLine => assert_eq!(boot.source(), &ImageSource::CommandLine),
                SourceCase::Environment => assert_eq!(boot.source(), &ImageSource::Environment),
                SourceCase::User => assert!(matches!(boot.source(), ImageSource::UserConfig(_))),
                SourceCase::Project => {
                    assert!(matches!(boot.source(), ImageSource::ProjectConfig(_)))
                }
                SourceCase::Default => assert!(boot.is_default()),
            }
        }
    }

    enum SourceCase {
        CommandLine,
        Environment,
        User,
        Project,
        Default,
    }

    /// A released build must ignore the debug-only initial-recommendation
    /// seam, and the seam is itself held to the immutable-reference rule: an
    /// unpinned value is rejected, never lossily converted.
    #[test]
    fn a_release_build_ignores_the_test_default_image_seam() {
        const SEAM: &str = "localhost:1/seam@sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_TEST_DEFAULT_IMAGE", SEAM);
        #[cfg(debug_assertions)]
        assert_eq!(initial_recommendation().unwrap().as_str(), SEAM);
        #[cfg(not(debug_assertions))]
        assert_eq!(
            initial_recommendation().unwrap().as_str(),
            defaults::INITIAL_DEFAULT_IMAGE_REF
        );
        env.set_var("AGENT_VM_TEST_DEFAULT_IMAGE", "localhost:1/seam:latest");
        #[cfg(debug_assertions)]
        assert!(
            initial_recommendation().is_err(),
            "a tag-only seam must be rejected, not converted"
        );
        env.remove_var("AGENT_VM_TEST_DEFAULT_IMAGE");
        assert_eq!(
            initial_recommendation().unwrap().as_str(),
            defaults::INITIAL_DEFAULT_IMAGE_REF
        );
    }

    #[test]
    fn config_images_accept_oci_references() {
        for accepted in [
            "ghcr.io/wirenboard/agent-vm-template:latest",
            "localhost:1/user:latest",
            "agent-vm-e2e-258-fixture:marker-free",
            "repo@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "docker.io/library/debian:13",
            "nginx:latest",
        ] {
            assert!(
                ImageRef::from_config(accepted).is_ok(),
                "{accepted} must be an acceptable config image"
            );
        }
    }

    #[test]
    fn config_images_reject_local_paths_and_bad_characters() {
        for rejected in [
            "/",
            "/abs/rootfs",
            "./rootfs",
            "../rootfs",
            ".",
            "..",
            "",
            " ",
            "\t",
            "localhost:1/user:la test",
            "localhost\n:1/x",
            "/tmp/img.disk",
        ] {
            let result = ImageRef::from_config(rejected);
            assert!(
                result.is_err(),
                "{rejected:?} must be rejected; the value must not be echoed"
            );
            if let Err(reason) = result {
                assert!(
                    !reason.contains(rejected) || rejected.len() <= 1,
                    "{reason}"
                );
            }
        }
    }

    #[test]
    fn immutable_references_accept_only_digest_pinned_oci_refs() {
        for accepted in [
            "localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ghcr.io/owner/name@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            // `repo:tag@sha256:…` is accepted: the digest still fixes identity.
            "localhost:1/a:tag@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ] {
            assert_eq!(
                ImmutableImageRef::parse(accepted).unwrap().as_str(),
                accepted,
                "{accepted} must be an immutable reference"
            );
        }

        for rejected in [
            // tag only
            "localhost:1/a:latest",
            "ghcr.io/owner/name",
            // local path / characters (the config-image policy)
            "/",
            "./rootfs",
            "localhost:1/a:la test",
            "",
            // malformed / unsupported / short digest (the OCI parser's grammar,
            // not the permissive `Digest::from_str`)
            "localhost:1/a@sha256:00ff",
            "localhost:1/a@md5:00112233445566778899aabbccddeeff",
            "localhost:1/a@sha256:",
            "localhost:1/a@",
        ] {
            let error = ImmutableImageRef::parse(rejected).expect_err(rejected);
            assert!(
                !error.contains(rejected) || rejected.chars().count() <= 1,
                "the reason must not echo {rejected:?}: {error}"
            );
        }
    }

    /// Exact conjunction: an accepted reference implies neither the config
    /// policy nor the digest requirement was bypassed, over all four Boolean
    /// combinations (ADR-0018).
    #[test]
    fn immutable_acceptance_is_exactly_the_measured_conjunction() {
        for bits in 0u8..4 {
            let facts = ImmutableImageFacts {
                config_acceptable: bits & 1 != 0,
                has_digest: bits & 2 != 0,
            };
            let accepted = immutable_image_is_acceptable(ImmutableImageFacts {
                config_acceptable: facts.config_acceptable,
                has_digest: facts.has_digest,
            });
            assert_eq!(
                accepted,
                facts.config_acceptable && facts.has_digest,
                "bits={bits:02b}"
            );
        }
    }

    #[test]
    fn override_preserves_bytes_and_rejects_empty_or_nul() {
        assert_eq!(
            ImageRef::from_override(" local name ".to_string())
                .unwrap()
                .as_str(),
            " local name "
        );
        assert!(ImageRef::from_override(String::new()).is_err());
        assert!(ImageRef::from_override("a\0b".to_string()).is_err());
    }

    #[test]
    fn env_override_treats_empty_as_unset() {
        assert!(env_override(None).unwrap().is_none());
        assert!(env_override(Some("")).unwrap().is_none());
        let present = env_override(Some(" "))
            .unwrap()
            .expect("whitespace is present");
        assert_eq!(present.source, OverrideSource::Environment);
        assert_eq!(present.reference.as_str(), " ");
    }

    /// `doctor`'s env slot must not conflate an unset variable with one that is
    /// present but not valid Unicode; every other verb fails on such a value.
    #[test]
    fn doctor_env_override_distinguishes_unset_from_non_unicode() {
        let mut env = crate::test_env::guard();
        env.remove_var("AGENT_VM_IMAGE_TAG");
        assert_eq!(doctor_env_override(), EnvOverride::Unset);

        env.set_var("AGENT_VM_IMAGE_TAG", "localhost:1/x:latest");
        match doctor_env_override() {
            EnvOverride::Present(override_) => {
                assert_eq!(override_.reference.as_str(), "localhost:1/x:latest");
            }
            other => panic!("expected a present override, got {other:?}"),
        }

        env.set_var("AGENT_VM_IMAGE_TAG", "");
        assert_eq!(doctor_env_override(), EnvOverride::Unset);

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            env.set_var("AGENT_VM_IMAGE_TAG", std::ffi::OsStr::from_bytes(b"\xff"));
            assert_eq!(doctor_env_override(), EnvOverride::Invalid);
        }
    }

    /// `requested` must not silently drop a value clap filled but `reconcile`
    /// never normalized (Standards S3: an invalid state is rejected, not
    /// indistinguishable from an absent flag).
    #[test]
    fn requested_rejects_an_unreconciled_value() {
        let unreconciled = ImageArgs {
            image: Some("localhost:1/x:latest".to_string()),
            origin: None,
        };
        assert!(unreconciled.requested().is_err());
        assert!(ImageArgs::default().requested().unwrap().is_none());
    }

    /// Exact conjunction: an accepted override implies neither check was
    /// bypassed, over all four Boolean combinations.
    #[test]
    fn override_acceptance_is_exactly_the_measured_conjunction() {
        for bits in 0u8..4 {
            let facts = OverrideImageFacts {
                nonempty: bits & 1 != 0,
                has_nul: bits & 2 != 0,
            };
            let accepted = override_image_is_acceptable(OverrideImageFacts {
                nonempty: facts.nonempty,
                has_nul: facts.has_nul,
            });
            assert_eq!(
                accepted,
                facts.nonempty && !facts.has_nul,
                "bits={bits:02b}"
            );
        }
    }

    /// Exact conjunction: an accepted decision implies none of the three checks
    /// was bypassed, over all eight Boolean combinations.
    #[test]
    fn config_image_acceptance_is_exactly_the_measured_conjunction() {
        for bits in 0u8..8 {
            let facts = ConfigImageFacts {
                oci_valid: bits & 1 != 0,
                sdk_local_path: bits & 2 != 0,
                characters_ok: bits & 4 != 0,
            };
            let accepted = config_image_is_acceptable(ConfigImageFacts {
                oci_valid: facts.oci_valid,
                sdk_local_path: facts.sdk_local_path,
                characters_ok: facts.characters_ok,
            });
            assert_eq!(
                accepted,
                facts.oci_valid && !facts.sdk_local_path && facts.characters_ok,
                "bits={bits:03b}"
            );
        }
    }

    proptest! {
        /// Accepted config strings never look like SDK local paths and carry no
        /// whitespace or control characters; inserting either into a known-valid
        /// reference rejects.
        #[test]
        fn accepted_config_images_never_look_local_or_unsafe(extra in ".{1,6}") {
            prop_assume!(!extra.chars().any(|c| c.is_control() || c.is_whitespace()));
            let valid = format!("ghcr.io/owner/name:tag{}", extra);
            if let Ok(image) = ImageRef::from_config(&valid) {
                prop_assert!(!microsandbox_utils::looks_like_local_path_text(image.as_str()));
                prop_assert!(!image.as_str().chars().any(|c| c.is_whitespace() || c.is_control()));
            }
            let with_space = format!("ghcr.io/owner/name:tag {}", extra);
            let with_newline = format!("ghcr.io/owner/name:tag\n{}", extra);
            prop_assert!(ImageRef::from_config(&with_space).is_err());
            prop_assert!(ImageRef::from_config(&with_newline).is_err());
        }
    }

    /// `ConfiguredImages`/`ConfiguredImage` need a public path to file for the
    /// doctor section: the source must name the declaring file.
    #[test]
    fn user_tier_names_its_file_in_the_source() {
        let boot = select(None, &configured_user("localhost:1/u:latest")).unwrap();
        assert_eq!(
            boot.source().describe(),
            "user config /home/u/.config/agent-vm/config.toml"
        );
        assert_eq!(
            boot.to_string(),
            "localhost:1/u:latest (from user config /home/u/.config/agent-vm/config.toml)"
        );
    }

    /// The exact default SDK reference is asserted in memory, never through
    /// printed output (which redacts the default tier). With an isolated `HOME`
    /// and a record seeded from `A`, a changed recommendation `B` must not win,
    /// and neither `Display` nor `Debug` may name the record-sourced reference.
    #[test]
    fn a_retained_record_is_the_exact_default_reference() {
        const A: &str =
            "localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const B: &str =
            "localhost:1/b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        env.set_var("AGENT_VM_TEST_DEFAULT_IMAGE", B);
        super::default_selection::adopt(&ImmutableImageRef::parse(A).unwrap()).unwrap();

        let empty = ConfiguredImages::for_test(ImageTierFixture {
            user: None,
            project: None,
        });
        let boot = select(None, &empty).unwrap();
        assert_eq!(
            boot.reference().as_str(),
            A,
            "the record wins over the seam"
        );
        assert!(boot.is_default());
        assert!(
            !boot.to_string().contains(A),
            "Display leaked the record: {boot}"
        );
        assert!(
            !format!("{boot:?}").contains(A),
            "Debug leaked the record: {boot:?}"
        );
        assert!(
            !boot.to_string().contains(B),
            "Display leaked the seam: {boot}"
        );
    }

    /// The *SDK input*, not merely the selector: the reference the real
    /// `SandboxConfig` is built with must be the retained record's exact digest.
    /// Asserted in memory (serialized to a `Value`, never printed), so it holds
    /// even though the default tier is display-redacted.
    #[test]
    fn a_retained_record_is_the_sdk_config_image_reference() {
        const A: &str =
            "localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const B: &str =
            "localhost:1/b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        env.set_var("AGENT_VM_TEST_DEFAULT_IMAGE", B);
        super::default_selection::adopt(&ImmutableImageRef::parse(A).unwrap()).unwrap();

        let empty = ConfiguredImages::for_test(ImageTierFixture {
            user: None,
            project: None,
        });
        let boot = select(None, &empty).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let config = runtime.block_on(async {
            microsandbox::Sandbox::builder("agent-vm-test")
                .image(boot.reference().as_str())
                .replace()
                .build()
                .await
                .expect("building the test sandbox config")
        });
        let value = serde_json::to_value(&config).unwrap();
        assert_eq!(
            value["image"]["Oci"]["reference"],
            serde_json::json!(A),
            "the SDK config must carry the retained digest"
        );
    }

    #[test]
    fn display_escapes_control_characters_in_the_reference() {
        let configured = ConfiguredImages::for_test(ImageTierFixture {
            user: Some(ConfiguredImage::for_test("x", "/u/config.toml")),
            project: None,
        });
        let requested = override_for("bad\u{1b}[31mref", OverrideSource::CommandLine);
        let boot = select(Some(requested), &configured).unwrap();
        assert!(!boot.to_string().contains('\u{1b}'), "{boot}");
    }
}
