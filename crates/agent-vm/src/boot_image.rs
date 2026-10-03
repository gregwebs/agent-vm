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

use std::fmt;
use std::path::PathBuf;

use anyhow::{Result, bail};
use vstd::prelude::*;

use crate::config::ConfiguredImages;
use crate::defaults;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// True when no user source chose the image. `setup` uses this to decide
    /// whether a missing shipped command is fatal (the default image is
    /// agent-vm's to keep working) or a warning (the user owns their image).
    pub(crate) fn is_default(&self) -> bool {
        matches!(self.source, ImageSource::Default)
    }
}

impl fmt::Display for BootImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (from {})",
            crate::config::escape_str(self.reference.as_str()),
            self.source.describe(),
        )
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

/// The sole selection owner: first present source wins. Not pure — the
/// default slot reads the debug test seam and later #261's retained selection
/// via [`default_image`], and it is only reached when every higher slot is
/// absent, so the default is acquired lazily via `default`.
pub(crate) fn select(requested: Option<ImageOverride>, configured: &ConfiguredImages) -> BootImage {
    select_with(requested, configured, default_image)
}

/// [`select`] with the default slot supplied as a thunk. `select` passes
/// [`default_image`]; the precedence table is tested through this private
/// helper with an already-known default, so the table does not depend on the
/// debug seam.
fn select_with(
    requested: Option<ImageOverride>,
    configured: &ConfiguredImages,
    default: impl FnOnce() -> ImageRef,
) -> BootImage {
    if let Some(requested) = requested {
        return BootImage {
            reference: requested.reference,
            source: requested.source.into(),
        };
    }
    if let Some(image) = configured.user() {
        return BootImage {
            reference: image.reference().clone(),
            source: ImageSource::UserConfig(image.file().to_path_buf()),
        };
    }
    if let Some(image) = configured.project() {
        return BootImage {
            reference: image.reference().clone(),
            source: ImageSource::ProjectConfig(image.file().to_path_buf()),
        };
    }
    BootImage {
        reference: default(),
        source: ImageSource::Default,
    }
}

/// The default boot image: `defaults::DEFAULT_IMAGE_REF` unless the
/// **debug-only** test seam overrides it.
///
/// This function is the one seam #261 replaces with a retained, seeded
/// selection. `AGENT_VM_TEST_DEFAULT_IMAGE` exists because a boot-free CLI test
/// that falls through to the default would otherwise start a real multi-GB
/// `ghcr.io` pull after the debug dump; it follows the
/// `AGENT_VM_TEST_CREDENTIAL` precedent. Release builds compile the read out
/// entirely (pinned by a unit test).
pub(crate) fn default_image() -> ImageRef {
    #[cfg(debug_assertions)]
    if let Some(raw) = std::env::var_os("AGENT_VM_TEST_DEFAULT_IMAGE")
        && let Ok(reference) = ImageRef::from_override(raw.to_string_lossy().into_owned())
    {
        return reference;
    }
    ImageRef(defaults::DEFAULT_IMAGE_REF.to_string())
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

} // verus!

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfiguredImage, ConfiguredImages, ImageTierFixture};
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
                ImageRef::from_override("localhost:1/d:latest".to_string()).unwrap()
            });
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

    /// A released build must ignore the debug-only test seam.
    #[test]
    fn a_release_build_ignores_the_test_default_image_seam() {
        let mut env = crate::test_env::guard();
        env.set_var("AGENT_VM_TEST_DEFAULT_IMAGE", "localhost:1/seam:latest");
        #[cfg(debug_assertions)]
        assert_eq!(default_image().as_str(), "localhost:1/seam:latest");
        #[cfg(not(debug_assertions))]
        assert_eq!(default_image().as_str(), defaults::DEFAULT_IMAGE_REF);
        env.remove_var("AGENT_VM_TEST_DEFAULT_IMAGE");
        assert_eq!(default_image().as_str(), defaults::DEFAULT_IMAGE_REF);
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
        let boot = select(None, &configured_user("localhost:1/u:latest"));
        assert_eq!(
            boot.source().describe(),
            "user config /home/u/.config/agent-vm/config.toml"
        );
        assert_eq!(
            boot.to_string(),
            "localhost:1/u:latest (from user config /home/u/.config/agent-vm/config.toml)"
        );
    }

    #[test]
    fn display_escapes_control_characters_in_the_reference() {
        let configured = ConfiguredImages::for_test(ImageTierFixture {
            user: Some(ConfiguredImage::for_test("x", "/u/config.toml")),
            project: None,
        });
        let requested = override_for("bad\u{1b}[31mref", OverrideSource::CommandLine);
        let boot = select(Some(requested), &configured);
        assert!(!boot.to_string().contains('\u{1b}'), "{boot}");
    }
}
