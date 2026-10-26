//! The import hint attached to a registry acquisition failure (#359). One
//! predicate, one text, every acquisition call site (launch, pull, setup).
//! Text only: no Docker is consulted (ADR-0035).

use crate::boot_image::ImageLabel;
use crate::image_publish::ResultReference;
use vstd::prelude::*;

verus! {

/// The measured facts the hint decision reads. Named fields rather than
/// adjacent `bool` parameters, so an argument swap cannot invert the decision.
pub(crate) struct ImageMissFacts {
    /// The failure chain carries `ImageError::Registry`.
    pub(crate) registry_error: bool,
    /// The selected reference is a mutable OCI reference an import could produce.
    pub(crate) mutable_tag: bool,
    /// The reference may be rendered (not a redacted default-tier selection).
    pub(crate) reference_may_be_named: bool,
}

/// The hint decision, contracted (ADR-0018): offered **iff** the failure came
/// from a registry, the reference is one an import could produce, and printing
/// it leaks no redacted selection.
pub(crate) fn import_hint_is_offered(facts: ImageMissFacts) -> (offered: bool)
    ensures offered == (facts.registry_error && facts.mutable_tag && facts.reference_may_be_named),
{ facts.registry_error && facts.mutable_tag && facts.reference_may_be_named }

} // verus!

/// Attach the hint to a registry-failure chain, keeping the original error
/// beneath it. Returns `error` unchanged when the predicate refuses, so no call
/// site needs its own condition.
pub(crate) fn attach(error: anyhow::Error, reference: &str, label: &ImageLabel) -> anyhow::Error {
    // `mutable_tag` is measured as "parses as a result reference": strictly
    // stronger than "has no digest" (a local rootfs path has none but is not
    // importable), and exactly "the printed --tag would be accepted".
    let parsed = reference.parse::<ResultReference>().ok();
    let facts = ImageMissFacts {
        registry_error: has_registry_error(&error),
        mutable_tag: parsed.is_some(),
        reference_may_be_named: !label.is_redacted(),
    };
    match parsed {
        Some(result) if import_hint_is_offered(facts) => error.context(render(&result)),
        _ => error,
    }
}

/// Downcasts the wrapped `ImageError` anywhere in the chain: `MicrosandboxError::Image`
/// is `#[from]`, so the registry variant is a chain member, not the top error.
fn has_registry_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<microsandbox_image::ImageError>(),
            Some(microsandbox_image::ImageError::Registry(_))
        )
    })
}

/// The hint text for one reference.
///
/// The lead line states where the acquisition failed, so the top of the message
/// is not `Error: hint: …`; it is not a diagnosis (`image refresh` uses
/// `PullPolicy::Always`, so a cache miss is not implied). The reference is
/// spelled as one shell word, the same spelling in every line, so the whole hint
/// can be pasted; for a plain value that is byte-identical to the plain text and
/// no shell is named, because every shell reads it.
fn render(reference: &ResultReference) -> String {
    let shown = reference.shell_arg();
    // The remedy lines are indented by two spaces. A `\`-continuation strips
    // the *next* line's leading whitespace, so the indent must come from here.
    let indent = "  ";
    let shell_note = crate::shell::bash_zsh_note(&[&shown])
        .map(|note| format!("The commands above are {note}.\n"))
        .unwrap_or_default();
    format!(
        "could not acquire {shown} from its registry\n\n\
hint: an image that exists only in your local Docker daemon is not visible to\n\
agent-vm until it is imported into agent-vm's own image cache:\n\
{indent}agent-vm image import --docker {shown} --tag {shown}\n\
A completed OCI or Docker-save archive works too:\n\
{indent}agent-vm image import --input <FILE> --tag {shown}\n\
{shell_note}\
The imported reference must match the --image value exactly."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn registry() -> anyhow::Error {
        anyhow::Error::new(microsandbox::MicrosandboxError::Image(
            microsandbox_image::ImageError::Registry(
                std::io::Error::other("Not authorized: url https://x").into(),
            ),
        ))
        .context("creating sandbox")
    }

    #[test]
    fn hint_truth_table() {
        for bits in 0..8 {
            assert_eq!(
                import_hint_is_offered(ImageMissFacts {
                    registry_error: bits & 1 != 0,
                    mutable_tag: bits & 2 != 0,
                    reference_may_be_named: bits & 4 != 0
                }),
                bits == 7
            );
        }
    }

    #[test]
    fn registry_failure_for_a_tag_gets_the_exact_hint() {
        let label = ImageLabel::for_tests("my-image:dev");
        let error = attach(registry(), "my-image:dev", &label);
        let shown = format!("{error:?}");
        // Literal, never `render()`: a wording regression in the hint must fail
        // this test, not move its own expectation with it.
        let expected = concat!(
            "could not acquire my-image:dev from its registry\n\n",
            "hint: an image that exists only in your local Docker daemon is not visible to\n",
            "agent-vm until it is imported into agent-vm's own image cache:\n",
            "  agent-vm image import --docker my-image:dev --tag my-image:dev\n",
            "A completed OCI or Docker-save archive works too:\n",
            "  agent-vm image import --input <FILE> --tag my-image:dev\n",
            "The imported reference must match the --image value exactly."
        );
        assert!(shown.starts_with(expected), "{shown}");
        // The registry chain stays beneath the hint.
        assert!(shown.contains("Not authorized: url https://x"), "{shown}");
    }

    #[test]
    fn healthy_or_non_registry_chain_is_unchanged() {
        let error = anyhow::anyhow!("plain fault").context("creating sandbox");
        let before = format!("{error:?}");
        let count = error.chain().count();
        let error = attach(error, "app:dev", &ImageLabel::for_tests("app:dev"));
        assert_eq!(format!("{error:?}"), before);
        assert_eq!(error.chain().count(), count);
    }

    #[test]
    fn digest_pinned_reference_gets_no_hint() {
        let reference = format!("app@sha256:{}", "a".repeat(64));
        assert!(
            !format!(
                "{:?}",
                attach(registry(), &reference, &ImageLabel::for_tests("explicit"))
            )
            .contains("hint:")
        );
    }

    #[test]
    fn local_path_reference_gets_no_hint() {
        assert!(
            !format!(
                "{:?}",
                attach(registry(), "./rootfs", &ImageLabel::for_tests("explicit"))
            )
            .contains("hint:")
        );
    }

    #[test]
    fn redacted_label_gets_no_hint() {
        assert!(
            !format!(
                "{:?}",
                attach(registry(), "app:dev", &ImageLabel::for_default_upgrade())
            )
            .contains("hint:")
        );
    }

    #[test]
    fn non_ascii_reference_hint_is_a_shell_word() {
        let raw = "localhost:1/x:é";
        assert!(raw.parse::<ResultReference>().is_ok());
        let shown = format!("{:?}", attach(registry(), raw, &ImageLabel::for_tests(raw)));
        assert!(shown.contains("agent-vm image import --docker $'localhost:1/x:\\xc3\\xa9' --tag $'localhost:1/x:\\xc3\\xa9'"));
        assert!(!shown.contains('é'));
        // `$'…'` is not POSIX: a reader pasting into `sh`/`dash` must be told.
        assert!(
            shown.contains("The commands above are quoted for bash or zsh."),
            "{shown}"
        );
    }

    #[test]
    fn a_plain_reference_hint_names_no_shell() {
        let shown = format!(
            "{:?}",
            attach(registry(), "app:dev", &ImageLabel::for_tests("app:dev"))
        );
        assert!(shown.contains("agent-vm image import --docker app:dev --tag app:dev"));
        assert!(!shown.contains("bash"), "{shown}");
    }
}
