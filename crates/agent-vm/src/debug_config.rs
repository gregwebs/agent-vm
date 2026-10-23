//! The `AGENT_VM_DEBUG_CONFIG` dump of a built `SandboxConfig`.
//!
//! Two kinds of launcher input can be dumped behind the same opt-in: the
//! `SandboxConfig` a launch or `setup` verification hands to the SDK
//! ([`sandbox_config`]), and the reference/options a **boot-free native image
//! acquisition** hands to `Registry` ([`native_acquisition`]). An integration
//! test can then assert the real input (reference, registry, pull policy)
//! rather than a selector notice or a connection error.
//!
//! The two records are deliberately distinct: a native acquisition builds no
//! `SandboxConfig`, so rendering it as one would be a counterfeit that made a
//! VM-free path look like a boot.
//!
//! # Redaction
//!
//! The default tier's reference is record/recommendation-sourced and may name a
//! private registry, so the **display copy** of both records replaces the image
//! reference with [`REDACTED_REFERENCE`] when the selection is redacted. The
//! value handed to the SDK is unchanged — only the rendered JSON differs.
//!
//! Neither dump includes registry credentials or cache configuration.

use anyhow::Result;

/// The fixed text shown where a redacted selection's image reference would be.
pub(crate) const REDACTED_REFERENCE: &str = "<redacted default boot image>";

/// The `[debug] sandbox config JSON: ` line for `config`, or `None` when the
/// opt-in is absent. Serialization errors propagate rather than defaulting to
/// an empty string, so a missing dump is never mistaken for a valid one.
///
/// When `redact_image` is set, the JSON's image reference is replaced with
/// [`REDACTED_REFERENCE`] before it is rendered; the caller's `config` (and
/// therefore the SDK input) is untouched.
pub(crate) fn sandbox_config(
    config: &microsandbox::sandbox::SandboxConfig,
    redact_image: bool,
) -> Result<Option<String>> {
    if std::env::var("AGENT_VM_DEBUG_CONFIG").is_err() {
        return Ok(None);
    }
    if redact_image {
        let mut value = serde_json::to_value(config)?;
        if let Some(reference) = value.pointer_mut("/image/Oci/reference") {
            *reference = serde_json::Value::String(REDACTED_REFERENCE.to_string());
        }
        let json = serde_json::to_string_pretty(&value)?;
        return Ok(Some(format!("[debug] sandbox config JSON: {json}")));
    }
    let json = serde_json::to_string_pretty(config)?;
    Ok(Some(format!("[debug] sandbox config JSON: {json}")))
}

/// The `[debug] native image acquisition JSON: ` line for one
/// native pull inside [`crate::image_acquire::acquire`], or `None` when the
/// opt-in is absent.
///
/// Rendered immediately before the actual native call from the exact target and
/// options passed to `Registry`, so a test can tell a real acquisition from a
/// selector notice. The record is a distinct `kind`: no `SandboxConfig` exists
/// on this path and none is implied.
pub(crate) fn native_acquisition(
    reference: &microsandbox_image::Reference,
    options: &microsandbox_image::PullOptions,
    label: &crate::boot_image::ImageLabel,
) -> Result<Option<String>> {
    if std::env::var("AGENT_VM_DEBUG_CONFIG").is_err() {
        return Ok(None);
    }
    let platform = microsandbox_image::Platform::host_linux();
    let rendered_reference = if label.is_redacted() {
        REDACTED_REFERENCE.to_string()
    } else {
        reference.whole()
    };
    let record = serde_json::json!({
        "kind": "native-image-acquire",
        "reference": rendered_reference,
        "pull_policy": format!("{:?}", options.pull_policy).to_lowercase(),
        "force": options.force,
        "platform": {
            "os": platform.os.to_string(),
            "arch": platform.arch.to_string(),
        },
    });
    Ok(Some(format!(
        "[debug] native image acquisition JSON: {}",
        serde_json::to_string_pretty(&record)?
    )))
}
