//! The `AGENT_VM_DEBUG_CONFIG` dump of a built `SandboxConfig`.
//!
//! Three launcher sites build a config and hand it to the SDK: launch's boot
//! builder, `pull`'s throwaway acquisition, and `setup`'s verification
//! acquisition. Each can emit the exact config it passes to the SDK — behind
//! the same `AGENT_VM_DEBUG_CONFIG` opt-in — so an integration test can assert
//! the real acquisition input (the selected image reference, registry,
//! pull policy) rather than a selector notice or a connection error.
//!
//! The SDK has no such hook of its own; these three launcher sites own it.
//!
//! # Redaction
//!
//! The default tier's reference is record/recommendation-sourced and may name a
//! private registry, so the **display copy** of the config replaces the image
//! reference with [`REDACTED_REFERENCE`] when [`sandbox_config`] is told the
//! selection is redacted. The `SandboxConfig` handed to the SDK is unchanged —
//! only the rendered JSON differs.

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
