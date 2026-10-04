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

use anyhow::Result;

/// The `[debug] sandbox config JSON: ` line for `config`, or `None` when the
/// opt-in is absent. Serialization errors propagate rather than defaulting to
/// an empty string, so a missing dump is never mistaken for a valid one.
pub(crate) fn sandbox_config(
    config: &microsandbox::sandbox::SandboxConfig,
) -> Result<Option<String>> {
    if std::env::var("AGENT_VM_DEBUG_CONFIG").is_err() {
        return Ok(None);
    }
    let json = serde_json::to_string_pretty(config)?;
    Ok(Some(format!("[debug] sandbox config JSON: {json}")))
}
