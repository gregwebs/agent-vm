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
//!
//! # Control characters
//!
//! Both records are printed as a delimited block rather than a single line — the
//! launch path's through `launch_notice::LaunchNotices::emit_block`, the native
//! one directly — because pretty JSON is the readable form and it is what a test
//! parses back. Its *values* are measured though — a project or bind path can hold
//! any byte — and `serde_json` escapes the C0 range only, so DEL and the C1 range
//! (U+0085, a line break to some readers) would reach the terminal raw. Every
//! record therefore renders through `dump_line`, which spells those characters as
//! JSON `\uXXXX` escapes: the block's structure stays the launcher's, its values
//! stay one line each, and the record still parses.

use std::fmt::Write as _;

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
    // Serializing `config` directly in the unredacted case, rather than through a
    // `Value`, keeps its field order.
    let json = if redact_image {
        let mut value = serde_json::to_value(config)?;
        if let Some(reference) = value.pointer_mut("/image/Oci/reference") {
            *reference = serde_json::Value::String(REDACTED_REFERENCE.to_string());
        }
        serde_json::to_string_pretty(&value)?
    } else {
        serde_json::to_string_pretty(config)?
    };
    Ok(Some(dump_line("[debug] sandbox config JSON: ", &json)))
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
    Ok(Some(dump_line(
        "[debug] native image acquisition JSON: ",
        &serde_json::to_string_pretty(&record)?,
    )))
}

/// The emitted record: `prefix` and its pretty JSON, with every control character
/// `serde_json` leaves raw spelled as a JSON `\uXXXX` escape.
///
/// `serde_json` escapes the C0 range (`\n` as `\\n`, a tab as `\\t`) and stops
/// there, so DEL and the C1 range survive into the dump as the bytes a terminal
/// acts on. They can only occur inside a string literal — the structure this
/// walks is otherwise ASCII — so replacing them with `\uXXXX` keeps the record
/// valid JSON, keeps its indentation and line breaks, and tells the reader which
/// bytes the value actually held.
fn dump_line(prefix: &str, json: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + json.len());
    out.push_str(prefix);
    for character in json.chars() {
        match character {
            '\u{7f}'..='\u{9f}' => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            printable_or_newline => out.push(printable_or_newline),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #416 review: the block door's contract is that its *structure* is the
    /// launcher's, so a measured value inside it must be neutralized by the block's
    /// own renderer. `serde_json` leaves DEL and the C1 range raw, and a bind path
    /// can hold either, so both are escaped here — spelled, not dropped.
    #[test]
    fn a_measured_value_cannot_smuggle_a_control_byte_into_the_record() {
        let host = "/home/dev/proj\u{85}nel\u{7f}del";
        let record = serde_json::json!({
            "kind": "sandbox-config",
            "mounts": [{ "host": host, "guest": "/workspace" }],
        });
        let json = serde_json::to_string_pretty(&record).expect("rendering the record");
        let line = dump_line("[debug] sandbox config JSON: ", &json);

        assert!(
            line.contains(r"proj\u0085nel\u007fdel"),
            "the measured bytes are spelled: {line}"
        );
        assert!(
            !line.contains('\u{85}') && !line.contains('\u{7f}'),
            "nothing a terminal acts on survives: {line}"
        );

        // Still the block it was: pretty, indented, one value per line.
        let body = line
            .strip_prefix("[debug] sandbox config JSON: ")
            .expect("the record's prefix");
        assert!(body.contains("\n  \"mounts\": [\n"), "body: {body}");
        assert!(body.ends_with('}'), "body: {body}");

        // And still JSON, holding the value the path actually was.
        let parsed: serde_json::Value = serde_json::from_str(body).expect("the dump still parses");
        assert_eq!(parsed["mounts"][0]["host"], host);
    }
}
