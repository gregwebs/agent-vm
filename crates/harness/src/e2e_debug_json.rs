//! `e2e.sh`'s launcher-log JSON readers (#700).
//!
//! The launcher prints debug records into the same stream as everything else, so
//! the JSON a row asserts on is a *prefix* of a line that continues with more log
//! text. `jq` and `json.loads` both refuse that, which is why the shell had a
//! Python heredoc; a `sed` cut at end-of-line would be a guess about where the
//! value ends.
//!
//! Two readers:
//!
//! * `--sandbox-config` — the first `[debug] sandbox config JSON: ` dump, emitted
//!   again as one JSON document so a row can assert on it with `jq`. A missing
//!   dump and a malformed one are both failures: an empty observation must never
//!   read as "the config had nothing".
//! * `--acquisition-dumps` — every sandbox-config and native-acquisition dump in
//!   **document order**, as `name<TAB>reference`. Order matters: the set is
//!   compared whole, so a dropped or reordered dump is a failure, not a shorter
//!   list.
//!
//! Both are independent of `agent-vm` (ADR-0072): this module keeps its own
//! model of the marker lines and learns nothing from the crate that writes them.

use std::{fs, path::PathBuf};

use clap::Args;
use serde_json::Value;

const SANDBOX_MARKER: &str = "[debug] sandbox config JSON: ";
const NATIVE_MARKER: &str = "[debug] native image acquisition JSON: ";
/// The row name a native acquisition dump is reported under; it has no sandbox
/// name, so its fixed kind is the name.
const NATIVE_KIND: &str = "native-image-acquire";
const NO_VALUE: &str = "<none>";

#[derive(Debug, Args)]
pub struct E2eDebugJsonArgs {
    /// Print the first sandbox-config dump as one JSON document.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["acquisition_dumps", "self_test"])]
    sandbox_config: Option<PathBuf>,

    /// Print `name<TAB>reference` for every acquisition dump, in document order.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["sandbox_config", "self_test"])]
    acquisition_dumps: Option<PathBuf>,

    /// Run the boot-free controls for both readers.
    #[arg(long)]
    self_test: bool,
}

pub fn run(args: E2eDebugJsonArgs) -> Result<String, String> {
    if args.self_test {
        self_test()?;
        return Ok("e2e debug-json controls passed".to_owned());
    }
    if let Some(path) = args.sandbox_config {
        let text = read_log(&path)?;
        return sandbox_config(&text);
    }
    if let Some(path) = args.acquisition_dumps {
        let text = read_log(&path)?;
        return acquisition_dumps(&text);
    }
    Err("choose --sandbox-config PATH, --acquisition-dumps PATH or --self-test".to_owned())
}

/// The launcher log is not required to be UTF-8 (a guest can print arbitrary
/// bytes into it), so the read never fails on encoding: the dumps themselves are
/// ASCII. A *missing* log is still a failure.
fn read_log(path: &std::path::Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn sandbox_config(text: &str) -> Result<String, String> {
    let offset = text
        .find(SANDBOX_MARKER)
        .ok_or("the launch emitted no sandbox config dump")?;
    let value = decode_one(
        &text[offset + SANDBOX_MARKER.len()..],
        "the sandbox config dump",
    )?;
    serde_json::to_string(&value).map_err(|error| format!("cannot re-emit the dump: {error}"))
}

fn acquisition_dumps(text: &str) -> Result<String, String> {
    // Every marker occurrence, then sorted by position: the rows assert on the
    // document's own order, not on the order the markers are listed here.
    let mut found = Vec::new();
    for (marker, kind) in [
        (SANDBOX_MARKER, Kind::Sandbox),
        (NATIVE_MARKER, Kind::Native),
    ] {
        let mut index = 0;
        while let Some(relative) = text[index..].find(marker) {
            let start = index + relative + marker.len();
            found.push((start, kind));
            index = start;
        }
    }
    found.sort_by_key(|(start, _)| *start);

    let mut rows = Vec::new();
    for (start, kind) in found {
        let value = decode_one(&text[start..], "a debug dump")?;
        rows.push(match kind {
            Kind::Native => {
                if value.get("kind").and_then(Value::as_str) != Some(NATIVE_KIND) {
                    return Err("unexpected native acquisition kind".to_owned());
                }
                format!(
                    "{NATIVE_KIND}\t{}",
                    value
                        .get("reference")
                        .map(text_field)
                        .unwrap_or_else(|| NO_VALUE.to_owned())
                )
            }
            Kind::Sandbox => {
                let name = value
                    .get("name")
                    .map(text_field)
                    .unwrap_or_else(|| NO_VALUE.to_owned());
                let reference = value
                    .get("image")
                    .and_then(|image| image.get("Oci"))
                    .and_then(|oci| oci.get("reference"))
                    .map(text_field)
                    .unwrap_or_else(|| NO_VALUE.to_owned());
                format!("{name}\t{reference}")
            }
        });
    }
    Ok(rows.join("\n"))
}

#[derive(Clone, Copy)]
enum Kind {
    Sandbox,
    Native,
}

/// One JSON value starting at `text` (leading whitespace skipped), ignoring
/// whatever follows it. That is exactly Python's `JSONDecoder.raw_decode`, and it
/// is why this cannot be `serde_json::from_str`: the document continues with log
/// text after the value.
fn decode_one(text: &str, what: &str) -> Result<Value, String> {
    let trimmed = text.trim_start();
    let mut stream = serde_json::Deserializer::from_str(trimmed).into_iter::<Value>();
    match stream.next() {
        Some(Ok(value)) => Ok(value),
        Some(Err(error)) => Err(format!("{what} is not JSON: {error}")),
        None => Err(format!("{what} is not JSON: no value")),
    }
}

/// A dump's field, rendered the way the rows compare it: whole, never as a
/// substring. A non-string field is reported literally rather than dropped.
fn text_field(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn self_test() -> Result<(), String> {
    let log = format!(
        "==> banner\n\
         {SANDBOX_MARKER}{{\"name\": \"first\", \"image\": {{\"Oci\": {{\"reference\": \"repo:tag\"}}}}}}\n\
         more log text\n\
         {NATIVE_MARKER}{{\"kind\": \"{NATIVE_KIND}\", \"reference\": \"repo@sha256:aa\"}}\n\
         {SANDBOX_MARKER}  {{\"name\": \"second\"}} trailing prose\n"
    );
    let dumps = acquisition_dumps(&log)?;
    let expected = "first\trepo:tag\n\
                    native-image-acquire\trepo@sha256:aa\n\
                    second\t<none>";
    if dumps != expected {
        return Err(format!("the dumps read {dumps:?}, want {expected:?}"));
    }
    let config = sandbox_config(&log)?;
    let parsed: Value = serde_json::from_str(&config).map_err(|error| error.to_string())?;
    if parsed.get("name").and_then(Value::as_str) != Some("first") {
        return Err(format!("the sandbox config read {config}"));
    }

    let error = sandbox_config("just log text\n")
        .err()
        .ok_or("a log with no dump was accepted as a config")?;
    if !error.contains("the launch emitted no sandbox config dump") {
        return Err(format!(
            "a missing dump failed without its message: {error}"
        ));
    }

    let malformed = format!("{SANDBOX_MARKER}{{\"name\": ");
    let error = sandbox_config(&malformed)
        .err()
        .ok_or("a malformed dump was accepted as a config")?;
    if !error.contains("is not JSON") {
        return Err(format!(
            "a malformed dump failed without its message: {error}"
        ));
    }

    let wrong_kind = format!("{NATIVE_MARKER}{{\"kind\": \"something-else\"}}");
    let error = acquisition_dumps(&wrong_kind)
        .err()
        .ok_or("an unexpected native kind was accepted")?;
    if !error.contains("unexpected native acquisition kind") {
        return Err(format!(
            "an unexpected native kind failed without its message: {error}"
        ));
    }
    // A value followed by more JSON is one dump, not two: the reader stops after
    // the first value, which is what keeps trailing log text from being an error.
    if decode_one("{\"a\": 1}\n{\"b\": 2}", "a probe")?
        .get("b")
        .is_some()
    {
        return Err("the decoder consumed a second value from one dump".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_debug_json_controls_hold() {
        self_test().expect("e2e debug-json controls pass");
    }
}
