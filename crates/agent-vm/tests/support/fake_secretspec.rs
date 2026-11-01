//! The fake `secretspec serve --read-only` endpoint, as the black-box suites use
//! it: a scenario file the compiled binary reads, and the value-free transcript
//! it writes back.
//!
//! Included with `#[path = "support/fake_secretspec.rs"] mod fake_secretspec;`
//! rather than through `support`, so only the crates that drive a SecretSpec
//! launch compile it (the same reason `fake_msb.rs` is separate).
//!
//! The fake activates **only** when `AGENT_VM_TEST_SECRETSPEC_FAKE` names a
//! scenario *and* the process was invoked as exactly `serve --read-only`, which
//! is what makes the release negative control (E13) meaningful: a release binary
//! with the hook still compiled in would answer the same argv. Only debug builds
//! contain the hook at all.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// The environment variable the debug binary reads. Spelled here as well as in
/// the binary so a test cannot drift from the hook it is testing.
pub const FAKE_ENV: &str = "AGENT_VM_TEST_SECRETSPEC_FAKE";

/// A scenario file plus the transcript path it writes.
pub struct Scenario {
    pub path: PathBuf,
    pub transcript: PathBuf,
}

/// Write `scenario` into `dir` with a transcript beside it. The transcript path
/// is always this test's own, so two tests in parallel cannot interleave.
pub fn write_scenario(dir: &Path, name: &str, mut scenario: Value) -> Scenario {
    let path = dir.join(format!("secretspec-{name}.json"));
    let transcript = dir.join(format!("secretspec-{name}.jsonl"));
    let object = scenario.as_object_mut().expect("a scenario object");
    object.insert("transcript".into(), json!(transcript));
    std::fs::write(&path, serde_json::to_vec(&scenario).unwrap()).expect("write the scenario");
    Scenario { path, transcript }
}

/// Every transcript event, in order. Empty when the fake never ran, which is how
/// "nothing spawned" is asserted.
pub fn transcript(scenario: &Scenario) -> Vec<Value> {
    std::fs::read_to_string(&scenario.transcript)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// The client frames the fake received for `method`, in order.
pub fn requests(scenario: &Scenario, method: &str) -> Vec<Value> {
    transcript(scenario)
        .into_iter()
        .filter(|event| event["event"] == "request" && event["method"] == method)
        .map(|event| event["frame"].clone())
        .collect()
}

/// The events of one kind, in order.
pub fn events(scenario: &Scenario, kind: &str) -> Vec<Value> {
    transcript(scenario)
        .into_iter()
        .filter(|event| event["event"] == kind)
        .collect()
}

/// Whether the fake recorded any contract violation of the client's frames.
pub fn violations(scenario: &Scenario) -> Vec<Value> {
    events(scenario, "violation")
}

/// A `credentials.yaml` with one `source: secretspec` entry.
///
/// `executable` is the test binary by default: it is absolute, owned by the test
/// runner and mode 0755, so it passes the narrow target-file check. The table's
/// `extra` lines are appended (indented) so a test can add `scope`/`name`.
pub fn secretspec_yaml(
    service: &str,
    env_name: &str,
    executable: &Path,
    manifest: &Path,
    extra: &[&str],
) -> String {
    let mut table = String::new();
    for line in extra {
        table.push_str(&format!("      {line}\n"));
    }
    format!(
        "credentials:\n  - service: {service}\n    source: secretspec\n    apiKey:\n      \
         name: {env_name}\n      sentinelEnv: true\n      inject: [{{domain: \
         api.{service}.example, scheme: bearer}}]\n    secretspec:\n      executable: \
         {executable}\n      manifest: {manifest}\n      profile: default\n{table}",
        executable = executable.display(),
        manifest = manifest.display(),
    )
}

/// A manifest that declares `providers = ["env"]` for one secret: the documented
/// provider mechanism, with no SecretSpec user configuration and no
/// `SECRETSPEC_PROVIDER` in the environment.
pub fn manifest_with_env_provider(secret: &str) -> String {
    // SecretSpec 0.21's schema: `[project] name + revision`, then a profile that
    // maps each secret name to its declaration. `providers = ["env"]` is the
    // documented provider mechanism — the reason no `provider` key exists in
    // agent-vm's own configuration.
    format!(
        "[project]\nname = \"agent-vm-test\"\nrevision = \"1.0\"\n\n[profiles.default]\n\
         {secret} = {{ description = \"agent-vm test secret\", providers = [\"env\"], required = \
         false }}\n"
    )
}
