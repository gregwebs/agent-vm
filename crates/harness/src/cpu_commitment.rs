//! CPU-commitment evidence drivers (ADR-0072, #686).
//!
//! `script/test/cpu-commitment-select.py` and `cpu-commitment-manifest.py` used
//! to own the Phase 0 selection and runtime-provenance manifest. Both are here
//! now, and the inline Python the native wrapper carried is a subcommand too.
//!
//! Exit statuses are part of the caller's interface: 0 ok, 1 refusal, 2 misuse
//! (clap's own parse status) and 3 inconclusive evidence. `failure_status` keeps
//! 3 distinct from a refusal instead of collapsing the two.

use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MANIFEST: &str = "runtime-manifest.json";
const REQUIRED: [&str; 7] = [
    "msb_path",
    "msb_sha256",
    "firmware_path",
    "firmware_sha256",
    "agent_sha",
    "vendor_sha",
    "clean_firmware_rebuild",
];
const INCONCLUSIVE: &str = "manifest: INCONCLUSIVE: ";
const USAGE: &str =
    "usage: cpu-commitment --self-test|select|manifest|snapshot|container-identity|cargo-row";

// The bytes the Python driver wrote, frozen as a literal. Only the two absolute
// fixture paths are substituted back before comparing, so a change to key order,
// indentation, the trailing newline or a hash fails here.
const GOLDEN_MANIFEST: &str = include_str!("../tests/data/cpu-commitment-runtime-manifest.json");
const GOLDEN_MSB_PATH: &str = "/private/tmp/cpu-commitment-runtime-manifest-golden/msb";
const GOLDEN_FIRMWARE_PATH: &str = "/private/tmp/cpu-commitment-runtime-manifest-golden/firmware";

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct CpuCommitmentArgs {
    /// Run the boot-free selection, manifest, snapshot and identity controls.
    #[arg(long)]
    self_test: bool,

    #[command(subcommand)]
    command: Option<CpuCommitmentCommand>,
}

#[derive(Debug, Subcommand)]
enum CpuCommitmentCommand {
    /// Select Cargo's one isolated agent-vm test executable.
    Select {
        #[arg(value_name = "CARGO_JSONL")]
        rows: PathBuf,
        #[arg(value_name = "ISOLATED_TARGET_DIR")]
        target_dir: PathBuf,
    },
    /// Write or verify the runtime provenance manifest.
    Manifest(ManifestArgs),
    /// Snapshot pinned recursive Git inputs into an owned build source tree.
    Snapshot {
        #[arg(value_name = "SOURCE")]
        source: PathBuf,
        #[arg(value_name = "TARGET")]
        target: PathBuf,
    },
    /// Require two Docker inspect receipts to name the same nonempty image identity.
    ContainerIdentity {
        #[arg(value_name = "BEFORE")]
        before: PathBuf,
        #[arg(value_name = "AFTER")]
        after: PathBuf,
    },
    /// Write one Cargo JSON row, so a shell control can build a fixture ledger.
    CargoRow {
        #[arg(value_name = "REASON")]
        reason: String,
        #[arg(value_name = "TARGET")]
        target: String,
        #[arg(value_name = "KIND")]
        kind: String,
        #[arg(value_name = "TEST_PROFILE")]
        test_profile: String,
        #[arg(value_name = "EXECUTABLE")]
        executable: String,
        #[arg(value_name = "SUCCESS")]
        success: String,
    },
}

#[derive(Debug, Args)]
struct ManifestArgs {
    #[command(subcommand)]
    command: ManifestCommand,
}

#[derive(Debug, Subcommand)]
enum ManifestCommand {
    Write {
        #[arg(value_name = "EVIDENCE_DIR")]
        evidence: PathBuf,
        #[arg(value_name = "MSB")]
        msb: PathBuf,
        #[arg(value_name = "FIRMWARE")]
        firmware: PathBuf,
        #[arg(value_name = "AGENT_SHA")]
        agent_sha: String,
        #[arg(value_name = "VENDOR_SHA")]
        vendor_sha: String,
    },
    Verify {
        #[arg(value_name = "EVIDENCE_DIR")]
        evidence: PathBuf,
        #[arg(value_name = "MSB")]
        msb: PathBuf,
        #[arg(value_name = "FIRMWARE")]
        firmware: PathBuf,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeManifest {
    msb_path: String,
    msb_sha256: String,
    firmware_path: String,
    firmware_sha256: String,
    agent_sha: String,
    vendor_sha: String,
    clean_firmware_rebuild: String,
}

struct SnapshotRecord {
    source: String,
    build_source: String,
    commit: String,
    tree: String,
}

pub fn run(args: CpuCommitmentArgs) -> Result<String, String> {
    if args.self_test {
        self_test()?;
        return Ok("cpu-commitment controls passed".to_owned());
    }
    match args.command.ok_or(USAGE)? {
        CpuCommitmentCommand::Select { rows, target_dir } => select(&rows, &target_dir),
        CpuCommitmentCommand::Manifest(args) => match args.command {
            ManifestCommand::Write {
                evidence,
                msb,
                firmware,
                agent_sha,
                vendor_sha,
            } => {
                write_manifest(&evidence, &msb, &firmware, &agent_sha, &vendor_sha)?;
                Ok(String::new())
            }
            ManifestCommand::Verify {
                evidence,
                msb,
                firmware,
            } => {
                verify_manifest(&evidence, &msb, &firmware)?;
                Ok("manifest: ok".to_owned())
            }
        },
        CpuCommitmentCommand::Snapshot { source, target } => snapshot(&source, &target),
        CpuCommitmentCommand::ContainerIdentity { before, after } => {
            verify_container_identity(&before, &after)?;
            Ok("container identity: ok".to_owned())
        }
        CpuCommitmentCommand::CargoRow {
            reason,
            target,
            kind,
            test_profile,
            executable,
            success,
        } => cargo_row(
            &reason,
            &target,
            &kind,
            &test_profile,
            &executable,
            &success,
        ),
    }
}

/// The exit status this command asks for, when it asks for one of its own:
/// inconclusive evidence is 3, a bare invocation is the same misuse clap reports
/// as 2 for a bad argument list.
pub fn failure_status(error: &str) -> Option<i32> {
    if error.starts_with(INCONCLUSIVE) {
        Some(3)
    } else if error == USAGE {
        Some(2)
    } else {
        None
    }
}

fn select(rows_path: &Path, target_dir: &Path) -> Result<String, String> {
    let unreadable = |detail: String| {
        select_error(format!(
            "cannot read Cargo JSON {}: {detail}",
            rows_path.display()
        ))
    };
    let text = fs::read_to_string(rows_path).map_err(|error| unreadable(error.to_string()))?;
    let rows = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line).map_err(|error| unreadable(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(index) = rows.iter().position(|row| !row.is_object()) {
        return Err(unreadable(format!("row {} is not an object", index + 1)));
    }
    let finished = rows
        .iter()
        .filter(|row| field_is(row, "reason", "build-finished"))
        .collect::<Vec<_>>();
    if finished.is_empty() {
        return Err(select_error(format!(
            "{} has no build-finished record",
            rows_path.display()
        )));
    }
    if finished
        .iter()
        .any(|row| row.get("success").and_then(Value::as_bool) != Some(true))
    {
        return Err(select_error(format!(
            "{} reports a failed build",
            rows_path.display()
        )));
    }
    let artifacts = rows
        .iter()
        .filter(|row| {
            field_is(row, "reason", "compiler-artifact")
                && row
                    .get("target")
                    .and_then(|target| target.get("name"))
                    .and_then(Value::as_str)
                    == Some("agent-vm")
                && row
                    .get("target")
                    .and_then(|target| target.get("kind"))
                    .and_then(Value::as_array)
                    .is_some_and(|kind| kind.iter().any(|value| value.as_str() == Some("bin")))
                && row
                    .get("profile")
                    .and_then(|profile| profile.get("test"))
                    .and_then(Value::as_bool)
                    == Some(true)
                && executable_of(row).is_some()
        })
        .collect::<Vec<_>>();
    if artifacts.len() != 1 {
        return Err(select_error(format!(
            "expected exactly one agent-vm test artifact, got {}",
            artifacts.len()
        )));
    }
    let executable =
        Path::new(executable_of(artifacts[0]).expect("the artifact filter requires an executable"));
    let resolved = fs::canonicalize(executable).map_err(|error| {
        select_error(format!(
            "the artifact {} does not resolve: {error}",
            executable.display()
        ))
    })?;
    let root = fs::canonicalize(target_dir).map_err(|error| {
        select_error(format!(
            "the isolated target directory {} does not resolve: {error}",
            target_dir.display()
        ))
    })?;
    if !resolved.starts_with(&root) {
        return Err(select_error(format!(
            "the artifact {} is outside the isolated target dir {}",
            resolved.display(),
            root.display()
        )));
    }
    if !resolved.is_file() {
        return Err(select_error(format!(
            "the artifact {} is not a regular file",
            resolved.display()
        )));
    }
    Ok(resolved.display().to_string())
}

fn select_error(reason: String) -> String {
    format!("select: {reason}")
}

fn field_is(row: &Value, name: &str, expected: &str) -> bool {
    row.get(name).and_then(Value::as_str) == Some(expected)
}

fn executable_of(row: &Value) -> Option<&str> {
    row.get("executable")
        .and_then(Value::as_str)
        .filter(|executable| !executable.is_empty())
}

/// A fixture writer for the Cargo ledger controls: one JSON row, the same shape
/// Cargo emits, so the shell can build a positive and every refusal case.
fn cargo_row(
    reason: &str,
    target: &str,
    kind: &str,
    test_profile: &str,
    executable: &str,
    success: &str,
) -> Result<String, String> {
    let row = if reason == "compiler-artifact" {
        json!({
            "reason": reason,
            "target": {"name": target, "kind": [kind]},
            "profile": {"test": test_profile == "true"},
            "executable": executable,
        })
    } else {
        json!({"reason": reason, "success": success == "true"})
    };
    serde_json::to_string(&row).map_err(|error| format!("cargo-row: cannot encode row: {error}"))
}

fn write_manifest(
    evidence: &Path,
    msb: &Path,
    firmware: &Path,
    agent_sha: &str,
    vendor_sha: &str,
) -> Result<RuntimeManifest, String> {
    let manifest = RuntimeManifest {
        msb_path: canonical_string(msb)?,
        msb_sha256: sha256(msb)?,
        firmware_path: canonical_string(firmware)?,
        firmware_sha256: sha256(firmware)?,
        agent_sha: agent_sha.to_owned(),
        vendor_sha: vendor_sha.to_owned(),
        clean_firmware_rebuild: "UNPROVEN".to_owned(),
    };
    let path = evidence.join(MANIFEST);
    fs::write(&path, render_manifest(&manifest)?)
        .map_err(|error| format!("manifest: cannot write {}: {error}", path.display()))?;
    Ok(manifest)
}

fn verify_manifest(evidence: &Path, msb: &Path, firmware: &Path) -> Result<(), String> {
    let path = evidence.join(MANIFEST);
    let text = fs::read_to_string(&path).map_err(|error| {
        manifest_inconclusive(format!(
            "the manifest {} is unreadable: {error}",
            path.display()
        ))
    })?;
    let value: Value = serde_json::from_str(&text).map_err(|error| {
        manifest_inconclusive(format!(
            "the manifest {} is malformed: {error}",
            path.display()
        ))
    })?;
    let object = value.as_object().ok_or_else(|| {
        manifest_inconclusive("the manifest is malformed: not an object".to_owned())
    })?;
    let missing = REQUIRED
        .iter()
        .filter(|key| !object.get(**key).is_some_and(json_truthy))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(manifest_inconclusive(format!(
            "the manifest is missing {}",
            missing.join(", ")
        )));
    }
    let manifest = manifest_from_value(&value)
        .map_err(|reason| manifest_inconclusive(format!("the manifest is malformed: {reason}")))?;
    if manifest.clean_firmware_rebuild != "UNPROVEN" {
        return Err(manifest_inconclusive(
            "the manifest must state clean-from-source firmware rebuild UNPROVEN".to_owned(),
        ));
    }
    for (label, path_value, declared_path, declared_hash) in [
        ("MSB_PATH", msb, manifest.msb_path, manifest.msb_sha256),
        (
            "MSB_LIBKRUNFW_PATH",
            firmware,
            manifest.firmware_path,
            manifest.firmware_sha256,
        ),
    ] {
        let actual_path = fs::canonicalize(path_value).map_err(|error| {
            manifest_inconclusive(format!("{label} path cannot be resolved: {error}"))
        })?;
        let declared = fs::canonicalize(&declared_path).map_err(|error| {
            manifest_inconclusive(format!("{label} path cannot be resolved: {error}"))
        })?;
        if actual_path != declared {
            return Err(manifest_inconclusive(format!(
                "{label} {} != manifest {}",
                actual_path.display(),
                declared.display()
            )));
        }
        let actual = sha256(&actual_path)?;
        if actual != declared_hash.to_lowercase() {
            return Err(manifest_inconclusive(format!(
                "{label} sha256 {actual} != manifest {declared_hash}"
            )));
        }
    }
    Ok(())
}

fn manifest_inconclusive(reason: String) -> String {
    format!("{INCONCLUSIVE}{reason}")
}

fn manifest_from_value(value: &Value) -> Result<RuntimeManifest, &'static str> {
    let object = value.as_object().ok_or("not an object")?;
    let string = |name| {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or("a required value is not a string")
    };
    Ok(RuntimeManifest {
        msb_path: string("msb_path")?,
        msb_sha256: string("msb_sha256")?,
        firmware_path: string("firmware_path")?,
        firmware_sha256: string("firmware_sha256")?,
        agent_sha: string("agent_sha")?,
        vendor_sha: string("vendor_sha")?,
        clean_firmware_rebuild: string("clean_firmware_rebuild")?,
    })
}

/// JSON truthiness as the Python driver's `if not manifest.get(key)` read it.
fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_none_or(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn render_manifest(manifest: &RuntimeManifest) -> Result<String, String> {
    let fields = json!({
        "agent_sha": manifest.agent_sha,
        "clean_firmware_rebuild": manifest.clean_firmware_rebuild,
        "firmware_path": manifest.firmware_path,
        "firmware_sha256": manifest.firmware_sha256,
        "msb_path": manifest.msb_path,
        "msb_sha256": manifest.msb_sha256,
        "vendor_sha": manifest.vendor_sha,
    });
    pretty_json(&fields)
}

/// `json.dumps(indent=2, sort_keys=True) + "\n"`; `serde_json`'s map is sorted,
/// so key order is the same one the Python driver wrote.
fn pretty_json(value: &Value) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|text| format!("{text}\n"))
        .map_err(|error| format!("manifest: cannot encode JSON: {error}"))
}

fn canonical_string(path: &Path) -> Result<String, String> {
    fs::canonicalize(path)
        .map(|path| path.display().to_string())
        .map_err(|error| format!("manifest: cannot resolve {}: {error}", path.display()))
}

fn sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("manifest: cannot read {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .map_err(|error| format!("manifest: cannot read {}: {error}", path.display()))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn snapshot(source: &Path, target: &Path) -> Result<String, String> {
    let source = fs::canonicalize(source)
        .map_err(|error| format!("snapshot: cannot resolve {}: {error}", source.display()))?;
    let pin = git_text(&source, ["rev-parse", "HEAD"])?;
    let mut records = Vec::new();
    snapshot_at(&source, target, &pin, &mut records)?;
    Ok(records.join("\n"))
}

/// Clone `source` at `pin` into `target`, then recurse into every pinned
/// submodule. The ledger line order is the parent before its children, as the
/// Python driver wrote them.
fn snapshot_at(
    source: &Path,
    target: &Path,
    pin: &str,
    records: &mut Vec<String>,
) -> Result<(), String> {
    let head = git_text(source, ["rev-parse", "HEAD"])?;
    if head != pin {
        return Err(format!(
            "snapshot: {} is at {head}, not the pinned {pin}",
            source.display()
        ));
    }
    run_git(
        None,
        [
            OsStr::new("clone"),
            OsStr::new("--no-hardlinks"),
            OsStr::new("--no-checkout"),
            source.as_os_str(),
            target.as_os_str(),
        ],
    )?;
    run_git(
        Some(target),
        [
            OsStr::new("checkout"),
            OsStr::new("--detach"),
            OsStr::new(pin),
        ],
    )?;
    let target_text = fs::canonicalize(target)
        .map_err(|error| format!("snapshot: cannot resolve {}: {error}", target.display()))?
        .display()
        .to_string();
    let tree = git_text(source, ["rev-parse", &format!("{pin}^{{tree}}")])?;
    records.push(snapshot_line(&SnapshotRecord {
        source: source.display().to_string(),
        build_source: target_text,
        commit: pin.to_owned(),
        tree,
    })?);
    for entry in git_bytes(source, ["ls-tree", "-rz", pin])?.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let separator = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or("snapshot: malformed git tree entry")?;
        let (metadata, name) = (&entry[..separator], &entry[separator + 1..]);
        let mut fields = metadata.split(|byte| byte.is_ascii_whitespace());
        let mode = fields.next().ok_or("snapshot: malformed git tree entry")?;
        let _kind = fields.next().ok_or("snapshot: malformed git tree entry")?;
        let sha = fields.next().ok_or("snapshot: malformed git tree entry")?;
        if mode != b"160000" {
            continue;
        }
        let relative = std::str::from_utf8(name)
            .map_err(|_| "snapshot: a Git submodule path is not UTF-8".to_owned())?;
        let child_pin = std::str::from_utf8(sha)
            .map_err(|_| "snapshot: a Git submodule commit is not UTF-8".to_owned())?;
        snapshot_at(
            &source.join(relative),
            &target.join(relative),
            child_pin,
            records,
        )?;
    }
    Ok(())
}

/// One ledger line, byte-compatible with the Python driver's `json.dumps`: the
/// same four keys in the same order, with the same `", "` and `": "` separators.
fn snapshot_line(record: &SnapshotRecord) -> Result<String, String> {
    let quote = |text: &str| {
        serde_json::to_string(text)
            .map_err(|error| format!("snapshot: cannot encode receipt: {error}"))
    };
    Ok(format!(
        r#"{{"source": {}, "build_source": {}, "commit": {}, "tree": {}}}"#,
        quote(&record.source)?,
        quote(&record.build_source)?,
        quote(&record.commit)?,
        quote(&record.tree)?
    ))
}

fn git_text<'a>(
    directory: &Path,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Result<String, String> {
    let output = git_bytes(directory, arguments)?;
    String::from_utf8(output)
        .map_err(|_| {
            format!(
                "snapshot: git output for {} is not UTF-8",
                directory.display()
            )
        })
        .map(|text| text.trim().to_owned())
}

fn git_bytes<'a>(
    directory: &Path,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .map_err(|error| format!("snapshot: cannot run git: {error}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "snapshot: git -C {} failed: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_git<'a>(
    directory: Option<&Path>,
    arguments: impl IntoIterator<Item = &'a OsStr>,
) -> Result<(), String> {
    let mut command = Command::new("git");
    if let Some(directory) = directory {
        command.arg("-C").arg(directory);
    }
    let output = command
        .args(arguments)
        .output()
        .map_err(|error| format!("snapshot: cannot run git: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "snapshot: git {} failed: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Both receipts must name the same image. A missing `Id` or `RepoDigests` is a
/// refusal, not two absent values that happen to be equal.
fn verify_container_identity(before: &Path, after: &Path) -> Result<(), String> {
    let receipt = |path: &Path| -> Result<Value, String> {
        let text = fs::read_to_string(path).map_err(|error| {
            format!(
                "container identity: cannot read {}: {error}",
                path.display()
            )
        })?;
        let value: Value = serde_json::from_str(&text).map_err(|error| {
            format!(
                "container identity: cannot parse {}: {error}",
                path.display()
            )
        })?;
        value
            .as_array()
            .and_then(|items| items.first())
            .cloned()
            .ok_or_else(|| {
                format!(
                    "container identity: {} is not a nonempty inspect array",
                    path.display()
                )
            })
    };
    let before = receipt(before)?;
    let after = receipt(after)?;
    let (before_id, before_digests) = image_identity(&before);
    let (after_id, after_digests) = image_identity(&after);
    if before_id.is_none()
        || after_id.is_none()
        || before_digests.is_none()
        || after_digests.is_none()
        || before_digests.is_some_and(Vec::is_empty)
    {
        return Err("container identity: an inspect receipt has no image identity".to_owned());
    }
    if before_id != after_id || before_digests != after_digests {
        return Err("container identity: the image identity changed".to_owned());
    }
    Ok(())
}

fn image_identity(value: &Value) -> (Option<&str>, Option<&Vec<Value>>) {
    (
        value.get("Id").and_then(Value::as_str),
        value.get("RepoDigests").and_then(Value::as_array),
    )
}

fn self_test() -> Result<(), String> {
    selector_controls()?;
    manifest_controls()?;
    snapshot_controls()?;
    container_identity_controls()?;
    manifest_golden_controls()?;
    Ok(())
}

fn selector_controls() -> Result<(), String> {
    let temporary = Temporary::new("cpu-commitment-select")?;
    let target = temporary.path.join("isolated");
    let deps = target.join("deps");
    fs::create_dir_all(&deps).map_err(|error| error.to_string())?;
    let executable = deps.join("agent_vm-aaaa");
    fs::write(&executable, "fixture").map_err(|error| error.to_string())?;
    let finished = json!({"reason":"build-finished","success":true});
    let artifact = |path: &Path| json!({"reason":"compiler-artifact","target":{"name":"agent-vm","kind":["bin"]},"profile":{"test":true},"executable":path});
    write_rows(
        &temporary.path.join("good.jsonl"),
        &[finished.clone(), artifact(&executable)],
    )?;
    if select(&temporary.path.join("good.jsonl"), &target)? != canonical_string(&executable)? {
        return Err("selector positive control chose the wrong executable".to_owned());
    }
    let refusals = [
        ("zero", vec![finished.clone()]),
        (
            "two",
            vec![
                finished.clone(),
                artifact(&executable),
                artifact(&deps.join("agent_vm-bbbb")),
            ],
        ),
        (
            "lib-only",
            vec![
                finished.clone(),
                json!({"reason":"compiler-artifact","target":{"name":"agent-vm","kind":["lib"]},"profile":{"test":false}}),
            ],
        ),
        (
            "failed-build",
            vec![
                json!({"reason":"build-finished","success":false}),
                artifact(&executable),
            ],
        ),
        ("no-build-finished", vec![artifact(&executable)]),
    ];
    for (name, rows) in refusals {
        let path = temporary.path.join(format!("{name}.jsonl"));
        write_rows(&path, &rows)?;
        if select(&path, &target).is_ok() {
            return Err(format!("selector accepted {name}"));
        }
    }
    let outside = temporary.path.join("outside-agent-vm");
    fs::write(&outside, "fixture").map_err(|error| error.to_string())?;
    let outside_rows = temporary.path.join("outside.jsonl");
    write_rows(&outside_rows, &[finished.clone(), artifact(&outside)])?;
    if select(&outside_rows, &target).is_ok() {
        return Err("selector accepted an artifact outside the isolated target".to_owned());
    }
    let other = temporary.path.join("other-target/deps");
    fs::create_dir_all(&other).map_err(|error| error.to_string())?;
    fs::write(other.join("agent_vm-stale"), "fixture").map_err(|error| error.to_string())?;
    if select(&outside_rows, &target).is_ok() {
        return Err("selector found a stale artifact by name".to_owned());
    }
    let missing = deps.join("does-not-exist");
    let missing_rows = temporary.path.join("missing.jsonl");
    write_rows(&missing_rows, &[finished, artifact(&missing)])?;
    if select(&missing_rows, &target).is_ok() {
        return Err("selector accepted a missing artifact".to_owned());
    }
    fs::write(temporary.path.join("malformed.jsonl"), "not JSON\n")
        .map_err(|error| error.to_string())?;
    if select(&temporary.path.join("malformed.jsonl"), &target).is_ok() {
        return Err("selector accepted malformed Cargo JSON".to_owned());
    }
    if select(
        &temporary.path.join("good.jsonl"),
        &temporary.path.join("no-such-target"),
    )
    .is_ok()
    {
        return Err("selector accepted an isolated target that does not resolve".to_owned());
    }
    println!("cpu-commitment selection controls passed");
    Ok(())
}

fn write_rows(path: &Path, rows: &[Value]) -> Result<(), String> {
    let mut text = String::new();
    for row in rows {
        text.push_str(&serde_json::to_string(row).map_err(|error| error.to_string())?);
        text.push('\n');
    }
    fs::write(path, text).map_err(|error| error.to_string())
}

fn manifest_controls() -> Result<(), String> {
    let temporary = Temporary::new("cpu-commitment-manifest")?;
    let evidence = temporary.path.join("evidence");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    let msb = temporary.path.join("msb");
    let firmware = temporary.path.join("firmware");
    fs::write(&msb, "msb").map_err(|error| error.to_string())?;
    fs::write(&firmware, "firmware").map_err(|error| error.to_string())?;
    write_manifest(&evidence, &msb, &firmware, &"a".repeat(40), &"b".repeat(40))?;
    verify_manifest(&evidence, &msb, &firmware)?;
    let missing = temporary.path.join("missing");
    fs::create_dir_all(&missing).map_err(|error| error.to_string())?;
    if verify_manifest(&missing, &msb, &firmware).is_ok() {
        return Err("manifest verifier accepted a missing manifest".to_owned());
    }
    let changed = temporary.path.join("changed-firmware");
    fs::write(&changed, "changed").map_err(|error| error.to_string())?;
    if verify_manifest(&evidence, &msb, &changed).is_ok() {
        return Err("manifest verifier accepted a mismatched runtime path".to_owned());
    }
    let mut value: Value = serde_json::from_str(
        &fs::read_to_string(evidence.join(MANIFEST)).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    value["clean_firmware_rebuild"] = Value::String("PROVEN".to_owned());
    fs::write(
        evidence.join(MANIFEST),
        serde_json::to_string(&value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if verify_manifest(&evidence, &msb, &firmware).is_ok() {
        return Err("manifest verifier accepted a proven firmware label".to_owned());
    }
    println!("cpu-commitment manifest controls passed");
    Ok(())
}

fn snapshot_controls() -> Result<(), String> {
    let temporary = Temporary::new("cpu-commitment-snapshot")?;
    let source = temporary.path.join("source");
    fs::create_dir_all(&source).map_err(|error| error.to_string())?;
    run_git(Some(&source), [OsStr::new("init")])?;
    run_git(
        Some(&source),
        [
            OsStr::new("config"),
            OsStr::new("user.email"),
            OsStr::new("harness@example.invalid"),
        ],
    )?;
    run_git(
        Some(&source),
        [
            OsStr::new("config"),
            OsStr::new("user.name"),
            OsStr::new("Harness"),
        ],
    )?;
    fs::write(source.join("tracked"), "fixture").map_err(|error| error.to_string())?;
    run_git(Some(&source), [OsStr::new("add"), OsStr::new("tracked")])?;
    run_git(
        Some(&source),
        [
            OsStr::new("commit"),
            OsStr::new("-m"),
            OsStr::new("fixture"),
        ],
    )?;
    let output = snapshot(&source, &temporary.path.join("copy"))?;
    let receipt: Value = serde_json::from_str(&output).map_err(|error| error.to_string())?;
    if receipt["source"]
        != fs::canonicalize(&source)
            .map_err(|error| error.to_string())?
            .display()
            .to_string()
        || receipt["commit"].as_str().is_none_or(str::is_empty)
        || !temporary.path.join("copy/tracked").is_file()
    {
        return Err("snapshot control did not produce a checked-out receipt".to_owned());
    }
    if snapshot(&source, &temporary.path.join("copy")).is_ok() {
        return Err("snapshot control accepted cloning over an existing tree".to_owned());
    }
    println!("cpu-commitment snapshot controls passed");
    Ok(())
}

fn container_identity_controls() -> Result<(), String> {
    let temporary = Temporary::new("cpu-commitment-container")?;
    let before = temporary.path.join("before.json");
    let after = temporary.path.join("after.json");
    fs::write(
        &before,
        r#"[{"Id":"sha256:one","RepoDigests":["fedora@sha256:one"]}]"#,
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        &after,
        r#"[{"Id":"sha256:one","RepoDigests":["fedora@sha256:one"]}]"#,
    )
    .map_err(|error| error.to_string())?;
    verify_container_identity(&before, &after)?;
    fs::write(
        &after,
        r#"[{"Id":"sha256:two","RepoDigests":["fedora@sha256:two"]}]"#,
    )
    .map_err(|error| error.to_string())?;
    if verify_container_identity(&before, &after).is_ok() {
        return Err("container identity accepted a changed image".to_owned());
    }
    fs::write(&after, r#"[{"Id":"sha256:one"}]"#).map_err(|error| error.to_string())?;
    if verify_container_identity(&before, &after).is_ok() {
        return Err("container identity accepted a receipt without digests".to_owned());
    }
    println!("cpu-commitment container identity controls passed");
    Ok(())
}

/// The manifest golden. The frozen bytes are the Python driver's own output, so
/// comparing the writer against them is not the writer grading itself. The three
/// mutations are the regressions a port can introduce -- a renamed field, a
/// changed key order, a dropped entry -- and the golden must reject each.
fn manifest_golden_controls() -> Result<(), String> {
    let temporary = Temporary::new("cpu-commitment-golden")?;
    let evidence = temporary.path.join("evidence");
    fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
    let msb = temporary.path.join("msb");
    let firmware = temporary.path.join("firmware");
    fs::write(&msb, "msb").map_err(|error| error.to_string())?;
    fs::write(&firmware, "firmware").map_err(|error| error.to_string())?;
    write_manifest(&evidence, &msb, &firmware, &"a".repeat(40), &"b".repeat(40))?;
    let written = fs::read_to_string(evidence.join(MANIFEST)).map_err(|error| error.to_string())?;
    // Only this run's temporary paths differ from the frozen fixture paths.
    let actual = written
        .replace(&canonical_string(&msb)?, GOLDEN_MSB_PATH)
        .replace(&canonical_string(&firmware)?, GOLDEN_FIRMWARE_PATH);
    if actual != GOLDEN_MANIFEST {
        return Err(format!(
            "runtime-manifest output differs from the frozen Python golden:\n{actual}"
        ));
    }

    let renamed = actual.replace("\"msb_path\"", "\"msbPath\"");
    if renamed == GOLDEN_MANIFEST {
        return Err("golden accepted a renamed manifest field".to_owned());
    }
    println!("runtime-manifest mutation PASS: field rename is rejected by the frozen golden");

    let reordered = swap_first_two_fields(&actual)?;
    if reordered == GOLDEN_MANIFEST {
        return Err("golden accepted a changed key order".to_owned());
    }
    println!("runtime-manifest mutation PASS: changed ordering is rejected by the frozen golden");

    let dropped = actual
        .lines()
        .filter(|line| !line.contains("\"vendor_sha\""))
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    if dropped == GOLDEN_MANIFEST {
        return Err("golden accepted a dropped manifest entry".to_owned());
    }
    println!("runtime-manifest mutation PASS: a dropped entry is rejected by the frozen golden");
    Ok(())
}

fn swap_first_two_fields(manifest: &str) -> Result<String, String> {
    let mut lines = manifest.lines().map(str::to_owned).collect::<Vec<_>>();
    if lines.len() < 4 {
        return Err("the runtime manifest has too few lines to reorder".to_owned());
    }
    lines.swap(1, 2);
    Ok(format!("{}\n", lines.join("\n")))
}

struct Temporary {
    path: PathBuf,
}

impl Temporary {
    fn new(label: &str) -> Result<Self, String> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)
            .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_hold() {
        self_test().expect("CPU-commitment controls pass");
    }

    #[test]
    fn frozen_manifest_is_the_python_drivers_output() {
        manifest_golden_controls().expect("runtime manifest golden holds");
    }

    #[test]
    fn inconclusive_evidence_is_not_a_refusal() {
        assert_eq!(
            failure_status("manifest: INCONCLUSIVE: the manifest is missing agent_sha"),
            Some(3)
        );
        assert_eq!(failure_status("select: expected exactly one"), None);
        assert_eq!(failure_status(USAGE), Some(2));
    }
}
