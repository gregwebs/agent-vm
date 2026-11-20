//! Boot-free integration tests for the **launch build** (`--dockerfile`, ADR-0061, #527).
//!
//! Each test spawns the real `agent-vm` with an isolated `HOME`/`AGENT_VM_STATE_DIR`,
//! a temp project directory, a **fake `docker`** that replays a real OCI archive,
//! and a fake runtime pair. Nothing about the importer or the cache is faked: the
//! archive is a genuine OCI layout consumed by the real native loader inside the
//! real binary, so "the build landed in the cache and the launch booted it" is
//! observed through the cache's own API and the launcher's `AGENT_VM_DEBUG_CONFIG`
//! dump rather than through the launcher's claims about itself.
//!
//! The launch runs to the debug dump and then fails at the faked runtime, which
//! is exactly the seam these tests need: everything ADR-0061 governs (Docker
//! argv, publication, read-back, `PullPolicy`, ordering, stdin, exit status,
//! stdout purity) happens before it.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use microsandbox_image::{GlobalCache, Reference};

#[path = "support/acquisition_gate.rs"]
mod acquisition_gate;
#[path = "support/fake_docker.rs"]
mod fake_docker;
#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/image_archive.rs"]
mod image_archive;
mod support;

use acquisition_gate::{AcquisitionGate, AcquisitionStage, GateReply, Peer};
use image_archive::{ArchiveSpec, LayerContent, Written};
use support::run_with_timeout;

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    _home: tempfile::TempDir,
    _state: tempfile::TempDir,
    _bin: tempfile::TempDir,
    _project: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    bin: PathBuf,
    project: PathBuf,
    docker_log: PathBuf,
    stdin_log: PathBuf,
    /// Extra child environment. `None` value means "unset".
    extra: Vec<(String, Option<OsString>)>,
}

impl Harness {
    fn new() -> Self {
        // `/tmp` rather than `support::project_tempdir()`: a real launch binds a
        // control socket under `<state>/msb-home/run/sandboxes/...`, and the
        // workspace `target/tmp` prefix would push that path past the 103-byte
        // Unix-socket limit. These tests assert no guest-mirrored path.
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let bin = tempfile::tempdir_in("/tmp").unwrap();
        let project = tempfile::tempdir_in("/tmp").unwrap();
        let docker_log = bin.path().join("docker.log");
        let stdin_log = bin.path().join("docker-stdin.log");

        fake_docker::write(&bin.path().join("docker"));
        fake_msb::write(bin.path());

        fs::write(project.path().join("Dockerfile"), "FROM scratch\n")
            .expect("write the project's Dockerfile");

        Self {
            home: home.path().to_path_buf(),
            state: state.path().to_path_buf(),
            bin: bin.path().to_path_buf(),
            project: project.path().to_path_buf(),
            _home: home,
            _state: state,
            _bin: bin,
            _project: project,
            docker_log,
            stdin_log,
            extra: Vec::new(),
        }
    }

    fn set(&mut self, key: &str, value: impl Into<OsString>) -> &mut Self {
        self.extra.push((key.to_string(), Some(value.into())));
        self
    }

    fn docker_exit(&mut self, code: i32) -> &mut Self {
        self.set("FAKE_DOCKER_EXIT", code.to_string())
    }

    /// Point the fake Docker at `written`'s archive, and have its probe report the
    /// manifest digest a real Docker would report for that build (ADR-0071 §5
    /// P1/P2: the probe's digest is the exported manifest's digest).
    fn replay(&mut self, written: &Written) -> &mut Self {
        self.set("FAKE_DOCKER_ARCHIVE", written.path.clone());
        self.set("FAKE_DOCKER_PROBE_DIGEST", written.manifest_digest.clone())
    }

    /// What the fake probe's `--metadata-file` reports. `None` writes no file at
    /// all, like a builder whose exporter reports nothing.
    fn probe_reports(&mut self, digest: Option<&str>) -> &mut Self {
        match digest {
            Some(digest) => self.set("FAKE_DOCKER_PROBE_DIGEST", digest),
            None => {
                self.extra
                    .push(("FAKE_DOCKER_PROBE_DIGEST".to_string(), None));
                self
            }
        }
    }

    /// Turn on `launch_build`'s debug lines: the hit and every fallback are
    /// specified to state themselves there (Q7, Q10), and nowhere else.
    fn debug(&mut self) -> &mut Self {
        self.set("RUST_LOG", "agent_vm::launch_build=debug")
    }

    /// Drop the harness's `AGENT_VM_DEBUG_CONFIG` opt-in, so stderr holds only
    /// what a default launch prints.
    fn default_stderr(&mut self) -> &mut Self {
        self.extra.push(("AGENT_VM_DEBUG_CONFIG".to_string(), None));
        self
    }

    /// Write a fresh OCI archive with `spec` under the harness's bin dir and
    /// point the fake Docker at it, returning what its bytes resolve to.
    fn replay_spec(&mut self, name: &str, spec: &ArchiveSpec) -> Written {
        let path = self.bin.join(name);
        let written = image_archive::write(&path, spec);
        self.replay(&written);
        written
    }

    fn dockerfile(&self) -> PathBuf {
        self.project.join("Dockerfile")
    }

    fn msb_home(&self) -> PathBuf {
        self.state.join("msb-home")
    }

    fn cache_dir(&self) -> PathBuf {
        self.msb_home().join("cache")
    }

    /// The internal reference for this harness's `Dockerfile`, computed the way
    /// ADR-0061 specifies: sha256 of the **canonical** path's bytes.
    fn internal_tag(&self) -> String {
        let canonical = self.dockerfile().canonicalize().unwrap();
        let digest = image_archive::sha256_hex(canonical.as_os_str().as_encoded_bytes());
        let hex = digest
            .strip_prefix("sha256:")
            .expect("sha256_hex names its algorithm");
        format!("agent-vm.invalid/dockerfile/{hex}:latest")
    }

    fn internal_repo(&self) -> String {
        self.internal_tag()
            .rsplit_once(':')
            .map(|(repo, _)| repo.to_string())
            .expect("the internal tag has a tag part")
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear();
        cmd.env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("HOME", &self.home)
            .env("AGENT_VM_STATE_DIR", &self.state)
            .env("MSB_PATH", self.bin.join("msb"))
            .env("FAKE_DOCKER_LOG", &self.docker_log)
            .env("FAKE_DOCKER_STDIN_LOG", &self.stdin_log)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .current_dir(&self.project);
        for (key, value) in &self.extra {
            match value {
                Some(value) => {
                    cmd.env(key, value);
                }
                None => {
                    cmd.env_remove(key);
                }
            }
        }
        cmd
    }

    fn run(&self, argv: &[&str]) -> Output {
        let mut cmd = self.base_command();
        cmd.args(argv);
        run_with_timeout(cmd, Duration::from_secs(90))
    }

    fn docker_calls(&self) -> Vec<Vec<OsString>> {
        fake_docker::calls(&self.docker_log)
    }

    /// What each Docker invocation read on stdin, in call order.
    fn docker_stdin(&self) -> Vec<Vec<u8>> {
        fake_docker::stdin_records(&self.stdin_log)
    }

    fn pins_file(&self) -> PathBuf {
        self.home.join(".config/agent-vm/image-pins.json")
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Whether an invocation is the launch-build **probe**: only it passes a
/// `--metadata-file` (ADR-0071).
fn is_probe(call: &[OsString]) -> bool {
    call.iter().any(|arg| arg == "--metadata-file")
}

/// A call's argv with its output group removed — `--output <VALUE>`, plus the
/// probe's `--metadata-file <PATH>` — so a probe and an export compare as the
/// same command except for where Docker sends the image (R2, Q10).
fn without_output(call: &[OsString]) -> Vec<OsString> {
    let at = call
        .iter()
        .position(|arg| arg == "--output")
        .unwrap_or_else(|| panic!("a launch build always names an output: {call:?}"));
    let end = if call.get(at + 2).is_some_and(|arg| arg == "--metadata-file") {
        at + 4
    } else {
        at + 2
    };
    let mut rest = call.to_vec();
    rest.drain(at..end);
    rest
}

/// A probe invocation's `--metadata-file` path.
fn probe_metadata(call: &[OsString]) -> PathBuf {
    let at = call
        .iter()
        .position(|arg| arg == "--metadata-file")
        .unwrap_or_else(|| panic!("not a probe invocation: {call:?}"));
    PathBuf::from(&call[at + 1])
}

/// Pump the acquisition gate for one whole launch: refuse the first validated
/// cache read with a reply the gate makes an error, let every other checkpoint
/// through, and stop when the launch reports that create returned.
///
/// Returns whether a cache read was refused. A launch reaches `create-returned`
/// even when `create` fails, so the pump always terminates with the child.
fn refuse_the_first_cache_read(gate: &mut AcquisitionGate) -> bool {
    let mut refused = false;
    let mut answered = 0usize;
    while let Some((stage, checkpoint)) = gate.next_within(Duration::from_secs(30)) {
        answered += 1;
        assert!(answered < 64, "the launch never stopped asking: {stage:?}");
        if !refused && stage == AcquisitionStage::CacheValidated {
            refused = true;
            // An unknown reply is an acquisition error at any stage: a cache
            // read that fails, which is the probe problem under test.
            checkpoint.reply_unexpected("refuse-cache-read");
        } else {
            checkpoint.reply(GateReply::Continue);
        }
        if refused && stage == AcquisitionStage::CreateReturned {
            break;
        }
    }
    refused
}

/// A call's argv as lossy strings, for messages and flag positions.
fn rendered(call: &[OsString]) -> Vec<String> {
    call.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

fn stderr_of(output: &Output) -> String {
    text(&output.stderr)
}

fn code_of(output: &Output) -> i32 {
    output
        .status
        .code()
        .unwrap_or_else(|| panic!("agent-vm died by signal: {:?}", output.status))
}

/// Every word the probe's own notices use. A default-stderr line naming any of
/// them is a probe outcome, which Q7 keeps off that channel.
const PROBE_WORDS: [&str; 6] = [
    "launch-build",
    "probe",
    "buildx",
    "metadata",
    "digest",
    "cached",
];

/// Assert `stderr` names nothing from [`PROBE_WORDS`].
///
/// The expected stream is not asserted in full: its temp paths, the sandbox
/// name's process-id suffix and the host-dependent notices (git identity,
/// credentials) vary per run and per host.
fn assert_probe_silence(stderr: &str, what: &str) {
    let lowered = stderr.to_lowercase();
    let named: Vec<&str> = PROBE_WORDS
        .into_iter()
        .filter(|word| lowered.contains(word))
        .collect();
    assert!(
        named.is_empty(),
        "{what} names {named:?} outside the debug channel:\n{stderr}"
    );
}

/// The `SandboxConfig` JSON the launcher dumps right before create.
fn debug_config_json(stderr: &str) -> serde_json::Value {
    const MARKER: &str = "[debug] sandbox config JSON: ";
    let idx = stderr
        .find(MARKER)
        .unwrap_or_else(|| panic!("no debug config JSON found in stderr:\n{stderr}"));
    let rest = &stderr[idx + MARKER.len()..];
    serde_json::Deserializer::from_str(rest)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| panic!("no JSON value found after the debug marker:\n{stderr}"))
        .unwrap_or_else(|e| panic!("debug config JSON failed to parse: {e}\nstderr:\n{stderr}"))
}

/// The image reference the SDK was actually handed.
fn sdk_image(stderr: &str) -> String {
    let config = debug_config_json(stderr);
    config["image"]["Oci"]["reference"]
        .as_str()
        .unwrap_or_else(|| panic!("the dumped config has no OCI image reference:\n{config}"))
        .to_string()
}

fn cache(cache_dir: &Path) -> GlobalCache {
    GlobalCache::new(cache_dir).expect("open the fixture cache")
}

fn manifest_digest_of(cache_dir: &Path, raw: &str) -> Option<String> {
    let reference: Reference = raw.parse().expect("test reference parses");
    cache(cache_dir)
        .read_image_metadata(&reference)
        .expect("read image metadata")
        .map(|meta| meta.manifest_digest)
}

/// Names directly under `dir` (by file name), for "no session state" assertions.
fn entries(dir: &Path) -> Vec<String> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = read
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The whole contract in one launch: the Docker argv is exactly the owned set,
/// the archive is published under the internal tag, the SDK is handed
/// `repo@<built digest>` with `PullPolicy::Never`, the banner names the typed
/// path, and no pin is written.
#[test]
fn builds_publishes_and_boots_the_built_digest() {
    let mut h = Harness::new();
    let written = h.replay_spec("built.tar", &ArchiveSpec::default());

    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("[debug] sandbox config JSON: "),
        "the launch must reach the SDK with a built image:\n{stderr}"
    );

    // Docker saw the probe, then the export: the same owned flag set plus the
    // file and the context, differing only in their output group.
    let calls = h.docker_calls();
    assert_eq!(
        calls.len(),
        2,
        "a cold launch probes, then exports: {calls:?}"
    );
    assert!(is_probe(&calls[0]), "the probe runs first: {calls:?}");
    assert!(!is_probe(&calls[1]), "the export runs second: {calls:?}");
    assert_eq!(
        without_output(&calls[0]),
        without_output(&calls[1]),
        "probe and export differ only in where Docker sends the image"
    );
    for (index, call) in calls.iter().enumerate() {
        let argv = rendered(call);
        assert_eq!(&argv[0..2], ["buildx", "build"], "call {index}: {argv:?}");
        assert!(
            !argv.iter().any(|arg| arg == "-t" || arg == "--tag"),
            "call {index}: a launch build names no tag of its own: {argv:?}"
        );
        assert!(
            !argv
                .iter()
                .any(|arg| arg.starts_with("--builder") || arg.starts_with("--progress")),
            "call {index}: a launch build passes no builder/progress options: {argv:?}"
        );
        let file_position = argv
            .iter()
            .position(|arg| arg == "-f")
            .unwrap_or_else(|| panic!("call {index}: no -f in {argv:?}"));
        assert_eq!(
            PathBuf::from(&argv[file_position + 1]),
            h.dockerfile().canonicalize().unwrap(),
            "call {index}: the Dockerfile is passed by absolute path: {argv:?}"
        );
        assert_eq!(
            PathBuf::from(argv.last().unwrap()),
            h.project.canonicalize().unwrap(),
            "call {index}: the context is the Dockerfile's own directory: {argv:?}"
        );
    }
    // The probe's own group: no image written anywhere, and one metadata file in
    // this launch's private staging dir.
    let probe = rendered(&calls[0]);
    let output = probe
        .iter()
        .position(|arg| arg == "--output")
        .expect("the probe names its output");
    assert_eq!(
        probe[output + 1],
        "type=image,oci-mediatypes=true,store=false",
        "the probe writes no Docker-store image and reports the OCI digest: {probe:?}"
    );
    let metadata = probe_metadata(&calls[0]);
    assert_eq!(metadata.file_name().unwrap(), "probe.json");
    assert!(
        metadata.starts_with(h.msb_home().join("tmp")),
        "the probe's metadata lives in the staging root: {}",
        metadata.display()
    );
    assert!(
        !metadata.exists(),
        "the staging dir holding the probe's metadata is gone afterwards: {}",
        metadata.display()
    );

    // The archive landed in the cache under the internal tag, at its own digest.
    assert_eq!(
        manifest_digest_of(&h.cache_dir(), &h.internal_tag()).as_deref(),
        Some(written.manifest_digest.as_str()),
        "the internal tag must name the built manifest"
    );

    // What the SDK boots is that digest, not the moving tag, and never from a
    // registry: R16 needs both the immutable reference *and* `PullPolicy::Never`.
    let config = debug_config_json(&stderr);
    let image = sdk_image(&stderr);
    assert_eq!(
        image,
        format!("{}@{}", h.internal_repo(), written.manifest_digest),
        "the SDK gets an immutable repo@digest"
    );
    assert_eq!(
        config["pull_policy"], "Never",
        "a launch build must never contact a registry for its own image"
    );

    // The banner names the typed path, not the internal name.
    assert!(
        stderr.contains("==> Boot image: --dockerfile Dockerfile"),
        "the banner shows the typed path:\n{stderr}"
    );
    assert!(
        !stderr.contains("==> Boot image: agent-vm.invalid"),
        "the internal name is never the banner:\n{stderr}"
    );

    // Typing the flag is the consent: no pin record, no retained default, and
    // no approval store access at all.
    assert!(
        !h.home.join(".config/agent-vm").exists(),
        "a launch build writes nothing under ~/.config/agent-vm: {:?}",
        entries(&h.home.join(".config"))
    );
}

/// The context is the typed parent, not the project directory.
#[test]
fn context_is_the_typed_parent() {
    let mut h = Harness::new();
    fs::create_dir(h.project.join("sub")).unwrap();
    fs::write(h.project.join("sub/Dockerfile"), "FROM scratch\n").unwrap();
    h.replay_spec("built.tar", &ArchiveSpec::default());

    let out = h.run(&["--dockerfile", "sub/Dockerfile", "--", "true"]);
    assert!(
        stderr_of(&out).contains("[debug] sandbox config JSON: "),
        "the launch must reach the SDK:\n{}",
        stderr_of(&out)
    );

    let calls = h.docker_calls();
    assert_eq!(calls.len(), 2, "probe + export: {calls:?}");
    for call in &calls {
        let argv = rendered(call);
        assert_eq!(
            PathBuf::from(argv.last().unwrap()),
            h.project.canonicalize().unwrap().join("sub"),
            "the context is the Dockerfile's own directory: {argv:?}"
        );
    }
}

/// `-f` gets the **typed** path and the context its typed parent, even when the
/// Dockerfile is reached through a symlink — the integration case the unit test
/// mirrors, and the one a real Docker would read the wrong file for.
#[test]
fn dockerfile_argument_is_the_typed_path_through_a_symlink() {
    let mut h = Harness::new();
    fs::create_dir(h.project.join("real")).unwrap();
    fs::write(h.project.join("real/Dockerfile"), "FROM scratch\n").unwrap();
    fs::create_dir(h.project.join("link")).unwrap();
    std::os::unix::fs::symlink("../real/Dockerfile", h.project.join("link/Dockerfile")).unwrap();
    h.replay_spec("built.tar", &ArchiveSpec::default());

    let out = h.run(&["--dockerfile", "link/Dockerfile", "--", "true"]);
    assert!(
        stderr_of(&out).contains("[debug] sandbox config JSON: "),
        "the launch must reach the SDK:\n{}",
        stderr_of(&out)
    );

    // Built from the typed spelling. `current_dir()` is already resolved, so the
    // typed path is `cwd/link/Dockerfile` — not the `real/` path the symlink
    // names, which is what canonicalizing here would hand Docker.
    let cwd = h.project.canonicalize().unwrap();
    let calls = h.docker_calls();
    assert_eq!(calls.len(), 2, "probe + export: {calls:?}");
    for call in &calls {
        let argv = rendered(call);
        let file_position = argv
            .iter()
            .position(|arg| arg == "-f")
            .unwrap_or_else(|| panic!("no -f in {argv:?}"));
        assert_eq!(
            PathBuf::from(&argv[file_position + 1]),
            cwd.join("link/Dockerfile"),
            "the typed path, not the symlink target: {argv:?}"
        );
        assert_eq!(
            PathBuf::from(argv.last().unwrap()),
            cwd.join("link"),
            "the context is the typed parent: {argv:?}"
        );
    }

    // Only the *tag* is hashed from the canonical path, so the same Dockerfile
    // reached two ways is one cache entry.
    let canonical = h.project.join("real/Dockerfile").canonicalize().unwrap();
    let digest = image_archive::sha256_hex(canonical.as_os_str().as_encoded_bytes());
    let expected = format!(
        "agent-vm.invalid/dockerfile/{}:latest",
        digest
            .strip_prefix("sha256:")
            .expect("sha256_hex names its algorithm")
    );
    assert!(
        manifest_digest_of(&h.cache_dir(), &expected).is_some(),
        "the internal tag hashes the canonical path, so link/ and real/ share one entry"
    );
}

/// A rebuild boots the new content, with no prompt and no pin.
#[test]
fn rebuild_boots_new_content_without_prompt() {
    let mut h = Harness::new();
    let first = h.replay_spec(
        "first.tar",
        &ArchiveSpec {
            layer: LayerContent::Valid,
            marker: "first".to_string(),
            ..ArchiveSpec::default()
        },
    );
    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let first_image = sdk_image(&stderr_of(&out));

    let second = h.replay_spec(
        "second.tar",
        &ArchiveSpec {
            layer: LayerContent::Valid,
            marker: "second".to_string(),
            ..ArchiveSpec::default()
        },
    );
    assert_ne!(
        first.manifest_digest, second.manifest_digest,
        "the fixture must produce different content"
    );
    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    let second_image = sdk_image(&stderr);

    assert_ne!(
        first_image, second_image,
        "a rebuild must boot the new content, not a cached decision"
    );
    assert!(
        second_image.ends_with(&second.manifest_digest),
        "the second launch boots the second digest: {second_image}"
    );
    assert!(
        !stderr.contains("Do you want to")
            && !stderr.contains("Approve")
            && !stderr.contains("--yes"),
        "a launch build never prompts:\n{stderr}"
    );
    assert!(
        !h.pins_file().exists(),
        "a rebuild writes no image pin either"
    );
    assert_eq!(
        h.docker_calls().len(),
        4,
        "two launches, each probe + export"
    );
}

/// A well-formed `AGENT_VM_IMAGE_TAG` is ignored rather than conflicting.
#[test]
fn env_image_is_ignored() {
    let mut h = Harness::new();
    let written = h.replay_spec("built.tar", &ArchiveSpec::default());
    h.set("AGENT_VM_IMAGE_TAG", "bogus.invalid/never-pulled:1");

    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("[debug] sandbox config JSON: "),
        "the launch must reach the SDK even with an image in the environment:\n{stderr}"
    );
    assert_eq!(
        sdk_image(&stderr),
        format!("{}@{}", h.internal_repo(), written.manifest_digest),
        "--dockerfile outranks AGENT_VM_IMAGE_TAG"
    );
    assert_eq!(h.docker_calls().len(), 2, "probe + export, once");
}

/// On a direct route the launcher's stdout carries nothing of Docker's.
#[test]
fn stdout_is_only_the_guest_program() {
    let mut h = Harness::new();
    h.set("FAKE_DOCKER_STDERR_MARKER", "FAKE_DOCKER_STDERR_MARKER:527");
    h.replay_spec("built.tar", &ArchiveSpec::default());

    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stdout = text(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "the launcher writes nothing to stdout on a direct route, got:\n{stdout}"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("FAKE_DOCKER_STDERR_MARKER:527"),
        "Docker's own output goes to stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("==> Building --dockerfile Dockerfile (context "),
        "the build notice goes to stderr:\n{stderr}"
    );
}

/// Paths that cannot name a Dockerfile fail before Docker runs, with a
/// message that says what is wrong.
#[test]
fn empty_and_directory_dockerfile_fail_before_docker() {
    let h = Harness::new();

    // An empty value never reaches the launcher: clap reports it as a missing
    // value (status 2) because an empty argument names nothing. `resolve_from`'s
    // own empty-value error is therefore a library-level guard, covered by unit
    // tests, not a reachable CLI path.
    let out = h.run(&["--dockerfile", "", "--", "true"]);
    assert_eq!(code_of(&out), 2, "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("--dockerfile"),
        "{}",
        stderr_of(&out)
    );
    assert!(h.docker_calls().is_empty(), "no Docker run attempted");

    let cases: [(&str, &str); 2] = [
        (".", "is not a regular file"),
        ("Dockerfile/", "resolving --dockerfile Dockerfile/"),
    ];
    for (value, expected) in cases {
        let out = h.run(&["--dockerfile", value, "--", "true"]);
        assert_eq!(
            code_of(&out),
            125,
            "--dockerfile {value:?} must fail as a direct launch:\n{}",
            stderr_of(&out)
        );
        assert!(
            stderr_of(&out).contains(expected),
            "--dockerfile {value:?} should say {expected:?}:\n{}",
            stderr_of(&out)
        );
        assert!(
            h.docker_calls().is_empty(),
            "--dockerfile {value:?} must fail before Docker runs"
        );
    }
}

/// The staging directory under `MSB_HOME/tmp` is removed after success and
/// after a failed build.
#[test]
fn staging_dir_is_cleaned() {
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());
    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    assert!(
        stderr_of(&out).contains("[debug] sandbox config JSON: "),
        "the successful case must build:\n{}",
        stderr_of(&out)
    );
    let tmp = h.msb_home().join("tmp");
    assert!(
        tmp.is_dir(),
        "the staging root must exist where this test looks for leaks: {tmp:?}"
    );
    let left = entries(&tmp);
    assert!(
        left.iter().all(|name| !name.starts_with("image-")),
        "a successful build leaves no staging directory: {left:?}"
    );

    // A nonzero Docker exit.
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());
    h.docker_exit(3);
    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    assert_eq!(code_of(&out), 125);
    let tmp = h.msb_home().join("tmp");
    assert!(tmp.is_dir(), "{tmp:?}");
    let left = entries(&tmp);
    assert!(
        left.iter().all(|name| !name.starts_with("image-")),
        "a failed build leaves no staging directory: {left:?}"
    );

    // A successful export whose bytes cannot be published: the staging dir must
    // still be gone, since `publish` is a later `?` in the same scope.
    let mut h = Harness::new();
    let garbage = h.bin.join("garbage.tar");
    fs::write(&garbage, b"this is not an OCI archive").unwrap();
    h.set("FAKE_DOCKER_ARCHIVE", garbage);
    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    assert_eq!(code_of(&out), 125, "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("publishing the --dockerfile Dockerfile build result"),
        "the publication failure names the typed Dockerfile:\n{}",
        stderr_of(&out)
    );
    let tmp = h.msb_home().join("tmp");
    let left = entries(&tmp);
    assert!(
        left.iter().all(|name| !name.starts_with("image-")),
        "a failed publication leaves no staging directory: {left:?}"
    );
}

/// A config-file `image` is ignored too, not just the environment tier.
#[test]
fn config_image_is_ignored() {
    let mut h = Harness::new();
    let written = h.replay_spec("built.tar", &ArchiveSpec::default());
    fs::create_dir_all(h.project.join(".agent-vm")).unwrap();
    fs::write(
        h.project.join(".agent-vm/config.toml"),
        "image = \"never-used.invalid/x:1\"\n",
    )
    .unwrap();

    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("[debug] sandbox config JSON: "),
        "a configured image must not stop a launch build:\n{stderr}"
    );
    assert_eq!(
        sdk_image(&stderr),
        format!("{}@{}", h.internal_repo(), written.manifest_digest),
        "--dockerfile outranks a project config `image`"
    );
}

/// Pure CLI arithmetic must be rejected *before* the build: a `--memory` that
/// cannot be represented costs nothing, not a multi-minute Docker build.
#[test]
fn memory_overflow_fails_before_docker() {
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());

    let out = h.run(&[
        "--memory",
        "5000000",
        "--dockerfile",
        "Dockerfile",
        "--",
        "true",
    ]);
    assert_eq!(code_of(&out), 125, "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("--memory in GiB overflows u32 MiB"),
        "the failure is the CLI check:\n{}",
        stderr_of(&out)
    );
    assert!(
        h.docker_calls().is_empty(),
        "the build must not run for a CLI rejection"
    );
    assert!(
        !stderr_of(&out).contains("==> Building"),
        "no build notice either:\n{}",
        stderr_of(&out)
    );
    assert!(
        !stderr_of(&out).contains("==> Boot image:"),
        "no boot notice either, so the launch never started:\n{}",
        stderr_of(&out)
    );
}

/// A zero ceiling on either axis is refused while parsing, exactly like the
/// overflow above: no Docker build, no notice, no runtime prologue.
#[test]
fn zero_resource_ceiling_fails_before_docker() {
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());

    for (flag, message) in [
        ("--memory", "--memory must be at least 1 GiB"),
        ("--cpus", "--cpus must be at least 1"),
    ] {
        let out = h.run(&[flag, "0", "--dockerfile", "Dockerfile", "--", "true"]);
        assert_eq!(code_of(&out), 125, "{flag}: {}", stderr_of(&out));
        let stderr = stderr_of(&out);
        assert!(stderr.contains(message), "{flag}: {stderr}");
        assert!(
            h.docker_calls().is_empty(),
            "{flag}: the build must not run for a CLI rejection"
        );
        assert!(!stderr.contains("==> Building"), "{flag}: {stderr}");
        assert!(!stderr.contains("==> Boot image:"), "{flag}: {stderr}");
    }
}

/// A typed `--image` alongside `--dockerfile` is a usage error on both routes.
#[test]
fn typed_image_conflicts() {
    let h = Harness::new();
    for argv in [
        vec!["--dockerfile", "Dockerfile", "--image", "x:1", "shell"],
        vec!["--dockerfile", "Dockerfile", "--image", "x:1", "--", "true"],
    ] {
        let out = h.run(&argv);
        assert_eq!(
            code_of(&out),
            2,
            "{argv:?} must be a usage error:\n{}",
            stderr_of(&out)
        );
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("--dockerfile and --image cannot be used together"),
            "{argv:?} should name the conflict:\n{stderr}"
        );
        assert!(h.docker_calls().is_empty(), "{argv:?} must not run Docker");
        assert!(!h.msb_home().exists(), "{argv:?} must create no cache home");
    }
}

/// Docker's stdin is `/dev/null`, so the input meant for the guest survives.
#[test]
fn docker_never_sees_launcher_stdin() {
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());

    let mut cmd = h.base_command();
    cmd.args(["--dockerfile", "Dockerfile", "--", "cat", "-"]);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn agent-vm");
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(b"payload\n").expect("write payload");
    }
    let out = child.wait_with_output().expect("wait for agent-vm");

    assert!(
        h.stdin_log.exists(),
        "the fake Docker must have run:\n{}",
        text(&out.stderr)
    );
    let calls = h.docker_calls();
    let records = h.docker_stdin();
    assert_eq!(
        calls.len(),
        2,
        "a cold launch probes, then exports: {calls:?}"
    );
    assert!(is_probe(&calls[0]), "the probe runs first: {calls:?}");
    assert_eq!(
        records.len(),
        calls.len(),
        "one stdin record per Docker call: {records:?}"
    );
    for (index, (call, record)) in calls.iter().zip(&records).enumerate() {
        assert_eq!(
            record,
            b"",
            "the {} (call {index}) must receive /dev/null, not the launcher's reserved input",
            if is_probe(call) { "probe" } else { "export" }
        );
    }

    // The same launch again is a hit: one more call, and its probe is equally
    // starved of the launcher's stdin.
    let mut cmd = h.base_command();
    cmd.args(["--dockerfile", "Dockerfile", "--", "cat", "-"]);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn agent-vm");
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(b"payload\n").expect("write payload");
    }
    let out = child.wait_with_output().expect("wait for agent-vm");
    let calls = h.docker_calls();
    let records = h.docker_stdin();
    assert_eq!(calls.len(), 3, "the repeat launch probes once: {calls:?}");
    assert!(is_probe(&calls[2]), "and that call is the probe");
    assert_eq!(records.len(), 3, "one stdin record per Docker call");
    assert_eq!(
        records[2],
        b"",
        "the hit's probe must receive /dev/null too:\n{}",
        text(&out.stderr)
    );
}

/// AC1: a repeat launch of an unchanged Dockerfile makes exactly one Docker
/// call — the probe — and boots the cached `repo@D` with no export, no
/// publication, no tag move and no pin.
#[test]
fn a_repeat_launch_boots_the_cached_result_without_exporting() {
    let mut h = Harness::new();
    let written = h.replay_spec("built.tar", &ArchiveSpec::default());
    h.debug();

    let first = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    assert!(
        stderr_of(&first).contains("[debug] sandbox config JSON: "),
        "the cold launch must reach the SDK:\n{}",
        stderr_of(&first)
    );
    let calls = h.docker_calls().len();
    assert_eq!(calls, 2, "a cold launch probes, then exports");

    let second = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&second);
    assert!(
        stderr.contains("[debug] sandbox config JSON: "),
        "the warm launch must reach the SDK:\n{stderr}"
    );
    let all = h.docker_calls();
    assert_eq!(all.len(), 3, "the warm launch makes one call: {all:?}");
    assert!(
        is_probe(&all[2]),
        "and that call is the probe: {:?}",
        rendered(&all[2])
    );
    assert_eq!(
        sdk_image(&stderr),
        format!("{}@{}", h.internal_repo(), written.manifest_digest),
        "the hit boots the probed digest"
    );
    assert_eq!(
        debug_config_json(&stderr)["pull_policy"],
        "Never",
        "and never contacts a registry"
    );
    assert!(
        stderr.contains("==> Boot image: --dockerfile Dockerfile"),
        "the banner is unchanged by a hit:\n{stderr}"
    );
    assert!(
        stderr.contains("launch-build probe result is cached; skipping the export"),
        "a hit says so on the debug channel:\n{stderr}"
    );
    assert!(
        !h.pins_file().exists() && !h.home.join(".config/agent-vm").exists(),
        "a hit writes nothing under ~/.config/agent-vm"
    );
    let left = entries(&h.msb_home().join("tmp"));
    assert!(
        left.iter().all(|name| !name.starts_with("image-")),
        "a hit leaves no staging directory: {left:?}"
    );
}

/// AC4: A → B → A. The third launch boots A's cached digest, with one call, and
/// leaves the internal tag naming B (ADR-0071 §2, Q6).
#[test]
fn a_reverted_dockerfile_boots_its_cached_digest_and_leaves_the_tag() {
    let mut h = Harness::new();
    let a = h.replay_spec(
        "a.tar",
        &ArchiveSpec {
            layer: LayerContent::Valid,
            marker: "a".to_string(),
            ..ArchiveSpec::default()
        },
    );
    h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let b = h.replay_spec(
        "b.tar",
        &ArchiveSpec {
            layer: LayerContent::Valid,
            marker: "b".to_string(),
            ..ArchiveSpec::default()
        },
    );
    assert_ne!(a.manifest_digest, b.manifest_digest);
    h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    assert_eq!(
        manifest_digest_of(&h.cache_dir(), &h.internal_tag()).as_deref(),
        Some(b.manifest_digest.as_str())
    );

    // Back to A: the bytes from the first launch are still cached.
    h.replay(&a);
    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("[debug] sandbox config JSON: "),
        "the reverted launch must reach the SDK:\n{stderr}"
    );
    let calls = h.docker_calls();
    assert_eq!(
        calls.len(),
        5,
        "probe+export, probe+export, probe: {calls:?}"
    );
    assert!(is_probe(&calls[4]), "the last call is the probe");
    assert_eq!(
        sdk_image(&stderr),
        format!("{}@{}", h.internal_repo(), a.manifest_digest),
        "the reverted launch boots A, not the tag"
    );
    assert_eq!(
        manifest_digest_of(&h.cache_dir(), &h.internal_tag()).as_deref(),
        Some(b.manifest_digest.as_str()),
        "a hit leaves the internal tag naming B"
    );
}

/// F7: a probe whose digest the export disagrees with can never boot wrong
/// content: every launch misses, and the debug line names both digests.
#[test]
fn a_probe_digest_the_export_disagrees_with_is_logged() {
    let mut h = Harness::new();
    let written = h.replay_spec("built.tar", &ArchiveSpec::default());
    let invented = format!("sha256:{}", "a".repeat(64));
    h.debug().probe_reports(Some(&invented));

    for launch in 1..=2 {
        let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("[debug] sandbox config JSON: "),
            "launch {launch} must reach the SDK:\n{stderr}"
        );
        assert_eq!(
            sdk_image(&stderr),
            format!("{}@{}", h.internal_repo(), written.manifest_digest),
            "launch {launch} boots the export's verified digest"
        );
        assert!(
            stderr.contains("launch-build probe and export digests differ"),
            "launch {launch} names the disagreement:\n{stderr}"
        );
        assert!(
            stderr.contains(&invented) && stderr.contains(&written.manifest_digest),
            "launch {launch} names both digests:\n{stderr}"
        );
    }
    assert_eq!(
        h.docker_calls().len(),
        4,
        "a disagreement always degrades to probe + export: {:?}",
        h.docker_calls()
    );
}

/// AC5: a probe that reports nothing usable is a probe *problem*, not a build
/// failure — after a zero exit, agent-vm exports and boots the exported result,
/// saying so only on the debug channel.
#[test]
fn a_probe_without_a_digest_falls_back_to_the_export() {
    for report in [None, Some("not-a-digest"), Some("sha256:abc")] {
        let mut h = Harness::new();
        let written = h.replay_spec("built.tar", &ArchiveSpec::default());
        h.debug().probe_reports(report);

        for launch in 1..=2 {
            let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
            let stderr = stderr_of(&out);
            assert!(
                stderr.contains("[debug] sandbox config JSON: "),
                "launch {launch} with probe report {report:?} must reach the SDK:\n{stderr}"
            );
            // The harness fails at the faked runtime, as every row here does; what
            // matters is that the *build* did not fail (AC5's baseline status).
            assert_eq!(
                code_of(&out),
                125,
                "launch {launch} fails only at the faked runtime:\n{stderr}"
            );
            assert!(
                !stderr.contains("docker buildx build failed"),
                "a probe problem is never the build's failure:\n{stderr}"
            );
            assert_eq!(
                sdk_image(&stderr),
                format!("{}@{}", h.internal_repo(), written.manifest_digest),
                "launch {launch} boots the exported result"
            );
            assert!(
                stderr.contains("launch-build probe reported no usable digest; exporting"),
                "launch {launch} says why it exported:\n{stderr}"
            );
        }
        assert_eq!(
            h.docker_calls().len(),
            4,
            "each launch still probes and exports: {:?}",
            h.docker_calls()
        );
    }
}

/// F6 through the whole launch: a probe cache read that *fails* (not a miss) is
/// a probe problem, not a failure. The export really runs and the launch boots
/// the exported result.
#[test]
fn a_failed_probe_cache_read_still_exports_and_boots() {
    let mut h = Harness::new();
    let written = h.replay_spec("built.tar", &ArchiveSpec::default());
    h.debug();
    // Warm the cache, so this launch's probe read finds the digest and can fail
    // on it instead of missing.
    h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    assert_eq!(h.docker_calls().len(), 2, "probe + export, once");

    let mut gate = AcquisitionGate::new(&h.bin);
    let mut cmd = h.base_command();
    // The fine-grained stages, so the refusal lands on the cache read itself.
    cmd.env("AGENT_VM_TEST_ACQUIRE_GATE_DETAIL", "1");
    let peer = Peer::spawn(cmd, &gate, &["--dockerfile", "Dockerfile", "--", "true"]);
    assert!(
        refuse_the_first_cache_read(&mut gate),
        "the probe's cache read must reach a validated entry to fail on"
    );
    let out = peer.wait();

    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("[debug] sandbox config JSON: "),
        "a failed probe cache read must still reach the SDK:\n{stderr}"
    );
    assert!(
        stderr.contains("launch-build probe cache read failed; exporting"),
        "the fallback says why it exported:\n{stderr}"
    );
    assert!(
        !stderr.contains("docker buildx build failed"),
        "a cache read is never the build's failure:\n{stderr}"
    );
    assert_eq!(
        sdk_image(&stderr),
        format!("{}@{}", h.internal_repo(), written.manifest_digest),
        "the launch boots the exported result"
    );
    let calls = h.docker_calls();
    assert_eq!(
        calls.len(),
        4,
        "the warm launch probes, then exports: {calls:?}"
    );
    assert!(
        is_probe(&calls[2]),
        "the warm launch's first call is its probe"
    );
    assert!(
        !is_probe(&calls[3]),
        "and the second is the export the failed read fell back to"
    );
}

/// R7: after a zero probe exit, metadata that exists but cannot be read falls
/// back to the export. Silent, apart from the debug line.
#[test]
fn an_unreadable_probe_metadata_file_falls_back_to_the_export() {
    let mut h = Harness::new();
    let written = h.replay_spec("built.tar", &ArchiveSpec::default());
    h.debug().set("FAKE_DOCKER_PROBE_METADATA_UNREADABLE", "1");

    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("[debug] sandbox config JSON: "),
        "an unreadable metadata file must still reach the SDK:\n{stderr}"
    );
    assert!(
        !stderr.contains("docker buildx build failed"),
        "an unreadable metadata file is never the build's failure:\n{stderr}"
    );
    assert!(
        stderr.contains("launch-build probe reported no usable digest; exporting"),
        "the fallback says why it exported:\n{stderr}"
    );
    assert!(
        stderr.contains("the probe metadata file could not be read"),
        "and names the unreadable file as the reason:\n{stderr}"
    );
    assert_eq!(
        sdk_image(&stderr),
        format!("{}@{}", h.internal_repo(), written.manifest_digest),
        "the launch boots the exported result"
    );
    assert_eq!(
        h.docker_calls().len(),
        2,
        "probe + export: {:?}",
        h.docker_calls()
    );
}

/// Q7: nothing about the probe is user-visible. On default stderr a miss, a hit
/// and a fallback each print none of the probe's lines.
#[test]
fn probe_outcomes_are_silent_on_default_stderr() {
    // A miss: the first launch of new content, which exports. This is the arm
    // whose only probe notice is "not cached; exporting".
    let mut hit = Harness::new();
    hit.default_stderr();
    hit.replay_spec("built.tar", &ArchiveSpec::default());
    let out = hit.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("==> Boot image: --dockerfile Dockerfile"),
        "the first launch ran:\n{stderr}"
    );
    assert_probe_silence(&stderr, "a miss");

    // A hit: the second launch of unchanged content. No debug dump here: the
    // whole stream is checked, and the dump legitimately spells
    // `manifest_digest` and `cache`.
    let out = hit.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("==> Boot image: --dockerfile Dockerfile"),
        "the warm launch ran:\n{stderr}"
    );
    assert_probe_silence(&stderr, "a hit");

    // A fallback: a probe that reports nothing usable, every launch.
    let mut fallback = Harness::new();
    fallback.default_stderr();
    fallback.replay_spec("built.tar", &ArchiveSpec::default());
    fallback.probe_reports(None);
    let out = fallback.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("==> Boot image: --dockerfile Dockerfile"),
        "the falling-back launch ran:\n{stderr}"
    );
    assert_probe_silence(&stderr, "a fallback");
}

/// F8: Docker says the build succeeded and the *export* then fails. That is the
/// launcher's failure, with Docker's own status — the probe is never treated as
/// the build.
#[test]
fn an_export_failure_after_a_probe_is_the_launchers_failure() {
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());
    // A digest the cache cannot hold, so the probe cannot stand in for the export.
    h.probe_reports(Some(&format!("sha256:{}", "a".repeat(64))))
        .set("FAKE_DOCKER_EXPORT_EXIT", "4");

    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    let stderr = stderr_of(&out);
    assert_eq!(code_of(&out), 125, "{stderr}");
    assert!(
        stderr.contains("docker buildx build failed (exit 4)"),
        "the export's own status is reported:\n{stderr}"
    );
    assert!(
        !stderr.contains("[debug] sandbox config JSON: "),
        "a failed export never reaches the SDK:\n{stderr}"
    );
    assert_eq!(
        h.docker_calls().len(),
        2,
        "the probe and the export, and nothing more: {:?}",
        h.docker_calls()
    );
    assert_eq!(
        manifest_digest_of(&h.cache_dir(), &h.internal_tag()),
        None,
        "a failed export publishes nothing, even though the probe reported a digest"
    );
    let tmp = h.msb_home().join("tmp");
    let left = entries(&tmp);
    assert!(
        left.iter().all(|name| !name.starts_with("image-")),
        "a failed export leaves no staging directory: {left:?}"
    );
}

/// A failed build on a direct route is the launcher's own failure (125), it
/// happens before any session state exists, and nothing is published.
#[test]
fn failed_build_direct_exits_125_before_any_session_state() {
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());
    h.docker_exit(3);

    let out = h.run(&["--dockerfile", "Dockerfile", "--", "true"]);
    assert_eq!(
        code_of(&out),
        125,
        "Docker's exit 3 must never leak:\n{}",
        stderr_of(&out)
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("docker buildx build failed (exit 3)"),
        "the failure names Docker's status:\n{stderr}"
    );
    assert!(
        !stderr.contains("==> Boot image:"),
        "a failed build never reaches the banner:\n{stderr}"
    );
    assert!(
        !stderr.contains("[debug] sandbox config JSON: "),
        "a failed build never reaches the builder:\n{stderr}"
    );
    let state_entries = entries(&h.state);
    assert!(
        state_entries.iter().all(|name| name == "msb-home"),
        "a failed build provisions no session state: {state_entries:?}"
    );
    assert_eq!(
        manifest_digest_of(&h.cache_dir(), &h.internal_tag()),
        None,
        "a failed build publishes nothing"
    );
    assert_eq!(
        h.docker_calls().len(),
        1,
        "the failing probe is the build's failure, and nothing is re-run"
    );
}

/// The same failure on the tool route is exit 1, and still no banner.
#[test]
fn failed_build_tool_route_exits_1() {
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());
    h.docker_exit(3);

    let out = h.run(&["--dockerfile", "Dockerfile", "shell"]);
    assert_eq!(
        code_of(&out),
        1,
        "a tool launch reports its own failure:\n{}",
        stderr_of(&out)
    );
    assert!(
        !stderr_of(&out).contains("==> Boot image:"),
        "a failed build never reaches the banner:\n{}",
        stderr_of(&out)
    );
    assert_eq!(
        h.docker_calls().len(),
        1,
        "the failing probe is the build's failure, and nothing is re-run"
    );
}

/// A missing Dockerfile fails before Docker runs and creates no state.
#[test]
fn missing_dockerfile_fails_before_docker() {
    let h = Harness::new();
    let out = h.run(&["--dockerfile", "nope", "--", "true"]);
    assert_eq!(code_of(&out), 125, "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("resolving --dockerfile nope"),
        "{}",
        stderr_of(&out)
    );
    assert!(h.docker_calls().is_empty(), "no Docker run attempted");
    assert!(
        !h.msb_home().exists(),
        "a rejected path creates no cache home: {:?}",
        entries(&h.state)
    );
}

/// A missing Docker names the escape hatch instead of a bare ENOENT.
#[test]
fn missing_docker_names_the_hint() {
    let mut h = Harness::new();
    h.replay_spec("built.tar", &ArchiveSpec::default());

    // A PATH holding nothing at all: on Linux CI `/usr/bin` holds a real Docker,
    // so admitting it would run the real thing and pass for the wrong reason.
    // Everything this launch spawns before the build is named by absolute path
    // (`MSB_PATH`), so an empty PATH reaches exactly the spawn that is missing.
    let empty = h.bin.join("empty-path");
    fs::create_dir_all(&empty).unwrap();
    let mut cmd = h.base_command();
    cmd.env("PATH", empty.display().to_string());
    cmd.arg("--dockerfile").arg("Dockerfile");
    cmd.arg("--").arg("true");
    let out = run_with_timeout(cmd, Duration::from_secs(90));

    assert_eq!(code_of(&out), 125, "{}", stderr_of(&out));
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("running `docker buildx build` for --dockerfile Dockerfile"),
        "the failure must be the Docker spawn, not a later publish:\n{stderr}"
    );
    assert!(
        !stderr.contains("failed (exit"),
        "Docker never ran, so no exit status may be reported:\n{stderr}"
    );
    assert!(
        stderr.contains("agent-vm image build") && stderr.contains("BUILDX_BUILDER"),
        "a missing Docker should name both escape hatches:\n{stderr}"
    );
}

/// `setup` has no image selection, so it refuses the flag.
#[test]
fn setup_rejects_dockerfile() {
    let h = Harness::new();
    let out = h.run(&["--dockerfile", "Dockerfile", "setup"]);
    assert_eq!(
        code_of(&out),
        2,
        "setup must refuse --dockerfile:\n{}",
        stderr_of(&out)
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("'--dockerfile'"),
        "the refusal names the option:\n{stderr}"
    );
    assert!(h.docker_calls().is_empty(), "no Docker run attempted");
}
