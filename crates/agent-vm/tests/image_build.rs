//! Black-box integration tests for `agent-vm image build`/`image import` (#260).
//!
//! These spawn the real compiled `agent-vm` binary with a controlled
//! `HOME`/`AGENT_VM_STATE_DIR`/`MSB_PATH` and a **fake `docker` on PATH** that
//! records its argv and replays a real, tiny OCI archive on stdout. Nothing
//! about the importer is faked: the archive is written by
//! `support/image_archive.rs` and consumed by the real native
//! `microsandbox_image::load_archive` inside the real binary, so a successful
//! build proves the whole export → stage → native-import path works and lands
//! in the cache a launch reads.
//!
//! The tests were designed against the runtime's seams: the only external
//! process agent-vm runs on this path is Docker (`buildx build`), and Docker is
//! a data source (an archive) plus a status, both trivially controllable. The
//! native cache is observed through its own public API
//! (`GlobalCache::read_image_metadata`) rather than by reimplementing its
//! filename hashing.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Read as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use microsandbox_image::{CachedImageMetadata, GlobalCache, Reference};

#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/image_archive.rs"]
mod image_archive;
mod support;

use image_archive::{ArchiveSpec, LayerContent, PlatformSpec, Written};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

fn reference(raw: &str) -> Reference {
    raw.parse().expect("test reference parses")
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A fake Docker plus fake msb, an isolated private HOME/state, and the argv
/// log. One harness owns its temp dirs for its whole test.
struct Harness {
    _home: tempfile::TempDir,
    _state: tempfile::TempDir,
    _bin: tempfile::TempDir,
    _empty_path: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    bin: PathBuf,
    empty_path: PathBuf,
    docker_log: PathBuf,
    msb_log: PathBuf,
    archive: PathBuf,
    /// Extra child environment. `None` value means "unset".
    extra: Vec<(String, Option<OsString>)>,
    /// When true, PATH omits the fake-docker directory (Docker is missing).
    docker_missing: bool,
}

const FAKE_DOCKER_STDERR_MARKER: &str = "FAKE_DOCKER_STDERR_MARKER:260";

impl Harness {
    fn new() -> Self {
        let home = support::project_tempdir();
        let state = support::project_tempdir();
        let bin = support::project_tempdir();
        let empty_path = support::project_tempdir();
        let docker_log = bin.path().join("docker.log");
        let msb_log = bin.path().join("msb.log");
        let archive = home.path().join("replay.tar");

        write_fake_docker(&bin.path().join("docker"));
        write_fake_msb(&bin.path().join("msb"), fake_msb::VERSION_LINE);

        Self {
            home: home.path().to_path_buf(),
            state: state.path().to_path_buf(),
            bin: bin.path().to_path_buf(),
            empty_path: empty_path.path().to_path_buf(),
            _home: home,
            _state: state,
            _bin: bin,
            _empty_path: empty_path,
            docker_log,
            msb_log,
            archive,
            extra: Vec::new(),
            docker_missing: false,
        }
    }

    fn set(&mut self, key: &str, value: impl Into<OsString>) -> &mut Self {
        self.extra.push((key.to_string(), Some(value.into())));
        self
    }

    fn unset(&mut self, key: &str) -> &mut Self {
        self.extra.push((key.to_string(), None));
        self
    }

    fn docker_missing(&mut self) -> &mut Self {
        self.docker_missing = true;
        self
    }

    fn docker_exit(&mut self, code: i32) -> &mut Self {
        self.set("FAKE_DOCKER_EXIT", code.to_string())
    }

    fn docker_signal(&mut self, signal: &str) -> &mut Self {
        self.set("FAKE_DOCKER_SIGNAL", signal)
    }

    fn docker_emit_on_failure(&mut self) -> &mut Self {
        self.set("FAKE_DOCKER_EMIT_ON_FAILURE", "1")
    }

    fn docker_stderr_bytes(&mut self, bytes: usize) -> &mut Self {
        self.set("FAKE_DOCKER_STDERR_BYTES", bytes.to_string())
    }

    /// Point the fake Docker at `written`'s archive.
    fn replay(&mut self, written: &Written) -> &mut Self {
        self.archive = written.path.clone();
        self.set("FAKE_DOCKER_ARCHIVE", self.archive.clone())
    }

    /// Point the fake Docker at an arbitrary file (e.g. garbage or an archive
    /// built with a different reference).
    fn replay_file(&mut self, path: &Path) -> &mut Self {
        self.archive = path.to_path_buf();
        self.set("FAKE_DOCKER_ARCHIVE", self.archive.clone())
    }

    fn msb_home(&self) -> PathBuf {
        self.state.join("msb-home")
    }

    /// The private cache the ambient backend resolves with this harness's state.
    fn cache_dir(&self) -> PathBuf {
        self.msb_home().join("cache")
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear();
        let path = if self.docker_missing {
            format!("{}:/bin", self.empty_path.display())
        } else {
            format!("{}:/usr/bin:/bin", self.bin.display())
        };
        cmd.env("PATH", path)
            .env("HOME", &self.home)
            .env("AGENT_VM_STATE_DIR", &self.state)
            .env("MSB_PATH", self.bin.join("msb"))
            .env("FAKE_DOCKER_LOG", &self.docker_log)
            .env("FAKE_DOCKER_STDERR_MARKER", FAKE_DOCKER_STDERR_MARKER)
            .env("MSB_RECORD", &self.msb_log);
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

    fn run_os(&self, argv: &[OsString]) -> Output {
        let mut cmd = self.base_command();
        cmd.args(argv);
        run_with_timeout(cmd, Duration::from_secs(60))
    }

    fn run(&self, argv: &[&str]) -> Output {
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        self.run_os(&argv)
    }

    /// Every fake-Docker invocation's argv, in order.
    fn docker_calls(&self) -> Vec<Vec<OsString>> {
        let bytes = fs::read(&self.docker_log).unwrap_or_default();
        let mut calls: Vec<Vec<OsString>> = Vec::new();
        let mut current: Option<Vec<OsString>> = None;
        for token in bytes.split(|byte| *byte == 0) {
            match token {
                b"CALL" => current = Some(Vec::new()),
                b"END" => {
                    calls.push(current.take().expect("END after CALL"));
                }
                b"UNEXPECTED" | b"" => {}
                other => {
                    if let Some(call) = current.as_mut() {
                        call.push(OsString::from_vec(other.to_vec()));
                    }
                }
            }
        }
        assert!(current.is_none(), "the docker log ended mid-call");
        calls
    }

    /// Did the fake `msb` receive any invocation other than `--version`?
    fn msb_invocations(&self) -> Vec<Vec<OsString>> {
        let bytes = fs::read(&self.msb_log).unwrap_or_default();
        if bytes.is_empty() {
            return Vec::new();
        }
        vec![
            bytes
                .split(|byte| *byte == 0)
                .filter(|token| !token.is_empty())
                .map(|token| OsString::from_vec(token.to_vec()))
                .collect(),
        ]
    }
}

fn write_fake_docker(path: &Path) {
    let script = r#"#!/bin/bash
# Fake Docker for agent-vm image build/import tests. Records argv NUL-separated, replays a
# fixture archive on stdout, and can fail or die by signal on demand.
{
  printf 'CALL\0'
  for a in "$@"; do printf '%s\0' "$a"; done
  printf 'END\0'
} >> "${FAKE_DOCKER_LOG:?}"

case "${1:-} ${2:-}" in
  "buildx build") mode=build ;;
  "image save")
    [ "${3:-}" = --output ] && [ -n "${4:-}" ] && [ "${5:-}" = -- ] && [ "$#" -eq 6 ] || { printf 'UNEXPECTED\0' >> "$FAKE_DOCKER_LOG"; exit 97; }
    mode=save; out="$4" ;;
  *) printf 'UNEXPECTED\0' >> "${FAKE_DOCKER_LOG:?}"; echo "fake docker: unexpected subcommand" >&2; exit 97 ;;
esac

emit_archive() {
  if [ "$mode" = save ]; then cat "$FAKE_DOCKER_ARCHIVE" > "$out"; else cat "$FAKE_DOCKER_ARCHIVE"; fi
}

if [ -n "${FAKE_DOCKER_SLEEP:-}" ]; then
  sleep "${FAKE_DOCKER_SLEEP}"
fi

printf '%s\n' "${FAKE_DOCKER_STDERR_MARKER:-}" >&2

if [ -n "${FAKE_DOCKER_STDERR_BYTES:-}" ]; then
  head -c "${FAKE_DOCKER_STDERR_BYTES}" /dev/zero | tr '\0' 'x' >&2
fi

if [ -n "${FAKE_DOCKER_SIGNAL:-}" ]; then
  kill "-${FAKE_DOCKER_SIGNAL}" "$$"
  sleep 1
  exit 98
fi

if [ -n "${FAKE_DOCKER_EXIT:-}" ] && [ "${FAKE_DOCKER_EXIT}" != "0" ]; then
  if [ -n "${FAKE_DOCKER_EMIT_ON_FAILURE:-}" ] && [ -n "${FAKE_DOCKER_ARCHIVE:-}" ]; then
    emit_archive
  fi
  exit "${FAKE_DOCKER_EXIT}"
fi

if [ -n "${FAKE_DOCKER_ARCHIVE:-}" ]; then
  emit_archive
fi
exit 0
"#;
    fs::write(path, script).expect("write fake docker");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod fake docker");
}

fn write_fake_msb(path: &Path, version_line: &str) {
    let script = format!(
        r#"#!/bin/bash
if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
  echo '{version_line}'
  exit 0
fi
if [ -n "${{MSB_RECORD:-}}" ]; then
  printf 'CALL\0' >> "$MSB_RECORD"
  for a in "$@"; do printf '%s\0' "$a" >> "$MSB_RECORD"; done
fi
echo "fake msb: build must not run msb" >&2
exit 91
"#
    );
    fs::write(path, script).expect("write fake msb");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod fake msb");
}

/// Run `cmd` to completion, killing it if it exceeds `timeout`. Drains stdout
/// and stderr on separate threads so a full pipe cannot deadlock the wait.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn agent-vm");
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let stdout = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stdout_pipe.read_to_end(&mut buf).expect("drain stdout");
        buf
    });
    let stderr = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stderr_pipe.read_to_end(&mut buf).expect("drain stderr");
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("agent-vm did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn code_of(output: &Output) -> i32 {
    output
        .status
        .code()
        .unwrap_or_else(|| panic!("agent-vm died by signal: {:?}", output.status))
}

// ---------------------------------------------------------------------------
// Cache observation
// ---------------------------------------------------------------------------

fn cache(cache_dir: &Path) -> GlobalCache {
    GlobalCache::new(cache_dir).expect("open fixture cache")
}

fn metadata(cache_dir: &Path, raw: &str) -> CachedImageMetadata {
    let reference = reference(raw);
    cache(cache_dir)
        .read_image_metadata(&reference)
        .expect("read image metadata")
        .unwrap_or_else(|| panic!("no cached metadata for {raw}"))
}

fn has_metadata(cache_dir: &Path, raw: &str) -> bool {
    cache(cache_dir)
        .read_image_metadata(&reference(raw))
        .expect("read image metadata")
        .is_some()
}

/// The materialized EROFS layer for `diff_id` exists and is non-empty.
fn layer_materialized(cache_dir: &Path, diff_id: &str) -> bool {
    let digest: microsandbox_image::Digest = diff_id.parse().expect("diff id digest");
    let path = cache(cache_dir).layer_erofs_path(&digest);
    fs::metadata(&path).is_ok_and(|meta| meta.len() > 0)
}

/// Snapshot every regular file under `root` (paths + bytes), for
/// "unchanged on failure" assertions.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("snapshot {}: {error}", dir.display()),
    };
    for entry in entries {
        let path = entry.expect("snapshot entry").path();
        let meta = fs::symlink_metadata(&path).expect("snapshot metadata");
        // `cache/manifests/.msb-leases/*.lock` is runtime bookkeeping the
        // vendored runtime creates beside the published metadata, not part of
        // it: a launch takes a lease per content dir. Snapshotting it would
        // make these counts depend on how many sandboxes exist.
        if meta.is_dir() {
            if dir == root
                && root.ends_with("cache/manifests")
                && path.file_name().is_some_and(|name| name == ".msb-leases")
            {
                continue;
            }
            walk(root, &path, out);
        } else {
            assert!(
                meta.is_file(),
                "snapshot refuses nonregular {}",
                path.display()
            );
            out.insert(path.clone(), fs::read(path).expect("snapshot bytes"));
        }
    }
}

#[test]
fn snapshots_skip_only_the_manifest_roots_lease_directory() {
    let dir = tempfile::tempdir().unwrap();
    let manifests = dir.path().join("cache/manifests");
    let leases = manifests.join(".msb-leases");
    let nested = manifests.join("image/.msb-leases");
    let config = dir.path().join(".config/.msb-leases");
    for path in [&leases, &nested, &config] {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("record"), b"kept except root lease").unwrap();
    }
    let files = snapshot(&manifests);
    assert!(!files.contains_key(&leases.join("record")));
    assert!(files.contains_key(&nested.join("record")));
    assert!(snapshot(&dir.path().join(".config")).contains_key(&config.join("record")));
}

/// A valid fixture seeded at `raw` via a real build, returning its derived
/// values.
fn seed_build(harness: &mut Harness, raw: &str, marker: &str) -> Written {
    let spec = ArchiveSpec {
        marker: marker.to_string(),
        ..ArchiveSpec::default()
    };
    let path = harness.home.join(format!("{marker}-seed.tar"));
    let written = image_archive::write(&path, &spec);
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", raw]);
    assert_eq!(
        code_of(&output),
        0,
        "seed build failed: {}",
        stderr_of(&output)
    );
    written
}

// ---------------------------------------------------------------------------
// 1. Forwarding
// ---------------------------------------------------------------------------

#[test]
fn default_context_and_owned_flags() {
    let mut harness = Harness::new();
    let spec = ArchiveSpec::default();
    let path = harness.home.join("a.tar");
    let written = image_archive::write(&path, &spec);
    harness.replay(&written);

    // Run from a project dir so a relative context is meaningful; cwd must be
    // preserved (no chdir, no canonicalization).
    let project = support::project_tempdir();
    fs::write(project.path().join("Containerfile"), "FROM scratch\n").unwrap();
    let mut cmd = harness.base_command();
    cmd.current_dir(project.path());
    cmd.args([
        "image",
        "build",
        "--tag",
        "app:dev",
        "-f",
        "Containerfile",
        ".",
    ]);
    let output = run_with_timeout(cmd, Duration::from_secs(60));
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    let calls = harness.docker_calls();
    assert_eq!(calls.len(), 1, "exactly one Docker call");
    let argv = &calls[0];
    let rendered: Vec<String> = argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert_eq!(&rendered[0..2], ["buildx", "build"]);
    // The relative Dockerfile and context spelling reach Docker untouched.
    assert!(rendered.windows(2).any(|w| w == ["-f", "Containerfile"]));
    assert_eq!(rendered.last().unwrap(), ".");
    assert!(
        !rendered.iter().any(|arg| arg == "-t" || arg == "--tag"),
        "no Docker output alias: {rendered:?}"
    );
    assert!(
        !rendered.iter().any(|arg| arg.contains("BASE_IMAGE")),
        "no injected build arg: {rendered:?}"
    );
    assert!(
        !harness
            .msb_invocations()
            .iter()
            .any(|args| args.first().is_some_and(|a| a != "--version")),
        "build must not run an msb load"
    );

    // The result is immediately readable in the cache a launch reads.
    let meta = metadata(&harness.cache_dir(), "app:dev");
    assert_eq!(meta.manifest_digest, written.manifest_digest);
    assert_eq!(meta.config_digest, written.config_digest);
}

#[test]
fn optional_arguments_reach_docker_verbatim() {
    let mut harness = Harness::new();
    let spec = ArchiveSpec::default();
    let path = harness.home.join("a.tar");
    let written = image_archive::write(&path, &spec);
    harness.replay(&written);

    let output = harness.run(&[
        "image",
        "build",
        "--tag",
        "app:dev",
        "--build-arg",
        "A=one two",
        "--build-arg",
        "B=",
        "--build-arg",
        "C=a=b",
        "--build-arg",
        "FROM_ENV",
        "--build-arg",
        "META=$(echo pwned); ' \" #",
        "--target",
        "stage",
        "--builder",
        "mybuilder",
        "--pull",
        "--no-cache",
        "--progress",
        "plain",
        "ctx with spaces",
    ]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    let argv = &harness.docker_calls()[0];
    let rendered: Vec<String> = argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    for pair in [
        ["--build-arg", "A=one two"],
        ["--build-arg", "B="],
        ["--build-arg", "C=a=b"],
        ["--build-arg", "FROM_ENV"],
        ["--build-arg", "META=$(echo pwned); ' \" #"],
        ["--target", "stage"],
        ["--builder", "mybuilder"],
        ["--progress", "plain"],
    ] {
        assert!(
            rendered.windows(2).any(|w| w == pair),
            "missing {:?} in {rendered:?}",
            pair
        );
    }
    assert!(rendered.contains(&"--pull".to_string()));
    assert!(rendered.contains(&"--no-cache".to_string()));
    assert_eq!(rendered.last().unwrap(), "ctx with spaces");
}

#[test]
fn non_utf8_context_file_and_build_arg_are_forwarded() {
    let mut harness = Harness::new();
    let spec = ArchiveSpec::default();
    let path = harness.home.join("a.tar");
    let written = image_archive::write(&path, &spec);
    harness.replay(&written);

    // A filename that is not valid UTF-8 (0x80 is an invalid start byte).
    let weird_name = OsString::from_vec(b"ctx-\x80".to_vec());
    let weird_file = OsString::from_vec(b"FILE-\x80".to_vec());
    let weird_arg = {
        let mut bytes = b"K=".to_vec();
        bytes.push(0x80);
        OsString::from_vec(bytes)
    };

    let argv: Vec<OsString> = vec![
        OsString::from("image"),
        OsString::from("build"),
        OsString::from("--tag"),
        OsString::from("app:dev"),
        OsString::from("-f"),
        weird_file.clone(),
        OsString::from("--build-arg"),
        weird_arg.clone(),
        weird_name.clone(),
    ];
    let output = harness.run_os(&argv);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    let argv = &harness.docker_calls()[0];
    assert!(argv.windows(2).any(|w| w[1] == weird_file));
    assert!(argv.windows(2).any(|w| w[1] == weird_arg));
    assert_eq!(argv.last().unwrap(), &weird_name);
}

#[test]
fn absolute_dockerfile_outside_the_context_is_forwarded_verbatim() {
    let mut harness = Harness::new();
    let spec = ArchiveSpec::default();
    let path = harness.home.join("a.tar");
    let written = image_archive::write(&path, &spec);
    harness.replay(&written);

    // An absolute Dockerfile that lives outside the build context (and has a
    // space in its name): Docker must receive the caller's exact spelling, not
    // a path agent-vm resolved, joined, canonicalized or copied.
    let project = support::project_tempdir();
    let dockerfile_dir = support::project_tempdir();
    let dockerfile = dockerfile_dir.path().join("Dockerfile outside context");
    fs::write(&dockerfile, "FROM scratch\n").unwrap();

    let mut cmd = harness.base_command();
    cmd.current_dir(project.path());
    cmd.args(["image", "build", "--tag", "app:dev", "--file"]);
    cmd.arg(&dockerfile);
    cmd.arg(".");
    let output = run_with_timeout(cmd, Duration::from_secs(60));
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    let argv = &harness.docker_calls()[0];
    let rendered: Vec<String> = argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let dockerfile_arg = dockerfile.to_string_lossy().into_owned();
    assert!(
        rendered
            .windows(2)
            .any(|w| w == ["-f", dockerfile_arg.as_str()]),
        "absolute out-of-context Dockerfile must be verbatim: {argv:?}"
    );
    assert_eq!(rendered.last().unwrap(), ".");
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        written.manifest_digest
    );
}

// ---------------------------------------------------------------------------
// 2. Owned output/platform
// ---------------------------------------------------------------------------

#[test]
fn exactly_one_host_platform_flag_and_anonymous_oci_stdout() {
    let mut harness = Harness::new();
    let spec = ArchiveSpec::default();
    let path = harness.home.join("a.tar");
    let written = image_archive::write(&path, &spec);
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    let argv = &harness.docker_calls()[0];
    let rendered: Vec<String> = argv
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let expected = match std::env::consts::ARCH {
        "x86_64" => "linux/amd64",
        "aarch64" => "linux/arm64",
        other => panic!("unexpected arch {other}"),
    };
    let platforms: Vec<&String> = rendered
        .iter()
        .filter(|arg| arg.starts_with("linux/") || arg.starts_with("--platform="))
        .collect();
    assert_eq!(platforms.len(), 1, "one platform flag: {rendered:?}");
    assert_eq!(
        rendered[rendered.iter().position(|a| a == "--platform").unwrap() + 1],
        expected
    );
    assert!(
        rendered
            .windows(2)
            .any(|w| w == ["--output", "type=oci,dest=-"])
    );
    assert!(rendered.contains(&"--provenance=false".to_string()));
    assert!(rendered.contains(&"--sbom=false".to_string()));
    for forbidden in ["--load", "--push", "--output=type=docker"] {
        assert!(
            !rendered.iter().any(|arg| arg == forbidden),
            "{forbidden}: {rendered:?}"
        );
    }
    // No Docker-store alias: the only reference Docker sees is none at all.
    assert!(!rendered.iter().any(|arg| arg == "app:dev"));
}

// ---------------------------------------------------------------------------
// 3. Parsing boundaries
// ---------------------------------------------------------------------------

#[test]
fn bad_result_references_fail_before_docker_or_msb_build() {
    let harness = Harness::new();
    for bad in [
        "app@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "./local-path",
        "/abs/path",
        "has space",
        "",
    ] {
        let output = harness.run(&["image", "build", "--tag", bad]);
        assert!(
            !output.status.success(),
            "{bad:?} must be rejected, got {:?}",
            output.status
        );
        // clap ran (usage error), so no runtime and no Docker.
        assert!(!harness.docker_log.exists(), "docker ran for {bad:?}");
    }
    // A missing --tag is a clap error.
    let output = harness.run(&["image", "build"]);
    assert!(!output.status.success());
    assert!(!harness.docker_log.exists());
}

#[test]
fn out_of_surface_options_are_usage_errors() {
    let harness = Harness::new();
    for argv in [
        vec![
            "image",
            "build",
            "--tag",
            "app:dev",
            "--platform",
            "linux/amd64",
        ],
        vec![
            "image",
            "build",
            "--tag",
            "app:dev",
            "--output",
            "type=docker",
        ],
        vec!["image", "build", "--tag", "app:dev", "--load"],
        vec!["image", "build", "--tag", "app:dev", "--push"],
        vec!["image", "build", "--tag", "app:dev", "ctx-a", "ctx-b"],
        vec!["image", "build", "--tag", "app:dev", "--unknown"],
        vec![
            "image", "build", "--tag", "app:dev", "ctx", "--", "trailing",
        ],
    ] {
        let output = harness.run(&argv);
        assert!(
            !output.status.success(),
            "{argv:?} must be a usage error, got {:?}",
            output.status
        );
        assert!(!harness.docker_log.exists(), "docker ran for {argv:?}");
    }
}

#[test]
fn invalid_tag_diagnostics_echo_rejected_tokens_including_digest_values() {
    let harness = Harness::new();
    // clap renders the rejected token; the adapter's own reason is fixed.
    let output = harness.run(&[
        "image",
        "build",
        "--tag",
        "invalid-260-DIAGNOSTIC-SENTINEL bad",
    ]);
    assert!(!output.status.success());
    let text = stderr_of(&output);
    assert!(
        text.contains("invalid-260-DIAGNOSTIC-SENTINEL bad"),
        "ordinary clap rendering echoes the token: {text}"
    );
    assert!(text.contains("--tag"), "{text}");
    assert!(!harness.docker_log.exists());

    // A digest-pinned result is rejected with a fixed reason naming no value.
    let digest = "registry.example.com/team/app@sha256:\
                  2222222222222222222222222222222222222222222222222222222222222222";
    let output = harness.run(&["image", "build", "--tag", digest]);
    assert!(!output.status.success());
    let text = stderr_of(&output);
    assert!(text.contains("mutable result reference"), "{text}");
    assert!(
        text.contains("2222222222222222"),
        "clap echoes the token: {text}"
    );
    assert!(!harness.docker_log.exists());
}

#[test]
fn help_and_version_do_not_initialize_msb_docker_or_state() {
    // No HOME, no MSB_PATH, no fake docker on PATH: help must still work.
    let bare = support::project_tempdir();
    for argv in [
        vec!["image", "build", "--help"],
        vec!["help", "image", "build"],
        vec!["--version"],
        vec!["image", "--help"],
        vec!["image", "import", "--help"],
        vec!["help", "image", "import"],
        vec!["image", "help", "import"],
    ] {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", bare.path())
            .args(&argv)
            .current_dir(bare.path());
        let output = run_with_timeout(cmd, Duration::from_secs(30));
        assert_eq!(
            code_of(&output),
            0,
            "{argv:?} must succeed: {}",
            stderr_of(&output)
        );
        let text = format!("{}{}", stdout_of(&output), stderr_of(&output));
        assert!(text.contains("agent-vm"), "{argv:?}: {text}");
    }
    // Nothing was created in the empty HOME-less cwd.
    assert_eq!(
        fs::read_dir(bare.path()).unwrap().count(),
        0,
        "help/version must not create state"
    );
}

#[test]
fn configured_tool_named_image_is_refused_and_build_is_allowed() {
    let harness = Harness::new();
    let config_dir = harness.home.join(".config/agent-vm");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[[tools]]\nname = \"image\"\ncommand = \"build\"\n",
    )
    .unwrap();

    let output = harness.run(&["doctor"]);
    assert!(!output.status.success(), "a tool named image is reserved");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("reserved") && stderr.contains("tool \"image\""),
        "the refusal must name the reserved tool: {stderr}"
    );
    assert!(!harness.docker_log.exists());
    fs::write(
        config_dir.join("config.toml"),
        "[[tools]]\nname = \"build\"\ncommand = \"build\"\n",
    )
    .unwrap();
    let out = harness.run(&["help", "build"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(stdout_of(&out).contains("Launch build in a per-project sandbox"));
}

// ---------------------------------------------------------------------------
// 4. No catalog/default/selection input
// ---------------------------------------------------------------------------

#[test]
fn build_ignores_config_the_retained_record_and_image_overrides() {
    let mut harness = Harness::new();
    let spec = ArchiveSpec::default();
    let path = harness.home.join("a.tar");
    let written = image_archive::write(&path, &spec);
    harness.replay(&written);

    // A corrupt retained-default record and a project config with an image plus
    // a former layer directory: none of these are build inputs.
    let config_dir = harness.home.join(".config/agent-vm");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(config_dir.join("default-image.json"), b"{ not json").unwrap();
    let project = support::project_tempdir();
    fs::create_dir_all(project.path().join(".agent-vm")).unwrap();
    fs::write(
        project.path().join(".agent-vm/config.toml"),
        "image = \"localhost:1/project:latest\"\n",
    )
    .unwrap();
    fs::create_dir_all(project.path().join(".agent-vm/layers")).unwrap();
    fs::write(project.path().join(".agent-vm/layers/POISON"), b"stale").unwrap();

    let before = snapshot(&harness.home);
    harness.set("AGENT_VM_IMAGE_TAG", "localhost:1/env:latest");
    let mut cmd = harness.base_command();
    cmd.current_dir(project.path());
    cmd.args(["image", "build", "--tag", "app:dev"]);
    let output = run_with_timeout(cmd, Duration::from_secs(60));
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    // No config/default file changed; no record was created.
    let after = snapshot(&harness.home);
    let home_config_before: BTreeMap<_, _> = before
        .iter()
        .filter(|(path, _)| path.starts_with(&config_dir))
        .collect();
    let home_config_after: BTreeMap<_, _> = after
        .iter()
        .filter(|(path, _)| path.starts_with(&config_dir))
        .collect();
    assert_eq!(home_config_before, home_config_after);
    assert!(config_dir.join("default-image.json").exists());
    assert!(
        fs::read(project.path().join(".agent-vm/layers/POISON")).unwrap() == b"stale",
        "former layer directory is untouched"
    );

    // A user build arg named BASE_IMAGE is forwarded only when supplied.
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0);
    let without: Vec<String> = harness.docker_calls()[1]
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert!(!without.iter().any(|arg| arg.contains("BASE_IMAGE")));

    harness.replay(&written);
    let output = harness.run(&[
        "image",
        "build",
        "--tag",
        "app:dev",
        "--build-arg",
        "BASE_IMAGE=alpine:3.22",
    ]);
    assert_eq!(code_of(&output), 0);
    let with: Vec<String> = harness.docker_calls()[2]
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        with.iter().filter(|arg| arg.contains("BASE_IMAGE")).count(),
        1,
        "exactly the user's value: {with:?}"
    );
}

#[test]
fn build_succeeds_despite_a_malformed_tool_config() {
    let mut harness = Harness::new();
    let path = harness.home.join("a.tar");
    let written = image_archive::write(&path, &ArchiveSpec::default());
    harness.replay(&written);

    // A user config whose `image` is not a usable reference and a project file
    // that is not valid TOML at all: `build` consumes neither, so both are
    // inert. A build that read Catalog/ConfiguredImages would fail here.
    let config_dir = harness.home.join(".config/agent-vm");
    fs::create_dir_all(&config_dir).unwrap();
    let user_config = b"image = \"not a valid ref !!\"\n";
    fs::write(config_dir.join("config.toml"), user_config).unwrap();
    let project = support::project_tempdir();
    fs::create_dir_all(project.path().join(".agent-vm")).unwrap();
    let project_config =
        b"[[tools]]\nname = \"shell\"\ncommand = \"bash\"\nthis is not valid toml = =\n";
    fs::write(project.path().join(".agent-vm/config.toml"), project_config).unwrap();
    let mut cmd = harness.base_command();
    cmd.current_dir(project.path());
    cmd.args(["image", "build", "--tag", "app:dev"]);
    let output = run_with_timeout(cmd, Duration::from_secs(60));
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        written.manifest_digest
    );
    // Neither config was rewritten or repaired.
    assert_eq!(
        fs::read(config_dir.join("config.toml")).unwrap(),
        user_config.to_vec()
    );
    assert_eq!(
        fs::read(project.path().join(".agent-vm/config.toml")).unwrap(),
        project_config.to_vec()
    );
}

// ---------------------------------------------------------------------------
// 5. Successful import and replacement
// ---------------------------------------------------------------------------

#[test]
fn successful_import_names_the_result_and_preserves_other_refs() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "other:keep", "A");
    assert!(has_metadata(&harness.cache_dir(), "other:keep"));
    assert!(layer_materialized(&harness.cache_dir(), &a.diff_id));

    // A second image under a different ref.
    let spec_b = ArchiveSpec {
        marker: "B".to_string(),
        ..ArchiveSpec::default()
    };
    let path_b = harness.home.join("b.tar");
    let b = image_archive::write(&path_b, &spec_b);
    harness.replay(&b);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    let meta = metadata(&harness.cache_dir(), "app:dev");
    assert_eq!(meta.manifest_digest, b.manifest_digest);
    assert_eq!(meta.config_digest, b.config_digest);
    assert_eq!(meta.layers[0].diff_id, b.diff_id);
    assert!(layer_materialized(&harness.cache_dir(), &b.diff_id));

    // The unrelated ref still names A.
    let other = metadata(&harness.cache_dir(), "other:keep");
    assert_eq!(other.manifest_digest, a.manifest_digest);

    // Rebuilding the same result replaces it and never short-circuits on a
    // cache hit: one Docker call each time.
    let spec_c = ArchiveSpec {
        marker: "C".to_string(),
        ..ArchiveSpec::default()
    };
    let path_c = harness.home.join("c.tar");
    let c = image_archive::write(&path_c, &spec_c);
    harness.replay(&c);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0);
    let meta = metadata(&harness.cache_dir(), "app:dev");
    assert_eq!(meta.manifest_digest, c.manifest_digest);
    assert_eq!(meta.layers[0].diff_id, c.diff_id);
    assert!(layer_materialized(&harness.cache_dir(), &c.diff_id));
    assert_eq!(harness.docker_calls().len(), 3, "one call per invocation");
    let repeated = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&repeated), 0);
    assert_eq!(
        harness.docker_calls().len(),
        4,
        "identical inputs still build"
    );
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        c.manifest_digest
    );
}

// ---------------------------------------------------------------------------
// 6. Builder spawn/status/signal failures
// ---------------------------------------------------------------------------

#[test]
fn missing_docker_fails_without_importing() {
    let mut harness = Harness::new();
    harness.docker_missing();
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert!(!output.status.success());
    let text = stderr_of(&output);
    assert!(text.contains("docker buildx build"), "{text}");
    assert!(text.contains("type=oci"), "the driver hint: {text}");
    assert!(!has_metadata(&harness.cache_dir(), "app:dev"));
}

#[test]
fn builder_nonzero_exit_fails_without_importing_and_keeps_old_result() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");
    let before = snapshot(&harness.home.join(".config"));
    let cache_before = snapshot(&harness.metadata_snapshot_root());

    harness.set("FAKE_DOCKER_EXIT", "23");
    harness.set(
        "FAKE_DOCKER_ARCHIVE",
        harness.home.join("does-not-exist.tar"),
    );
    let output = harness.run(&[
        "image",
        "build",
        "--tag",
        "app:dev",
        "--build-arg",
        "SECRET=leak-me",
    ]);
    assert_eq!(code_of(&output), 23, "the builder's code is propagated");
    let text = stderr_of(&output);
    assert!(text.contains("docker buildx build failed"), "{text}");
    assert!(
        !text.contains("leak-me"),
        "build-arg values are not logged: {text}"
    );

    // Old result and config/default snapshots are unchanged.
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        a.manifest_digest
    );
    assert_eq!(snapshot(&harness.home.join(".config")), before);
    assert_eq!(snapshot(&harness.metadata_snapshot_root()), cache_before);
}

#[test]
fn complete_archive_with_nonzero_exit_is_never_imported() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");
    let cache_before = snapshot(&harness.metadata_snapshot_root());

    // A complete, valid archive on stdout, but the exporter exits 23.
    let spec = ArchiveSpec {
        marker: "B".to_string(),
        ..ArchiveSpec::default()
    };
    let path = harness.home.join("b.tar");
    let b = image_archive::write(&path, &spec);
    harness.replay(&b);
    harness.docker_emit_on_failure();
    harness.set("FAKE_DOCKER_EXIT", "23");

    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 23);
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        a.manifest_digest,
        "the old result must survive a nonzero exporter"
    );
    assert_eq!(snapshot(&harness.metadata_snapshot_root()), cache_before);
}

#[test]
fn builder_signal_maps_to_128_plus_signo() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");
    harness.docker_signal("TERM");
    harness.replay(&a);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 143);
    assert!(!stderr_of(&output).is_empty());
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        a.manifest_digest
    );
}

#[test]
fn large_builder_stderr_does_not_deadlock() {
    let mut harness = Harness::new();
    let spec = ArchiveSpec::default();
    let path = harness.home.join("a.tar");
    let written = image_archive::write(&path, &spec);
    harness.replay(&written);
    harness.docker_stderr_bytes(2 * 1024 * 1024);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert!(stderr_of(&output).contains(FAKE_DOCKER_STDERR_MARKER));
}

impl Harness {
    /// Root whose native cache metadata a failure must not change.
    fn metadata_snapshot_root(&self) -> PathBuf {
        self.cache_dir().join("manifests")
    }
}

// ---------------------------------------------------------------------------
// 7. Native importer failures (and limitations)
// ---------------------------------------------------------------------------

#[test]
fn empty_or_garbage_archive_fails_and_keeps_old_result() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");
    let cache_before = snapshot(&harness.metadata_snapshot_root());

    let empty = harness.home.join("empty.tar");
    fs::write(&empty, b"").unwrap();
    harness.replay_file(&empty);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert!(!output.status.success(), "empty archive must fail");

    let complete = image_archive::write(
        &harness.home.join("complete.tar"),
        &ArchiveSpec {
            marker: "truncated-B".to_string(),
            ..ArchiveSpec::default()
        },
    );
    let truncated = harness.home.join("truncated.tar");
    let bytes = fs::read(complete.path).unwrap();
    fs::write(&truncated, &bytes[..1024]).unwrap();
    harness.replay_file(&truncated);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert!(!output.status.success(), "truncated archive must fail");
    assert!(stderr_of(&output).contains("importing build result"));

    let garbage = harness.home.join("garbage.tar");
    image_archive::write_garbage(&garbage);
    harness.replay_file(&garbage);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert!(!output.status.success(), "garbage archive must fail");
    let text = stderr_of(&output);
    assert!(text.contains("importing build result"), "{text}");

    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        a.manifest_digest
    );
    assert_eq!(snapshot(&harness.metadata_snapshot_root()), cache_before);
}

#[test]
fn missing_or_corrupt_blob_fails_and_keeps_old_result() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");

    for (name, spec) in [
        (
            "missing-layer",
            ArchiveSpec {
                marker: "B".to_string(),
                omit_layer_blob: true,
                ..ArchiveSpec::default()
            },
        ),
        (
            "digest-mismatch",
            ArchiveSpec {
                marker: "C".to_string(),
                layer: LayerContent::DigestMismatch,
                ..ArchiveSpec::default()
            },
        ),
    ] {
        let path = harness.home.join(format!("{name}.tar"));
        image_archive::write(&path, &spec);
        harness.replay_file(&path);
        let output = harness.run(&["image", "build", "--tag", "app:dev"]);
        assert!(!output.status.success(), "{name} must fail to import");
        assert_eq!(
            metadata(&harness.cache_dir(), "app:dev").manifest_digest,
            a.manifest_digest,
            "{name}: old result must survive"
        );
    }
}

#[test]
fn incompatible_descriptor_platform_is_rejected() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");
    let spec = ArchiveSpec {
        marker: "B".to_string(),
        config_platform: PlatformSpec::Host,
        descriptor_platform: PlatformSpec::Foreign,
        ..ArchiveSpec::default()
    };
    let path = harness.home.join("foreign-descriptor.tar");
    image_archive::write(&path, &spec);
    harness.replay_file(&path);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert!(
        !output.status.success(),
        "foreign descriptor must not import"
    );
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        a.manifest_digest
    );
}

#[test]
fn invalid_layer_stream_with_valid_descriptors_is_rejected() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");
    let spec = ArchiveSpec {
        marker: "B".to_string(),
        layer: LayerContent::NotATar,
        ..ArchiveSpec::default()
    };
    let path = harness.home.join("not-a-tar.tar");
    image_archive::write(&path, &spec);
    harness.replay_file(&path);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert!(
        !output.status.success(),
        "a non-tar layer must fail to materialize"
    );
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        a.manifest_digest
    );
}

#[test]
fn metadata_write_io_error_is_reported_and_keeps_old_result() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");

    // Precreate a directory at the native `.json.part` temp path so the atomic
    // rename cannot complete.
    let target = reference("app:dev");
    let part = cache(&harness.cache_dir())
        .image_metadata_path(&target)
        .with_extension("json.part");
    fs::create_dir_all(&part).unwrap();

    let spec = ArchiveSpec {
        marker: "B".to_string(),
        ..ArchiveSpec::default()
    };
    let path = harness.home.join("b.tar");
    image_archive::write(&path, &spec);
    harness.replay_file(&path);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert!(!output.status.success(), "the metadata write must fail");
    let text = stderr_of(&output);
    assert!(text.contains("importing build result"), "{text}");
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        a.manifest_digest
    );
}

/// Impersonator limitation characterizations: the native importer accepts an
/// absent descriptor platform, and never compares the config's platform with
/// the host. These record the boundary without repairing it.
#[test]
fn absent_platform_and_foreign_config_are_accepted_and_characterized() {
    for (name, spec) in [
        (
            "absent-descriptor-foreign-config",
            ArchiveSpec {
                marker: "NF".to_string(),
                config_platform: PlatformSpec::Foreign,
                descriptor_platform: PlatformSpec::Absent,
                ..ArchiveSpec::default()
            },
        ),
        (
            "host-descriptor-foreign-config",
            ArchiveSpec {
                marker: "HF".to_string(),
                config_platform: PlatformSpec::Foreign,
                descriptor_platform: PlatformSpec::Host,
                ..ArchiveSpec::default()
            },
        ),
    ] {
        let mut harness = Harness::new();
        let path = harness.home.join(format!("{name}.tar"));
        let written = image_archive::write(&path, &spec);
        harness.replay_file(&path);
        let output = harness.run(&["image", "build", "--tag", "limitation:test"]);
        assert_eq!(
            code_of(&output),
            0,
            "{name}: native import currently accepts this: {}",
            stderr_of(&output)
        );
        assert_eq!(
            metadata(&harness.cache_dir(), "limitation:test").manifest_digest,
            written.manifest_digest,
        );
    }
}

// ---------------------------------------------------------------------------
// 8. Fresh cache/home consistency
// ---------------------------------------------------------------------------

#[test]
fn default_private_home_uses_the_private_cache() {
    let (mut harness, cache_dir) = harness_without_state_override();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert_eq!(
        metadata(&cache_dir, "app:dev").manifest_digest,
        written.manifest_digest
    );
}

#[test]
fn xdg_state_home_uses_its_own_cache() {
    let mut harness = Harness::new();
    harness.unset("AGENT_VM_STATE_DIR");
    let xdg = support::project_tempdir();
    harness.set("XDG_STATE_HOME", xdg.path());
    let xdg_cache = xdg.path().join("agent-vm/msb-home/cache");

    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert_eq!(
        metadata(&xdg_cache, "app:dev").manifest_digest,
        written.manifest_digest
    );
    assert!(!has_metadata(&harness.cache_dir(), "app:dev"));
}

#[test]
fn inherited_msb_home_cannot_override_the_private_home() {
    let mut harness = Harness::new();
    let foreign = support::project_tempdir();
    harness.set("MSB_HOME", foreign.path());
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        written.manifest_digest
    );
    assert!(!foreign.path().join("cache/manifests").exists());
}

/// Build a harness whose HOME has no `AGENT_VM_STATE_DIR`; returns the cache
/// path the platform default resolves to.
fn harness_without_state_override() -> (Harness, PathBuf) {
    let mut harness = Harness::new();
    harness.unset("AGENT_VM_STATE_DIR");
    let cache_dir = if cfg!(target_os = "macos") {
        harness.home.join(".agent-vm-msb/cache")
    } else {
        harness.home.join(".local/state/agent-vm/msb-home/cache")
    };
    (harness, cache_dir)
}

// ---------------------------------------------------------------------------
// 9. Shared configuration
// ---------------------------------------------------------------------------

#[test]
fn opt_in_shared_cache_default_location_receives_the_result() {
    let mut harness = Harness::new();
    harness.set("AGENT_VM_SHARE_MSB_CACHE", "1");
    let shared = harness.home.join(".microsandbox/cache");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert_eq!(
        metadata(&shared, "app:dev").manifest_digest,
        written.manifest_digest
    );
    assert!(!has_metadata(&harness.cache_dir(), "app:dev"));
}

#[test]
fn persisted_shared_redirect_survives_unsetting_the_flag() {
    let mut harness = Harness::new();
    let shared_dir = support::project_tempdir();
    let shared = shared_dir.path().join("shared-cache");
    // First run opts in, writing the redirect into MSB_HOME/config.json.
    harness.set("AGENT_VM_SHARE_MSB_CACHE", "1");
    harness.set("AGENT_VM_MSB_CACHE_DIR", &shared);
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert_eq!(
        metadata(&shared, "app:dev").manifest_digest,
        written.manifest_digest
    );

    // Second run with the flag unset: the persisted redirect still governs.
    let mut harness2 = harness;
    harness2.unset("AGENT_VM_SHARE_MSB_CACHE");
    let spec = ArchiveSpec {
        marker: "B".to_string(),
        ..ArchiveSpec::default()
    };
    let path = harness2.home.join("b.tar");
    let b = image_archive::write(&path, &spec);
    harness2.replay_file(&path);
    let output = harness2.run(&["image", "build", "--tag", "second:ref"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert_eq!(
        metadata(&shared, "second:ref").manifest_digest,
        b.manifest_digest
    );
    assert!(
        !has_metadata(&harness2.cache_dir(), "second:ref"),
        "the private cache must not be used while the redirect persists"
    );
}

#[test]
fn msb_config_path_redirect_is_honoured() {
    let mut harness = Harness::new();
    let config_dir = support::project_tempdir();
    let cache_dir = config_dir.path().join("explicit-cache");
    let config_path = config_dir.path().join("config.json");
    fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "paths": { "cache": cache_dir.to_str().unwrap() }
        }))
        .unwrap(),
    )
    .unwrap();
    harness.set("MSB_CONFIG_PATH", &config_path);

    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert_eq!(
        metadata(&cache_dir, "app:dev").manifest_digest,
        written.manifest_digest
    );
    assert!(!has_metadata(&harness.cache_dir(), "app:dev"));
}

#[test]
fn invalid_shared_config_fails_before_the_builder() {
    let mut harness = Harness::new();
    // Opt in but give no HOME-derived location and no override: resolution
    // errors before Docker is ever considered.
    harness.set("AGENT_VM_SHARE_MSB_CACHE", "1");
    harness.unset("HOME");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert!(!output.status.success());
    assert!(!harness.docker_log.exists(), "Docker must not run");
}

// ---------------------------------------------------------------------------
// 10. Staging / lifecycle
// ---------------------------------------------------------------------------

#[test]
fn staging_is_private_isolated_and_cleaned_on_success_and_failure() {
    let mut harness = Harness::new();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let project = support::project_tempdir();
    let containerfile = project.path().join("Dockerfile");
    fs::write(&containerfile, "FROM scratch\n").unwrap();

    let before_context = fs::read(&containerfile).unwrap();

    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));

    // Only this invocation's staging remains (nothing): MSB_HOME/tmp exists but
    // holds no build-* directory after success.
    let tmp = harness.msb_home().join("tmp");
    assert!(tmp.is_dir());
    assert_eq!(
        fs::read_dir(&tmp).unwrap().count(),
        0,
        "staging cleaned on success"
    );
    // Context/source bytes unchanged.
    assert_eq!(fs::read(&containerfile).unwrap(), before_context);

    // A failure also cleans its own staging.
    harness.docker_exit(7);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 7);
    assert_eq!(
        fs::read_dir(&tmp).unwrap().count(),
        0,
        "staging cleaned on failure"
    );
}

#[test]
fn staged_archive_never_appears_in_the_context() {
    let mut harness = Harness::new();
    let context = support::project_tempdir();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let mut cmd = harness.base_command();
    cmd.current_dir(context.path());
    cmd.args(["image", "build", "--tag", "app:dev", "."]);
    let output = run_with_timeout(cmd, Duration::from_secs(60));
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    assert_eq!(
        fs::read_dir(context.path()).unwrap().count(),
        0,
        "no staging artifact is left in the context"
    );
}

#[test]
fn staging_directory_mode_is_0700_and_archive_0600() {
    for exit in [0, 23] {
        let mut harness = Harness::new();
        let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
        harness.replay(&written).docker_exit(exit);
        harness.set("FAKE_DOCKER_SLEEP", "5");
        let base = harness.base_command();
        // Set umask only in the child: a process-wide test umask would race
        // parallel tests, and a restrictive inherited mask could hide 0755.
        let mut cmd = Command::new("/bin/bash");
        cmd.env_clear()
            .envs(base.get_envs().map(|(key, value)| (key, value.unwrap())));
        cmd.args(["-c", "umask 022; exec \"$@\"", "permission-test"])
            .arg(agent_vm_bin())
            .args(["image", "build", "--tag", "app:dev"]);
        let build = std::thread::spawn(move || run_with_timeout(cmd, Duration::from_secs(60)));
        let deadline = Instant::now() + Duration::from_secs(10);
        let observed = (|| -> std::io::Result<(u32, u32)> {
            while !harness.docker_log.exists() {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "fake Docker did not start",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let staging: Vec<_> = fs::read_dir(harness.msb_home().join("tmp"))?
                .collect::<std::io::Result<Vec<_>>>()?
                .into_iter()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("image-"))
                .collect();
            if staging.len() != 1 {
                return Err(std::io::Error::other(format!(
                    "expected one live staging directory, found {}",
                    staging.len()
                )));
            }
            let directory = staging[0].path();
            Ok((
                fs::metadata(&directory)?.permissions().mode() & 0o7777,
                fs::metadata(directory.join("result.tar"))?
                    .permissions()
                    .mode()
                    & 0o7777,
            ))
        })();
        // Reap the build before asserting modes, including on a failed observation.
        let output = build.join().expect("build thread");
        assert_eq!(code_of(&output), exit, "{}", stderr_of(&output));
        let (directory_mode, archive_mode) = observed.expect("stat live staging during export");
        assert_eq!(directory_mode, 0o700, "live staging directory mode");
        assert_eq!(archive_mode, 0o600, "live staged archive mode");
        assert_eq!(
            fs::read_dir(harness.msb_home().join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn shared_custom_cache_preserves_config_keys_and_private_database() {
    let mut harness = Harness::new();
    let shared = harness.home.join("chosen-cache");
    fs::create_dir_all(harness.msb_home()).unwrap();
    let config = harness.msb_home().join("config.json");
    fs::write(
        &config,
        br#"{"paths":{"tls":"/fixture/tls"},"log":{"level":"error"}}"#,
    )
    .unwrap();
    harness.set("AGENT_VM_SHARE_MSB_CACHE", "1");
    harness.set("AGENT_VM_MSB_CACHE_DIR", &shared);
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    let actual: serde_json::Value = serde_json::from_slice(&fs::read(config).unwrap()).unwrap();
    assert_eq!(actual["paths"]["tls"], "/fixture/tls");
    assert_eq!(actual["log"]["level"], "error");
    assert_eq!(
        metadata(&shared, "app:dev").manifest_digest,
        written.manifest_digest
    );
    assert!(!has_metadata(&harness.cache_dir(), "app:dev"));
    assert!(!shared.join("db").exists());
    assert!(!shared.join("sandboxes").exists());
}

#[test]
fn failed_build_does_not_create_an_absent_retained_record() {
    let mut harness = Harness::new();
    harness.docker_exit(23);
    let output = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&output), 23);
    assert!(
        !harness
            .home
            .join(".config/agent-vm/default-image.json")
            .exists()
    );
    assert_eq!(harness.docker_calls().len(), 1);
    assert!(harness.msb_invocations().is_empty());
}

fn assert_value_free(output: &Output, sentinels: &[&str]) {
    for sentinel in sentinels {
        assert!(
            !stdout_of(output).contains(sentinel),
            "{}",
            stdout_of(output)
        );
        assert!(
            !stderr_of(output).contains(sentinel),
            "{}",
            stderr_of(output)
        );
    }
}
fn import_docker(harness: &Harness, tag: &str) -> Output {
    harness.run(&[
        "image",
        "import",
        "--docker",
        "agent-vm-standard:local",
        "--tag",
        tag,
    ])
}
fn import_input(harness: &Harness, path: &Path, tag: &str) -> Output {
    harness.run_os(&[
        "image".into(),
        "import".into(),
        "--input".into(),
        path.into(),
        "--tag".into(),
        tag.into(),
    ])
}
fn assert_imported(cache: &Path, raw: &str, written: &Written) {
    let actual = metadata(cache, raw);
    assert_eq!(actual.config_digest, written.config_digest);
    assert!(layer_materialized(cache, &written.diff_id));
    assert_eq!(actual.layers[0].diff_id, written.diff_id);
}
#[test]
fn docker_import_saves_exactly_and_publishes() {
    let mut harness = Harness::new();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let output = import_docker(&harness, "agent-vm-standard:local");
    assert_eq!(code_of(&output), 0, "{}", stderr_of(&output));
    let calls = harness.docker_calls();
    assert_eq!(calls.len(), 1);
    let path = PathBuf::from(&calls[0][3]);
    assert!(path.starts_with(harness.msb_home().join("tmp")));
    assert!(
        path.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("image-")
    );
    assert_eq!(path.file_name().unwrap(), "result.tar");
    assert_eq!(
        calls[0],
        [
            OsString::from("image"),
            "save".into(),
            "--output".into(),
            path.into_os_string(),
            "--".into(),
            "agent-vm-standard:local".into()
        ]
    );
    assert_eq!(
        metadata(&harness.cache_dir(), "agent-vm-standard:local").manifest_digest,
        written.manifest_digest
    );
    assert_imported(&harness.cache_dir(), "agent-vm-standard:local", &written);
    assert_eq!(
        stdout_of(&output),
        "Imported agent-vm-standard:local into agent-vm's image cache; launch it with `--image agent-vm-standard:local`\n"
    );
    assert!(!stderr_of(&output).contains("Imported"));
    assert!(harness.msb_invocations().is_empty());
}
#[test]
fn input_import_works_without_docker() {
    let mut harness = Harness::new();
    harness.docker_missing();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input(&harness, &written.path, "app:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_imported(&harness.cache_dir(), "app:dev", &written);
    assert!(!harness.docker_log.exists());
    assert!(stdout_of(&out).starts_with("Imported app:dev"));
}
#[test]
fn docker_save_nonzero_keeps_old_reference() {
    let mut harness = Harness::new();
    let a = seed_build(&mut harness, "app:dev", "A");
    let before = snapshot(&harness.metadata_snapshot_root());
    let b = image_archive::write(
        &harness.home.join("b.tar"),
        &ArchiveSpec {
            marker: "B".into(),
            ..Default::default()
        },
    );
    harness.replay(&b).docker_exit(23).docker_emit_on_failure();
    let out = import_docker(&harness, "app:dev");
    assert_eq!(code_of(&out), 23);
    assert!(stderr_of(&out).contains("docker image save failed"));
    assert_eq!(snapshot(&harness.metadata_snapshot_root()), before);
    assert_eq!(
        metadata(&harness.cache_dir(), "app:dev").manifest_digest,
        a.manifest_digest
    );
    assert!(out.stdout.is_empty());
}
#[test]
fn docker_save_signal_maps_to_128_plus_signo() {
    let mut harness = Harness::new();
    seed_build(&mut harness, "app:dev", "A");
    let before = snapshot(&harness.metadata_snapshot_root());
    harness.docker_signal("TERM");
    let out = import_docker(&harness, "app:dev");
    assert_eq!(code_of(&out), 143);
    assert_eq!(snapshot(&harness.metadata_snapshot_root()), before);
}
#[test]
fn docker_import_with_docker_missing_fails_cleanly() {
    let mut harness = Harness::new();
    harness.docker_missing();
    let out = import_docker(&harness, "app:dev");
    assert_eq!(code_of(&out), 1);
    assert!(stderr_of(&out).contains("docker image save"));
    assert!(snapshot(&harness.metadata_snapshot_root()).is_empty());
}
#[test]
fn import_usage_errors_are_value_free_and_run_nothing() {
    let digest = format!("app:SENTINEL_A5@sha256:{}", "a".repeat(64));
    let docker_pinned_source = format!("app@sha256:{}", "a".repeat(64));
    let conflict = "`agent-vm image import` accepts exactly one source, --docker REF or --input PATH, and at most one --tag REF; the arguments are not shown";
    let missing = "`agent-vm image import` needs exactly one source, --docker REF or --input PATH; --tag REF is required with --input and defaults to --docker";
    let unsupported = "`agent-vm image import` does not accept that argument; the arguments are not shown. Supported: --docker REF [--tag REF] | --input PATH --tag REF";
    // Omitted `--tag` plus a `--docker` source that is not a mutable result
    // reference: a post-parse usage error, refused before any state exists.
    let inferred_digest = "`agent-vm image import`: --docker cannot supply the default --tag: --tag must name a mutable result reference (e.g. my-app:dev); a digest-pinned reference cannot be updated by a later build or import. Pass an explicit mutable --tag REF";
    let inferred_local = "`agent-vm image import`: --docker cannot supply the default --tag: --tag must be an OCI image reference (e.g. ghcr.io/owner/name:tag or repo@sha256:…); a local path is not accepted here — use --image for a local rootfs. Pass an explicit mutable --tag REF";
    let pinned = "invalid value for --tag <REF>: --tag must name a mutable result reference (e.g. my-app:dev); a digest-pinned reference cannot be updated by a later build or import";
    let local = "invalid value for --tag <REF>: --tag must be an OCI image reference (e.g. ghcr.io/owner/name:tag or repo@sha256:…); a local path is not accepted here — use --image for a local rootfs";
    let docker = "invalid value for --docker <REF>: --docker must name an image in the local Docker daemon (e.g. my-image:dev): not empty, no whitespace or NUL, and not starting with '-'";
    for (args, text) in [
        (
            vec![
                "--docker",
                "SENTINEL_A1",
                "--input",
                "SENTINEL_A2",
                "--tag",
                "app:dev",
            ],
            conflict,
        ),
        (vec!["--tag", "app:SENTINEL_A3"], missing),
        (vec!["--input", "SENTINEL_A4"], missing),
        (
            vec!["--docker", docker_pinned_source.as_str()],
            inferred_digest,
        ),
        (vec!["--docker", "./SENTINEL_A12"], inferred_local),
        (
            vec!["--docker", "x", "--tag", "app:dev", "--tag", "SENTINEL_A13"],
            conflict,
        ),
        (vec!["--docker", "x", "--tag", digest.as_str()], pinned),
        (vec!["--docker", "x", "--tag", "./SENTINEL_A6"], local),
        (vec!["--docker=-SENTINEL_A7", "--tag", "app:dev"], docker),
        (vec!["--docker=--privileged", "--tag", "app:dev"], docker),
        (
            vec!["--docker", "SENTINEL_A8 x", "--tag", "app:dev"],
            docker,
        ),
        (
            vec![
                "--docker",
                "x",
                "--tag",
                "app:dev",
                "--platform",
                "SENTINEL_A9",
            ],
            unsupported,
        ),
        (
            vec![
                "--docker",
                "x",
                "--tag",
                "app:dev",
                "--output",
                "SENTINEL_A10",
            ],
            unsupported,
        ),
        (
            vec!["--docker", "x", "--tag", "app:dev", "--load"],
            unsupported,
        ),
        (
            vec!["--docker", "x", "--tag", "app:dev", "--push"],
            unsupported,
        ),
        (
            vec!["--docker", "x", "--tag", "app:dev", "SENTINEL_A11"],
            unsupported,
        ),
    ] {
        let harness = Harness::new();
        let argv = ["image", "import"]
            .into_iter()
            .chain(args)
            .collect::<Vec<_>>();
        let out = harness.run(&argv);
        assert_eq!(code_of(&out), 2, "{} {}", stderr_of(&out), argv.join(" "));
        assert_eq!(
            stderr_of(&out),
            format!(
                "error: {text}\n\nUsage: agent-vm image import <--docker <REF> [--tag <REF>]|--input <PATH> --tag <REF>>\n\nFor more information, try '--help'.\n"
            )
        );
        assert_value_free(&out, &["SENTINEL", "--privileged"]);
        assert!(harness.docker_calls().is_empty());
        assert!(!harness.msb_home().exists());
    }
}
#[test]
fn input_missing_or_directory_fails_before_any_state() {
    let harness = Harness::new();
    let dir = harness.home.join("SENTINEL_IN2");
    fs::create_dir(&dir).unwrap();
    let fifo = harness.home.join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    for path in [harness.home.join("SENTINEL_IN1.tar"), dir, fifo] {
        let out = import_input(&harness, &path, "app:dev");
        assert_eq!(code_of(&out), 1);
        assert!(stderr_of(&out).contains("--input must name an existing regular file"));
        assert_value_free(&out, &["SENTINEL_IN1", "SENTINEL_IN2"]);
        assert!(!harness.msb_home().exists());
        assert!(harness.docker_calls().is_empty());
        assert!(harness.msb_invocations().is_empty());
    }
}
#[test]
fn input_garbage_archive_keeps_old_reference() {
    let mut harness = Harness::new();
    seed_build(&mut harness, "app:dev", "A");
    let before = snapshot(&harness.metadata_snapshot_root());
    let path = harness.home.join("garbage.tar");
    image_archive::write_garbage(&path);
    assert_eq!(code_of(&import_input(&harness, &path, "app:dev")), 1);
    assert_eq!(snapshot(&harness.metadata_snapshot_root()), before);
}
#[test]
fn input_typo_with_shared_cache_opt_in_writes_nothing() {
    let mut harness = Harness::new();
    let shared = harness.home.join("shared");
    harness
        .set("AGENT_VM_SHARE_MSB_CACHE", "1")
        .set("AGENT_VM_MSB_CACHE_DIR", &shared);
    let out = import_input(&harness, &harness.home.join("missing"), "app:dev");
    assert_eq!(code_of(&out), 1);
    assert!(stderr_of(&out).contains("--input must name an existing regular file"));
    for path in [
        harness.msb_home(),
        harness.msb_home().join("config.json"),
        shared.clone(),
        harness.msb_home().join("tmp"),
    ] {
        assert!(!path.exists());
    }
    assert!(harness.docker_calls().is_empty());
    assert!(harness.msb_invocations().is_empty());
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input(&harness, &written.path, "app:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(shared.join("manifests").is_dir());
}
#[test]
fn build_is_no_longer_a_verb() {
    let harness = Harness::new();
    let out = harness.run(&["build", "--tag", "app:dev"]);
    assert_eq!(code_of(&out), 2);
    assert!(stderr_of(&out).contains("unrecognized subcommand 'build'"));
    assert!(harness.docker_calls().is_empty());
    let project = support::project_tempdir();
    fs::create_dir(project.path().join(".agent-vm")).unwrap();
    fs::write(
        project.path().join(".agent-vm/config.toml"),
        "[[tools]\nbroken",
    )
    .unwrap();
    let mut command = harness.base_command();
    command
        .current_dir(project.path())
        .args(["build", "--tag", "app:dev"]);
    let out = run_with_timeout(command, Duration::from_secs(30));
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("config.toml"));
    assert!(!stderr_of(&out).contains("unrecognized subcommand"));
    assert!(harness.docker_calls().is_empty());
}
#[test]
fn docker_import_honours_persisted_shared_redirect() {
    let mut harness = Harness::new();
    let shared = harness.home.join("shared");
    harness
        .set("AGENT_VM_SHARE_MSB_CACHE", "1")
        .set("AGENT_VM_MSB_CACHE_DIR", &shared);
    let a = seed_build(&mut harness, "app:dev", "A");
    harness.unset("AGENT_VM_SHARE_MSB_CACHE").replay(&a);
    let out = import_docker(&harness, "second:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_imported(&shared, "second:dev", &a);
    assert!(!harness.cache_dir().join("manifests").exists());
}
#[test]
fn docker_import_never_writes_selection_or_config() {
    let mut harness = Harness::new();
    let config = harness.home.join(".config");
    fs::create_dir_all(config.join("agent-vm")).unwrap();
    fs::write(config.join("agent-vm/config.toml"), "tools = []\n").unwrap();
    let before = snapshot(&config);
    let a = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&a);
    assert_eq!(code_of(&import_docker(&harness, "app:dev")), 0);
    assert_eq!(snapshot(&config), before);
    assert!(!config.join("agent-vm/default-image.json").exists());
}
#[test]
fn build_success_notice_is_on_stdout() {
    let mut harness = Harness::new();
    let a = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&a);
    let out = harness.run(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&out), 0);
    assert_eq!(
        stdout_of(&out),
        "Imported build result as app:dev; launch it with `--image app:dev`\n"
    );
    assert!(stderr_of(&out).contains(FAKE_DOCKER_STDERR_MARKER));
    assert!(!stderr_of(&out).contains("Imported"));
}

/// The build notice prints the same pasted word as import, so it owes the same
/// note: `$'…'` is not POSIX and a dash user would paste a different tag.
#[test]
fn build_success_notice_names_its_shell_for_a_non_ascii_tag() {
    let mut harness = Harness::new();
    let a = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&a);
    let out = harness.run(&["image", "build", "--tag", "app:é"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        "Imported build result as $'app:\\xc3\\xa9'; launch it with `--image $'app:\\xc3\\xa9'` (quoted for bash or zsh)\n"
    );
}
#[test]
fn docker_save_archive_publishes_tag_and_its_repotags() {
    for tags in [Some(vec!["z-source:dev".into()]), None] {
        let mut harness = Harness::new();
        let written = image_archive::write_docker_save(
            &harness.home.join("save.tar"),
            &[image_archive::DockerSaveImage {
                marker: "A".into(),
                repo_tags: tags.clone(),
            }],
        );
        harness.replay(&written[0]);
        let out = harness.run(&[
            "image",
            "import",
            "--docker",
            "z-source:dev",
            "--tag",
            "a-target:dev",
        ]);
        assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
        assert_imported(&harness.cache_dir(), "a-target:dev", &written[0]);
        if tags.is_some() {
            assert_imported(&harness.cache_dir(), "z-source:dev", &written[0]);
        }
        assert_eq!(
            snapshot(&harness.metadata_snapshot_root()).len(),
            if tags.is_some() { 2 } else { 1 }
        );
        assert!(!stdout_of(&out).contains("z-source"));
    }
}
#[test]
fn multi_image_archive_publishes_every_named_image() {
    let harness = Harness::new();
    let written = image_archive::write_docker_save(
        &harness.home.join("save.tar"),
        &[
            image_archive::DockerSaveImage {
                marker: "one".into(),
                repo_tags: Some(vec!["z-one:dev".into()]),
            },
            image_archive::DockerSaveImage {
                marker: "two".into(),
                repo_tags: Some(vec!["y-two:dev".into()]),
            },
        ],
    );
    let out = import_input(&harness, &written[0].path, "a:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    for (raw, index) in [("a:dev", 0), ("z-one:dev", 0), ("y-two:dev", 1)] {
        assert_imported(&harness.cache_dir(), raw, &written[index]);
    }
}
#[test]
fn late_alias_failure_restores_the_requested_tag() {
    use std::os::unix::fs::MetadataExt as _;

    for build in [false, true] {
        let mut harness = Harness::new();
        let a = image_archive::write_docker_save(
            &harness.home.join("a.tar"),
            &[image_archive::DockerSaveImage {
                marker: "A".into(),
                repo_tags: Some(vec!["z-source:dev".into()]),
            }],
        );
        assert_eq!(
            code_of(&import_input(&harness, &a[0].path, "a-target:dev")),
            0
        );
        let target = cache(&harness.cache_dir()).image_metadata_path(&reference("a-target:dev"));
        let before = fs::read(&target).unwrap();
        // Keep the old inode alive: a replacement cannot reuse its number.
        let original = fs::File::open(&target).unwrap();
        let original_inode = original.metadata().unwrap().ino();
        let blocked = cache(&harness.cache_dir())
            .image_metadata_path(&reference("z-source:dev"))
            .with_extension("json.part");
        fs::create_dir(&blocked).unwrap();
        let b = image_archive::write_docker_save(
            &harness.home.join("b.tar"),
            &[image_archive::DockerSaveImage {
                marker: "B".into(),
                repo_tags: Some(vec!["z-source:dev".into()]),
            }],
        );
        let out = if build {
            harness.replay(&b[0]);
            harness.run(&["image", "build", "--tag", "a-target:dev"])
        } else {
            import_input(&harness, &b[0].path, "a-target:dev")
        };
        assert_eq!(code_of(&out), 1);
        assert!(stderr_of(&out).contains(if build {
            "importing build result"
        } else {
            "importing image"
        }));
        // A pre-publication failure leaves the requested metadata untouched:
        // restore_reference is a no-op when its bytes still equal the prior
        // bytes. A different inode with the original bytes therefore proves
        // that publication replaced A before rollback atomically restored A.
        // Keeping `original` open rules out inode reuse as a false negative.
        assert_ne!(fs::metadata(&target).unwrap().ino(), original_inode);
        assert_eq!(fs::read(target).unwrap(), before);
        assert_imported(&harness.cache_dir(), "a-target:dev", &a[0]);
        assert_ne!(a[0].config_digest, b[0].config_digest);
        assert_ne!(
            metadata(&harness.cache_dir(), "a-target:dev").config_digest,
            b[0].config_digest,
            "the failed second alias must not leave the requested tag on B"
        );
    }
}
#[test]
fn late_alias_failure_removes_a_new_requested_tag() {
    let harness = Harness::new();
    let blocked = cache(&harness.cache_dir())
        .image_metadata_path(&reference("z-source:dev"))
        .with_extension("json.part");
    fs::create_dir(&blocked).unwrap();
    let b = image_archive::write_docker_save(
        &harness.home.join("b.tar"),
        &[image_archive::DockerSaveImage {
            marker: "B".into(),
            repo_tags: Some(vec!["z-source:dev".into()]),
        }],
    );
    let out = import_input(&harness, &b[0].path, "a-target:dev");
    assert_eq!(code_of(&out), 1, "{}", stderr_of(&out));
    assert!(
        !cache(&harness.cache_dir())
            .image_metadata_path(&reference("a-target:dev"))
            .exists()
    );
}
#[test]
fn non_ascii_tag_notice_round_trips() {
    let harness = Harness::new();
    let a = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input(&harness, &a.path, "app:é");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        "Imported $'app:\\xc3\\xa9' into agent-vm's image cache; launch it with `--image $'app:\\xc3\\xa9'` (quoted for bash or zsh)\n"
    );
    let notice = stdout_of(&out);
    let word = notice
        .split("--image ")
        .nth(1)
        .unwrap()
        .split('`')
        .next()
        .unwrap();
    let shell = Command::new("bash")
        .args(["-c", &format!("printf %s {word}")])
        .output()
        .unwrap();
    assert!(shell.status.success());
    assert!(has_metadata(
        &harness.cache_dir(),
        std::str::from_utf8(&shell.stdout).unwrap()
    ));
}

// ---------------------------------------------------------------------------
// 12. Defaulted result reference and selection-aware completion (#385)
// ---------------------------------------------------------------------------

const RETAINED_A: &str =
    "127.0.0.1:1/private-a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

impl Harness {
    /// The user tier's config file, beside the isolated `HOME`.
    fn user_config_path(&self) -> PathBuf {
        self.home.join(".config/agent-vm/config.toml")
    }

    /// The private retained-default record.
    fn record_path(&self) -> PathBuf {
        self.home.join(".config/agent-vm/default-image.json")
    }

    /// A project directory with an isolated cwd, for project-tier cases.
    fn project_dir(&self) -> PathBuf {
        let dir = self.home.join("project");
        fs::create_dir_all(dir.join(".agent-vm")).unwrap();
        dir
    }

    fn write_user_image(&mut self, reference: &str) -> &mut Self {
        let path = self.user_config_path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("image = \"{reference}\"\n")).unwrap();
        self
    }

    fn write_project_image(&self, reference: &str) -> PathBuf {
        let dir = self.project_dir();
        fs::write(
            dir.join(".agent-vm/config.toml"),
            format!("image = \"{reference}\"\n"),
        )
        .unwrap();
        dir
    }

    fn write_record(&mut self, contents: &str) -> &mut Self {
        fs::create_dir_all(self.record_path().parent().unwrap()).unwrap();
        fs::write(self.record_path(), contents).unwrap();
        self
    }

    /// Run with an isolated cwd so a project config is arranged per case and
    /// the test process's own cwd is never read.
    fn run_in(&self, dir: &Path, argv: &[&str]) -> Output {
        let mut cmd = self.base_command();
        cmd.current_dir(dir).args(argv);
        run_with_timeout(cmd, Duration::from_secs(60))
    }

    /// Run with an isolated cwd and no project config, so "nothing configured"
    /// cases cannot inherit whatever the caller's cwd declares.
    fn run_isolated(&self, argv: &[&str]) -> Output {
        self.run_in(&self.project_dir(), argv)
    }

    /// Every file under the user config directory, for "unchanged" assertions.
    fn config_snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        snapshot(&self.home.join(".config"))
    }
}

/// The existing import completion sentence, exactly as printed.
fn launch_notice(reference: &str) -> String {
    format!(
        "Imported {reference} into agent-vm's image cache; launch it with `--image {reference}`\n"
    )
}

const SHOW_HINT: &str = "Run `agent-vm image show` to see the currently configured image.\n";

#[test]
fn docker_source_only_defaults_the_result_reference() {
    for source in ["app:dev", "app", "localhost:5000/x:y"] {
        let mut harness = Harness::new();
        let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
        harness.replay(&written);
        let out = harness.run_isolated(&["image", "import", "--docker", source]);
        assert_eq!(code_of(&out), 0, "{source}: {}", stderr_of(&out));
        // The Docker source is still what reaches Docker, and the inferred
        // destination is what lands in the cache.
        assert_eq!(
            harness.docker_calls()[0].last().unwrap(),
            &OsString::from(source)
        );
        assert_imported(&harness.cache_dir(), source, &written);
        // No configured image: only the launch guidance.
        assert_eq!(stdout_of(&out), launch_notice(source), "source {source}");
    }
}

#[test]
fn a_bare_hexadecimal_docker_id_is_accepted_as_the_inferred_reference() {
    // The omitted-tag decision uses the existing mutable-reference parser, not
    // a new "looks like an ID" detector: a bare hexadecimal ID parses as a
    // mutable bare name, so it is a valid inferred destination. Only sources
    // that parser rejects (digest-pinned, local paths) need an explicit tag.
    let id = "a".repeat(64);
    let mut harness = Harness::new();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_isolated(&["image", "import", "--docker", &id]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        harness.docker_calls()[0].last().unwrap(),
        &OsString::from(&id)
    );
    assert_imported(&harness.cache_dir(), &id, &written);
    assert_eq!(stdout_of(&out), launch_notice(&id));
}

#[test]
fn explicit_tag_still_overrides_the_defaulted_reference() {
    for argv in [
        vec!["--docker", "src:dev", "--tag", "dst:dev"],
        vec!["--tag", "dst:dev", "--docker", "src:dev"],
        vec!["--docker", "src:dev", "-t", "dst:dev"],
    ] {
        let mut harness = Harness::new();
        let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
        harness.replay(&written);
        let argv: Vec<&str> = ["image", "import"]
            .into_iter()
            .chain(argv.iter().copied())
            .collect();
        let out = harness.run(&argv);
        assert_eq!(code_of(&out), 0, "{argv:?}: {}", stderr_of(&out));
        assert_imported(&harness.cache_dir(), "dst:dev", &written);
        assert!(!has_metadata(&harness.cache_dir(), "src:dev"));
        assert_eq!(harness.docker_calls()[0].last().unwrap(), "src:dev");
        // The notice compares the destination, never the Docker source.
        assert_eq!(stdout_of(&out), launch_notice("dst:dev"));
    }
}

#[test]
fn import_is_silent_when_the_configuration_selects_the_result() {
    for docker in [true, false] {
        let mut harness = Harness::new();
        harness.write_user_image("app:dev");
        let before = harness.config_snapshot();
        let out = if docker {
            let written =
                image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
            harness.replay(&written);
            let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
            assert_imported(&harness.cache_dir(), "app:dev", &written);
            out
        } else {
            let written =
                image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
            let out = import_input_in(&harness, &harness.project_dir(), &written.path, "app:dev");
            assert_imported(&harness.cache_dir(), "app:dev", &written);
            out
        };
        assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
        assert!(
            stdout_of(&out).is_empty(),
            "docker={docker}: {}",
            stdout_of(&out)
        );
        // Import observes; it never writes configuration or a default record.
        assert_eq!(harness.config_snapshot(), before);
        assert!(!harness.record_path().exists());
        assert!(harness.msb_invocations().is_empty());
    }
}

#[test]
fn import_points_at_image_show_when_another_image_is_configured() {
    // User tier differing.
    let mut harness = Harness::new();
    harness.write_user_image("app:other");
    let cwd = harness.project_dir();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_in(&cwd, &["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        format!("{}{SHOW_HINT}", launch_notice("app:dev"))
    );
    // The selected reference is not disclosed.
    assert!(!stdout_of(&out).contains("app:other"));
    assert!(!stderr_of(&out).contains("app:other"));

    // Project tier differing.
    let harness = Harness::new();
    let cwd = harness.write_project_image("app:other");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input_in(&harness, &cwd, &written.path, "app:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        format!("{}{SHOW_HINT}", launch_notice("app:dev"))
    );
}

fn import_input_in(harness: &Harness, cwd: &Path, path: &Path, tag: &str) -> Output {
    let path = path.to_string_lossy().into_owned();
    harness.run_in(cwd, &["image", "import", "--input", &path, "--tag", tag])
}

#[test]
fn import_compares_the_effective_selection() {
    // The environment winner matches while the user tier differs: silent.
    let mut harness = Harness::new();
    harness
        .write_user_image("app:other")
        .set("AGENT_VM_IMAGE_TAG", "app:dev");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));

    // The environment winner differs while the user tier matches: hint.
    let mut harness = Harness::new();
    harness
        .write_user_image("app:dev")
        .set("AGENT_VM_IMAGE_TAG", "app:env");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        format!("{}{SHOW_HINT}", launch_notice("app:dev"))
    );

    // An empty environment override is unset, exactly as for `image show`.
    let mut harness = Harness::new();
    harness
        .write_user_image("app:dev")
        .set("AGENT_VM_IMAGE_TAG", "");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));
}

#[test]
fn import_follows_the_tier_precedence_of_the_selection() {
    // user differs, project matches: user wins, so the result does not match.
    let mut harness = Harness::new();
    harness.write_user_image("app:user");
    let cwd = harness.write_project_image("app:dev");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_in(&cwd, &["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        format!("{}{SHOW_HINT}", launch_notice("app:dev"))
    );

    // user matches, project differs: the user tier wins, so silent.
    let mut harness = Harness::new();
    harness.write_user_image("app:dev");
    let cwd = harness.write_project_image("app:project");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_in(&cwd, &["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));

    // project only, matching: silent.
    let harness = Harness::new();
    let cwd = harness.write_project_image("app:dev");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input_in(&harness, &cwd, &written.path, "app:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));
}

#[test]
fn import_keeps_only_the_launch_guidance_for_a_fallback_selection() {
    // Nothing configured: the fallback (retained or recommended) is not an
    // image the user chose, so no `image show` hint is added.
    let harness = Harness::new();
    let cwd = harness.project_dir();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input_in(&harness, &cwd, &written.path, "app:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(stdout_of(&out), launch_notice("app:dev"));
    assert!(!stdout_of(&out).contains(SHOW_HINT.trim()));
    assert!(!harness.record_path().exists());
    assert!(!stderr_of(&out).contains("ghcr.io"));

    // A retained default that differs: still only the launch guidance, and the
    // record is untouched (no adoption, no repair).
    let mut harness = Harness::new();
    harness.write_record(&format!("{{\"version\":1,\"image\":\"{RETAINED_A}\"}}\n"));
    let cwd = harness.project_dir();
    let before = harness.config_snapshot();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input_in(&harness, &cwd, &written.path, "app:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(stdout_of(&out), launch_notice("app:dev"));
    assert_eq!(harness.config_snapshot(), before);
    // The private retained reference is never disclosed.
    for text in [stdout_of(&out), stderr_of(&out)] {
        assert!(!text.contains("private-a"), "{text}");
    }
}

#[test]
fn import_survives_an_unreadable_selection() {
    // Broken user config (even with a matching environment override): the
    // publication still succeeds, with unknown selection handling.
    let mut harness = Harness::new();
    let path = harness.user_config_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "[[tools]\nNAME_SENTINEL = broken").unwrap();
    harness.set("AGENT_VM_IMAGE_TAG", "app:dev");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_imported(&harness.cache_dir(), "app:dev", &written);
    assert_eq!(
        stdout_of(&out),
        format!("{}{SHOW_HINT}", launch_notice("app:dev"))
    );
    // Neither the config error nor its content leaks, and nothing is repaired.
    for text in [stdout_of(&out), stderr_of(&out)] {
        assert!(!text.contains("NAME_SENTINEL"), "{text}");
        assert!(!text.contains("config.toml"), "{text}");
    }

    // A non-Unicode environment override is an unknown selection, not silence.
    let mut harness = Harness::new();
    harness.write_user_image("app:dev");
    harness.set("AGENT_VM_IMAGE_TAG", OsString::from_vec(vec![0xff, b'x']));
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        format!("{}{SHOW_HINT}", launch_notice("app:dev"))
    );

    // A damaged retained record needed by the fallback: same handling, and the
    // record is left exactly as found (no reset to the recommendation).
    let mut harness = Harness::new();
    harness.write_record("SENTINEL_RECORD damaged\n");
    let cwd = harness.project_dir();
    let before = harness.config_snapshot();
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input_in(&harness, &cwd, &written.path, "app:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        format!("{}{SHOW_HINT}", launch_notice("app:dev"))
    );
    assert_eq!(harness.config_snapshot(), before);
    for text in [stdout_of(&out), stderr_of(&out)] {
        assert!(!text.contains("SENTINEL_RECORD"), "{text}");
    }
}

#[test]
fn an_unused_damaged_record_cannot_suppress_a_matching_selection() {
    // A higher explicit source wins, so the fallback record is never read: the
    // completion check must not fail (or hint) because of unused damage.
    let mut harness = Harness::new();
    harness
        .write_user_image("app:dev")
        .write_record("SENTINEL_RECORD damaged\n");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));
}

#[test]
fn import_compares_exact_reference_spelling() {
    // `app` and `app:latest` are different text even though native registry
    // resolution treats them alike; both directions keep the show hint.
    for (configured, imported) in [("app", "app:latest"), ("app:latest", "app")] {
        let mut harness = Harness::new();
        harness.write_user_image(configured);
        let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
        harness.replay(&written);
        let out = harness.run_isolated(&["image", "import", "--docker", imported]);
        assert_eq!(code_of(&out), 0, "{imported}: {}", stderr_of(&out));
        assert_imported(&harness.cache_dir(), imported, &written);
        assert_eq!(
            stdout_of(&out),
            format!("{}{SHOW_HINT}", launch_notice(imported))
        );
    }
}

#[test]
fn import_compares_the_requested_reference_not_archive_aliases() {
    let mut harness = Harness::new();
    harness.write_user_image("z-source:dev");
    let written = image_archive::write_docker_save(
        &harness.home.join("save.tar"),
        &[image_archive::DockerSaveImage {
            marker: "A".into(),
            repo_tags: Some(vec!["z-source:dev".into()]),
        }],
    );
    let out = import_input_in(
        &harness,
        &harness.project_dir(),
        &written[0].path,
        "a-target:dev",
    );
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    // The archive alias matches the configured image, but the requested result
    // reference does not: guidance plus the hint.
    assert_imported(&harness.cache_dir(), "z-source:dev", &written[0]);
    assert_eq!(
        stdout_of(&out),
        format!("{}{SHOW_HINT}", launch_notice("a-target:dev"))
    );
}

#[test]
fn build_completion_output_ignores_the_selection() {
    // Only import became selection-aware.
    let mut harness = Harness::new();
    harness.write_user_image("app:dev");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    harness.replay(&written);
    let out = harness.run_isolated(&["image", "build", "--tag", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        "Imported build result as app:dev; launch it with `--image app:dev`\n"
    );
}

#[test]
fn import_observes_the_selection_only_after_native_ingestion() {
    // The default tier arms a process-global dependency-log guard. If the
    // selector ran before the native import, this dependency event would be
    // dropped; observing after publication is what keeps it visible.
    const MARKER: &str = "loaded layer blob from docker archive";
    let log = "microsandbox_image::archive::docker=debug";

    // Fallback selection (nothing configured): the native marker survives.
    let mut harness = Harness::new();
    harness.set("RUST_LOG", log);
    let written = image_archive::write_docker_save(
        &harness.home.join("save.tar"),
        &[image_archive::DockerSaveImage {
            marker: "A".into(),
            repo_tags: None,
        }],
    );
    harness.replay(&written[0]);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains(MARKER),
        "native ingestion log was suppressed: {}",
        stderr_of(&out)
    );
    assert_eq!(stdout_of(&out), launch_notice("app:dev"));

    // Explicit-selection control: the logger/fixture is genuinely active.
    let mut harness = Harness::new();
    harness.write_user_image("app:other").set("RUST_LOG", log);
    let written = image_archive::write_docker_save(
        &harness.home.join("save.tar"),
        &[image_archive::DockerSaveImage {
            marker: "A".into(),
            repo_tags: None,
        }],
    );
    harness.replay(&written[0]);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains(MARKER),
        "control case lost the ingestion log: {}",
        stderr_of(&out)
    );

    // Late publication failure with a fallback selection: the real error is
    // still reported, the marker is still visible, and no notice is printed.
    let mut harness = Harness::new();
    harness.set("RUST_LOG", log);
    let blocked = cache(&harness.cache_dir())
        .image_metadata_path(&reference("z-source:dev"))
        .with_extension("json.part");
    fs::create_dir_all(blocked.parent().unwrap()).unwrap();
    fs::create_dir(&blocked).unwrap();
    let written = image_archive::write_docker_save(
        &harness.home.join("save.tar"),
        &[image_archive::DockerSaveImage {
            marker: "A".into(),
            repo_tags: Some(vec!["z-source:dev".into()]),
        }],
    );
    harness.replay(&written[0]);
    let out = harness.run_isolated(&["image", "import", "--docker", "app:dev"]);
    assert_eq!(code_of(&out), 1, "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("importing image"),
        "{}",
        stderr_of(&out)
    );
    assert!(stderr_of(&out).contains(MARKER), "{}", stderr_of(&out));
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));
    assert!(!has_metadata(&harness.cache_dir(), "app:dev"));
}

#[test]
fn non_ascii_tag_guidance_keeps_its_shell_word_with_the_show_hint() {
    let mut harness = Harness::new();
    harness.write_user_image("app:other");
    let written = image_archive::write(&harness.home.join("a.tar"), &ArchiveSpec::default());
    let out = import_input_in(&harness, &harness.project_dir(), &written.path, "app:é");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        format!(
            "Imported $'app:\\xc3\\xa9' into agent-vm's image cache; launch it with `--image $'app:\\xc3\\xa9'` (quoted for bash or zsh)\n{SHOW_HINT}"
        )
    );
    // The escaped word still round-trips to the published reference.
    let shown = stdout_of(&out);
    let word = shown
        .split("--image ")
        .nth(1)
        .unwrap()
        .split('`')
        .next()
        .unwrap();
    let shell = Command::new("bash")
        .args(["-c", &format!("printf %s {word}")])
        .output()
        .unwrap();
    assert!(shell.status.success());
    assert!(has_metadata(
        &harness.cache_dir(),
        std::str::from_utf8(&shell.stdout).unwrap()
    ));
}

/// The explicit result reference is the one canonical acquisition key.
/// Importing under an equivalent Hub spelling must land where a launch or
/// refresh looks, and must not create the old native spelling as a second key.
#[test]
fn import_primary_tag_uses_the_canonical_cache_key() {
    let harness = Harness::new();
    let written = image_archive::write(&harness.home.join("a01.tar"), &ArchiveSpec::default());
    let out = import_input(&harness, &written.path, "registry-1.docker.io/alpine:dev");
    assert_eq!(code_of(&out), 0, "{}", stderr_of(&out));

    let cache = cache(&harness.cache_dir());
    let canonical = reference("docker.io/library/alpine:dev");
    assert_imported(
        &harness.cache_dir(),
        "docker.io/library/alpine:dev",
        &written,
    );
    assert!(
        cache.image_metadata_path(&canonical).exists(),
        "the canonical Hub key must be populated"
    );
    let old = reference("registry-1.docker.io/alpine:dev");
    assert!(
        !cache.image_metadata_path(&old).exists(),
        "the pre-canonical spelling must not become a second cache entry"
    );
}
