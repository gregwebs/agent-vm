//! Process-level coverage for `agent-vm --version` (issue #335, controls C1/C2).
//!
//! The version line embeds the source revision captured by `build.rs`. These
//! tests exercise the real binary as a child process: both flags, a broken
//! config, a hostile `PATH` and changed runtime overrides must not alter the
//! output, must never run a decoy `git`/`msb`/`docker`, and must not create any
//! state.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

/// A directory with executable `git`, `msb` and `docker` decoys that append to
/// `marker` and then fail loudly. Any invocation is a defect.
fn decoy_bin(dir: &Path, marker: &Path) -> std::path::PathBuf {
    let bin = dir.join("bin");
    fs::create_dir(&bin).unwrap();
    for tool in ["git", "msb", "docker"] {
        let path = bin.join(tool);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' {tool} >> '{}'\nexit 97\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

struct Fixture {
    _root: TempDir,
    home: std::path::PathBuf,
    cwd: std::path::PathBuf,
    bin: std::path::PathBuf,
    marker: std::path::PathBuf,
    state: std::path::PathBuf,
    initial_paths: Vec<std::path::PathBuf>,
}

impl Fixture {
    /// A private HOME and cwd. `broken` writes an unparseable project and user
    /// config, which `main` loads *before* parsing but must only carry as data.
    fn new(broken: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let cwd = root.path().join("project");
        let marker = root.path().join("decoy-invocations");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        if broken {
            let user = home.join(".config/agent-vm");
            fs::create_dir_all(&user).unwrap();
            fs::write(user.join("config.toml"), "this is = not [ valid toml").unwrap();
            let project = cwd.join(".agent-vm");
            fs::create_dir_all(&project).unwrap();
            fs::write(project.join("config.toml"), "[[tools]\nname").unwrap();
        }
        let bin = decoy_bin(root.path(), &marker);
        let state = root.path().join("state");
        let initial_paths = snapshot(root.path());
        Self {
            state,
            initial_paths,
            _root: root,
            home,
            cwd,
            bin,
            marker,
        }
    }

    fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
        command
            .args(args)
            .current_dir(&self.cwd)
            .env_clear()
            .env("HOME", &self.home)
            .env("AGENT_VM_STATE_DIR", &self.state)
            .env("XDG_STATE_HOME", self._root.path().join("xdg-state"))
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("TMPDIR", self._root.path())
            .env("PATH", &self.bin)
            .env_remove("AGENT_VM_GIT_SHA")
            .env_remove("GITHUB_SHA")
            .env_remove("AGENT_VM_BUILD_PROVENANCE_STRICT");
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command.output().expect("run agent-vm")
    }

    fn assert_no_decoys(&self) {
        assert!(!self.state.exists(), "version created state");
        assert_eq!(
            snapshot(self._root.path()),
            self.initial_paths,
            "unexpected state paths"
        );
        assert!(
            !self.marker.exists(),
            "a decoy git/msb/docker ran: {}",
            fs::read_to_string(&self.marker).unwrap_or_default()
        );
    }
}

/// The embedded line must be exactly `agent-vm <crate version> (<state>)`,
/// one newline-terminated line, with a documented state.
fn assert_version_output(output: &Output) -> String {
    assert!(output.status.success(), "exit status {:?}", output.status);
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let line = text
        .strip_suffix('\n')
        .expect("exactly one trailing newline");
    assert!(!line.contains('\n'), "more than one stdout line: {line:?}");
    let prefix = concat!("agent-vm ", env!("CARGO_PKG_VERSION"), " (");
    assert!(line.starts_with(prefix), "grammar: {line:?}");
    assert!(line.ends_with(')'), "grammar: {line:?}");
    let inner = &line[prefix.len()..line.len() - 1];
    let (revision, label) = match inner.split_once(", ") {
        Some((revision, label)) => (revision, Some(label)),
        None => (inner, None),
    };
    assert!(
        revision == "unknown"
            || (matches!(revision.len(), 40 | 64)
                && revision
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "revision must be a full lowercase hex id or `unknown`: {revision:?}"
    );
    assert!(
        label.is_none() || label == Some("dirty") || label == Some("state unknown"),
        "label must be absent, `dirty` or `state unknown`: {label:?}"
    );
    line.to_string()
}

#[test]
fn both_version_flags_agree_without_touching_the_runtime() {
    let fixture = Fixture::new(false);
    let long = fixture.run(&["--version"], &[]);
    let short = fixture.run(&["-V"], &[]);
    assert_eq!(long.stdout, short.stdout, "`-V` and `--version` must match");
    assert_version_output(&long);
    assert_version_output(&short);
    fixture.assert_no_decoys();
}

#[test]
fn a_broken_config_still_renders_version_and_runs_no_tool() {
    // `main` loads config before parsing; a broken project/user config must be
    // carried as data and must not stop clap's version from exiting 0.
    let clean = Fixture::new(false);
    let broken = Fixture::new(true);
    let expected = assert_version_output(&clean.run(&["--version"], &[]));
    for flag in ["--version", "-V"] {
        let observed = assert_version_output(&broken.run(&[flag], &[]));
        assert_eq!(expected, observed);
    }
    clean.assert_no_decoys();
    broken.assert_no_decoys();
}

#[test]
fn changed_runtime_overrides_do_not_alter_the_embedded_identity() {
    // The SHA overrides and strict flag are *build* inputs. At runtime they must
    // be inert: no re-probe, no git, no changed output (control C2).
    let baseline = Fixture::new(false);
    let expected = assert_version_output(&baseline.run(&["--version"], &[]));
    let changed = Fixture::new(false);
    for strict in ["1", "invalid-at-runtime"] {
        for flag in ["--version", "-V"] {
            let observed = assert_version_output(&changed.run(
                &[flag],
                &[
                    (
                        "AGENT_VM_GIT_SHA",
                        "0000000000000000000000000000000000000000",
                    ),
                    ("GITHUB_SHA", "1111111111111111111111111111111111111111"),
                    ("AGENT_VM_BUILD_PROVENANCE_STRICT", strict),
                ],
            ));
            assert_eq!(expected, observed);
        }
    }
    baseline.assert_no_decoys();
    changed.assert_no_decoys();
}

fn snapshot(root: &Path) -> Vec<std::path::PathBuf> {
    fn visit(path: &Path, paths: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            paths.push(entry.path());
            if entry.file_type().unwrap().is_dir() {
                visit(&entry.path(), paths);
            }
        }
    }
    let mut paths = Vec::new();
    visit(root, &mut paths);
    paths.sort();
    paths
}
