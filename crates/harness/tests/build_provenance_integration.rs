//! Integration controls for the `agent-vm` build-identity probe.
//!
//! These build owned miniature Cargo/Git workspaces. They deliberately invoke
//! the real build script rather than importing it, so Cargo's watcher and
//! fingerprint behaviour stays under test.

use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    package: PathBuf,
    target: PathBuf,
    cargo: PathBuf,
    toolchain: String,
    logs: PathBuf,
    run_number: usize,
    keep: bool,
}

impl Fixture {
    fn new(label: &str) -> Self {
        Self::new_with_git(label, true)
    }

    fn without_git(label: &str) -> Self {
        Self::new_with_git(label, false)
    }

    fn new_with_git(label: &str, git_init: bool) -> Self {
        let root = env::temp_dir().join(format!(
            "bp-contract-{label}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let package = root.join("crates/agent-vm");
        fs::create_dir_all(package.join("src")).expect("create fixture package");
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname = \"agent-vm\"\nversion = \"0.0.1\"\nedition = \"2024\"\n\n[workspace]\n",
        )
        .expect("write fixture manifest");
        fs::write(
            package.join("src/main.rs"),
            "fn main() { println!(\"{}\", concat!(\"agent-vm \", env!(\"AGENT_VM_BUILD_VERSION\"))); }\n",
        )
        .expect("write fixture main");
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let build_rs = env::var_os("AGENT_VM_BUILD_RS")
            .map(PathBuf::from)
            .unwrap_or_else(|| repo_root.join("crates/agent-vm/build.rs"));
        fs::copy(build_rs, package.join("build.rs")).expect("copy actual build script");
        fs::write(root.join(".gitignore"), "target/\n").expect("write fixture ignore");
        let toolchain = env::var("AGENT_VM_FIXTURE_TOOLCHAIN").unwrap_or_else(|_| {
            fs::read_to_string(repo_root.join("rust-toolchain.toml"))
                .expect("read toolchain")
                .lines()
                .find_map(|line| {
                    line.trim()
                        .strip_prefix("channel = ")
                        .map(|value| value.trim_matches('"').to_owned())
                })
                .expect("read pinned channel")
        });
        let cargo = find_program("cargo");
        let fixture = Self {
            target: root.join("target"),
            logs: root.join("_cargo-logs"),
            root,
            package,
            cargo,
            toolchain,
            run_number: 0,
            keep: true,
        };
        fs::create_dir(&fixture.logs).expect("create cargo logs");
        if git_init {
            fixture.git(&["init", "-q", "-b", "main"]);
            fixture.git(&["config", "core.filemode", "true"]);
        }
        fixture
    }

    fn child(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", env::var("PATH").expect("PATH is set"))
            .env(
                "HOME",
                env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned()),
            )
            .env(
                "TMPDIR",
                env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned()),
            )
            .env("RUSTUP_TOOLCHAIN", &self.toolchain)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_TERMINAL_PROMPT", "0");
        command
    }

    fn git(&self, args: &[&str]) {
        self.git_at(&self.root, args);
    }

    fn git_at(&self, directory: &Path, args: &[&str]) {
        let output = self
            .child(Path::new("git"))
            .current_dir(directory)
            .args([
                "--no-optional-locks",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "protocol.file.allow=always",
            ])
            .args(args)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn commit(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--no-gpg-sign", "-m", message]);
    }

    fn head(&self) -> String {
        let output = self
            .child(Path::new("git"))
            .current_dir(&self.root)
            .args(["--no-optional-locks", "rev-parse", "HEAD"])
            .output()
            .expect("read fixture head");
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .expect("head UTF-8")
            .trim()
            .to_owned()
    }

    fn build(&mut self) -> Output {
        self.build_with(&[])
    }

    fn build_with(&mut self, environment: &[(&str, &str)]) -> Output {
        let target = self.target.clone();
        self.build_at(&target, environment, true)
    }

    fn build_with_os(&mut self, key: OsString, value: OsString, required_success: bool) -> Output {
        let mut command = self.child(&self.cargo);
        command
            .current_dir(&self.root)
            .env("CARGO_TARGET_DIR", &self.target)
            .env(key, value)
            .args([
                "build",
                "--offline",
                "-vv",
                "--manifest-path",
                self.package
                    .join("Cargo.toml")
                    .to_str()
                    .expect("UTF-8 path"),
            ]);
        let output = command.output().expect("run fixture cargo build");
        self.run_number += 1;
        fs::write(
            self.logs.join(format!("cargo-{:04}.log", self.run_number)),
            [&output.stdout[..], &output.stderr[..]].concat(),
        )
        .expect("retain cargo log");
        assert!(
            !required_success || output.status.success(),
            "fixture cargo build failed; logs retained at {}: {}",
            self.logs.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn build_at(
        &mut self,
        target: &Path,
        environment: &[(&str, &str)],
        required_success: bool,
    ) -> Output {
        let mut command = self.child(&self.cargo);
        command
            .current_dir(&self.root)
            .env("CARGO_TARGET_DIR", target)
            .args([
                "build",
                "--offline",
                "-vv",
                "--manifest-path",
                self.package
                    .join("Cargo.toml")
                    .to_str()
                    .expect("UTF-8 path"),
            ]);
        for (key, value) in environment {
            command.env(key, value);
        }
        let output = command.output().expect("run fixture cargo build");
        self.run_number += 1;
        fs::write(
            self.logs.join(format!("cargo-{:04}.log", self.run_number)),
            [&output.stdout[..], &output.stderr[..]].concat(),
        )
        .expect("retain cargo log");
        assert!(
            !required_success || output.status.success(),
            "fixture cargo build failed; logs retained at {}: {}",
            self.logs.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn version(&self) -> String {
        self.version_at(&self.target)
    }

    fn version_at(&self, target: &Path) -> String {
        let output = self
            .child(&target.join("debug/agent-vm"))
            .current_dir(&self.root)
            .arg("--version")
            .output()
            .expect("run fixture binary");
        assert!(output.status.success());
        String::from_utf8(output.stdout).expect("version UTF-8")
    }

    fn relocate(&mut self, root: PathBuf) {
        fs::rename(&self.root, &root).expect("move fixture root");
        self.root = root.clone();
        self.package = root.join("crates/agent-vm");
        self.target = root.join("target");
        self.logs = root.join("_cargo-logs");
    }

    fn linked(&self, root: PathBuf) -> Self {
        let logs = root.join("_cargo-logs");
        fs::create_dir(&logs).expect("create linked cargo logs");
        Self {
            package: root.join("crates/agent-vm"),
            target: root.join("target"),
            root,
            cargo: self.cargo.clone(),
            toolchain: self.toolchain.clone(),
            logs,
            run_number: 0,
            keep: true,
        }
    }

    fn fingerprint_paths(&self, target: &Path) -> HashSet<String> {
        let mut paths = HashSet::new();
        for entry in fs::read_dir(target.join("debug/.fingerprint")).expect("read fingerprints") {
            let entry = entry.expect("read fingerprint entry");
            if !entry.file_type().expect("fingerprint file type").is_dir() {
                continue;
            }
            for file in fs::read_dir(entry.path()).expect("read fingerprint directory") {
                let file = file.expect("read fingerprint file");
                if file
                    .path()
                    .extension()
                    .is_none_or(|extension| extension != "json")
                {
                    continue;
                }
                let json: serde_json::Value =
                    serde_json::from_slice(&fs::read(file.path()).expect("read fingerprint JSON"))
                        .expect("parse fingerprint JSON");
                let Some(local) = json.get("local").and_then(serde_json::Value::as_array) else {
                    continue;
                };
                for entry in local {
                    let Some(watcher) = entry.get("RerunIfChanged") else {
                        continue;
                    };
                    let Some(watched) = watcher.get("paths").and_then(serde_json::Value::as_array)
                    else {
                        continue;
                    };
                    paths.extend(
                        watched
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_owned),
                    );
                }
            }
        }
        paths
    }

    fn pass(mut self) {
        self.keep = false;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.keep {
            fs::remove_dir_all(&self.root).expect("remove fixture");
        } else {
            eprintln!(
                "build-provenance failure artifacts: {}",
                self.root.display()
            );
        }
    }
}

fn find_program(name: &str) -> PathBuf {
    env::var_os("PATH")
        .and_then(|paths| {
            env::split_paths(&paths)
                .map(|path| path.join(name))
                .find(|path| path.is_file())
        })
        .unwrap_or_else(|| PathBuf::from(name))
}

fn rebuild_events(output: &Output) -> (usize, usize) {
    let log = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    let text = String::from_utf8_lossy(&log);
    (
        text.matches("build-script-build").count(),
        text.matches("--crate-name agent_vm ").count(),
    )
}

fn provenance_diagnostics(output: &Output) -> String {
    [output.stdout.as_slice(), output.stderr.as_slice()]
        .concat()
        .split(|byte| *byte == b'\n')
        .filter_map(|line| std::str::from_utf8(line).ok())
        .filter(|line| line.contains("build provenance:"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn b1_b2_fixture_framework_preserves_build_identity_controls() {
    let mut b1 = Fixture::new("b1");
    b1.commit("c");
    let b1_head = b1.head();
    b1.build();
    assert_eq!(
        b1.version(),
        format!("agent-vm 0.0.1 ({b1_head})\n"),
        "B1 clean local repository"
    );
    b1.pass();

    let mut b2 = Fixture::new("b2");
    fs::write(b2.root.join("notes.txt"), "one\n").expect("seed notes");
    b2.commit("c");
    let head = b2.head();
    b2.build();
    assert_eq!(
        b2.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B2 baseline clean"
    );
    fs::write(b2.root.join("notes.txt"), "two\n").expect("edit notes");
    b2.build();
    assert_eq!(
        b2.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B2 unstaged tracked edit is dirty"
    );
    b2.git(&["add", "notes.txt"]);
    b2.build();
    assert_eq!(
        b2.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B2 staged tracked edit is dirty"
    );
    b2.git(&["reset", "-q"]);
    fs::remove_file(b2.root.join("notes.txt")).expect("delete notes");
    b2.build();
    assert_eq!(
        b2.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B2 tracked deletion is dirty"
    );
    let diagnostics = provenance_diagnostics(&b2.build());
    assert!(
        diagnostics.is_empty(),
        "B2 normal build emitted provenance diagnostic: {diagnostics}"
    );
    assert_ne!(
        rebuild_events(&b2.build()),
        (0, 0),
        "B2 dirty build did not rerun"
    );
    b2.pass();
}

#[test]
fn b11_b12_unversioned_directories_do_not_adopt_an_outer_checkout() {
    let mut b11 = Fixture::without_git("b11");
    b11.build();
    assert_eq!(
        b11.version(),
        "agent-vm 0.0.1 (unknown)\n",
        "B11 no Git metadata is unknown"
    );
    b11.git(&["init", "-q", "-b", "main"]);
    b11.git(&["config", "core.filemode", "true"]);
    b11.commit("c");
    let head = b11.head();
    b11.build();
    assert_eq!(
        b11.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B11 Git restored recovers the real HEAD"
    );
    b11.pass();

    let outer = Fixture::new("b12-outer");
    let nested_root = outer.root.join("nested");
    fs::create_dir(&nested_root).expect("create nested tarball directory");
    fs::write(outer.root.join("outer.txt"), "outer\n").expect("write outer file");
    outer.commit("outer");
    let mut b12 = Fixture::without_git("b12-tarball");
    fs::remove_dir_all(&b12.root).expect("replace tarball root");
    fs::rename(&nested_root, &b12.root).expect("place tarball under outer checkout");
    b12.package = b12.root.join("crates/agent-vm");
    b12.target = b12.root.join("target");
    b12.logs = b12.root.join("_cargo-logs");
    // The package must be created inside the nested directory, not in a
    // separate fixture root, to exercise Git's top-level ownership check.
    fs::create_dir_all(b12.package.join("src")).expect("create nested package");
    fs::write(
        b12.package.join("Cargo.toml"),
        "[package]\nname = \"agent-vm\"\nversion = \"0.0.1\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .expect("write nested manifest");
    fs::write(
        b12.package.join("src/main.rs"),
        "fn main() { println!(\"{}\", concat!(\"agent-vm \", env!(\"AGENT_VM_BUILD_VERSION\"))); }\n",
    )
    .expect("write nested main");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/agent-vm/build.rs"),
        b12.package.join("build.rs"),
    )
    .expect("copy nested build script");
    fs::create_dir(&b12.logs).expect("create nested cargo logs");
    b12.build();
    assert_eq!(
        b12.version(),
        "agent-vm 0.0.1 (unknown)\n",
        "B12 tarball nested in an unrelated repo is unknown"
    );
    b12.pass();
    outer.pass();
}

#[test]
fn b15_unrepresentable_paths_fall_back_without_unsafe_cargo_directives() {
    let mut fixture = Fixture::new("b15");
    fs::write(fixture.root.join("note"), "plain\n").expect("write plain note");
    fs::write(fixture.root.join("note "), "trailing space\n").expect("write unsafe note");
    fs::write(fixture.root.join("note middle"), "interior space\n").expect("write safe note");
    fixture.commit("c");
    let head = fixture.head();
    fixture.build();
    let paths = fixture.fingerprint_paths(&fixture.target);
    assert!(
        paths.contains("../../note") && paths.contains("../../note middle"),
        "B15 safe names are package-relative spellings: {paths:?}"
    );
    assert!(
        !paths.contains("../../note ")
            && paths.contains("build.rs/agent-vm-provenance-always-rerun"),
        "B15 terminal-space candidate is omitted, not trimmed"
    );
    assert_safe_watch_paths(&paths, "B15 no raw absolute watcher path");
    fs::write(fixture.root.join("note "), "edited trailing space\n").expect("edit unsafe note");
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B15 editing only the unsafe name still reports dirty"
    );
    fixture.pass();

    for (label, name) in [
        ("lf", b"bad\nname".as_slice()),
        ("cr", b"bad\rname".as_slice()),
        ("unicode", "caf\u{00e9}.txt".as_bytes()),
        ("nonunicode", b"bad\xffname".as_slice()),
    ] {
        let mut weird = Fixture::new(&format!("b15-{label}"));
        if let Err(error) = fs::write(
            weird.root.join(std::ffi::OsString::from_vec(name.to_vec())),
            "unsafe\n",
        ) {
            assert_eq!(label, "nonunicode", "write unsafe tracked name: {error}");
            eprintln!("B15 non-Unicode tracked name is unsupported here: {error}");
            weird.pass();
            continue;
        }
        weird.commit("c");
        let output = weird.build();
        let paths = weird.fingerprint_paths(&weird.target);
        assert!(
            paths.contains("build.rs/agent-vm-provenance-always-rerun")
                && provenance_diagnostics(&output).contains("incomplete"),
            "B15 independent {label} name fallback"
        );
        assert_safe_watch_paths(&paths, &format!("B15 independent {label} watcher paths"));
        weird.pass();
    }

    for (label, odd_name) in [
        ("spaces", "path middle"),
        ("unicode", "path-\u{00e9}"),
        ("cr", "path\rroot"),
        ("lf", "path\nroot"),
        ("terminal-space", "path "),
    ] {
        for source in [true, false] {
            let mut odd = Fixture::new(&format!(
                "b15-{}-{label}",
                if source { "source" } else { "target" }
            ));
            if source {
                let root = odd.root.parent().expect("fixture parent").join(odd_name);
                odd.relocate(root);
            }
            odd.commit("c");
            let target = odd
                .root
                .parent()
                .expect("fixture parent")
                .join(format!(
                    "b15-output-{}-{label}",
                    if source { "source" } else { "target" }
                ))
                .join(if source { "target" } else { odd_name });
            odd.build_at(&target, &[], true);
            let paths = odd.fingerprint_paths(&target);
            assert_safe_watch_paths(
                &paths,
                &format!(
                    "B15 independent odd {label} {}",
                    if source { "source" } else { "target" }
                ),
            );
            let expected = if source && matches!(label, "cr" | "lf") {
                "agent-vm 0.0.1 (unknown)\n".to_owned()
            } else {
                format!("agent-vm 0.0.1 ({})\n", odd.head())
            };
            assert_eq!(
                odd.version_at(&target),
                expected,
                "B15 independent odd {label} {} identity",
                if source { "source" } else { "target" }
            );
            odd.pass();
        }
    }

    for (label, common_name) in [
        ("spaces", "common middle"),
        ("cr", "common\rdir"),
        ("unicode", "common-\u{00e9}"),
    ] {
        let mut odd = Fixture::new(&format!("b15-common-{label}"));
        odd.commit("c");
        let common = odd.root.parent().expect("fixture parent").join(format!(
            "{}-{common_name}",
            odd.root
                .file_name()
                .expect("fixture name")
                .to_string_lossy()
        ));
        fs::rename(odd.root.join(".git"), &common).expect("move common Git directory");
        fs::write(
            odd.root.join(".git"),
            format!("gitdir: {}\n", common.display()),
        )
        .expect("write Git directory marker");
        let output = odd.build();
        let paths = odd.fingerprint_paths(&odd.target);
        assert_safe_watch_paths(
            &paths,
            &format!("B15 independent odd {label} common Git dir"),
        );
        if label == "spaces" {
            assert!(
                paths.iter().any(|path| path.contains("common middle")),
                "B15 space-containing common Git directory remains representable"
            );
        } else {
            assert!(
                paths.contains("build.rs/agent-vm-provenance-always-rerun")
                    && provenance_diagnostics(&output).contains("incomplete"),
                "B15 {label} common Git directory falls back"
            );
        }
        odd.pass();
    }
}

fn assert_safe_watch_paths(paths: &HashSet<String>, case: &str) {
    assert!(
        paths
            .iter()
            .all(|path| !path.starts_with('/') && !path.contains(['\r', '\n']) && path.is_ascii()),
        "{case}: {paths:?}"
    );
}

fn non_alias_mtimes(fixture: &Fixture) -> HashMap<String, std::time::SystemTime> {
    fixture
        .fingerprint_paths(&fixture.target)
        .into_iter()
        .filter(|path| !path.ends_with("/alias"))
        .filter_map(|path| {
            fs::symlink_metadata(fixture.package.join(&path))
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .map(|mtime| (path, mtime))
        })
        .collect()
}

fn chmod_executable(path: &Path, executable: bool) {
    let mode = fs::metadata(path).expect("read mode").permissions().mode();
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if executable {
            mode | 0o111
        } else {
            mode & !0o111
        }),
    )
    .expect("change executable mode");
}

#[test]
fn b16_b18_strict_mode_controls_hold() {
    let strict = [("AGENT_VM_BUILD_PROVENANCE_STRICT", "1")];
    let mut b16 = Fixture::new("b16");
    let script = b16.root.join("run.sh");
    fs::write(&script, "#!/bin/sh\necho hi\n").expect("write executable");
    chmod_executable(&script, true);
    b16.commit("c");
    let head = b16.head();
    b16.build_with(&strict);
    assert_eq!(
        b16.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B16 strict clean baseline"
    );
    assert!(
        b16.fingerprint_paths(&b16.target)
            .contains("build.rs/agent-vm-provenance-always-rerun"),
        "B16 strict fallback dependency"
    );
    chmod_executable(&script, false);
    let output = b16.build_with(&strict);
    assert!(
        rebuild_events(&output).0 > 0
            && rebuild_events(&output).1 > 0
            && b16.version() == format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B16 strict detects preserved-name collision-resistant mode dirt"
    );
    chmod_executable(&script, true);
    b16.build_with(&strict);
    assert_eq!(
        b16.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B16 strict reports clean after mode restore"
    );
    let old_name = b16.root.join(".agent-vm-provenance-always-rerun");
    fs::write(&old_name, "collision\n").expect("write old collision");
    chmod_executable(&script, false);
    assert_ne!(
        rebuild_events(&b16.build_with(&strict)),
        (0, 0),
        "B16 old-name file collision cannot disable strict"
    );
    fs::remove_file(&old_name).expect("remove old collision");
    fs::create_dir(&old_name).expect("create old collision directory");
    assert_ne!(
        rebuild_events(&b16.build_with(&strict)),
        (0, 0),
        "B16 old-name directory collision cannot disable strict"
    );
    chmod_executable(&script, true);
    let unchanged = b16.build_with(&strict);
    assert!(
        rebuild_events(&unchanged).0 > 0 && rebuild_events(&unchanged).1 > 0,
        "B16 unchanged strict build reruns"
    );
    b16.pass();

    let mut default = Fixture::new("b16-default");
    default.commit("c");
    default.build();
    fs::write(
        default.root.join(".agent-vm-provenance-always-rerun"),
        "collision\n",
    )
    .expect("write untracked default collision");
    assert_eq!(
        rebuild_events(&default.build()),
        (0, 0),
        "B16 default untracked old-name entry stays fresh"
    );
    default.pass();

    let mut fallback = Fixture::without_git("b16-fallback");
    fallback.build();
    let fallback_name = fallback.root.join(".agent-vm-provenance-always-rerun");
    fs::write(&fallback_name, "collision\n").expect("write fallback collision");
    let file_retry = fallback.build();
    assert!(
        rebuild_events(&file_retry).0 > 0
            && rebuild_events(&file_retry).1 > 0
            && fallback
                .fingerprint_paths(&fallback.target)
                .contains("build.rs/agent-vm-provenance-always-rerun"),
        "B16 fallback old-name file collision retries"
    );
    fs::remove_file(&fallback_name).expect("remove fallback collision");
    fs::create_dir(&fallback_name).expect("create fallback collision directory");
    let directory_retry = fallback.build();
    assert!(
        rebuild_events(&directory_retry).0 > 0
            && rebuild_events(&directory_retry).1 > 0
            && fallback
                .fingerprint_paths(&fallback.target)
                .contains("build.rs/agent-vm-provenance-always-rerun"),
        "B16 fallback old-name directory collision retries"
    );
    fallback.pass();

    let mut b17 = Fixture::new("b17");
    let tool = b17.root.join("tool.sh");
    fs::write(&tool, "#!/bin/sh\necho hi\n").expect("write tool");
    chmod_executable(&tool, true);
    b17.commit("c");
    let head = b17.head();
    b17.build();
    chmod_executable(&tool, false);
    assert_eq!(
        rebuild_events(&b17.build()),
        (0, 0),
        "B17 default mode-only chmod stays fresh"
    );
    assert_eq!(
        b17.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B17 default stale clean label residual"
    );
    b17.build_with(&strict);
    assert_eq!(
        b17.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B17 strict detects mode-only dirt"
    );
    chmod_executable(&tool, true);
    b17.build_with(&strict);
    assert_eq!(
        b17.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B17 strict clean after restore"
    );
    let older_target = b17.root.join("older-target");
    fs::write(&older_target, "target\n").expect("write symlink target");
    let regular = b17.root.join("regular.txt");
    fs::write(&regular, "regular\n").expect("write regular file");
    b17.commit("add regular file");
    let second_head = b17.head();
    b17.build_with(&strict);
    fs::remove_file(&regular).expect("remove regular file");
    std::os::unix::fs::symlink("older-target", &regular)
        .expect("replace regular file with symlink");
    b17.build_with(&strict);
    assert_eq!(
        b17.version(),
        format!("agent-vm 0.0.1 ({second_head}, dirty)\n"),
        "B17 strict detects regular-to-symlink transition"
    );
    fs::remove_file(&regular).expect("remove symlink");
    fs::write(&regular, "regular\n").expect("restore regular file");
    b17.build_with(&strict);
    assert_eq!(
        b17.version(),
        format!("agent-vm 0.0.1 ({second_head})\n"),
        "B17 strict clean after symlink restore"
    );
    let origin = b17.root.with_file_name(format!(
        "{}-sub-origin",
        b17.root
            .file_name()
            .expect("fixture name")
            .to_string_lossy()
    ));
    fs::create_dir(&origin).expect("create B17 submodule origin");
    b17.git_at(&origin, &["init", "-q", "-b", "main"]);
    let origin_tool = origin.join("tool.sh");
    fs::write(&origin_tool, "#!/bin/sh\nexit 0\n").expect("write submodule tool");
    chmod_executable(&origin_tool, true);
    b17.git_at(&origin, &["add", "-A"]);
    b17.git_at(&origin, &["commit", "-q", "--no-gpg-sign", "-m", "tool"]);
    b17.git(&[
        "submodule",
        "add",
        "-q",
        origin.to_str().expect("origin path"),
        "vendor/sub",
    ]);
    b17.commit("add submodule");
    let third_head = b17.head();
    let sub_tool = b17.root.join("vendor/sub/tool.sh");
    b17.build_with(&strict);
    let before_mtime = fs::metadata(&sub_tool)
        .expect("read submodule tool")
        .modified()
        .expect("read submodule mtime");
    chmod_executable(&sub_tool, false);
    let output = b17.build_with(&strict);
    assert!(
        fs::metadata(&sub_tool)
            .expect("read changed submodule tool")
            .modified()
            .expect("read changed mtime")
            == before_mtime
            && rebuild_events(&output) != (0, 0)
            && b17.version() == format!("agent-vm 0.0.1 ({third_head}, dirty)\n"),
        "B17 strict submodule chmod dirt with unchanged mtime"
    );
    chmod_executable(&sub_tool, true);
    b17.build_with(&strict);
    assert_eq!(
        b17.version(),
        format!("agent-vm 0.0.1 ({third_head})\n"),
        "B17 strict submodule chmod restoration"
    );
    fs::remove_dir_all(&origin).expect("remove B17 submodule origin");
    b17.pass();

    let mut b18 = Fixture::new("b18");
    let tool = b18.root.join("tool.sh");
    fs::write(&tool, "#!/bin/sh\necho hi\n").expect("write tool");
    chmod_executable(&tool, true);
    b18.commit("c");
    let head = b18.head();
    b18.build();
    chmod_executable(&tool, false);
    assert_eq!(
        rebuild_events(&b18.build()),
        (0, 0),
        "B18 default chmod stays fresh"
    );
    b18.build_with(&strict);
    assert_eq!(
        b18.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B18 enabling strict measures dirt"
    );
    chmod_executable(&tool, true);
    b18.build_with(&strict);
    let unset = b18.build();
    assert_ne!(
        rebuild_events(&unset),
        (0, 0),
        "B18 unsetting strict reruns once"
    );
    assert_eq!(
        rebuild_events(&b18.build()),
        (0, 0),
        "B18 cheap behavior returns after unset"
    );
    for value in ["2", "true"] {
        let output = b18.build_at(
            &b18.target.clone(),
            &[("AGENT_VM_BUILD_PROVENANCE_STRICT", value)],
            false,
        );
        assert!(
            !output.status.success()
                && !provenance_diagnostics(&output).contains(value)
                && provenance_diagnostics(&output).contains("AGENT_VM_BUILD_PROVENANCE_STRICT"),
            "B18 invalid strict value is value-free"
        );
    }
    for value in ["0", "1", ""] {
        assert!(
            b18.build_with(&[("AGENT_VM_BUILD_PROVENANCE_STRICT", value)])
                .status
                .success(),
            "B18 accepted strict value {value:?}"
        );
    }
    let mut non_unicode = Fixture::new("b18-nonunicode");
    non_unicode.commit("c");
    non_unicode.build();
    let before = non_unicode.version();
    let non_unicode_value = OsString::from_vec(vec![0xff]);
    let cached = non_unicode.build_with_os(
        OsString::from("AGENT_VM_BUILD_PROVENANCE_STRICT"),
        non_unicode_value.clone(),
        true,
    );
    assert_eq!(
        rebuild_events(&cached),
        (0, 0),
        "B18 absent-to-non-Unicode cached default"
    );
    assert_eq!(non_unicode.version(), before, "B18 cached default output");
    fs::write(non_unicode.root.join("change.txt"), "x\n").expect("trigger non-Unicode probe");
    non_unicode.git(&["add", "change.txt"]);
    let failed = non_unicode.build_with_os(
        OsString::from("AGENT_VM_BUILD_PROVENANCE_STRICT"),
        non_unicode_value,
        false,
    );
    assert!(
        !failed.status.success()
            && String::from_utf8_lossy(&failed.stderr).contains("AGENT_VM_BUILD_PROVENANCE_STRICT"),
        "B18 non-Unicode strict value hard-fails when the probe runs"
    );
    non_unicode.pass();
    b18.pass();
}

#[test]
fn dangling_link_matrix_retains_a_dependency_and_measures_every_transition() {
    for nested in [false, true] {
        for parent_watch in [false, true] {
            for strict_mode in [false, true] {
                let label = format!(
                    "dangling-{}-{}-{}",
                    if nested { "submodule" } else { "top" },
                    if parent_watch { "parent" } else { "fallback" },
                    if strict_mode { "strict" } else { "default" }
                );
                let mut fixture = Fixture::new(&label);
                fixture.commit("top");
                let mut tree = fixture.root.clone();
                let mut origin = None;
                if nested {
                    let source = fixture.root.with_file_name(format!(
                        "{}-origin",
                        fixture
                            .root
                            .file_name()
                            .expect("fixture name")
                            .to_string_lossy()
                    ));
                    fs::create_dir(&source).expect("create dangling submodule source");
                    fixture.git_at(&source, &["init", "-q", "-b", "main"]);
                    fs::write(source.join("sub.txt"), "sub\n").expect("write dangling source");
                    fixture.git_at(&source, &["add", "-A"]);
                    fixture.git_at(&source, &["commit", "-q", "--no-gpg-sign", "-m", "sub"]);
                    fixture.git(&[
                        "submodule",
                        "add",
                        "-q",
                        source.to_str().expect("source path"),
                        "vendor/sub",
                    ]);
                    tree = fixture.root.join("vendor/sub");
                    origin = Some(source);
                }
                if parent_watch {
                    tree.push("links");
                    fs::create_dir(&tree).expect("create dangling parent");
                }
                let link = tree.join("link");
                std::os::unix::fs::symlink("absent-one", &link).expect("create dangling link");
                fixture.git_at(&tree, &["add", "link"]);
                fixture.git_at(&tree, &["commit", "-q", "--no-gpg-sign", "-m", "link"]);
                if nested {
                    fixture.commit("submodule link");
                }
                let head = fixture.head();
                let strict = if strict_mode {
                    vec![("AGENT_VM_BUILD_PROVENANCE_STRICT", "1")]
                } else {
                    Vec::new()
                };
                fixture.build_with(&strict);
                let paths = fixture.fingerprint_paths(&fixture.target);
                assert_eq!(
                    paths.contains("build.rs/agent-vm-provenance-always-rerun"),
                    strict_mode || !parent_watch,
                    "dangling {label} baseline dependency policy"
                );
                let unchanged = fixture.build_with(&strict);
                if parent_watch && !strict_mode {
                    assert_eq!(
                        rebuild_events(&unchanged),
                        (0, 0),
                        "dangling {label} bounded unchanged cost"
                    );
                } else {
                    assert_ne!(
                        rebuild_events(&unchanged),
                        (0, 0),
                        "dangling {label} fallback unchanged cost"
                    );
                }
                for (change, dirty) in [
                    ("delete", true),
                    ("retarget", true),
                    ("regular", true),
                    ("restore", false),
                ] {
                    if link.exists() || fs::symlink_metadata(&link).is_ok() {
                        fs::remove_file(&link).expect("remove dangling link");
                    }
                    match change {
                        "retarget" => std::os::unix::fs::symlink("absent-two", &link)
                            .expect("retarget dangling link"),
                        "regular" => fs::write(&link, "regular\n").expect("replace dangling link"),
                        "restore" => std::os::unix::fs::symlink("absent-one", &link)
                            .expect("restore dangling link"),
                        "delete" => {}
                        _ => unreachable!(),
                    }
                    let output = fixture.build_with(&strict);
                    assert_ne!(
                        rebuild_events(&output),
                        (0, 0),
                        "dangling {label} {change} invalidates"
                    );
                    assert_eq!(
                        fixture.version(),
                        format!(
                            "agent-vm 0.0.1 ({head}{})\n",
                            if dirty { ", dirty" } else { "" }
                        ),
                        "dangling {label} {change} status"
                    );
                    let paths = fixture.fingerprint_paths(&fixture.target);
                    assert!(
                        if matches!(change, "retarget" | "restore") {
                            if parent_watch {
                                paths.iter().any(|path| path.ends_with("/links"))
                            } else {
                                paths.contains("build.rs/agent-vm-provenance-always-rerun")
                            }
                        } else {
                            paths.iter().any(|path| path.ends_with("/link"))
                        },
                        "dangling {label} {change} required dependency retained"
                    );
                }
                if let Some(source) = origin {
                    fs::remove_dir_all(source).expect("remove dangling source");
                }
                fixture.pass();
            }
        }
    }
}

#[test]
fn discovery_faults_retain_partial_watchers_retry_and_recover() {
    let real_git = find_program("git");
    for fault in ["HEAD", "packed-refs", "symbolic"] {
        let mut fixture = Fixture::new(&format!("fault-{fault}"));
        fixture.commit("a");
        let a = fixture.head();
        fixture.git(&["branch", "a"]);
        fixture.git(&["checkout", "-q", "-b", "b"]);
        fixture.git(&["commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "b"]);
        let b = fixture.head();
        fixture.git(&["symbolic-ref", "refs/heads/alias", "refs/heads/a"]);
        fixture.git(&["symbolic-ref", "HEAD", "refs/heads/alias"]);
        let adapter = fixture.root.join("adapter");
        fs::create_dir(&adapter).expect("create Git adapter");
        let control = adapter.join("fault");
        fs::write(&control, fault).expect("write fault control");
        let wrapper = adapter.join("git");
        fs::write(&wrapper, format!("#!/bin/sh\nfault=$(cat {0})\ncase \"$fault:$*\" in\n  symbolic:*symbolic-ref*|HEAD:*--git-path*HEAD|packed-refs:*--git-path*packed-refs) exit 128 ;;\nesac\nexec {1} \"$@\"\n", control.display(), real_git.display())).expect("write Git adapter");
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755))
            .expect("make Git adapter executable");
        let path = format!("{}:{}", adapter.display(), env::var("PATH").expect("PATH"));
        let output = fixture.build_with(&[("PATH", &path)]);
        assert!(
            fixture.version() == format!("agent-vm 0.0.1 ({a})\n")
                && fixture
                    .fingerprint_paths(&fixture.target)
                    .contains("build.rs/agent-vm-provenance-always-rerun")
                && provenance_diagnostics(&output).contains("incomplete"),
            "fault {fault} fallback retains partial watchers"
        );
        assert_ne!(
            rebuild_events(&fixture.build_with(&[("PATH", &path)])),
            (0, 0),
            "fault {fault} retries per build"
        );
        fixture.git(&["symbolic-ref", "refs/heads/alias", "refs/heads/b"]);
        fixture.build_with(&[("PATH", &path)]);
        assert_eq!(
            fixture.version(),
            format!("agent-vm 0.0.1 ({b})\n"),
            "fault {fault} alias retarget regression"
        );
        fs::write(&control, "").expect("clear fault");
        fixture.build_with(&[("PATH", &path)]);
        assert!(
            !fixture
                .fingerprint_paths(&fixture.target)
                .contains("build.rs/agent-vm-provenance-always-rerun")
                && fixture.version() == format!("agent-vm 0.0.1 ({b})\n"),
            "fault {fault} recovery drops fallback"
        );
        assert_eq!(
            rebuild_events(&fixture.build_with(&[("PATH", &path)])),
            (0, 0),
            "fault {fault} recovered fresh"
        );
        fixture.git(&["checkout", "-q", "--detach", &a]);
        fixture.build_with(&[("PATH", &path)]);
        assert!(
            !fixture
                .fingerprint_paths(&fixture.target)
                .contains("build.rs/agent-vm-provenance-always-rerun")
                && fixture.version() == format!("agent-vm 0.0.1 ({a})\n"),
            "fault {fault} detached terminal complete"
        );
        fixture.pass();
    }
}

#[test]
fn b19_symbolic_ref_aliases_are_watched_and_invalidate() {
    let mut fixture = Fixture::new("b19");
    fixture.commit("a");
    let a = fixture.head();
    fixture.git(&["branch", "a"]);
    fixture.git(&["checkout", "-q", "-b", "b"]);
    fixture.git(&["commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "b"]);
    let b = fixture.head();
    fixture.git(&["checkout", "-q", "main"]);
    fixture.git(&["symbolic-ref", "refs/heads/alias", "refs/heads/a"]);
    fixture.git(&["symbolic-ref", "HEAD", "refs/heads/alias"]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({a})\n"),
        "B19 alias baseline is a"
    );
    let paths = fixture.fingerprint_paths(&fixture.target);
    assert!(
        paths.iter().any(|path| path.ends_with("refs/heads/alias"))
            && paths.iter().any(|path| path.ends_with("refs/heads/a"))
            && paths.iter().any(|path| path.ends_with(".git/HEAD")),
        "B19 every symbolic link and terminal is watched"
    );
    let top_non_alias_mtimes = non_alias_mtimes(&fixture);
    fixture.git(&["symbolic-ref", "refs/heads/alias", "refs/heads/b"]);
    assert_eq!(
        top_non_alias_mtimes,
        non_alias_mtimes(&fixture),
        "B19 alias retarget preserves non-alias mtimes"
    );
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({b})\n"),
        "B19 retargeting only alias yields b"
    );
    fixture.git(&["symbolic-ref", "refs/heads/alias", "refs/heads/a"]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({a})\n"),
        "B19 retargeting back yields a"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B19 fresh after alias retargeting"
    );
    let origin = fixture.root.with_file_name(format!(
        "{}-sub-origin",
        fixture
            .root
            .file_name()
            .expect("fixture name")
            .to_string_lossy()
    ));
    fs::create_dir(&origin).expect("create B19 submodule origin");
    fixture.git_at(&origin, &["init", "-q", "-b", "main"]);
    fs::write(origin.join("sub.txt"), "sub\n").expect("write B19 submodule source");
    fixture.git_at(&origin, &["add", "-A"]);
    fixture.git_at(&origin, &["commit", "-q", "--no-gpg-sign", "-m", "sub"]);
    fixture.git(&[
        "submodule",
        "add",
        "-q",
        origin.to_str().expect("origin path"),
        "vendor/sub",
    ]);
    let sub = fixture.root.join("vendor/sub");
    let sub_a = git_stdout(&fixture, &sub, &["rev-parse", "HEAD"]);
    let sub_a = sub_a.trim().to_owned();
    fixture.git_at(&sub, &["branch", "a"]);
    fixture.git_at(&sub, &["checkout", "-q", "-b", "b"]);
    fixture.git_at(
        &sub,
        &["commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "b"],
    );
    fixture.git_at(&sub, &["symbolic-ref", "refs/heads/alias", "refs/heads/a"]);
    fixture.git_at(&sub, &["symbolic-ref", "HEAD", "refs/heads/alias"]);
    fixture.commit("submodule aliases");
    let top = fixture.head();
    fixture.build();
    assert!(
        git_stdout(&fixture, &sub, &["rev-parse", "HEAD"]).trim() == sub_a
            && fixture.version() == format!("agent-vm 0.0.1 ({top})\n"),
        "B19 submodule alias baseline clean"
    );
    assert!(
        fixture
            .fingerprint_paths(&fixture.target)
            .iter()
            .any(|path| path.ends_with("modules/vendor/sub/refs/heads/alias")),
        "B19 submodule intermediate alias watched"
    );
    let sub_non_alias_mtimes = non_alias_mtimes(&fixture);
    fixture.git_at(&sub, &["symbolic-ref", "refs/heads/alias", "refs/heads/b"]);
    assert_eq!(
        sub_non_alias_mtimes,
        non_alias_mtimes(&fixture),
        "B19 submodule alias retarget preserves non-alias mtimes"
    );
    let output = fixture.build();
    assert!(
        rebuild_events(&output) != (0, 0)
            && fixture.version() == format!("agent-vm 0.0.1 ({top}, dirty)\n"),
        "B19 submodule alias retarget invalidates to dirty"
    );
    fixture.git_at(&sub, &["symbolic-ref", "refs/heads/alias", "refs/heads/a"]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({top})\n"),
        "B19 submodule alias restoration clean"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B19 submodule alias unchanged fresh"
    );
    fs::remove_dir_all(&origin).expect("remove B19 submodule origin");
    fixture.pass();
}

#[test]
fn b14_complete_discovery_is_precise_and_dirty_transitions_invalidate() {
    let mut fixture = Fixture::new("b14");
    fs::write(fixture.root.join("outside.txt"), "base\n").expect("write tracked file");
    fixture.commit("c");
    let head = fixture.head();
    fixture.build();
    assert!(
        !fixture
            .fingerprint_paths(&fixture.target)
            .contains("build.rs/agent-vm-provenance-always-rerun"),
        "B14 complete discovery omits the ENOTDIR fallback"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B14 first unchanged default build is fresh"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B14 second unchanged default build is fresh"
    );
    fs::write(fixture.root.join("outside.txt"), "dirty-one\n").expect("dirty tracked file");
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B14 dirty content build is dirty"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B14 unchanged dirty build is fresh"
    );
    fs::write(fixture.root.join("outside.txt"), "dirty-two\n").expect("change dirty file");
    let output = fixture.build();
    let (probe, launcher) = rebuild_events(&output);
    assert!(
        probe > 0
            && launcher > 0
            && fixture.version() == format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B14 dirty-X to dirty-Y reruns and stays dirty: probe={probe} launcher={launcher}"
    );
    fixture.pass();
}

#[test]
fn b13_shallow_clone_with_uninitialized_gitlink_stays_clean() {
    let origin = Fixture::new("b13-origin");
    origin.commit("first");
    let submodule_origin = origin.root.with_file_name(format!(
        "{}-submodule-origin",
        origin
            .root
            .file_name()
            .expect("fixture name")
            .to_string_lossy()
    ));
    fs::create_dir(&submodule_origin).expect("create submodule origin");
    origin.git_at(&submodule_origin, &["init", "-q", "-b", "main"]);
    fs::write(submodule_origin.join("sub.txt"), "sub\n").expect("write submodule source");
    origin.git_at(&submodule_origin, &["add", "-A"]);
    origin.git_at(
        &submodule_origin,
        &["commit", "-q", "--no-gpg-sign", "-m", "sub"],
    );
    origin.git(&[
        "submodule",
        "add",
        "-q",
        submodule_origin.to_str().expect("UTF-8 submodule origin"),
        "vendor/sub",
    ]);
    origin.commit("second with optional gitlink");
    origin.git(&[
        "commit",
        "-q",
        "--no-gpg-sign",
        "--allow-empty",
        "-m",
        "third",
    ]);
    let clone_root = origin.root.with_file_name(format!(
        "{}-clone",
        origin
            .root
            .file_name()
            .expect("fixture name")
            .to_string_lossy()
    ));
    origin.git_at(
        origin.root.parent().expect("fixture parent"),
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &format!("file://{}", origin.root.display()),
            clone_root.to_str().expect("UTF-8 clone root"),
        ],
    );
    let mut clone = origin.linked(clone_root.clone());
    let shallow = clone_root.join(".git/shallow");
    assert!(
        shallow.is_file()
            && git_stdout(
                &clone,
                &clone_root,
                &["rev-parse", "--is-shallow-repository"]
            )
            .trim()
                == "true"
            && git_stdout(&clone, &clone_root, &["rev-list", "--count", "HEAD"]).trim() == "1"
            && git_stdout(&origin, &origin.root, &["rev-list", "--count", "HEAD"]).trim() == "3",
        "B13 actual file-transport shallow clone"
    );
    assert!(
        clone_root.join("vendor/sub").is_dir() && !clone_root.join("vendor/sub/.git").exists(),
        "B13 optional gitlink remains uninitialized"
    );
    clone.build();
    assert_eq!(
        clone.version(),
        format!("agent-vm 0.0.1 ({})\n", clone.head()),
        "B13 shallow clone with uninitialized gitlink is clean"
    );
    assert_eq!(
        rebuild_events(&clone.build()),
        (0, 0),
        "B13 shallow optional gitlink stays fresh"
    );
    fs::remove_dir_all(&submodule_origin).expect("remove submodule origin");
    clone.pass();
    origin.pass();
}

fn git_stdout(fixture: &Fixture, directory: &Path, args: &[&str]) -> String {
    let output = fixture
        .child(Path::new("git"))
        .current_dir(directory)
        .args(args)
        .output()
        .expect("run git query");
    assert!(output.status.success(), "git query {args:?} failed");
    String::from_utf8(output.stdout).expect("git query UTF-8")
}

#[test]
fn b3_b4_b6_track_repository_state() {
    let mut b3 = Fixture::new("b3");
    fs::write(b3.root.join(".gitignore"), "ignored/\n").expect("write ignore");
    fs::write(b3.root.join("tracked.txt"), "x\n").expect("write tracked");
    b3.commit("c");
    let head = b3.head();
    b3.build();
    fs::write(b3.root.join("untracked.txt"), "u\n").expect("write untracked");
    fs::create_dir(b3.root.join("ignored")).expect("create ignored");
    fs::write(b3.root.join("ignored/thing"), "i\n").expect("write ignored file");
    b3.build();
    assert_eq!(
        b3.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B3 untracked and ignored files stay clean"
    );
    b3.pass();

    let mut b4 = Fixture::new("b4");
    b4.commit("c");
    let head_a = b4.head();
    b4.build();
    assert_eq!(
        b4.version(),
        format!("agent-vm 0.0.1 ({head_a})\n"),
        "B4 baseline A"
    );
    b4.git(&["checkout", "-q", "-b", "x"]);
    b4.git(&["commit", "-q", "--no-gpg-sign", "--allow-empty", "-m", "b"]);
    let head_b = b4.head();
    b4.build();
    assert_eq!(
        b4.version(),
        format!("agent-vm 0.0.1 ({head_b})\n"),
        "B4 empty commit B changes identity"
    );
    b4.git(&["checkout", "-q", "main"]);
    b4.build();
    assert_eq!(
        b4.version(),
        format!("agent-vm 0.0.1 ({head_a})\n"),
        "B4 branch switch back to A"
    );
    b4.git(&["checkout", "-q", "--detach", "x"]);
    b4.build();
    assert_eq!(
        b4.version(),
        format!("agent-vm 0.0.1 ({head_b})\n"),
        "B4 detached at B"
    );
    b4.pass();

    let mut b6 = Fixture::new("b6");
    fs::write(b6.root.join("outside.txt"), "base\n").expect("write outside");
    b6.commit("c");
    let head = b6.head();
    b6.build();
    fs::write(b6.root.join("outside.txt"), "edited\n").expect("edit outside");
    b6.build();
    assert_eq!(
        b6.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B6 non-crate tracked edit is dirty"
    );
    fs::write(b6.root.join("outside.txt"), "base\n").expect("restore outside");
    b6.build();
    assert_eq!(
        b6.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B6 revert is clean again"
    );
    fs::remove_file(b6.root.join("outside.txt")).expect("delete outside");
    b6.build();
    assert_eq!(
        b6.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B6 deletion is dirty"
    );
    b6.commit("delete");
    let new_head = b6.head();
    b6.build();
    assert_eq!(
        b6.version(),
        format!("agent-vm 0.0.1 ({new_head})\n"),
        "B6 commit with deletion pins new HEAD"
    );
    b6.pass();
}

#[test]
fn b5_packed_refs_and_linked_worktree_invalidate_the_probe() {
    let mut fixture = Fixture::new("b5");
    fixture.commit("c");
    let head = fixture.head();
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B5 baseline clean"
    );
    fixture.git(&["pack-refs", "--all"]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B5 first packing keeps HEAD"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B5 fresh after first packing"
    );
    fixture.git(&[
        "commit",
        "-q",
        "--no-gpg-sign",
        "--allow-empty",
        "-m",
        "loose",
    ]);
    let loose_head = fixture.head();
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({loose_head})\n"),
        "B5 packed terminal to new loose commit"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B5 fresh after new loose commit"
    );
    let loose = fixture.root.join(".git/refs/heads/main");
    fixture.git(&["pack-refs", "--all", "--no-prune"]);
    fixture.build();
    assert!(
        loose.exists() && fixture.version() == format!("agent-vm 0.0.1 ({loose_head})\n"),
        "B5 no-prune retains loose ref and correct HEAD"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B5 fresh after no-prune"
    );
    fixture.git(&["pack-refs", "--all", "--prune"]);
    let output = fixture.build();
    assert!(
        !loose.exists()
            && rebuild_events(&output) != (0, 0)
            && fixture.version() == format!("agent-vm 0.0.1 ({loose_head})\n"),
        "B5 prune independently invalidates and removes loose ref"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B5 fresh after prune"
    );
    fixture.git(&["pack-refs", "--all"]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({loose_head})\n"),
        "B5 repeated packing keeps HEAD"
    );
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B5 fresh after repeated packing"
    );
    let linked_root = fixture.root.with_file_name(format!(
        "{}-linked",
        fixture
            .root
            .file_name()
            .expect("fixture name")
            .to_string_lossy()
    ));
    fixture.git(&[
        "worktree",
        "add",
        "-q",
        "-b",
        "linked",
        linked_root.to_str().expect("UTF-8 linked root"),
    ]);
    let mut linked = fixture.linked(linked_root.clone());
    linked.build();
    assert!(
        linked_root.join(".git").is_file()
            && linked.version() == format!("agent-vm 0.0.1 ({loose_head})\n"),
        "B5 real linked worktree clean"
    );
    linked.git(&[
        "commit",
        "-q",
        "--no-gpg-sign",
        "--allow-empty",
        "-m",
        "linked commit",
    ]);
    let linked_head = linked.head();
    linked.build();
    assert_eq!(
        linked.version(),
        format!("agent-vm 0.0.1 ({linked_head})\n"),
        "B5 linked worktree commit invalidates"
    );
    assert_eq!(
        rebuild_events(&linked.build()),
        (0, 0),
        "B5 linked worktree unchanged fresh"
    );
    linked.pass();
    fixture.pass();
}

#[test]
fn b7_submodule_state_controls_hold() {
    let mut fixture = Fixture::new("b7");
    fs::write(fixture.root.join("top.txt"), "top\n").expect("write top file");
    fixture.commit("top");
    let origin = fixture.root.with_file_name(format!(
        "{}-origin",
        fixture
            .root
            .file_name()
            .expect("fixture name")
            .to_string_lossy()
    ));
    fs::create_dir(&origin).expect("create submodule origin");
    fixture.git_at(&origin, &["init", "-q", "-b", "main"]);
    fs::write(origin.join("sub.txt"), "sub\n").expect("write submodule file");
    fixture.git_at(&origin, &["add", "-A"]);
    fixture.git_at(&origin, &["commit", "-q", "--no-gpg-sign", "-m", "sub"]);
    let origin_head = {
        let output = fixture
            .child(Path::new("git"))
            .current_dir(&origin)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("origin head");
        String::from_utf8(output.stdout)
            .expect("origin head UTF-8")
            .trim()
            .to_owned()
    };
    fixture.git(&[
        "submodule",
        "add",
        "-q",
        origin.to_str().expect("UTF-8 origin"),
        "vendor/sub",
    ]);
    fixture.commit("submodule");
    let head = fixture.head();
    let sub = fixture.root.join("vendor/sub");
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B7 baseline clean with submodule"
    );
    fs::write(sub.join("sub.txt"), "changed\n").expect("edit submodule");
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B7 submodule content edit is dirty"
    );
    fixture.git_at(&sub, &["checkout", "-q", "--", "sub.txt"]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B7 submodule revert is clean"
    );
    fs::write(sub.join("sub.txt"), "staged\n").expect("stage submodule edit");
    fixture.git_at(&sub, &["add", "sub.txt"]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B7 submodule staged edit is dirty"
    );
    fixture.git_at(&sub, &["reset", "-q", "--hard"]);
    fixture.git_at(
        &sub,
        &[
            "commit",
            "-q",
            "--no-gpg-sign",
            "--allow-empty",
            "-m",
            "sub2",
        ],
    );
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head}, dirty)\n"),
        "B7 submodule commit moves gitlink to dirty"
    );
    fixture.git_at(&sub, &["checkout", "-q", "--detach", &origin_head]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B7 submodule ref switch restores clean gitlink"
    );
    fs::write(sub.join("untracked.txt"), "u\n").expect("write untracked submodule file");
    assert_eq!(
        rebuild_events(&fixture.build()),
        (0, 0),
        "B7 default submodule untracked stays fresh"
    );
    let strict = fixture.build_with(&[("AGENT_VM_BUILD_PROVENANCE_STRICT", "1")]);
    assert!(
        rebuild_events(&strict).0 > 0,
        "B7 untracked-submodule measurement executes probe"
    );
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B7 from-clean submodule untracked stays clean"
    );
    fs::remove_file(sub.join("untracked.txt")).expect("remove untracked submodule file");

    let nested_origin = fixture.root.with_file_name(format!(
        "{}-nested-origin",
        fixture
            .root
            .file_name()
            .expect("fixture name")
            .to_string_lossy()
    ));
    fs::create_dir(&nested_origin).expect("create nested origin");
    fixture.git_at(&nested_origin, &["init", "-q", "-b", "main"]);
    fs::write(nested_origin.join("sub.txt"), "nested\n").expect("write nested source");
    fixture.git_at(&nested_origin, &["add", "-A"]);
    fixture.git_at(
        &nested_origin,
        &["commit", "-q", "--no-gpg-sign", "-m", "nested"],
    );
    fixture.git_at(
        &sub,
        &[
            "submodule",
            "add",
            "-q",
            nested_origin.to_str().expect("UTF-8 nested origin"),
            "nested",
        ],
    );
    fixture.git_at(&sub, &["add", "-A"]);
    fixture.git_at(&sub, &["commit", "-q", "--no-gpg-sign", "-m", "nested"]);
    fixture.commit("nested");
    let nested_head = fixture.head();
    let nested = sub.join("nested");
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({nested_head})\n"),
        "B7 nested submodule clean baseline"
    );
    fs::write(nested.join("sub.txt"), "nested dirt\n").expect("edit nested submodule");
    let nested_dirty = fixture.build();
    assert!(
        rebuild_events(&nested_dirty) != (0, 0)
            && fixture.version() == format!("agent-vm 0.0.1 ({nested_head}, dirty)\n"),
        "B7 nested tracked content invalidates"
    );
    fixture.git_at(&nested, &["checkout", "-q", "--", "sub.txt"]);
    fixture.build();
    assert_eq!(
        fixture.version(),
        format!("agent-vm 0.0.1 ({nested_head})\n"),
        "B7 nested restoration clean"
    );
    fs::remove_dir_all(&nested_origin).expect("remove nested origin");
    fs::remove_dir_all(&origin).expect("remove submodule origin");
    fixture.pass();
}

#[test]
fn b8_b10_override_and_unavailable_git_controls_hold() {
    let mut b8 = Fixture::new("b8");
    b8.commit("c");
    let head = b8.head();
    let explicit = "a".repeat(40);
    let github = "b".repeat(40);
    b8.build_with(&[("AGENT_VM_GIT_SHA", &explicit), ("GITHUB_SHA", &github)]);
    assert_eq!(
        b8.version(),
        format!("agent-vm 0.0.1 ({explicit})\n"),
        "B8 explicit override beats GITHUB_SHA and HEAD"
    );
    b8.build_with(&[("GITHUB_SHA", &github)]);
    assert_eq!(
        b8.version(),
        format!("agent-vm 0.0.1 ({github})\n"),
        "B8 GITHUB_SHA beats local HEAD"
    );
    b8.build();
    assert_eq!(
        b8.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B8 no override falls back to HEAD"
    );
    b8.pass();

    let mut b9 = Fixture::new("b9");
    b9.commit("c");
    let head = b9.head();
    let upper = format!("ABCDEF{}", "0".repeat(34));
    b9.build_with(&[("AGENT_VM_GIT_SHA", &upper)]);
    assert_eq!(
        b9.version(),
        format!("agent-vm 0.0.1 ({})\n", upper.to_lowercase()),
        "B9 uppercase override is normalized"
    );
    let full64 = format!("ABCDEF{}", "1".repeat(58));
    b9.build_with(&[("AGENT_VM_GIT_SHA", &full64)]);
    assert_eq!(
        b9.version(),
        format!("agent-vm 0.0.1 ({})\n", full64.to_lowercase()),
        "B9 64-hex override is accepted and normalized"
    );
    for value in [
        "abc123".to_owned(),
        "1".repeat(63),
        "2".repeat(65),
        String::new(),
        "aa\nbb".to_owned(),
        "z".repeat(40),
        "refs/heads/main".to_owned(),
    ] {
        let output = b9.build_with(&[("AGENT_VM_GIT_SHA", &value)]);
        assert!(
            b9.version() == format!("agent-vm 0.0.1 ({head})\n")
                && (value.is_empty() || !provenance_diagnostics(&output).contains(&value)),
            "B9 invalid override falls back without echo: {value:?}"
        );
    }
    let injection = "cargo:rustc-env=AGENT_VM_BUILD_VERSION=evil\n";
    b9.build_with(&[("AGENT_VM_GIT_SHA", injection)]);
    assert_eq!(
        b9.version(),
        format!("agent-vm 0.0.1 ({head})\n"),
        "B9 newline override cannot inject a directive"
    );
    b9.pass();

    let mut b10 = Fixture::new("b10");
    fs::write(b10.root.join("notes.txt"), "a\n").expect("write notes");
    b10.commit("c");
    let override_sha = "c".repeat(40);
    fs::write(b10.root.join("notes.txt"), "b\n").expect("dirty notes");
    b10.build_with(&[("AGENT_VM_GIT_SHA", &override_sha)]);
    assert_eq!(
        b10.version(),
        format!("agent-vm 0.0.1 ({override_sha}, dirty)\n"),
        "B10 override with tracked dirt is dirty"
    );
    b10.git(&["checkout", "-q", "--", "notes.txt"]);
    let fake_bin = b10.root.join("broken-git-bin");
    fs::create_dir(&fake_bin).expect("create fake git directory");
    let fake_git = fake_bin.join("git");
    fs::write(&fake_git, "#!/bin/sh\nexit 127\n").expect("write fake git");
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755))
        .expect("make fake git executable");
    let path = format!("{}:{}", fake_bin.display(), env::var("PATH").expect("PATH"));
    b10.build_with(&[("AGENT_VM_GIT_SHA", &override_sha), ("PATH", &path)]);
    assert_eq!(
        b10.version(),
        format!("agent-vm 0.0.1 ({override_sha}, state unknown)\n"),
        "B10 override with Git unavailable is state unknown"
    );
    b10.pass();
}
