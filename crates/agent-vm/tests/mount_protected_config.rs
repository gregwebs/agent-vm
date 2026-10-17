//! Boot-free CLI evidence for ADR-0038. No image acquisition or VM boot is successful.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

mod support;

/// Never resolves; only used to drive execution far enough into `launch()` to
/// prove `builder.build()` already ran (its debug JSON dump happens right
/// before the pull, which is what fails here).
const BOGUS_IMAGE: &str = "localhost:1/does-not-exist:latest";

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

#[path = "support/fake_msb.rs"]
mod fake_msb;

/// Run `child` to completion, killing it if it doesn't exit within `timeout`.
/// Reads stdout/stderr on separate threads so a full pipe can't deadlock.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn agent-vm");
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("agent-vm did not exit within {timeout:?} (possible hang)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Output {
        status,
        stdout: stdout_handle.join().unwrap(),
        stderr: stderr_handle.join().unwrap(),
    }
}

/// One isolated `$HOME` + `AGENT_VM_STATE_DIR` + project dir (cwd) + fake
/// `MSB_PATH`.
struct Harness {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    project: tempfile::TempDir,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        // The relay socket lives below the state directory, so keep that one
        // under `/tmp` for the Unix socket-path limit. `$HOME` stays on the
        // workspace filesystem, and the project helper fails fast if
        // `CARGO_TARGET_DIR` pushed the project under a guest tmpfs prefix
        // (where the guest would remap it to `/workspace`).
        let home = tempfile::tempdir_in(support::workspace_tmpdir()).unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = support::project_tempdir();
        let fake_msb = fake_msb::write(home.path());
        Self {
            home,
            state,
            project,
            fake_msb,
        }
    }

    fn home_path(&self) -> PathBuf {
        self.home.path().canonicalize().unwrap()
    }

    fn run_shell(&self, mounts: &[&str]) -> Output {
        self.run_verb("shell", mounts, true, self.project.path())
    }

    fn run_shell_from(&self, mounts: &[&str], project: &Path) -> Output {
        self.run_verb("shell", mounts, true, project)
    }

    fn run_verb(&self, verb: &str, mounts: &[&str], set_home: bool, project: &Path) -> Output {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env(
                "AGENT_VM_STATE_DIR",
                self.state.path().canonicalize().unwrap(),
            )
            .env("MSB_PATH", &self.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .current_dir(project);
        if set_home {
            cmd.env("HOME", self.home.path());
        } else {
            // `--root` is the only mode that reaches `mount::prepare` with no
            // `$HOME` at all (non-root fails earlier, resolving guest
            // identity).
            cmd.arg("--root");
        }
        for mount in mounts {
            cmd.arg("--mount").arg(mount);
        }
        cmd.args(["--no-git", "--image", BOGUS_IMAGE]).arg(verb);
        run_with_timeout(cmd, Duration::from_secs(15))
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Extract the `SandboxConfig` JSON that `AGENT_VM_DEBUG_CONFIG=1` dumps to
/// stderr right after `builder.build()`.
fn debug_config_json(stderr: &str) -> serde_json::Value {
    const MARKER: &str = "[debug] sandbox config JSON: ";
    let idx = stderr
        .find(MARKER)
        .unwrap_or_else(|| panic!("no debug config JSON found in stderr:\n{stderr}"));
    let rest = &stderr[idx + MARKER.len()..];
    serde_json::Deserializer::from_str(rest)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap_or_else(|| panic!("no JSON value found after debug marker in stderr:\n{stderr}"))
        .unwrap_or_else(|e| panic!("debug config JSON failed to parse: {e}\nstderr:\n{stderr}"))
}

/// The `(host, guest, readonly)` triples of a dumped config's `Bind` mounts.
fn bind_mounts(config: &serde_json::Value) -> Vec<(String, String, bool)> {
    config["mounts"]
        .as_array()
        .expect("config.mounts must be an array")
        .iter()
        .filter(|m| m["type"] == "Bind")
        .map(|m| {
            (
                m["host"].as_str().expect("host").to_string(),
                m["guest"].as_str().expect("guest").to_string(),
                m["options"]["readonly"].as_bool().expect("readonly"),
            )
        })
        .collect()
}

/// A rejected plan must leave no session, fork, credential or builder state —
/// the discipline `mount_fork.rs` already pins.
fn assert_no_launch_side_effects(harness: &Harness, stderr: &str) {
    for notice in [
        "[debug] sandbox config JSON:",
        "==> agent-vm-",
        "GitHub repo scope",
        "Initialized fork",
        "Reusing fork",
        "==> Mounting",
    ] {
        assert!(
            !stderr.contains(notice),
            "a rejected plan must not emit {notice:?}: {stderr}"
        );
    }
    let entries = std::fs::read_dir(harness.state.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert!(
        entries.is_empty(),
        "a rejected plan must not create session, fork, credential, or builder state: {entries:?}"
    );
}

fn refused(h: &Harness, out: Output, text: &str) {
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains(text), "{stderr}");
    assert_no_launch_side_effects(h, &stderr);
}
fn reached(out: Output) -> String {
    let stderr = stderr_of(&out);
    assert!(stderr.contains("[debug] sandbox config JSON:"), "{stderr}");
    stderr
}
fn config_dir(h: &Harness) -> PathBuf {
    let dir = h.home_path().join(".config/agent-vm");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
fn hash_project(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    // session.rs::hash_path: first six SHA-256 bytes over the canonical path.
    let path = project.canonicalize().unwrap();
    Sha256::digest(path.as_os_str().as_bytes())[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
#[test]
fn m1_home_without_any_authority_is_refused() {
    let h = Harness::new();
    let out = h.run_shell_from(&[], &h.home_path());
    assert!(stderr_of(&out).contains("project directory"));
    refused(&h, out, "instead of $HOME");
}
#[test]
fn m2_config_roots_refused_but_strict_child_allowed() {
    let h = Harness::new();
    let dir = config_dir(&h);
    for path in [dir.parent().unwrap(), dir.as_path()] {
        refused(&h, h.run_shell_from(&[], path), "launch authority");
    }
    let sub = dir.join("sub");
    std::fs::create_dir(&sub).unwrap();
    reached(h.run_shell_from(&[], &sub));
}
#[test]
fn m3_rw_refused_ro_and_fork_allowed() {
    let h = Harness::new();
    let dir = config_dir(&h);
    let parent = dir.parent().unwrap();
    refused(
        &h,
        h.run_shell(&[&parent.display().to_string()]),
        "read-only (:ro)",
    );
    let text = reached(h.run_shell(&[&format!("{}:/cfg:ro", parent.display())]));
    assert!(
        bind_mounts(&debug_config_json(&text))
            .iter()
            .any(|(host, guest, ro)| Path::new(host) == parent && guest == "/cfg" && *ro)
    );
    let out = h.run_shell(&[&format!("{}:/cfg:fork", dir.display())]);
    assert!(
        stderr_of(&out).contains("Initialized fork"),
        "{}",
        stderr_of(&out)
    );
}
#[test]
fn m4_departing_symlink_protects_external_route() {
    use std::os::unix::fs::symlink;
    let h = Harness::new();
    let ext = h.project.path().join("ext");
    std::fs::create_dir_all(ext.join("config")).unwrap();
    symlink(ext.join("config"), h.home_path().join(".config")).unwrap();
    refused(&h, h.run_shell_from(&[], &ext), "launch authority");
    let unrelated = h.project.path().join("other");
    std::fs::create_dir(&unrelated).unwrap();
    reached(h.run_shell_from(&[], &unrelated));
}
#[test]
fn m5_credentials_only_still_protects_home() {
    let h = Harness::new();
    std::fs::write(config_dir(&h).join("credentials.yaml"), "credentials: []\n").unwrap();
    refused(
        &h,
        h.run_shell_from(&[], &h.home_path()),
        "launch authority",
    );
}
#[test]
fn m6_follow_links_target_is_readonly_and_allowed() {
    use std::os::unix::fs::symlink;
    let h = Harness::new();
    let cfg = config_dir(&h);
    let project = h.home_path().join("code/p");
    let links = project.join("links");
    std::fs::create_dir_all(&links).unwrap();
    symlink(&cfg, links.join("cfg")).unwrap();
    let text = reached(h.run_shell_from(
        &[&format!("{}:/links:follow-links", links.display())],
        &project,
    ));
    assert!(
        bind_mounts(&debug_config_json(&text))
            .iter()
            .any(|(host, _, ro)| Path::new(host) == cfg && *ro)
    );
}
#[test]
fn m7_hard_link_refusal_then_single_link_control() {
    let h = Harness::new();
    let cfg = config_dir(&h).join("config.toml");
    std::fs::write(&cfg, "# no network\n").unwrap();
    let alias = h.project.path().join("cfg.toml");
    std::fs::hard_link(&cfg, &alias).unwrap();
    refused(&h, h.run_shell(&[]), "has 2 hard links");
    std::fs::remove_file(alias).unwrap();
    reached(h.run_shell(&[]));
}
#[test]
fn m8_missing_guest_home_and_state_planting_prevented() {
    use std::os::unix::fs::{MetadataExt, symlink};
    for guest_home in [true, false] {
        let h = Harness::new();
        let hash = hash_project(h.project.path());
        let state = h.state.path().canonicalize().unwrap().join(hash);
        let source = if guest_home {
            state.join("home")
        } else {
            state.clone()
        };
        symlink(source.join(".config"), h.home_path().join(".config")).unwrap();
        let out = h.run_shell(&[]);
        assert!(stderr_of(&out).contains("AGENT_VM_STATE_DIR"));
        refused(&h, out, "does not exist yet");
        let planted = source.join(".config/agent-vm/credentials.yaml");
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(&planted, "credentials: []\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o644)).unwrap();
        let a = std::fs::metadata(&planted).unwrap();
        let b = std::fs::metadata(h.home_path().join(".config/agent-vm/credentials.yaml")).unwrap();
        assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
        let p2 = h.project.path().join("p2");
        std::fs::create_dir(&p2).unwrap();
        reached(h.run_shell_from(&[], &p2));
        let text = stderr_of(&h.run_shell(&[]));
        assert!(text.contains("launch authority"), "{text}");
        assert!(!text.contains("[debug] sandbox config JSON:"));
    }
}
fn relative_run(h: &Harness, project: &Path, state: &Path) -> Output {
    let mut cmd = Command::new(agent_vm_bin());
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", h.home.path())
        .env("AGENT_VM_STATE_DIR", state)
        .env("MSB_PATH", &h.fake_msb)
        .env("AGENT_VM_DEBUG_CONFIG", "1")
        .current_dir(project)
        .args(["--no-git", "--image", BOGUS_IMAGE, "shell"]);
    run_with_timeout(cmd, Duration::from_secs(15))
}
#[test]
fn m9_relative_state_safe_and_exposing() {
    use std::os::unix::fs::symlink;
    for exposing in [false, true] {
        let h = Harness::new();
        let project = h.project.path().join("code/proj");
        std::fs::create_dir_all(&project).unwrap();
        let state = h.project.path().join("rel-state");
        if exposing {
            symlink(
                state.join(hash_project(&project)).join("home/.config"),
                h.home_path().join(".config"),
            )
            .unwrap();
        }
        let out = relative_run(&h, &project, Path::new("../../rel-state"));
        if exposing {
            let text = stderr_of(&out);
            assert!(text.contains("does not exist yet"), "{text}");
            let joined = project
                .canonicalize()
                .unwrap()
                .join("../../rel-state")
                .join(hash_project(&project))
                .join("home");
            assert!(text.contains("guest home bind"), "{text}");
            assert!(
                text.contains(&format!("\"{}\"", joined.display())),
                "{text}"
            );
            assert!(!text.contains("[debug] sandbox config JSON:"));
            assert!(!state.exists());
        } else {
            reached(out);
        }
    }
}
#[test]
fn m10_case_variant_first_launch_never_plants_authority() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let h = Harness::new();
    let probe = h.project.path().join("probe");
    std::fs::create_dir_all(probe.join("abc")).unwrap();
    let a = std::fs::metadata(probe.join("abc")).unwrap();
    if !std::fs::metadata(probe.join("ABC")).is_ok_and(|b| (a.dev(), a.ino()) == (b.dev(), b.ino()))
    {
        eprintln!("SKIPPED M10: filesystem is case-sensitive");
        return;
    }
    // A twelve-hex-digit hash can lack a-f (~0.36%); its upper-case spelling is
    // then the same string, so the case arm is never exercised and the row
    // would pass without testing what it claims. Pick a deterministic candidate
    // whose hash changes under ASCII uppercasing, or skip honestly.
    let Some(project) = (1..=64)
        .map(|i| {
            let candidate = h.project.path().join(format!("case-{i}"));
            std::fs::create_dir(&candidate).unwrap();
            candidate
        })
        .find(|candidate| {
            let hash = hash_project(candidate);
            hash != hash.to_ascii_uppercase()
        })
    else {
        eprintln!("SKIPPED M10: no candidate project hash within 64 has an ASCII letter");
        return;
    };
    let hash = hash_project(&project);
    let upper = hash.to_ascii_uppercase();
    assert_ne!(upper, hash, "the case variant must change the spelling");
    let state = h.state.path().canonicalize().unwrap();
    symlink(
        state.join(&upper).join("home/.config"),
        h.home_path().join(".config"),
    )
    .unwrap();
    for _ in 0..2 {
        refused(&h, h.run_shell_from(&[], &project), "does not exist yet");
    }
    let p2 = h.project.path().join("p2");
    std::fs::create_dir(&p2).unwrap();
    reached(h.run_shell_from(&[], &p2));
    assert!(!state.join(&hash).exists());
    assert_eq!(
        std::fs::metadata(h.home_path().join(".config/agent-vm/credentials.yaml"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    let planted = state
        .join(&hash)
        .join("home/.config/agent-vm/credentials.yaml");
    std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
    std::fs::write(&planted, "credentials: []\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o644)).unwrap();
    let a = std::fs::metadata(planted).unwrap();
    let b = std::fs::metadata(h.home_path().join(".config/agent-vm/credentials.yaml")).unwrap();
    assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
    let text = stderr_of(&h.run_shell_from(&[], &project));
    assert!(text.contains("launch authority"), "{text}");
    assert!(!text.contains("[debug] sandbox config JSON:"));
}
#[test]
fn m11b_root_mode_preserves_raw_non_utf8_authority_home() {
    use std::ffi::OsString;
    use std::os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt, symlink},
    };
    let h = Harness::new();
    let probe = h
        .home_path()
        .join(OsString::from_vec(b"probe-\xff".to_vec()));
    match std::fs::create_dir(&probe) {
        Ok(()) => std::fs::remove_dir(&probe).unwrap(),
        Err(error)
            if error.raw_os_error() == Some(libc::EILSEQ)
                || error.raw_os_error() == Some(libc::EINVAL) =>
        {
            eprintln!("SKIPPED M11b: filesystem rejects invalid-UTF-8 names: {error}");
            return;
        }
        Err(error) => panic!("invalid-UTF-8 filename probe failed unexpectedly: {error}"),
    }
    if !cfg!(target_os = "linux") {
        eprintln!("SKIPPED M11b: Linux-only end-to-end row");
        return;
    }
    let raw_home = h
        .home_path()
        .join(OsString::from_vec(b"home-\xff".to_vec()));
    std::fs::create_dir(&raw_home).unwrap();
    assert!(raw_home.to_str().is_none());
    let link = raw_home.join(".config");
    symlink(h.project.path().join(".config"), &link).unwrap();
    let run = || {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", raw_home.as_os_str())
            .env("AGENT_VM_STATE_DIR", h.state.path())
            .env("MSB_PATH", &h.fake_msb)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .current_dir(h.project.path())
            .args(["--root", "--no-git", "--image", BOGUS_IMAGE, "shell"]);
        run_with_timeout(cmd, Duration::from_secs(15))
    };
    let out = run();
    assert!(stderr_of(&out).contains("project directory"));
    refused(&h, out, "launch authority");
    assert!(
        !h.project
            .path()
            .join(".config/agent-vm/credentials.yaml")
            .exists()
    );
    std::fs::remove_file(&link).unwrap();
    reached(run());
    let file = h.project.path().join(".config/agent-vm/credentials.yaml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "credentials: []\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    symlink(h.project.path().join(".config"), link).unwrap();
    let a = std::fs::metadata(file).unwrap();
    let b = std::fs::metadata(raw_home.join(".config/agent-vm/credentials.yaml")).unwrap();
    assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
    assert_eq!(a.nlink(), 1);
    let text = stderr_of(&run());
    assert!(text.contains("launch authority"), "{text}");
    assert!(!text.contains("[debug] sandbox config JSON:"));
}

#[test]
fn m12_home_launch_refused_with_valid_network_authority() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new();
    let file = h.home_path().join(".config/agent-vm/config.toml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(
        &file,
        include_str!("../../../script/test/fixtures/persisted-network/user-allow-host.toml"),
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(
        file.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let out = h.run_shell_from(&[], &h.home_path());
    assert!(!out.status.success());
    let stderr = stderr_of(&out);
    for (_, expected) in
        include_str!("../../../script/test/fixtures/persisted-network/expected-stderr.tsv")
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .filter(|(row, _)| *row == "PN5")
    {
        assert!(stderr.contains(expected), "{stderr}");
    }
    assert!(!stderr.contains("Egress policy"));
    assert_no_launch_side_effects(&h, &stderr);
}
