//! `bin/agent-vm-ccusage` resolves the state root in shell, so it has to apply
//! the launcher's rules itself (#437, ADR-0050): absolute `$HOME`, a refused
//! relative `AGENT_VM_STATE_DIR`, an ignored relative or empty `XDG_STATE_HOME`
//! with a one-line notice. No VM and no network: `npx` is a stub on `PATH` that
//! prints the `CLAUDE_CONFIG_DIR` it was handed, so the test can see which
//! per-project histories were actually selected.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    root: tempfile::TempDir,
    home: PathBuf,
    bin: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let stub = bin.join("npx");
        std::fs::write(
            &stub,
            "#!/bin/sh\nprintf 'npx-ran\\n'\nprintf 'cfg=%s\\n' \"$CLAUDE_CONFIG_DIR\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { root, home, bin }
    }

    /// The wrapper with an isolated environment: absolute `HOME`, the stub
    /// `npx` first on `PATH`, and the fixture as cwd. A test overrides only the
    /// variables it is about.
    fn command(&self) -> Command {
        self.command_with("bash")
    }

    /// [`command`] under a named shell, so macOS's `/bin/bash` (3.2) can be
    /// exercised next to whatever `bash` `PATH` finds.
    fn command_with(&self, shell: &str) -> Command {
        let mut cmd = Command::new(shell);
        cmd.env_clear()
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../bin/agent-vm-ccusage")
                    .canonicalize()
                    .unwrap(),
            )
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("HOME", &self.home)
            .current_dir(self.root.path());
        cmd
    }

    fn run(&self, mut cmd: Command) -> Output {
        cmd.output().expect("bash must be on PATH for this test")
    }

    /// The state root a project's history would live in, with a `claude`
    /// directory the wrapper's `find` has to pick out.
    fn seed_history(&self, state_root: &Path, project: &str) -> PathBuf {
        let claude = state_root.join(project).join("claude");
        std::fs::create_dir_all(&claude).unwrap();
        claude
    }

    fn home_default_root(&self) -> PathBuf {
        self.home.join(".local/state/agent-vm")
    }

    /// The per-project histories the wrapper added, without the two host
    /// histories it always searches (`$HOME/.claude`, `$HOME/.config/claude`).
    fn state_paths(&self, out: &Output) -> Vec<PathBuf> {
        let host = [self.home.join(".claude"), self.home.join(".config/claude")];
        searched_paths(out)
            .into_iter()
            .filter(|path| !host.contains(path))
            .collect()
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The `CLAUDE_CONFIG_DIR` the stub `npx` was handed, split into its entries.
fn searched_paths(out: &Output) -> Vec<PathBuf> {
    let stdout = stdout_of(out);
    let cfg = stdout
        .lines()
        .find_map(|line| line.strip_prefix("cfg="))
        .unwrap_or_else(|| panic!("npx never ran:\n{stdout}"));
    cfg.split(',')
        .filter(|entry| !entry.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// The launcher treats agent-vm's own override as configuration, not a hint: a
/// relative value is an error naming the value and the remedy, and the wrapper
/// must not run `ccusage` against some guessed root instead.
#[test]
fn a_relative_state_dir_is_refused_with_the_remedy() {
    let h = Fixture::new();
    let mut cmd = h.command();
    cmd.env("AGENT_VM_STATE_DIR", "rel-state");
    let out = h.run(cmd);

    assert_eq!(out.status.code(), Some(2), "not a refusal");
    let stderr = stderr_of(&out);
    assert!(stderr.contains("AGENT_VM_STATE_DIR"), "{stderr}");
    assert!(stderr.contains("rel-state"), "{stderr}");
    assert!(stderr.contains("not an absolute path"), "{stderr}");
    assert!(stderr.contains("unset it"), "no remedy named: {stderr}");
    assert!(!stdout_of(&out).contains("npx-ran"), "npx ran: {out:?}");
}

/// Set-but-empty is a refused value, not an unset variable — the launcher
/// refuses it too, so the wrapper must not fall through to the default.
#[test]
fn an_empty_state_dir_is_refused() {
    let h = Fixture::new();
    let mut cmd = h.command();
    cmd.env("AGENT_VM_STATE_DIR", "");
    let out = h.run(cmd);

    assert_eq!(out.status.code(), Some(2), "not a refusal");
    let stderr = stderr_of(&out);
    assert!(stderr.contains("AGENT_VM_STATE_DIR"), "{stderr}");
    assert!(
        stderr.contains("''"),
        "the empty value is not named: {stderr}"
    );
    assert!(!stdout_of(&out).contains("npx-ran"), "npx ran: {out:?}");
}

/// The XDG spec says to ignore an invalid value, so relative and set-but-empty
/// are not errors — but ignoring them changes the root, so one notice names the
/// value and the root used, and the histories searched are the fallback's.
#[test]
fn an_unusable_xdg_state_home_is_ignored_and_the_fallback_is_used() {
    for value in ["rel-xdg", ""] {
        let h = Fixture::new();
        let claude = h.seed_history(&h.home_default_root(), "home-default");
        let mut cmd = h.command();
        cmd.env("XDG_STATE_HOME", value);
        let out = h.run(cmd);

        assert!(
            out.status.success(),
            "not a fallback for {value:?}: {out:?}"
        );
        let stderr = stderr_of(&out);
        assert_eq!(
            stderr.lines().count(),
            1,
            "not one line for {value:?}: {stderr:?}"
        );
        assert!(stderr.contains("ignoring XDG_STATE_HOME"), "{stderr}");
        let fallback = h.home_default_root();
        assert!(
            stderr.contains(&fallback.display().to_string()),
            "the notice does not name the root it used instead: {stderr:?}"
        );
        assert_eq!(
            h.state_paths(&out),
            vec![claude],
            "the fallback root's history is not the one searched"
        );
    }
}

/// A value from the environment is not a chosen string: a newline or an ESC in
/// it must not end the notice's line, add bytes a terminal acts on, or move the
/// terminal.
#[test]
fn a_control_byte_cannot_forge_a_line() {
    let h = Fixture::new();
    for value in ["rel\nFORGED-LINE", "rel\u{1b}[31mFORGED"] {
        let mut cmd = h.command();
        cmd.env("XDG_STATE_HOME", value);
        let out = h.run(cmd);

        assert!(out.status.success(), "{out:?}");
        assert!(
            stdout_of(&out).contains("npx-ran"),
            "npx did not run: {out:?}"
        );
        let stderr = stderr_of(&out);
        assert_eq!(stderr.lines().count(), 1, "not one line: {stderr:?}");
        assert_eq!(
            stderr.matches('\n').count(),
            1,
            "more than the terminating newline: {stderr:?}"
        );
        assert!(
            !stderr.contains('\u{1b}'),
            "a raw ESC reached the terminal: {stderr:?}"
        );
        assert!(
            stderr.contains("FORGED"),
            "the value is not shown: {stderr:?}"
        );
    }
}

/// `$HOME` is the base every fallback is built from, so it gets the launcher's
/// discipline instead of silently producing a cwd-relative root.
#[test]
fn an_unusable_home_is_refused() {
    let h = Fixture::new();
    for (home, expected) in [
        (Some("rel-home"), "is not an absolute path"),
        (Some(""), "is set but empty"),
        (None, "is not set"),
    ] {
        let mut cmd = h.command();
        match home {
            Some(value) => {
                cmd.env("HOME", value);
            }
            None => {
                cmd.env_remove("HOME");
            }
        }
        let out = h.run(cmd);

        assert_eq!(out.status.code(), Some(2), "not a refusal for {home:?}");
        let stderr = stderr_of(&out);
        assert!(stderr.contains("HOME"), "{stderr}");
        assert!(stderr.contains(expected), "{home:?}: {stderr}");
        assert!(!stdout_of(&out).contains("npx-ran"), "npx ran: {out:?}");
    }
}

/// An accepted override is used verbatim (`/agent-vm` appended for
/// `XDG_STATE_HOME`), not merely tolerated: only the selected root's history is
/// searched, the other roots' histories are not, and nothing is announced.
#[test]
fn an_absolute_override_selects_its_own_root_without_a_notice() {
    let h = Fixture::new();
    let override_root = h.root.path().join("state");
    let xdg_root = h.root.path().join("xdg");
    let from_override = h.seed_history(&override_root, "override-project");
    let from_xdg = h.seed_history(&xdg_root.join("agent-vm"), "xdg-project");
    let from_home = h.seed_history(&h.home_default_root(), "home-project");

    let mut cmd = h.command();
    cmd.env("AGENT_VM_STATE_DIR", &override_root);
    let out = h.run(cmd);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stderr_of(&out), "", "unexpected notice");
    assert_eq!(h.state_paths(&out), vec![from_override.clone()]);

    let mut cmd = h.command();
    cmd.env("XDG_STATE_HOME", &xdg_root);
    let out = h.run(cmd);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stderr_of(&out), "", "unexpected notice");
    assert_eq!(h.state_paths(&out), vec![from_xdg]);

    let mut cmd = h.command();
    cmd.env("AGENT_VM_STATE_DIR", &override_root);
    cmd.env("XDG_STATE_HOME", "ignored-because-the-override-wins");
    let out = h.run(cmd);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stderr_of(&out), "", "the unused XDG value was announced");
    let searched = h.state_paths(&out);
    assert_eq!(searched, vec![from_override]);
    assert!(
        !searched.contains(&from_home),
        "the HOME default was searched under an override"
    );
}

/// The comma-skip warning is the wrapper's other measured path: it must stay one
/// line too, since the directory name comes from the filesystem.
#[test]
fn a_skipped_comma_path_cannot_forge_a_line() {
    let h = Fixture::new();
    let override_root = h.root.path().join("state");
    let skipped = override_root.join("hash,co\nmma").join("claude");
    std::fs::create_dir_all(&skipped).unwrap();
    let selected = h.seed_history(&override_root, "kept");

    let mut cmd = h.command();
    cmd.env("AGENT_VM_STATE_DIR", &override_root);
    let out = h.run(cmd);

    assert!(out.status.success(), "{out:?}");
    let stderr = stderr_of(&out);
    assert!(stderr.contains("skipping"), "no warning: {stderr:?}");
    assert_eq!(stderr.lines().count(), 1, "not one line: {stderr:?}");
    assert_eq!(
        stderr.matches('\n').count(),
        1,
        "more than the terminating newline: {stderr:?}"
    );
    assert_eq!(h.state_paths(&out), vec![selected]);
}

/// macOS still ships Bash 3.2 at `/bin/bash`, older than the `bash` a developer
/// is likely to have first on `PATH`; the wrapper's rules must hold there too.
#[test]
fn the_rules_hold_under_the_system_bash() {
    let system_bash = Path::new("/bin/bash");
    if !system_bash.exists() {
        eprintln!("SKIPPED: /bin/bash is not present");
        return;
    }
    let h = Fixture::new();
    let claude = h.seed_history(&h.home_default_root(), "home-default");
    let mut cmd = h.command_with(system_bash.to_str().unwrap());
    cmd.env("XDG_STATE_HOME", "rel\nFORGED-LINE");
    let out = h.run(cmd);

    assert!(out.status.success(), "{out:?}");
    let stderr = stderr_of(&out);
    assert_eq!(stderr.lines().count(), 1, "not one line: {stderr:?}");
    assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
    assert_eq!(h.state_paths(&out), vec![claude]);
}
