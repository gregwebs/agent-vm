//! Binary-level pins: the non-interactive refusal and what a hand-stamped store
//! makes the product do (#736 V34 and the load half of V43).
//!
//! These rows exist to prove *end to end* what the `--bin` unit rows prove by
//! hand: an unapproved `trust = false` source refuses a real launch, writes no
//! store file, and never prompts; an approved one (stamped by the independent
//! `support::source_pins` oracle, not through the production writer) is read.
//!
//! Isolation is the harness's whole contract: a fresh `$HOME`, a fresh
//! `AGENT_VM_STATE_DIR`, the project under `CARGO_TARGET_TMPDIR` so the guest
//! path is mirrored, and a fake runtime. Nothing here can reach
//! `~/.config/agent-vm` of the developer running the suite.
//!
//! The shared support modules are rebuilt per test crate, so each uses a
//! different subset of them; unused items are expected rather than a defect.
#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Duration,
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

#[path = "support/authority_snapshot.rs"]
mod authority_snapshot;
#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/source_pins.rs"]
mod source_pins;
#[path = "support/mod.rs"]
mod support;

use support::run_with_timeout;

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// One project, one scratch home, one fake runtime.
struct Harness {
    _home: tempfile::TempDir,
    _state: tempfile::TempDir,
    _project: tempfile::TempDir,
    home_root: PathBuf,
    project_root: PathBuf,
    state_root: PathBuf,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = support::project_tempdir();
        let home_root = home.path().canonicalize().unwrap();
        let state_root = state.path().canonicalize().unwrap();
        let project_root = project.path().canonicalize().unwrap();
        let fake_msb = fake_msb::install_pair(home.path(), fake_msb::Mode::StrictAcquisition).path;
        Self {
            _home: home,
            _state: state,
            _project: project,
            home_root,
            project_root,
            state_root,
            fake_msb,
        }
    }

    fn project_config(&self) -> PathBuf {
        support::project_config_path(&self.home_root, &self.project_root)
    }

    fn store_dir(&self) -> PathBuf {
        source_pins::store_dir(&self.home_root, &self.project_root)
    }

    fn write_project(&self, body: &str) {
        let path = self.project_config();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
    }

    /// The repo source every row pins: one tool, so `lint` is a launch verb.
    /// `top_level` precedes the `[[tools]]` table, where top-level keys must be.
    fn write_source(&self, top_level: &str) -> PathBuf {
        let path = self.project_root.join("conf/agent-vm.toml");
        write(
            &path,
            &format!("{top_level}[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n"),
        );
        path
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home_root)
            .env("AGENT_VM_STATE_DIR", &self.state_root)
            .env("MSB_PATH", &self.fake_msb)
            .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
            .stdin(Stdio::null())
            .current_dir(&self.project_root);
        cmd
    }

    /// A launch-shaped invocation with no terminal on any descriptor, exactly a
    /// CI run: stdin is `/dev/null`, both outputs are pipes.
    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = self.base_command();
        cmd.args(args);
        run_with_timeout(cmd, Duration::from_secs(30))
    }

    fn doctor(&self) -> Output {
        self.run(&["doctor"])
    }
}

/// The one-project body the non-interactive rows share. The source declares a
/// tool and `allow_tools` names it, so a *successful* load would list `lint` as
/// a verb: an exit 2 "unrecognized subcommand" can never pass for the refusal.
fn pinned_project(allow: bool) -> String {
    format!(
        "\
         [[sources]]\nname = \"repo\"\npath = \"./conf/agent-vm.toml\"\n{}\
         ",
        if allow { "allow = true\n" } else { "" }
    )
}

/// `crate::one_line::quoted_path`'s rendering for an ASCII path: `"…"`.
fn quoted_path(path: &Path) -> String {
    format!("{:?}", path.display().to_string())
}

/// R8, spelled from the product's documented sentences rather than scraped from
/// its output, so a wording regression fails here.
fn refusal_text(project_config: &Path, source: &Path, current: &str) -> String {
    format!(
        "config: {}: 1 pinned source is not approved for this project:\n\
         \x20 sources[0] repo {}: never approved (current sha256:{current})\n\
         review the change with `agent-vm config diff` and approve it with \
         `agent-vm config approve` (a later release's workflow, not this version's); \
         this version approves only from an eligible launch — a tool verb, `run` or \
         `--`, never `doctor`, help or a built-in — run in this project's interactive \
         terminal\n",
        quoted_path(project_config),
        quoted_path(source)
    )
}

/// `Error: <the refusal>` — the prefix `anyhow`'s `main` return prints.
fn refusal_stderr(project_config: &Path, source: &Path, current: &str) -> String {
    format!("Error: {}", refusal_text(project_config, source, current))
}

#[test]
fn an_unapproved_pinned_source_refuses_every_noninteractive_route() {
    let h = Harness::new();
    let source = h.write_source("");
    h.write_project(&pinned_project(false));
    let current = source_pins::sha256_hex(&std::fs::read(&source).unwrap());
    let expected = refusal_stderr(&h.project_config(), &source, &current);
    let authority = h.home_root.join(".config/agent-vm");
    let before = authority_snapshot::take(&authority);

    // A declared verb, the two direct spellings that must survive a broken
    // catalog, and `doctor` as the built-in that reports the refusal.
    for (argv, code) in [
        (vec!["lint"], 1),
        (vec!["run", "true"], 125),
        (vec!["--", "true"], 125),
        (vec!["doctor"], 1),
    ] {
        let out = h.run(&argv);
        assert_eq!(
            out.status.code(),
            Some(code),
            "agent-vm {argv:?}: {}",
            stderr_of(&out)
        );
        assert_eq!(
            stderr_of(&out),
            expected,
            "agent-vm {argv:?}: the exact R8 refusal"
        );
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("[y/N]"),
            "agent-vm {argv:?}: nothing may prompt"
        );
    }

    assert_eq!(
        authority_snapshot::take(&authority),
        before,
        "the refusal created no pins.json, pins.lock or snapshot"
    );
    assert_eq!(
        source_pins::entries(&h.store_dir()),
        ["config.toml".to_owned()],
        "the refusal created no pins.json, pins.lock or snapshot"
    );
    assert!(
        !h.home_root
            .join(".config/agent-vm/image-pins.json")
            .exists(),
        "no launch began, so no image approval was written either"
    );
}

/// V43's refusal half: `allow = true` does not change the refusal, and the four
/// adoptable facets never reach a launch plan because the load never succeeds.
#[test]
fn an_unapproved_allow_true_source_refuses_before_adopting_anything() {
    let h = Harness::new();
    let source = h.write_source(
        "image = \"localhost:1/repo:latest\"\n\
         mounts = [\"/host:/guest:ro\"]\n\
         [network]\nallow_lan = true\n",
    );
    h.write_project(&pinned_project(true));
    let current = source_pins::sha256_hex(&std::fs::read(&source).unwrap());

    let out = h.run(&["lint"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert_eq!(
        stderr_of(&out),
        refusal_stderr(&h.project_config(), &source, &current)
    );
    // Nothing was adopted, so the declarations never become a plan: the fake
    // runtime saw no invocation and no image approval was recorded.
    let log = h.fake_msb.with_file_name("msb-invocations.log");
    let invocations = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        invocations.lines().all(|line| line == "--version"),
        "no create, mount or egress call reached the runtime: {invocations}"
    );
    assert_eq!(
        source_pins::entries(&h.store_dir()),
        ["config.toml".to_owned()],
        "no approval, no lock, no snapshot"
    );
}

/// V39(c) at binary level: an approved `(false, false)` source whose inert
/// top-level values are malformed loads, stays inert, and renders its pin. A
/// fixture that auto-approved would not prove the pin was *looked up*, so the
/// store is stamped by the oracle and the digest is asserted.
#[test]
fn an_approved_inert_source_with_malformed_values_loads_and_renders_its_pin() {
    let h = Harness::new();
    let source = h.write_source(
        "image = \"localhost:1/inert:latest\"\nnetwork = 42\nmounts = \"bad\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\n",
    );
    h.write_project("[[sources]]\nname = \"repo\"\npath = \"./conf/agent-vm.toml\"\n");
    let hash = source_pins::approve(&h.home_root, &h.project_root, &source);

    let out = h.doctor();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains(&format!(
            "  repo {} (found, 2 tools) [trust=false, allow=false, pin=approved sha256:{hash}; \
             inert: image, mounts, [network]]\n",
            source.display()
        )),
        "{stdout}"
    );
}
