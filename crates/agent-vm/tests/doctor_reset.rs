//! Black-box integration test for `agent-vm doctor --reset-msb-db` (see
//! `src/doctor.rs`).
//!
//! Spawns the actual compiled `agent-vm` binary as a subprocess with a
//! controlled `HOME` / `AGENT_VM_STATE_DIR` / `MSB_PATH`, exercising the
//! real `main()` prologue (`point_at_msb` + `point_at_msb_home`) end to end
//! without needing Hypervisor.framework or an actual VM boot — `doctor` is
//! pure filesystem work dispatched before the tokio runtime, so it
//! completes without touching the network. Mirrors the harness pattern in
//! `msb_cache_share.rs`.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Write a fake `msb` that always reports the patched-build marker,
/// satisfying `point_at_msb`'s `--version` check. Mirrors
/// `msb_cache_share.rs`'s `write_fake_msb` test helper.
fn write_fake_msb(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("msb");
    std::fs::write(
        &path,
        "#!/bin/sh\necho 'msb 0.4.6+agent-vm.phase4'\nexit 0\n",
    )
    .unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

struct Harness {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let fake_msb = write_fake_msb(home.path());
        Self {
            home,
            state,
            fake_msb,
        }
    }

    fn msb_home(&self) -> PathBuf {
        self.state.path().join("msb-home")
    }

    fn db_dir(&self) -> PathBuf {
        self.msb_home().join("db")
    }

    fn run_doctor_reset(&self) -> Output {
        Command::new(agent_vm_bin())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("AGENT_VM_STATE_DIR", self.state.path())
            .env("MSB_PATH", &self.fake_msb)
            .args(["doctor", "--reset-msb-db"])
            .output()
            .expect("failed to run agent-vm doctor --reset-msb-db")
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn resets_an_existing_db_and_reports_repull() {
    let h = Harness::new();
    std::fs::create_dir_all(h.db_dir()).unwrap();
    std::fs::write(h.db_dir().join("msb.db"), b"forward-migrated-schema").unwrap();

    let out = h.run_doctor_reset();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = stdout_of(&out);
    assert!(stdout.contains("Moved microsandbox db aside"));
    assert!(stdout.contains(&h.db_dir().display().to_string()));
    assert!(stdout.contains("re-pulled"));

    assert!(!h.db_dir().exists(), "db/ should be gone");
    let siblings: Vec<_> = std::fs::read_dir(h.msb_home())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("db.reset-"))
        .collect();
    assert_eq!(siblings.len(), 1, "expected exactly one db.reset-* sibling");
}

#[test]
fn is_a_clean_noop_when_no_db_exists() {
    let h = Harness::new();

    let out = h.run_doctor_reset();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = stdout_of(&out);
    assert!(stdout.contains("No microsandbox db"));
    assert!(stdout.contains("nothing was moved"));
    assert!(!h.db_dir().exists());
}
