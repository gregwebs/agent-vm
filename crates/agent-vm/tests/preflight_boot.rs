//! Black-box integration tests for the boot-path msb.db preflight guard
//! (`src/msb_preflight.rs`, wired as the first statement of `run::launch`
//! in `src/run.rs`). See issue #30.
//!
//! Mirrors the harness pattern in `doctor_reset.rs` / `msb_passthrough.rs`:
//! spawn the actual compiled `agent-vm` binary with a controlled `HOME` /
//! `AGENT_VM_STATE_DIR` / `MSB_PATH`, exercising the real `main()` prologue
//! end to end. `agent-vm shell` is used as the boot-path entry point; the
//! guard runs before `ProjectSession::for_cwd()`, so cwd validity doesn't
//! matter for the "ahead" case (it must bail before ever reaching that far).

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Fake `msb` that only needs to answer `--version` with the patched-build
/// marker; the preflight guard must bail (ahead case) or fail past it
/// before any real msb invocation happens on the boot path.
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

/// Build a real SQLite file at `path` with a `seaql_migrations` table
/// holding `versions`. Uses sqlx directly (the same fixture approach as
/// `msb_preflight.rs`'s unit tests) so the fixture is independent of the
/// preflight code under test.
fn seed_sqlite_db(path: &Path, versions: &[&str]) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        use sqlx::Row as _;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&url)
            .await
            .expect("connect to fixture db");
        sqlx::query(
            "CREATE TABLE seaql_migrations (version VARCHAR NOT NULL PRIMARY KEY, applied_at BIGINT NOT NULL)",
        )
        .execute(&pool)
        .await
        .expect("create seaql_migrations table");
        for v in versions {
            sqlx::query("INSERT INTO seaql_migrations (version, applied_at) VALUES (?, 0)")
                .bind(*v)
                .execute(&pool)
                .await
                .expect("insert migration row");
        }
        let count: i64 = sqlx::query("SELECT COUNT(*) AS c FROM seaql_migrations")
            .fetch_one(&pool)
            .await
            .expect("count rows")
            .get("c");
        assert_eq!(count as usize, versions.len());
        pool.close().await;
    });
}

/// Run `child` to completion, killing it if it doesn't exit within
/// `timeout`. Mirrors `msb_passthrough.rs`'s helper of the same name.
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

/// Run `child`, but unlike `run_with_timeout`, treat hitting `deadline` as
/// expected rather than a test failure: kill it and return whatever
/// stdout/stderr it produced up to that point. Used for the "proceeds past
/// the guard" case, where what happens next is real boot machinery
/// (sandbox reaping, Sandbox::builder/start) that has no fake/stub in this
/// harness — on some platforms it fails fast (e.g. a short-socket-path
/// error), on others it can block for a long time on hypervisor/network
/// access this test environment doesn't have. Either way, the guard's own
/// behavior (did it print the ahead-db message?) is decided long before
/// that point, so a bounded, always-killed run is sufficient and avoids a
/// platform-dependent hang.
fn run_briefly_then_kill(mut cmd: Command, deadline: Duration) -> Output {
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

    let deadline = Instant::now() + deadline;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break child.wait().expect("wait after kill failed");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Output {
        status,
        stdout: stdout_handle.join().unwrap(),
        stderr: stderr_handle.join().unwrap(),
    }
}

struct Harness {
    #[allow(dead_code)] // kept alive for the tempdir's Drop; HOME points into it
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    fake_msb: PathBuf,
    cwd: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let fake_msb = write_fake_msb(home.path());
        let cwd = tempfile::tempdir().unwrap();
        Self {
            home,
            state,
            fake_msb,
            cwd,
        }
    }

    fn msb_home(&self) -> PathBuf {
        self.state.path().join("msb-home-m20260606_000001")
    }

    fn db_path(&self) -> PathBuf {
        self.msb_home().join("db").join("msb.db")
    }

    fn shell_cmd(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("AGENT_VM_STATE_DIR", self.state.path())
            .env("MSB_PATH", &self.fake_msb)
            .current_dir(self.cwd.path())
            .arg("shell");
        cmd
    }

    fn run_shell(&self) -> Output {
        run_with_timeout(self.shell_cmd(), Duration::from_secs(15))
    }

    /// Like `run_shell`, but for the "proceeds past the guard" case: real
    /// boot machinery beyond the guard has no fake/stub here and its
    /// eventual outcome is platform-dependent (see `run_briefly_then_kill`),
    /// so this always kills the process after a short, bounded window
    /// instead of requiring it to exit.
    fn run_shell_briefly(&self) -> Output {
        run_briefly_then_kill(self.shell_cmd(), Duration::from_secs(3))
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

const FUTURE_MIGRATION: &str = "m29990101_000001_future_thing";
const BUNDLED_MIGRATION: &str = "m20260305_000001_create_image_tables";

#[test]
fn ahead_db_blocks_boot_before_any_vm_work() {
    let h = Harness::new();
    seed_sqlite_db(&h.db_path(), &[BUNDLED_MIGRATION, FUTURE_MIGRATION]);

    let out = h.run_shell();

    assert!(
        !out.status.success(),
        "expected non-zero exit; stderr:\n{}",
        stderr_of(&out)
    );
    let stderr = stderr_of(&out);
    assert!(stderr.contains(FUTURE_MIGRATION), "stderr:\n{stderr}");
    assert!(
        stderr.contains("agent-vm doctor --reset-msb-db"),
        "stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("NEWER than this build"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn behind_or_in_sync_db_proceeds_past_the_guard() {
    let h = Harness::new();
    // Subset of bundled -> behind/in-sync, not ahead.
    seed_sqlite_db(&h.db_path(), &[BUNDLED_MIGRATION]);

    // The guard must not be what stops this run — it should proceed past
    // the preflight into real boot machinery (sandbox reaping, Sandbox
    // builder/start) that this harness has no fake/stub for. What happens
    // next is platform-dependent (fails fast on some platforms, can block
    // on hypervisor/network access on others) and is not what this test is
    // about, so we always kill the process after a short window rather than
    // require it to exit. We only assert the preflight message is absent.
    let out = h.run_shell_briefly();

    let stderr = stderr_of(&out);
    assert!(
        !stderr.contains("NEWER than this build"),
        "guard must not fire for a behind/in-sync db; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("agent-vm doctor --reset-msb-db"),
        "guard must not fire for a behind/in-sync db; stderr:\n{stderr}"
    );
}
