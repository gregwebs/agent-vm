//! Black-box integration tests for `agent-vm msb <args...>`
//! (`src/msb_cmd.rs`, wired in `src/main.rs`).
//!
//! Unlike `msb_cmd.rs`'s unit tests — which exercise `Args` parsing via a
//! local `TestCli` mirror and `run_with_path` via its `Option<OsString>`
//! seam, deliberately avoiding process-wide env mutation and a real
//! `main()` — these tests spawn the actual compiled `agent-vm` binary with
//! a controlled `HOME` / `AGENT_VM_STATE_DIR` / `MSB_PATH`, exercising the
//! real `main()` startup path end-to-end: `point_at_msb()`'s `--version`
//! marker check, `point_at_msb_home()` pinning `MSB_HOME`, the pre-runtime
//! `Cmd::Msb` short-circuit, and `msb_cmd::run`'s child spawn — all without
//! needing a real `msb` binary, Hypervisor.framework, or an actual VM boot.
//!
//! The fake `msb` is a shell stub (mirrors `write_fake_msb` in
//! `msb_cache_share.rs` / `msb_install.rs`'s unit tests): it answers a
//! bare `--version` with the patched-build marker (satisfying
//! `point_at_msb()`'s preflight check), and for any other invocation
//! records the args it received and its `$MSB_HOME` to `RECORD_FILE`,
//! prints a distinguishing marker to stdout, and exits with
//! `$FAKE_MSB_EXIT_CODE` (default 0).
//!
//! `msb_ls_inherits_msb_home_from_pinned_environment` is the automated
//! regression test for the actual ticket bug (gregwebs/agent-vm#18): a
//! bundled-`msb` child must see agent-vm's private `MSB_HOME`, not the
//! default `~/.microsandbox`. It is the "fully faithful MSB_HOME
//! assertion" the implementation plan flagged as optional (guarded behind
//! `#[ignore]` + process-wide env mutation) — here it comes for free
//! because each test spawns its own subprocess with its own environment,
//! so no global env mutation or `#[ignore]`/serial gating is needed.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Build a real SQLite file at `path` with a `seaql_migrations` table
/// holding `versions`. Used by the msb.db preflight-guard tests below (see
/// issue #30 / `src/msb_preflight.rs`); independent of the preflight code
/// under test.
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

const FUTURE_MIGRATION: &str = "m29990101_000001_future_thing";
const BUNDLED_MIGRATION: &str = "m20260305_000001_create_image_tables";

/// Write a fake `msb` that:
/// - answers a bare `--version` (exactly one arg) with the patched-build
///   marker, satisfying `point_at_msb()`'s preflight check;
/// - for any other invocation, records the args it received and its
///   `$MSB_HOME` to `$RECORD_FILE` (if set), prints a distinguishing
///   marker to stdout, and exits with `$FAKE_MSB_EXIT_CODE` (default 0).
fn write_fake_msb(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("msb");
    std::fs::write(
        &path,
        r#"#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
    echo 'msb 0.4.6+agent-vm.phase4'
    exit 0
fi
if [ -n "$RECORD_FILE" ]; then
    {
        printf 'MSB_HOME=%s\n' "$MSB_HOME"
        printf 'ARGC=%s\n' "$#"
        i=1
        for a in "$@"; do
            printf 'ARG%s=%s\n' "$i" "$a"
            i=$((i + 1))
        done
    } > "$RECORD_FILE"
fi
printf 'FAKE_MSB_STDOUT_MARKER:%s\n' "$*"
exit "${FAKE_MSB_EXIT_CODE:-0}"
"#,
    )
    .unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// Run `child` to completion, killing it if it doesn't exit within
/// `timeout`. Reads stdout/stderr on separate threads so a full pipe can't
/// deadlock the wait. Mirrors `msb_cache_share.rs`'s helper of the same name.
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

/// One isolated `$HOME` + `AGENT_VM_STATE_DIR` + fake `MSB_PATH`, plus a
/// helper to invoke `agent-vm msb <args>` with a fully-controlled
/// environment (no inherited vars beyond `PATH`).
struct Harness {
    #[allow(dead_code)] // kept alive for the tempdir's Drop; HOME points into it
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    fake_msb: PathBuf,
    record_file: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let fake_msb = write_fake_msb(home.path());
        let record_file = tempfile::tempdir().unwrap();
        Self {
            home,
            state,
            fake_msb,
            record_file,
        }
    }

    fn msb_home(&self) -> PathBuf {
        self.state.path().join("msb-home-m20260606_000001")
    }

    fn legacy_msb_home(&self) -> PathBuf {
        self.state.path().join("msb-home")
    }

    fn record_path(&self) -> PathBuf {
        self.record_file.path().join("record")
    }

    fn db_path(&self) -> PathBuf {
        self.msb_home().join("db").join("msb.db")
    }

    /// Run `agent-vm msb <args>` with `HOME`, `AGENT_VM_STATE_DIR`,
    /// `MSB_PATH`, and `RECORD_FILE` pinned to this harness, plus any extra
    /// env vars (e.g. `FAKE_MSB_EXIT_CODE`). No other env is inherited.
    fn run_msb(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("AGENT_VM_STATE_DIR", self.state.path())
            .env("MSB_PATH", &self.fake_msb)
            .env("RECORD_FILE", self.record_path())
            .arg("msb")
            .args(args);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        run_with_timeout(cmd, Duration::from_secs(15))
    }

    fn read_record(&self) -> String {
        std::fs::read_to_string(self.record_path())
            .unwrap_or_else(|e| panic!("reading {}: {e}", self.record_path().display()))
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The actual ticket bug (gregwebs/agent-vm#18), verified end-to-end: a
/// bundled-`msb` child spawned via `agent-vm msb ...` must see agent-vm's
/// private `MSB_HOME` (`$AGENT_VM_STATE_DIR/msb-home`), not the default
/// `~/.microsandbox`. Without this, `agent-vm msb ls` would report "No
/// sandboxes found" even when agent-vm has sandboxes running.
#[test]
fn msb_ls_inherits_msb_home_from_pinned_environment() {
    let h = Harness::new();
    let out = h.run_msb(&["ls"], &[]);

    assert!(out.status.success(), "stderr:\n{}", stderr_of(&out));
    let record = h.read_record();
    let expected = format!("MSB_HOME={}\n", h.msb_home().display());
    assert!(
        record.starts_with(&expected),
        "child did not see the pinned MSB_HOME; record:\n{record}\nexpected prefix:\n{expected}"
    );
}

/// The binary adopts compatible legacy state before dispatching to its msb
/// child. Image-cache and sandbox markers are deliberately opaque to
/// agent-vm; whole-home rename is what preserves their backend ownership.
#[test]
fn compatible_legacy_adoption_preserves_image_and_sandbox_state_for_child() {
    let h = Harness::new();
    let legacy = h.legacy_msb_home();
    std::fs::create_dir_all(legacy.join("cache/images")).unwrap();
    std::fs::create_dir_all(legacy.join("sandboxes/stale-sandbox")).unwrap();
    std::fs::write(
        legacy.join("cache/images/image-marker"),
        "image stays available",
    )
    .unwrap();
    std::fs::write(
        legacy.join("sandboxes/stale-sandbox/overlay-marker"),
        "sandbox stays discoverable",
    )
    .unwrap();

    let out = h.run_msb(&["ls"], &[]);

    assert!(out.status.success(), "stderr:\n{}", stderr_of(&out));
    assert!(
        h.read_record()
            .starts_with(&format!("MSB_HOME={}\n", h.msb_home().display()))
    );
    assert!(h.msb_home().join("cache/images/image-marker").is_file());
    assert!(
        h.msb_home()
            .join("sandboxes/stale-sandbox/overlay-marker")
            .is_file()
    );
    assert!(
        !legacy.exists(),
        "compatible legacy home must be renamed whole"
    );
}

/// A retained forward-migrated legacy database must not be preflighted as the
/// active home: the child gets a fresh namespace and can still run.
#[test]
fn ahead_legacy_is_retained_while_child_uses_a_fresh_schema_home() {
    let h = Harness::new();
    let legacy_db = h.legacy_msb_home().join("db/msb.db");
    seed_sqlite_db(&legacy_db, &[FUTURE_MIGRATION]);

    let out = h.run_msb(&["ls"], &[]);

    assert!(out.status.success(), "stderr:\n{}", stderr_of(&out));
    assert!(
        h.read_record()
            .starts_with(&format!("MSB_HOME={}\n", h.msb_home().display()))
    );
    assert!(legacy_db.is_file(), "ahead legacy db must be retained");
    assert!(h.msb_home().is_dir(), "fresh active home must be created");
}

/// Shared-cache configuration belongs to the adopted versioned home and does
/// not move the private DB or sandbox namespaces to the external cache.
#[test]
fn adopted_home_writes_shared_cache_config_without_moving_private_state() {
    let h = Harness::new();
    let legacy = h.legacy_msb_home();
    let shared = tempfile::tempdir().unwrap();
    let shared_cache = shared.path().join("cache");
    std::fs::create_dir_all(legacy.join("db")).unwrap();
    std::fs::write(legacy.join("db/private-marker"), "private").unwrap();
    std::fs::create_dir_all(legacy.join("sandboxes/sandbox")).unwrap();

    let out = h.run_msb(
        &["ls"],
        &[
            ("AGENT_VM_SHARE_MSB_CACHE", "1"),
            ("AGENT_VM_MSB_CACHE_DIR", shared_cache.to_str().unwrap()),
        ],
    );

    assert!(out.status.success(), "stderr:\n{}", stderr_of(&out));
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(h.msb_home().join("config.json")).unwrap()).unwrap();
    assert_eq!(config["paths"]["cache"], shared_cache.to_str().unwrap());
    assert!(h.msb_home().join("db/private-marker").is_file());
    assert!(h.msb_home().join("sandboxes/sandbox").is_dir());
    assert!(!shared_cache.join("db").exists());
    assert!(!shared_cache.join("sandboxes").exists());
}

/// Trailing args — including hyphenated flags — must reach the child
/// verbatim and in order, through the real `Cli`/`Cmd::Msb` clap parse
/// (not just the local `TestCli` mirror in `msb_cmd.rs`'s unit tests).
#[test]
fn msb_forwards_trailing_args_verbatim_including_hyphenated_flags() {
    let h = Harness::new();
    let out = h.run_msb(&["status", "--json", "--extra=1"], &[]);

    assert!(out.status.success(), "stderr:\n{}", stderr_of(&out));
    let record = h.read_record();
    assert!(record.contains("ARGC=3"), "record:\n{record}");
    assert!(record.contains("ARG1=status"), "record:\n{record}");
    assert!(record.contains("ARG2=--json"), "record:\n{record}");
    assert!(record.contains("ARG3=--extra=1"), "record:\n{record}");
}

/// Regression test for `#[command(disable_help_flag = true)]`, at the real
/// binary level: `agent-vm msb --help` must reach the fake msb (proven by
/// the stdout marker and the record file), not be intercepted by clap and
/// answered with clap's own help for the `Msb` variant.
#[test]
fn msb_help_flag_reaches_msb_not_clap() {
    let h = Harness::new();
    let out = h.run_msb(&["--help"], &[]);

    assert!(out.status.success(), "stderr:\n{}", stderr_of(&out));
    assert!(
        stdout_of(&out).contains("FAKE_MSB_STDOUT_MARKER:--help"),
        "expected the fake msb's marker in stdout, got:\n{}",
        stdout_of(&out)
    );
    let record = h.read_record();
    assert!(record.contains("ARGC=1"), "record:\n{record}");
    assert!(record.contains("ARG1=--help"), "record:\n{record}");
}

/// A bare `agent-vm msb` (no trailing args) must still dispatch to msb
/// (with zero args, so msb shows its own top-level help), not clap's help
/// for the `Msb` variant.
#[test]
fn msb_no_args_still_dispatches_to_msb() {
    let h = Harness::new();
    let out = h.run_msb(&[], &[]);

    assert!(out.status.success(), "stderr:\n{}", stderr_of(&out));
    let record = h.read_record();
    assert!(record.contains("ARGC=0"), "record:\n{record}");
}

/// The child's exit code becomes agent-vm's own exit code.
#[test]
fn msb_exit_code_propagates_from_child() {
    let h = Harness::new();
    let out = h.run_msb(
        &["definitely-not-a-subcommand"],
        &[("FAKE_MSB_EXIT_CODE", "7")],
    );

    assert_eq!(out.status.code(), Some(7), "stderr:\n{}", stderr_of(&out));
}

/// The preflight guard (issue #30, `src/msb_preflight.rs`) must block the
/// passthrough BEFORE the child msb is spawned when the private db was
/// forward-migrated by a newer microsandbox: exit non-zero, name the
/// offending migration and the `#28` recovery command, and never invoke
/// the fake msb (no record file written).
#[test]
fn msb_ls_blocked_by_ahead_db_before_child_spawns() {
    let h = Harness::new();
    seed_sqlite_db(&h.db_path(), &[BUNDLED_MIGRATION, FUTURE_MIGRATION]);

    let out = h.run_msb(&["ls"], &[]);

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
        !h.record_path().exists(),
        "fake msb must never have been invoked for a blocked run"
    );
}

/// A behind/in-sync db (subset of the bundled migration set) must proceed
/// past the guard unchanged and reach the child msb, exactly like the
/// no-db case already covered above.
#[test]
fn msb_ls_reaches_child_when_db_is_behind_or_in_sync() {
    let h = Harness::new();
    seed_sqlite_db(&h.db_path(), &[BUNDLED_MIGRATION]);

    let out = h.run_msb(&["ls"], &[]);

    assert!(out.status.success(), "stderr:\n{}", stderr_of(&out));
    let record = h.read_record();
    assert!(record.contains("ARG1=ls"), "record:\n{record}");
}
