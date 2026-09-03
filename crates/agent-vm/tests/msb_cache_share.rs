//! Black-box integration tests for the opt-in shared msb OCI-cache feature
//! (`AGENT_VM_SHARE_MSB_CACHE` / `AGENT_VM_MSB_CACHE_DIR`, see
//! `src/msb_install.rs::point_at_msb_home`).
//!
//! Unlike the unit tests in `msb_install.rs` (which call the pure helpers
//! directly with explicit inputs, deliberately avoiding process-wide env
//! mutation), these tests spawn the actual compiled `agent-vm` binary as a
//! subprocess with a controlled `HOME` / `AGENT_VM_STATE_DIR` / `MSB_PATH`.
//! That exercises the real `main()` startup path end-to-end — including the
//! real vendored `microsandbox` SDK reading the `config.json` this feature
//! writes — without needing Hypervisor.framework or an actual VM boot: the
//! `setup --no-verify` subcommand fails during the (network) image pull,
//! which happens well after `point_at_msb_home()` has already run and
//! (when opted in) already initialized the shared cache directory. That
//! failure is expected and is not what these tests assert on; the
//! filesystem side effects of `point_at_msb_home()` are.
//!
//! `localhost:1` is used as a deliberately-bogus registry: connecting to
//! port 1 on loopback fails immediately (`ECONNREFUSED`) with no DNS or
//! external network required, so these tests are hermetic and fast.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

/// A bogus-but-well-formed image ref. Never resolves; only used to drive
/// execution far enough into `setup::run` to prove `point_at_msb_home()`
/// already ran (its side effects happen in `main()`, before any of this).
const BOGUS_IMAGE: &str = "localhost:1/does-not-exist:latest";

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Write a fake `msb` that always reports the official version this
/// agent-vm build vendors, satisfying `point_at_msb`'s `--version` check
/// regardless of subcommand or args. Mirrors `msb_install.rs`'s
/// `write_fake_msb` test helper.
fn write_fake_msb(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("msb");
    std::fs::write(&path, "#!/bin/sh\necho 'msb 0.6.15'\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

/// Run `child` to completion, killing it if it doesn't exit within
/// `timeout`. Reads stdout/stderr on separate threads so a full pipe can't
/// deadlock the wait.
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
/// helper to invoke `agent-vm setup --no-verify` against the bogus image
/// with a fully-controlled environment (no inherited vars beyond `PATH`).
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

    fn config_json(&self) -> PathBuf {
        self.msb_home().join("config.json")
    }

    /// Run `agent-vm setup --no-verify --image <bogus>` with `HOME` and
    /// `AGENT_VM_STATE_DIR` pinned to this harness's tempdirs, `MSB_PATH`
    /// pinned to the fake patched msb, plus any extra env vars (e.g. the
    /// feature flag under test). No other env is inherited.
    fn run_setup(&self, extra_env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("AGENT_VM_STATE_DIR", self.state.path())
            .env("MSB_PATH", &self.fake_msb)
            .args(["setup", "--no-verify", "--image", BOGUS_IMAGE]);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        run_with_timeout(cmd, Duration::from_secs(15))
    }

    fn read_config_json(&self) -> serde_json::Value {
        let bytes = std::fs::read(self.config_json())
            .unwrap_or_else(|e| panic!("reading {}: {e}", self.config_json().display()));
        serde_json::from_slice(&bytes).expect("config.json should be valid JSON")
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn default_off_never_writes_config_json() {
    let h = Harness::new();
    h.run_setup(&[]);
    assert!(
        !h.config_json().exists(),
        "config.json must not exist when AGENT_VM_SHARE_MSB_CACHE is unset"
    );
    // msb-home itself must still have been created (unrelated existing behavior).
    assert!(h.msb_home().is_dir());
}

#[test]
fn opt_in_writes_expected_config_and_shares_default_location() {
    let h = Harness::new();
    h.run_setup(&[("AGENT_VM_SHARE_MSB_CACHE", "1")]);

    let doc = h.read_config_json();
    let expected_cache = h.home.path().join(".microsandbox").join("cache");
    assert_eq!(
        doc["paths"]["cache"],
        serde_json::Value::String(expected_cache.to_str().unwrap().to_string())
    );

    // Our own code (write_shared_cache_config) create_dir_all's the shared
    // cache dir itself, independent of the SDK, so this must exist even
    // though the subsequent network pull fails.
    assert!(
        expected_cache.is_dir(),
        "shared cache dir should have been created at {}",
        expected_cache.display()
    );

    // Private state must not have moved into the shared HOME.
    assert!(
        !h.home.path().join(".microsandbox").join("db").exists(),
        "db/ must stay under agent-vm's private MSB_HOME, not the shared HOME"
    );
}

/// End-to-end proof (issue #65) that the widened `env_flag` truthy set
/// reaches the real binary through `point_at_msb_home`: `On` was a no-op
/// before this change (`msb_install`'s old `parse_flag` only accepted
/// `1`/`true`) and now opts the user in, same as `"1"` above.
#[test]
fn opt_in_accepts_the_shared_truthy_set() {
    let h = Harness::new();
    h.run_setup(&[("AGENT_VM_SHARE_MSB_CACHE", "On")]);

    let doc = h.read_config_json();
    let expected_cache = h.home.path().join(".microsandbox").join("cache");
    assert_eq!(
        doc["paths"]["cache"],
        serde_json::Value::String(expected_cache.to_str().unwrap().to_string())
    );
}

#[test]
fn override_env_var_wins_and_default_location_untouched() {
    let h = Harness::new();
    let override_dir = tempfile::tempdir().unwrap();
    let override_cache = override_dir.path().join("shared-cache");

    h.run_setup(&[
        ("AGENT_VM_SHARE_MSB_CACHE", "1"),
        ("AGENT_VM_MSB_CACHE_DIR", override_cache.to_str().unwrap()),
    ]);

    let doc = h.read_config_json();
    assert_eq!(
        doc["paths"]["cache"],
        serde_json::Value::String(override_cache.to_str().unwrap().to_string())
    );
    assert!(override_cache.is_dir());
    assert!(
        !h.home.path().join(".microsandbox").exists(),
        "default ~/.microsandbox must not be touched when an override dir is given"
    );
}

#[test]
fn opt_in_is_idempotent_across_separate_process_runs() {
    let h = Harness::new();
    h.run_setup(&[("AGENT_VM_SHARE_MSB_CACHE", "1")]);
    let first = std::fs::read(h.config_json()).unwrap();

    h.run_setup(&[("AGENT_VM_SHARE_MSB_CACHE", "1")]);
    let second = std::fs::read(h.config_json()).unwrap();

    assert_eq!(
        first, second,
        "re-running the opt-in flow in a fresh process must produce byte-identical config.json"
    );
}

#[test]
fn unsetting_the_flag_does_not_revert_a_previously_shared_config() {
    let h = Harness::new();
    h.run_setup(&[("AGENT_VM_SHARE_MSB_CACHE", "1")]);
    let opted_in = std::fs::read(h.config_json()).unwrap();

    // Flag-off run: per the plan's "option (a)" decision, this must never
    // read or write config.json, so the stale shared-cache pointer survives.
    h.run_setup(&[]);
    let after_flag_off = std::fs::read(h.config_json()).unwrap();

    assert_eq!(
        opted_in, after_flag_off,
        "flag-off run must leave a previously-written config.json untouched (manual revert only)"
    );
}

#[test]
fn flag_off_tolerates_a_malformed_preexisting_config_json() {
    let h = Harness::new();
    std::fs::create_dir_all(h.msb_home()).unwrap();
    std::fs::write(h.config_json(), "{").unwrap();

    let out = h.run_setup(&[]);

    // Our code path never touches config.json when the flag is off, so it
    // must not be the source of any failure here (the run still fails
    // downstream on the bogus network pull, which is expected and ignored).
    let err = stderr_of(&out);
    assert!(
        !err.contains("fix or remove"),
        "flag-off run must not attempt to parse config.json at all; stderr:\n{err}"
    );
    assert_eq!(std::fs::read_to_string(h.config_json()).unwrap(), "{");
}

#[test]
fn opt_in_refuses_to_clobber_a_malformed_preexisting_config_json() {
    let h = Harness::new();
    std::fs::create_dir_all(h.msb_home()).unwrap();
    std::fs::write(h.config_json(), "{").unwrap();

    let out = h.run_setup(&[("AGENT_VM_SHARE_MSB_CACHE", "1")]);

    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(
        err.contains("fix or remove"),
        "expected the malformed-config hint in stderr:\n{err}"
    );
    assert_eq!(
        std::fs::read_to_string(h.config_json()).unwrap(),
        "{",
        "malformed config.json must be left byte-for-byte untouched, not clobbered"
    );
    // The shared cache dir must not have been created either: the write
    // helper errors out before create_dir_all when the read/parse fails.
    assert!(!h.home.path().join(".microsandbox").exists());
}

#[test]
fn opt_in_merges_into_an_existing_valid_config_without_dropping_keys() {
    let h = Harness::new();
    std::fs::create_dir_all(h.msb_home()).unwrap();
    std::fs::write(
        h.config_json(),
        r#"{"log_level":"debug","paths":{"msb":"/custom/msb"}}"#,
    )
    .unwrap();

    h.run_setup(&[("AGENT_VM_SHARE_MSB_CACHE", "1")]);

    let doc = h.read_config_json();
    assert_eq!(doc["log_level"], serde_json::Value::String("debug".into()));
    assert_eq!(
        doc["paths"]["msb"],
        serde_json::Value::String("/custom/msb".into())
    );
    let expected_cache = h.home.path().join(".microsandbox").join("cache");
    assert_eq!(
        doc["paths"]["cache"],
        serde_json::Value::String(expected_cache.to_str().unwrap().to_string())
    );
}

#[test]
fn opt_in_without_home_or_override_aborts_with_actionable_error() {
    let h = Harness::new();
    let mut cmd = Command::new(agent_vm_bin());
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        // Deliberately no HOME.
        .env("AGENT_VM_STATE_DIR", h.state.path())
        .env("MSB_PATH", &h.fake_msb)
        .env("AGENT_VM_SHARE_MSB_CACHE", "1")
        .args(["setup", "--no-verify", "--image", BOGUS_IMAGE]);
    let out = run_with_timeout(cmd, Duration::from_secs(15));

    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("AGENT_VM_SHARE_MSB_CACHE"), "stderr:\n{err}");
    assert!(err.contains("AGENT_VM_MSB_CACHE_DIR"), "stderr:\n{err}");
    assert!(
        !h.config_json().exists(),
        "no config.json should be written when resolution fails before the write step"
    );
}
