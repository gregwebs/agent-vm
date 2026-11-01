//! Black-box coverage for the hidden interceptor command's stdin/stdout boundary.

use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt as _},
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

/// Wall-clock ceiling for one hook invocation *in this harness*. The production
/// handler budget is 90 s and no scenario here legitimately needs 10 s, so the
/// ceiling turns a production hang into a failed test with a diagnostic instead
/// of a hung CI job.
const HOOK_WATCHDOG: Duration = Duration::from_secs(60);
/// How long a pipe collector may keep waiting for EOF after the hook has
/// exited. A descendant holding either pipe is a **failure**, not a wait: the
/// hook kills its own children, so a pipe it did not close means one outlived
/// it, and returning that output anyway would hide the leak.
const HOOK_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Run one `agent-vm _intercept-hook` invocation under a watchdog.
fn run_hook_bounded(command: Command, request: &[u8]) -> Output {
    wait_bounded(command, request, HOOK_WATCHDOG)
}

/// [`run_hook_bounded`]'s body, with the ceiling injectable so the watchdog's own
/// failure path is testable without waiting a minute.
fn wait_bounded(mut command: Command, request: &[u8], watchdog: Duration) -> Output {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own process group, so one kill reaches the hook and anything that
        // stayed in its group.
        //
        // What it does *not* reach are the hook's own host-CLI children: they
        // `setpgid` into groups of their own so the hook can kill them one by
        // one, which is exactly what makes them unreachable from here. While the
        // hook is alive they are bounded by its deadlines (2 s hook keychain,
        // 45 s vendor CLI) and it kills them; if the hook is killed first, they
        // outlive it by at most that same deadline. The timeout path below says
        // so in its diagnostic instead of pretending the kill was total.
        .process_group(0);
    let mut child = command.spawn().expect("spawn agent-vm _intercept-hook");
    let pid = child.id() as libc::pid_t;
    child
        .stdin
        .take()
        .expect("the hook's stdin is piped")
        .write_all(request)
        .expect("write the hook request");
    let stdout = collect(child.stdout.take().expect("stdout is piped"));
    let stderr = collect(child.stderr.take().expect("stderr is piped"));
    let start = Instant::now();
    let status = loop {
        match child.try_wait().expect("wait for agent-vm _intercept-hook") {
            Some(status) => break status,
            None if start.elapsed() >= watchdog => {
                let elapsed = start.elapsed();
                kill_group(pid, &mut child);
                // The kill closes every pipe the hook itself held. A pipe that
                // stays open afterwards belongs to a host-CLI grandchild in its
                // own process group — unreachable here — so name it rather than
                // silently abandoning a blocked collector thread.
                let mut held = Vec::new();
                for (which, received) in [("stdout", &stdout), ("stderr", &stderr)] {
                    if received.recv_timeout(HOOK_DRAIN_GRACE).is_err() {
                        held.push(which);
                    }
                }
                let escaped = if held.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; {} still held by a descendant in its own process group",
                        held.join(" and ")
                    )
                };
                panic!(
                    "agent-vm _intercept-hook did not exit within {watchdog:?} \
                     (elapsed {elapsed:?}); its process group was killed{escaped}"
                );
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    Output {
        status,
        stdout: finish(stdout, pid, &mut child, "stdout"),
        stderr: finish(stderr, pid, &mut child, "stderr"),
    }
}

/// Drain one pipe on its own thread, so neither pipe can block the wait above.
fn collect(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (sent, received) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        let _ = sent.send(bytes);
    });
    received
}

fn finish(
    received: mpsc::Receiver<Vec<u8>>,
    pid: libc::pid_t,
    child: &mut Child,
    which: &str,
) -> Vec<u8> {
    if let Ok(bytes) = received.recv_timeout(HOOK_DRAIN_GRACE) {
        return bytes;
    }
    // The hook is gone but something still holds the pipe, which the constant's
    // doc calls a failure. Kill whatever is left of the group so the collector
    // can end, then fail either way: returning the bytes would report a run whose
    // output was cut short as a healthy one, and that is the state this harness
    // exists to catch.
    kill_group(pid, child);
    let drained = received.recv_timeout(HOOK_DRAIN_GRACE).is_ok();
    panic!(
        "agent-vm _intercept-hook exited but a descendant held {which} for longer \
         than {HOOK_DRAIN_GRACE:?} (collector finished only after the group kill: \
         {drained}); the output of such a run is not returned"
    )
}

fn kill_group(pid: libc::pid_t, child: &mut Child) {
    unsafe {
        let _ = libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn run_hook(sni: &str, request: &[u8]) -> Output {
    let state = tempfile::tempdir().expect("create isolated hook state");
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
    command
        .args([
            "_intercept-hook",
            "--state-dir",
            state.path().to_str().unwrap(),
        ])
        .env("MSB_INTERCEPT_SNI", sni);
    run_hook_bounded(command, request)
}

/// F07: the watchdog has to turn a nonterminating child into a *failed* test
/// with a diagnostic, not a hung one, and it must leave no descendant behind.
/// The panic is caught so the marker can be checked after it: this assertion is
/// the reason the whole harness can be trusted to fail rather than hang.
#[test]
fn the_watchdog_fails_a_nonterminating_child_instead_of_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("finished");
    let script = dir.path().join("nonterminating");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n(sleep 2; touch '{}') &\nexec /bin/sleep 300\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let start = Instant::now();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_bounded(Command::new(&script), b"", Duration::from_millis(500))
    }));
    let message = match outcome {
        Ok(_) => panic!("the watchdog must not return a successful output"),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
            .expect("the harness panic carries a diagnostic"),
    };
    assert!(
        message.contains("did not exit within"),
        "diagnostic was {message:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "the watchdog took {:?}",
        start.elapsed()
    );
    // The descendant would touch this 2 s after spawn; give it the chance and
    // then require it to be gone.
    std::thread::sleep(Duration::from_secs(3).saturating_sub(start.elapsed()));
    assert!(
        !marker.exists(),
        "the watchdog must kill the group, not just stop waiting"
    );
}

/// N10: the drain grace documents "a descendant holding either pipe is a
/// failure, not a wait". So a hook that exits while a descendant still holds a
/// pipe must fail the test — even though the kill then lets the collector finish
/// and the output would look complete. Returning it would report a truncated run
/// as a healthy one.
#[test]
fn a_descendant_holding_a_pipe_fails_instead_of_truncating_the_output() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("finished");
    let script = dir.path().join("leaky");
    // The first descendant holds stderr open for far longer than the grace (and
    // closes stdout, so only stderr is diagnostic-worthy). The second one is
    // scheduled to touch its marker *after* the grace must have expired, so the
    // marker can only exist if the failure path did not kill the group.
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n( exec 1>/dev/null; sleep 60 ) &\n\
             ( exec 1>/dev/null 2>/dev/null; sleep 6; touch '{}' ) &\nexit 0\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let start = Instant::now();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_bounded(Command::new(&script), b"", Duration::from_secs(30))
    }));
    let message = match outcome {
        Ok(_) => panic!("a held pipe must fail the harness, not return its output"),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
            .expect("the harness panic carries a diagnostic"),
    };
    assert!(
        message.contains("a descendant held stderr"),
        "diagnostic was {message:?}"
    );
    assert!(
        message.contains("collector finished only after the group kill: true"),
        "the diagnostic must say the kill is what ended the drain: {message:?}"
    );
    std::thread::sleep(Duration::from_secs(7).saturating_sub(start.elapsed()));
    assert!(
        !marker.exists(),
        "the failure path must still kill the descendants it can reach"
    );
}

#[test]
fn hidden_hook_rejects_oauth_prefix_lookalike_without_exposing_a_token() {
    let output = run_hook("platform.claude.com", b"POST /v1/oauth/token?ignored=1 HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Length: 0\r\n\r\n");
    assert!(output.status.success());
    let response = String::from_utf8(output.stdout).unwrap();
    assert!(response.starts_with("HTTP/1.1 403"));
    assert!(!response.to_ascii_lowercase().contains("access_token"));
    assert!(!response.to_ascii_lowercase().contains("bearer"));
}

#[test]
fn hidden_hook_denies_off_list_github_before_any_authenticated_forward() {
    let output = run_hook(
        "api.github.com",
        b"GET /repos/not-allowed/project HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
    );
    assert!(output.status.success());
    let response = String::from_utf8(output.stdout).unwrap();
    assert!(response.starts_with("HTTP/1.1 403"));
    assert!(!response.to_ascii_lowercase().contains("authorization:"));
    assert!(!response.to_ascii_lowercase().contains("bearer"));
}

#[test]
fn hidden_hook_rejects_invalid_oauth_before_host_cli_lock_or_token_file() {
    let home = tempfile::tempdir().unwrap();
    let state_parent = tempfile::tempdir().unwrap();
    let state = state_parent.path().join("project");
    let marker = home.path().join("host-cli-was-run");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let codex = bin.join("codex");
    fs::write(&codex, format!("#!/bin/sh\\ntouch {}\\n", marker.display())).unwrap();
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o755)).unwrap();
    let request = b"POST /oauth/token?not-allowed HTTP/1.1\r\nHost: auth.openai.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n";
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
    command
        .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
        .env("MSB_INTERCEPT_SNI", "auth.openai.com")
        .env("HOME", home.path())
        .env("PATH", &bin);
    let output = run_hook_bounded(command, request);
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("HTTP/1.1 403")
    );
    assert!(!marker.exists());
    let secrets = state_parent.path().join("project.secrets");
    assert!(!secrets.join("openai.refresh.lock").exists());
    assert!(!secrets.join("openai").exists());
}

fn write_executable(path: &Path) {
    fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn run_positive(provider: &str, sni: &str, request: String, bearer: &str) -> Output {
    let home = tempfile::tempdir().unwrap();
    let state_parent = tempfile::tempdir().unwrap();
    let state = state_parent.path().join("project");
    fs::create_dir_all(&state).unwrap();
    let bin = home.path().join("bin");
    fs::create_dir(&bin).unwrap();
    write_executable(&bin.join(if provider == "anthropic" {
        "claude"
    } else {
        "codex"
    }));
    if provider == "anthropic" {
        let dir = home.path().join(".claude");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join(".credentials.json"), format!(r#"{{"claudeAiOauth":{{"accessToken":"{bearer}","expiresAt":9999999999000,"scopes":["user:inference"]}}}}"#)).unwrap();
    } else {
        let dir = home.path().join(".codex");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("auth.json"),
            format!(r#"{{"tokens":{{"access_token":"{bearer}"}}}}"#),
        )
        .unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
    command
        .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
        .env("MSB_INTERCEPT_SNI", sni)
        .env("HOME", home.path())
        .env("PATH", &bin);
    let output = run_hook_bounded(command, request.as_bytes());
    let token = state_parent.path().join("project.secrets").join(provider);
    assert!(!token.starts_with(&state));
    assert_eq!(fs::read_to_string(&token).unwrap(), bearer);
    assert_eq!(
        fs::metadata(&token).unwrap().permissions().mode() & 0o777,
        0o600
    );
    output
}

#[test]
fn hidden_hook_anthropic_pipeline_writes_host_only_bearer_and_returns_placeholder() {
    let bearer = "ANTHROPIC_REAL_CANARY";
    let body = r#"{"grant_type":"refresh_token","refresh_token":"msb-anthropic-placeholder-r-v2"}"#;
    let request = format!(
        "POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let output = run_positive("anthropic", "platform.claude.com", request, bearer);
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("HTTP/1.1 200"));
    assert!(stdout.contains("msb-anthropic-placeholder-a-v2"));
    assert!(!stdout.contains(bearer));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(bearer));
}

#[test]
fn hidden_hook_openai_pipeline_writes_host_only_bearer_and_returns_placeholder() {
    let bearer = "OPENAI_REAL_CANARY";
    let body = "grant_type=refresh_token&refresh_token=msb-openai-placeholder-r-v2";
    let request = format!(
        "POST /oauth/token HTTP/1.1\r\nHost: auth.openai.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let output = run_positive("openai", "auth.openai.com", request, bearer);
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("HTTP/1.1 200"));
    assert!(stdout.contains("msb-openai-placeholder-a-v2"));
    assert!(!stdout.contains(bearer));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(bearer));
}

/// Builds an isolated HOME/PATH/state-dir hook invocation whose only host
/// CLI (`claude` or `codex`, matching `provider`) touches a marker file if
/// it is ever spawned. `home_setup` seeds (or deliberately omits) the host
/// credential file before the hook runs. Used to prove — through the real
/// binary's argument parsing, process boundary, and actual file paths, not
/// just an in-process unit call — that a validated request whose host
/// credential is unavailable gets a typed 503 without ever spawning the
/// noninteractive host CLI (issue #55's fail-closed contract).
fn run_unavailable(
    provider: &str,
    sni: &str,
    request: String,
    home_setup: impl FnOnce(&Path),
) -> Output {
    let home = tempfile::tempdir().unwrap();
    let state_parent = tempfile::tempdir().unwrap();
    let state = state_parent.path().join("project");
    let bin = home.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let marker = home.path().join("host-cli-was-run");
    let cli_name = if provider == "anthropic" {
        "claude"
    } else {
        "codex"
    };
    fs::write(
        bin.join(cli_name),
        format!("#!/bin/sh\ntouch {}\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(bin.join(cli_name), fs::Permissions::from_mode(0o755)).unwrap();
    home_setup(home.path());
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
    command
        .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
        .env("MSB_INTERCEPT_SNI", sni)
        .env("HOME", home.path())
        .env("PATH", &bin);
    let output = run_hook_bounded(command, request.as_bytes());
    assert!(
        !marker.exists(),
        "an unavailable host credential must never spawn the noninteractive host CLI"
    );
    output
}

fn assert_typed_503(output: &Output, relogin_command: &str) {
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.starts_with("HTTP/1.1 503"), "{stdout}");
    assert!(stdout.contains("\"temporarily_unavailable\""));
    assert!(stdout.contains(relogin_command));
    let lower = stdout.to_ascii_lowercase();
    assert!(!lower.contains("access_token"));
    assert!(!lower.contains("bearer"));
    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("bearer")
    );
}

fn anthropic_refresh_request() -> String {
    let body = r#"{"grant_type":"refresh_token","refresh_token":"msb-anthropic-placeholder-r-v2"}"#;
    format!(
        "POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn openai_refresh_request() -> String {
    let body = "grant_type=refresh_token&refresh_token=msb-openai-placeholder-r-v2";
    format!(
        "POST /oauth/token HTTP/1.1\r\nHost: auth.openai.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn hidden_hook_missing_anthropic_credentials_returns_typed_503_without_spawning_host_cli() {
    let output = run_unavailable(
        "anthropic",
        "platform.claude.com",
        anthropic_refresh_request(),
        |_home| {}, // no ~/.claude directory at all
    );
    assert_typed_503(&output, "claude login");
}

#[test]
fn hidden_hook_malformed_anthropic_credentials_returns_typed_503_without_spawning_host_cli() {
    let output = run_unavailable(
        "anthropic",
        "platform.claude.com",
        anthropic_refresh_request(),
        |home| {
            let dir = home.join(".claude");
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join(".credentials.json"), "not valid json {{{").unwrap();
        },
    );
    assert_typed_503(&output, "claude login");
}

#[test]
fn hidden_hook_missing_openai_credentials_returns_typed_503_without_spawning_host_cli() {
    let output = run_unavailable(
        "openai",
        "auth.openai.com",
        openai_refresh_request(),
        |_home| {}, // no ~/.codex directory at all
    );
    assert_typed_503(&output, "codex login");
}

#[test]
fn hidden_hook_malformed_openai_credentials_returns_typed_503_without_spawning_host_cli() {
    let output = run_unavailable(
        "openai",
        "auth.openai.com",
        openai_refresh_request(),
        |home| {
            let dir = home.join(".codex");
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("auth.json"), "{{{not json").unwrap();
        },
    );
    assert_typed_503(&output, "codex login");
}

/// End-to-end proof of the rotation state machine through the real
/// subprocess tree (test harness -> `agent-vm _intercept-hook` -> the fake
/// `claude` CLI it spawns): a near-expiry host credential is due for
/// rotation, the bounded host CLI actually runs (not just an injected
/// closure) and rewrites the host credential file, and the hook re-reads
/// and installs the fresh bearer into the host-only sibling secrets file —
/// never the guest-visible response — while the stale bearer is never
/// served.
#[test]
fn hidden_hook_due_anthropic_credential_rotates_through_real_host_cli_and_installs_fresh_bearer() {
    let home = tempfile::tempdir().unwrap();
    let state_parent = tempfile::tempdir().unwrap();
    let state = state_parent.path().join("project");
    fs::create_dir_all(&state).unwrap();
    let bin = home.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let marker = home.path().join("host-cli-was-run");
    let claude_dir = home.path().join(".claude");
    fs::create_dir(&claude_dir).unwrap();
    let creds_path = claude_dir.join(".credentials.json");

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let expiring_ms = now_ms + 60_000; // 60s left: due for rotation (<=600s margin)
    fs::write(
        &creds_path,
        format!(
            r#"{{"claudeAiOauth":{{"accessToken":"OLD_NEAR_EXPIRY_CANARY","expiresAt":{expiring_ms},"scopes":["user:inference"]}}}}"#
        ),
    )
    .unwrap();
    let fresh_ms = now_ms + 3_600_000;
    let script = format!(
        "#!/bin/sh\ntouch {marker}\ncat > {creds} <<INNER\n{{\"claudeAiOauth\":{{\"accessToken\":\"FRESH_ROTATED_CANARY\",\"expiresAt\":{fresh_ms},\"scopes\":[\"user:inference\"]}}}}\nINNER\nexit 0\n",
        marker = marker.display(),
        creds = creds_path.display(),
    );
    fs::write(bin.join("claude"), script).unwrap();
    fs::set_permissions(bin.join("claude"), fs::Permissions::from_mode(0o755)).unwrap();

    // The fake CLI script needs real `touch`/`cat` on its own PATH in
    // addition to the isolated bin dir the hook itself resolves `claude`
    // from — this differs from the other fixtures' `exit 0`-only scripts.
    let path_var = format!("{}:/bin:/usr/bin", bin.display());
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
    command
        .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
        .env("MSB_INTERCEPT_SNI", "platform.claude.com")
        .env("HOME", home.path())
        .env("PATH", &path_var);
    let output = run_hook_bounded(command, anthropic_refresh_request().as_bytes());
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        marker.exists(),
        "the bounded host CLI must actually run for a due credential"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("HTTP/1.1 200"), "{stdout}");
    assert!(!stdout.contains("OLD_NEAR_EXPIRY_CANARY"));
    assert!(!stdout.contains("FRESH_ROTATED_CANARY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("FRESH_ROTATED_CANARY"));

    let token_path = state_parent
        .path()
        .join("project.secrets")
        .join("anthropic");
    assert!(!token_path.starts_with(&state));
    assert_eq!(
        fs::read_to_string(&token_path).unwrap(),
        "FRESH_ROTATED_CANARY"
    );
    assert_eq!(
        fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

/// #492: the Anthropic hook reads two host credential locations, so its
/// black-box cases need a fake `security` beside the fake `claude`. macOS-only
/// because the keychain location does not exist off macOS — there, the file is
/// the whole answer and the cases above already cover it.
#[cfg(target_os = "macos")]
mod keychain {
    use std::path::PathBuf;

    use super::*;

    /// What the fake `security` on `PATH` does. The script only recognises the
    /// two argv forms the reader is allowed to send (see `assert_query_forms`),
    /// and exits **97** on anything else, so a wrong query fails instead of being
    /// silently answered.
    enum KeychainFake {
        /// Print this blob.
        Blob(String),
        /// Fail with this exit status — not 44, so it is a failure, not a miss.
        Exit(u8),
        /// Hold the query open past the hook's keychain deadline.
        Sleep,
        /// Print more than the reader's cap, then exit.
        Oversized,
        /// A plain-text blob the reader cannot parse.
        Malformed,
        /// Miss when `-a` is given, answer with this blob for the bare query.
        MissOnAccount(String),
        /// Burn most of the one shared deadline on a miss, then hold the bare
        /// query open past the remainder.
        SlowMissThenSlowHit,
    }

    /// The two argv forms this fixture's item answers, as the reader must send
    /// them: the account-qualified query first, then the bare one.
    ///
    /// Each argument is wrapped in `<>` and the forms are compared *whole*, not
    /// by substring: joining the arguments with spaces (what `"$*"` does) would
    /// make `-s Claude Code-credentials` — one argument — identical to
    /// `-s Claude Code-credentials` sent as two, and the service name's space is
    /// exactly the boundary a sloppy reader could get wrong. Separation is part
    /// of the contract.
    const ACCOUNT_QUERY: &str =
        "<find-generic-password><-a><agentvm-test-user><-w><-s><Claude Code-credentials>";
    const BARE_QUERY: &str = "<find-generic-password><-w><-s><Claude Code-credentials>";

    /// The fixture's own handles. Dropped only after the assertions, or the
    /// files would vanish first.
    struct HookPaths {
        _home: tempfile::TempDir,
        _state_parent: tempfile::TempDir,
        _bin: tempfile::TempDir,
        home: PathBuf,
        state: PathBuf,
        keychain: PathBuf,
        security_log: PathBuf,
    }

    impl HookPaths {
        fn token(&self) -> PathBuf {
            self.state
                .with_file_name("project.secrets")
                .join("anthropic")
        }

        fn credential_file(&self) -> PathBuf {
            self.home.join(".claude/.credentials.json")
        }

        fn security_bin(&self) -> PathBuf {
            self._bin.path().join("security")
        }

        fn security_calls(&self) -> Vec<String> {
            fs::read_to_string(&self.security_log)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    fn write_script(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn blob(token: &str, expires_at_ms: i64) -> String {
        format!(
            r#"{{"claudeAiOauth":{{"accessToken":"{token}","expiresAt":{expires_at_ms},"scopes":["user:inference"]}}}}"#
        )
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    /// One hook invocation over an isolated `HOME`, with a fake `security` and a
    /// fake `claude`. `claude_script` runs as the rotation CLI; it can rewrite
    /// `$HOME/keychain.json` but never the credential file, which is how the
    /// self-heal case proves the re-read follows the keychain.
    fn run_anthropic_hook(
        credential_file: Option<String>,
        keychain: KeychainFake,
        claude_script: &str,
    ) -> (Output, HookPaths) {
        run_anthropic_hook_with_token(credential_file, None, keychain, claude_script)
    }

    /// The same, with a bearer **already installed** in the sibling host-only
    /// token file — the state a long-running sandbox is in when the outage
    /// arrives. F05's point is that a failed refresh must not serve it.
    fn run_anthropic_hook_with_token(
        credential_file: Option<String>,
        installed_token: Option<&str>,
        keychain: KeychainFake,
        claude_script: &str,
    ) -> (Output, HookPaths) {
        let home_dir = tempfile::tempdir().unwrap();
        let state_parent = tempfile::tempdir().unwrap();
        let bin_dir = tempfile::tempdir().unwrap();
        let home = home_dir.path().to_path_buf();
        let bin = bin_dir.path().to_path_buf();
        let state = state_parent.path().join("project");
        fs::create_dir_all(&state).unwrap();
        let secrets = state.with_file_name("project.secrets");
        if let Some(token) = installed_token {
            fs::create_dir_all(&secrets).unwrap();
            fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
            let token_file = secrets.join("anthropic");
            fs::write(&token_file, token).unwrap();
            fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let claude_dir = home.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();
        if let Some(contents) = &credential_file {
            fs::write(claude_dir.join(".credentials.json"), contents).unwrap();
        }
        let keychain_path = home.join("keychain.json");
        let security_log = home.join("security.log");
        let keychain_body = match &keychain {
            KeychainFake::Blob(blob) | KeychainFake::MissOnAccount(blob) => {
                // A trailing newline, because `security -w` always prints one.
                fs::write(&keychain_path, format!("{blob}\n")).unwrap();
                format!("/bin/cat '{}'\n", keychain_path.display())
            }
            KeychainFake::Exit(status) => format!("exit {status}\n"),
            KeychainFake::Sleep => "sleep 30\n".to_string(),
            KeychainFake::Oversized => {
                let mut flood = vec![b'a'; 1024 * 1024 + 1];
                flood.push(b'\n');
                let path = home.join("oversized.json");
                fs::write(&path, flood).unwrap();
                format!("/bin/cat '{}'\n", path.display())
            }
            KeychainFake::Malformed => {
                let path = home.join("malformed.json");
                fs::write(&path, "not valid json {{{\n").unwrap();
                format!("/bin/cat '{}'\n", path.display())
            }
            KeychainFake::SlowMissThenSlowHit => {
                "case \"$form\" in\n  account) sleep 1.6; exit 44 ;;\nesac\nsleep 1.6\nexit 1\n"
                    .to_string()
            }
        };
        // An account miss is its own behaviour: exit 44 for the qualified form
        // only, so "no item for this account" stays distinct from every other
        // failure.
        let account_guard = match &keychain {
            KeychainFake::MissOnAccount(_) => "if [ \"$form\" = account ]; then exit 44; fi\n",
            _ => "",
        };
        write_script(
            &bin.join("security"),
            &format!(
                "#!/bin/sh\n\
                 line=\n\
                 for a in \"$@\"; do line=\"$line<$a>\"; done\n\
                 printf '%s\\n' \"$line\" >> '{log}'\n\
                 case \"$line\" in\n\
                 \x20 '{account_query}') form=account ;;\n\
                 \x20 '{bare_query}') form=bare ;;\n\
                 \x20 *) exit 97 ;;\n\
                 esac\n\
                 {account_guard}{keychain_body}",
                log = security_log.display(),
                account_query = ACCOUNT_QUERY,
                bare_query = BARE_QUERY,
            ),
        );
        write_script(
            &bin.join("claude"),
            &format!("#!/bin/sh\n{claude_script}\n"),
        );

        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
        command
            .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
            .env("MSB_INTERCEPT_SNI", "platform.claude.com")
            .env("HOME", &home)
            // The fake `security` shadows the real one; `/bin` and `/usr/bin`
            // stay for the scripts' own `sleep`/`cat`.
            .env("PATH", format!("{}:/bin:/usr/bin", bin.display()))
            .env("USER", "agentvm-test-user");
        let output = run_hook_bounded(command, anthropic_refresh_request().as_bytes());
        (
            output,
            HookPaths {
                _home: home_dir,
                _state_parent: state_parent,
                _bin: bin_dir,
                home,
                state,
                keychain: keychain_path,
                security_log,
            },
        )
    }

    /// Every query the hook sent must be one of the two forms the reader is
    /// allowed to send. Without this, a wrong account, a wrong service, a dropped
    /// `-w`, a service name split on its space or a write subcommand would be
    /// answered by the fake (or fail as a miss) and the case would still pass on
    /// the fallback path.
    fn assert_query_forms(paths: &HookPaths) {
        let calls = paths.security_calls();
        assert!(!calls.is_empty(), "the keychain was never consulted");
        for call in &calls {
            assert!(
                call == ACCOUNT_QUERY || call == BARE_QUERY,
                "unexpected `security` arguments: {call:?} (allowed: {ACCOUNT_QUERY:?}, {BARE_QUERY:?})"
            );
        }
    }

    /// The 503 cases: same assertions as the shared helper, plus the query forms
    /// and the guarantee that the *already installed* bearer was not served.
    fn assert_typed_503_without_serving(paths: &HookPaths, output: &Output, old_bearer: &str) {
        assert_query_forms(paths);
        assert_typed_503(output, "claude login");
        let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        assert!(
            !stdout.contains(&old_bearer.to_ascii_lowercase()),
            "the already-installed bearer must not be served: {stdout}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr)
                .to_ascii_lowercase()
                .contains(&old_bearer.to_ascii_lowercase()),
            "the already-installed bearer must not reach stderr"
        );
    }

    fn assert_served(output: &Output, paths: &HookPaths, bearer: &str) {
        assert_query_forms(paths);
        assert!(
            output.status.success(),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout.clone()).unwrap();
        assert!(stdout.starts_with("HTTP/1.1 200"), "{stdout}");
        assert!(
            stdout.contains("msb-anthropic-placeholder-a-v2"),
            "{stdout}"
        );
        assert!(
            !stdout.contains(bearer),
            "the real token must not be served"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(bearer),
            "the real token must not reach stderr"
        );
        let token = paths.token();
        assert!(
            !token.starts_with(&paths.state),
            "the real token must stay outside the guest-visible state dir"
        );
        assert_eq!(fs::read_to_string(&token).unwrap(), bearer);
        assert_eq!(
            fs::metadata(&token).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// Case 1 / story 2: a live keychain item beats the stale file, and the
    /// keychain bearer is what lands in the host-only token file.
    #[test]
    fn a_fresh_keychain_item_beats_the_stale_file() {
        let now = now_ms();
        let (output, paths) = run_anthropic_hook(
            Some(blob("FILE_STALE", now - 3_600_000)),
            KeychainFake::Blob(blob("KC_FRESH", now + 4 * 3_600_000)),
            "exit 0",
        );
        assert_served(&output, &paths, "KC_FRESH");
        assert!(
            paths
                .security_calls()
                .iter()
                .all(|line| line.starts_with("<find-generic-password>")),
            "agent-vm must only ever read the item: {:?}",
            paths.security_calls()
        );
    }

    /// Case 2 / story 11: the later expiry wins regardless of which location it
    /// is. Guards against an accidental "the keychain always wins".
    #[test]
    fn a_fresher_file_beats_the_keychain() {
        let now = now_ms();
        let (output, paths) = run_anthropic_hook(
            Some(blob("FILE_FRESH", now + 2 * 3_600_000)),
            KeychainFake::Blob(blob("KC_OLDER", now + 3_600_000)),
            "exit 0",
        );
        assert_served(&output, &paths, "FILE_FRESH");
    }

    /// Case 9a: no credential file at all, and the keychain answers.
    #[test]
    fn a_keychain_item_with_no_credential_file_is_served() {
        let now = now_ms();
        let (output, paths) = run_anthropic_hook(
            None,
            KeychainFake::Blob(blob("KC_ONLY", now + 4 * 3_600_000)),
            "exit 0",
        );
        assert_served(&output, &paths, "KC_ONLY");
        assert!(!paths.credential_file().exists());
    }

    /// Case 3 — the regression this ticket exists for. The file stays stale and
    /// only the keychain value changes when the fake `claude` runs, so the
    /// post-rotation re-read has to consult the keychain; before #492 it saw the
    /// stale file and answered 503.
    #[test]
    fn rotation_heals_a_session_whose_fresh_token_landed_in_the_keychain() {
        let now = now_ms();
        let rotated = blob("KC_ROTATED", now + 3_600_000);
        let stale = blob("FILE_STALE", now - 3_600_000);
        let (output, paths) = run_anthropic_hook(
            Some(stale.clone()),
            // Near expiry: due for rotation, and not servable above the floor.
            KeychainFake::Blob(blob("KC_NEAR_EXPIRY", now + 60_000)),
            // The host CLI refreshes the keychain item and leaves the file
            // alone, which is exactly the reporting host's behaviour.
            &format!("printf '%s\\n' '{rotated}' > \"$HOME/keychain.json\""),
        );
        assert_served(&output, &paths, "KC_ROTATED");
        assert_eq!(
            fs::read_to_string(paths.credential_file()).unwrap(),
            stale,
            "agent-vm must never write the host credential file"
        );
        assert!(
            fs::read_to_string(&paths.keychain)
                .unwrap()
                .contains("KC_ROTATED"),
            "the fake CLI must have rewritten the item, or this asserts nothing"
        );
        assert!(
            paths
                .security_calls()
                .iter()
                .all(|line| line.starts_with("<find-generic-password>")),
            "only reads, never `add-generic-password`: {:?}",
            paths.security_calls()
        );
    }

    /// Case 4a / story 8: a failing keychain degrades to the file instead of
    /// failing the request.
    #[test]
    fn a_failing_keychain_degrades_to_the_file() {
        let (output, paths) = run_anthropic_hook(
            Some(blob("FILE_CANARY", 9_999_999_999_000)),
            KeychainFake::Exit(1),
            "exit 0",
        );
        assert_served(&output, &paths, "FILE_CANARY");
    }

    /// Case 4b / stories 7, 14: a keychain that never answers is bounded by the
    /// hook's deadline, so the request still completes well inside the budget.
    #[test]
    fn a_slow_keychain_is_bounded_and_degrades_to_the_file() {
        let start = std::time::Instant::now();
        let (output, paths) = run_anthropic_hook(
            Some(blob("FILE_CANARY", 9_999_999_999_000)),
            KeychainFake::Sleep,
            "exit 0",
        );
        assert_served(&output, &paths, "FILE_CANARY");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "one hooked request took {:?}",
            start.elapsed()
        );
    }

    /// Case 5 / story 9: both locations expired is still today's typed 503
    /// naming the host login.
    #[test]
    fn both_locations_expired_is_the_typed_503() {
        let now = now_ms();
        let (output, paths) = run_anthropic_hook(
            Some(blob("FILE_STALE", now - 3_600_000)),
            KeychainFake::Blob(blob("KC_STALE", now - 7_200_000)),
            "exit 0",
        );
        assert_query_forms(&paths);
        assert_typed_503(&output, "claude login");
        assert!(!paths.token().exists(), "nothing usable was installed");
    }

    /// F05: the outage arrives at a *running* sandbox, which already has a bearer
    /// installed. A refresh that fails must not authorize a success off that old
    /// bearer — "not served" means the response does not claim usable
    /// credentials, not that the file is deleted.
    #[test]
    fn both_expired_with_an_old_bearer_installed_is_still_the_typed_503() {
        let now = now_ms();
        let (output, paths) = run_anthropic_hook_with_token(
            Some(blob("FILE_STALE", now - 3_600_000)),
            Some("OLD_BEARER_CANARY"),
            KeychainFake::Blob(blob("KC_STALE", now - 7_200_000)),
            "exit 0",
        );
        assert_typed_503_without_serving(&paths, &output, "OLD_BEARER_CANARY");
        // Retaining the old file is not evidence it was served; deleting it is
        // nobody's requirement here.
        assert_eq!(
            fs::read_to_string(paths.token()).unwrap(),
            "OLD_BEARER_CANARY"
        );
    }

    /// F05: a denied or locked keychain with no credential file at all — the
    /// reporting host's shape — must not fall back to the installed bearer.
    #[test]
    fn a_denied_keychain_with_no_credential_file_does_not_serve_the_old_bearer() {
        let (output, paths) = run_anthropic_hook_with_token(
            None,
            Some("OLD_BEARER_CANARY"),
            // Not 44, so it is a failure rather than a miss: the shape of a
            // denied or locked item.
            KeychainFake::Exit(36),
            "exit 0",
        );
        assert_typed_503_without_serving(&paths, &output, "OLD_BEARER_CANARY");
    }

    /// F05: a keychain that never answers, with a malformed file, is the same
    /// fail-closed outcome from the other direction.
    #[test]
    fn a_timed_out_keychain_with_a_malformed_file_does_not_serve_the_old_bearer() {
        let (output, paths) = run_anthropic_hook_with_token(
            Some("not valid json {{{".into()),
            Some("OLD_BEARER_CANARY"),
            KeychainFake::Sleep,
            "exit 0",
        );
        assert_typed_503_without_serving(&paths, &output, "OLD_BEARER_CANARY");
    }

    /// F05: a malformed *item* is ineligible too, so an expired file plus a
    /// broken item is still a 503 rather than a success built from the old
    /// bearer.
    #[test]
    fn a_malformed_item_with_an_expired_file_does_not_serve_the_old_bearer() {
        let now = now_ms();
        let (output, paths) = run_anthropic_hook_with_token(
            Some(blob("FILE_STALE", now - 3_600_000)),
            Some("OLD_BEARER_CANARY"),
            KeychainFake::Malformed,
            "exit 0",
        );
        assert_typed_503_without_serving(&paths, &output, "OLD_BEARER_CANARY");
    }

    /// F05: an item over the cap with an expired file is the same, so the size
    /// bound cannot be a route to serving stale credentials either.
    #[test]
    fn an_oversized_item_with_an_expired_file_does_not_serve_the_old_bearer() {
        let now = now_ms();
        let (output, paths) = run_anthropic_hook_with_token(
            Some(blob("FILE_STALE", now - 3_600_000)),
            Some("OLD_BEARER_CANARY"),
            KeychainFake::Oversized,
            "exit 0",
        );
        assert_typed_503_without_serving(&paths, &output, "OLD_BEARER_CANARY");
    }

    /// F05's recovery mirror: a refresh that only touches the keychain replaces
    /// the stale bearer already installed, at the expected path and mode, and
    /// the host vendor file stays untouched.
    #[test]
    fn a_keychain_only_refresh_replaces_the_preinstalled_stale_bearer() {
        let now = now_ms();
        let rotated = blob("KC_ROTATED", now + 3_600_000);
        let stale_file = blob("FILE_STALE", now - 3_600_000);
        let (output, paths) = run_anthropic_hook_with_token(
            Some(stale_file.clone()),
            Some("OLD_BEARER_CANARY"),
            // Near expiry: due for rotation, and not servable above the floor.
            KeychainFake::Blob(blob("KC_NEAR_EXPIRY", now + 60_000)),
            &format!("printf '%s\\n' '{rotated}' > \"$HOME/keychain.json\""),
        );
        assert_served(&output, &paths, "KC_ROTATED");
        assert_eq!(
            fs::metadata(paths.token()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_to_string(paths.credential_file()).unwrap(),
            stale_file,
            "agent-vm must never write the host credential file"
        );
    }

    /// F11: the strict fake is not vacuous — it rejects a query the reader is not
    /// allowed to send, so a regression in the argv shape fails the case above
    /// instead of being quietly answered.
    #[test]
    fn the_fake_rejects_an_unexpected_query() {
        let (_output, paths) = run_anthropic_hook(
            Some(blob("FILE_STALE", 0)),
            KeychainFake::Blob(blob("KC_FRESH", 9_999_999_999_000)),
            "exit 0",
        );
        let bin = paths.security_bin();
        for wrong in [
            // `-w` missing: the reader would get a different presentation.
            vec![
                "find-generic-password",
                "-a",
                "agentvm-test-user",
                "-s",
                "Claude Code-credentials",
            ],
            // Wrong service.
            vec![
                "find-generic-password",
                "-a",
                "agentvm-test-user",
                "-w",
                "-s",
                "Other-service",
            ],
            // Wrong account.
            vec![
                "find-generic-password",
                "-a",
                "someone-else",
                "-w",
                "-s",
                "Claude Code-credentials",
            ],
            // The service name split on its space into two arguments. This is
            // the case a `"$*"` comparison cannot see, and the reason the fake
            // logs and matches delimited arguments instead.
            vec![
                "find-generic-password",
                "-a",
                "agentvm-test-user",
                "-w",
                "-s",
                "Claude",
                "Code-credentials",
            ],
            // A write, which agent-vm must never issue.
            vec![
                "add-generic-password",
                "-a",
                "agentvm-test-user",
                "-w",
                "-s",
                "Claude Code-credentials",
            ],
        ] {
            let status = Command::new(&bin)
                .args(&wrong)
                .env("USER", "agentvm-test-user")
                .status()
                .expect("run the fake `security`");
            assert_eq!(
                status.code(),
                Some(97),
                "the fake must reject {wrong:?} rather than answer it"
            );
        }
    }

    /// Case 7 / R3: the account-qualified query is tried first, and the bare
    /// retry finds the item when it misses.
    #[test]
    fn the_account_qualified_query_falls_back_to_the_bare_one() {
        let now = now_ms();
        let (output, paths) = run_anthropic_hook(
            None,
            KeychainFake::MissOnAccount(blob("KC_BARE", now + 4 * 3_600_000)),
            "exit 0",
        );
        assert_served(&output, &paths, "KC_BARE");
        // The whole argv, element by element: the qualified form first, then the
        // bare one. A substring check here would accept a service name split
        // into two arguments.
        assert_eq!(paths.security_calls(), [ACCOUNT_QUERY, BARE_QUERY]);
    }

    /// Case 8 / R4: an item larger than the cap is unusable, not memory.
    #[test]
    fn an_oversized_keychain_item_degrades_to_the_file() {
        let (output, paths) = run_anthropic_hook(
            Some(blob("FILE_CANARY", 9_999_999_999_000)),
            KeychainFake::Oversized,
            "exit 0",
        );
        assert_served(&output, &paths, "FILE_CANARY");
    }

    /// Review #9b: a normal-sized *malformed* item is ineligible too, so the
    /// file is served — the oversize case alone would not prove that.
    #[test]
    fn a_malformed_keychain_item_degrades_to_the_file() {
        let (output, paths) = run_anthropic_hook(
            Some(blob("FILE_CANARY", 9_999_999_999_000)),
            KeychainFake::Blob("not valid json {{{".into()),
            "exit 0",
        );
        assert_served(&output, &paths, "FILE_CANARY");
    }

    /// Review #9c / R4 / F10: both lookups share one deadline. The fake misses
    /// on the account-qualified query and then answers nothing, so the pair has
    /// to cost ~one deadline rather than two — and both calls have to have run,
    /// or "fast" would just mean the retry never happened.
    #[test]
    fn the_two_lookups_share_one_deadline() {
        // One cheap invocation first: the first exec of a freshly built test
        // binary pays a one-off cold-start cost (measured ~1.7 s here) that is
        // process startup, not the deadline under assertion.
        let (warm, warm_paths) = run_anthropic_hook(
            Some(blob("FILE_STALE", 0)),
            KeychainFake::Blob(blob("KC_WARM", 9_999_999_999_000)),
            "exit 0",
        );
        assert_served(&warm, &warm_paths, "KC_WARM");

        let start = std::time::Instant::now();
        let (output, paths) = run_anthropic_hook(
            Some(blob("FILE_CANARY", 9_999_999_999_000)),
            KeychainFake::SlowMissThenSlowHit,
            "exit 0",
        );
        assert_served(&output, &paths, "FILE_CANARY");
        // Retry entry, proven by the log rather than by the clock: exactly the
        // account-qualified query and then the bare one.
        assert_eq!(
            paths.security_calls(),
            [ACCOUNT_QUERY, BARE_QUERY],
            "the bare retry must actually run, in that order"
        );
        // One deadline is 2 s; two of them would be at least 3.2 s here. Only
        // this assertion is timing-based, and it has headroom for a busy host.
        assert!(
            start.elapsed() < std::time::Duration::from_millis(2_900),
            "the retry must share the first attempt's deadline, took {:?}",
            start.elapsed()
        );
    }
}
