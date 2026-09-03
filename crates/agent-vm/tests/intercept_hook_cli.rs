//! Black-box coverage for the hidden interceptor command's stdin/stdout boundary.

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output, Stdio},
};

fn run_hook(sni: &str, request: &[u8]) -> Output {
    let state = tempfile::tempdir().expect("create isolated hook state");
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-vm"))
        .args([
            "_intercept-hook",
            "--state-dir",
            state.path().to_str().unwrap(),
        ])
        .env("MSB_INTERCEPT_SNI", sni)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start hidden hook");
    child.stdin.take().unwrap().write_all(request).unwrap();
    child.wait_with_output().expect("wait for hidden hook")
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-vm"))
        .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
        .env("MSB_INTERCEPT_SNI", "auth.openai.com")
        .env("HOME", home.path())
        .env("PATH", &bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(request).unwrap();
    let output = child.wait_with_output().unwrap();
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-vm"))
        .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
        .env("MSB_INTERCEPT_SNI", sni)
        .env("HOME", home.path())
        .env("PATH", &bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-vm"))
        .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
        .env("MSB_INTERCEPT_SNI", sni)
        .env("HOME", home.path())
        .env("PATH", &bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-vm"))
        .args(["_intercept-hook", "--state-dir", state.to_str().unwrap()])
        .env("MSB_INTERCEPT_SNI", "platform.claude.com")
        .env("HOME", home.path())
        .env("PATH", &path_var)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(anthropic_refresh_request().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
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
