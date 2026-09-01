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
