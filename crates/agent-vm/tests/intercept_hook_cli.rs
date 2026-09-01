//! Black-box coverage for the hidden interceptor command's stdin/stdout boundary.
//!
//! These cases use a fresh empty state directory and deliberately invalid/off-list
//! requests, so they exercise the production CLI without reading or rotating host
//! credentials.

use std::{
    io::Write,
    process::{Command, Stdio},
};

fn run_hook(sni: &str, request: &[u8]) -> String {
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
        .spawn()
        .expect("start hidden hook");
    child
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(request)
        .expect("write intercepted request");
    let output = child.wait_with_output().expect("wait for hidden hook");
    assert!(
        output.status.success(),
        "hook stderr is intentionally not captured"
    );
    String::from_utf8(output.stdout).expect("hook response is UTF-8")
}

#[test]
fn hidden_hook_rejects_oauth_prefix_lookalike_without_exposing_a_token() {
    let response = run_hook(
        "platform.claude.com",
        b"POST /v1/oauth/token?ignored=1 HTTP/1.1\r\nHost: platform.claude.com\r\nContent-Length: 0\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    assert!(!response.to_ascii_lowercase().contains("access_token"));
    assert!(!response.to_ascii_lowercase().contains("bearer"));
}

#[test]
fn hidden_hook_denies_off_list_github_before_any_authenticated_forward() {
    let response = run_hook(
        "api.github.com",
        b"GET /repos/not-allowed/project HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    assert!(!response.to_ascii_lowercase().contains("authorization:"));
    assert!(!response.to_ascii_lowercase().contains("bearer"));
}
