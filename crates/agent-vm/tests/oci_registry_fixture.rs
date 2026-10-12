//! Raw-TCP tests for the loopback OCI registry fixture's request handling.
//!
//! The image-upgrade harness only drives the fixture indirectly, so a `Range`
//! regression there surfaces as a misleading 30s handshake timeout (and, before
//! a fix, a worker panic that aborts the whole test binary). These tests speak
//! HTTP at `Server` directly and assert on the raw status line, headers, and
//! bytes, which pins resumption behaviour the indirect harness leaves
//! timing-dependent.
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::Duration;

#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/image_archive.rs"]
mod image_archive;
#[path = "support/oci_registry.rs"]
mod oci_registry;

use oci_registry::Server;

const BLOB_PATH: &str = "/v2/fixture/blobs/sha256:aaaa";
const BLOB_DIGEST: &str = "sha256:aaaa";

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

fn server_with_blob(blob: &[u8]) -> Server {
    let server = Server::new();
    server.put(
        BLOB_PATH,
        blob.to_vec(),
        "application/octet-stream",
        BLOB_DIGEST,
    );
    server
}

struct RawResponse {
    head: String,
    body: Vec<u8>,
}

impl RawResponse {
    fn status(&self) -> &str {
        self.head.lines().next().unwrap_or_default()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    }
}

fn split_response(bytes: &[u8]) -> RawResponse {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response header terminator");
    RawResponse {
        head: String::from_utf8(bytes[..split].to_vec()).unwrap(),
        body: bytes[split + 4..].to_vec(),
    }
}

fn request(raw: &str, host: &str) -> RawResponse {
    let mut stream = TcpStream::connect(host).expect("connect fixture registry");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    split_response(&bytes)
}

fn get(host: &str, path: &str, range: Option<&str>) -> RawResponse {
    let mut raw = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(range) = range {
        raw.push_str(&format!("Range: {range}\r\n"));
    }
    raw.push_str("\r\n");
    request(&raw, host)
}

#[test]
fn open_ended_range_serves_byte_exact_suffix() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server.host, BLOB_PATH, Some("bytes=1024-"));
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(
        response.header("content-range"),
        Some("bytes 1024-2047/2048")
    );
    assert_eq!(response.header("content-length"), Some("1024"));
    assert_eq!(response.body.as_slice(), &blob[1024..]);
    assert_eq!(server.errors(), Vec::<String>::new());
}

#[test]
fn bounded_range_serves_byte_exact_slice() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server.host, BLOB_PATH, Some("bytes=100-199"));
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(response.header("content-range"), Some("bytes 100-199/2048"));
    assert_eq!(response.header("content-length"), Some("100"));
    assert_eq!(response.body.as_slice(), &blob[100..=199]);
    assert_eq!(server.errors(), Vec::<String>::new());
}

#[test]
fn suffix_range_serves_last_bytes() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server.host, BLOB_PATH, Some("bytes=-16"));
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    assert_eq!(
        response.header("content-range"),
        Some("bytes 2032-2047/2048")
    );
    assert_eq!(response.header("content-length"), Some("16"));
    assert_eq!(response.body.as_slice(), &blob[2032..]);
    assert_eq!(server.errors(), Vec::<String>::new());
}

#[test]
fn range_past_end_is_unsatisfiable() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let response = get(&server.host, BLOB_PATH, Some("bytes=4096-"));
    assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
    assert_eq!(response.header("content-range"), Some("bytes */2048"));
    assert_eq!(response.header("content-length"), Some("0"));
    assert!(response.body.is_empty());
    // A legitimate unsatisfiable range is not a fixture error.
    assert_eq!(server.errors(), Vec::<String>::new());
}

#[test]
fn unsupported_range_is_recorded_and_worker_keeps_serving() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    for range in ["bytes=0-9,20-29", "items=0-1", "bytes=abc-"] {
        let response = get(&server.host, BLOB_PATH, Some(range));
        assert_eq!(response.status(), "HTTP/1.1 416 Range Not Satisfiable");
        assert_eq!(response.header("content-range"), Some("bytes */2048"));
    }
    let errors = server.errors();
    assert_eq!(errors.len(), 3, "recorded: {errors:?}");
    assert!(errors.iter().all(|error| error.contains(BLOB_PATH)));
    // The worker survived every bad request and still serves correctly.
    let response = get(&server.host, BLOB_PATH, None);
    assert_eq!(response.status(), "HTTP/1.1 200 OK");
    assert_eq!(response.body.as_slice(), blob.as_slice());
}

#[test]
fn range_against_stalling_path_still_signals_and_releases() {
    let blob = patterned(2048);
    let server = server_with_blob(&blob);
    let ready = server.stall_blob(BLOB_PATH);
    let host = server.host.clone();
    let mut stream = TcpStream::connect(&host).expect("connect fixture registry");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(
            format!("GET {BLOB_PATH} HTTP/1.1\r\nHost: {host}\r\nRange: bytes=1024-\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("handshake for a partial (206) request");
    server.release_blob();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let response = split_response(&bytes);
    assert_eq!(response.status(), "HTTP/1.1 206 Partial Content");
    // Half of the 1024-byte served slice precedes the handshake; releasing
    // drops the stream, so the remainder never arrives.
    assert_eq!(response.body.len(), 512);
}

#[test]
fn write_executable_is_executable_and_leaves_no_temporary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shim");
    fake_msb::write_executable(&path, "#!/bin/sh\necho fixture-shim\n");
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);
    let mut names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, [std::ffi::OsString::from("shim")]);
    let output = Command::new(&path).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"fixture-shim\n");
}
