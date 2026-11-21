//! Publish an unbootable OCI candidate to a local registry (#700, from #390).
//!
//! The pins rows need a tag that *resolves* — the manifest and its blobs are all
//! present, the config parses — and then fails native validation, so the refusal
//! they assert on is about the image, not about a missing blob (which the registry
//! itself rejects on `PUT`). Docker cannot build such a candidate: it validates
//! what it pushes. So the bytes are constructed here: a layer that is not a
//! tarball, a minimal config that declares it, and a schema-2 manifest that names
//! both.
//!
//! This is a client, not a registry: `POST` an upload, `PUT` each blob at its own
//! digest, `PUT` the manifest. No HTTP crate — the harness keeps its wire bytes
//! (ADR-0072), and the three requests are small enough to write out in full. Every
//! read, write and connect carries a timeout: a registry that stops answering must
//! fail the row, not hang the run.
//!
//! Nothing here reads `agent-vm`: the manifest is this module's own model of the
//! OCI image-spec documents a native acquisition validates.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
    time::Duration,
};

use clap::Args;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
/// A response body is only ever read for an error message; anything larger is a
/// registry this client does not serve.
const BODY_LIMIT: usize = 1 << 20;
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
/// The unbootable layer: present, uploaded, and not a tarball.
const LAYER: &[u8] = b"not-a-tarball";

#[derive(Debug, Args)]
pub struct E2eRegistryPushArgs {
    /// The registry's port on 127.0.0.1.
    #[arg(long, value_name = "PORT", required_unless_present = "self_test")]
    port: Option<u16>,

    /// The repository to publish into.
    #[arg(long, value_name = "REPO", required_unless_present = "self_test")]
    repo: Option<String>,

    /// The tag to publish.
    #[arg(long, value_name = "TAG", required_unless_present = "self_test")]
    tag: Option<String>,

    /// Run the boot-free controls against a stub registry.
    #[arg(long)]
    self_test: bool,
}

pub fn run(args: E2eRegistryPushArgs) -> Result<crate::Outcome, String> {
    if args.self_test {
        self_test()?;
        return Ok(crate::Outcome::Report(
            "e2e registry-push controls passed".to_owned(),
        ));
    }
    let port = args.port.ok_or("--port PORT is required")?;
    let repo = args.repo.ok_or("--repo REPO is required")?;
    let tag = args.tag.ok_or("--tag TAG is required")?;
    let published = push(port, &repo, &tag)?;
    Ok(crate::Outcome::Report(format!(
        "registry push: {repo}:{tag} {} ({} bytes)",
        published.manifest_digest, published.manifest_size
    )))
}

struct Published {
    manifest_digest: String,
    manifest_size: usize,
}

/// The whole publication, from the empty upload to the manifest behind the tag.
fn push(port: u16, repo: &str, tag: &str) -> Result<Published, String> {
    let config = serde_json::to_vec(&json!({
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [digest_of(LAYER)]},
        "config": {},
    }))
    .map_err(|error| format!("FAIL: cannot encode the image config: {error}"))?;
    let (layer_digest, layer_size) = upload(port, repo, LAYER)?;
    let (config_digest, config_size) = upload(port, repo, &config)?;
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": config_digest, "size": config_size},
        "layers": [{"mediaType": OCI_LAYER, "digest": layer_digest, "size": layer_size}],
    }))
    .map_err(|error| format!("FAIL: cannot encode the manifest: {error}"))?;

    let response = request(
        port,
        "PUT",
        &format!("/v2/{repo}/manifests/{tag}"),
        &[("Content-Type", OCI_MANIFEST)],
        &manifest,
    )?;
    expect(&response, &["201", "200"], "the manifest PUT")?;
    Ok(Published {
        manifest_digest: digest_of(&manifest),
        manifest_size: manifest.len(),
    })
}

/// One blob: open an upload, then complete it at the digest of the bytes sent.
/// The (digest, size) pair is what the manifest must name.
fn upload(port: u16, repo: &str, bytes: &[u8]) -> Result<(String, usize), String> {
    let opened = request(
        port,
        "POST",
        &format!("/v2/{repo}/blobs/uploads/"),
        &[],
        b"",
    )?;
    expect(&opened, &["202"], "the upload POST")?;
    let location = opened
        .header("location")
        .ok_or("FAIL: the upload POST returned no Location")?;
    let digest = digest_of(bytes);
    // A registry may answer with a relative location; both forms are legal.
    let location = if location.starts_with("http://") {
        location.to_owned()
    } else {
        format!("http://127.0.0.1:{port}{location}")
    };
    let separator = if location.contains('?') { '&' } else { '?' };
    let completed = request(
        port,
        "PUT",
        &format!("{location}{separator}digest={digest}"),
        &[("Content-Type", "application/octet-stream")],
        bytes,
    )?;
    expect(&completed, &["201"], "the blob PUT")?;
    Ok((digest, bytes.len()))
}

fn digest_of(bytes: &[u8]) -> String {
    let hex = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

struct Response {
    /// The HTTP status code, as the reason-phrase-free token `expect` compares.
    code: String,
    status_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn expect(response: &Response, accepted: &[&str], what: &str) -> Result<(), String> {
    if accepted.contains(&response.code.as_str()) {
        return Ok(());
    }
    Err(format!(
        "FAIL: {what} was answered {}: {}",
        response.status_line,
        String::from_utf8_lossy(&response.body).trim()
    ))
}

/// One request/response, `Connection: close`, bounded in both directions. The
/// only URL form accepted is this registry's own.
fn request(
    port: u16,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Response, String> {
    let prefix = format!("http://127.0.0.1:{port}");
    let path = target.strip_prefix(&prefix).unwrap_or(target);
    if path.starts_with("http://") {
        return Err(format!("FAIL: refusing a request outside 127.0.0.1:{port}"));
    }
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .map_err(|error| format!("FAIL: cannot connect to the registry at {address}: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("FAIL: cannot bound the registry connection: {error}"))?;

    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\
         Content-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|error| format!("FAIL: cannot send the {method} {path}: {error}"))?;

    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("FAIL: cannot read the {method} {path} answer: {error}"))?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        if raw.len() > BODY_LIMIT {
            return Err(format!("FAIL: the {method} {path} answer is too large"));
        }
    }
    parse_response(&raw).map_err(|error| format!("{error} ({method} {path})"))
}

fn parse_response(raw: &[u8]) -> Result<Response, String> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("FAIL: the registry answer has no header block")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default().to_owned();
    let code = status_line.split(' ').nth(1).unwrap_or_default().to_owned();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();
    Ok(Response {
        code,
        status_line,
        headers,
        body: raw[split + 4..].to_vec(),
    })
}

// --- Boot-free controls -----------------------------------------------------

fn self_test() -> Result<(), String> {
    // Two uploads (a POST then a PUT each) and the manifest: five requests.
    let registry = StubRegistry::start(&[202, 201, 202, 201, 201])?;
    let published = push(registry.port, "probe", "pin")?;
    let recorded = registry.finish()?;
    if recorded.len() != 5 {
        let paths = recorded
            .iter()
            .map(|request| request.path.clone())
            .collect::<Vec<_>>();
        return Err(format!(
            "the publication sent {} requests: {paths:?}",
            recorded.len()
        ));
    }
    let config = recorded[3].body.clone();
    let expected_paths = [
        "/v2/probe/blobs/uploads/".to_owned(),
        format!("/v2/probe/blobs/uploads/u1?digest={}", digest_of(LAYER)),
        "/v2/probe/blobs/uploads/".to_owned(),
        format!("/v2/probe/blobs/uploads/u3?digest={}", digest_of(&config)),
        "/v2/probe/manifests/pin".to_owned(),
    ];
    let paths = recorded
        .iter()
        .map(|request| request.path.clone())
        .collect::<Vec<_>>();
    if paths != expected_paths {
        return Err(format!(
            "the publication sent {paths:?}, want {expected_paths:?}"
        ));
    }
    let methods = recorded
        .iter()
        .map(|request| request.method.as_str())
        .collect::<Vec<_>>();
    if methods != ["POST", "PUT", "POST", "PUT", "PUT"] {
        return Err(format!("the publication sent {methods:?}"));
    }
    if recorded[1].body != LAYER {
        return Err("the layer PUT did not carry the unbootable layer".to_owned());
    }
    if recorded[4]
        .header("content-type")
        .is_none_or(|value| value != OCI_MANIFEST)
    {
        return Err(format!(
            "the manifest PUT carried {:?}",
            recorded[4].header("content-type")
        ));
    }

    // The manifest must name the blobs that were actually uploaded, at their own
    // sizes: a manifest that names something else is a candidate no launcher can
    // validate for the reason the row asserts.
    let manifest: Value = serde_json::from_slice(&recorded[4].body)
        .map_err(|error| format!("the pushed manifest is not JSON: {error}"))?;
    if manifest["config"]["digest"] != digest_of(&config)
        || manifest["config"]["size"] != config.len() as u64
    {
        return Err(format!(
            "the manifest names config {:?}",
            manifest["config"]
        ));
    }
    if manifest["layers"][0]["digest"] != digest_of(LAYER)
        || manifest["layers"][0]["size"] != LAYER.len() as u64
    {
        return Err(format!(
            "the manifest names layer {:?}",
            manifest["layers"][0]
        ));
    }
    if published.manifest_digest != digest_of(&recorded[4].body) {
        return Err(format!(
            "the push reported {} for a manifest it sent as {}",
            published.manifest_digest,
            digest_of(&recorded[4].body)
        ));
    }
    // The config declares the layer's own diff_id, which is what makes the
    // candidate parsable: only the extraction is meant to fail.
    let config_doc: Value =
        serde_json::from_slice(&config).map_err(|error| format!("bad config: {error}"))?;
    if config_doc["rootfs"]["diff_ids"][0] != digest_of(LAYER) {
        return Err(format!("the config declares {:?}", config_doc["rootfs"]));
    }
    if config_doc["architecture"] != "arm64" || config_doc["os"] != "linux" {
        return Err(format!("the config declares {config_doc}"));
    }

    // A registry that refuses the upload fails the publication with its status.
    let refusing = StubRegistry::start(&[500])?;
    let error = push(refusing.port, "probe", "pin")
        .err()
        .ok_or("a refusing registry was reported as a success")?;
    if !error.contains("the upload POST was answered HTTP/1.1 500") {
        return Err(format!(
            "a refusing registry failed without its status: {error}"
        ));
    }
    refusing.finish()?;
    Ok(())
}

/// A registry that answers the requests this client makes and records them.
struct StubRegistry {
    port: u16,
    handle: thread::JoinHandle<Result<Vec<Recorded>, String>>,
}

struct Recorded {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl StubRegistry {
    fn start(statuses: &'static [u16]) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("cannot bind the stub registry: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let handle = thread::spawn(move || {
            let mut recorded = Vec::new();
            for (index, status) in statuses.iter().enumerate() {
                let (mut stream, _) = accept_within(&listener, Duration::from_secs(30))?;
                // BSD `accept` can hand back a socket that inherited the
                // listener's non-blocking flag; the stub reads a request in the
                // clear, so put it back into blocking mode explicitly.
                stream
                    .set_nonblocking(false)
                    .and_then(|()| stream.set_read_timeout(Some(Duration::from_secs(30))))
                    .map_err(|error| error.to_string())?;
                let request = read_request(&mut stream)?;
                let location = format!("/v2/probe/blobs/uploads/u{}", index + 1);
                let status_line = match *status {
                    202 => format!("202 Accepted\r\nLocation: {location}"),
                    other => format!("{other} Stub"),
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .map_err(|error| format!("the stub registry write failed: {error}"))?;
                recorded.push(request);
            }
            Ok(recorded)
        });
        Ok(Self { port, handle })
    }

    fn finish(self) -> Result<Vec<Recorded>, String> {
        self.handle
            .join()
            .map_err(|_| "the stub registry panicked".to_owned())?
    }
}

/// A blocking accept, bounded: a client that stops early must fail the control
/// instead of parking its thread forever.
fn accept_within(
    listener: &TcpListener,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err("the stub registry waited for a request that never came".to_owned());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("the stub registry accept failed: {error}")),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Recorded, String> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !raw.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("the stub registry read failed: {error}"))?;
        if read == 0 {
            return Err("the stub registry saw the connection close".to_owned());
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("no header block")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default().to_owned();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<Vec<_>>();
    let mut body = raw[split + 4..].to_vec();
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.parse::<usize>())
        .transpose()
        .map_err(|error| format!("the stub registry read a bad Content-Length: {error}"))?
        .unwrap_or(0);
    while body.len() < length {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("the stub registry read failed: {error}"))?;
        if read == 0 {
            return Err("the stub registry saw the body end early".to_owned());
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(Recorded {
        method,
        path,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_push_controls_hold() {
        self_test().expect("e2e registry-push controls pass");
    }
}
