//! Test-owned loopback OCI server, serving genuine archive bytes. No runtime
//! acquisition is mocked. Closing each response bounds protocol complexity.
#![allow(dead_code)]
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::image_archive::{self, ArchiveSpec, Written};

#[derive(Clone)]
pub struct Image {
    pub written: Written,
    pub blobs: BTreeMap<String, Vec<u8>>,
    pub index: Vec<u8>,
}
impl Image {
    pub fn from_archive(path: &std::path::Path, spec: &ArchiveSpec) -> Self {
        let written = image_archive::write(path, spec);
        let mut blobs = BTreeMap::new();
        let mut index = vec![];
        for entry in tar::Archive::new(std::fs::File::open(path).unwrap())
            .entries()
            .unwrap()
        {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = vec![];
            entry.read_to_end(&mut bytes).unwrap();
            if let Some(hex) = name.strip_prefix("blobs/sha256/") {
                blobs.insert(format!("sha256:{hex}"), bytes);
            } else if name == "index.json" {
                index = bytes;
            }
        }
        Self {
            written,
            blobs,
            index,
        }
    }
}
#[derive(Clone)]
struct Response {
    bytes: Vec<u8>,
    media: &'static str,
    digest: String,
}

type BlobStall = (
    Mutex<Option<(String, std::sync::mpsc::Sender<()>)>>,
    std::sync::Condvar,
);

pub struct Server {
    pub host: String,
    routes: Arc<Mutex<BTreeMap<String, Response>>>,
    pub requests: Arc<Mutex<Vec<(String, String)>>>,
    pub headers: Arc<Mutex<Vec<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    task: Option<JoinHandle<()>>,
    stall: Arc<BlobStall>,
    basic_challenge: Arc<std::sync::atomic::AtomicBool>,
}
impl Server {
    pub fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback binding prerequisite");
        let host = listener.local_addr().unwrap().to_string();
        let routes = Arc::new(Mutex::new(BTreeMap::<String, Response>::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let headers = Arc::new(Mutex::new(Vec::new()));
        let worker_headers = headers.clone();
        let basic_challenge = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_challenge = basic_challenge.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stall = Arc::new((
            Mutex::new(None::<(String, std::sync::mpsc::Sender<()>)>),
            std::sync::Condvar::new(),
        ));
        let worker_stall = stall.clone();
        let (r, q, s) = (routes.clone(), requests.clone(), stop.clone());
        let task = std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                if s.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let words: Vec<_> = line.split_whitespace().collect();
                if words.len() < 2 {
                    continue;
                }
                let (method, path) = (words[0].to_owned(), words[1].to_owned());
                let mut range = None;
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    worker_headers.lock().unwrap().push(line.clone());
                    if line.to_ascii_lowercase().starts_with("range:") {
                        range = Some(line.clone());
                    }
                }
                q.lock().unwrap().push((method.clone(), path.clone()));
                let response = if path == "/v2/" {
                    Some(Response {
                        bytes: b"{}".to_vec(),
                        media: "application/json",
                        digest: image_archive::sha256_hex(b"{}"),
                    })
                } else {
                    r.lock().unwrap().get(&path).cloned()
                };
                if path == "/v2/" && worker_challenge.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    continue;
                }
                if let Some(response) = response {
                    // Native currently requests full blobs; if that changes fail
                    // visibly rather than silently serving an incorrect range.
                    assert!(range.is_none(), "unexpected native Range: {range:?}");
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nDocker-Content-Digest: {}\r\nContent-Length: {}\r\nDocker-Distribution-Api-Version: registry/2.0\r\nConnection: close\r\n\r\n",
                        response.media,
                        response.digest,
                        response.bytes.len()
                    );
                    if method != "HEAD" {
                        let mut stalled = worker_stall.0.lock().unwrap();
                        if let Some((stall_path, signal)) = &*stalled
                            && stall_path == &path
                        {
                            let _ = stream.write_all(&response.bytes[..response.bytes.len() / 2]);
                            let _ = signal.send(());
                            while stalled.is_some() {
                                stalled = worker_stall.1.wait(stalled).unwrap();
                            }
                            continue;
                        }
                        drop(stalled);
                        let _ = stream.write_all(&response.bytes);
                    }
                } else {
                    let body =
                        br#"{"errors":[{"code":"MANIFEST_UNKNOWN","message":"fixture missing"}]}"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    if method != "HEAD" {
                        let _ = stream.write_all(body);
                    }
                }
            }
        });
        Self {
            host,
            routes,
            requests,
            headers,
            stop,
            task: Some(task),
            stall,
            basic_challenge,
        }
    }
    pub fn require_basic_auth(&self) {
        self.basic_challenge
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn stall_blob(&self, path: &str) -> std::sync::mpsc::Receiver<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        *self.stall.0.lock().unwrap() = Some((path.to_owned(), tx));
        rx
    }
    pub fn release_blob(&self) {
        *self.stall.0.lock().unwrap() = None;
        self.stall.1.notify_all();
    }
    pub fn image(&self, repo: &str, tag: &str, image: &Image) -> String {
        for (digest, bytes) in &image.blobs {
            let manifest = digest == &image.written.manifest_digest;
            let kind = if manifest { "manifests" } else { "blobs" };
            self.put(
                &format!("/v2/{repo}/{kind}/{digest}"),
                bytes.clone(),
                if manifest {
                    "application/vnd.oci.image.manifest.v1+json"
                } else {
                    "application/octet-stream"
                },
                digest,
            );
        }
        self.put(
            &format!("/v2/{repo}/manifests/{tag}"),
            image.blobs[&image.written.manifest_digest].clone(),
            "application/vnd.oci.image.manifest.v1+json",
            &image.written.manifest_digest,
        );
        format!("{}/{repo}@{}", self.host, image.written.manifest_digest)
    }
    pub fn index(&self, repo: &str, tag: &str, bytes: Vec<u8>) -> String {
        let digest = image_archive::sha256_hex(&bytes);
        for key in [tag, &digest] {
            self.put(
                &format!("/v2/{repo}/manifests/{key}"),
                bytes.clone(),
                "application/vnd.oci.image.index.v1+json",
                &digest,
            );
        }
        format!("{}/{repo}@{digest}", self.host)
    }
    pub fn put(&self, path: &str, bytes: Vec<u8>, media: &'static str, digest: &str) {
        self.routes.lock().unwrap().insert(
            path.to_owned(),
            Response {
                bytes,
                media,
                digest: digest.to_owned(),
            },
        );
    }
    pub fn remove(&self, path: &str) {
        self.routes.lock().unwrap().remove(path);
    }
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.release_blob();
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = TcpStream::connect(&self.host);
        self.task.take().unwrap().join().unwrap();
    }
}
