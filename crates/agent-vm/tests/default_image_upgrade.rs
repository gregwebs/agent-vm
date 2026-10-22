//! Actual CLI + native registry/cache, no VM or Docker daemon. Anonymous
//! loopback endpoints require compatible machine policy and noninteractive
//! read-only keyring lookup. HOME isolation does not bypass either policy.
use microsandbox_image::{GlobalCache, PullOptions, PullPolicy, Reference, Registry};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;
#[path = "support/acquisition_gate.rs"]
mod acquisition_gate;
#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/image_archive.rs"]
mod image_archive;
#[path = "support/oci_registry.rs"]
mod oci_registry;
mod support;
// The real launch update probe, compiled into this target unchanged so the S1
// producer/consumer test runs production platform selection, transport and
// comparison instead of a reimplementation. Its only crate-local dependency is
// the advisory marker read, adapted below to this harness's isolated root.
#[path = "../src/image_check.rs"]
mod image_check;

/// Test-local `pulled_marker` for the production probe above: the same file
/// layout under whichever isolated state root the current test thread scoped in.
mod pulled_marker {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    thread_local! {
        static ROOT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    /// Restores the previous root on drop, including while unwinding, so one
    /// test's root can never leak into another test on the same thread.
    pub struct ScopedRoot(Option<PathBuf>);

    impl Drop for ScopedRoot {
        fn drop(&mut self) {
            ROOT.with(|root| *root.borrow_mut() = self.0.take());
        }
    }

    pub fn scoped_root(root: &Path) -> ScopedRoot {
        ScopedRoot(ROOT.with(|cell| cell.replace(Some(root.to_owned()))))
    }

    pub fn read(image_ref: &str) -> Option<String> {
        let root = ROOT.with(|cell| cell.borrow().clone())?;
        std::fs::read_to_string(super::pulled_marker_path(&root, image_ref))
            .ok()
            .map(|text| text.trim().to_owned())
    }
}
use acquisition_gate::{
    AcquisitionGate, AcquisitionStage, GateReply, Peer, assert_guard_free, assert_guard_held,
    guard_path,
};
use image_archive::{ArchiveSpec, LayerContent, PlatformSpec};
use oci_registry::{Image, Server};

/// Run a freshly written fixture shim once. `execve` of a file that another
/// thread's concurrent `fork` still holds a duplicate write descriptor for
/// fails with `ETXTBSY`; `rename` keeps the inode, so writing through a
/// temporary does not narrow that race. The kernel timing is not controllable,
/// so retry briefly rather than failing the harness.
fn calibration_status(path: &Path, log: &Path) -> std::process::ExitStatus {
    let mut attempts = 0;
    loop {
        match Command::new(path)
            .env_clear()
            .env("HOST_CALL_LOG", log)
            .arg("fixture-calibration")
            .status()
        {
            Ok(status) => return status,
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 =>
            {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("fixture calibration exec {path:?} failed: {error}"),
        }
    }
}

struct Harness {
    root: tempfile::TempDir,
    _short_state: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    msb: PathBuf,
}
impl Harness {
    fn new() -> Self {
        let root = support::project_tempdir();
        let home = root.path().join("home");
        let short_state = tempfile::Builder::new()
            .prefix("av262-")
            .tempdir_in("/tmp")
            .unwrap();
        let state = short_state.path().to_owned();
        fs::create_dir(&home).unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let msb = bin.join("msb");
        fake_msb::write_executable(
            &msb,
            &format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{}'; exit 0; fi\nprintf '%s\\n' \"$*\" >> \"$HOST_CALL_LOG\"\nexit 93\n",
                fake_msb::VERSION_LINE
            ),
        );
        for name in ["docker", "buildx", "curl", "wget"] {
            fake_msb::write_executable(
                &bin.join(name),
                "#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> \"$HOST_CALL_LOG\"\nexit 94\n",
            );
        }
        // Calibrate each negative oracle: a missing log must mean no call,
        // not a broken shim. These are test-owned processes and files.
        let log = root.path().join("calls");
        for (name, code) in [
            ("docker", 94),
            ("buildx", 94),
            ("curl", 94),
            ("wget", 94),
            ("msb", 93),
        ] {
            let status = calibration_status(&bin.join(name), &log);
            assert_eq!(status.code(), Some(code));
            assert!(
                fs::read_to_string(&log)
                    .unwrap()
                    .contains("fixture-calibration")
            );
            fs::remove_file(&log).unwrap();
        }
        let docker = home.join("docker");
        fs::create_dir(&docker).unwrap();
        fs::write(docker.join("config.json"), b"{\"auths\":{}}").unwrap();
        Self {
            root,
            _short_state: short_state,
            home,
            state,
            msb,
        }
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
        cmd.env_clear()
            .current_dir(self.root.path())
            .env("HOME", &self.home)
            .env("AGENT_VM_STATE_DIR", &self.state)
            .env("MSB_PATH", &self.msb)
            .env("AGENT_VM_SHARE_MSB_CACHE", "0")
            .env("DOCKER_CONFIG", self.home.join("docker"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.msb.parent().unwrap().display()),
            )
            .env("HOST_CALL_LOG", self.root.path().join("calls"));
        cmd
    }
    fn run(&self, args: &[&str]) -> Output {
        bounded(self.command().args(args))
    }
    fn set_default(&self, target: &str) -> Output {
        self.run(&["image", "set-default", "--image", target])
    }
    /// `image refresh [--image REF]`: native acquisition only, no VM.
    fn refresh(&self, target: Option<&str>) -> Output {
        match target {
            Some(target) => self.run(&["image", "refresh", "--image", target]),
            None => self.run(&["image", "refresh"]),
        }
    }
    fn record(&self) -> PathBuf {
        self.home.join(".config/agent-vm/default-image.json")
    }
    fn selected(&self) -> String {
        serde_json::from_slice::<serde_json::Value>(&fs::read(self.record()).unwrap()).unwrap()["image"].as_str().unwrap().to_owned()
    }
    fn cache(&self) -> GlobalCache {
        GlobalCache::new(&self.state.join("msb-home/cache")).unwrap()
    }
    fn image(&self, spec: &ArchiveSpec) -> Image {
        Image::from_archive(&self.root.path().join(format!("{}.tar", spec.marker)), spec)
    }
    fn no_fallback(&self) {
        assert!(
            !self.root.path().join("calls").exists(),
            "unexpected VM/Docker/host fallback"
        );
    }
}
fn bounded(cmd: &mut Command) -> Output {
    let child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    collect_bounded(child)
}
fn collect_bounded(child: std::process::Child) -> Output {
    let id = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    let task = std::thread::spawn(move || {
        tx.send(child.wait_with_output().unwrap()).unwrap();
    });
    let result = rx.recv_timeout(Duration::from_secs(60));
    if result.is_err() {
        unsafe {
            libc::kill(id as i32, libc::SIGKILL);
        }
    }
    task.join().unwrap();
    result
        .expect("native CLI exceeded 60s; inspect read-only keyring / managed-policy prerequisites")
}
fn success(out: &Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
/// The advisory marker's content, derived from the producer's documented path
/// (state root + the first 8 bytes of SHA-256 of the selected reference).
fn pulled_marker_path(state: &Path, reference: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(reference.as_bytes());
    let digest = hasher.finalize();
    let mut name = String::new();
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        write!(name, "{byte:02x}").unwrap();
    }
    state.join("pulled-digests").join(name)
}

fn pulled_marker_digest(h: &Harness, reference: &str) -> Option<String> {
    fs::read_to_string(pulled_marker_path(&h.state, reference))
        .ok()
        .map(|text| text.trim().to_owned())
}

/// The marker file's exact bytes, so a failure row can prove it did not move.
fn pulled_marker_bytes(h: &Harness, reference: &str) -> Option<Vec<u8>> {
    fs::read(pulled_marker_path(&h.state, reference)).ok()
}

/// The production launch update probe, run on this thread against the harness's
/// isolated state root. Its real HTTP request, platform selection and comparison
/// are what the S1 assertions read.
fn probe_update_state(h: &Harness, reference: &str) -> Option<image_check::UpdateState> {
    let _root = pulled_marker::scoped_root(&h.state);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(image_check::check_for_update(reference, false))
        .unwrap()
}

fn describe_update_state(state: &Option<image_check::UpdateState>) -> String {
    match state {
        None => "None (the probe was undecided or unreachable)".to_string(),
        Some(image_check::UpdateState::NotCached) => "NotCached".to_string(),
        Some(image_check::UpdateState::UpToDate) => "UpToDate".to_string(),
        Some(image_check::UpdateState::UpdateAvailable { cached, remote }) => {
            format!("UpdateAvailable {{ cached: {cached}, remote: {remote} }}")
        }
    }
}

/// Open and drop one real TCP connection to the fixture's listener.
fn warm_loopback(host: &str) {
    let address = host.parse().expect("fixture host:port");
    std::net::TcpStream::connect_timeout(&address, Duration::from_secs(30))
        .expect("the fixture listener must accept its first loopback connection");
}

fn assert_up_to_date(h: &Harness, reference: &str, context: &str) {
    let state = probe_update_state(h, reference);
    assert!(
        matches!(state, Some(image_check::UpdateState::UpToDate)),
        "{context}: the launch update probe disagrees with the refresh marker: {} (marker: {:?})",
        describe_update_state(&state),
        pulled_marker_digest(h, reference)
    );
}

fn assert_update_available(h: &Harness, reference: &str, context: &str) {
    match probe_update_state(h, reference) {
        // Both banner fields are read here so this target also proves they carry
        // the two distinct digests (and keeps them live for `-D warnings`).
        Some(image_check::UpdateState::UpdateAvailable { cached, remote }) => {
            assert_ne!(cached, remote, "{context}: the banner must name a move");
            assert!(!cached.is_empty() && !remote.is_empty(), "{context}");
        }
        _ => panic!("{context}: the launch update probe must see the moved host child"),
    }
}

/// R9: every path under the isolated state root **except** the native image
/// cache and the advisory marker directory, with file sizes. A boot-free
/// acquisition must not add sandbox directories, guest disks or other runtime
/// state; the expected native EROFS/fsmeta/VMDK artifacts live under the cache
/// and are inventoried separately by `ReferenceSnapshot`.
fn non_cache_state(h: &Harness) -> BTreeMap<PathBuf, Option<u64>> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Option<u64>>) {
        for entry in fs::read_dir(path).expect("read the state inventory directory") {
            let entry = entry.expect("read a state inventory entry");
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap();
            let excluded =
                relative.starts_with("msb-home/cache") || relative.starts_with("pulled-digests");
            if excluded {
                continue;
            }
            let metadata = entry.metadata().expect("stat the state inventory entry");
            let size = metadata.is_file().then_some(metadata.len());
            out.insert(relative.to_owned(), size);
            if entry
                .file_type()
                .expect("state inventory entry type")
                .is_dir()
            {
                walk(root, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(&h.state, &h.state, &mut out);
    out
}

fn complete(cache: &GlobalCache, pin: &str) {
    assert!(
        Registry::pull_cached(
            cache,
            &pin.parse::<Reference>().unwrap(),
            &PullOptions {
                pull_policy: PullPolicy::Never,
                ..Default::default()
            }
        )
        .unwrap()
        .is_some()
    );
}

/// Derive inventory from independently parsed baseline metadata and descriptor
/// extent references, never from a post-failure pull result. Full bytes are
/// hashed: structurally valid replacement EROFS is still a failure.
struct Snapshot {
    record: Vec<u8>,
    files: BTreeMap<PathBuf, (u64, String)>,
}
impl Snapshot {
    fn take(h: &Harness, pin: &str, image: &Image) -> Self {
        let cache = h.cache();
        let (metadata, others) = artifact_paths(&cache, pin, image);
        Self {
            record: fs::read(h.record()).unwrap(),
            files: hash_paths(std::iter::once(metadata).chain(others)),
        }
    }
    fn unchanged(&self, h: &Harness, pin: &str) {
        assert_eq!(fs::read(h.record()).unwrap(), self.record);
        self.artifacts_unchanged(h, pin);
    }
    fn artifacts_unchanged(&self, h: &Harness, pin: &str) {
        assert_inventory_unchanged(&self.files);
        complete(&h.cache(), pin);
        h.no_fallback();
    }
}

/// The same inventory for a reference that has **no** retained record (an
/// explicit refresh target), so refresh cases can prove artifact preservation
/// without inventing a default record.
struct ReferenceSnapshot {
    files: BTreeMap<PathBuf, (u64, String)>,
}
impl ReferenceSnapshot {
    fn take(cache: &GlobalCache, reference: &str, image: &Image) -> Self {
        // The reference's own metadata file is deliberately excluded: a refresh
        // legitimately replaces it. Everything content-addressed below it must
        // survive byte-identically.
        let (_, others) = artifact_paths(cache, reference, image);
        Self {
            files: hash_paths(others),
        }
    }
    fn unchanged(&self) {
        assert_inventory_unchanged(&self.files);
    }
}

fn assert_inventory_unchanged(files: &BTreeMap<PathBuf, (u64, String)>) {
    for (path, (len, hash)) in files {
        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes.len() as u64, *len, "{}", path.display());
        assert_eq!(
            image_archive::sha256_hex(&bytes),
            *hash,
            "{}",
            path.display()
        );
    }
}

/// Independently checked baseline metadata plus every artifact path it names.
fn artifact_paths(cache: &GlobalCache, reference: &str, image: &Image) -> (PathBuf, Vec<PathBuf>) {
    let reference: Reference = reference.parse().unwrap();
    let metadata_path = cache.image_metadata_path(&reference);
    let metadata_bytes = fs::read(&metadata_path).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes).unwrap();
    assert_eq!(metadata["manifest_digest"], image.written.manifest_digest);
    assert_eq!(metadata["config_digest"], image.written.config_digest);
    assert_eq!(
        image_archive::sha256_hex(metadata["raw_manifest_json"].as_str().unwrap().as_bytes()),
        image.written.manifest_digest
    );
    assert_eq!(
        image_archive::sha256_hex(metadata["raw_config_json"].as_str().unwrap().as_bytes()),
        image.written.config_digest
    );
    assert_eq!(metadata["layers"][0]["diff_id"], image.written.diff_id);
    let manifest = image.written.manifest_digest.parse().unwrap();
    let descriptor = cache.vmdk_path(&manifest);
    let mut paths = vec![cache.fsmeta_erofs_path(&manifest), descriptor.clone()];
    for layer in metadata["layers"].as_array().unwrap() {
        paths.push(cache.layer_erofs_path(&layer["diff_id"].as_str().unwrap().parse().unwrap()));
        let tar = cache.tar_path(&layer["digest"].as_str().unwrap().parse().unwrap());
        if tar.exists() {
            paths.push(tar);
        }
    }
    let descriptor_bytes = fs::read_to_string(&descriptor).unwrap();
    for line in descriptor_bytes
        .lines()
        .filter(|line| line.starts_with("RW ") || line.starts_with("RDONLY "))
    {
        if let Some(path) = line.split('"').nth(1) {
            let path = Path::new(path);
            paths.push(if path.is_absolute() {
                path.to_owned()
            } else {
                descriptor.parent().unwrap().join(path)
            });
        }
    }
    (metadata_path, paths)
}

fn hash_paths(paths: impl IntoIterator<Item = PathBuf>) -> BTreeMap<PathBuf, (u64, String)> {
    paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (
                path,
                (bytes.len() as u64, image_archive::sha256_hex(&bytes)),
            )
        })
        .collect()
}

/// The metadata digest recorded under a cache key, read independently of any
/// pull result.
fn cached_manifest_digest(cache: &GlobalCache, reference: &str) -> String {
    let reference: Reference = reference.parse().unwrap();
    let bytes = fs::read(cache.image_metadata_path(&reference)).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    metadata["manifest_digest"].as_str().unwrap().to_owned()
}

#[test]
fn explicit_tag_and_index_set_default_populate_pin_and_preserve_old_artifacts() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let b = h.image(&ArchiveSpec {
        marker: "B".into(),
        ..Default::default()
    });
    let c = h.image(&ArchiveSpec {
        marker: "C".into(),
        config_platform: PlatformSpec::Foreign,
        descriptor_platform: PlatformSpec::Foreign,
        ..Default::default()
    });
    let pin_a = server.image("private-repo", "moving", &a);
    let tag = format!("{}/private-repo:moving", server.host);
    success(&h.set_default(&tag));
    assert_eq!(h.selected(), pin_a);
    complete(&h.cache(), &pin_a);
    let snapshot = Snapshot::take(&h, &pin_a, &a);
    let pin_b = server.image("private-repo", "moving", &b);
    success(&h.set_default(&tag));
    assert_eq!(h.selected(), pin_b);
    complete(&h.cache(), &pin_b);
    // Compare the A inventory while permitting the intended record change.
    snapshot.artifacts_unchanged(&h, &pin_a);
    server.image("private-repo", "foreign", &c);
    let mut index: serde_json::Value = serde_json::from_slice(&b.index).unwrap();
    index["manifests"].as_array_mut().unwrap().push(
        serde_json::from_slice::<serde_json::Value>(&c.index).unwrap()["manifests"][0].clone(),
    );
    let index_pin = server.index("private-repo", "multi", serde_json::to_vec(&index).unwrap());
    assert_ne!(index_pin, pin_b);
    success(&h.set_default(&index_pin));
    assert_eq!(h.selected(), pin_b);
    success(&h.set_default(&format!(
        "{}/private-repo:ignored@{}",
        server.host, b.written.manifest_digest
    )));
    let formatted = format!("{{ \"image\": \"{pin_b}\", \"version\": 1 }}\n");
    fs::write(h.record(), &formatted).unwrap();
    success(&h.set_default(&pin_b));
    assert_eq!(fs::read(h.record()).unwrap(), formatted.as_bytes());
    let count = server.count();
    let _ = h.run(&["doctor"]);
    assert_eq!(server.count(), count);
    h.no_fallback();
}

#[test]
fn every_native_failure_preserves_a_record_metadata_and_artifact_hashes() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin_a = server.image("images", "a", &a);
    success(&h.set_default(&pin_a));
    for spec in [
        ArchiveSpec {
            marker: "foreign-direct".into(),
            config_platform: PlatformSpec::Foreign,
            ..Default::default()
        },
        ArchiveSpec {
            marker: "absent-platform".into(),
            config_platform: PlatformSpec::Absent,
            ..Default::default()
        },
        ArchiveSpec {
            marker: "corrupt".into(),
            layer: LayerContent::DigestMismatch,
            ..Default::default()
        },
        ArchiveSpec {
            marker: "not-tar".into(),
            layer: LayerContent::NotATar,
            ..Default::default()
        },
        ArchiveSpec {
            marker: "missing-blob".into(),
            omit_layer_blob: true,
            ..Default::default()
        },
    ] {
        let image = h.image(&spec);
        let pin = server.image("images", &spec.marker, &image);
        let before = Snapshot::take(&h, &pin_a, &a);
        let output = h.set_default(&pin);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("this command did not change the retained default")
        );
        before.unchanged(&h, &pin_a);
        if spec.config_platform == PlatformSpec::Foreign {
            let deceptive = server.index("images", "deceptive", image.index.clone());
            let before = Snapshot::take(&h, &pin_a, &a);
            assert_eq!(h.set_default(&deceptive).status.code(), Some(1));
            before.unchanged(&h, &pin_a);
        }
    }
    let before = Snapshot::take(&h, &pin_a, &a);
    assert_eq!(
        h.set_default(&format!("{}/images:missing", server.host))
            .status
            .code(),
        Some(1)
    );
    before.unchanged(&h, &pin_a);
    // B shares A's exact first layer but has a corrupt second layer. Independently
    // assemble its manifest/config so cached shared materialization is exercised.
    let bad = h.image(&ArchiveSpec {
        marker: "bad-second".into(),
        layer: LayerContent::DigestMismatch,
        ..Default::default()
    });
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&a.blobs[&a.written.manifest_digest]).unwrap();
    let bad_manifest: serde_json::Value =
        serde_json::from_slice(&bad.blobs[&bad.written.manifest_digest]).unwrap();
    manifest["layers"]
        .as_array_mut()
        .unwrap()
        .push(bad_manifest["layers"][0].clone());
    let mut config: serde_json::Value =
        serde_json::from_slice(&a.blobs[&a.written.config_digest]).unwrap();
    config["rootfs"]["diff_ids"]
        .as_array_mut()
        .unwrap()
        .push(bad.written.diff_id.clone().into());
    let config = serde_json::to_vec(&config).unwrap();
    let config_digest = image_archive::sha256_hex(&config);
    manifest["config"]["digest"] = config_digest.clone().into();
    manifest["config"]["size"] = config.len().into();
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let digest = image_archive::sha256_hex(&manifest);
    server.image("images", "bad-source", &bad);
    server.put(
        &format!("/v2/images/blobs/{config_digest}"),
        config,
        "application/octet-stream",
        &config_digest,
    );
    server.put(
        "/v2/images/manifests/shared-bad",
        manifest,
        "application/vnd.oci.image.manifest.v1+json",
        &digest,
    );
    let before = Snapshot::take(&h, &pin_a, &a);
    let start = server.count();
    assert_eq!(
        h.set_default(&format!("{}/images:shared-bad", server.host))
            .status
            .code(),
        Some(1)
    );
    before.unchanged(&h, &pin_a);
    assert!(
        !server.requests()[start..]
            .iter()
            .any(|(_, p)| p == &format!("/v2/images/blobs/{}", a.written.layer_digest)),
        "shared A layer must be reused"
    );
    let b = h.image(&ArchiveSpec {
        marker: "publication-b".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "b", &b);
    fs::remove_file(h.record().with_file_name("default-image.lock")).unwrap();
    fs::create_dir(h.record().with_file_name("default-image.lock")).unwrap();
    let before = Snapshot::take(&h, &pin_a, &a);
    let out = h.set_default(&pin_b);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("publishing"));
    complete(&h.cache(), &pin_b);
    before.unchanged(&h, &pin_a);
}

#[test]
fn actual_usage_health_and_config_boundaries_do_not_choose_set_default_target() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin = server.image("images", "a", &a);
    for args in [
        vec!["image", "set-default", "--help"],
        vec!["help", "image", "set-default"],
        vec!["image", "set-default"],
        vec!["image", "set-default", "--image", "/path"],
        vec!["image", "set-default", "--image", "a:tag", "--yes"],
    ] {
        let out = h.run(&args);
        assert_eq!(
            out.status.code(),
            Some(if args.contains(&"--help") || args[0] == "help" {
                0
            } else {
                2
            })
        );
        if args.contains(&"/path") {
            assert!(String::from_utf8_lossy(&out.stderr).contains("agent-vm --image PATH <tool>"));
        }
        assert!(!h.record().exists());
        assert_eq!(server.count(), 0);
    }
    let user = h.home.join(".config/agent-vm/config.toml");
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::write(&user, "broken = [").unwrap();
    let missing = bounded(
        h.command()
            .env("AGENT_VM_IMAGE_TAG", std::ffi::OsStr::from_bytes(b"\xff"))
            .args(["image", "set-default"]),
    );
    assert_eq!(missing.status.code(), Some(2));
    assert!(!h.record().exists());
    assert_eq!(server.count(), 0);
    let out = bounded(
        h.command()
            .env("AGENT_VM_IMAGE_TAG", std::ffi::OsStr::from_bytes(b"\xff"))
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", "invalid")
            .args(["image", "set-default", "--image", &pin]),
    );
    success(&out);
    assert_eq!(h.selected(), pin);
    assert_eq!(fs::read(&user).unwrap(), b"broken = [");
    for kind in ["malformed", "symlink"] {
        fs::remove_file(h.record()).unwrap();
        if kind == "malformed" {
            fs::write(h.record(), b"private damaged bytes").unwrap();
        } else {
            std::os::unix::fs::symlink(&user, h.record()).unwrap();
        }
        let count = server.count();
        assert_eq!(h.set_default(&pin).status.code(), Some(1));
        assert_eq!(server.count(), count);
        assert!(fs::symlink_metadata(h.record()).is_ok());
    }
    h.no_fallback();
}

#[test]
fn interrupted_stream_and_refused_registry_preserve_every_old_byte() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin_a = server.image("images", "a", &a);
    success(&h.set_default(&pin_a));
    let b = h.image(&ArchiveSpec {
        marker: "interrupted".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "b", &b);
    let before = Snapshot::take(&h, &pin_a, &a);
    let ready = server.stall_blob(&format!("/v2/images/blobs/{}", b.written.layer_digest));
    let mut child = h
        .command()
        .args(["image", "set-default", "--image", &pin_b])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    if ready.recv_timeout(Duration::from_secs(30)).is_err() {
        child.kill().unwrap();
        child.wait().unwrap();
        server.release_blob();
        panic!("native blob request handshake missing; inspect credential/policy prerequisites");
    }
    child.kill().unwrap();
    child.wait().unwrap();
    server.release_blob();
    before.unchanged(&h, &pin_a);
    // A dropped network stream is a native application failure, distinct from
    // killing the process. Release the partial blob after its handshake.
    let before = Snapshot::take(&h, &pin_a, &a);
    let ready = server.stall_blob(&format!("/v2/images/blobs/{}", b.written.layer_digest));
    let mut child = h
        .command()
        .args(["image", "set-default", "--image", &pin_b])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    if ready.recv_timeout(Duration::from_secs(30)).is_err() {
        child.kill().unwrap();
        child.wait().unwrap();
        server.release_blob();
        panic!("native partial blob handshake missing");
    }
    server.release_blob();
    let out = collect_bounded(child);
    // A resuming client's `Range` is served as `206`; a recorded error means
    // the fixture met a request shape it does not model. Report it before the
    // exit-code assertion, where the recorded errors are the useful signal.
    assert_eq!(server.errors(), Vec::<String>::new());
    assert_eq!(out.status.code(), Some(1));
    before.unchanged(&h, &pin_a);
    let host = server.host.clone();
    drop(server);
    let before = Snapshot::take(&h, &pin_a, &a);
    let out = h.set_default(&format!("{host}/images:unavailable"));
    assert_eq!(out.status.code(), Some(1));
    before.unchanged(&h, &pin_a);
}

#[test]
fn shared_cache_redirect_and_broken_completion_output_keep_success() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin = server.image("images", "a", &a);
    let shared = h.root.path().join("shared");
    let out = bounded(
        h.command()
            .env("AGENT_VM_SHARE_MSB_CACHE", "1")
            .env("AGENT_VM_MSB_CACHE_DIR", &shared)
            .args(["image", "set-default", "--image", &pin]),
    );
    success(&out);
    complete(&GlobalCache::new(&shared).unwrap(), &pin);
    // Persisted native redirect is used after removing the opt-in env flag.
    success(&h.set_default(&pin));
    assert_eq!(h.selected(), pin);
    // A closed completion-notice pipe must not fail a real *publication*. With
    // stderr dropped, an actual A -> B change must still exit 0, commit exactly
    // B, and leave a complete native B cache. A same-pin retry is only an
    // Unchanged no-op and cannot distinguish a swallowed output error from a
    // replacement that was never committed.
    let b = h.image(&ArchiveSpec {
        marker: "closed-stderr".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "b", &b);
    assert_ne!(pin, pin_b);
    let mut child = h
        .command()
        .env("AGENT_VM_SHARE_MSB_CACHE", "1")
        .env("AGENT_VM_MSB_CACHE_DIR", &shared)
        .args(["image", "set-default", "--image", &pin_b])
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stderr.take());
    assert!(collect_bounded(child).status.success());
    assert_eq!(h.selected(), pin_b);
    complete(&GlobalCache::new(&shared).unwrap(), &pin_b);
    // The retained same-pin retry stays byte-identical: B was published once,
    // and re-acquiring B does not reformat the record.
    let formatted = fs::read(h.record()).unwrap();
    success(&h.set_default(&pin_b));
    assert_eq!(fs::read(h.record()).unwrap(), formatted);
    h.no_fallback();
}

#[test]
fn set_default_preserves_all_overrides_and_default_diagnostic_redaction() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin = server.image("private-marker", "a", &a);
    let user = h.home.join(".config/agent-vm/config.toml");
    // Launch cwd must not contain the harness's authority home (ADR-0038).
    let project_dir = h.root.path().join("project");
    fs::create_dir(&project_dir).unwrap();
    let project = project_dir.join(".agent-vm/config.toml");
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::create_dir_all(project.parent().unwrap()).unwrap();
    fs::write(&user, "image = \"localhost:1/user:tag\"\n").unwrap();
    fs::write(&project, "image = \"localhost:1/project:tag\"\n").unwrap();
    let user_bytes = fs::read(&user).unwrap();
    let project_bytes = fs::read(&project).unwrap();
    success(&bounded(
        h.command()
            .current_dir(&project_dir)
            .env("AGENT_VM_IMAGE_TAG", "localhost:1/env:tag")
            .env("RUST_LOG", "trace")
            .args(["image", "set-default", "--image", &pin]),
    ));
    assert_eq!(fs::read(&user).unwrap(), user_bytes);
    assert_eq!(fs::read(&project).unwrap(), project_bytes);
    for (cli, ambient, expected) in [
        (
            Some("localhost:1/cli:tag"),
            Some("localhost:1/env:tag"),
            "localhost:1/cli:tag",
        ),
        (None, Some("localhost:1/env:tag"), "localhost:1/env:tag"),
        (None, None, "localhost:1/user:tag"),
    ] {
        let mut cmd = h.command();
        cmd.current_dir(&project_dir);
        cmd.env("AGENT_VM_DEBUG_CONFIG", "1");
        if let Some(env) = ambient {
            cmd.env("AGENT_VM_IMAGE_TAG", env);
        }
        cmd.arg("--no-git");
        if let Some(cli) = cli {
            cmd.args(["--image", cli]);
        }
        cmd.args(["shell", "bash", "-c", "true"]);
        let out = bounded(&mut cmd);
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(text.contains(expected), "{text}");
        assert_eq!(h.selected(), pin);
    }
    fs::remove_file(&user).unwrap();
    let out = bounded(
        h.command()
            .current_dir(&project_dir)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .args(["--no-git", "shell", "bash", "-c", "true"]),
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("localhost:1/project:tag"));
    fs::remove_file(&project).unwrap();
    let count = server.count();
    let out = bounded(
        h.command()
            .current_dir(&project_dir)
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .args(["--no-git", "shell", "bash", "-c", "true"]),
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("the default boot image"));
    assert!(!text.contains("private-marker"));
    assert_eq!(server.count(), count);
    assert_eq!(h.selected(), pin);
    // Fake msb can fail launch, but must not be called by set-default itself.
}

#[test]
fn malformed_metadata_wrong_diff_id_and_foreign_index_fail_without_publication() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin_a = server.image("images", "a", &a);
    success(&h.set_default(&pin_a));
    let foreign = h.image(&ArchiveSpec {
        marker: "foreign-index".into(),
        config_platform: PlatformSpec::Foreign,
        descriptor_platform: PlatformSpec::Foreign,
        ..Default::default()
    });
    server.image("images", "foreign", &foreign);
    let target = server.index("images", "foreign-index", foreign.index.clone());
    let before = Snapshot::take(&h, &pin_a, &a);
    assert_eq!(h.set_default(&target).status.code(), Some(1));
    before.unchanged(&h, &pin_a);
    for (name, config) in [
        (
            "wrong-diff",
            serde_json::json!({"os":"linux","architecture":image_archive::host_arch(),"rootfs":{"type":"layers","diff_ids":[format!("sha256:{}", "f".repeat(64))]}}),
        ),
        ("malformed-config", serde_json::json!({"rootfs":7})),
    ] {
        let b = h.image(&ArchiveSpec {
            marker: name.into(),
            ..Default::default()
        });
        server.image("images", name, &b);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&b.blobs[&b.written.manifest_digest]).unwrap();
        let config = serde_json::to_vec(&config).unwrap();
        let digest = image_archive::sha256_hex(&config);
        manifest["config"]["digest"] = digest.clone().into();
        manifest["config"]["size"] = config.len().into();
        server.put(
            &format!("/v2/images/blobs/{digest}"),
            config,
            "application/octet-stream",
            &digest,
        );
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let digest = image_archive::sha256_hex(&bytes);
        server.put(
            &format!("/v2/images/manifests/{name}"),
            bytes,
            "application/vnd.oci.image.manifest.v1+json",
            &digest,
        );
        let before = Snapshot::take(&h, &pin_a, &a);
        assert_eq!(
            h.set_default(&format!("{}/images:{name}", server.host))
                .status
                .code(),
            Some(1)
        );
        before.unchanged(&h, &pin_a);
    }
    server.put(
        "/v2/images/manifests/malformed-manifest",
        b"not JSON".to_vec(),
        "application/vnd.oci.image.manifest.v1+json",
        &image_archive::sha256_hex(b"not JSON"),
    );
    let before = Snapshot::take(&h, &pin_a, &a);
    assert_eq!(
        h.set_default(&format!("{}/images:malformed-manifest", server.host))
            .status
            .code(),
        Some(1)
    );
    before.unchanged(&h, &pin_a);
}

#[test]
fn native_user_registry_settings_and_trace_redaction_are_preserved() {
    let mut h = Harness::new();
    let server = Server::new();
    server.require_basic_auth();
    let a = h.image(&ArchiveSpec::default());
    let pin = server.image("private-marker", "a", &a);
    // Control-character HOME is test owned, and accepted OCI target is private
    // looking; application/native errors must not echo either raw value.
    let moved = h.root.path().join("home\u{1b}unsafe");
    fs::rename(&h.home, &moved).unwrap();
    h.home = moved;
    let native_config = h.state.join("msb-home/config.json");
    fs::create_dir_all(native_config.parent().unwrap()).unwrap();
    let settings = serde_json::json!({"registries":{"hosts":{server.host.clone():{"insecure":true,"auth":{"username":"fixture-user","password_env":"FIXTURE_PASSWORD"}}}}});
    fs::write(&native_config, serde_json::to_vec(&settings).unwrap()).unwrap();
    let out = bounded(
        h.command()
            .env("FIXTURE_PASSWORD", "fixture-password")
            .env("RUST_LOG", "trace")
            .args(["image", "set-default", "--image", &pin]),
    );
    success(&out);
    use base64::Engine as _;
    let expected = format!(
        "Authorization: Basic {}",
        base64::engine::general_purpose::STANDARD.encode("fixture-user:fixture-password")
    );
    assert!(
        server.headers().iter().any(|header| header
            .trim()
            .split_once(": ")
            .is_some_and(|(name, value)| name.eq_ignore_ascii_case("Authorization")
                && value == expected.strip_prefix("Authorization: ").unwrap())),
        "configured native credentials were not forwarded"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!text.contains("private-marker"));
    assert!(!text.contains("fixture-password"));
    assert!(!text.contains("home\u{1b}unsafe"), "{text:?}");
    let ca = h.root.path().join("invalid-ca.pem");
    fs::write(&ca, b"invalid certificate").unwrap();
    let mut settings = settings;
    settings["registries"]["ca_certs"] = ca.to_string_lossy().into_owned().into();
    fs::write(&native_config, serde_json::to_vec(&settings).unwrap()).unwrap();
    let before = Snapshot::take(&h, &pin, &a);
    let out = bounded(
        h.command()
            .env("FIXTURE_PASSWORD", "fixture-password")
            .env("RUST_LOG", "trace")
            .args(["image", "set-default", "--image", &pin]),
    );
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("trust"), "{text}");
    assert!(!text.contains("private-marker"));
    assert!(!text.contains("fixture-password"));
    assert!(!text.contains("home\u{1b}unsafe"), "{text:?}");
    before.unchanged(&h, &pin);
}

#[test]
fn old_artifact_hash_oracle_detects_a_structurally_valid_overwrite() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin_a = server.image("images", "a", &a);
    success(&h.set_default(&pin_a));
    let before = Snapshot::take(&h, &pin_a, &a);
    let b = h.image(&ArchiveSpec {
        marker: "oracle-B".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "b", &b);
    success(&h.set_default(&pin_b));
    let cache = h.cache();
    let a_path = cache.layer_erofs_path(&a.written.diff_id.parse().unwrap());
    let b_path = cache.layer_erofs_path(&b.written.diff_id.parse().unwrap());
    let original = fs::read(&a_path).unwrap();
    let replacement = fs::read(b_path).unwrap();
    assert_ne!(original, replacement);
    fs::write(&a_path, replacement).unwrap();
    // Completeness intentionally accepts a structurally valid EROFS. Only the
    // independent old-byte inventory distinguishes this plausible defect.
    complete(&cache, &pin_a);
    let detected = std::panic::catch_unwind(|| before.artifacts_unchanged(&h, &pin_a));
    fs::write(&a_path, original).unwrap();
    assert!(detected.is_err(), "hash oracle accepted an overwrite");
    before.artifacts_unchanged(&h, &pin_a);
}

// -- `image refresh`: boot-free native acquisition -------------------------

/// R3/R10: re-resolving a moving tag lands the new manifest under the same cache
/// key, reuses cached layer bytes, keeps the old content intact and records the
/// *acquired* digest in the advisory marker.
#[test]
fn refresh_reacquires_a_moving_tag_without_destroying_cached_artifacts() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let b = h.image(&ArchiveSpec {
        marker: "B".into(),
        ..Default::default()
    });
    let tag = format!("{}/images:mutable", server.host);
    let _pin_a = server.image("images", "mutable", &a);
    success(&h.refresh(Some(&tag)));
    assert_eq!(
        cached_manifest_digest(&h.cache(), &tag),
        a.written.manifest_digest
    );
    complete(&h.cache(), &tag);
    let old = ReferenceSnapshot::take(&h.cache(), &tag, &a);

    // A same-content refresh re-resolves the manifest but downloads no layer
    // blob and rewrites no layer bytes.
    let before = server.requests().len();
    success(&h.refresh(Some(&tag)));
    old.unchanged();
    let layer_paths: Vec<String> = server.requests()[before..]
        .iter()
        .map(|(method, path)| format!("{method} {path}"))
        .filter(|request| request.contains("/blobs/sha256:"))
        .filter(|request| !request.contains(&a.written.config_digest))
        .collect();
    assert!(
        layer_paths.is_empty(),
        "a same-content refresh must not re-download layer blobs: {layer_paths:?}"
    );

    // The tag moves: the next refresh must land B under the same key, leave A's
    // artifacts byte-identical, and mark the acquired digest.
    let _pin_b = server.image("images", "mutable", &b);
    let before_move = server.requests().len();
    success(&h.refresh(Some(&tag)));
    assert_eq!(
        cached_manifest_digest(&h.cache(), &tag),
        b.written.manifest_digest
    );
    complete(&h.cache(), &tag);
    let after_move = &server.requests()[before_move..];
    assert!(
        after_move
            .iter()
            .any(|(_, path)| path == "/v2/images/manifests/mutable"),
        "refresh must re-resolve the manifest of the requested tag: {after_move:?}"
    );
    old.unchanged();
    let marker = pulled_marker_digest(&h, &tag);
    assert_eq!(marker.as_deref(), Some(b.written.manifest_digest.as_str()));
    // R9: a further refresh allocates no runtime guest state outside the cache.
    let state = non_cache_state(&h);
    success(&h.refresh(Some(&tag)));
    assert_eq!(
        non_cache_state(&h),
        state,
        "refresh must not create sandbox directories or guest disks"
    );
    h.no_fallback();
}

/// R5: a default-tier bare refresh adopts the selected immutable reference only
/// after a successful acquisition, and never before.
#[test]
fn bare_refresh_adopts_the_recommendation_only_after_success() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin = server.image("images", "a", &a);
    // Fail first: the recommendation names a manifest the registry does not
    // serve, so acquisition fails and nothing may be retained.
    let absent = format!("{}/images@sha256:{}", server.host, "9".repeat(64));
    let failed = bounded(
        h.command()
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &absent)
            .args(["image", "refresh"]),
    );
    assert!(!failed.status.success(), "an absent manifest must fail");
    assert!(
        !h.record().exists(),
        "a failed acquisition must retain nothing"
    );
    assert!(
        !String::from_utf8_lossy(&failed.stderr).contains(&absent),
        "the default tier must not print its reference"
    );

    // Then succeed: the exact selected immutable reference is adopted once.
    success(&bounded(
        h.command()
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &pin)
            .args(["image", "refresh"]),
    ));
    assert_eq!(h.selected(), pin);
    let record = fs::read(h.record()).unwrap();
    // A repeat bare refresh preserves the record bytes.
    success(&h.refresh(None));
    assert_eq!(fs::read(h.record()).unwrap(), record);
    complete(&h.cache(), &pin);
    h.no_fallback();
}

/// One entry of the fail-closed HOME/state inventory.
#[derive(Debug, PartialEq, Eq)]
enum TreeEntry {
    Dir(u32),
    /// Symlinks are recorded as links and never followed.
    Symlink(PathBuf),
    File(u32, Vec<u8>),
    Other(u32),
}

/// S6: a complete recursive inventory — relative path, entry kind, permissions and
/// regular-file bytes — so "nothing was created" means the whole tree, not the two
/// paths a record/registry oracle happens to name. A missing root is an empty
/// inventory; the harness creates both roots before the snapshot.
fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, TreeEntry> {
    use std::os::unix::fs::PermissionsExt as _;
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, TreeEntry>) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("inventory of {} failed: {error}", dir.display()),
        };
        for entry in entries {
            let path = entry.expect("inventory entry").path();
            let relative = path
                .strip_prefix(root)
                .expect("inventory path is under its root")
                .to_owned();
            let metadata = fs::symlink_metadata(&path).expect("inventory symlink_metadata");
            let mode = metadata.permissions().mode();
            let is_dir = metadata.is_dir();
            let entry = if metadata.is_symlink() {
                TreeEntry::Symlink(fs::read_link(&path).expect("inventory link target"))
            } else if is_dir {
                TreeEntry::Dir(mode)
            } else if metadata.is_file() {
                TreeEntry::File(mode, fs::read(&path).expect("inventory regular-file bytes"))
            } else {
                TreeEntry::Other(mode)
            };
            out.insert(relative, entry);
            if is_dir {
                walk(root, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// R11: a CLI/env local rootfs or disk target is refused from input alone, with
/// no registry request, cache, record or VM side effect.
///
/// S6: "before any state" is asserted against the **whole** isolated HOME and
/// state trees, not just record/registry absence, so moving the preflight after
/// the MSB prologue would fail here. Only entries reached through ordinary
/// directory reads are inventoried; no cache constructor is called, because that
/// would itself create state.
#[test]
fn refresh_refuses_local_targets_before_any_state() {
    let h = Harness::new();
    let server = Server::new();
    for target in ["/private/tmp/rootfs", "./rootfs"] {
        let home = tree_snapshot(&h.home);
        let state = tree_snapshot(&h.state);
        let out = h.refresh(Some(target));
        assert_eq!(out.status.code(), Some(1), "{target}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("agent-vm --image PATH <tool>"),
            "{target}: {stderr}"
        );
        assert!(!stderr.contains(target), "{target}: {stderr}");
        assert!(!h.record().exists());
        assert_eq!(tree_snapshot(&h.home), home, "{target}: HOME was touched");
        assert_eq!(
            tree_snapshot(&h.state),
            state,
            "{target}: the rejected target created state"
        );
    }
    let home = tree_snapshot(&h.home);
    let state = tree_snapshot(&h.state);
    let out = bounded(
        h.command()
            .env("AGENT_VM_IMAGE_TAG", "../rootfs")
            .args(["image", "refresh"]),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(!h.record().exists());
    assert_eq!(server.count(), 0);
    assert_eq!(tree_snapshot(&h.home), home, "env target: HOME was touched");
    assert_eq!(
        tree_snapshot(&h.state),
        state,
        "env target: the rejected target created state"
    );
    h.no_fallback();
}

// ---------------------------------------------------------------------------
//
// S2 — a *failed* refresh of an already cached tag.
//
// Native acquisition writes under the key the user's launches read, so the
// refresh-specific risk is a failing re-point of the same tag T. Every row starts
// from a real cached A under T, re-points **that same T** at genuinely invalid
// content, and requires the whole previous state to survive byte-identically.
// This is distinct from the coordination schedule's postvalidation restore: an
// ordinary native error owns no publication, so no restore is attempted.

/// The previous state of one cached refresh key.
struct RefreshBaseline {
    metadata: Vec<u8>,
    artifacts: ReferenceSnapshot,
    marker: Option<Vec<u8>>,
}

impl RefreshBaseline {
    fn take(h: &Harness, reference: &str, image: &Image) -> Self {
        let cache = h.cache();
        let metadata_path = cache.image_metadata_path(&reference.parse::<Reference>().unwrap());
        // Every call site seeds this baseline from a *successful* refresh, which
        // must have written the advisory marker. Failing to read it must not
        // masquerade as "no marker" in the unchanged comparison below.
        let marker = pulled_marker_bytes(h, reference)
            .unwrap_or_else(|| panic!("refresh wrote no advisory marker for {reference}"));
        Self {
            metadata: fs::read(metadata_path).expect("cached metadata before the failure"),
            artifacts: ReferenceSnapshot::take(&cache, reference, image),
            marker: Some(marker),
        }
    }

    /// Exact cached-key bytes, the acquired image's artifact hashes, Never
    /// completeness and the advisory marker all survive; no VM/daemon fallback.
    fn unchanged(&self, h: &Harness, reference: &str) {
        let cache = h.cache();
        let metadata_path = cache.image_metadata_path(&reference.parse::<Reference>().unwrap());
        assert_eq!(
            fs::read(metadata_path).expect("cached metadata after the failure"),
            self.metadata,
            "the failed refresh rewrote the cached key's metadata"
        );
        assert_eq!(
            pulled_marker_bytes(h, reference),
            self.marker,
            "the failed refresh moved the advisory marker"
        );
        self.artifacts.unchanged();
        complete(&cache, reference);
        h.no_fallback();
    }
}

/// The retained fallback a present-record row must not disturb.
struct RetainedFallback {
    pin: String,
    record: Vec<u8>,
    artifacts: ReferenceSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefreshFailure {
    DigestMismatch,
    NotATar,
    MissingBlob,
    ForeignIndex,
    AuthDenied,
    InterruptedStream,
    RefusedRegistry,
}

const REFRESH_FAILURES: [RefreshFailure; 7] = [
    RefreshFailure::DigestMismatch,
    RefreshFailure::NotATar,
    RefreshFailure::MissingBlob,
    RefreshFailure::ForeignIndex,
    RefreshFailure::AuthDenied,
    RefreshFailure::InterruptedStream,
    RefreshFailure::RefusedRegistry,
];

/// One genuine same-tag failure for `image refresh`, then every preservation
/// oracle. A fresh registry/server per row keeps the denial and drop rows from
/// affecting each other.
fn refresh_same_tag_failure(mode: RefreshFailure, retained: bool) {
    let context = format!("{mode:?} (retained default: {retained})");
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let tag = format!("{}/images:refresh-target", server.host);
    let tag_route = "/v2/images/manifests/refresh-target".to_string();
    server.image("images", "refresh-target", &a);
    success(&h.refresh(Some(&tag)));
    complete(&h.cache(), &tag);

    // Ambient selection baselines: an explicit refresh may not rewrite them.
    let user = h.home.join(".config/agent-vm/config.toml");
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::write(&user, "image = \"localhost:1/user:tag\"\n").unwrap();
    let project = h.root.path().join("project/.agent-vm/config.toml");
    fs::create_dir_all(project.parent().unwrap()).unwrap();
    fs::write(&project, "image = \"localhost:1/project:tag\"\n").unwrap();
    let user_bytes = fs::read(&user).unwrap();
    let project_bytes = fs::read(&project).unwrap();

    let fallback = retained.then(|| {
        let d = h.image(&ArchiveSpec {
            marker: "s2-retained-d".into(),
            ..Default::default()
        });
        let pin = server.image("images", "s2-retained-d", &d);
        success(&h.set_default(&pin));
        RetainedFallback {
            record: fs::read(h.record()).unwrap(),
            artifacts: ReferenceSnapshot::take(&h.cache(), &pin, &d),
            pin,
        }
    });
    let baseline = RefreshBaseline::take(&h, &tag, &a);

    match mode {
        RefreshFailure::InterruptedStream => {
            let b = h.image(&ArchiveSpec {
                marker: "s2-interrupted".into(),
                ..Default::default()
            });
            server.image("images", "refresh-target", &b);
            let ready = server.stall_blob(&format!("/v2/images/blobs/{}", b.written.layer_digest));
            let mut child = h
                .command()
                .args(["image", "refresh", "--image", &tag])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            if ready.recv_timeout(Duration::from_secs(30)).is_err() {
                child.kill().unwrap();
                child.wait().unwrap();
                server.release_blob();
                panic!("{context}: native partial blob handshake missing");
            }
            // Closing the partial response is a native application failure, not a
            // killed process; the recorded fixture errors are the useful signal.
            server.release_blob();
            let out = collect_bounded(child);
            assert_eq!(server.errors(), Vec::<String>::new(), "{context}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("error decoding response body"),
                "{context}: a truncated body must surface as a native stream error"
            );
            assert!(
                !out.status.success(),
                "{context}: a truncated blob stream must fail:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        RefreshFailure::RefusedRegistry => {
            drop(server);
            let out = h.refresh(Some(&tag));
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !out.status.success(),
                "{context}: an unreachable registry must fail:\n{stderr}"
            );
            assert!(
                stderr.contains("error sending request")
                    || stderr.contains("Connection refused")
                    || stderr.contains("connection refused"),
                "{context}: the failure must be the refused connection: {stderr}"
            );
        }
        RefreshFailure::AuthDenied => {
            server.deny_manifest(&tag_route);
            let denied_before = server.denied_requests().len();
            let requests_before = server.count();
            let out = h.refresh(Some(&tag));
            assert!(
                !out.status.success(),
                "{context}: a denied manifest must fail:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("Not authorized") && stderr.contains(&tag_route),
                "{context}: the failure must name the denied manifest: {stderr}"
            );
            let denied = &server.denied_requests()[denied_before..];
            assert!(
                !denied.is_empty()
                    && denied
                        .iter()
                        .all(|(path, status)| path == &tag_route && *status == 401),
                "{context}: the denial oracle needs the exact cached tag route/401, got {denied:?}"
            );
            assert!(
                server.requests()[requests_before..]
                    .iter()
                    .any(|(_, path)| path == &tag_route),
                "{context}: the refresh never re-resolved the cached tag"
            );
        }
        _ => {
            let bad = match mode {
                RefreshFailure::DigestMismatch => h.image(&ArchiveSpec {
                    marker: "s2-digest-mismatch".into(),
                    layer: LayerContent::DigestMismatch,
                    ..Default::default()
                }),
                RefreshFailure::NotATar => h.image(&ArchiveSpec {
                    marker: "s2-not-a-tar".into(),
                    layer: LayerContent::NotATar,
                    ..Default::default()
                }),
                RefreshFailure::MissingBlob => h.image(&ArchiveSpec {
                    marker: "s2-missing-blob".into(),
                    omit_layer_blob: true,
                    ..Default::default()
                }),
                RefreshFailure::ForeignIndex => h.image(&ArchiveSpec {
                    marker: "s2-foreign".into(),
                    config_platform: PlatformSpec::Foreign,
                    descriptor_platform: PlatformSpec::Foreign,
                    ..Default::default()
                }),
                RefreshFailure::AuthDenied
                | RefreshFailure::InterruptedStream
                | RefreshFailure::RefusedRegistry => unreachable!("handled above"),
            };
            if mode == RefreshFailure::ForeignIndex {
                // A genuine index with no host child: native index resolution must
                // fail, not merely a direct-config platform check.
                server.image("images", "s2-foreign-child", &bad);
                server.index("images", "refresh-target", bad.index.clone());
            } else {
                server.image("images", "refresh-target", &bad);
            }
            let out = h.refresh(Some(&tag));
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !out.status.success(),
                "{context}: the invalid re-point must fail:\n{stderr}"
            );
            // Fail for the *intended* boundary: a 404 or a parse slip would also
            // be "nonzero" while proving nothing about the content class.
            let expected = match mode {
                RefreshFailure::DigestMismatch => "Invalid digest",
                RefreshFailure::NotATar => "tar ingestion failed",
                RefreshFailure::MissingBlob => "fixture missing",
                RefreshFailure::ForeignIndex => {
                    "no entry found in image index manifest matching client's default platform"
                }
                RefreshFailure::AuthDenied
                | RefreshFailure::InterruptedStream
                | RefreshFailure::RefusedRegistry => unreachable!("handled above"),
            };
            assert!(
                stderr.contains(expected),
                "{context}: failed at an unintended boundary ({expected}): {stderr}"
            );
        }
    }

    baseline.unchanged(&h, &tag);
    assert_eq!(
        fs::read(&user).unwrap(),
        user_bytes,
        "{context}: user config"
    );
    assert_eq!(
        fs::read(&project).unwrap(),
        project_bytes,
        "{context}: project config"
    );
    match fallback {
        Some(fallback) => {
            assert_eq!(h.selected(), fallback.pin, "{context}: retained selection");
            assert_eq!(
                fs::read(h.record()).unwrap(),
                fallback.record,
                "{context}: the retained record moved"
            );
            complete(&h.cache(), &fallback.pin);
            fallback.artifacts.unchanged();
        }
        None => assert!(
            !h.record().exists(),
            "{context}: a failed explicit refresh must retain nothing"
        ),
    }
}

/// S2/AC5: every listed native failure against the **same** cached tag leaves the
/// prior usable A content and the absent retained record untouched.
#[test]
fn refresh_same_tag_failures_preserve_cached_a() {
    for mode in REFRESH_FAILURES {
        refresh_same_tag_failure(mode, false);
    }
}

/// S2/AC5: the same rows while a separate retained fallback exists — the failed
/// refresh of T must not select, replace or disturb it.
#[test]
fn refresh_same_tag_failures_preserve_cached_a_and_the_retained_default() {
    for mode in REFRESH_FAILURES {
        refresh_same_tag_failure(mode, true);
    }
}

/// S2: a killed client mid-download (before native publication) preserves the
/// cached tag and releases the acquisition guard. This is prepublication
/// preservation, not a general process-death rollback guarantee.
#[test]
fn refresh_killed_during_download_preserves_cached_a_and_releases_the_guard() {
    for retained in [false, true] {
        let context = format!("killed mid-download (retained default: {retained})");
        let h = Harness::new();
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let tag = format!("{}/images:refresh-target", server.host);
        server.image("images", "refresh-target", &a);
        success(&h.refresh(Some(&tag)));
        let fallback = retained.then(|| {
            let d = h.image(&ArchiveSpec {
                marker: "s2-kill-retained".into(),
                ..Default::default()
            });
            let pin = server.image("images", "s2-kill-retained", &d);
            success(&h.set_default(&pin));
            RetainedFallback {
                record: fs::read(h.record()).unwrap(),
                artifacts: ReferenceSnapshot::take(&h.cache(), &pin, &d),
                pin,
            }
        });
        let baseline = RefreshBaseline::take(&h, &tag, &a);
        let b = h.image(&ArchiveSpec {
            marker: "s2-kill-b".into(),
            ..Default::default()
        });
        server.image("images", "refresh-target", &b);
        let ready = server.stall_blob(&format!("/v2/images/blobs/{}", b.written.layer_digest));
        let mut child = h
            .command()
            .args(["image", "refresh", "--image", &tag])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        if ready.recv_timeout(Duration::from_secs(30)).is_err() {
            child.kill().unwrap();
            child.wait().unwrap();
            server.release_blob();
            panic!("{context}: native blob request handshake missing");
        }
        child.kill().unwrap();
        child.wait().unwrap();
        server.release_blob();
        baseline.unchanged(&h, &tag);
        assert_guard_free(&guard_path(&h.cache(), &tag));
        match fallback {
            Some(fallback) => {
                assert_eq!(h.selected(), fallback.pin, "{context}");
                assert_eq!(fs::read(h.record()).unwrap(), fallback.record, "{context}");
                complete(&h.cache(), &fallback.pin);
                fallback.artifacts.unchanged();
            }
            None => assert!(!h.record().exists(), "{context}"),
        }
    }
}

/// S2: the default tier's own failure rows. A bare refresh of the immutable
/// recommendation must leave the previous cache key, (absent or exactly
/// retained) record and artifacts untouched — no adoption on failure, and no
/// version-1 retained default invented to carry a mutable tag.
#[test]
fn bare_refresh_failure_preserves_the_default_tier_key() {
    for retained in [false, true] {
        let context = format!("default tier (retained: {retained})");
        let h = Harness::new();
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let pin = server.image("images", "default-tier", &a);
        if retained {
            success(&bounded(
                h.command()
                    .env("AGENT_VM_TEST_DEFAULT_IMAGE", &pin)
                    .args(["image", "refresh"]),
            ));
            assert_eq!(h.selected(), pin);
        } else {
            success(&h.refresh(Some(&pin)));
            assert!(!h.record().exists());
        }
        complete(&h.cache(), &pin);
        let baseline = RefreshBaseline::take(&h, &pin, &a);
        let record = fs::read(h.record()).ok();
        // The immutable route the recommendation names stops being served.
        let manifest_route = format!("/v2/images/manifests/{}", pin.rsplit('@').next().unwrap());
        server.remove(&manifest_route);
        let requests_before = server.requests().len();
        let out = bounded(
            h.command()
                .env("AGENT_VM_TEST_DEFAULT_IMAGE", &pin)
                .args(["image", "refresh"]),
        );
        assert!(
            !out.status.success(),
            "{context}: an unserved immutable target must fail:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            server.requests()[requests_before..]
                .iter()
                .any(|(_, path)| path == &manifest_route),
            "{context}: the failing refresh never requested the removed immutable manifest {manifest_route}"
        );
        baseline.unchanged(&h, &pin);
        assert_eq!(fs::read(h.record()).ok(), record, "{context}: record bytes");
        if !retained {
            assert!(
                !h.record().exists(),
                "{context}: a failed acquisition must not adopt a default"
            );
        }
    }
}

/// B2: an immutable multiarch index I resolves to host child M. Refresh succeeds
/// without a VM, the requested cache key I identifies M, an explicit refresh
/// retains nothing, and a bare refresh retains **exactly I** (not M).
/// Build an actual multiarch index from independent host/foreign manifests.
fn multiarch_index(h: &Harness, server: &Server, tag: &str, host: &Image) -> String {
    let foreign = h.image(&ArchiveSpec {
        marker: format!("{tag}-foreign"),
        config_platform: PlatformSpec::Foreign,
        descriptor_platform: PlatformSpec::Foreign,
        ..Default::default()
    });
    server.image("images", &format!("{tag}-foreign"), &foreign);
    let mut index: serde_json::Value = serde_json::from_slice(&host.index).unwrap();
    index["manifests"].as_array_mut().unwrap().push(
        serde_json::from_slice::<serde_json::Value>(&foreign.index).unwrap()["manifests"][0]
            .clone(),
    );
    server.index("images", tag, serde_json::to_vec(&index).unwrap())
}

#[test]
fn refresh_resolves_an_immutable_index_to_the_host_child_without_retaining_m() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    // Register the child manifest/config/layer routes, then the index bytes that
    // select that child on this host.
    let child_pin = server.image("images", "child", &a);
    let index_pin = multiarch_index(&h, &server, "indexed", &a);
    let index_digest = index_pin.rsplit('@').next().unwrap().to_owned();
    let child_digest = a.written.manifest_digest.clone();
    assert_ne!(
        index_digest, child_digest,
        "the fixture must be a real index"
    );

    success(&h.refresh(Some(&index_pin)));
    // Requested key I: complete metadata naming the resolved host child M.
    assert_eq!(cached_manifest_digest(&h.cache(), &index_pin), child_digest);
    let metadata: serde_json::Value = serde_json::from_slice(
        &fs::read(
            h.cache()
                .image_metadata_path(&index_pin.parse::<Reference>().unwrap()),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(metadata["config_digest"], a.written.config_digest);
    assert!(
        metadata["raw_config_json"]
            .as_str()
            .unwrap()
            .contains(&format!(
                "\"architecture\":\"{}\"",
                image_archive::host_arch()
            ))
    );
    assert!(!h.record().exists(), "an explicit refresh never retains");
    // The advisory marker names the acquired child under the selected key.
    assert_eq!(
        pulled_marker_digest(&h, &index_pin).as_deref(),
        Some(child_digest.as_str())
    );

    // A fresh bare refresh retains I, not M. A later recommendation J must
    // not move the retained selection, even while Always reacquires I.
    let fresh = Harness::new();
    success(&bounded(
        fresh
            .command()
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &index_pin)
            .args(["image", "refresh"]),
    ));
    assert_eq!(fresh.selected(), index_pin);
    assert_ne!(fresh.selected(), child_pin);
    complete(&fresh.cache(), &index_pin);
    let record = fs::read(fresh.record()).unwrap();
    let j = fresh.image(&ArchiveSpec {
        marker: "J".into(),
        ..Default::default()
    });
    server.image("images", "child-j", &j);
    let index_j = multiarch_index(&fresh, &server, "indexed-j", &j);
    let before = server.requests().len();
    success(&bounded(
        fresh
            .command()
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &index_j)
            .args(["image", "refresh"]),
    ));
    assert_eq!(fs::read(fresh.record()).unwrap(), record);
    assert_eq!(
        cached_manifest_digest(&fresh.cache(), &index_pin),
        child_digest
    );
    let since = &server.requests()[before..];
    assert!(
        since
            .iter()
            .any(|(_, path)| *path == format!("/v2/images/manifests/{index_digest}")),
        "{since:?}"
    );
    assert!(
        !since.iter().any(|(_, path)| *path
            == format!(
                "/v2/images/manifests/{}",
                index_j.rsplit('@').next().unwrap()
            )),
        "{since:?}"
    );
    fresh.no_fallback();
    h.no_fallback();
}

/// Publish an index under `tag` whose `manifests` are exactly `children`, in
/// order. Each child's manifest/config/layer routes are registered first, so the
/// index is the only thing that decides which child a pull lands.
fn ordered_index(server: &Server, tag: &str, children: &[(&str, &Image)]) -> String {
    let mut index: serde_json::Value = serde_json::from_slice(&children[0].1.index).unwrap();
    let descriptors: Vec<serde_json::Value> = children
        .iter()
        .map(|(route, image)| {
            server.image("images", route, image);
            serde_json::from_slice::<serde_json::Value>(&image.index).unwrap()["manifests"][0]
                .clone()
        })
        .collect();
    index["manifests"] = serde_json::Value::Array(descriptors);
    server.index("images", tag, serde_json::to_vec(&index).unwrap())
}

/// S1: the marker `image refresh` writes and the digest the launch update probe
/// compares must be the same *host* child, in both positions, for a mutable tag
/// and for an immutable index, and with two independently known host children in
/// both index orders. Before the fix the producer recorded the host child while
/// the consumer compared an `linux/amd64` entry, so an arm64 host saw a permanent
/// "update available" banner that the suggested refresh could never clear.
#[test]
fn refresh_marker_and_host_update_probe_agree() {
    let h = Harness::new();
    let server = Server::new();
    // This host delays the test process's *first* loopback connect past the
    // probe's own 5s timeout (observed ~13s); warm the path once so the consumer
    // assertions below read a real probe decision instead of that startup delay.
    warm_loopback(&server.host);
    let host = h.image(&ArchiveSpec::default());
    let foreign = h.image(&ArchiveSpec {
        marker: "s1-foreign".into(),
        config_platform: PlatformSpec::Foreign,
        descriptor_platform: PlatformSpec::Foreign,
        ..Default::default()
    });
    let host_digest = host.written.manifest_digest.clone();
    assert_ne!(
        host_digest, foreign.written.manifest_digest,
        "the fixture needs two distinct children"
    );

    // A foreign descriptor must not be selected merely because it comes first.
    for (tag, foreign_first) in [("s1-foreign-first", true), ("s1-host-first", false)] {
        let (first, second) = if foreign_first {
            (("s1-foreign-a", &foreign), ("s1-host-a", &host))
        } else {
            (("s1-host-a", &host), ("s1-foreign-a", &foreign))
        };
        ordered_index(&server, tag, &[first, second]);
        let reference = format!("{}/images:{tag}", server.host);
        success(&h.refresh(Some(&reference)));
        assert_eq!(cached_manifest_digest(&h.cache(), &reference), host_digest);
        complete(&h.cache(), &reference);
        assert_eq!(
            pulled_marker_digest(&h, &reference).as_deref(),
            Some(host_digest.as_str())
        );
        assert_up_to_date(&h, &reference, tag);
    }

    // Move **only** the host child (the foreign descriptor stays as it was): the
    // probe must now report an update, and the refresh it suggests must clear it.
    let next = h.image(&ArchiveSpec {
        marker: "s1-next".into(),
        ..Default::default()
    });
    let next_digest = next.written.manifest_digest.clone();
    assert_ne!(next_digest, host_digest);
    let moved = format!("{}/images:s1-foreign-first", server.host);
    ordered_index(
        &server,
        "s1-foreign-first",
        &[("s1-foreign-a", &foreign), ("s1-next", &next)],
    );
    assert_update_available(&h, &moved, "moved host child");
    success(&h.refresh(Some(&moved)));
    assert_eq!(cached_manifest_digest(&h.cache(), &moved), next_digest);
    assert_eq!(
        pulled_marker_digest(&h, &moved).as_deref(),
        Some(next_digest.as_str())
    );
    complete(&h.cache(), &moved);
    assert_up_to_date(&h, &moved, "after refreshing the moved tag");

    // The immutable index consumer: the manifests selector is the index digest,
    // the marker still records the resolved host child.
    let immutable = ordered_index(
        &server,
        "s1-immutable",
        &[("s1-immutable-host", &host), ("s1-foreign-a", &foreign)],
    );
    success(&h.refresh(Some(&immutable)));
    complete(&h.cache(), &immutable);
    assert_eq!(
        cached_manifest_digest(&h.cache(), &immutable),
        host_digest,
        "the requested index key must identify its resolved host child"
    );
    assert_eq!(
        pulled_marker_digest(&h, &immutable).as_deref(),
        Some(host_digest.as_str())
    );
    assert!(!h.record().exists(), "an explicit refresh never retains");
    assert_up_to_date(&h, &immutable, "immutable index");

    // Two independently known host children in both orders: the cache key and
    // marker must name the **first** eligible descriptor, not the last, and the
    // production consumer must agree with whatever real resolution chose.
    let first_host = h.image(&ArchiveSpec {
        marker: "s1-m1".into(),
        ..Default::default()
    });
    let second_host = h.image(&ArchiveSpec {
        marker: "s1-m2".into(),
        ..Default::default()
    });
    assert_ne!(
        first_host.written.manifest_digest,
        second_host.written.manifest_digest
    );
    for (tag, first, second) in [
        ("s1-duplicate-12", &first_host, &second_host),
        ("s1-duplicate-21", &second_host, &first_host),
    ] {
        let expected = first.written.manifest_digest.clone();
        let first_route = format!("{tag}-first");
        let second_route = format!("{tag}-second");
        let pin = ordered_index(
            &server,
            tag,
            &[
                (first_route.as_str(), first),
                (second_route.as_str(), second),
            ],
        );
        let reference = format!("{}/images:{tag}", server.host);
        success(&h.refresh(Some(&reference)));
        assert_eq!(
            cached_manifest_digest(&h.cache(), &reference),
            expected,
            "{tag}: native resolution must land the first host child"
        );
        assert_eq!(
            pulled_marker_digest(&h, &reference).as_deref(),
            Some(expected.as_str()),
            "{tag}: the marker must record the same child"
        );
        assert_ne!(pin.rsplit('@').next().unwrap(), expected);
        complete(&h.cache(), &reference);
        assert_up_to_date(&h, &reference, tag);
    }
    h.no_fallback();
}

// ===========================================================================
//
// R15 — same-cache/same-reference coordination between helper writers.
//
// Two real CLI processes share one cache and one normalized reference. The
// winner must publish and validate under the launcher guard; a peer must
// snapshot only *after* it acquires the guard, and a failed peer must never
// restore or delete the winner's bytes. Stages are advanced one acknowledged
// checkpoint at a time: no sleeps decide a race, and the guard is probed with a
// real independent `flock`.

/// The mutable reference used by one coordination schedule.
struct Coordinated {
    h: Harness,
    server: Server,
    tag: String,
}

impl Coordinated {
    /// A local cache with `A` already acquired under the mutable tag.
    fn cached_a() -> (Self, Image) {
        let h = Harness::new();
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let tag = format!("{}/images:coordinated", server.host);
        server.image("images", "coordinated", &a);
        success(&h.refresh(Some(&tag)));
        complete(&h.cache(), &tag);
        (Self { h, server, tag }, a)
    }

    /// The same cache with **no** metadata under the tag.
    fn absent() -> Self {
        let h = Harness::new();
        let server = Server::new();
        let tag = format!("{}/images:coordinated", server.host);
        Self { h, server, tag }
    }

    fn b(&self) -> Image {
        let b = self.h.image(&ArchiveSpec {
            marker: "coordinated-B".into(),
            ..Default::default()
        });
        self.server.image("images", "coordinated", &b);
        b
    }

    fn metadata(&self) -> PathBuf {
        self.h
            .cache()
            .image_metadata_path(&self.tag.parse::<Reference>().unwrap())
    }

    fn metadata_bytes(&self) -> Vec<u8> {
        fs::read(self.metadata()).unwrap()
    }

    fn guard(&self) -> PathBuf {
        guard_path(&self.h.cache(), &self.tag)
    }

    fn spawn(&self, gate: &AcquisitionGate) -> Peer {
        Peer::spawn(
            self.h.command(),
            gate,
            &["image", "refresh", "--image", &self.tag],
        )
    }
}

/// Start `Q`, prove it really contends on the launcher guard rather than
/// snapshotting, and leave it blocked before the native pull.
fn start_contending(c: &Coordinated, gate: &mut AcquisitionGate) -> Peer {
    let q = c.spawn(gate);
    gate.expect(AcquisitionStage::BeforeLock)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::LockContended)
        .reply(GateReply::Continue);
    // It is now blocked on the real blocking flock, so no snapshot may arrive.
    gate.expect_none(Duration::from_millis(250));
    assert_guard_held(&c.guard());
    q
}

/// R15 schedule 1: a success P publishes B, then a native-failing Q (started
/// while P still held A) must keep B byte-identical and attempt no restore.
/// Run for both initial states: cached A and absent metadata.
#[test]
fn coordination_success_then_native_failure_keeps_the_winners_bytes() {
    for initial in ["cached", "absent"] {
        let (c, old) = match initial {
            "cached" => {
                let (c, a) = Coordinated::cached_a();
                let snapshot = ReferenceSnapshot::take(&c.h.cache(), &c.tag, &a);
                (c, Some((snapshot, a)))
            }
            _ => (Coordinated::absent(), None),
        };
        let mut gate = AcquisitionGate::new(c.h.root.path());
        let b = c.b();
        let p = c.spawn(&gate);
        gate.expect(AcquisitionStage::BeforeLock)
            .reply(GateReply::Continue);
        let p_snapshot = gate.expect(AcquisitionStage::Snapshot);
        assert_guard_held(&c.guard());

        // Q starts while P still holds the pre-wait state.
        let q = start_contending(&c, &mut gate);

        // P publishes B and validates it.
        p_snapshot.reply(GateReply::Continue);
        gate.expect(AcquisitionStage::NativeOk)
            .reply(GateReply::Continue);
        success(&p.wait());
        assert_eq!(
            cached_manifest_digest(&c.h.cache(), &c.tag),
            b.written.manifest_digest,
            "{initial}: P must publish B"
        );
        let published = c.metadata_bytes();
        let marker = pulled_marker_digest(&c.h, &c.tag);

        // Q gets its snapshot only now, and it is B — never the pre-wait state.
        let q_snapshot = gate.expect(AcquisitionStage::Snapshot);
        assert_guard_held(&c.guard());
        assert_eq!(c.metadata_bytes(), published, "{initial}: Q snapshot B");
        assert_eq!(
            pulled_marker_digest(&c.h, &c.tag),
            marker,
            "{initial}: no Q marker before acquisition"
        );

        // A genuine native failure for Q: its manifest route is gone.
        c.server.remove("/v2/images/manifests/coordinated");
        q_snapshot.reply(GateReply::Continue);
        let out = q.wait();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{initial}: Q must fail:\n{stderr}");
        assert!(
            !stderr.contains("restoring previous reference metadata"),
            "{initial}: a native failure must not attempt a restore:\n{stderr}"
        );
        // No restore/validation checkpoint was reached at all.
        gate.expect_none(Duration::from_millis(250));

        assert_eq!(c.metadata_bytes(), published, "{initial}: B bytes kept");
        assert_eq!(
            cached_manifest_digest(&c.h.cache(), &c.tag),
            b.written.manifest_digest,
            "{initial}: B stays complete"
        );
        complete(&c.h.cache(), &c.tag);
        if let Some((snapshot, _)) = old {
            snapshot.unchanged();
        }
        assert_eq!(
            pulled_marker_digest(&c.h, &c.tag),
            marker,
            "{initial}: Q failure must not move the marker"
        );
        assert!(
            !c.h.record().exists(),
            "{initial}: explicit refresh retains nothing"
        );
        assert_guard_free(&c.guard());
        c.h.no_fallback();
    }
}

/// R15 schedule 2: after P publishes B, Q's native pull of a genuine
/// foreign-platform direct manifest **succeeds**, the wrapper's raw-platform
/// validation fails under the guard, and Q restores exactly B — for an initially
/// absent key that means it must delete only its own acquisition, never P's.
#[test]
fn coordination_postvalidation_failure_restores_the_winners_bytes() {
    for initial in ["cached", "absent"] {
        let (c, old) = match initial {
            "cached" => {
                let (c, a) = Coordinated::cached_a();
                let snapshot = ReferenceSnapshot::take(&c.h.cache(), &c.tag, &a);
                (c, Some((snapshot, a)))
            }
            _ => (Coordinated::absent(), None),
        };
        let mut gate = AcquisitionGate::new(c.h.root.path());
        let b = c.b();
        let p = c.spawn(&gate);
        gate.expect(AcquisitionStage::BeforeLock)
            .reply(GateReply::Continue);
        let p_snapshot = gate.expect(AcquisitionStage::Snapshot);
        let q = start_contending(&c, &mut gate);
        p_snapshot.reply(GateReply::Continue);
        gate.expect(AcquisitionStage::NativeOk)
            .reply(GateReply::Continue);
        success(&p.wait());
        let published = c.metadata_bytes();
        let b_artifacts = ReferenceSnapshot::take(&c.h.cache(), &c.tag, &b);
        let marker = pulled_marker_digest(&c.h, &c.tag);
        assert_eq!(
            cached_manifest_digest(&c.h.cache(), &c.tag),
            b.written.manifest_digest
        );

        // Q snapshots B, then the tag serves a foreign-platform image whose
        // native pull succeeds and whose validation must fail.
        let q_snapshot = gate.expect(AcquisitionStage::Snapshot);
        assert_eq!(c.metadata_bytes(), published, "{initial}: Q snapshots B");
        let foreign = c.h.image(&ArchiveSpec {
            marker: "coordinated-C".into(),
            config_platform: PlatformSpec::Foreign,
            descriptor_platform: PlatformSpec::Host,
            ..Default::default()
        });
        c.server.image("images", "coordinated", &foreign);
        q_snapshot.reply(GateReply::Continue);
        let native_ok = gate.expect(AcquisitionStage::NativeOk);
        assert_guard_held(&c.guard());
        native_ok.reply(GateReply::Continue);
        let restoring = gate.expect(AcquisitionStage::BeforeRestore);
        assert_guard_held(&c.guard());
        restoring.reply(GateReply::Continue);
        let restored = gate.expect(AcquisitionStage::AfterRestore);
        assert_guard_held(&c.guard());
        restored.reply(GateReply::Continue);
        let out = q.wait();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{initial}: Q must fail:\n{stderr}");
        assert!(
            stderr.contains("restored") && stderr.contains("platform"),
            "{initial}: the explicit validation cause and restore stage must both \
             be reported:\n{stderr}"
        );

        // Q restored exactly B, and nothing of B (or the old A artifacts) moved.
        assert_eq!(c.metadata_bytes(), published, "{initial}: B bytes restored");
        assert_eq!(
            cached_manifest_digest(&c.h.cache(), &c.tag),
            b.written.manifest_digest
        );
        complete(&c.h.cache(), &c.tag);
        b_artifacts.unchanged();
        if let Some((snapshot, _)) = old {
            snapshot.unchanged();
        }
        assert_eq!(pulled_marker_digest(&c.h, &c.tag), marker);
        assert!(!c.h.record().exists());
        assert_guard_free(&c.guard());
        c.h.no_fallback();
    }
}

/// R15 schedule 3: a postvalidation-failing Q holds the guard from its snapshot
/// through validation and restore. P must contend, and the exact pre-Q state
/// (A's bytes, or the file's absence) must be back **before** P can run — which
/// is what catches releasing the guard after the native pull but before the
/// rollback.
#[test]
fn coordination_validation_failure_then_success_restores_before_the_peer_runs() {
    for initial in ["cached", "absent"] {
        let (c, old) = match initial {
            "cached" => {
                let (c, a) = Coordinated::cached_a();
                let snapshot = ReferenceSnapshot::take(&c.h.cache(), &c.tag, &a);
                (c, Some((snapshot, a)))
            }
            _ => (Coordinated::absent(), None),
        };
        let mut gate = AcquisitionGate::new(c.h.root.path());
        let before = if c.metadata().exists() {
            Some(c.metadata_bytes())
        } else {
            assert!(old.is_none(), "{initial}: absence must match the fixture");
            None
        };

        // Q snapshots the pre-Q state and genuinely acquires the foreign image.
        let q = c.spawn(&gate);
        gate.expect(AcquisitionStage::BeforeLock)
            .reply(GateReply::Continue);
        let q_snapshot = gate.expect(AcquisitionStage::Snapshot);
        let foreign = c.h.image(&ArchiveSpec {
            marker: "coordinated-C".into(),
            config_platform: PlatformSpec::Foreign,
            descriptor_platform: PlatformSpec::Host,
            ..Default::default()
        });
        c.server.image("images", "coordinated", &foreign);
        q_snapshot.reply(GateReply::Continue);
        let q_native_ok = gate.expect(AcquisitionStage::NativeOk);

        // P starts (and contends) while Q still owns the guard after native
        // publication.
        let p = c.spawn(&gate);
        gate.expect(AcquisitionStage::BeforeLock)
            .reply(GateReply::Continue);
        gate.expect(AcquisitionStage::LockContended)
            .reply(GateReply::Continue);
        gate.expect_none(Duration::from_millis(250));
        assert_guard_held(&c.guard());

        // Q fails validation, restores, and releases.
        q_native_ok.reply(GateReply::Continue);
        let restoring = gate.expect(AcquisitionStage::BeforeRestore);
        assert_guard_held(&c.guard());
        restoring.reply(GateReply::Continue);
        let restored = gate.expect(AcquisitionStage::AfterRestore);
        assert_guard_held(&c.guard());
        match &before {
            Some(bytes) => assert_eq!(
                &c.metadata_bytes(),
                bytes,
                "{initial}: A restored under guard"
            ),
            None => assert!(
                !c.metadata().exists(),
                "{initial}: absence restored under guard"
            ),
        }
        restored.reply(GateReply::Continue);
        let out = q.wait();
        assert!(!out.status.success(), "{initial}: Q must fail");

        // The exact pre-Q state is back *before* P may proceed.
        match &before {
            Some(bytes) => assert_eq!(&c.metadata_bytes(), bytes, "{initial}: A restored"),
            None => assert!(
                !c.metadata().exists(),
                "{initial}: Q's own acquisition must be removed, not left behind"
            ),
        }
        if let Some((snapshot, _)) = &old {
            snapshot.unchanged();
        }

        // P now snapshots the restored state and publishes B.
        let b = c.b();
        let p_snapshot = gate.expect(AcquisitionStage::Snapshot);
        assert!(
            !c.metadata().exists() == before.is_none(),
            "{initial}: P snapshot"
        );
        p_snapshot.reply(GateReply::Continue);
        gate.expect(AcquisitionStage::NativeOk)
            .reply(GateReply::Continue);
        success(&p.wait());
        assert_eq!(
            cached_manifest_digest(&c.h.cache(), &c.tag),
            b.written.manifest_digest,
            "{initial}: P publishes B after Q's rollback"
        );
        complete(&c.h.cache(), &c.tag);
        if let Some((snapshot, _)) = old {
            snapshot.unchanged();
        }
        assert!(!c.h.record().exists());
        assert_guard_free(&c.guard());
        c.h.no_fallback();
    }
}

/// R15 schedule 4: the restore primitive itself fails. Both stages must be
/// reported, B's artifacts and the marker must survive, no restoration may be
/// claimed, and a later clean acquisition must recover. Repeated on a
/// default-tier target where the failure text must stay safely redacted.
#[test]
fn coordination_restore_failure_reports_both_stages_and_recovers() {
    // Both pre-wait states must preserve a successful peer even if restoration fails.
    for initial in ["cached", "absent"] {
        let (c, old) = if initial == "cached" {
            let (c, a) = Coordinated::cached_a();
            let old = ReferenceSnapshot::take(&c.h.cache(), &c.tag, &a);
            (c, Some(old))
        } else {
            (Coordinated::absent(), None)
        };
        let mut gate = AcquisitionGate::new(c.h.root.path());
        let b = c.b();
        let p = c.spawn(&gate);
        gate.expect(AcquisitionStage::BeforeLock)
            .reply(GateReply::Continue);
        let p_snapshot = gate.expect(AcquisitionStage::Snapshot);
        let q = start_contending(&c, &mut gate);
        p_snapshot.reply(GateReply::Continue);
        gate.expect(AcquisitionStage::NativeOk)
            .reply(GateReply::Continue);
        success(&p.wait());
        let published = c.metadata_bytes();
        let b_artifacts = ReferenceSnapshot::take(&c.h.cache(), &c.tag, &b);
        let marker = pulled_marker_digest(&c.h, &c.tag);

        let q_snapshot = gate.expect(AcquisitionStage::Snapshot);
        assert_eq!(c.metadata_bytes(), published);
        let foreign = c.h.image(&ArchiveSpec {
            marker: "coordinated-C".into(),
            config_platform: PlatformSpec::Foreign,
            descriptor_platform: PlatformSpec::Host,
            ..Default::default()
        });
        c.server.image("images", "coordinated", &foreign);
        q_snapshot.reply(GateReply::Continue);
        gate.expect(AcquisitionStage::NativeOk)
            .reply(GateReply::Continue);
        // The fault runs *before* the restore primitive mutates metadata.
        gate.expect(AcquisitionStage::BeforeRestore)
            .reply(GateReply::FailRestore);
        let out = q.wait();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "the restore failure must fail Q");
        assert!(
            stderr.contains("platform")
                && stderr.contains("restoring previous reference metadata also failed"),
            "both stages must be reported:\n{stderr}"
        );
        assert!(
            !stderr.contains("previous reference metadata was restored"),
            "a failed restore must not claim restoration:\n{stderr}"
        );
        // B's content and every old A artifact survive, and the marker is unmoved.
        b_artifacts.unchanged();
        if let Some(old) = old {
            old.unchanged();
        }
        assert_eq!(pulled_marker_digest(&c.h, &c.tag), marker);
        assert!(!c.h.record().exists());
        // Recovery: the tag serves B again and a clean acquisition succeeds.
        c.server.image("images", "coordinated", &b);
        let recovered = c.h.refresh(Some(&c.tag));
        success(&recovered);
        assert_eq!(
            cached_manifest_digest(&c.h.cache(), &c.tag),
            b.written.manifest_digest
        );
        complete(&c.h.cache(), &c.tag);
        assert_guard_free(&c.guard());
        c.h.no_fallback();
    }

    // Default tier: same fault, redacted output, no adoption or marker.
    let h = Harness::new();
    let server = Server::new();
    // The initial recommendation must be an immutable pin, and its repository
    // name is the private-source sentinel the redacted output may not disclose.
    let foreign = h.image(&ArchiveSpec {
        marker: "coordinated-C".into(),
        config_platform: PlatformSpec::Foreign,
        descriptor_platform: PlatformSpec::Host,
        ..Default::default()
    });
    let private = server.image("private-retained-token", "t", &foreign);
    let mut gate = AcquisitionGate::new(h.root.path());
    let mut command = h.command();
    command.env("AGENT_VM_TEST_DEFAULT_IMAGE", &private);
    let q = Peer::spawn(command, &gate, &["image", "refresh"]);
    gate.expect(AcquisitionStage::BeforeLock)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::Snapshot)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::NativeOk)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::BeforeRestore)
        .reply(GateReply::FailRestore);
    let out = q.wait();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{combined}");
    assert!(
        combined.contains("restoring previous reference metadata also failed")
            && combined.contains("cache recovery is required"),
        "the default tier must keep both stages and the recovery need:\n{combined}"
    );
    assert!(
        !combined.contains("private-retained-token"),
        "the default tier leaked its reference:\n{combined}"
    );
    assert!(!h.record().exists(), "a failed refresh must not adopt");
    h.no_fallback();
}

// ---------------------------------------------------------------------------
//
// Bounded R15 controls beyond the four mandatory schedules.

/// The guard is scoped to one reference in the **actual cache**: an unrelated
/// reference progresses while T is held, a second state root resolving the same
/// persisted cache contends on the same key, and the guard's inode is stable and
/// free again once the helper returns.
#[test]
fn coordination_guard_scope_is_one_reference_in_the_actual_cache() {
    use std::os::unix::fs::MetadataExt;

    // (a) A different reference in the same cache proceeds under T's guard.
    let (c, a) = Coordinated::cached_a();
    let old = ReferenceSnapshot::take(&c.h.cache(), &c.tag, &a);
    let mut gate = AcquisitionGate::new(c.h.root.path());
    let b = c.b();
    let p = c.spawn(&gate);
    gate.expect(AcquisitionStage::BeforeLock)
        .reply(GateReply::Continue);
    let p_snapshot = gate.expect(AcquisitionStage::Snapshot);
    let guard = c.guard();
    assert_guard_held(&guard);
    let inode = fs::metadata(&guard).unwrap().ino();

    let unrelated = c.h.image(&ArchiveSpec {
        marker: "unrelated".into(),
        ..Default::default()
    });
    let unrelated_pin = c.server.image("images", "unrelated", &unrelated);
    // One successful acquisition must progress while T is locked. Do not hide
    // transport/acquisition failures with a retry: they need their own diagnosis.
    success(&c.h.refresh(Some(&unrelated_pin)));
    complete(&c.h.cache(), &unrelated_pin);
    assert_guard_held(&guard);

    p_snapshot.reply(GateReply::Continue);
    gate.expect(AcquisitionStage::NativeOk)
        .reply(GateReply::Continue);
    success(&p.wait());
    assert_eq!(
        cached_manifest_digest(&c.h.cache(), &c.tag),
        b.written.manifest_digest
    );
    complete(&c.h.cache(), &c.tag);
    old.unchanged();
    assert_guard_free(&guard);
    assert_eq!(
        fs::metadata(&guard).unwrap().ino(),
        inode,
        "the guard file must keep one inode across processes"
    );
    c.h.no_fallback();

    // (b) Two state roots that persist the same shared cache resolve the same
    // guard and reference key, so the second really contends.
    let first = Harness::new();
    let second = Harness::new();
    let server = Server::new();
    let shared = first.root.path().join("shared-cache");
    let image = first.image(&ArchiveSpec::default());
    let tag = format!("{}/images:shared", server.host);
    server.image("images", "shared", &image);
    let cache = GlobalCache::new(&shared).unwrap();
    let guard = guard_path(&cache, &tag);
    let mut gate = AcquisitionGate::new(first.root.path());
    let mut p_cmd = first.command();
    p_cmd
        .env("AGENT_VM_SHARE_MSB_CACHE", "1")
        .env("AGENT_VM_MSB_CACHE_DIR", &shared);
    let p = Peer::spawn(p_cmd, &gate, &["image", "refresh", "--image", &tag]);
    gate.expect(AcquisitionStage::BeforeLock)
        .reply(GateReply::Continue);
    let p_snapshot = gate.expect(AcquisitionStage::Snapshot);
    assert_guard_held(&guard);
    let mut q_cmd = second.command();
    q_cmd
        .env("AGENT_VM_SHARE_MSB_CACHE", "1")
        .env("AGENT_VM_MSB_CACHE_DIR", &shared);
    let q = Peer::spawn(q_cmd, &gate, &["image", "refresh", "--image", &tag]);
    gate.expect(AcquisitionStage::BeforeLock)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::LockContended)
        .reply(GateReply::Continue);
    gate.expect_none(Duration::from_millis(250));
    assert_guard_held(&guard);

    p_snapshot.reply(GateReply::Continue);
    gate.expect(AcquisitionStage::NativeOk)
        .reply(GateReply::Continue);
    success(&p.wait());
    gate.expect(AcquisitionStage::Snapshot)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::NativeOk)
        .reply(GateReply::Continue);
    success(&q.wait());
    assert_eq!(
        cached_manifest_digest(&cache, &tag),
        image.written.manifest_digest
    );
    complete(&cache, &tag);
    assert_guard_free(&guard);
    first.no_fallback();
    second.no_fallback();
}

/// The one reference-free contention notice emitted by the acquisition guard.
const GUARD_NOTICE: &str = "waiting for another agent-vm acquisition of this image";

/// T1: the guard wait is observable through a real held descriptor. A peer's
/// refresh emits the fixed notice exactly once while this test holds the
/// reference's own `flock`, then the acquisition succeeds after the release.
/// An uncontended acquisition is silent, and a lock that cannot be opened at
/// all is a state error, not contention.
#[test]
fn refresh_reports_real_guard_contention_once_and_releases_into_success() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let tag = format!("{}/images:guard-notice", server.host);
    server.image("images", "guard-notice", &a);

    // Silent immediate acquisition: no contention, so no notice.
    let immediate = h.refresh(Some(&tag));
    success(&immediate);
    let immediate_stderr = String::from_utf8_lossy(&immediate.stderr);
    assert!(
        !immediate_stderr.contains(GUARD_NOTICE),
        "an uncontended acquisition must be silent: {immediate_stderr}"
    );

    // Hold the exact guard a peer uses, on an independently opened descriptor.
    let cache = h.cache();
    let lock = guard_path(&cache, &tag);
    fs::create_dir_all(lock.parent().unwrap()).unwrap();
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock)
        .expect("open the guard to hold it");
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .expect("this test must hold the guard");

    let mut command = h.command();
    command
        .args(["image", "refresh", "--image", &tag])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn the contending refresh");
    let stderr = child.stderr.take().expect("piped stderr");
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            let _ = sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    let mut before_release = Vec::new();
    loop {
        match receiver.recv_timeout(Duration::from_secs(60)) {
            Ok(line) => {
                before_release.push(line.clone());
                if line.contains(GUARD_NOTICE) {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("no contention notice within 60s; stderr so far: {before_release:?}");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let status = child.wait().expect("reap the exited refresh");
                panic!(
                    "the refresh ended ({status}) before any contention notice; stderr: {before_release:?}"
                );
            }
        }
    }
    assert_eq!(
        before_release
            .iter()
            .filter(|line| line.contains(GUARD_NOTICE))
            .count(),
        1,
        "the notice must be emitted once: {before_release:?}"
    );

    // Release: the same child now acquires and completes.
    drop(held);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let status = loop {
        match child.try_wait().expect("poll the contending refresh") {
            Some(status) => break status,
            None if std::time::Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the contending refresh did not finish after the guard was released");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    // The reader retains every line it forwards, so its complete return is the
    // whole-run oracle. `before_release` is a prefix copy of it; chaining the two
    // counts the held-window lines twice and is not an independent observation.
    let reader_all = reader.join().expect("join the stderr reader");
    assert!(
        status.success(),
        "the released acquisition must succeed: {reader_all:?}"
    );
    assert_eq!(
        reader_all
            .iter()
            .filter(|line| line.contains(GUARD_NOTICE))
            .count(),
        1,
        "the notice must be emitted exactly once: {reader_all:?}"
    );
    complete(&cache, &tag);

    // A hard lock-open failure is a reference-state error, never labelled
    // contention. A directory at the guard path makes `open` fail.
    let other = format!("{}/images:guard-unopenable", server.host);
    let unopenable = guard_path(&cache, &other);
    fs::create_dir_all(&unopenable).unwrap();
    let out = h.refresh(Some(&other));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("opening the image-cache coordination lock failed"),
        "a hard lock-open error must name its own stage: {stderr}"
    );
    assert!(
        !stderr.contains(GUARD_NOTICE),
        "a hard error must not be labelled contention: {stderr}"
    );
    assert!(!h.record().exists());
    h.no_fallback();
}

/// `setup --no-verify` and both `image set-default` pulls enter the same guard
/// before snapshotting; a digest input whose derived child key is identical to
/// the target key completes without nesting the guard.
#[test]
fn coordination_setup_and_set_default_enter_the_same_guard() {
    // setup --no-verify: default tier, adoption only after acquisition.
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin = server.image("images", "entry", &a);
    let mut gate = AcquisitionGate::new(h.root.path());
    let mut setup_cmd = h.command();
    setup_cmd.env("AGENT_VM_TEST_DEFAULT_IMAGE", &pin);
    let setup = Peer::spawn(setup_cmd, &gate, &["setup", "--no-verify"]);
    gate.expect(AcquisitionStage::BeforeLock)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::Snapshot)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::NativeOk)
        .reply(GateReply::Continue);
    success(&setup.wait());
    assert_eq!(h.selected(), pin);
    complete(&h.cache(), &pin);
    h.no_fallback();

    // A tag target: the target key, then the derived child key, each guarded.
    let h2 = Harness::new();
    let server2 = Server::new();
    let a2 = h2.image(&ArchiveSpec::default());
    let tag = format!("{}/images:sd", server2.host);
    let _pin = server2.image("images", "sd", &a2);
    let mut gate2 = AcquisitionGate::new(h2.root.path());
    let sd = Peer::spawn(
        h2.command(),
        &gate2,
        &["image", "set-default", "--image", &tag],
    );
    for _ in 0..2 {
        gate2
            .expect(AcquisitionStage::BeforeLock)
            .reply(GateReply::Continue);
        gate2
            .expect(AcquisitionStage::Snapshot)
            .reply(GateReply::Continue);
        gate2
            .expect(AcquisitionStage::NativeOk)
            .reply(GateReply::Continue);
    }
    success(&sd.wait());
    assert_eq!(
        h2.selected(),
        format!("{}/images@{}", server2.host, a2.written.manifest_digest)
    );
    complete(
        &h2.cache(),
        &format!("{}/images@{}", server2.host, a2.written.manifest_digest),
    );
    h2.no_fallback();

    // A digest input derives the same key twice; sequential guards must not
    // deadlock and the record keeps the direct manifest reference.
    let h3 = Harness::new();
    let server3 = Server::new();
    let a3 = h3.image(&ArchiveSpec::default());
    let pin3 = server3.image("images", "same", &a3);
    let mut gate3 = AcquisitionGate::new(h3.root.path());
    let sd3 = Peer::spawn(
        h3.command(),
        &gate3,
        &["image", "set-default", "--image", &pin3],
    );
    for _ in 0..2 {
        gate3
            .expect(AcquisitionStage::BeforeLock)
            .reply(GateReply::Continue);
        gate3
            .expect(AcquisitionStage::Snapshot)
            .reply(GateReply::Continue);
        gate3
            .expect(AcquisitionStage::NativeOk)
            .reply(GateReply::Continue);
    }
    success(&sd3.wait());
    assert_eq!(h3.selected(), pin3);
    complete(&h3.cache(), &pin3);
    h3.no_fallback();
}

/// B2: `setup --no-verify` retains the exact selected immutable index on a
/// fresh host, and a host already retaining I reacquires I — never a changed
/// recommendation J — preserving record bytes.
#[test]
fn setup_no_verify_adopts_a_fresh_index_and_reacquires_a_retained_one() {
    let fresh = Harness::new();
    let server = Server::new();
    let a = fresh.image(&ArchiveSpec::default());
    let child_pin = server.image("images", "child", &a);
    let index_pin = multiarch_index(&fresh, &server, "indexed", &a);
    let child_digest = a.written.manifest_digest.clone();
    assert_ne!(index_pin, child_pin, "the fixture must be a real index");

    success(&bounded(
        fresh
            .command()
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &index_pin)
            .args(["setup", "--no-verify"]),
    ));
    assert_eq!(fresh.selected(), index_pin, "retain exactly I, not M");
    assert_eq!(
        cached_manifest_digest(&fresh.cache(), &index_pin),
        child_digest
    );
    complete(&fresh.cache(), &index_pin);
    fresh.no_fallback();

    // A second host adopts I, then a later recommendation J appears.
    let h = Harness::new();
    success(&bounded(
        h.command()
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &index_pin)
            .args(["setup", "--no-verify"]),
    ));
    assert_eq!(h.selected(), index_pin);
    let record = fs::read(h.record()).unwrap();
    let j = h.image(&ArchiveSpec {
        marker: "index-J".into(),
        ..Default::default()
    });
    let _child_j = server.image("images", "child-j", &j);
    let index_j = multiarch_index(&h, &server, "indexed-j", &j);
    assert_ne!(index_j, index_pin);
    let index_digest = index_pin.rsplit('@').next().unwrap().to_owned();
    let index_j_digest = index_j.rsplit('@').next().unwrap().to_owned();
    let before = server.requests().len();
    success(&bounded(
        h.command()
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &index_j)
            .args(["setup", "--no-verify"]),
    ));
    assert_eq!(
        fs::read(h.record()).unwrap(),
        record,
        "record bytes preserved"
    );
    assert_eq!(h.selected(), index_pin);
    let since = &server.requests()[before..];
    assert!(
        since
            .iter()
            .any(|(_, path)| *path == format!("/v2/images/manifests/{index_digest}")),
        "the retained index digest must be re-resolved: {since:?}"
    );
    assert!(
        !since
            .iter()
            .any(|(_, path)| *path == format!("/v2/images/manifests/{index_j_digest}")),
        "the changed recommendation must never be acquired: {since:?}"
    );
    complete(&h.cache(), &index_pin);
    h.no_fallback();
}

/// R14: injected source chains must survive only an explicit refresh; default
/// refresh and set-default preserve both safe stages but discard private URLs.
#[test]
fn postvalidation_faults_keep_explicit_causes_and_redact_default_operations() {
    for operation in ["explicit-refresh", "default-refresh", "set-default"] {
        let h = Harness::new();
        let server = Server::new();
        let image = h.image(&ArchiveSpec::default());
        let pin = server.image("private-reference-token", "fault", &image);
        let mut gate = AcquisitionGate::new(h.root.path());
        let mut command = h.command();
        command.env("AGENT_VM_DEBUG_CONFIG", "1");
        let args = match operation {
            "explicit-refresh" => vec!["image", "refresh", "--image", pin.as_str()],
            "default-refresh" => {
                command.env("AGENT_VM_TEST_DEFAULT_IMAGE", &pin);
                vec!["image", "refresh"]
            }
            _ => vec!["image", "set-default", "--image", pin.as_str()],
        };
        let peer = Peer::spawn(command, &gate, &args);
        gate.expect(AcquisitionStage::BeforeLock)
            .reply(GateReply::Continue);
        gate.expect(AcquisitionStage::Snapshot)
            .reply(GateReply::Continue);
        let acquired = gate.expect(AcquisitionStage::NativeOk);
        let lock = guard_path(&h.cache(), &pin);
        assert_guard_held(&lock);
        complete(&h.cache(), &pin); // fault never synthesizes native success
        acquired.reply(GateReply::FailValidation);
        let restoring = gate.expect(AcquisitionStage::BeforeRestore);
        assert_guard_held(&lock);
        restoring.reply(GateReply::FailRestore);
        let out = peer.wait();
        assert!(!out.status.success());
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            text.contains("restoring previous reference metadata also failed"),
            "{operation}: {text}"
        );
        assert!(
            text.contains("cache recovery is required"),
            "{operation}: {text}"
        );
        assert!(
            !text.contains("previous reference metadata was restored"),
            "{operation}: {text}"
        );
        for private in [
            "private-validation-source.invalid",
            "private-restore-source.invalid",
        ] {
            assert_eq!(
                text.contains(private),
                operation == "explicit-refresh",
                "{operation}: {text}"
            );
        }
        if operation != "explicit-refresh" {
            assert!(
                !text.contains("private-reference-token"),
                "{operation}: {text}"
            );
        }
        if operation == "set-default" {
            assert!(
                text.contains("this command did not change the retained default"),
                "{text}"
            );
        }
        assert!(!h.record().exists());
        assert!(pulled_marker_digest(&h, &pin).is_none());
        assert_guard_free(&lock);
        h.no_fallback();
    }
}

/// R4/R5: successful native acquisition, not only the debug notice, identifies
/// the selected tier. Each served reference carries different genuine bytes.
#[test]
fn refresh_selection_and_broken_config_recovery_acquire_only_the_winning_tier() {
    struct Row {
        name: &'static str,
        cli: bool,
        env: Option<&'static str>,
        user: bool,
        project: bool,
        retained: bool,
        broken: bool,
        expected: &'static str,
    }
    let rows = [
        Row {
            name: "cli",
            cli: true,
            env: Some("env"),
            user: true,
            project: true,
            retained: true,
            broken: false,
            expected: "cli",
        },
        Row {
            name: "env",
            cli: false,
            env: Some("env"),
            user: true,
            project: true,
            retained: false,
            broken: false,
            expected: "env",
        },
        Row {
            name: "user",
            cli: false,
            env: None,
            user: true,
            project: true,
            retained: false,
            broken: false,
            expected: "user",
        },
        Row {
            name: "empty-env-user",
            cli: false,
            env: Some(""),
            user: true,
            project: true,
            retained: false,
            broken: false,
            expected: "user",
        },
        Row {
            name: "project",
            cli: false,
            env: None,
            user: false,
            project: true,
            retained: false,
            broken: false,
            expected: "project",
        },
        Row {
            name: "empty-env-project",
            cli: false,
            env: Some(""),
            user: false,
            project: true,
            retained: false,
            broken: false,
            expected: "project",
        },
        Row {
            name: "retained",
            cli: false,
            env: None,
            user: false,
            project: false,
            retained: true,
            broken: false,
            expected: "retained",
        },
        Row {
            name: "empty-env-retained",
            cli: false,
            env: Some(""),
            user: false,
            project: false,
            retained: true,
            broken: false,
            expected: "retained",
        },
        Row {
            name: "recommendation",
            cli: false,
            env: None,
            user: false,
            project: false,
            retained: false,
            broken: false,
            expected: "recommendation",
        },
        Row {
            name: "broken-cli",
            cli: true,
            env: Some("env"),
            user: true,
            project: true,
            retained: false,
            broken: true,
            expected: "cli",
        },
        Row {
            name: "broken-env",
            cli: false,
            env: Some("env"),
            user: true,
            project: true,
            retained: false,
            broken: true,
            expected: "env",
        },
        Row {
            name: "broken-default",
            cli: false,
            env: None,
            user: true,
            project: true,
            retained: true,
            broken: true,
            expected: "retained",
        },
    ];
    for row in rows {
        let h = Harness::new();
        let server = Server::new();
        let mut tiers = BTreeMap::new();
        for name in [
            "cli",
            "env",
            "user",
            "project",
            "retained",
            "recommendation",
        ] {
            let image = h.image(&ArchiveSpec {
                marker: name.into(),
                ..Default::default()
            });
            let pin = server.image(name, "selected", &image);
            let reference = if matches!(name, "retained" | "recommendation") {
                pin
            } else {
                format!("{}/{name}:selected", server.host)
            };
            tiers.insert(name, (reference, image));
        }
        let project = h.root.path().join("project");
        fs::create_dir(&project).unwrap();
        if row.user || row.retained {
            fs::create_dir_all(h.home.join(".config/agent-vm")).unwrap();
        }
        if row.user {
            fs::write(
                h.home.join(".config/agent-vm/config.toml"),
                if row.broken {
                    "not valid TOML = [".to_owned()
                } else {
                    format!("image = {:?}\n", tiers["user"].0)
                },
            )
            .unwrap();
        }
        if row.project {
            fs::create_dir(project.join(".agent-vm")).unwrap();
            fs::write(
                project.join(".agent-vm/config.toml"),
                format!("image = {:?}\n", tiers["project"].0),
            )
            .unwrap();
        }
        let record_before = row.retained.then(|| {
            let bytes = format!(
                "{{ \"version\": 1, \"image\": {:?} }}\n",
                tiers["retained"].0
            )
            .into_bytes();
            fs::write(h.record(), &bytes).unwrap();
            bytes
        });
        let mut command = h.command();
        command
            .current_dir(&project)
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &tiers["recommendation"].0)
            .args(["image", "refresh"]);
        if let Some(env) = row.env {
            command.env(
                "AGENT_VM_IMAGE_TAG",
                if env.is_empty() { "" } else { &tiers[env].0 },
            );
        }
        if row.cli {
            command.args(["--image", &tiers["cli"].0]);
        }
        let out = bounded(&mut command);
        success(&out);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            stdout.contains("configured image settings could not be read"),
            row.broken,
            "{}: {stdout}",
            row.name
        );
        let (winner, image) = &tiers[row.expected];
        assert_eq!(
            cached_manifest_digest(&h.cache(), winner),
            image.written.manifest_digest,
            "{}",
            row.name
        );
        complete(&h.cache(), winner);
        for (_, path) in server.requests() {
            if path == "/v2/" {
                continue;
            }
            assert!(
                path.starts_with(&format!("/v2/{}/", row.expected)),
                "{}: losing tier requested {path}",
                row.name
            );
        }
        match record_before {
            Some(bytes) => assert_eq!(
                fs::read(h.record()).unwrap(),
                bytes,
                "{}: retained record moved",
                row.name
            ),
            None if row.expected == "recommendation" => assert_eq!(h.selected(), *winner),
            None => assert!(
                !h.record().exists(),
                "{}: explicit tier adopted a fallback",
                row.name
            ),
        }
        h.no_fallback();
    }
}

/// Native Never-completeness is not sufficient: a different, fully materialized
/// host image under the requested key must not be mistaken for this result.
#[test]
fn refresh_rejects_complete_cache_result_identity_disagreement_and_restores_metadata() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let b = h.image(&ArchiveSpec {
        marker: "identity-B".into(),
        ..Default::default()
    });
    let tag = format!("{}/images:identity", server.host);
    server.image("images", "identity", &a);
    let pin_b = server.image("images", "b", &b);
    success(&h.refresh(Some(&tag)));
    success(&h.refresh(Some(&pin_b)));
    let cache = h.cache();
    let metadata = cache.image_metadata_path(&tag.parse::<Reference>().unwrap());
    let prior = fs::read(&metadata).unwrap();
    let marker = pulled_marker_digest(&h, &tag);
    let mut gate = AcquisitionGate::new(h.root.path());
    let peer = Peer::spawn(h.command(), &gate, &["image", "refresh", "--image", &tag]);
    gate.expect(AcquisitionStage::BeforeLock)
        .reply(GateReply::Continue);
    gate.expect(AcquisitionStage::Snapshot)
        .reply(GateReply::Continue);
    let acquired = gate.expect(AcquisitionStage::NativeOk);
    let lock = guard_path(&cache, &tag);
    assert_guard_held(&lock);
    // Controlled fault at the validation boundary, not a claim that arbitrary
    // external writers participate in the launcher guard's rollback protocol.
    let b_metadata = cache.image_metadata_path(&pin_b.parse::<Reference>().unwrap());
    fs::write(&metadata, fs::read(b_metadata).unwrap()).unwrap();
    complete(&cache, &tag); // calibrate that completeness alone accepts B
    assert_eq!(
        cached_manifest_digest(&cache, &tag),
        b.written.manifest_digest
    );
    acquired.reply(GateReply::Continue);
    gate.expect(AcquisitionStage::BeforeRestore)
        .reply(GateReply::Continue);
    let restored = gate.expect(AcquisitionStage::AfterRestore);
    assert_guard_held(&lock);
    assert_eq!(fs::read(&metadata).unwrap(), prior);
    restored.reply(GateReply::Continue);
    let out = peer.wait();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("identity"));
    assert_eq!(pulled_marker_digest(&h, &tag), marker);
    assert!(!h.record().exists());
    complete(&cache, &tag);
    h.no_fallback();
}

/// Retention publication and advisory marker writes have different policies:
/// a failed record lock fails refresh; a failed marker write only warns.
#[test]
fn default_refresh_requires_adoption_but_not_a_writable_advisory_marker() {
    for fail_record in [false, true] {
        let h = Harness::new();
        let server = Server::new();
        let image = h.image(&ArchiveSpec::default());
        let pin = server.image("images", "publication", &image);
        if fail_record {
            fs::create_dir_all(h.record().parent().unwrap()).unwrap();
            fs::create_dir(h.record().with_file_name("default-image.lock")).unwrap();
        } else {
            fs::create_dir_all(&h.state).unwrap();
            fs::write(h.state.join("pulled-digests"), b"not a directory").unwrap();
        }
        let out = bounded(
            h.command()
                .env("AGENT_VM_TEST_DEFAULT_IMAGE", &pin)
                .args(["image", "refresh"]),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.success(), !fail_record, "{stderr}");
        complete(&h.cache(), &pin);
        if fail_record {
            assert!(!h.record().exists());
            assert!(
                stderr.contains("retaining the selected default boot image"),
                "{stderr}"
            );
        } else {
            assert_eq!(h.selected(), pin);
            assert!(
                stderr.contains("failed to record the refreshed image digest"),
                "{stderr}"
            );
        }
        h.no_fallback();
    }
}
