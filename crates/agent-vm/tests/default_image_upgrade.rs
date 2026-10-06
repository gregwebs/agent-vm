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
#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/image_archive.rs"]
mod image_archive;
#[path = "support/oci_registry.rs"]
mod oci_registry;
mod support;
use image_archive::{ArchiveSpec, LayerContent, PlatformSpec};
use oci_registry::{Image, Server};

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
            let status = Command::new(bin.join(name))
                .env_clear()
                .env("HOST_CALL_LOG", &log)
                .arg("fixture-calibration")
                .status()
                .unwrap();
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
    fn upgrade(&self, target: &str) -> Output {
        self.run(&["upgrade", "--image", target])
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
        let reference: Reference = pin.parse().unwrap();
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
        let mut paths = vec![
            metadata_path,
            cache.fsmeta_erofs_path(&manifest),
            descriptor.clone(),
        ];
        for layer in metadata["layers"].as_array().unwrap() {
            paths
                .push(cache.layer_erofs_path(&layer["diff_id"].as_str().unwrap().parse().unwrap()));
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
        let files = paths
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).unwrap();
                (
                    path,
                    (bytes.len() as u64, image_archive::sha256_hex(&bytes)),
                )
            })
            .collect();
        Self {
            record: fs::read(h.record()).unwrap(),
            files,
        }
    }
    fn unchanged(&self, h: &Harness, pin: &str) {
        assert_eq!(fs::read(h.record()).unwrap(), self.record);
        self.artifacts_unchanged(h, pin);
    }
    fn artifacts_unchanged(&self, h: &Harness, pin: &str) {
        for (path, (len, hash)) in &self.files {
            let bytes = fs::read(path).unwrap();
            assert_eq!(bytes.len() as u64, *len, "{}", path.display());
            assert_eq!(
                image_archive::sha256_hex(&bytes),
                *hash,
                "{}",
                path.display()
            );
        }
        complete(&h.cache(), pin);
        h.no_fallback();
    }
}

#[test]
fn explicit_tag_and_index_upgrade_populate_pin_and_preserve_old_artifacts() {
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
    success(&h.upgrade(&tag));
    assert_eq!(h.selected(), pin_a);
    complete(&h.cache(), &pin_a);
    let snapshot = Snapshot::take(&h, &pin_a, &a);
    let pin_b = server.image("private-repo", "moving", &b);
    success(&h.upgrade(&tag));
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
    success(&h.upgrade(&index_pin));
    assert_eq!(h.selected(), pin_b);
    success(&h.upgrade(&format!(
        "{}/private-repo:ignored@{}",
        server.host, b.written.manifest_digest
    )));
    let formatted = format!("{{ \"image\": \"{pin_b}\", \"version\": 1 }}\n");
    fs::write(h.record(), &formatted).unwrap();
    success(&h.upgrade(&pin_b));
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
    success(&h.upgrade(&pin_a));
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
        let output = h.upgrade(&pin);
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
            assert_eq!(h.upgrade(&deceptive).status.code(), Some(1));
            before.unchanged(&h, &pin_a);
        }
    }
    let before = Snapshot::take(&h, &pin_a, &a);
    assert_eq!(
        h.upgrade(&format!("{}/images:missing", server.host))
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
        h.upgrade(&format!("{}/images:shared-bad", server.host))
            .status
            .code(),
        Some(1)
    );
    before.unchanged(&h, &pin_a);
    assert!(
        !server.requests.lock().unwrap()[start..]
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
    let out = h.upgrade(&pin_b);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("publishing"));
    complete(&h.cache(), &pin_b);
    before.unchanged(&h, &pin_a);
}

#[test]
fn actual_usage_health_and_config_boundaries_do_not_choose_upgrade_target() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin = server.image("images", "a", &a);
    for args in [
        vec!["upgrade", "--help"],
        vec!["help", "upgrade"],
        vec!["upgrade"],
        vec!["upgrade", "--image", "/path"],
        vec!["upgrade", "--image", "a:tag", "--yes"],
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
            assert!(String::from_utf8_lossy(&out.stderr).contains("shell --image"));
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
            .args(["upgrade"]),
    );
    assert_eq!(missing.status.code(), Some(2));
    assert!(!h.record().exists());
    assert_eq!(server.count(), 0);
    let out = bounded(
        h.command()
            .env("AGENT_VM_IMAGE_TAG", std::ffi::OsStr::from_bytes(b"\xff"))
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", "invalid")
            .args(["upgrade", "--image", &pin]),
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
        assert_eq!(h.upgrade(&pin).status.code(), Some(1));
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
    success(&h.upgrade(&pin_a));
    let b = h.image(&ArchiveSpec {
        marker: "interrupted".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "b", &b);
    let before = Snapshot::take(&h, &pin_a, &a);
    let ready = server.stall_blob(&format!("/v2/images/blobs/{}", b.written.layer_digest));
    let mut child = h
        .command()
        .args(["upgrade", "--image", &pin_b])
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
        .args(["upgrade", "--image", &pin_b])
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
    assert_eq!(out.status.code(), Some(1));
    before.unchanged(&h, &pin_a);
    let host = server.host.clone();
    drop(server);
    let before = Snapshot::take(&h, &pin_a, &a);
    let out = h.upgrade(&format!("{host}/images:unavailable"));
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
            .args(["upgrade", "--image", &pin]),
    );
    success(&out);
    complete(&GlobalCache::new(&shared).unwrap(), &pin);
    // Persisted native redirect is used after removing the opt-in env flag.
    success(&h.upgrade(&pin));
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
        .args(["upgrade", "--image", &pin_b])
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
    success(&h.upgrade(&pin_b));
    assert_eq!(fs::read(h.record()).unwrap(), formatted);
    h.no_fallback();
}

#[test]
fn upgrade_preserves_all_overrides_and_default_diagnostic_redaction() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin = server.image("private-marker", "a", &a);
    let user = h.home.join(".config/agent-vm/config.toml");
    let project = h.root.path().join(".agent-vm/config.toml");
    fs::create_dir_all(user.parent().unwrap()).unwrap();
    fs::create_dir_all(project.parent().unwrap()).unwrap();
    fs::write(&user, "image = \"localhost:1/user:tag\"\n").unwrap();
    fs::write(&project, "image = \"localhost:1/project:tag\"\n").unwrap();
    let user_bytes = fs::read(&user).unwrap();
    let project_bytes = fs::read(&project).unwrap();
    success(&bounded(
        h.command()
            .env("AGENT_VM_IMAGE_TAG", "localhost:1/env:tag")
            .env("RUST_LOG", "trace")
            .args(["upgrade", "--image", &pin]),
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
        cmd.env("AGENT_VM_DEBUG_CONFIG", "1");
        if let Some(env) = ambient {
            cmd.env("AGENT_VM_IMAGE_TAG", env);
        }
        cmd.args(["shell", "--no-git"]);
        if let Some(cli) = cli {
            cmd.args(["--image", cli]);
        }
        cmd.args(["--", "bash", "-c", "true"]);
        let out = bounded(&mut cmd);
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(text.contains(expected), "{text}");
        assert_eq!(h.selected(), pin);
    }
    fs::remove_file(&user).unwrap();
    let out = bounded(
        h.command()
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .args(["shell", "--no-git", "--", "bash", "-c", "true"]),
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("localhost:1/project:tag"));
    fs::remove_file(&project).unwrap();
    let count = server.count();
    let out = bounded(
        h.command()
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .args(["shell", "--no-git", "--", "bash", "-c", "true"]),
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("the default boot image"));
    assert!(!text.contains("private-marker"));
    assert_eq!(server.count(), count);
    assert_eq!(h.selected(), pin);
    // Fake msb can fail launch, but must not be called by upgrade itself.
}

#[test]
fn malformed_metadata_wrong_diff_id_and_foreign_index_fail_without_publication() {
    let h = Harness::new();
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin_a = server.image("images", "a", &a);
    success(&h.upgrade(&pin_a));
    let foreign = h.image(&ArchiveSpec {
        marker: "foreign-index".into(),
        config_platform: PlatformSpec::Foreign,
        descriptor_platform: PlatformSpec::Foreign,
        ..Default::default()
    });
    server.image("images", "foreign", &foreign);
    let target = server.index("images", "foreign-index", foreign.index.clone());
    let before = Snapshot::take(&h, &pin_a, &a);
    assert_eq!(h.upgrade(&target).status.code(), Some(1));
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
            h.upgrade(&format!("{}/images:{name}", server.host))
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
        h.upgrade(&format!("{}/images:malformed-manifest", server.host))
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
            .args(["upgrade", "--image", &pin]),
    );
    success(&out);
    use base64::Engine as _;
    let expected = format!(
        "Authorization: Basic {}",
        base64::engine::general_purpose::STANDARD.encode("fixture-user:fixture-password")
    );
    assert!(
        server.headers.lock().unwrap().iter().any(|header| header
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
            .args(["upgrade", "--image", &pin]),
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
    success(&h.upgrade(&pin_a));
    let before = Snapshot::take(&h, &pin_a, &a);
    let b = h.image(&ArchiveSpec {
        marker: "oracle-B".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "b", &b);
    success(&h.upgrade(&pin_b));
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
