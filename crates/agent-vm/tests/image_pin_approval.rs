//! Host-wide OCI approval, driven through the compiled CLI (#390).
//!
//! Every row here is boot-free: a loopback OCI registry serves genuine tiny
//! images, the runtime is the complete fake `msb` + `libkrunfw` pair, and the
//! `create` call is expected to fail. That is the point — a pin records
//! *measured content*, not a successful boot, so a deliberate create failure is
//! the boundary these tests order against.
//!
//! The prompt-free rows run under a real pseudo-terminal (`support::pty`) as
//! well as on a pipe: `image refresh` and `image set-default` never ask and
//! never read stdin (#541), so a PTY row proves that nothing waits for input.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
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
#[path = "support/pin_gate.rs"]
mod pin_gate;
#[path = "support/pty.rs"]
mod pty;
mod support;

use acquisition_gate::{AcquisitionGate, AcquisitionStage, GateReply};
use fake_msb::{FakeMsb, Mode};
use image_archive::{ArchiveSpec, LayerContent, PlatformSpec};
use oci_registry::{Image, Server};
use pin_gate::{PinCheckpoint, PinGate, PinPeer, PinStage, Reply};
use pty::{Action, Pty};
use sha2::{Digest as _, Sha256};

struct Harness {
    root: tempfile::TempDir,
    _state: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
    state: PathBuf,
    runtime: FakeMsb,
}

impl Harness {
    fn new(mode: Mode) -> Self {
        let root = support::project_tempdir();
        let state = tempfile::Builder::new()
            .prefix("avpin-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let project = root.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let runtime = fake_msb::install_pair(&bin, mode);
        // A fake Docker for `image build`: it replays `$FAKE_DOCKER_ARCHIVE` on
        // stdout and refuses anything but `buildx build`, so a wrong invocation
        // fails loudly.
        let docker = bin.join("docker");
        // Two opt-in hooks, inert unless a test sets them: a marker proving the
        // build ran at all, and a cwd rename standing in for a user renaming
        // their project while `docker buildx build` runs.
        fs::write(
            &docker,
            "#!/bin/sh\n\
             if [ \"$1\" = buildx ] && [ \"$2\" = build ]; then\n\
             \x20 if [ -n \"$FAKE_DOCKER_MARKER\" ]; then echo ran >> \"$FAKE_DOCKER_MARKER\"; fi\n\
             \x20 if [ -n \"$FAKE_DOCKER_RENAME_CWD_TO\" ]; then mv \"$(pwd -P)\" \"$FAKE_DOCKER_RENAME_CWD_TO\" || exit 98; fi\n\
             \x20 cat \"$FAKE_DOCKER_ARCHIVE\"\n\
             \x20 exit 0\n\
             fi\n\
             echo 'fake docker: unexpected subcommand' >&2\n\
             exit 97\n",
        )
        .unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            root,
            home,
            project,
            state: state.path().to_owned(),
            _state: state,
            runtime,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
        command
            .env_clear()
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("AGENT_VM_STATE_DIR", &self.state)
            .env("MSB_PATH", &self.runtime.path)
            .env("AGENT_VM_SHARE_MSB_CACHE", "0")
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.path().join("bin").display()),
            );
        command
    }

    /// `agent-vm --image REF shell -- true`, the shortest real launch shape.
    fn launch(&self, reference: &str) -> Output {
        let mut command = self.command();
        command.args(["--image", reference, "shell", "--", "true"]);
        bounded(command)
    }

    fn refresh(&self, reference: &str) -> Output {
        let mut command = self.command();
        command.args(["image", "refresh", "--image", reference]);
        bounded(command)
    }

    /// A bare refresh whose ambient selection is `reference`: the seeding shape
    /// that approves a reference **without** claiming a role.
    ///
    /// This is not a convenience wrapper for `--image`: `--image` is a target
    /// filter over references already in use, so it can only refresh one. A
    /// fixture that needs a first approval the CLI would not consider in use
    /// must make its reference the ambient next-launch selection.
    fn refresh_as_ambient(&self, reference: &str) -> Output {
        let mut command = self.command();
        command
            .env("AGENT_VM_IMAGE_TAG", reference)
            .args(["image", "refresh"]);
        bounded(command)
    }

    /// [`Self::refresh_as_ambient`] rooted at another project/state root.
    fn refresh_as_ambient_in(&self, project: &Path, state: &Path, reference: &str) -> Output {
        let mut command = self.command_in(project, state);
        command
            .env("AGENT_VM_IMAGE_TAG", reference)
            .args(["image", "refresh"]);
        bounded(command)
    }

    /// Approve `reference` for this project without claiming Boot or Output.
    fn approve_ambient_fixture(&self, reference: &str) {
        let out = self.refresh_as_ambient(reference);
        assert!(
            out.status.success(),
            "approve {reference} as the ambient selection: {}{}",
            stdout_of(&out),
            stderr(&out)
        );
    }

    /// A pin for `reference` **and** a host record naming it: the fixture S1's
    /// `set-default` used to leave behind, now two explicit commands.
    fn pin_and_set_default(&self, reference: &str) {
        self.approve_ambient_fixture(reference);
        assert!(
            set_default(self, reference).status.success(),
            "set the host record"
        );
    }

    fn image(&self, spec: &ArchiveSpec) -> Image {
        Image::from_archive(&self.root.path().join(format!("{}.tar", spec.marker)), spec)
    }

    fn pins(&self) -> PathBuf {
        self.home.join(".config/agent-vm/image-pins.json")
    }

    fn pinned_digest(&self) -> String {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(self.pins()).unwrap()).unwrap();
        value["pins"][0]["manifest_digest"]
            .as_str()
            .expect("a pin records a manifest digest")
            .to_owned()
    }

    /// The record for one canonical reference. Selecting by reference, not by
    /// position: once two references are approved the store's order is an
    /// implementation detail, and a replacement moves its record to the end.
    fn pin_for(&self, reference: &str) -> Option<(String, u64)> {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(self.pins()).ok()?).ok()?;
        value["pins"]
            .as_array()?
            .iter()
            // These harness references are already canonical
            // (`127.0.0.1:PORT/images:tag`), so the stored spelling is the
            // text the test names.
            .find(|record| record["reference"] == reference)
            .map(|record| {
                (
                    record["manifest_digest"].as_str().unwrap().to_owned(),
                    record["revision"].as_u64().unwrap(),
                )
            })
    }

    fn pinned_digest_for(&self, reference: &str) -> Option<String> {
        self.pin_for(reference).map(|(digest, _)| digest)
    }

    /// The project's established default, as the store records it.
    fn default_record_in(&self, project: &Path) -> Option<serde_json::Value> {
        let id = project_id(project);
        self.pins_value()?["defaults"]
            .as_array()?
            .iter()
            .find(|record| record["project"] == id.as_str())
            .cloned()
    }

    /// The host's retained record, decoded.
    fn host_record(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(
            &fs::read(self.home.join(".config/agent-vm/default-image.json")).ok()?,
        )
        .ok()
    }

    /// The immutable digest one default-tier launch re-acquires from an empty
    /// cache: the strongest observable proof of *which* approved content the
    /// redacted default tier selected.
    fn reacquired_digest(&self, server: &Server) -> String {
        self.reacquired_digest_in(&self.project, &self.state, server)
    }

    fn reacquired_digest_in(&self, project: &Path, state: &Path, server: &Server) -> String {
        fs::remove_dir_all(self.cache()).expect("the preparation cached its content");
        let before = server.requests().len();
        let mut command = self.command_in(project, state);
        command.args(["shell", "--", "true"]);
        let out = bounded(command);
        assert!(!out.status.success(), "the fake runtime cannot boot");
        let digests: Vec<String> = server.requests()[before..]
            .iter()
            .filter_map(|(_, path)| path.rsplit_once("/manifests/"))
            .map(|(_, digest)| digest.to_owned())
            .filter(|digest| digest.starts_with("sha"))
            .collect();
        assert_eq!(digests.len(), 1, "one approved digest: {digests:?}");
        digests.into_iter().next().unwrap()
    }

    /// A default-tier launch: no `--image`, so the default slot decides.
    fn launch_default(&self) -> Output {
        let mut command = self.command();
        command.args(["shell", "--", "true"]);
        bounded(command)
    }

    /// A default-tier launch whose initial recommendation is `reference`.
    fn launch_on_recommendation(&self, reference: &str) -> Output {
        let mut command = self.command();
        command
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", reference)
            .args(["shell", "--", "true"]);
        bounded(command)
    }

    fn refresh_default(&self) -> Output {
        let mut command = self.command();
        command.arg("image").arg("refresh");
        bounded(command)
    }

    fn approval_records(&self) -> usize {
        serde_json::from_slice::<serde_json::Value>(&fs::read(self.pins()).unwrap()).unwrap()
            ["pins"]
            .as_array()
            .unwrap()
            .len()
    }

    /// `agent-vm image import --input ARCHIVE --tag REF`, on a null stdin so a
    /// prompt path would refuse instead of reading a terminal this test does not
    /// have: "no prompt" is proven, not assumed.
    fn import(&self, archive: &Path, tag: &str) -> Output {
        let mut command = self.command();
        command.stdin(std::process::Stdio::null()).args([
            "image",
            "import",
            "--input",
            archive.to_str().unwrap(),
            "--tag",
            tag,
        ]);
        bounded(command)
    }

    /// `agent-vm image build --tag REF` with a fake Docker that replays
    /// `archive` on stdout.
    fn build(&self, archive: &Path, tag: &str) -> Output {
        let mut command = self.command();
        command
            .env("FAKE_DOCKER_ARCHIVE", archive)
            .args(["image", "build", "--tag", tag]);
        bounded(command)
    }

    fn msb_invocations(&self) -> String {
        fs::read_to_string(&self.runtime.invocations).unwrap_or_default()
    }

    fn cache(&self) -> PathBuf {
        self.state.join("msb-home/cache")
    }

    /// A second project under the harness root.
    fn project_at(&self, name: &str) -> PathBuf {
        let dir = self.root.path().join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// [`Self::command`] rooted at another project and state root: the
    /// cross-project rows need both to differ from the launching project's.
    fn command_in(&self, project: &Path, state: &Path) -> Command {
        let mut command = self.command();
        command
            .current_dir(project)
            .env("AGENT_VM_STATE_DIR", state);
        command
    }

    fn pins_value(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&fs::read(self.pins()).ok()?).ok()
    }

    /// The record for one (project, reference) pair. The store holds one record
    /// per project **and** reference, so a reference-only reader would read
    /// another project's approval once two projects share this HOME.
    fn record_in(&self, project: &Path, reference: &str) -> Option<serde_json::Value> {
        let id = project_id(project);
        self.pins_value()?["pins"]
            .as_array()?
            .iter()
            .find(|record| record["project"] == id.as_str() && record["reference"] == reference)
            .cloned()
    }

    fn pin_in(&self, project: &Path, reference: &str) -> Option<(String, u64)> {
        let record = self.record_in(project, reference)?;
        Some((
            record["manifest_digest"].as_str()?.to_owned(),
            record["revision"].as_u64()?,
        ))
    }

    fn records_in(&self, project: &Path) -> usize {
        let id = project_id(project);
        self.pins_value()
            .and_then(|value| {
                value["pins"].as_array().map(|pins| {
                    pins.iter()
                        .filter(|record| record["project"] == id.as_str())
                        .count()
                })
            })
            .unwrap_or(0)
    }
}

/// The project identifier, computed independently of the binary: the lowercase
/// hex SHA-256 of the canonical directory's bytes, which is also the prefix the
/// session state directory is named from.
fn project_id(dir: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        dir.canonicalize()
            .expect("canonicalize the project")
            .as_os_str()
            .as_encoded_bytes(),
    );
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bounded(command: Command) -> Output {
    bounded_with_stderr(command, std::process::Stdio::piped())
}

/// [`bounded`] with the child's stderr supplied by the caller, for the rows that
/// prove what an unwritable stderr does to a render.
fn bounded_with_stderr(mut command: Command, stderr: std::process::Stdio) -> Output {
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(stderr)
        .spawn()
        .expect("run the compiled CLI");
    let id = child.id();
    let (sender, receiver) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        sender
            .send(child.wait_with_output().expect("collect CLI"))
            .ok();
    });
    let output = receiver.recv_timeout(Duration::from_secs(60));
    if output.is_err() {
        unsafe {
            libc::kill(id as i32, libc::SIGKILL);
        }
    }
    waiter.join().expect("join CLI collector");
    output.expect("CLI exceeded 60 seconds")
}

/// Every runtime invocation that is not the pre-flight `--version` check: the
/// create attempts, which are what must never happen without approved content.
fn create_invocations(h: &Harness) -> usize {
    h.msb_invocations()
        .lines()
        .filter(|line| !line.trim_start().starts_with("--version"))
        .count()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The manifest digests the registry was asked for from request `from` on.
/// Filtering manifest paths keeps the oracle about resolution rather than about
/// every blob or API probe the client happens to make.
fn manifests_requested_since(server: &Server, from: usize) -> Vec<String> {
    server.requests()[from..]
        .iter()
        .filter_map(|(_, path)| path.rsplit_once("/manifests/"))
        .map(|(_, digest)| digest.to_owned())
        .collect()
}

/// The digest half of a `repo@digest` identity, as the store records it.
fn digest_of(child: &str) -> String {
    child
        .rsplit_once('@')
        .expect("an acquired identity is repo@digest")
        .1
        .to_owned()
}

/// An OCI archive fixture named for this test, with `marker` inside its layer.
fn archive_at(h: &Harness, name: &str, marker: &str) -> image_archive::Written {
    image_archive::write(
        &h.root.path().join(name),
        &ArchiveSpec {
            marker: marker.to_owned(),
            ..ArchiveSpec::default()
        },
    )
}

/// The image reference the SDK was handed, read from the opt-in config dump.
fn sdk_image(out: &Output) -> String {
    let text = stderr(out);
    let start = text
        .find("{\n  \"name\"")
        .or_else(|| text.find("{\"name\""))
        .unwrap_or_else(|| panic!("no debug config JSON in:\n{text}"));
    // The dump is followed by further tracing, so stop at the first complete
    // JSON value instead of guessing where it ends.
    let value: serde_json::Value = serde_json::Deserializer::from_str(&text[start..])
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no debug config JSON in:\n{text}"))
        .unwrap_or_else(|error| panic!("unparseable debug config ({error}):\n{text}"));
    value["image"]["Oci"]["reference"]
        .as_str()
        .unwrap_or_else(|| panic!("no OCI reference in the dumped config: {value}"))
        .to_owned()
}

/// A first launch pins what it validated, and does so BEFORE the SDK create.
///
/// The pin gate pauses the process at `PinCommitted`; at that instant the runtime
/// has recorded no invocation beyond `--version`, so the approval provably
/// precedes every create attempt it protects.
#[test]
fn first_pin_is_committed_before_the_sdk_create() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.image(&ArchiveSpec::default());
    let child = server.image("images", "pin", &image);
    let tag = format!("{}/images:pin", server.host);

    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    gate.attach(&mut command);
    let child_process = command
        .args(["--image", &tag, "shell", "--", "true"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated launch");
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinLock).reply(Reply::Continue);
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinSave).reply(Reply::Continue);
    gate.expect(PinStage::PinCommitted).reply(Reply::Continue);
    // The approved record exists and no create has been attempted yet.
    assert_eq!(h.pinned_digest(), child.rsplit_once('@').unwrap().1);
    assert!(
        !h.msb_invocations()
            .lines()
            .any(|line| !line.starts_with("--version")),
        "the pin must be committed before any create invocation: {}",
        h.msb_invocations()
    );
    drop(gate);

    let output = child_process
        .wait_with_output()
        .expect("collect the launch");
    assert!(
        !output.status.success(),
        "the fake runtime cannot boot a guest"
    );
    assert_eq!(
        sdk_image(&output),
        child,
        "the SDK consumes the approved host child, never the selected tag"
    );
    assert!(
        fs::read_to_string(h.pins())
            .unwrap()
            .contains(child.rsplit_once('@').unwrap().1),
        "a failed create must not undo the approval"
    );
}

/// A warm, approved launch makes **no** registry request at all: the selection
/// is answered from the approved digest and the cache, so a moving tag or an
/// unreachable registry cannot change guest content.
#[test]
fn warm_pinned_launch_makes_no_registry_request() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.image(&ArchiveSpec::default());
    let child = server.image("images", "warm", &image);
    let tag = format!("{}/images:warm", server.host);
    let cold = h.launch(&tag);
    assert!(!cold.status.success());
    assert_eq!(sdk_image(&cold), child);
    assert!(
        server.count() > 0,
        "the first launch must acquire the image"
    );
    assert_eq!(h.pinned_digest(), child.rsplit_once('@').unwrap().1);

    // Move the tag and inherit the removed advisory environment variable: a
    // warm approved launch must neither re-resolve the tag nor probe anything.
    let moved = h.image(&ArchiveSpec {
        marker: "warm-moved".into(),
        ..Default::default()
    });
    let moved_child = server.image("images", "warm", &moved);
    assert_ne!(moved_child, child);
    let before = server.count();
    let mut command = h.command();
    command
        .env("AGENT_VM_UPDATE_CHECK", "1")
        .env("RUST_LOG", "trace")
        .args(["--image", &tag, "shell", "--", "true"]);
    let warm = bounded(command);
    assert!(
        !warm.status.success(),
        "the create still fails deliberately"
    );
    assert_eq!(sdk_image(&warm), child, "a warm launch stays on A");
    assert_eq!(
        server.count(),
        before,
        "a warm approved launch must make no registry request: {:?}",
        &server.requests()[before..]
    );
}

/// Losing the cache does not re-open the tag: the approved digest is reacquired,
/// and if it is unavailable the launch fails before anything is created.
#[test]
fn cache_loss_reacquires_the_approved_digest_not_the_tag() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.image(&ArchiveSpec::default());
    let child = server.image("images", "loss", &image);
    let tag = format!("{}/images:loss", server.host);
    let cold = h.launch(&tag);
    assert!(!cold.status.success());
    let child_digest = child.rsplit_once('@').unwrap().1.to_owned();
    assert_eq!(h.pinned_digest(), child_digest);

    // Move the tag to B, then delete only the owned cache.
    let moved = h.image(&ArchiveSpec {
        marker: "loss-moved".into(),
        ..Default::default()
    });
    let moved_child = server.image("images", "loss", &moved);
    fs::remove_dir_all(h.cache()).unwrap();
    let before = server.requests().len();
    let again = h.launch(&tag);
    assert!(
        !again.status.success(),
        "the create still fails deliberately"
    );
    assert_eq!(sdk_image(&again), child, "the approved digest is restored");
    let since = &server.requests()[before..];
    assert!(
        since
            .iter()
            .any(|(_, path)| path == &format!("/v2/images/manifests/{child_digest}")),
        "the approved digest must be reacquired: {since:?}"
    );
    assert!(
        !since
            .iter()
            .any(|(_, path)| path == "/v2/images/manifests/loss"),
        "a cache loss must never re-resolve the mutable tag: {since:?}"
    );
    assert_ne!(sdk_image(&again), moved_child);
    assert_eq!(h.pinned_digest(), child_digest);
}

/// An approved digest the registry no longer serves fails the launch before any
/// create; it never falls back to whatever the tag now names.
#[test]
fn unavailable_approved_digest_fails_before_create() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.image(&ArchiveSpec::default());
    let child = server.image("images", "gone", &image);
    let tag = format!("{}/images:gone", server.host);
    assert!(set_default(&h, &tag).status.success());
    assert_eq!(sdk_image(&h.launch(&tag)), child);
    let moved = h.image(&ArchiveSpec {
        marker: "gone-moved".into(),
        ..Default::default()
    });
    server.image("images", "gone", &moved);
    server.remove(&format!(
        "/v2/images/manifests/{}",
        child.rsplit_once('@').unwrap().1
    ));
    let pins_before = fs::read(h.pins()).unwrap();
    let default = h.home.join(".config/agent-vm/default-image.json");
    let default_before = fs::read(&default).ok();
    fs::remove_dir_all(h.cache()).unwrap();
    let requests_before = server.count();
    let invoked_before = create_invocations(&h);
    let out = h.launch(&tag);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        !stderr(&out).contains("Approve"),
        "an approved digest failure is not a replacement prompt: {}",
        stderr(&out)
    );
    assert_eq!(
        create_invocations(&h),
        invoked_before,
        "no create-capable invocation may follow a failed approved preparation"
    );
    assert_eq!(h.pinned_digest(), child.rsplit_once('@').unwrap().1);
    assert_eq!(fs::read(h.pins()).unwrap(), pins_before);
    assert_eq!(fs::read(default).ok(), default_before);
    assert_eq!(
        &server.requests()[requests_before..],
        &[
            ("GET".to_owned(), "/v2/".to_owned()),
            (
                "GET".to_owned(),
                format!("/v2/images/manifests/{}", child.rsplit_once('@').unwrap().1)
            ),
        ]
    );
}

/// A local rootfs launch is not an OCI selection: it passes through untouched
/// even when the approval store is corrupt, which an OCI launch must refuse.
#[test]
fn local_path_launch_is_unpinned_and_ignores_a_corrupt_store() {
    let h = Harness::new(Mode::LaunchSeam);
    let rootfs = h.root.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    let pins = h.pins();
    fs::create_dir_all(pins.parent().unwrap()).unwrap();
    fs::write(&pins, b"private damaged approval bytes").unwrap();

    let mut command = h.command();
    command.args(["--image", rootfs.to_str().unwrap(), "shell", "--", "true"]);
    let out = bounded(command);
    // The launch reaches the builder (the dumped config names the local path);
    // only the deliberate runtime failure ends it.
    assert!(
        stderr(&out).contains("rootfs"),
        "a local path must reach the SDK unchanged: {}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("image pin authority"),
        "{}",
        stderr(&out)
    );
    assert_eq!(fs::read(&pins).unwrap(), b"private damaged approval bytes");

    // The same store refuses an OCI selection before any registry request.
    let server = Server::new();
    let image = h.image(&ArchiveSpec::default());
    server.image("images", "corrupt", &image);
    let tag = format!("{}/images:corrupt", server.host);
    let before = server.count();
    let out = h.launch(&tag);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("image pin authority"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        server.count(),
        before,
        "a corrupt store fails before the network"
    );
}

/// `image refresh` never asks: it replaces a moved mutable tag on a pipe and on
/// a terminal alike, renders both digests, and reads no stdin (R6, B3).
#[test]
fn refresh_replaces_a_moved_tag_without_asking_on_a_pipe_or_a_terminal() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let tag = format!("{}/images:approve", server.host);
    let pin_a = server.image("images", "approve", &a);
    assert!(h.refresh_as_ambient(&tag).status.success(), "first pin");
    let b = h.image(&ArchiveSpec {
        marker: "approval-b".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "approve", &b);
    assert_ne!(pin_a, pin_b);

    // A pipe holding a decline: nothing may read it, and the refresh replaces.
    let piped = with_unread_stdin(command_with_refresh(&h, &tag), b"n\n");
    assert!(piped.0.status.success(), "{}", stderr(&piped.0));
    assert_eq!(piped.1, b"n\n", "stdin must be left unread");
    assert_no_question(&stderr(&piped.0));
    let text = stderr(&piped.0);
    assert!(
        text.contains("Replacing the approved image for") && text.contains(" in this project:"),
        "{text}"
    );
    assert!(
        text.contains(&format!("old: {}", digest_of(&pin_a))),
        "{text}"
    );
    assert!(
        text.contains(&format!("new: {}", digest_of(&pin_b))),
        "{text}"
    );
    assert_eq!(h.pinned_digest(), digest_of(&pin_b));
    assert_eq!(
        h.pin_for(&tag).unwrap().1,
        2,
        "a replacement bumps revision"
    );

    // The same refresh on a real terminal exits without any input being typed.
    // Its own A->B fixture: the pipe row already installed B, so a shared
    // registry would leave the terminal row re-verifying an unchanged pin — the
    // one path that never renders a replacement.
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let tag = format!("{}/images:terminal", server.host);
    let pin_a = server.image("images", "terminal", &a);
    assert!(h.refresh_as_ambient(&tag).status.success(), "first pin");
    let b = h.image(&ArchiveSpec {
        marker: "approval-terminal-b".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "terminal", &b);
    assert_ne!(pin_a, pin_b);

    let mut command = h.command();
    command
        .env("AGENT_VM_IMAGE_TAG", &tag)
        .args(["image", "refresh"]);
    let mut terminal = Pty::spawn(&mut command, b"Replacing the approved image for")
        .expect("open a pseudo-terminal");
    let (status, out) = terminal
        .drive(&Action::Write(b""), Duration::from_secs(60))
        .expect("wait for the refresh to exit");
    // `Pty::drive` only waits for its marker; it does not require it before the
    // child exits, so the replacement itself is asserted here.
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(status.success(), "{text}");
    assert!(
        text.contains("Replacing the approved image for") && text.contains(" in this project:"),
        "the terminal row renders the replacement: {text}"
    );
    assert!(
        text.contains(&format!("old: {}", digest_of(&pin_a))),
        "{text}"
    );
    assert!(
        text.contains(&format!("new: {}", digest_of(&pin_b))),
        "{text}"
    );
    assert_no_question(&text);
    assert_eq!(
        h.pin_for(&tag),
        Some((digest_of(&pin_b), 2)),
        "the terminal replaced it at revision 2"
    );
}

/// A bare `image refresh` command whose ambient selection is `reference`, for a
/// fixture that gates or peers a refresh of a reference it has not recorded a
/// role for.
fn refresh_as_ambient_command(h: &Harness, reference: &str) -> Command {
    let mut command = h.command();
    command
        .env("AGENT_VM_IMAGE_TAG", reference)
        .args(["image", "refresh"]);
    command
}

/// The exact command shape the pipe row needs: no stdin configured here, so the
/// helper can install its own recording pipe.
fn command_with_refresh(h: &Harness, tag: &str) -> Command {
    let mut command = h.command();
    // The tag is the ambient selection: `--image` may only refresh a reference
    // already in use, and here the row is about the reference being re-resolved.
    command
        .env("AGENT_VM_IMAGE_TAG", tag)
        .args(["image", "refresh"]);
    command
}

fn assert_no_question(text: &str) {
    assert!(!text.contains("[y/N]"), "no question is asked: {text}");
    assert!(!text.contains('?'), "no question is asked: {text}");
    assert!(!text.contains("Approve this"), "no prompt: {text}");
}

/// A non-interactive refresh replaces the approval and reads no stdin; an
/// unchanged one renders nothing (R6, B3).
#[test]
fn noninteractive_refresh_replaces_and_reads_no_stdin() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin_a = server.image("images", "piped", &a);
    let tag = format!("{}/images:piped", server.host);
    assert!(h.refresh_as_ambient(&tag).status.success());
    let b = h.image(&ArchiveSpec {
        marker: "piped-b".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "piped", &b);

    let (replaced, left) = with_unread_stdin(command_with_refresh(&h, &tag), b"n\n");
    assert!(replaced.status.success(), "{}", stderr(&replaced));
    assert_eq!(left, b"n\n", "stdin must be left unread");
    let text = stderr(&replaced);
    assert!(text.contains("Replacing the approved image for"), "{text}");
    assert!(
        text.contains(&format!("old: {}", digest_of(&pin_a))),
        "{text}"
    );
    assert!(
        text.contains(&format!("new: {}", digest_of(&pin_b))),
        "{text}"
    );
    assert_eq!(h.pinned_digest(), digest_of(&pin_b));

    // An unchanged refresh renders nothing: there is nothing to consent to.
    let (unchanged, left) = with_unread_stdin(command_with_refresh(&h, &tag), b"y\n");
    assert!(unchanged.status.success(), "{}", stderr(&unchanged));
    assert_eq!(left, b"y\n");
    assert!(
        !stderr(&unchanged).contains("old:"),
        "{}",
        stderr(&unchanged)
    );
}

/// The removed launch-time advisory has no alias, no hint and no effect.
#[test]
fn removed_update_check_is_an_unknown_option_before_the_verb_and_forwarded_after() {
    let h = Harness::new(Mode::StrictAcquisition);
    let mut command = h.command();
    command.args(["--update-check", "shell", "--", "true"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(2), "unknown option before the verb");
    assert!(!stderr(&out).contains("deprecat"), "{}", stderr(&out));

    let server = Server::new();
    let image = h.image(&ArchiveSpec::default());
    let child = server.image("images", "verb", &image);
    let tag = format!("{}/images:verb", server.host);
    assert!(!h.launch(&tag).status.success());
    assert_eq!(sdk_image(&h.launch(&tag)), child);
}

/// An archive alias never moves an approval, and the reference the command
/// names is approved (#391). A launch of the aliased reference keeps consuming
/// its approved digest with no tag query; a launch of the *result* reference
/// boots the imported bytes.
#[test]
fn import_alias_cannot_bypass_an_established_pin() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let child = server.image("images", "alias", &image_archive_image(&h, "alias-a"));
    let alias = format!("{}/images:alias", server.host);
    let result = format!("{}/images:result", server.host);

    let cold = h.launch(&alias);
    assert!(!cold.status.success());
    assert_eq!(sdk_image(&cold), child);
    let pinned = h
        .pinned_digest_for(&alias)
        .expect("the launch established a pin");

    // A Docker-save archive whose RepoTags name the approved reference, imported
    // under a different result reference.
    let archive_path = h.root.path().join("alias-b.tar");
    let save = image_archive::write_docker_save(
        &archive_path,
        &[image_archive::DockerSaveImage {
            marker: "alias-b".into(),
            repo_tags: Some(vec![alias.clone()]),
        }],
    );
    let imported = h.import(&archive_path, &result);
    assert_eq!(
        imported.status.code(),
        Some(0),
        "an import never prompts: {}",
        stderr(&imported)
    );

    assert_eq!(
        h.pinned_digest_for(&alias),
        Some(pinned),
        "an archive alias never replaces an established approval"
    );
    // The authority for the result half is the fixture, never the approval or the
    // cache under test: `docker_save_manifest` derives the manifest a docker-save
    // import synthesizes from the archive's own config and layer descriptors, so
    // the result must hold *that* manifest and the pin must name it — not A's
    // digest and not some other manifest that happens to share the config.
    let published = published_metadata(&cache_metadata_path(&h, &result));
    assert_eq!(
        published["config_digest"], save[0].config_digest,
        "the result reference holds the bytes the archive carried"
    );
    let (_, approved_result) = image_archive::docker_save_manifest("alias-b");
    assert_eq!(
        published["manifest_digest"], approved_result,
        "the result reference holds the fixture's synthesized manifest"
    );
    assert_eq!(
        h.pinned_digest_for(&result),
        Some(approved_result.clone()),
        "the result reference is approved at the fixture's manifest"
    );
    assert_ne!(
        approved_result,
        digest_of(&child),
        "the result reference is not approved at the alias's approved digest"
    );

    let before = server.count();
    let warm = h.launch(&alias);
    assert!(!warm.status.success());
    assert_eq!(sdk_image(&warm), child, "the alias's approval is unchanged");
    assert_eq!(
        server.count(),
        before,
        "an approved launch makes no registry request after an import"
    );

    // The result reference is approved at the imported bytes, and a warm launch
    // consumes exactly that `repo@digest` from the cache the import filled.
    let booted = h.launch(&result);
    assert_eq!(
        sdk_image(&booted),
        format!("{}/images@{approved_result}", server.host)
    );
}

/// The three-line render, exactly, for the canonical reference and host
/// platform.
fn assert_render(shown: &str, reference: &str, old: &str, new: &str) {
    let expected = format!(
        "Approving the image published as {reference} (linux/{}) for this project:\n  old: {old}\n  new: {new}\n",
        image_archive::host_arch()
    );
    assert!(
        shown.contains(&expected),
        "expected the approval render:\n{expected}\nin:\n{shown}"
    );
    assert!(
        !shown.contains("Approve this exact image change?"),
        "an explicit build/import never prompts: {shown}"
    );
}

fn import_notice(tag: &str) -> String {
    format!("Imported {tag} into agent-vm's image cache; launch it with `--image {tag}`\n")
}

fn build_notice(tag: &str) -> String {
    format!("Imported build result as {tag}; launch it with `--image {tag}`\n")
}

/// AC1/AC2/AC3/AC10: what a launch boots follows the explicit publications.
///
/// The tag is never served, so a registry request at any point would fail the
/// run: every launch here consumes the approved `repo@digest` from the cache.
#[test]
fn explicit_import_then_rebuild_move_what_a_launch_boots() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:t", server.host);

    let a = archive_at(&h, "a.tar", "A");
    let b = archive_at(&h, "b.tar", "B");
    let c = archive_at(&h, "c.tar", "C");

    // 1. Import A: the first write allocates sequence 1 and approves A/r1.
    let out = h.import(&a.path, &tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout_of(&out), import_notice(&tag));
    assert_render(&stderr(&out), &tag, "none", &a.manifest_digest);
    assert_eq!(h.pin_for(&tag), Some((a.manifest_digest.clone(), 1)));
    assert_eq!(h.approval_records(), 1);
    assert_eq!(
        sdk_image(&h.launch(&tag)),
        format!("{}/images@{}", server.host, a.manifest_digest)
    );

    // 2. Import B: the launch above claimed Boot (sequence 2), so this
    // replacement draws the next global allocation, revision 3.
    let out = h.import(&b.path, &tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout_of(&out), import_notice(&tag));
    assert_render(&stderr(&out), &tag, &a.manifest_digest, &b.manifest_digest);
    assert_eq!(h.pin_for(&tag), Some((b.manifest_digest.clone(), 3)));
    assert_eq!(
        sdk_image(&h.launch(&tag)),
        format!("{}/images@{}", server.host, b.manifest_digest)
    );

    // 3. A rebuild under the same tag: the next allocation, revision 4.
    let out = h.build(&c.path, &tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout_of(&out), build_notice(&tag));
    assert_render(&stderr(&out), &tag, &b.manifest_digest, &c.manifest_digest);
    assert_eq!(h.pin_for(&tag), Some((c.manifest_digest.clone(), 4)));
    assert_eq!(
        sdk_image(&h.launch(&tag)),
        format!("{}/images@{}", server.host, c.manifest_digest)
    );

    // 4. Republishing C leaves the store byte-identical and stderr silent.
    let approved = fs::read(h.pins()).unwrap();
    let out = h.import(&c.path, &tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fs::read(h.pins()).unwrap(), approved);
    assert!(!stderr(&out).contains("Approving"), "{}", stderr(&out));
    assert_eq!(h.pin_for(&tag), Some((c.manifest_digest.clone(), 4)));

    // The tag was never fetched: every launch was served from the cache.
    assert_eq!(server.count(), 0, "{:?}", server.requests());
}

/// AC9/AC10: a concurrent `image refresh` that commits between this import's
/// observation and its commit wins, and the import reports a stale approval.
/// The render is already on stderr at the checkpoint that precedes the commit,
/// and the store is still on the previous digest at that instant.
#[test]
fn a_concurrent_refresh_wins_and_the_import_reports_a_stale_approval() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let c = h.image(&ArchiveSpec {
        marker: "stale-c".into(),
        ..Default::default()
    });
    let pin_a = server.image("images", "stale", &a);
    let tag = format!("{}/images:stale", server.host);
    assert!(h.refresh_as_ambient(&tag).status.success(), "first pin");
    assert_eq!(
        h.pinned_digest_for(&tag),
        Some(digest_of(&pin_a)),
        "the first pin records the registry's child digest"
    );

    let b = archive_at(&h, "stale-b.tar", "stale-b");

    let stderr_path = h.root.path().join("stale-import.log");
    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    gate.attach(&mut command);
    let child = command
        .stdin(std::process::Stdio::null())
        .args([
            "image",
            "import",
            "--input",
            b.path.to_str().unwrap(),
            "--tag",
            &tag,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::from(
            fs::File::create(&stderr_path).unwrap(),
        ))
        .spawn()
        .expect("spawn the gated import");

    gate.expect(PinStage::Published).reply(Reply::Continue);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    // Held *after* the render and the predecessor observation, *before* the
    // commit: exactly the window the compare-and-swap covers.
    let held = gate.expect(PinStage::BeforePinLock);

    let rendered = fs::read_to_string(&stderr_path).unwrap();
    assert_render(&rendered, &tag, &digest_of(&pin_a), &b.manifest_digest);
    assert_eq!(
        h.pinned_digest_for(&tag),
        Some(digest_of(&pin_a)),
        "the render precedes the commit: the store still holds the predecessor"
    );

    // The winner: a refresh that replaces A with C while this import waits.
    let pin_c = server.image("images", "stale", &c);
    let refreshed = h.refresh_as_ambient(&tag);
    assert_eq!(refreshed.status.code(), Some(0), "{}", stderr(&refreshed));
    assert_eq!(h.pinned_digest_for(&tag), Some(digest_of(&pin_c)));

    held.reply(Reply::Continue);
    // The commit's under-lock reread happens next; the conflicting predecessor
    // is detected there, before any save checkpoint.
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    let output = child.wait_with_output().expect("collect the import");
    drop(gate);
    assert_eq!(output.status.code(), Some(1));
    let shown = fs::read_to_string(&stderr_path).unwrap();
    assert!(
        shown.contains("image approval is stale; retry the explicit operation"),
        "{shown}"
    );
    assert!(
        shown.contains("but its approval was not updated"),
        "{shown}"
    );
    assert_eq!(
        h.pin_for(&tag),
        Some((digest_of(&pin_c), 2)),
        "the winner stands"
    );
    assert_eq!(sdk_image(&h.launch(&tag)), pin_c, "the winner's bytes boot");
}

/// R2/D1's "the alias moved after publication" (not AC7, which is about failed
/// and interrupted loads): the read-back is pinned to what publication reported,
/// not to whatever the cache key names now. Dropping the `Published.digest`
/// comparison would approve C under T.
#[test]
fn a_result_moved_before_read_back_is_not_approved() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:t", server.host);
    let other = format!("{}/images:other", server.host);

    // Materialize C and approve it under a different reference.
    let c = archive_at(&h, "moved-c.tar", "moved-c");
    let out = h.import(&c.path, &other);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let c_record = h.pin_for(&other).expect("C is approved under :other");

    let b = archive_at(&h, "moved-b.tar", "moved-b");
    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    gate.attach(&mut command);
    let child = command
        .stdin(std::process::Stdio::null())
        .args([
            "image",
            "import",
            "--input",
            b.path.to_str().unwrap(),
            "--tag",
            &tag,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated import");

    // While the child is held right after publication, overwrite T's cache
    // metadata with the bytes `:other` published. Both files are addressed by
    // their exact references, not by a digest search: a second key naming the
    // same digest must not decide which file this test overwrites.
    let checkpoint = gate.expect(PinStage::Published);
    let c_metadata = cache_metadata_path(&h, &other);
    let b_metadata = cache_metadata_path(&h, &tag);
    assert_ne!(c_metadata, b_metadata, "the two references have two keys");
    assert_eq!(
        published_metadata(&c_metadata)["manifest_digest"],
        c.manifest_digest,
        "`:other` holds C before the injection"
    );
    assert_eq!(
        published_metadata(&b_metadata)["manifest_digest"],
        b.manifest_digest,
        "T holds B before the injection"
    );
    fs::copy(&c_metadata, &b_metadata).unwrap();
    checkpoint.reply(Reply::Continue);

    // Every later checkpoint the child reaches is a defect: it must refuse.
    gate.expect_none(Duration::from_secs(5));
    let output = child.wait_with_output().expect("collect the import");
    drop(gate);
    assert_eq!(output.status.code(), Some(1));
    let shown = stderr(&output);
    assert!(
        shown.contains("changed in the image cache before it could be approved"),
        "{shown}"
    );
    assert!(
        shown.contains("but its approval was not updated"),
        "{shown}"
    );
    assert_eq!(h.pin_for(&tag), None, "nothing is approved for T");
    assert_eq!(h.pin_for(&other), Some(c_record));
}

/// The native cache's metadata file for one digest-spelled reference.
fn cache_metadata_path(h: &Harness, reference: &str) -> PathBuf {
    microsandbox_image::GlobalCache::new(&h.cache())
        .expect("open the harness cache")
        .image_metadata_path(&reference.parse().expect("a cache reference"))
}

/// The parsed metadata a key's file holds.
fn published_metadata(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).expect("a published metadata file"))
        .expect("published metadata is JSON")
}

/// Every cache-only receipt the harness's cache holds, parsed.
fn content_receipts(h: &Harness) -> Vec<serde_json::Value> {
    let Ok(entries) = fs::read_dir(h.cache().join("agent-vm-content-metadata")) else {
        return Vec::new();
    };
    entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .map(|path| serde_json::from_slice(&fs::read(&path).unwrap()).unwrap())
        .collect()
}

/// The receipt for one acquired digest, if the cache keeps one.
fn receipt_for(h: &Harness, digest: &str) -> Option<serde_json::Value> {
    content_receipts(h)
        .into_iter()
        .find(|receipt| receipt["acquired_digest"] == digest)
}

/// D10: an approval owns a **content receipt** for the digest it approved.
///
/// The native loader publishes a digest-spelled archive name over the canonical
/// child key, so a publication-backed approval whose read-back kept no receipt
/// would lose its offline availability to an unrelated archive alias: the launch
/// would find B's content under A's key, fail the strict association check and
/// fall through to a registry that does not serve this tag.
#[test]
fn an_archive_alias_of_the_approved_digest_is_repaired_on_launch() {
    let h = Harness::new(Mode::LaunchSeam);
    // Bound but never served: a registry request here fails the run instead of
    // silently succeeding.
    let server = Server::new();
    let tag = format!("{}/images:t", server.host);

    // 1. Import A under T. The read-back preserves a content-only receipt for
    //    the digest it approved.
    let a = archive_at(&h, "repair-a.tar", "repair-a");
    let imported = h.import(&a.path, &tag);
    assert_eq!(imported.status.code(), Some(0), "{}", stderr(&imported));
    let a_pin = (a.manifest_digest.clone(), 1);
    assert_eq!(h.pin_for(&tag), Some(a_pin.clone()));
    let receipt = receipt_for(&h, &a.manifest_digest).expect(
        "the read-back must keep a content receipt for the digest it approved (D10); without \
         one, an archive alias of that digest cannot be repaired",
    );
    assert_eq!(
        receipt["source_bindings"],
        serde_json::json!([]),
        "a publication proves what the cache holds, never a registry association"
    );

    // A's content-addressed metadata, byte for byte.
    let approved_key = format!("{}/images@{}", server.host, a.manifest_digest);
    let approved_path = cache_metadata_path(&h, &approved_key);
    let approved_bytes = fs::read(&approved_path).unwrap();

    // 1b. Prepare A before the unrelated publication: Boot is now actively held,
    // so this row's subject (the receipt repair) is independent of the
    // unknown-role retention of AC19. It also allocates sequence 2.
    let prepared = h.launch(&tag);
    assert_eq!(sdk_image(&prepared), approved_key, "{}", stderr(&prepared));

    // 2. Import B under a *different* result reference, spelling the approved
    //    digest as an archive-carried name. The loader publishes that name, so
    //    A's child key now describes B.
    let other = format!("{}/images:other", server.host);
    let save = image_archive::write_docker_save(
        &h.root.path().join("repair-b.tar"),
        &[image_archive::DockerSaveImage {
            marker: "repair-b".into(),
            repo_tags: Some(vec![approved_key.clone()]),
        }],
    );
    let imported = h.import(&save[0].path, &other);
    assert_eq!(imported.status.code(), Some(0), "{}", stderr(&imported));
    // B's identity comes from the fixture (`docker_save_manifest`), not from the
    // store record this row is about: comparing that record with itself would
    // pass for any digest at all.
    let (_, b_digest) = image_archive::docker_save_manifest("repair-b");
    assert_eq!(
        h.pin_for(&other),
        Some((b_digest.clone(), 3)),
        "the reference the command named is approved at its global allocation"
    );
    assert_eq!(
        published_metadata(&cache_metadata_path(&h, &other))["manifest_digest"],
        serde_json::json!(b_digest),
        "the result reference holds the fixture's synthesized manifest"
    );
    let overwritten: serde_json::Value =
        serde_json::from_slice(&fs::read(&approved_path).unwrap()).unwrap();
    assert_eq!(
        overwritten["manifest_digest"],
        serde_json::json!(b_digest),
        "the fixture must really overwrite the digest-spelled key"
    );

    // 3. T's approval is unchanged, and its launch repairs A from the receipt.
    assert_eq!(
        h.pin_for(&tag),
        Some(a_pin),
        "an archive-carried name never replaces an approval"
    );
    let before = server.count();
    let launched = h.launch(&tag);
    assert_eq!(
        sdk_image(&launched),
        approved_key,
        "the launch boots the approved digest, not the alias: {}",
        stderr(&launched)
    );
    assert_eq!(
        server.count(),
        before,
        "a repaired approved digest needs no registry: {:?}",
        server.requests()
    );
    assert_eq!(
        fs::read(&approved_path).unwrap(),
        approved_bytes,
        "the repair restores the approved key byte for byte"
    );
    // 4. B's own result reference stays at B.
    assert_eq!(h.pin_for(&other), Some((b_digest, 3)));
}

/// D10 / G4: an alias-carrying publication whose *own* approval fails at the save
/// still leaves the previously approved image launchable offline. The receipt
/// that repairs A is published before the commit that failed, so a refused
/// approval cannot cost an approved image its availability.
#[test]
fn a_failed_approval_after_an_alias_publication_keeps_the_approved_image_launchable() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:t", server.host);

    let a = archive_at(&h, "repair-a.tar", "repair-a");
    let imported = h.import(&a.path, &tag);
    assert_eq!(imported.status.code(), Some(0), "{}", stderr(&imported));
    let a_pin = (a.manifest_digest.clone(), 1);
    assert_eq!(h.pin_for(&tag), Some(a_pin.clone()));
    let approved_key = format!("{}/images@{}", server.host, a.manifest_digest);
    let approved_path = cache_metadata_path(&h, &approved_key);
    let approved_bytes = fs::read(&approved_path).unwrap();

    // The alias-carrying publication, forced to fail its approval save.
    let other = format!("{}/images:other", server.host);
    let save = image_archive::write_docker_save(
        &h.root.path().join("repair-b.tar"),
        &[image_archive::DockerSaveImage {
            marker: "repair-b".into(),
            repo_tags: Some(vec![approved_key.clone()]),
        }],
    );
    let save_path = save[0].path.to_string_lossy().into_owned();
    let mut gate = PinGate::new(h.root.path());
    let peer = PinPeer::spawn(
        h.command(),
        &gate,
        &["image", "import", "--input", &save_path, "--tag", &other],
    );
    for stage in [
        PinStage::Published,
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    gate.expect(PinStage::BeforePinSave)
        .reply(Reply::FailBeforeSave);
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("but its approval was not updated"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        h.pin_for(&other),
        None,
        "the refused approval records nothing"
    );
    assert_eq!(h.pin_for(&tag), Some(a_pin.clone()));
    let overwritten: serde_json::Value =
        serde_json::from_slice(&fs::read(&approved_path).unwrap()).unwrap();
    assert_ne!(
        overwritten["manifest_digest"], a.manifest_digest,
        "the publication is not rolled back, so the alias still moved"
    );

    // G4's promise, now true: a launch keeps booting the previously approved
    // content, with no registry request.
    let before = server.count();
    let launched = h.launch(&tag);
    assert_eq!(
        sdk_image(&launched),
        approved_key,
        "the approved image still boots after a refused approval: {}",
        stderr(&launched)
    );
    assert_eq!(server.count(), before, "{:?}", server.requests());
    assert_eq!(
        fs::read(&approved_path).unwrap(),
        approved_bytes,
        "the repair restores the approved key byte for byte"
    );
}

/// Seed the cache with approved-ready content but neither an approval nor a
/// content receipt: the state a host that predates content receipts is in after
/// the import it once ran, whose approval this home has never recorded.
fn seed_receiptless_cache(h: &Harness, archive: &Path, tag: &str) {
    // The cache lives in the state directory and approvals live in `$HOME`, so
    // an import under a throwaway home fills exactly one of the two.
    let elsewhere = h.root.path().join("seeding-home");
    fs::create_dir_all(&elsewhere).unwrap();
    let mut command = h.command();
    command
        .env("HOME", &elsewhere)
        .stdin(std::process::Stdio::null())
        .args([
            "image",
            "import",
            "--input",
            archive.to_str().unwrap(),
            "--tag",
            tag,
        ]);
    let seeded = bounded(command);
    assert_eq!(seeded.status.code(), Some(0), "{}", stderr(&seeded));
    assert_eq!(
        h.pin_for(tag),
        None,
        "the throwaway import must approve nothing in the home under test"
    );
    forget_content_receipts(h);
}

/// Drop every content receipt, so the cache looks like one written before this
/// change: validated content, no evidence of it.
fn forget_content_receipts(h: &Harness) {
    match fs::remove_dir_all(h.cache().join("agent-vm-content-metadata")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        result => result.expect("drop the content receipts"),
    }
    assert!(
        content_receipts(h).is_empty(),
        "the seed must leave the cache with no content evidence"
    );
}

/// D11: a pin created by a launch from a **warm** cache — the shape of every pin
/// written before content evidence existed — still leaves that evidence, so an
/// archive alias of its digest cannot cost it offline availability.
///
/// The repair D10 added reads a content receipt for the exact acquired
/// `repo@digest`; a first pin that went through `CachedOrAcquire` used to write
/// none, and no part of this path can invent one from a cache whose key the
/// alias has already overwritten.
#[test]
fn a_receiptless_legacy_pin_survives_an_archive_alias_of_its_digest() {
    let h = Harness::new(Mode::LaunchSeam);
    // Bound but never served: a registry request fails this row instead of
    // silently succeeding.
    let server = Server::new();
    let tag = format!("{}/images:t", server.host);
    let a = archive_at(&h, "legacy-a.tar", "legacy-a");
    let approved_key = format!("{}/images@{}", server.host, a.manifest_digest);

    // 1. Cache content, no approval, no receipt.
    seed_receiptless_cache(&h, &a.path, &tag);

    // 2. The launch is the first post-upgrade event: a warm cache hit with no
    //    approval to start from, and no registry to ask.
    let before = server.count();
    let first = h.launch(&tag);
    assert_eq!(
        server.count(),
        before,
        "a warm first pin must not contact the registry: {:?}",
        server.requests()
    );
    assert_eq!(
        sdk_image(&first),
        approved_key,
        "the warm launch boots the digest the cache holds: {}",
        stderr(&first)
    );
    let a_pin = (a.manifest_digest.clone(), 1);
    assert_eq!(h.pin_for(&tag), Some(a_pin.clone()));
    // A's content-addressed metadata, byte for byte.
    let approved_path = cache_metadata_path(&h, &approved_key);
    let approved_bytes = fs::read(&approved_path).unwrap();

    // 3. Import B under a *different* result reference, spelling A's digest as an
    //    archive-carried name: the loader publishes that name, so A's key now
    //    describes B.
    let other = format!("{}/images:other", server.host);
    let save = image_archive::write_docker_save(
        &h.root.path().join("legacy-b.tar"),
        &[image_archive::DockerSaveImage {
            marker: "legacy-b".into(),
            repo_tags: Some(vec![approved_key.clone()]),
        }],
    );
    let imported = h.import(&save[0].path, &other);
    assert_eq!(imported.status.code(), Some(0), "{}", stderr(&imported));
    let (_, b_digest) = image_archive::docker_save_manifest("legacy-b");
    assert_eq!(
        h.pin_for(&other),
        Some((b_digest.clone(), 2)),
        "the alias import approves its own result at its global allocation"
    );
    let overwritten: serde_json::Value =
        serde_json::from_slice(&fs::read(&approved_path).unwrap()).unwrap();
    assert_eq!(
        overwritten["manifest_digest"],
        serde_json::json!(b_digest),
        "the fixture must really overwrite the digest-spelled key"
    );

    // 4. The approved tag still launches offline, at A, with A's metadata
    //    restored from the receipt.
    assert_eq!(
        h.pin_for(&tag),
        Some(a_pin),
        "an archive name never moves an approval"
    );
    let before = server.count();
    let launched = h.launch(&tag);
    assert_eq!(
        sdk_image(&launched),
        approved_key,
        "the legacy pin still boots its approved digest: {}",
        stderr(&launched)
    );
    assert_eq!(
        server.count(),
        before,
        "a repaired approved digest needs no registry: {:?}",
        server.requests()
    );
    assert_eq!(
        fs::read(&approved_path).unwrap(),
        approved_bytes,
        "the repair restores the approved key byte for byte"
    );

    // 5. The evidence that made the repair possible: the first pin validated
    //    content, so it left a content-only receipt for the exact identity a
    //    repair looks up. Asserted last so a missing receipt still shows up as the
    //    offline failure above, which is what a user would see.
    let receipt = receipt_for(&h, &a.manifest_digest).expect(
        "a first pin validates content, so it must leave content evidence for it (D11); \
         without one, an archive alias of that digest cannot be repaired",
    );
    assert_eq!(
        receipt["source_bindings"],
        serde_json::json!([]),
        "a cache hit proves what the cache holds, never a registry association"
    );
    assert_eq!(
        receipt["acquired_reference"],
        serde_json::json!(approved_key),
        "the receipt names the exact acquired identity a repair will look up"
    );
}

/// The same legacy sequence, with the alias import's own approval forced to fail
/// at the save: a refused approval must not cost the previously pinned image its
/// offline availability (G4).
#[test]
fn a_failed_approval_after_a_legacy_pin_cannot_cost_it_offline_availability() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:t", server.host);
    let a = archive_at(&h, "legacy-a.tar", "legacy-a");
    let approved_key = format!("{}/images@{}", server.host, a.manifest_digest);
    seed_receiptless_cache(&h, &a.path, &tag);
    let first = h.launch(&tag);
    assert_eq!(sdk_image(&first), approved_key, "{}", stderr(&first));
    let a_pin = (a.manifest_digest.clone(), 1);
    assert_eq!(h.pin_for(&tag), Some(a_pin.clone()));
    let approved_path = cache_metadata_path(&h, &approved_key);
    let approved_bytes = fs::read(&approved_path).unwrap();

    let other = format!("{}/images:other", server.host);
    let save = image_archive::write_docker_save(
        &h.root.path().join("legacy-b.tar"),
        &[image_archive::DockerSaveImage {
            marker: "legacy-b".into(),
            repo_tags: Some(vec![approved_key.clone()]),
        }],
    );
    let save_path = save[0].path.to_string_lossy().into_owned();
    let mut gate = PinGate::new(h.root.path());
    let peer = PinPeer::spawn(
        h.command(),
        &gate,
        &["image", "import", "--input", &save_path, "--tag", &other],
    );
    for stage in [
        PinStage::Published,
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    gate.expect(PinStage::BeforePinSave)
        .reply(Reply::FailBeforeSave);
    let out = peer.wait();
    drop(gate);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("but its approval was not updated"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        h.pin_for(&other),
        None,
        "the refused approval records nothing"
    );
    assert_eq!(h.pin_for(&tag), Some(a_pin));
    let (_, b_digest) = image_archive::docker_save_manifest("legacy-b");
    let overwritten: serde_json::Value =
        serde_json::from_slice(&fs::read(&approved_path).unwrap()).unwrap();
    assert_eq!(
        overwritten["manifest_digest"],
        serde_json::json!(b_digest),
        "the publication is not rolled back, so the alias still moved"
    );

    let before = server.count();
    let launched = h.launch(&tag);
    assert_eq!(
        sdk_image(&launched),
        approved_key,
        "the legacy pin still boots after a refused approval: {}",
        stderr(&launched)
    );
    assert_eq!(server.count(), before, "{:?}", server.requests());
    assert_eq!(
        fs::read(&approved_path).unwrap(),
        approved_bytes,
        "the repair restores the approved key byte for byte"
    );
}

fn image_archive_image(h: &Harness, marker: &str) -> Image {
    h.image(&ArchiveSpec {
        marker: marker.to_owned(),
        config_platform: PlatformSpec::Host,
        descriptor_platform: PlatformSpec::Host,
        layer: LayerContent::Valid,
        ..Default::default()
    })
}

/// A directory that exists is not an approval: the selection itself must be a
/// reference. This guards the local/OCI boundary from the other side.
#[test]
fn directory_selection_is_never_pinned() {
    let h = Harness::new(Mode::StrictAcquisition);
    let rootfs = h.root.path().join("plain-rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    let mut command = h.command();
    command.args(["--image", rootfs.to_str().unwrap(), "shell", "--", "true"]);
    let _ = bounded(command);
    assert!(
        !h.pins().exists(),
        "a local rootfs launch must never create an approval"
    );
    let _: &Path = &rootfs;
}

/// AC1/AC2, spec R4: approvals are per project. P1 pins a tag at A; P2 (same
/// HOME, independent cache) first-pins the same tag at whatever the registry
/// serves now, and P2's refresh moves only P2's record. P1 keeps booting A with
/// zero registry requests.
#[test]
fn projects_keep_independent_approvals_for_one_tag() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:split", server.host);
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "split", &a);

    // P1 pins the tag at A and boots A.
    let first = h.launch(&tag);
    assert!(!first.status.success(), "the fake runtime cannot boot");
    assert_eq!(sdk_image(&first), child_a);
    let p1_record = h
        .record_in(&h.project, &tag)
        .expect("P1 records its own approval");
    assert_eq!(p1_record["manifest_digest"], digest_of(&child_a));
    assert_eq!(p1_record["revision"], 1);

    // The registry moves the tag to B. P2 has no approval, so its first pin
    // resolves afresh from the registry: P1's record is never consulted.
    let p2 = h.project_at("second-project");
    let p2_state = tempfile::Builder::new()
        .prefix("avsplit-")
        .tempdir_in("/tmp")
        .unwrap();
    let b = h.image(&ArchiveSpec {
        marker: "split-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "split", &b);
    assert_ne!(child_a, child_b);
    let mut command = h.command_in(&p2, p2_state.path());
    command.args(["--image", &tag, "shell", "--", "true"]);
    assert_eq!(sdk_image(&bounded(command)), child_b);
    assert_eq!(
        h.record_in(&h.project, &tag).unwrap(),
        p1_record,
        "P2's first pin leaves P1's record byte-identical"
    );
    assert_eq!(
        h.pin_in(&p2, &tag),
        Some((digest_of(&child_b), 2)),
        "P2's own first pin draws the HOME-wide next allocation"
    );

    // A warm P1 launch boots A with no registry request at all.
    let before = server.count();
    assert_eq!(sdk_image(&h.launch(&tag)), child_a);
    assert_eq!(
        server.count(),
        before,
        "a warm P1 launch must make no registry request: {:?}",
        &server.requests()[before..]
    );

    // The registry moves the tag again; P2 refreshes with consent.
    let c = h.image(&ArchiveSpec {
        marker: "split-c".into(),
        ..Default::default()
    });
    let child_c = server.image("images", "split", &c);
    let mut command = h.command_in(&p2, p2_state.path());
    command.args(["image", "refresh", "--image", &tag]);
    let refreshed = bounded(command);
    assert!(refreshed.status.success(), "{}", stderr(&refreshed));
    assert_eq!(
        h.pin_in(&p2, &tag),
        Some((digest_of(&child_c), 3)),
        "only P2's record is replaced, at its next global allocation"
    );
    assert_eq!(
        h.record_in(&h.project, &tag).unwrap(),
        p1_record,
        "P2's refresh leaves P1's record and revision unchanged"
    );
    let before = server.count();
    assert_eq!(sdk_image(&h.launch(&tag)), child_a);
    assert_eq!(server.count(), before, "P1 still boots A, offline");
}

/// Spec R4/R6: a refresh in P1 replaces only P1's record. There is no decline
/// any more — the explicit command is the consent — so this row proves the
/// scope of the change, not the scope of a consent.
#[test]
fn a_refresh_in_one_project_cannot_touch_another() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let tag = format!("{}/images:decline", server.host);
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "decline", &a);

    // Both projects first-pin A while the tag still means A.
    assert!(!h.launch(&tag).status.success());
    let p2 = h.project_at("decline-project");
    let p2_state = tempfile::Builder::new()
        .prefix("avdecline-")
        .tempdir_in("/tmp")
        .unwrap();
    let mut command = h.command_in(&p2, p2_state.path());
    command.args(["--image", &tag, "shell", "--", "true"]);
    assert_eq!(sdk_image(&bounded(command)), child_a);
    let p2_record = h.record_in(&p2, &tag).unwrap();
    assert_eq!(p2_record["manifest_digest"], digest_of(&child_a));

    // Move the tag, then refresh in P1.
    let b = h.image(&ArchiveSpec {
        marker: "decline-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "decline", &b);
    let refreshed = h.refresh(&tag);
    assert!(refreshed.status.success(), "{}", stderr(&refreshed));
    assert_eq!(
        h.pin_in(&h.project, &tag),
        Some((digest_of(&child_b), 3)),
        "P1 replaces its own approval at the next global allocation"
    );
    assert_eq!(
        h.record_in(&p2, &tag).unwrap(),
        p2_record,
        "P2's record is byte-identical"
    );
}

/// AC3: a symlink alias is the same project (one record, no registry request on
/// the warm launch); a subdirectory is a different project (its own first pin).
#[test]
fn a_symlink_alias_shares_a_project_and_a_subdirectory_does_not() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:alias", server.host);
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "alias", &a);

    let alias = h.root.path().join("alias");
    std::os::unix::fs::symlink(&h.project, &alias).unwrap();
    let mut command = h.command_in(&alias, &h.state);
    command.args(["--image", &tag, "shell", "--", "true"]);
    assert_eq!(sdk_image(&bounded(command)), child_a);
    assert_eq!(h.records_in(&h.project), 1, "the alias is the same project");
    assert_eq!(h.records_in(&alias), 1);

    let before = server.count();
    let mut command = h.command_in(&alias, &h.state);
    command.args(["--image", &tag, "shell", "--", "true"]);
    assert_eq!(sdk_image(&bounded(command)), child_a);
    assert_eq!(
        server.count(),
        before,
        "the alias consumes the project's approval: {:?}",
        &server.requests()[before..]
    );
    assert_eq!(
        h.records_in(&h.project),
        1,
        "no second record for the alias"
    );

    // A subdirectory is a distinct project with its own first pin.
    let sub = h.project.join("sub");
    fs::create_dir_all(&sub).unwrap();
    let mut command = h.command_in(&sub, &h.state);
    command.args(["--image", &tag, "shell", "--", "true"]);
    assert_eq!(sdk_image(&bounded(command)), child_a);
    assert_eq!(h.records_in(&h.project), 1, "the parent is unchanged");
    assert_eq!(h.records_in(&sub), 1, "the subdirectory pins separately");
    assert_eq!(
        h.pin_in(&sub, &tag),
        Some((digest_of(&child_a), 2)),
        "a subdirectory's own first pin draws the next global allocation"
    );
}

/// AC3 control: the state root is not the approval scope. A cold cache under a
/// second `AGENT_VM_STATE_DIR` still boots the project's approved digest, asks
/// the registry for that digest and never for the tag, and writes nothing.
#[test]
fn another_state_root_is_the_same_project() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:stateroot", server.host);
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "stateroot", &a);
    assert!(!h.launch(&tag).status.success());
    assert_eq!(sdk_image(&h.launch(&tag)), child_a);
    let store = fs::read(h.pins()).unwrap();

    let b = h.image(&ArchiveSpec {
        marker: "stateroot-b".into(),
        ..Default::default()
    });
    server.image("images", "stateroot", &b);

    let cold_state = tempfile::Builder::new()
        .prefix("avcold-")
        .tempdir_in("/tmp")
        .unwrap();
    // What makes this row a cold-cache control: the second state root holds no
    // cache at all, so the launch has to reach the registry for the approved
    // digest rather than reuse the first project's bytes.
    assert!(
        !cold_state.path().join("msb-home/cache").exists(),
        "the second state root starts with no cache"
    );
    let before = server.requests().len();
    let mut command = h.command_in(&h.project, cold_state.path());
    command.args(["--image", &tag, "shell", "--", "true"]);
    let cold = bounded(command);
    assert_eq!(
        sdk_image(&cold),
        child_a,
        "the state root is not the approval scope"
    );
    let requests = server.requests();
    let after = &requests[before..];
    assert!(
        after
            .iter()
            .any(|(_, path)| path == &format!("/v2/images/manifests/{}", a.written.manifest_digest)),
        "the cold cache requests the approved digest: {after:?}"
    );
    assert!(
        !after
            .iter()
            .any(|(_, path)| path == "/v2/images/manifests/stateroot"),
        "the tag is never requested: {after:?}"
    );
    assert_eq!(fs::read(h.pins()).unwrap(), store, "no record was written");
}

/// AC4: an import in P1 approves the result for P1 only. P2's existing
/// approval for the same reference is byte-identical, and a P2 launch still
/// hands the SDK P2's approved digest.
#[test]
fn an_import_approves_only_its_own_project() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:import-scope", server.host);
    let old = archive_at(&h, "import-scope-old.tar", "old");
    let new = archive_at(&h, "import-scope-new.tar", "new");
    let p2 = h.project_at("import-project");

    // P2 imports the old bytes under the reference; both projects share the
    // state root, so they share the cache but not the approval.
    let mut command = h.command_in(&p2, &h.state);
    command
        .stdin(std::process::Stdio::null())
        .args(["image", "import", "--input", old.path.to_str().unwrap()])
        .args(["--tag", &tag]);
    let out = bounded(command);
    assert!(out.status.success(), "{}", stderr(&out));
    let p2_record = h.record_in(&p2, &tag).unwrap();
    assert_eq!(p2_record["manifest_digest"], old.manifest_digest);

    // P1 imports different bytes under the same reference.
    let out = h.import(&new.path, &tag);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        h.pin_in(&h.project, &tag),
        Some((new.manifest_digest.clone(), 2)),
        "P1 approves its own result at the next global allocation"
    );
    assert_eq!(
        h.record_in(&p2, &tag).unwrap(),
        p2_record,
        "P2's approval is byte-identical"
    );

    let mut command = h.command_in(&p2, &h.state);
    command.args(["--image", &tag, "shell", "--", "true"]);
    assert_eq!(
        sdk_image(&bounded(command)),
        format!("{}/images@{}", server.host, old.manifest_digest),
        "P2 still hands the SDK its own approved digest"
    );
    assert_eq!(server.count(), 0, "{:?}", server.requests());
}

/// AC4 for `image build`: the same isolation through the Docker path.
#[test]
fn a_build_approves_only_its_own_project() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:build-scope", server.host);
    let old = archive_at(&h, "build-scope-old.tar", "old");
    let new = archive_at(&h, "build-scope-new.tar", "new");
    let p2 = h.project_at("build-project");

    let mut command = h.command_in(&p2, &h.state);
    command
        .env("FAKE_DOCKER_ARCHIVE", &old.path)
        .args(["image", "build", "--tag", &tag]);
    let out = bounded(command);
    assert!(out.status.success(), "{}", stderr(&out));
    let p2_record = h.record_in(&p2, &tag).unwrap();
    assert_eq!(p2_record["manifest_digest"], old.manifest_digest);

    let out = h.build(&new.path, &tag);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        h.pin_in(&h.project, &tag),
        Some((new.manifest_digest.clone(), 2)),
        "P1 approves its own build result at the next global allocation"
    );
    assert_eq!(
        h.record_in(&p2, &tag).unwrap(),
        p2_record,
        "P2's approval is byte-identical"
    );

    let mut command = h.command_in(&p2, &h.state);
    command.args(["--image", &tag, "shell", "--", "true"]);
    assert_eq!(
        sdk_image(&bounded(command)),
        format!("{}/images@{}", server.host, old.manifest_digest),
        "P2 still hands the SDK its own approved digest"
    );
}

/// AC4/R3: `doctor` observes the invoking project's approval, not another
/// project's, even though both share one HOME and one cache.
#[test]
fn doctor_reports_each_projects_own_approved_content() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:doctor-scope", server.host);
    let labelled = |h: &Harness, marker: &str, host: &str| {
        h.image(&ArchiveSpec {
            marker: marker.to_owned(),
            labels: vec![(
                "org.agent-vm.network-requests.image.base".to_owned(),
                host.to_owned(),
            )],
            ..Default::default()
        })
    };
    let a = labelled(&h, "doctor-a", "a.example");
    let child_a = server.image("images", "doctor-scope", &a);
    assert!(!h.launch(&tag).status.success());
    assert_eq!(sdk_image(&h.launch(&tag)), child_a);

    // Move the tag and let P2 approve B for itself. A first pin here would be
    // cache-first and reuse P1's alias, so P2 resolves explicitly: a shared
    // cache is still shared, only the approval is per project.
    let p2 = h.project_at("doctor-project");
    let b = labelled(&h, "doctor-b", "b.example");
    server.image("images", "doctor-scope", &b);
    let out = h.refresh_as_ambient_in(&p2, &h.state, &tag);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        h.pin_in(&p2, &tag).unwrap().1,
        2,
        "P2's own first approval draws the HOME-wide next allocation"
    );

    let doctor_in = |project: &Path| {
        let mut command = h.command_in(project, &h.state);
        command.env("AGENT_VM_IMAGE_TAG", &tag).arg("doctor");
        let out = bounded(command);
        assert!(out.status.success(), "{}", stderr(&out));
        stdout_of(&out)
    };
    let section = |text: &str| {
        let start = text
            .find("==> image network requests")
            .unwrap_or_else(|| panic!("no image section in:\n{text}"));
        let rest = &text[start..];
        let end = rest
            .find("\n==> agent-vm doctor: available operations")
            .unwrap_or(rest.len());
        rest[..end].to_owned()
    };
    let p1_section = section(&doctor_in(&h.project));
    let p2_section = section(&doctor_in(&p2));
    assert!(
        p1_section.contains("for every launch a.example"),
        "P1's own approved content:\n{p1_section}"
    );
    assert!(
        !p1_section.contains("b.example"),
        "P1 must not report P2's content:\n{p1_section}"
    );
    assert!(
        p2_section.contains("for every launch b.example"),
        "P2's own approved content:\n{p2_section}"
    );
    assert!(
        !p2_section.contains("a.example"),
        "P2 must not report P1's content:\n{p2_section}"
    );
}

/// A CLI-shaped version-1 store, exactly what 0.7.38 writes: the bytes the
/// upgrade section archives.
fn legacy_store() -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "version": 1,
        "pins": [{
            "reference": "127.0.0.1:1/images:legacy",
            "platform": {
                "os": "linux",
                "architecture": image_archive::host_arch(),
                "variant": null
            },
            "manifest_digest": format!("sha256:{}", "1".repeat(64)),
            "revision": 1
        }],
        "pending_default": null
    }))
    .unwrap()
}

fn config_dir(h: &Harness) -> PathBuf {
    h.home.join(".config/agent-vm")
}

/// Install `bytes` as the store, with the stable lock a real store always has.
fn seed_store(h: &Harness, bytes: &[u8]) {
    fs::create_dir_all(config_dir(h)).unwrap();
    fs::write(h.pins(), bytes).unwrap();
    fs::write(config_dir(h).join("image-pins.lock"), b"").unwrap();
}

/// AC5: a valid, lock-accompanied version-1 store refuses every OCI command
/// with the legacy error — before any registry request, cache publication,
/// Docker run or SDK create — and no approval-authority file is created or
/// changed. `--yes` is a usage error now (AC13, covered by
/// `the_yes_flag_is_removed_from_both_verbs`), a local path still reaches the
/// runtime, and once the store is archived the next launch makes a first pin.
#[test]
fn a_legacy_host_wide_store_is_refused_until_upgraded() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:legacy", server.host);
    let image = h.image(&ArchiveSpec::default());
    server.image("images", "legacy", &image);
    let archive = archive_at(&h, "legacy.tar", "legacy");
    let legacy = legacy_store();
    seed_store(&h, &legacy);
    let docker_marker = h.root.path().join("docker-ran");
    let authority_files = || {
        let mut names: Vec<String> = fs::read_dir(config_dir(&h))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    };
    let before_files = authority_files();

    let mut outputs = Vec::new();
    let run = |args: &[&str]| {
        let mut command = h.command();
        command
            .env("FAKE_DOCKER_ARCHIVE", &archive.path)
            .env("FAKE_DOCKER_MARKER", &docker_marker)
            .stdin(std::process::Stdio::null())
            .args(args);
        bounded(command)
    };
    outputs.push(("launch", run(&["--image", &tag, "shell", "--", "true"])));
    outputs.push(("setup", run(&["setup", "--image", &tag, "--no-verify"])));
    outputs.push(("refresh", run(&["image", "refresh", "--image", &tag])));
    outputs.push((
        "set-default",
        run(&["image", "set-default", "--image", &tag]),
    ));
    outputs.push(("build", run(&["image", "build", "--tag", &tag])));
    outputs.push((
        "import",
        run(&[
            "image",
            "import",
            "--input",
            archive.path.to_str().unwrap(),
            "--tag",
            &tag,
        ]),
    ));
    for (label, out) in &outputs {
        let text = stderr(out);
        assert!(!out.status.success(), "{label} must fail: {text}");
        assert!(
            text.contains("host-wide version 1 format"),
            "{label} must name the legacy format: {text}"
        );
        assert!(
            !text.contains("damaged"),
            "{label} must not call a legacy store damage: {text}"
        );
    }
    assert_eq!(
        create_invocations(&h),
        0,
        "no SDK create may happen: {}",
        h.msb_invocations()
    );
    assert_eq!(
        server.count(),
        0,
        "no registry request may happen: {:?}",
        server.requests()
    );
    assert!(
        !docker_marker.exists(),
        "Docker must not run for a refused build"
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        legacy,
        "the legacy store is never rewritten"
    );
    assert_eq!(
        authority_files(),
        before_files,
        "no approval-authority file is created"
    );

    // A local rootfs launch bypasses approval entirely and reaches the runtime.
    let rootfs = h.project_at("rootfs");
    let mut command = h.command();
    command.args(["--image", rootfs.to_str().unwrap(), "shell", "--", "true"]);
    let local = bounded(command);
    assert!(
        !stderr(&local).contains("image-pins.json"),
        "a local path never consults the approval store: {}",
        stderr(&local)
    );
    // The existing local-path runtime path, reached unchanged. That path then
    // fails at config validation (`root_disk() is only valid for OCI images`),
    // which is the known non-OCI limitation, not an approval refusal.
    assert!(
        stderr(&local).contains("rootfs"),
        "a local path reaches the runtime unchanged: {}",
        stderr(&local)
    );

    // The upgrade's effect: archive the store (keeping the lock), then a launch
    // makes a first pin.
    fs::rename(h.pins(), h.root.path().join("v1-archive-image-pins.json")).unwrap();
    let out = h.launch(&tag);
    assert_eq!(
        sdk_image(&out),
        format!("{}/images@{}", server.host, image.written.manifest_digest),
        "the archived store's next launch makes a first pin"
    );
    let record = h.record_in(&h.project, &tag).expect("a first pin");
    let store: serde_json::Value = serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    assert_eq!(store["version"], 2);
    assert_eq!(record["revision"], 1);
}

/// AC6: a version-2 store whose `project` field is malformed is damage, not the
/// legacy error.
#[test]
fn a_malformed_project_scope_is_damage_not_legacy() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:malformed", server.host);
    let image = h.image(&ArchiveSpec::default());
    server.image("images", "malformed", &image);
    let out = h.refresh_as_ambient(&tag);
    assert!(out.status.success(), "{}", stderr(&out));

    let mut store: serde_json::Value =
        serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    store["pins"][0]["project"] = "XYZ".into();
    fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
    let bytes = fs::read(h.pins()).unwrap();

    let before = server.count();
    let out = h.launch(&tag);
    let text = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("damaged"), "{text}");
    assert!(!text.contains("host-wide version 1"), "{text}");
    assert_eq!(fs::read(h.pins()).unwrap(), bytes);
    assert_eq!(
        server.count(),
        before,
        "a damaged store fails before the network: {:?}",
        &server.requests()[before..]
    );
}

/// AC7: the pin's `project` names the same project whose 12-hex prefix names
/// the session state directory the launch created.
#[test]
fn a_launch_pin_names_its_session_project() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:identity", server.host);
    let image = h.image(&ArchiveSpec::default());
    let child = server.image("images", "identity", &image);
    let id = project_id(&h.project);

    assert_eq!(sdk_image(&h.launch(&tag)), child);
    let record = h.record_in(&h.project, &tag).expect("the launch pinned");
    assert_eq!(record["project"], id.as_str());
    let session = h.state.join(&id[..12]);
    assert!(
        session.join("claude").is_dir(),
        "the launch created the session directory named by the project's prefix: {}",
        session.display()
    );
}

/// AC7: an external rename while Docker runs does not split the command. The
/// approval lands under the project the command started in, and no record names
/// the renamed path.
#[test]
fn a_project_renamed_during_docker_export_keeps_its_identity() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:rename-build", server.host);
    server.image("images", "rename-build", &h.image(&ArchiveSpec::default()));
    let archive = archive_at(&h, "rename-build.tar", "rename-build");
    let original = project_id(&h.project);
    let renamed = h.root.path().join("renamed-project");

    let mut command = h.command();
    command
        .env("FAKE_DOCKER_ARCHIVE", &archive.path)
        .env("FAKE_DOCKER_RENAME_CWD_TO", &renamed)
        .args(["image", "build", "--tag", &tag]);
    let out = bounded(command);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(renamed.is_dir(), "the fake Docker renamed the project");
    assert!(!h.project.exists());

    let store: serde_json::Value = serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    let records = store["pins"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{store}");
    assert_eq!(
        records[0]["project"], original,
        "the approval names the project the command started in"
    );
    assert_ne!(
        records[0]["project"],
        project_id(&renamed),
        "no record names the renamed path"
    );
    assert_eq!(records[0]["manifest_digest"], archive.manifest_digest);
}

/// AC7 through the first-pin path: renaming the project while the candidate is
/// acquired still records the project the command started in, and the session
/// directory carries the same identity.
#[test]
fn a_project_renamed_during_first_pin_acquisition_keeps_its_identity() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let tag = format!("{}/images:rename-pin", server.host);
    let image = h.image(&ArchiveSpec::default());
    let child = server.image("images", "rename-pin", &image);
    let original = project_id(&h.project);
    let renamed = h.root.path().join("renamed-during-pin");

    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    gate.attach(&mut command);
    let launched = PinPeer::spawn(command, &gate, &["--image", &tag, "shell", "--", "true"]);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let checkpoint = gate.expect(PinStage::BeforePinLock);
    // The child is paused before its first write: rename the project now, the
    // way an external process can, with no `chdir` in the child.
    fs::rename(&h.project, &renamed).unwrap();
    checkpoint.reply(Reply::Continue);
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinSave).reply(Reply::Continue);
    gate.expect(PinStage::PinCommitted).reply(Reply::Continue);
    let out = launched.wait();
    drop(gate);
    assert_eq!(sdk_image(&out), child);

    let store: serde_json::Value = serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    let records = store["pins"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{store}");
    assert_eq!(records[0]["project"], original);
    assert_ne!(records[0]["project"], project_id(&renamed));
    assert!(
        h.state.join(&original[..12]).join("claude").is_dir(),
        "the session directory carries the same identity"
    );
    assert!(!h.state.join(&project_id(&renamed)[..12]).exists());
}

#[test]
fn a_foreign_platform_record_is_preserved_not_borrowed() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "platform", &a);
    let tag = format!("{}/images:platform", server.host);
    assert!(h.refresh_as_ambient(&tag).status.success());
    let mut store: serde_json::Value =
        serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    let arch = if image_archive::host_arch() == "arm64" {
        "amd64"
    } else {
        "arm64"
    };
    store["pins"][0]["platform"]["architecture"] = arch.into();
    let foreign = store["pins"][0].clone();
    fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
    let b = h.image(&ArchiveSpec {
        marker: "platform-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "platform", &b);
    // A validated mutable cache is a legitimate first-pin source. Remove only
    // the owned cache so this test measures native B rather than cached A.
    fs::remove_dir_all(h.cache()).unwrap();
    assert_ne!(child_a, child_b);
    assert_eq!(sdk_image(&h.launch(&tag)), child_b);
    let store: serde_json::Value = serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    let pins = store["pins"].as_array().unwrap();
    assert_eq!(pins.len(), 2);
    assert!(pins.contains(&foreign));
    let native = pins
        .iter()
        .find(|p| p["platform"]["architecture"] == image_archive::host_arch())
        .unwrap();
    assert_eq!(native["manifest_digest"], b.written.manifest_digest);
    let start = server.count();
    assert_eq!(sdk_image(&h.launch(&tag)), child_b);
    assert_eq!(server.count(), start);
}

/// R6/D5: the candidate is resolved once and frozen. The tag moves while the
/// command is paused at `candidate-ready`; the commit names the content that was
/// resolved, and the next warm launch boots it offline.
///
/// For `set-default` this also proves R5: one tag-manifest request, a host record
/// naming the resolved child, and no pin store at all.
#[test]
fn a_resolved_candidate_is_frozen_for_refresh_and_set_default() {
    for verb in ["refresh", "set-default"] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        server.image("images", "frozen", &a);
        let tag = format!("{}/images:frozen", server.host);
        if verb == "refresh" {
            // A refresh needs an approval to replace; the fixture is a refresh.
            assert!(h.refresh_as_ambient(&tag).status.success());
        }
        let b = h.image(&ArchiveSpec {
            marker: "frozen-b".into(),
            ..Default::default()
        });
        let child_b = server.image("images", "frozen", &b);
        let start = server.requests().len();
        let mut gate = PinGate::new(h.root.path());
        let mut command = h.command();
        if verb == "refresh" {
            // The fixture's tag must be the ambient selection to be in use.
            command
                .env("AGENT_VM_IMAGE_TAG", &tag)
                .arg("image")
                .arg("refresh");
        } else {
            command.args(["image", verb, "--image", &tag]);
        }
        let peer = PinPeer::spawn(command, &gate, &[]);
        gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
        // The tag moves to C after the command resolved B.
        let c = h.image(&ArchiveSpec {
            marker: "frozen-c".into(),
            ..Default::default()
        });
        server.image("images", "frozen", &c);
        let after_resolve = server.requests().len();
        // A refresh commits a pin; set-default commits only the host record.
        let stages: &[PinStage] = if verb == "refresh" {
            &[
                PinStage::BeforePinLock,
                PinStage::PinLocked,
                PinStage::BeforePinSave,
                PinStage::PinCommitted,
            ]
        } else {
            &[
                PinStage::BeforePinLock,
                PinStage::PinLocked,
                PinStage::BeforeDefaultSave,
                PinStage::DefaultSaved,
            ]
        };
        for stage in stages {
            gate.expect(*stage).reply(Reply::Continue);
        }
        let out = peer.wait();
        assert!(out.status.success(), "{verb}: {}", stderr(&out));
        assert_eq!(
            server.requests()[start..]
                .iter()
                .filter(|(_, path)| path == "/v2/images/manifests/frozen")
                .count(),
            1,
            "{verb} must request the tag manifest once"
        );
        if verb == "refresh" {
            assert_eq!(h.pinned_digest(), digest_of(&child_b));
            assert_eq!(
                sdk_image(&h.launch(&tag)),
                child_b,
                "the frozen candidate is what the warm launch boots"
            );
            assert_eq!(
                server.count(),
                after_resolve,
                "the warm launch consumes B offline"
            );
        } else {
            let default: serde_json::Value = serde_json::from_slice(
                &fs::read(h.home.join(".config/agent-vm/default-image.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(default, serde_json::json!({"version":1,"image":child_b}));
            assert!(
                !h.pins().exists(),
                "set-default writes no approval in any project"
            );
        }
    }
}

fn set_default(h: &Harness, tag: &str) -> Output {
    let mut cmd = h.command();
    cmd.args(["image", "set-default", "--image", tag]);
    bounded(cmd)
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// R9/D2: no operation writes a journal, and no S1 journal is written either.
///
/// (a) `image set-default` has one host-record save. An interruption before it
/// leaves the old record, after it the new one, and no approval either way.
/// (b) A recommendation-sourced first default-tier launch writes the host record
/// **first** and the pin store second, which is the narrowed ADR-0047 guarantee.
#[test]
fn interrupted_pin_transactions_keep_old_logical_state_and_recover() {
    // (a) set-default's single host save.
    for stop in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforeDefaultSave,
        PinStage::DefaultSaved,
    ] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let child_a = server.image("images", "journal", &a);
        let tag = format!("{}/images:journal", server.host);
        assert!(set_default(&h, &tag).status.success());
        let default = h.home.join(".config/agent-vm/default-image.json");
        let old_default = fs::read(&default).unwrap();
        let b = h.image(&ArchiveSpec {
            marker: "journal-b".into(),
            ..Default::default()
        });
        let child_b = server.image("images", "journal", &b);
        let mut gate = PinGate::new(h.root.path());
        let peer = pin_peer(&h, &gate, &["image", "set-default", "--image", &tag]);
        for stage in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
            PinStage::BeforeDefaultSave,
            PinStage::DefaultSaved,
        ] {
            let checkpoint = gate.expect(stage);
            if stage == stop {
                drop(peer);
                drop(checkpoint);
                break;
            }
            checkpoint.reply(Reply::Continue);
        }
        let written = stop == PinStage::DefaultSaved;
        let expected = if written { &child_b } else { &child_a };
        let physical_default = fs::read(&default).unwrap();
        if written {
            assert_eq!(
                read_json(&default),
                serde_json::json!({"version":1,"image":expected})
            );
        } else {
            assert_eq!(physical_default, old_default);
        }
        assert!(
            !h.pins().exists(),
            "set-default commits no approval in any project"
        );
        let mut cmd = h.command();
        cmd.args(["image", "show"]);
        let show = bounded(cmd);
        assert!(show.status.success(), "{stop:?}: {}", stderr(&show));
        assert!(
            stdout_of(&show).contains(expected),
            "{stop:?}: {}",
            stdout_of(&show)
        );
        let mut cmd = h.command();
        cmd.arg("doctor");
        let doctor = bounded(cmd);
        assert!(doctor.status.success(), "{}", stderr(&doctor));
        assert!(
            stdout_of(&doctor).contains("default: retained default"),
            "{}",
            stdout_of(&doctor)
        );
        // An observation never repairs: bytes are exactly what the interruption
        // left, and there is no journal to recover.
        assert_eq!(fs::read(&default).unwrap(), physical_default);
        assert!(!h.pins().exists());
    }

    // (b) A recommendation first launch: host record first, then the pin store.
    for stop in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforeDefaultSave,
        PinStage::DefaultSaved,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let child_a = server.image("images", "recommend", &a);
        let mut command = h.command();
        command
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child_a)
            .args(["shell", "--", "true"]);
        let mut gate = PinGate::new(h.root.path());
        let peer = pin_gate::PinPeer::spawn(command, &gate, &[]);
        for stage in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
            PinStage::BeforeDefaultSave,
            PinStage::DefaultSaved,
            PinStage::BeforePinSave,
            PinStage::PinCommitted,
        ] {
            let checkpoint = gate.expect(stage);
            if stage == stop {
                drop(peer);
                drop(checkpoint);
                break;
            }
            checkpoint.reply(Reply::Continue);
        }
        let default = h.home.join(".config/agent-vm/default-image.json");
        let host_written = matches!(
            stop,
            PinStage::DefaultSaved | PinStage::BeforePinSave | PinStage::PinCommitted
        );
        assert_eq!(
            fs::read(&default).is_ok(),
            host_written,
            "{stop:?}: the host record is written before the pin store"
        );
        if host_written {
            assert_eq!(
                read_json(&default),
                serde_json::json!({"version":1,"image":child_a})
            );
        }
        if stop == PinStage::PinCommitted {
            let store = read_json(&h.pins());
            assert_eq!(store["pins"].as_array().unwrap().len(), 1);
            assert_eq!(store["defaults"].as_array().unwrap().len(), 1);
            assert!(store["pending_default"].is_null(), "no journal is written");
        } else {
            assert!(
                !h.pins().exists(),
                "{stop:?}: an interruption before the pin save leaves no store"
            );
        }
    }
}

/// One gated set-default peer.
fn pin_peer(h: &Harness, gate: &PinGate, args: &[&str]) -> PinPeer {
    let mut command = h.command();
    command.args(args);
    pin_gate::PinPeer::spawn(command, gate, &[])
}

/// R6/D5 (fault row): a failed first default-tier launch may leave the host
/// starting choice initialized with measured content — the narrowed ADR-0047
/// guarantee — and never a project default without its pin.
#[test]
fn a_failed_first_default_pin_may_leave_the_host_starting_choice_initialized() {
    // A fault before the host save writes nothing at all.
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "fault", &a);
    let default = h.home.join(".config/agent-vm/default-image.json");
    let mut gate = PinGate::new(h.root.path());
    let peer = pin_peer_recommendation(&h, &gate, &child_a);
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    gate.expect(PinStage::BeforeDefaultSave)
        .reply(Reply::FailBeforeSave);
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(!default.exists(), "nothing is written");
    assert!(!h.pins().exists(), "nothing is written");

    // A fault at the pin save leaves the host record initialized with the
    // measured recommendation, and the next launch completes establishment from
    // it without any registry request beyond the cache.
    let mut gate = PinGate::new(h.root.path());
    let peer = pin_peer_recommendation(&h, &gate, &child_a);
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforeDefaultSave,
        PinStage::DefaultSaved,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    gate.expect(PinStage::BeforePinSave)
        .reply(Reply::FailBeforeSave);
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        read_json(&default),
        serde_json::json!({"version":1,"image":child_a}),
        "the host starting choice holds measured content"
    );
    assert!(!h.pins().exists(), "the pin store was never written");

    // The next default-tier use establishes from the host record, cache-first.
    let before = server.count();
    let mut command = h.command();
    command.args(["shell", "--", "true"]);
    let relaunch = bounded(command);
    assert!(!relaunch.status.success(), "the fake runtime cannot boot");
    assert_eq!(server.count(), before, "the cache answers the relaunch");
    let store = read_json(&h.pins());
    assert_eq!(store["pins"].as_array().unwrap().len(), 1);
    assert_eq!(store["defaults"][0]["image"], child_a.as_str());
}

/// A launch of the debug-only initial recommendation, and nothing else.
fn pin_peer_recommendation(h: &Harness, gate: &PinGate, recommendation: &str) -> PinPeer {
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", recommendation)
        .args(["shell", "--", "true"]);
    pin_gate::PinPeer::spawn(command, gate, &[])
}

#[test]
fn alternate_manifest_algorithms_keep_equivalent_approval_bytes() {
    for algorithm in ["sha384", "sha512"] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let child = server.image("images", "equivalent", &a);
        let tag = format!("{}/images:equivalent", server.host);
        assert!(h.refresh_as_ambient(&tag).status.success());
        let old = fs::read(h.pins()).unwrap();
        let manifest = &a.blobs[&a.written.manifest_digest];
        let digest = oci_registry::digest_hex(algorithm, manifest);
        server.put_manifest_under_algorithm("images", manifest, algorithm);
        server.put_with_header(
            "/v2/images/manifests/equivalent",
            manifest,
            "application/vnd.oci.image.manifest.v1+json",
            &digest,
        );
        let out = h.refresh_as_ambient(&tag);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(!stderr(&out).contains("Approve"));
        assert_eq!(
            fs::read(h.pins()).unwrap(),
            old,
            "equivalent config/layers keep revision and approved identity"
        );
        let start = server.count();
        assert_eq!(sdk_image(&h.launch(&tag)), child);
        assert_eq!(server.count(), start);
    }
}

#[test]
fn held_authority_lock_bounds_reads_and_mutation_waits() {
    use std::os::fd::AsRawFd;
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    server.image("images", "lock", &a);
    let tag = format!("{}/images:lock", server.host);
    // The row reads both records, so the fixture must create both: S1's
    // set-default used to write the pin itself (fixture-only change, #541).
    h.pin_and_set_default(&tag);
    let old = fs::read(h.pins()).unwrap();
    let default = h.home.join(".config/agent-vm/default-image.json");
    let old_default = fs::read(&default).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(h.pins().with_extension("lock"))
        .unwrap();
    let mut gate = PinGate::new(h.root.path());
    let peer = pin_gate::PinPeer::spawn(refresh_as_ambient_command(&h, &tag), &gate, &[]);
    let start = std::time::Instant::now();
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let before_lock = gate.expect(PinStage::BeforePinLock);
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    before_lock.reply(Reply::Continue);
    for verb in ["image", "doctor"] {
        let mut cmd = h.command();
        cmd.arg(verb);
        if verb == "image" {
            cmd.arg("show");
        }
        let read_start = std::time::Instant::now();
        let out = bounded(cmd);
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert!(read_start.elapsed() >= Duration::from_secs(2));
        assert!(read_start.elapsed() < Duration::from_secs(8));
    }
    // The one-time wait notice is attempted at the normal one-second threshold,
    // while this test still holds the real exclusive pin lock.
    gate.expect(PinStage::AuthorityNoticeAttempted)
        .reply(Reply::Continue);
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(start.elapsed() >= Duration::from_secs(30));
    assert!(start.elapsed() < Duration::from_secs(38));
    assert_eq!(fs::read(h.pins()).unwrap(), old);
    assert_eq!(fs::read(default).unwrap(), old_default);
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    assert!(
        h.refresh_as_ambient(&tag).status.success(),
        "timeout must release all locks"
    );
}

#[test]
fn unwritable_authority_preserves_a_with_a_root_safe_fault_control() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "permission", &a);
    let tag = format!("{}/images:permission", server.host);
    h.pin_and_set_default(&tag);
    let old = fs::read(h.pins()).unwrap();
    let b = h.image(&ArchiveSpec {
        marker: "permission-b".into(),
        ..Default::default()
    });
    server.image("images", "permission", &b);
    let mut gate = PinGate::new(h.root.path());
    let peer = pin_gate::PinPeer::spawn(refresh_as_ambient_command(&h, &tag), &gate, &[]);
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    let save = gate.expect(PinStage::BeforePinSave);
    let directory = h.pins().parent().unwrap().to_owned();
    let permissions = fs::metadata(&directory).unwrap().permissions();
    if unsafe { libc::geteuid() } == 0 {
        // Root bypasses DAC: this is an injected pre-write failure, NOT EACCES.
        save.reply(Reply::FailBeforeSave);
    } else {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(
            fs::write(directory.join("eacces-control"), b"must fail")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        save.reply(Reply::Continue);
    }
    let out = peer.wait();
    fs::set_permissions(directory, permissions).unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(fs::read(h.pins()).unwrap(), old);
    let start = server.count();
    assert_eq!(sdk_image(&h.launch(&tag)), child_a);
    assert_eq!(server.count(), start);
}

/// R7 fault row: adoption is one compare-and-swap save. A failure before that
/// save leaves the old store bytes, the old project default and no `(P, H)`
/// approval, and the project still boots D.
#[test]
fn a_failed_adoption_save_keeps_the_project_default() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_d = server.image("images", "adopt-fault", &a);
    // D: the project's own established default.
    assert!(!h.launch_on_recommendation(&child_d).status.success());
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_d);
    // H: a different retained host record for the same repository.
    let b = h.image(&ArchiveSpec {
        marker: "adopt-fault-b".into(),
        ..Default::default()
    });
    let child_h = server.image("images", "adopt-fault", &b);
    let tag = format!("{}/images:adopt-fault", server.host);
    let set = set_default(&h, &tag);
    assert!(set.status.success(), "{}", stderr(&set));
    assert_eq!(h.host_record().unwrap()["image"], child_h);
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child_d,
        "set-default moves no project default"
    );
    let old = fs::read(h.pins()).unwrap();

    // The bare refresh adopts H, but its one save is refused.
    let mut gate = PinGate::new(h.root.path());
    let peer = pin_gate::PinPeer::spawn(h.command(), &gate, &["image", "refresh"]);
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    gate.expect(PinStage::BeforePinSave)
        .reply(Reply::FailBeforeSave);
    // D still holds Boot, so S4 refreshes it independently after the failed
    // adoption: the old default was re-resolved once and is unchanged, which
    // needs no save and therefore no `BeforePinSave`.
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    assert!(
        text.contains("refresh [1/2]") && text.contains("failed"),
        "the adoption failure is a row: {text}"
    );
    assert!(
        text.contains("refresh [2/2]")
            && !text.contains("refresh [2/2] the default boot image (linux/arm64): failed"),
        "the still-held old default is refreshed independently: {text}"
    );
    assert!(
        text.contains("==> image refresh: 1 succeeded, 1 failed"),
        "{text}"
    );
    assert!(
        !text.contains("nothing was acquired or approved"),
        "a post-freeze failure is not a batch-wide refusal: {text}"
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        old,
        "the refused adoption left the store byte-identical"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child_d,
        "defaults[P] is still D"
    );
    assert!(
        h.pin_in(&h.project, &child_h).is_none(),
        "no (P, H) approval was inserted"
    );
    assert_eq!(
        h.reacquired_digest(&server),
        digest_of(&child_d),
        "the next launch still boots D"
    );
}

/// Run `args` in the harness with the child's stderr connected to a Unix socket
/// whose peer is gone, so every write to stderr fails (`EPIPE`). A closed
/// standard descriptor is not the same experiment: the runtime repairs a missing
/// stderr, so that control succeeded. The debug-config dump is off: this row is
/// about the render, not about unrelated output.
fn with_unwritable_stderr(h: &Harness, args: &[&str]) -> Output {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    let (writer, reader) = UnixStream::pair().expect("create the socket pair");
    drop(reader);
    let mut command = h.command();
    command.env_remove("AGENT_VM_DEBUG_CONFIG").args(args);
    let writer: OwnedFd = writer.into();
    bounded_with_stderr(command, std::process::Stdio::from(writer))
}

/// R6: a render that cannot be written commits nothing. Two real render paths —
/// a moved mutable tag and an adoption whose content differs — are made to fail
/// their stderr write, and each leaves the authority byte-identical.
#[test]
fn an_unwritable_stderr_commits_no_replacement_and_no_adoption() {
    // A replacement: the tag moves A -> B and the render cannot be written.
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "render", &a);
    let tag = format!("{}/images:render", server.host);
    assert!(h.refresh_as_ambient(&tag).status.success());
    let pins = fs::read(h.pins()).unwrap();
    let b = h.image(&ArchiveSpec {
        marker: "render-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "render", &b);
    assert_ne!(child_a, child_b);

    let out = with_unwritable_stderr(&h, &["image", "refresh", "--image", &tag]);
    assert_eq!(out.status.code(), Some(1), "the render failure is fatal");
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        pins,
        "no replacement was committed"
    );
    assert_eq!(
        h.pin_in(&h.project, &tag),
        Some((digest_of(&child_a), 1)),
        "the old approval is intact at its old revision"
    );

    // An adoption: the host record names different content, and its render
    // cannot be written either.
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_d = server.image("images", "render-adopt", &a);
    assert!(!h.launch_on_recommendation(&child_d).status.success());
    let b = h.image(&ArchiveSpec {
        marker: "render-adopt-b".into(),
        ..Default::default()
    });
    let child_h = server.image("images", "render-adopt", &b);
    let tag = format!("{}/images:render-adopt", server.host);
    assert!(set_default(&h, &tag).status.success());
    let pins = fs::read(h.pins()).unwrap();

    let out = with_unwritable_stderr(&h, &["image", "refresh"]);
    assert_eq!(out.status.code(), Some(1), "the render failure is fatal");
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        pins,
        "no adoption was committed"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child_d,
        "the project default is untouched"
    );
    assert!(
        h.pin_in(&h.project, &child_h).is_none(),
        "no approval was recorded for the host reference"
    );
}

/// R9: a journal 0.7.39–0.7.46 left is still authoritative. An unwritable
/// directory makes the next write demand recovery, observation keeps returning
/// the journal's `previous` bytes, and the write recovers once it can.
#[test]
fn failed_default_restore_requires_recovery_without_losing_old_approval() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "restore", &a);
    let tag = format!("{}/images:restore", server.host);
    // An approval to keep across the recovery.
    assert!(h.refresh_as_ambient(&tag).status.success());
    let default = h.home.join(".config/agent-vm/default-image.json");
    let old_default = format!("{{ \"image\": \"{child_a}\", \"version\": 1 }}\n");
    fs::write(&default, &old_default).unwrap();
    // Seed the interrupted state: the journal names the old bytes, the host
    // record already holds the proposed ones.
    let proposed = format!(
        "{{ \"image\": \"{}@sha256:{}\", \"version\": 1 }}\n",
        server.host,
        "b".repeat(64)
    );
    let mut store = read_json(&h.pins());
    store["pending_default"] = serde_json::json!({
        "previous": old_default,
        "proposed": proposed,
    });
    fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
    fs::write(&default, &proposed).unwrap();
    // A real 0.7.39–0.7.46 store always has this lock; without it the next
    // transaction would fail while creating it, not in the recovery itself.
    fs::write(config_dir(&h).join("default-image.lock"), b"").unwrap();
    let seeded = fs::read(h.pins()).unwrap();

    // Observation honors the journal and never repairs it.
    let mut cmd = h.command();
    cmd.args(["image", "show"]);
    let show = bounded(cmd);
    assert!(show.status.success(), "{}", stderr(&show));
    assert!(stdout_of(&show).contains(&child_a), "{}", stdout_of(&show));
    let mut cmd = h.command();
    cmd.arg("doctor");
    let doctor = bounded(cmd);
    assert!(doctor.status.success(), "{}", stderr(&doctor));
    assert!(
        stdout_of(&doctor).contains("default: retained default ["),
        "the journal's previous bytes stay authoritative: {}",
        stdout_of(&doctor)
    );
    assert_eq!(fs::read(h.pins()).unwrap(), seeded);

    // An unwritable directory makes the next write demand recovery. Root
    // bypasses directory EACCES, so on root this row stops after the
    // observation assertions above; the deterministic failed-restore adapter
    // case is `image_pin::store`'s `journal_real_write_failures...` test.
    let directory = h.pins().parent().unwrap().to_owned();
    let permissions = fs::metadata(&directory).unwrap().permissions();
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("root: observation and recovery rows only, not a genuine EACCES restore failure");
        assert!(h.refresh_as_ambient(&child_a).status.success());
        assert!(read_json(&h.pins())["pending_default"].is_null());
        assert_eq!(fs::read(&default).unwrap(), old_default.as_bytes());
        return;
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    let mut cmd = h.command();
    cmd.args(["image", "refresh", "--image", &child_a]);
    let out = bounded(cmd);
    fs::set_permissions(&directory, permissions).unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    // S4 reports per-operation failures as rows, so the reason is on stdout.
    assert!(
        stdout_of(&out).contains("requires recovery"),
        "{}",
        stdout_of(&out)
    );
    let pending = fs::read(h.pins()).unwrap();
    assert!(!read_json(&h.pins())["pending_default"].is_null());
    let mut cmd = h.command();
    cmd.args(["image", "show"]);
    let out = bounded(cmd);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout_of(&out).contains(&child_a));
    assert_eq!(fs::read(h.pins()).unwrap(), pending);

    // Writable again: the next write recovers the journal and keeps the pin.
    assert!(h.refresh_as_ambient(&child_a).status.success());
    assert!(read_json(&h.pins())["pending_default"].is_null());
    assert_eq!(fs::read(&default).unwrap(), old_default.as_bytes());
    let start = server.count();
    assert_eq!(sdk_image(&h.launch(&tag)), child_a);
    assert_eq!(server.count(), start);
}

#[test]
fn native_index_ignores_attestation_platformless_and_foreign_entries() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "host", &a);
    let mut index: serde_json::Value = serde_json::from_slice(&a.index).unwrap();
    let host = index["manifests"][0].clone();
    let mut attestation = host.clone();
    attestation["mediaType"] = "application/vnd.oci.attestation.manifest.v1+json".into();
    attestation["digest"] = format!("sha256:{}", "a".repeat(64)).into();
    let mut platformless = host.clone();
    platformless.as_object_mut().unwrap().remove("platform");
    platformless["digest"] = format!("sha256:{}", "b".repeat(64)).into();
    let mut foreign = host.clone();
    foreign["platform"]["architecture"] = if image_archive::host_arch() == "arm64" {
        "amd64"
    } else {
        "arm64"
    }
    .into();
    foreign["digest"] = format!("sha256:{}", "c".repeat(64)).into();
    index["manifests"] = serde_json::json!([attestation, platformless, foreign, host]);
    server.index("images", "filtered", serde_json::to_vec(&index).unwrap());
    let source = format!("{}/images:filtered", server.host);
    assert!(h.refresh_as_ambient(&source).status.success());
    assert_eq!(h.pinned_digest(), a.written.manifest_digest);
    assert_eq!(sdk_image(&h.launch(&source)), child);
    let old = fs::read(h.pins()).unwrap();
    index["manifests"][2]["digest"] = format!("sha256:{}", "d".repeat(64)).into();
    server.index("images", "filtered", serde_json::to_vec(&index).unwrap());
    let out = h.refresh_as_ambient(&source);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("Approve"));
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        old,
        "unrelated architecture movement is not approval movement"
    );
    for (_, path) in server.requests() {
        for skipped in ['a', 'b', 'c', 'd'] {
            assert_ne!(
                path,
                format!(
                    "/v2/images/manifests/sha256:{}",
                    skipped.to_string().repeat(64)
                )
            );
        }
    }
}

#[test]
fn unapproved_legacy_index_requires_its_immutable_source_proof() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "legacy-child", &a);
    let source = server.index("images", "legacy-index", a.index.clone());
    assert!(h.refresh_as_ambient(&source).status.success());
    // Simulate a pre-approval cache, not an approval minted from disk strings.
    // Removing authority is a deliberate reset inside this test-owned HOME.
    fs::remove_file(h.pins()).unwrap();
    fs::remove_file(h.pins().with_extension("lock")).unwrap();
    fs::remove_dir_all(h.cache().join("agent-vm-content-metadata")).unwrap();
    let route = format!(
        "/v2/images/manifests/{}",
        source.rsplit_once('@').unwrap().1
    );
    server.remove(&route);
    let start = server.count();
    let creates = create_invocations(&h);
    let out = h.launch(&source);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(!h.pins().exists());
    assert_eq!(create_invocations(&h), creates);
    assert_eq!(
        &server.requests()[start..],
        &[
            ("GET".to_owned(), "/v2/".to_owned()),
            ("GET".to_owned(), route)
        ]
    );
    server.index("images", "legacy-index", a.index.clone());
    assert_eq!(sdk_image(&h.launch(&source)), child);
    assert_eq!(h.pinned_digest(), a.written.manifest_digest);
    let old = fs::read(h.pins()).unwrap();
    let start = server.count();
    assert_eq!(sdk_image(&h.launch(&source)), child);
    assert_eq!(server.count(), start);
    assert_eq!(fs::read(h.pins()).unwrap(), old);
}

// --------------------------------------------------------- retained fallback

/// A fallback the store leaves alone keeps its exact bytes: `set-default` rewrites
/// it only when the logical selection actually moves.
fn retained_default(h: &Harness) -> Option<Vec<u8>> {
    fs::read(h.home.join(".config/agent-vm/default-image.json")).ok()
}

/// The set-default notice states the host choice, then what the invoking project
/// does about it, and only the host record can move (R5, B10).
#[test]
fn set_default_reports_the_host_choice_and_this_project() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "select", &a);
    let tag = format!("{}/images:select", server.host);
    let default = h.home.join(".config/agent-vm/default-image.json");

    let first = set_default(&h, &tag);
    assert!(first.status.success(), "{}", stderr(&first));
    let text = stderr(&first);
    assert!(
        text.contains("selected for projects that have none yet"),
        "{text}"
    );
    assert!(
        text.contains("This project has no default boot image yet"),
        "{text}"
    );
    assert!(
        !text.contains("already selected"),
        "the host record moved: {text}"
    );
    let retained = fs::read(&default).unwrap();
    assert_eq!(
        read_json(&default),
        serde_json::json!({"version": 1, "image": child})
    );
    assert!(
        !h.pins().exists(),
        "set-default writes no approval in any project"
    );

    // Repeating the same command moves nothing and says so.
    let again = set_default(&h, &tag);
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(
        stderr(&again).contains("already selected for projects that have none yet"),
        "{}",
        stderr(&again)
    );
    assert_eq!(fs::read(&default).unwrap(), retained);

    // A record someone moved aside is replaced with the validated child again.
    let other = serde_json::json!({
        "version": 1,
        "image": format!("{}/images@sha256:{}", server.host, "b".repeat(64))
    });
    fs::write(&default, serde_json::to_vec(&other).unwrap()).unwrap();
    let replaced = set_default(&h, &tag);
    assert!(replaced.status.success(), "{}", stderr(&replaced));
    assert!(!stderr(&replaced).contains("already selected"));
    assert!(stderr(&replaced).contains("selected for projects that have none yet"));
    assert_eq!(fs::read(&default).unwrap(), retained);
    assert!(!h.pins().exists());
}

/// R5: "already uses it" compares the content this project boots, not the
/// repository that serves it. The same manifest published under another
/// repository is the same content, so the notice does not ask the user to adopt
/// what they already run.
#[test]
fn set_default_reports_an_identical_child_served_elsewhere_as_already_used() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "mirror", &a);
    let mirrored = server.image("mirror", "mirror", &a);
    assert_eq!(
        digest_of(&child),
        digest_of(&mirrored),
        "the fixture serves one manifest under two repositories"
    );
    // The project establishes at the mirrored repository's reference.
    assert!(!h.launch_on_recommendation(&mirrored).status.success());
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], mirrored);

    let out = set_default(&h, &child);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("This project already uses it."),
        "the same booted child in another repository is already used: {}",
        stderr(&out)
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        mirrored,
        "the project keeps its own reference"
    );
}

/// R3/R4: a recommendation launch establishes the project default and seeds the
/// host record, without rewriting the approval it already had.
#[test]
fn a_recommendation_launch_establishes_the_project_and_seeds_the_host() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "adopt", &a);
    // The same key is pinned by an explicit operation, which never establishes.
    assert!(h.refresh_as_ambient(&child).status.success());
    assert_eq!(retained_default(&h), None);
    let pins = read_json(&h.pins());
    let project = project_id(&h.project);

    let requests = server.count();
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child)
        .args(["shell", "--", "true"]);
    let cold = bounded(command);
    assert!(!cold.status.success(), "the fake runtime cannot boot");
    assert!(
        stderr(&cold).contains("<redacted"),
        "the default tier's label never names its reference: {}",
        stderr(&cold)
    );
    assert_eq!(
        server.count(),
        requests,
        "an approved digest is consumed offline"
    );
    assert_eq!(
        read_json(&h.home.join(".config/agent-vm/default-image.json")),
        serde_json::json!({"version": 1, "image": child}),
        "the recommendation initializes the host starting choice"
    );
    let store = read_json(&h.pins());
    // The approval's content and token are unchanged; the Boot claim this
    // preparation records legitimately adds roles/scope/sequence (ADR-0068).
    let approval_content =
        |store: &serde_json::Value| -> Vec<(serde_json::Value, serde_json::Value)> {
            store["pins"]
                .as_array()
                .expect("pins")
                .iter()
                .map(|pin| (pin["manifest_digest"].clone(), pin["revision"].clone()))
                .collect()
        };
    assert_eq!(
        approval_content(&store),
        approval_content(&pins),
        "the approval content and token are unchanged"
    );
    assert_eq!(
        store["pins"][0]["roles"],
        serde_json::json!("boot"),
        "the default-tier preparation claims Boot"
    );
    assert_eq!(
        store["defaults"],
        serde_json::json!([{"project": project, "image": child}]),
        "the project default is the selected reference"
    );
    assert!(store["pending_default"].is_null());

    // Write-once: a warm relaunch of the same default changes neither record.
    // The host record has its own writer, so checking only the pin store would
    // not cover it.
    let retained_bytes = retained_default(&h).unwrap();
    let before = fs::read(h.pins()).unwrap();
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child)
        .args(["shell", "--", "true"]);
    let warm = bounded(command);
    assert!(!warm.status.success());
    assert_eq!(
        retained_default(&h).unwrap(),
        retained_bytes,
        "the host record is write-once across a warm relaunch"
    );
    assert_eq!(fs::read(h.pins()).unwrap(), before);
}

/// An interrupted writer is observed, never recovered, by an established warm
/// default launch: nothing it may write is missing, so it takes no lock. A
/// missing gate socket would fail any transaction stage.
#[test]
fn an_established_warm_launch_takes_no_lock_and_leaves_the_journal() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "warm-default", &a);
    assert!(h.refresh_as_ambient(&child).status.success());
    // A first real preparation records Boot for that key and resolves the
    // scope; only then is the following default-tier launch a complete no-op
    // that needs no exclusive lock. Merely adding `roles` by hand would be an
    // invalid store (a holder without a resolved scope).
    assert!(!h.launch(&child).status.success());
    let project = project_id(&h.project);
    let default = h.home.join(".config/agent-vm/default-image.json");
    let retained = serde_json::json!({"version": 1, "image": child}).to_string();
    fs::write(&default, &retained).unwrap();
    let mut record = read_json(&h.pins());
    record["pending_default"] = serde_json::json!({
        "previous": retained,
        "proposed": serde_json::json!({"version": 1, "image": format!(
            "{}/images@sha256:{}", server.host, "b".repeat(64)
        )}).to_string()
    });
    record["defaults"] = serde_json::json!([{"project": project, "image": child}]);
    fs::write(h.pins(), serde_json::to_vec(&record).unwrap()).unwrap();
    let pending = fs::read(h.pins()).unwrap();
    for gate_enabled in [true, false] {
        let mut command = h.command();
        if gate_enabled {
            command.env("AGENT_VM_TEST_PIN_GATE", h.root.path().join("absent.sock"));
        }
        command.args(["shell", "--", "true"]);
        let out = bounded(command);
        assert!(!out.status.success(), "the fake runtime cannot boot");
        assert!(stderr(&out).contains("<redacted"), "{}", stderr(&out));
        assert!(
            stderr(&out).contains("[debug] sandbox config JSON:"),
            "preparation reached SDK create without emitting a pin stage: {}",
            stderr(&out)
        );
        assert_eq!(fs::read(h.pins()).unwrap(), pending, "no recovery ran");
        assert_eq!(fs::read_to_string(&default).unwrap(), retained);
    }
}

/// An *unestablished* warm default launch does reach the transaction: with the
/// absent gate socket it fails at the pin lock, and without the gate it recovers
/// the S1 journal and establishes the project.
#[test]
fn an_unestablished_warm_launch_recovers_the_journal_and_establishes() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "warm-new", &a);
    assert!(h.refresh_as_ambient(&child).status.success());
    let project = project_id(&h.project);
    let default = h.home.join(".config/agent-vm/default-image.json");
    let retained = serde_json::json!({"version": 1, "image": child}).to_string();
    fs::write(&default, &retained).unwrap();
    let mut record = read_json(&h.pins());
    record["pending_default"] = serde_json::json!({
        "previous": retained,
        "proposed": serde_json::json!({"version": 1, "image": format!(
            "{}/images@sha256:{}", server.host, "b".repeat(64)
        )}).to_string()
    });
    fs::write(h.pins(), serde_json::to_vec(&record).unwrap()).unwrap();

    // Gated at an absent socket: the transaction fails before it writes.
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_PIN_GATE", h.root.path().join("absent.sock"))
        .args(["shell", "--", "true"]);
    let seeded = fs::read(h.pins()).unwrap();
    let out = bounded(command);
    assert!(!out.status.success());
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        seeded,
        "the transaction stopped before it wrote anything"
    );

    // Without the gate the journal is recovered and the project established.
    // The launch must select through the default tier, so no `--image` is given:
    // the host record now holds the approved child.
    let mut command = h.command();
    command.args(["shell", "--", "true"]);
    let out = bounded(command);
    assert!(!out.status.success(), "the fake runtime cannot boot");
    let store = read_json(&h.pins());
    assert!(
        store["pending_default"].is_null(),
        "the journal is recovered"
    );
    assert_eq!(
        store["defaults"],
        serde_json::json!([{"project": project, "image": child}])
    );
    assert_eq!(fs::read_to_string(&default).unwrap(), retained);
}

/// A second state root is a second cache: these rows need two real processes
/// whose only shared state is the host approval store.
fn state_root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("avpin-")
        .tempdir_in("/tmp")
        .unwrap()
}

/// `image set-default` never reads stdin and approves nothing: on a terminal and
/// on a pipe holding `y`, it exits 0 and writes only the host record (R5).
#[test]
fn set_default_never_reads_stdin_and_approves_nothing() {
    // A real terminal, with no answer typed: the command exits by itself.
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    server.image("images", "sd", &a);
    let tag = format!("{}/images:sd", server.host);
    let mut command = h.command();
    command.args(["image", "set-default", "--image", &tag]);
    let mut terminal =
        Pty::spawn(&mut command, b"Default boot image selected").expect("open a pseudo-terminal");
    let (status, out) = terminal
        .drive(&Action::Write(b""), Duration::from_secs(60))
        .expect("wait for the command to exit");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(status.success(), "{text}");
    assert_no_question(&text);
    assert!(
        !h.pins().exists(),
        "set-default approves nothing, so it creates no pin store"
    );
    let first = read_json(&h.home.join(".config/agent-vm/default-image.json"));

    // A pipe holding an answer: nothing reads it.
    let b = h.image(&ArchiveSpec {
        marker: "sd-b-pipe".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "sd", &b);
    let mut command = h.command();
    command.args(["image", "set-default", "--image", &tag]);
    let (out, unread) = with_unread_stdin(command, b"y\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(unread, b"y\n", "stdin must be left unread");
    assert!(!h.pins().exists());
    let second = read_json(&h.home.join(".config/agent-vm/default-image.json"));
    assert_ne!(first, second);
    assert_eq!(second, serde_json::json!({"version": 1, "image": child_b}));
    assert_eq!(
        h.pin_for(&tag),
        None,
        "no approval exists for the typed tag"
    );
}

fn with_unread_stdin(mut command: Command, input: &'static [u8]) -> (Output, Vec<u8>) {
    use std::io::{Read as _, Write as _};
    use std::os::fd::FromRawFd as _;
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is an owned, uninitialized pair that `pipe` fills on success.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "create a pipe");
    // SAFETY: `pipe` just handed us these two descriptors.
    let mut read_end = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let mut write_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    let child_read = read_end.try_clone().expect("dup the read end");
    write_end.write_all(input).expect("fill the stdin pipe");
    command.stdin(std::process::Stdio::from(child_read));
    let out = bounded(command);
    // The child has exited, so with our write end closed this is the remainder.
    drop(write_end);
    let mut unread = Vec::new();
    read_end.read_to_end(&mut unread).expect("read the pipe");
    (out, unread)
}

// --------------------------------------------------------- concurrent peers

/// Two real processes race for the *first* pin of one source against different
/// caches. Exactly one approval is committed, and the loser — which had already
/// acquired the moved tag — consumes the winner's frozen digest instead of
/// overwriting it.
#[test]
fn two_processes_racing_the_first_pin_commit_one_approval() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "race", &a);
    let tag = format!("{}/images:race", server.host);
    let b = h.image(&ArchiveSpec {
        marker: "race-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "race", &b);
    assert_ne!(child_a, child_b);

    let winner_state = state_root();
    let loser_state = state_root();
    let mut winner_gate = PinGate::new(h.root.path());
    let mut loser_gate = PinGate::new(h.root.path());
    let peer = |gate: &PinGate, state: &Path| {
        let mut command = h.command();
        command
            .env("AGENT_VM_STATE_DIR", state)
            .args(["--image", &tag, "shell", "--", "true"]);
        pin_gate::PinPeer::spawn(command, gate, &[])
    };

    // The loser freezes B first: its absent-approval read happens before any
    // lock is taken, so the two processes resolve different candidates for one
    // source key.
    let loser = peer(&loser_gate, loser_state.path());
    let loser_ready = loser_gate.expect(PinStage::CandidateReady);
    // The tag moves back to A, which the winner acquires while holding the
    // exclusive pin lock.
    server.image("images", "race", &a);
    let winner = peer(&winner_gate, winner_state.path());
    winner_gate
        .expect(PinStage::CandidateReady)
        .reply(Reply::Continue);
    winner_gate
        .expect(PinStage::BeforePinLock)
        .reply(Reply::Continue);
    let locked = winner_gate.expect(PinStage::PinLocked);

    // Both are past their own reads, so the loser competes for the same lock.
    loser_ready.reply(Reply::Continue);
    loser_gate
        .expect(PinStage::BeforePinLock)
        .reply(Reply::Continue);

    locked.reply(Reply::Continue);
    winner_gate
        .expect(PinStage::BeforePinSave)
        .reply(Reply::Continue);
    winner_gate
        .expect(PinStage::PinCommitted)
        .reply(Reply::Continue);

    // A conflict now sends the loser to the winner's frozen digest.
    loser_gate
        .expect(PinStage::PinLocked)
        .reply(Reply::Continue);

    let winner_out = winner.wait();
    let loser_out = loser.wait();
    assert!(
        !winner_out.status.success(),
        "the create fails deliberately"
    );
    assert!(!loser_out.status.success(), "the create fails deliberately");
    assert_eq!(sdk_image(&winner_out), child_a);
    assert_eq!(
        sdk_image(&loser_out),
        child_a,
        "the loser consumes the winner's frozen digest, not its own candidate"
    );
    let store: serde_json::Value = serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    assert_eq!(
        store["pins"].as_array().unwrap().len(),
        1,
        "exactly one approval exists: {store}"
    );
    assert_eq!(
        store["pins"][0]["manifest_digest"],
        child_a.rsplit_once('@').unwrap().1
    );
    assert_eq!(store["pins"][0]["revision"], 1);
}

/// Two peers set the same host child: the winner writes the record, the loser
/// reports "already selected". Neither writes an approval (R5, D2).
#[test]
fn a_peer_committing_the_same_candidate_is_reported_as_unchanged() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "same", &a);
    let tag = format!("{}/images:same", server.host);

    let winner_state = state_root();
    let loser_state = state_root();
    let mut winner_gate = PinGate::new(h.root.path());
    let mut loser_gate = PinGate::new(h.root.path());
    let peer = |gate: &PinGate, state: &Path| {
        let mut command = h.command();
        command
            .env("AGENT_VM_STATE_DIR", state)
            .args(["image", "set-default", "--image", &tag]);
        pin_gate::PinPeer::spawn(command, gate, &[])
    };

    // The loser resolves first; the winner takes the lock before it does.
    let loser = peer(&loser_gate, loser_state.path());
    let loser_ready = loser_gate.expect(PinStage::CandidateReady);
    let winner = peer(&winner_gate, winner_state.path());
    winner_gate
        .expect(PinStage::CandidateReady)
        .reply(Reply::Continue);
    winner_gate
        .expect(PinStage::BeforePinLock)
        .reply(Reply::Continue);
    let locked = winner_gate.expect(PinStage::PinLocked);

    loser_ready.reply(Reply::Continue);
    loser_gate
        .expect(PinStage::BeforePinLock)
        .reply(Reply::Continue);

    locked.reply(Reply::Continue);
    for stage in [PinStage::BeforeDefaultSave, PinStage::DefaultSaved] {
        winner_gate.expect(stage).reply(Reply::Continue);
    }
    let winner_out = winner.wait();
    assert!(winner_out.status.success(), "{}", stderr(&winner_out));
    assert!(
        stderr(&winner_out).contains("selected for projects that have none yet"),
        "{}",
        stderr(&winner_out)
    );

    // The peer finds the same child already selected and writes nothing.
    let retained = retained_default(&h).expect("the winner retained its child");
    assert_eq!(
        read_json(&h.home.join(".config/agent-vm/default-image.json"))["image"],
        child
    );
    loser_gate
        .expect(PinStage::PinLocked)
        .reply(Reply::Continue);
    let loser_out = loser.wait();
    assert!(loser_out.status.success(), "{}", stderr(&loser_out));
    assert!(
        stderr(&loser_out).contains("already selected"),
        "a peer's identical candidate is not a false change: {}",
        stderr(&loser_out)
    );
    assert_eq!(retained_default(&h).unwrap(), retained);
    assert!(
        !h.pins().exists(),
        "set-default writes no approval in any project"
    );
}

// ------------------------------------------------ project defaults (#541, S2)

/// AC1/AC2: `set-default` in an established project changes only the host's
/// starting choice; that project keeps its own default, and a fresh project
/// starts from the new one.
#[test]
fn set_default_never_changes_an_established_project() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "est", &a);
    let b = h.image(&ArchiveSpec {
        marker: "est-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "est", &b);
    let tag_b = format!("{}/images:est", server.host);

    // P establishes its own default from the initial recommendation.
    let first = h.launch_on_recommendation(&child_a);
    assert!(!first.status.success(), "the fake runtime cannot boot");
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child_a,
        "the first default-tier use establishes P's default"
    );

    let pins = fs::read(h.pins()).unwrap();
    let out = set_default(&h, &tag_b);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(
        text.contains("This project keeps its own default boot image"),
        "{text}"
    );
    assert!(text.contains("agent-vm image refresh"), "{text}");
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        pins,
        "set-default writes no approval and no project default"
    );
    assert_eq!(
        h.host_record().unwrap()["image"],
        child_b,
        "the host record names the new starting choice"
    );

    // P's next launch boots A, and its selection re-acquires A's approved
    // digest and nothing else.
    assert_eq!(
        h.reacquired_digest(&server),
        digest_of(&child_a),
        "P keeps its own default"
    );

    // A fresh project Q starts from the new host choice and establishes it.
    let q = h.project_at("fresh-q");
    let mut command = h.command_in(&q, &h.state);
    command.args(["shell", "--", "true"]);
    let q_out = bounded(command);
    assert!(!q_out.status.success());
    assert_eq!(
        h.default_record_in(&q).unwrap()["image"],
        child_b,
        "Q starts from the host choice"
    );
    assert_eq!(
        h.reacquired_digest_in(&q, &h.state, &server),
        digest_of(&child_b),
        "Q boots the content the host choice names"
    );
}

/// AC3: an unestablished project takes the host choice as its starting point.
#[test]
fn set_default_is_the_starting_choice_of_an_unestablished_project() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "start", &a);
    let tag = format!("{}/images:start", server.host);

    let out = set_default(&h, &tag);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("This project has no default boot image yet"),
        "{}",
        stderr(&out)
    );
    assert!(
        !h.pins().exists(),
        "set-default writes no approval in this project either"
    );
    assert_eq!(
        h.reacquired_digest(&server),
        digest_of(&child_a),
        "the project starts from it"
    );
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_a);
}

/// AC4: a bare refresh in an established project adopts the host's existing
/// default, renders the change, asks nothing, and reads no stdin.
#[test]
fn refresh_adopts_the_host_default_without_asking_or_reading_stdin() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "adopt", &a);
    let b = h.image(&ArchiveSpec {
        marker: "adopt-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "adopt", &b);
    let tag = format!("{}/images:adopt", server.host);

    assert!(!h.launch_on_recommendation(&child_a).status.success());
    assert!(set_default(&h, &tag).status.success());

    let mut command = h.command();
    command.arg("image").arg("refresh");
    let (out, unread) = with_unread_stdin(command, b"n\n");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(unread, b"n\n", "stdin must be left unread");
    let text = stderr(&out);
    assert!(
        text.contains("Adopting the host's default boot image"),
        "{text}"
    );
    assert!(
        text.contains(&format!("old: {}", digest_of(&child_a))),
        "{text}"
    );
    assert!(
        text.contains(&format!("new: {}", digest_of(&child_b))),
        "{text}"
    );
    assert_no_question(&text);
    assert!(
        stdout_of(&out).contains("==> this project now uses the host's default boot image"),
        "{}",
        stdout_of(&out)
    );
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_b);
    assert_eq!(
        h.pin_in(&h.project, &child_b).map(|(digest, _)| digest),
        Some(digest_of(&child_b)),
        "the host reference's approval is inserted"
    );

    // The next launch boots B, and adoption left it approved and cached.
    let before = server.count();
    let launch = h.launch_default();
    assert!(!launch.status.success(), "the fake runtime cannot boot");
    assert_eq!(
        server.count(),
        before,
        "adoption left B approved and cached"
    );
    assert_eq!(h.reacquired_digest(&server), digest_of(&child_b));
}

/// AC5: adoption in P never touches another established project.
#[test]
fn refresh_adoption_changes_only_this_project() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "scope", &a);
    let b = h.image(&ArchiveSpec {
        marker: "scope-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "scope", &b);
    let tag = format!("{}/images:scope", server.host);
    let q = h.project_at("scope-q");

    assert!(!h.launch_on_recommendation(&child_a).status.success());
    let mut command = h.command_in(&q, &h.state);
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child_a)
        .args(["shell", "--", "true"]);
    let q_first = bounded(command);
    assert!(!q_first.status.success(), "the fake runtime cannot boot");
    assert_eq!(h.default_record_in(&q).unwrap()["image"], child_a);
    let q_record = h.record_in(&q, &child_a).unwrap();
    assert!(set_default(&h, &tag).status.success());

    assert!(h.refresh_default().status.success());
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_b);
    assert_eq!(
        h.default_record_in(&q).unwrap()["image"],
        child_a,
        "Q's default is untouched"
    );
    assert_eq!(
        h.record_in(&q, &child_a).unwrap(),
        q_record,
        "Q's approval record is byte-identical"
    );
    // Q's selection still names A's approved digest.
    fs::remove_dir_all(h.cache()).unwrap();
    let before = server.requests().len();
    let mut command = h.command_in(&q, &h.state);
    command.args(["shell", "--", "true"]);
    let q_out = bounded(command);
    assert!(!q_out.status.success());
    let digests: Vec<String> = server.requests()[before..]
        .iter()
        .filter_map(|(_, path)| path.rsplit_once("/manifests/"))
        .map(|(_, digest)| digest.to_owned())
        .filter(|digest| digest.starts_with("sha"))
        .collect();
    assert_eq!(digests, vec![digest_of(&child_a)], "Q still boots A");
}

/// AC6: a host record equal to the project's default is re-verified, renders
/// nothing, and changes no bytes.
#[test]
fn refresh_with_an_unchanged_host_default_changes_nothing() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "same", &a);
    assert!(!h.launch_on_recommendation(&child_a).status.success());
    // The host record now names the project's own default.
    assert_eq!(h.host_record().unwrap()["image"], child_a);
    let pins = fs::read(h.pins()).unwrap();

    // AC6's other half: the refresh re-verifies the project's own default. Byte
    // preservation alone would also pass for a refresh that never asked anyone.
    let before = server.count();
    let out = h.refresh_default();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("Adopting"),
        "nothing changed, so nothing is adopted: {}",
        stderr(&out)
    );
    assert_eq!(
        manifests_requested_since(&server, before),
        vec![digest_of(&child_a)],
        "the project's own default is re-verified exactly once"
    );
    assert_eq!(fs::read(h.pins()).unwrap(), pins);
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_a);
}

/// AC7: an index default whose approved child already is the host record's
/// digest adopts without a digest render.
#[test]
fn refresh_adopts_an_equal_digest_host_default_without_a_render() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "index", &a);
    let index = server.index("images", "index", a.index.clone());
    let launch = h.launch_on_recommendation(&index);
    assert!(!launch.status.success(), "{}", stderr(&launch));
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        index,
        "the index reference is the project default: {}",
        stderr(&launch)
    );
    assert_eq!(h.pin_in(&h.project, &index).unwrap().0, digest_of(&child));

    let out = set_default(&h, &child);
    assert!(out.status.success(), "{}", stderr(&out));
    let refresh = h.refresh_default();
    assert!(refresh.status.success(), "{}", stderr(&refresh));
    assert!(
        !stderr(&refresh).contains("old:"),
        "equal digests render nothing: {}",
        stderr(&refresh)
    );
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child);
    assert_eq!(
        h.pin_in(&h.project, &child).map(|(digest, _)| digest),
        Some(digest_of(&child)),
        "the host reference's approval is inserted at the same child"
    );
}

/// R7: a hand-edited store can hold a project default with no approval for it.
/// The adoption render then shows the digest the record states — without
/// re-resolving the old default — and inserts the host reference's approval.
#[test]
fn an_adoption_of_a_hand_edited_default_renders_its_stated_digest() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_i = server.image("images", "hand-edited", &a);
    assert!(!h.launch_on_recommendation(&child_i).status.success());
    // Hand edit: the default record stays, its approval does not.
    let mut store = read_json(&h.pins());
    store["pins"] = serde_json::json!([]);
    // A hand edit must also drop the scope knowledge that went with the pin: a
    // resolved slot with no holder is damage, not "no approvals".
    store["scopes"] = serde_json::json!([]);
    fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
    // A host record naming different content.
    let b = h.image(&ArchiveSpec {
        marker: "hand-edited-b".into(),
        ..Default::default()
    });
    let child_h = server.image("images", "hand-edited", &b);
    let tag = format!("{}/images:hand-edited", server.host);
    let set = set_default(&h, &tag);
    assert!(set.status.success(), "{}", stderr(&set));
    assert_ne!(child_i, child_h);
    let before = server.count();

    let out = h.refresh_default();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(
        text.contains("Adopting the host's default boot image"),
        "{text}"
    );
    assert!(
        text.contains(&format!("old: {}", digest_of(&child_i))),
        "the record's stated digest is the old content: {text}"
    );
    assert!(
        text.contains(&format!("new: {}", digest_of(&child_h))),
        "{text}"
    );
    assert!(
        !server.requests()[before..]
            .iter()
            .any(|(_, path)| path.contains(&digest_of(&child_i))),
        "the old default is not re-resolved to render its own digest"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child_h,
        "the project adopts the host's default"
    );
    assert_eq!(
        h.pin_in(&h.project, &child_h),
        Some((digest_of(&child_h), 2)),
        "the host reference's approval is inserted at the next allocation"
    );
}

/// AC8: an S1 store upgrades without a reset. The first default-tier use
/// establishes the project from the host record it already followed.
#[test]
fn an_s1_store_upgrades_without_a_reset() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "upgrade", &a);
    // Warm the cache and learn the pin record's exact shape.
    assert!(h.refresh_as_ambient(&child).status.success());
    // Rewrite the store exactly as 0.7.39–0.7.46 writes it: no `defaults`.
    let mut store = read_json(&h.pins());
    store.as_object_mut().unwrap().remove("defaults");
    fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
    fs::write(
        h.home.join(".config/agent-vm/default-image.json"),
        serde_json::to_vec(&serde_json::json!({"version":1,"image":child})).unwrap(),
    )
    .unwrap();
    let before = server.count();

    let launch = h.launch_default();
    assert!(!launch.status.success(), "the fake runtime cannot boot");
    assert!(
        stderr(&launch).contains("<redacted"),
        "the default tier stays redacted: {}",
        stderr(&launch)
    );
    assert_eq!(
        server.count(),
        before,
        "it boots the content it booted, offline"
    );
    let store = read_json(&h.pins());
    assert_eq!(
        store["defaults"],
        serde_json::json!([{"project": project_id(&h.project), "image": child}]),
        "the store gains the project's default"
    );
    assert_eq!(store["pins"].as_array().unwrap().len(), 1, "no reset");
}

/// AC11: a damaged host record does not break an established project. Launch,
/// setup and `image show` succeed; `doctor` reports it and exits nonzero;
/// refresh fails before any registry request and writes nothing.
#[test]
fn a_damaged_host_record_fails_only_doctor_and_refresh_in_an_established_project() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "damaged", &a);
    assert!(!h.launch_on_recommendation(&child).status.success());
    fs::write(
        h.home.join(".config/agent-vm/default-image.json"),
        b"not a record",
    )
    .unwrap();
    let pins = fs::read(h.pins()).unwrap();

    let before = server.count();
    let launch = h.launch_default();
    assert!(
        !stderr(&launch).contains("boot-image selection"),
        "the project default is enough: {}",
        stderr(&launch)
    );
    assert_eq!(server.count(), before, "and needs no registry request");

    // A default-tier setup: the project's own default is enough, so the damaged
    // host record is never read.
    let mut command = h.command();
    command.args(["setup", "--no-verify"]);
    let setup = bounded(command);
    assert!(setup.status.success(), "{}", stderr(&setup));
    assert!(
        !stderr(&setup).contains("boot-image selection"),
        "{}",
        stderr(&setup)
    );

    let mut command = h.command();
    command.args(["image", "show"]);
    let show = bounded(command);
    assert!(show.status.success(), "{}", stderr(&show));
    assert!(
        stdout_of(&show).contains("Source: project default"),
        "{}",
        stdout_of(&show)
    );

    // The two read-only surfaces do not read the host record at all: the listing
    // is the pin file's records, and the active row counts them.
    let mut command = h.command();
    command.args(["image", "pins"]);
    let listing = bounded(command);
    assert!(
        listing.status.success(),
        "a damaged host record cannot fail the listing: {}",
        stderr(&listing)
    );
    assert_eq!(stderr(&listing), "");
    let (digest, revision) = h.pin_for(&child).expect("the launch recorded the child");
    assert_eq!(digest, digest_of(&child));
    // Built from the fixture's own inputs, independently of the renderer.
    assert_eq!(
        stdout_of(&listing),
        format!(
            "REFERENCE\tPLATFORM\tDIGEST\tREVISION\tROLES\tUNRESOLVED\n\
             {child}\tlinux/{}\t{digest}\t{revision}\tboot\toutput\n",
            image_archive::host_arch(),
        )
    );

    let mut command = h.command();
    command.arg("doctor");
    let doctor = bounded(command);
    assert!(!doctor.status.success(), "{}", stdout_of(&doctor));
    let text = stdout_of(&doctor);
    assert!(
        text.contains("default: error:"),
        "the host row reports the damage: {text}"
    );
    assert_active_row(
        &text,
        &format!(
            "active images: boot=recorded, output=not recorded, unclaimed=0 [{}]",
            h.pins().display()
        ),
    );
    assert_eq!(
        doctor.status.code(),
        Some(1),
        "host-record damage still fails doctor: {text}"
    );
    // The project's own default and the project-aware selection are unaffected
    // by host-only damage (R10): neither row may repeat the host error.
    let project_row = text
        .lines()
        .find(|line| line.starts_with("project default: "))
        .unwrap_or_else(|| panic!("no project default row: {text}"));
    assert_eq!(
        project_row,
        format!("project default: established [{}]", h.pins().display()),
        "{text}"
    );
    let selected_row = text
        .lines()
        .find(|line| line.starts_with("selected (without --image): "))
        .unwrap_or_else(|| panic!("no selected row: {text}"));
    assert_eq!(
        selected_row,
        format!(
            "selected (without --image): project default [{}]",
            h.pins().display()
        ),
        "{text}"
    );
    assert!(
        !project_row.contains("error:") && !selected_row.contains("error:"),
        "host-only damage must not fail the project rows: {text}"
    );

    let before = server.count();
    let refresh = h.refresh_default();
    assert_eq!(refresh.status.code(), Some(1), "{}", stderr(&refresh));
    assert_eq!(server.count(), before, "no registry request");
    assert_eq!(fs::read(h.pins()).unwrap(), pins);
    assert_eq!(
        fs::read(h.home.join(".config/agent-vm/default-image.json")).unwrap(),
        b"not a record"
    );
}

/// An authority that cannot be *located* is exempt from the boot-image
/// diagnosis, but a store that exists and does not decode is not (R10): the
/// exemption covers `$HOME` being unset, never damage.
#[test]
fn a_damaged_pin_store_fails_doctor_at_a_locatable_home() {
    let h = Harness::new(Mode::LaunchSeam);
    fs::create_dir_all(h.home.join(".config/agent-vm")).unwrap();
    fs::write(h.pins(), b"not json").unwrap();

    let mut command = h.command();
    command.arg("doctor");
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stdout_of(&out).contains("project default: error:"),
        "{}",
        stdout_of(&out)
    );
    assert!(
        stderr(&out).contains("image pin authority"),
        "the store's damage is the reported failure: {}",
        stderr(&out)
    );
}

/// AC13: neither update verb has `--yes`; it is an ordinary usage error.
#[test]
fn the_yes_flag_is_removed_from_both_verbs() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    for args in [
        vec!["image", "refresh", "--yes"],
        vec![
            "image",
            "set-default",
            "--image",
            "localhost:1/a:tag",
            "--yes",
        ],
    ] {
        let mut command = h.command();
        command.args(&args);
        let out = bounded(command);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("unexpected argument '--yes'"),
            "{args:?}: {}",
            stderr(&out)
        );
        assert!(
            !h.home.join(".config/agent-vm").exists(),
            "{args:?} must create nothing"
        );
    }
    assert_eq!(server.count(), 0, "no registry request");
    for verb in [
        ["image", "refresh", "--help"],
        ["image", "set-default", "--help"],
    ] {
        let mut command = h.command();
        command.args(verb);
        let out = bounded(command);
        assert!(out.status.success());
        assert!(
            !stdout_of(&out).contains("--yes"),
            "{verb:?} must not document --yes"
        );
    }
}

/// AC14: with no host record, a bare refresh re-verifies the project's own
/// default and never moves it, even when the recommendation changed.
#[test]
fn without_a_host_record_refresh_reverifies_the_project_default() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "nohost", &a);
    let b = h.image(&ArchiveSpec {
        marker: "nohost-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "nohost", &b);
    assert!(!h.launch_on_recommendation(&child_a).status.success());
    let host = h.home.join(".config/agent-vm/default-image.json");
    fs::remove_file(&host).unwrap();
    let pins = fs::read(h.pins()).unwrap();

    let before = server.count();
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child_b)
        .arg("image")
        .arg("refresh");
    let out = bounded(command);
    assert!(out.status.success(), "{}", stderr(&out));
    // AC14's other half: A is re-verified, not merely left alone.
    assert_eq!(
        manifests_requested_since(&server, before),
        vec![digest_of(&child_a)],
        "the project default is re-verified exactly once"
    );
    assert!(
        !stderr(&out).contains(&child_b),
        "the recommendation is never selected for an established project: {}",
        stderr(&out)
    );
    assert!(!host.exists(), "no host record is written");
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_a);
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        pins,
        "the approval is re-verified, not rewritten"
    );
    assert!(
        !server
            .requests()
            .iter()
            .any(|(_, path)| path.contains(&digest_of(&child_b))),
        "the recommendation is never requested"
    );
}

/// R3/R4: a bare refresh is a default-tier preparation too, so in a project with
/// no established default it establishes one — from the host record, or from the
/// recommendation, which it also seeds into the host record.
#[test]
fn a_bare_refresh_establishes_an_unestablished_project() {
    // (a) An approval and a retained host record, no project default: the bare
    // refresh establishes the host-selected immutable reference.
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "refresh-establishes", &a);
    h.pin_and_set_default(&child);
    assert!(
        h.default_record_in(&h.project).is_none(),
        "the fixture starts unestablished"
    );
    let out = h.refresh_default();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child,
        "the bare refresh establishes the host-selected reference"
    );
    assert_eq!(
        h.host_record().unwrap()["image"],
        child,
        "a host-sourced selection never rewrites the host record"
    );

    // (b) No host record: the recommendation seeds the host record and the
    // project default in one preparation.
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "refresh-seeds", &a);
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child)
        .arg("image")
        .arg("refresh");
    let out = bounded(command);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child,
        "the bare refresh establishes the recommendation it selected"
    );
    assert_eq!(
        h.host_record().unwrap()["image"],
        child,
        "R4: a recommendation selection still initializes the host record"
    );
}

/// AC12/AC6: a bare refresh with an unreadable configuration refuses the
/// default-tier fall-through. A **proven** in-use reference still recovers —
/// the environment's ambient selection, or a recorded holder passed with
/// `--image` — and either form establishes nothing. An arbitrary `--image` value
/// is refused like any other nonmember, before any registry request.
#[test]
fn a_bare_refresh_refuses_an_unreadable_config_but_a_proven_target_works() {
    for tier in ["project", "user"] {
        for variant in ["bare", "cli", "cli-held", "env"] {
            let h = Harness::new(Mode::StrictAcquisition);
            let server = Server::new();
            let a = h.image(&ArchiveSpec::default());
            let child = server.image("images", "broken", &a);
            let reference = format!("{}/images:broken", server.host);
            // A `cli-held` target must be recorded **before** the configuration
            // breaks: recovery is evidence from the healthy store.
            if variant == "cli-held" {
                let out = h.import(&a.written.path, &reference);
                assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
                assert_eq!(
                    h.record_in(&h.project, &reference).unwrap()["roles"],
                    "output",
                    "the recovery target is a genuine holder"
                );
            }
            let broken = h.home.join(".config/agent-vm/config.toml");
            fs::create_dir_all(broken.parent().unwrap()).unwrap();
            let config = "not toml [[[";
            match tier {
                "project" => {
                    let dir = h.project.join(".agent-vm");
                    fs::create_dir_all(&dir).unwrap();
                    fs::write(dir.join("config.toml"), config).unwrap();
                }
                _ => fs::write(&broken, config).unwrap(),
            }
            let default = h.home.join(".config/agent-vm/default-image.json");
            let requests_before = server.count();
            let pins_before = fs::read(h.pins()).ok();

            let out = match variant {
                "bare" => h.refresh_default(),
                "cli" | "cli-held" => h.refresh(&reference),
                _ => {
                    let mut command = h.command();
                    command
                        .env("AGENT_VM_IMAGE_TAG", &reference)
                        .arg("image")
                        .arg("refresh");
                    bounded(command)
                }
            };
            let text = stderr(&out);
            match variant {
                "bare" | "cli" => {
                    assert_eq!(out.status.code(), Some(1), "{tier}/{variant}: {text}");
                    if variant == "bare" {
                        assert!(
                            text.contains("does not fall back to the default boot image"),
                            "{tier}/{variant}: {text}"
                        );
                    } else {
                        // An arbitrary typed target is not in use, and an
                        // unreadable configuration cannot prove it is.
                        assert!(
                            text.contains("targets only references currently in use"),
                            "{tier}/{variant}: {text}"
                        );
                    }
                    assert_eq!(
                        server.count(),
                        requests_before,
                        "{tier}/{variant}: no request"
                    );
                    assert_eq!(
                        fs::read(h.pins()).ok(),
                        pins_before,
                        "{tier}/{variant}: no authority write"
                    );
                    assert!(!default.exists(), "{tier}/{variant}: no host record");
                    // The refusal needs no microsandbox state either: it is
                    // decided from input alone, before the preflight.
                    for created in [".agent-vm-msb", ".microsandbox"] {
                        assert!(
                            !h.home.join(created).exists(),
                            "{tier}/{variant}: a refused refresh created {created}"
                        );
                    }
                }
                _ => {
                    assert!(
                        out.status.success(),
                        "{tier}/{variant}: {:?}\nSTDOUT:\n{}\nSTDERR:\n{text}",
                        out.status.code(),
                        stdout_of(&out)
                    );
                    assert_eq!(
                        stdout_of(&out)
                            .matches("configured image settings could not be read")
                            .count(),
                        1,
                        "{tier}/{variant}: the warning is emitted exactly once: {}",
                        stdout_of(&out)
                    );
                    assert_eq!(
                        h.pin_in(&h.project, &reference).map(|(digest, _)| digest),
                        Some(digest_of(&child)),
                        "{tier}/{variant}: REF is approved for this project"
                    );
                    assert!(
                        h.default_record_in(&h.project).is_none(),
                        "{tier}/{variant}: an unreadable configuration establishes nothing"
                    );
                    assert!(!default.exists(), "{tier}/{variant}: no host record");
                }
            }
        }
    }
}

/// AC18: an unreadable configuration never establishes a project default, by
/// any default-tier preparation, and host initialization still happens.
///
/// Two shapes of "unreadable", because R3 names `Catalog::Broken`: TOML that
/// cannot be parsed, and readable TOML whose catalog cannot be built (a `tools`
/// entry naming an undeclared tool). The second still carries readable image
/// tiers, so `setup` selects exactly as before — only establishment is withheld.
#[test]
fn an_unreadable_config_never_establishes_a_project_default() {
    let fixtures = [
        ("unparsable", "not toml [[["),
        (
            "dangling-tools",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"missing\"]\n",
        ),
    ];
    for (shape, config_text) in fixtures {
        // With a host record: setup falls through, prepares, may first-pin, and
        // writes no project default. A launch after the fix establishes it.
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let child = server.image("images", &format!("broken-setup-{shape}"), &a);
        assert!(set_default(&h, &child).status.success());
        let config = h.project.join(".agent-vm");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("config.toml"), config_text).unwrap();
        let setup = {
            let mut command = h.command();
            command.args(["setup", "--no-verify"]);
            bounded(command)
        };
        assert!(setup.status.success(), "{shape}: {}", stderr(&setup));
        assert!(
            stdout_of(&setup).contains("could not be read"),
            "{shape}: setup still warns and falls through: {}",
            stdout_of(&setup)
        );
        assert_eq!(
            h.host_record().unwrap()["image"],
            child,
            "{shape}: setup prepares the host record's content"
        );
        assert_eq!(
            h.pin_in(&h.project, &child).map(|(digest, _)| digest),
            Some(digest_of(&child)),
            "{shape}: the preparation first-pins the selected content"
        );
        assert_eq!(
            h.record_in(&h.project, &child).unwrap()["roles"],
            "boot",
            "{shape}: the broken-catalog preparation records Boot (AC16)"
        );
        assert_eq!(
            h.pins_value().unwrap()["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|scope| scope["project"] == project_id(&h.project).as_str())
                .unwrap()["resolved"],
            "boot",
            "{shape}: the Boot slot is resolved"
        );
        assert!(
            h.default_record_in(&h.project).is_none(),
            "{shape}: an unreadable configuration establishes nothing"
        );
        fs::remove_file(config.join("config.toml")).unwrap();
        let launch = h.launch_default();
        assert!(!launch.status.success(), "the fake runtime cannot boot");
        assert_eq!(
            h.default_record_in(&h.project).unwrap()["image"],
            child,
            "{shape}: the next readable default-tier use establishes the project"
        );

        // With no host record: setup still initializes it from the
        // recommendation, and still writes no project default. A later readable
        // default-tier use establishes from the host record it seeded.
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let child = server.image("images", &format!("broken-fresh-{shape}"), &a);
        let config = h.project.join(".agent-vm");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("config.toml"), config_text).unwrap();
        let mut command = h.command();
        command
            .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child)
            .args(["setup", "--no-verify"]);
        let setup = bounded(command);
        assert!(setup.status.success(), "{shape}: {}", stderr(&setup));
        assert_eq!(
            h.host_record().unwrap()["image"],
            child,
            "{shape}: R4: the recommendation still initializes an absent host record"
        );
        assert!(
            h.default_record_in(&h.project).is_none(),
            "{shape}: a setup made while the configuration is unreadable establishes nothing"
        );
        fs::remove_file(config.join("config.toml")).unwrap();
        let launch = h.launch_default();
        assert!(!launch.status.success(), "the fake runtime cannot boot");
        assert_eq!(
            h.default_record_in(&h.project).unwrap()["image"],
            child,
            "{shape}: the next readable use establishes from the seeded host record"
        );
    }
}

/// B2's documented replacement: in an established project whose default
/// differs from the host record, an explicit `--image <its own default>`
/// re-verifies that reference and does not adopt.
#[test]
fn an_explicit_refresh_reverifies_the_project_default_without_adopting() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "explicit", &a);
    let b = h.image(&ArchiveSpec {
        marker: "explicit-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "explicit", &b);
    let tag = format!("{}/images:explicit", server.host);

    assert!(!h.launch_on_recommendation(&child_a).status.success());
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_a);
    assert!(set_default(&h, &tag).status.success());
    assert_eq!(h.host_record().unwrap()["image"], child_b);

    let pins = fs::read(h.pins()).unwrap();
    let before = server.count();
    let out = h.refresh(&child_a);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("Adopting"),
        "an explicit refresh adopts nothing: {}",
        stderr(&out)
    );
    assert!(
        !stdout_of(&out).contains("this project now uses the host's default boot image"),
        "no adoption notice: {}",
        stdout_of(&out)
    );
    assert_eq!(
        manifests_requested_since(&server, before),
        vec![digest_of(&child_a)],
        "only the named reference is resolved"
    );
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_a);
    assert_eq!(
        h.pin_for(&child_b),
        None,
        "the host's reference is not approved"
    );
    assert_eq!(fs::read(h.pins()).unwrap(), pins, "the store is unchanged");

    // The bare refresh still adopts: the explicit form is the opt-out.
    let adopt = h.refresh_default();
    assert!(adopt.status.success(), "{}", stderr(&adopt));
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_b);
}

/// R3: establishment belongs to the default tier. An explicit `--image`
/// refresh approves its target for the project and establishes nothing, even
/// when the project has no default yet.
#[test]
fn an_explicit_refresh_establishes_nothing() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "explicit-establish-a", &a);
    let b = h.image(&ArchiveSpec {
        marker: "explicit-establish-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "explicit-establish-b", &b);
    let tag = format!("{}/images:explicit-establish-a", server.host);
    assert!(set_default(&h, &tag).status.success());
    assert_eq!(h.host_record().unwrap()["image"], child_a);

    let out = h.refresh_as_ambient(&child_b);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        h.pin_in(&h.project, &child_b).map(|(digest, _)| digest),
        Some(digest_of(&child_b)),
        "the explicit refresh approves its target"
    );
    assert!(
        h.default_record_in(&h.project).is_none(),
        "an explicit refresh establishes nothing"
    );
    assert_eq!(
        h.host_record().unwrap()["image"],
        child_a,
        "and writes no host record"
    );

    // The default tier still starts from the host record, and establishes it.
    assert_eq!(
        h.reacquired_digest(&server),
        digest_of(&child_a),
        "the default tier selects the host record, not the explicit approval"
    );
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_a);
    assert_eq!(
        h.pin_in(&h.project, &child_b).map(|(digest, _)| digest),
        Some(digest_of(&child_b)),
        "the explicit approval is still there"
    );
}

/// B6: an S1 store (no `defaults`) does not establish a project on read. Until
/// its first default-tier use, the project still follows the host record, so a
/// `set-default` in that window changes what it boots.
#[test]
fn an_s1_store_follows_the_host_record_until_its_first_default_tier_use() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "window", &a);
    let b = h.image(&ArchiveSpec {
        marker: "window-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "window", &b);
    let tag = format!("{}/images:window", server.host);

    // The state 0.7.39-0.7.46 leaves: an approval and a host record, no
    // `defaults`.
    assert!(h.refresh_as_ambient(&child_a).status.success());
    let mut store = read_json(&h.pins());
    store.as_object_mut().unwrap().remove("defaults");
    fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
    fs::write(
        h.home.join(".config/agent-vm/default-image.json"),
        serde_json::to_vec(&serde_json::json!({"version": 1, "image": child_a})).unwrap(),
    )
    .unwrap();
    assert!(
        h.default_record_in(&h.project).is_none(),
        "nothing reads the store into an established default"
    );

    assert!(set_default(&h, &tag).status.success());
    assert_eq!(h.host_record().unwrap()["image"], child_b);
    assert_eq!(
        h.reacquired_digest(&server),
        digest_of(&child_b),
        "the window's set-default changes what it boots"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child_b,
        "the first default-tier use establishes the host choice it selected"
    );
}

/// B7: the first default-tier use of a project writes the store, so a launch
/// that 0.7.46 ran read-only now fails when `$HOME/.config/agent-vm` is not
/// writable.
#[test]
fn an_unwritable_store_fails_the_launch_that_must_establish() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "establish-write", &a);
    let tag = format!("{}/images:establish-write", server.host);

    // A warm approval and a host record, but no project default yet.
    assert!(h.refresh_as_ambient(&child).status.success());
    assert!(set_default(&h, &tag).status.success());
    assert!(h.default_record_in(&h.project).is_none());

    let directory = h.pins().parent().unwrap().to_owned();
    let permissions = fs::metadata(&directory).unwrap().permissions();
    if unsafe { libc::geteuid() } == 0 {
        // Root bypasses directory EACCES; the injected-fault form of this row is
        // `a_failed_first_default_pin_may_leave_the_host_starting_choice_initialized`.
        eprintln!("root: EACCES half skipped, the gate fault row covers the failure");
        return;
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    let out = h.launch_default();
    fs::set_permissions(&directory, permissions).unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("image pin authority"),
        "the failure names the store: {}",
        stderr(&out)
    );
    assert!(
        h.default_record_in(&h.project).is_none(),
        "a refused establishment writes no default"
    );

    // Writability restored: the next launch establishes, and boots the content
    // that was already approved.
    let before = server.count();
    let again = h.launch_default();
    assert!(!again.status.success(), "the fake runtime cannot boot");
    assert_eq!(server.count(), before, "the approval is warm");
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child,
        "the next launch establishes the host choice"
    );
}

/// R6 on a terminal: a bare refresh that adopts reads no input and asks
/// nothing, so the terminal is never a prompt surface.
#[test]
fn refresh_adoption_never_reads_a_terminal() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "pty-adopt", &a);
    let b = h.image(&ArchiveSpec {
        marker: "pty-adopt-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "pty-adopt", &b);
    let tag = format!("{}/images:pty-adopt", server.host);
    assert!(!h.launch_on_recommendation(&child_a).status.success());
    assert!(set_default(&h, &tag).status.success());

    let mut command = h.command();
    command.arg("image").arg("refresh");
    let mut terminal = Pty::spawn(&mut command, b"Adopting the host's default boot image")
        .expect("open a pseudo-terminal");
    let (status, out) = terminal
        .drive(&Action::Write(b""), Duration::from_secs(60))
        .expect("wait for the refresh to exit");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(status.success(), "{text}");
    assert!(
        text.contains("Adopting the host's default boot image"),
        "{text}"
    );
    assert!(
        text.contains(&format!("old: {}", digest_of(&child_a)))
            && text.contains(&format!("new: {}", digest_of(&child_b))),
        "{text}"
    );
    assert_no_question(&text);
    assert_eq!(h.default_record_in(&h.project).unwrap()["image"], child_b);
    assert_eq!(
        h.pin_in(&h.project, &child_b),
        Some((digest_of(&child_b), 2)),
        "the terminal adoption inserts the host reference's approval"
    );
}

/// R10: observing an unestablished project writes nothing at all.
#[test]
fn doctor_and_show_in_an_unestablished_project_write_nothing() {
    let h = Harness::new(Mode::LaunchSeam);
    for verb in [vec!["image", "show"], vec!["doctor"]] {
        let mut command = h.command();
        command.args(&verb);
        let out = bounded(command);
        assert!(out.status.success(), "{verb:?}: {}", stderr(&out));
        assert!(
            !h.home.join(".config/agent-vm").exists(),
            "{verb:?} must create nothing"
        );
    }
}

/// The §5 race: two first default-tier launches selecting different starting
/// choices keep the first committer's default, and each still boots the content
/// it approved this once.
#[test]
fn concurrent_first_launches_across_a_set_default_keep_the_first_project_default() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "race", &a);
    let b = h.image(&ArchiveSpec {
        marker: "race-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "race", &b);

    let mut first_gate = PinGate::new(h.root.path());
    let mut second_gate = PinGate::new(h.root.path());
    let mut first = h.command();
    first
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child_a)
        .args(["shell", "--", "true"]);
    let peer_a = pin_gate::PinPeer::spawn(first, &first_gate, &[]);
    let ready_a = first_gate.expect(PinStage::CandidateReady);
    // The host choice moves to B between the two selections.
    assert!(set_default(&h, &child_b).status.success());
    let mut second = h.command();
    second.args(["shell", "--", "true"]);
    let peer_b = pin_gate::PinPeer::spawn(second, &second_gate, &[]);
    let ready_b = second_gate.expect(PinStage::CandidateReady);

    // A commits first: its selection becomes the project's default.
    ready_a.reply(Reply::Continue);
    for stage in [
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        first_gate.expect(stage).reply(Reply::Continue);
    }
    ready_b.reply(Reply::Continue);
    for stage in [
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        second_gate.expect(stage).reply(Reply::Continue);
    }
    let out_a = peer_a.wait();
    let out_b = peer_b.wait();
    assert!(!out_a.status.success());
    assert!(!out_b.status.success());
    assert_eq!(
        h.pin_in(&h.project, &child_a).map(|(digest, _)| digest),
        Some(digest_of(&child_a)),
        "the first peer approved A"
    );
    assert_eq!(
        h.pin_in(&h.project, &child_b).map(|(digest, _)| digest),
        Some(digest_of(&child_b)),
        "the second peer still approved B for the launch it made"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        child_a,
        "write-once: the first committer's reference stands"
    );
    let store = read_json(&h.pins());
    assert_eq!(store["pins"].as_array().unwrap().len(), 2);
    assert!(store["pending_default"].is_null(), "no journal is written");
}

// ---------------------------------------------------------------------------
// ADR-0068: the active image set at the CLI boundary.
// ---------------------------------------------------------------------------

/// AC2/AC15: a one-off override switches the recorded Boot selection only after
/// it was acquired, before SDK create; the displaced X retires because Output
/// was already resolved. `image show` still reports the ambient selection.
#[test]
fn one_off_boot_switch_retires_after_acquisition_before_create() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let o = archive_at(&h, "switch-o.tar", "switch-o");
    let o_tag = format!("{}/images:o", server.host);
    let x_tag = format!("{}/images:x", server.host);
    let y_tag = format!("{}/images:y", server.host);
    let x = h.image(&ArchiveSpec {
        marker: "switch-x".into(),
        ..Default::default()
    });
    server.image("images", "x", &x);
    let y = h.image(&ArchiveSpec {
        marker: "switch-y".into(),
        ..Default::default()
    });
    let y_child = server.image("images", "y", &y);

    // Resolve Output first: a Boot-only switch may retire only when both slots
    // are known.
    let out = h.import(&o.path, &o_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!h.launch(&x_tag).status.success());
    assert_eq!(h.record_in(&h.project, &x_tag).unwrap()["roles"], "boot");

    // The one-off override: acquisition succeeds and is recorded even though the
    // SDK create afterwards fails (the fake runtime cannot boot).
    let out = h.launch(&y_tag);
    assert!(!out.status.success(), "the fake runtime cannot boot");
    assert_eq!(
        sdk_image(&out),
        y_child,
        "the acquired Y is what create gets"
    );
    assert!(
        h.pin_for(&x_tag).is_none(),
        "X is retired: Boot moved and Output was resolved elsewhere"
    );
    assert_eq!(h.record_in(&h.project, &y_tag).unwrap()["roles"], "boot");
    assert_eq!(h.record_in(&h.project, &o_tag).unwrap()["roles"], "output");
    assert!(
        h.pins_value().unwrap()["sequence"].as_u64().unwrap() >= 3,
        "the save persisted a global sequence"
    );

    // B7/AC15: show reports the ambient selection, never the recorded Boot.
    let mut command = h.command();
    command
        .env("AGENT_VM_IMAGE_TAG", &x_tag)
        .arg("image")
        .arg("show");
    let shown = bounded(command);
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    assert!(
        stdout_of(&shown).contains(&x_tag),
        "show keeps its ambient meaning: {}",
        stdout_of(&shown)
    );
}

/// S1/R8: an archive alias over a reference you approved earlier does not keep
/// that approval alive — but it can supply that reference's **next** pin,
/// cache-first. This is the documented outcome (USAGE, ADR-0043/0047) and the
/// hermetic twin of the native alias row.
#[test]
fn archive_alias_after_retirement_supplies_the_next_pin() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "alias-a".into(),
        ..Default::default()
    });
    let child_a = server.image("images", "x", &a);
    let tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&tag).status.success());
    assert_eq!(sdk_image(&h.launch(&tag)), child_a);
    let (a_digest, a_revision) = h.pin_for(&tag).expect("X is approved at A");
    assert_eq!(h.record_in(&h.project, &tag).unwrap()["roles"], "boot");

    // Boot moves to Y: X holds no role now, but its Output is still unknown, so
    // the store retains it (R2).
    let y = h.image(&ArchiveSpec {
        marker: "alias-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!h.launch(&y_tag).status.success());
    assert!(h.pin_for(&tag).is_some(), "?Output protects the unheld X");
    assert!(
        h.record_in(&h.project, &tag)
            .unwrap()
            .get("roles")
            .is_none()
    );

    // An archive whose own names include X's tag, imported under a *different*
    // result reference. Only the named result is approved, but claiming Output
    // resolves the scope's Output slot, so the unheld X is now both known-absent
    // and retires in that same save.
    let other = format!("{}/images:other", server.host);
    let save = image_archive::write_docker_save(
        &h.root.path().join("alias.tar"),
        &[image_archive::DockerSaveImage {
            marker: "alias-evil".into(),
            repo_tags: Some(vec![tag.clone()]),
        }],
    );
    let out = h.import(&save[0].path, &other);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        h.pin_for(&tag).is_none(),
        "an unheld, both-known-absent approval is not retained"
    );
    assert_eq!(h.record_in(&h.project, &other).unwrap()["roles"], "output");
    let mut references: Vec<String> = h.pins_value().unwrap()["pins"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["project"] == project_id(&h.project).as_str())
        .map(|record| record["reference"].as_str().unwrap().to_owned())
        .collect();
    references.sort();
    assert_eq!(
        references,
        vec![other.clone(), y_tag.clone()],
        "no archive-carried name became a record"
    );

    // The return is a first pin, so it acquires cache-first: the alias this
    // import published supplies the archive's own content, and no historical
    // approval is restored (R8/B4).
    let (archive_digest, _) = h
        .pin_in(&h.project, &other)
        .expect("the named result was approved");
    let before = server.count();
    let back = h.launch(&tag);
    assert!(!back.status.success());
    let sdk = sdk_image(&back);
    assert_eq!(
        digest_of(&sdk),
        archive_digest,
        "the alias supplies the archive's own content: {sdk}"
    );
    assert_eq!(server.count(), before, "cache-first: no registry request");
    let (digest, revision) = h
        .pin_for(&tag)
        .expect("the return approves fresh authority");
    assert_eq!(digest, archive_digest);
    assert_ne!(digest, a_digest, "the old approval is not restored");
    assert!(revision > a_revision, "a fresh global allocation");
    assert_eq!(h.record_in(&h.project, &tag).unwrap()["roles"], "boot");
}

/// AC7 (warm changed alias): a retired X is not restored from its old approval;
/// returning resolves the cache-first source, which now holds newer B.
#[test]
fn retired_return_uses_changed_warm_cache_not_old_approval() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let o = archive_at(&h, "return-o.tar", "return-o");
    let o_tag = format!("{}/images:o", server.host);
    let x_tag = format!("{}/images:x", server.host);
    let y_tag = format!("{}/images:y", server.host);
    assert_eq!(
        h.import(&o.path, &o_tag).status.code(),
        Some(0),
        "resolve Output first"
    );

    let a = h.image(&ArchiveSpec {
        marker: "return-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "x", &a);
    assert!(!h.launch(&x_tag).status.success());
    assert_eq!(sdk_image(&h.launch(&x_tag)), a_child);
    let (a_digest, a_revision) = h.pin_for(&x_tag).expect("X is approved at A");

    // The registry now serves B under X's tag. A second project shares the HOME
    // and cache but not the approval; its refresh re-establishes X's cache
    // entry at B.
    let b = h.image(&ArchiveSpec {
        marker: "return-b".into(),
        ..Default::default()
    });
    let b_child = server.image("images", "x", &b);
    assert_eq!(
        sdk_image(&h.launch(&x_tag)),
        a_child,
        "warm A is still approved"
    );
    let p2 = h.project_at("return-project");
    let refreshed = h.refresh_as_ambient_in(&p2, &h.state, &x_tag);
    assert!(refreshed.status.success(), "{}", stderr(&refreshed));
    assert_eq!(
        digests_requested_since(&server, 0),
        Vec::<String>::new(),
        "no digest-addressed manifest was requested: both acquisitions were cache hits"
    );

    // Retire X in P1: Boot moves to Y while Output is already resolved.
    let y = h.image(&ArchiveSpec {
        marker: "return-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let switched = h.launch(&y_tag);
    assert!(!switched.status.success());
    assert!(
        h.pin_in(&h.project, &x_tag).is_none(),
        "X is absent before the return: {}",
        stderr(&switched)
    );

    // Returning to X acquires and validates the selected source cache-first: the
    // cache now holds B, and no historical A approval is restored.
    let sequence = h.pins_value().unwrap()["sequence"].as_u64().unwrap();
    let network = server.count();
    let back = h.launch(&x_tag);
    assert!(!back.status.success());
    assert_eq!(sdk_image(&back), b_child, "the return boots B, not A");
    assert_eq!(server.count(), network, "the return is served by the cache");
    assert!(
        !stderr(&back).contains("old: "),
        "a first pin renders no old -> new change: {}",
        stderr(&back)
    );
    let (digest, revision) = h
        .pin_in(&h.project, &x_tag)
        .expect("the return approves fresh authority");
    assert_eq!(digest, digest_of(&b_child));
    assert_ne!(digest, a_digest, "the old approval is not restored");
    assert_eq!(
        revision,
        sequence + 1,
        "the return draws the next global allocation, not a per-key +1"
    );
    assert_ne!(revision, a_revision);
}

/// The digests the registry served as manifest requests since `from`.
fn digests_requested_since(server: &Server, from: usize) -> Vec<String> {
    server.requests()[from..]
        .iter()
        .filter_map(|(_, path)| path.rsplit_once("/manifests/"))
        .map(|(_, reference)| reference.to_owned())
        .filter(|reference| reference.starts_with("sha"))
        .collect()
}

/// AC18: once the rename committed, its checkpoint failing to report is a
/// success warning — exit 0, exact committed bytes, no failed-publication text.
#[test]
fn publication_after_rename_gate_disconnect_is_success() {
    let h = Harness::new(Mode::LaunchSeam);
    let a = archive_at(&h, "gate-a.tar", "gate-a");
    let tag = "example.com/team/gate:dev";
    // The same import with no gate at all: the only committed-bytes baseline
    // that is not derived from this implementation's own proposal.
    let baseline = gate_free_import(&h, &a.path, tag);
    let _ = fs::remove_dir_all(config_dir(&h));
    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    gate.attach(&mut command);
    let child = command
        .stdin(std::process::Stdio::null())
        .args([
            "image",
            "import",
            "--input",
            a.path.to_str().unwrap(),
            "--tag",
            tag,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated import");
    gate.expect(PinStage::Published).reply(Reply::Continue);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinLock).reply(Reply::Continue);
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinSave).reply(Reply::Continue);
    // The rename has happened; closing the gate without a reply is the report
    // failure this row is about.
    drop(gate.expect(PinStage::PinCommitted));
    let out = child.wait_with_output().expect("collect the import");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a committed publication reports success: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains(
            "warning: image publication succeeded and active image state was committed, but the \
             post-commit test checkpoint could not be reported; do not retry it as a failed \
             publication"
        ),
        "{text}"
    );
    assert!(!text.contains("approval was not updated"), "{text}");
    assert!(!text.contains("nothing was approved"), "{text}");
    // The proposed authority is exactly what was committed: byte-identical to
    // the gate-free run of the same import.
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        baseline,
        "the committed bytes are the gate-free baseline's"
    );
    assert_eq!(
        h.pin_for(tag),
        Some((a.manifest_digest.clone(), 1)),
        "the committed approval is on disk"
    );
}

/// A stdout whose read end is already closed: every write fails with `EPIPE`.
fn closed_stdout_pipe() -> fs::File {
    use std::os::fd::FromRawFd as _;
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "create a pipe");
    assert_eq!(unsafe { libc::close(fds[0]) }, 0, "close the read end");
    unsafe { fs::File::from_raw_fd(fds[1]) }
}

/// AC18: a completion notice that cannot be written does not change the exit
/// status or the committed authority, and warns with the notice-specific text.
#[test]
fn publication_after_rename_notice_epipe_is_success() {
    let h = Harness::new(Mode::LaunchSeam);
    let a = archive_at(&h, "epipe-a.tar", "epipe-a");
    let tag = "example.com/team/epipe:dev";
    let baseline = gate_free_import(&h, &a.path, tag);
    let _ = fs::remove_dir_all(config_dir(&h));
    let mut command = h.command();
    let child = command
        .stdin(std::process::Stdio::null())
        .args([
            "image",
            "import",
            "--input",
            a.path.to_str().unwrap(),
            "--tag",
            tag,
        ])
        .stdout(std::process::Stdio::from(closed_stdout_pipe()))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the import");
    let out = child.wait_with_output().expect("collect the import");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a committed publication exits 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains(
            "warning: image publication succeeded and active image state was committed, but its \
             completion notice could not be written; do not retry it as a failed publication"
        ),
        "{text}"
    );
    assert!(!text.contains("approval was not updated"), "{text}");
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        baseline,
        "a failed notice does not change one committed byte"
    );
    assert_eq!(h.pin_for(tag), Some((a.manifest_digest.clone(), 1)));
}

/// AC13/AC19: a literal old-v2 record is claimed once (role, scope, sequence in
/// one save), keeps its approval token, and the next complete no-op writes
/// nothing and takes no gate stage.
#[test]
fn warm_old_pin_claims_once_then_noops() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "old-claim-a".into(),
        ..Default::default()
    });
    let child = server.image("images", "old", &a);
    let tag = format!("{}/images:old", server.host);
    assert!(!h.launch(&tag).status.success());
    assert_eq!(sdk_image(&h.launch(&tag)), child);

    // Literal 0.7.49 shape: no roles, no scopes, no sequence.
    let mut store = h.pins_value().unwrap();
    for record in store["pins"].as_array_mut().unwrap() {
        record.as_object_mut().unwrap().remove("roles");
        record["revision"] = serde_json::json!(7);
    }
    store.as_object_mut().unwrap().remove("scopes");
    store.as_object_mut().unwrap().remove("sequence");
    seed_store(&h, &serde_json::to_vec(&store).unwrap());
    let old = fs::read(h.pins()).unwrap();

    // The first warm claim writes the role/scope/sequence in one save, keeping
    // the approval's content and token.
    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(sdk_image(&out), child);
    let claimed: serde_json::Value = serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    assert_eq!(claimed["pins"][0]["roles"], "boot");
    assert_eq!(claimed["pins"][0]["revision"], 7);
    assert_eq!(claimed["scopes"][0]["resolved"], "boot");
    assert_eq!(claimed["sequence"], serde_json::json!(8));
    assert_ne!(fs::read(h.pins()).unwrap(), old);

    // A complete no-op: byte-identical, and no pin stage (a gate socket that does
    // not exist would fail any stage).
    let bytes = fs::read(h.pins()).unwrap();
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_PIN_GATE", h.root.path().join("absent.sock"))
        .args(["--image", &tag, "shell", "--", "true"]);
    let network = server.count();
    let out = bounded(command);
    assert!(!out.status.success(), "the fake runtime cannot boot");
    assert_eq!(sdk_image(&out), child);
    assert_eq!(fs::read(h.pins()).unwrap(), bytes);
    assert_eq!(server.count(), network, "a no-op makes no registry request");
}

// ---------------------------------------------------------------------------
// The gated safety paths: first-pin failure, pre-lock ABA, claim-save faults.
// ---------------------------------------------------------------------------

/// A peer command in `state`, rooted at the launching project: the ABA schedules
/// run their peers on a separate state/cache root that shares only this HOME, so
/// the paused operation's shared cache barrier cannot block them (plan §8).
/// A peer's own state/cache root, short enough for the runtime's 103-byte
/// control-socket path limit (`target/tmp/<test>/…` is not).
fn peer_state(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("avp{name}-"))
        .tempdir_in("/tmp")
        .expect("a short peer state root")
}

fn peer_import(h: &Harness, state: &Path, archive: &Path, tag: &str) -> Output {
    let mut command = h.command_in(&h.project, state);
    command.stdin(std::process::Stdio::null()).args([
        "image",
        "import",
        "--input",
        archive.to_str().unwrap(),
        "--tag",
        tag,
    ]);
    bounded(command)
}

/// A deliberate no-role reinsertion by a peer: the reference is the peer's
/// ambient selection, because a filter may only refresh a reference already in
/// use and a retired key holds no role.
fn peer_refresh(h: &Harness, state: &Path, reference: &str) -> Output {
    let mut command = h.command_in(&h.project, state);
    command
        .env("AGENT_VM_IMAGE_TAG", reference)
        .args(["image", "refresh"]);
    bounded(command)
}

fn peer_launch(h: &Harness, state: &Path, reference: &str) -> Output {
    let mut command = h.command_in(&h.project, state);
    command.args(["--image", reference, "shell", "--", "true"]);
    bounded(command)
}

/// AC3: a failed acquisition and a failed Boot-claim save both preserve the exact
/// old authority — roles, scope resolution and `sequence` — and never reach SDK
/// create.
///
/// The warm half is `claim_selected`'s save path, which no earlier fault row
/// reaches: `unwritable_authority_…` faults a refresh, and the first-pin rows
/// fault `commit`.
#[test]
fn failed_boot_acquisition_or_claim_save_keeps_authority() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    // Output resolved to O first, so a Boot claim is allowed to retire.
    let o = h.image(&ArchiveSpec {
        marker: "claim-fault-o".into(),
        ..Default::default()
    });
    let o_tag = format!("{}/images:o", server.host);
    let out = h.import(&o.written.path, &o_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    // The ambient approval below also covers this Output holder, so its
    // reference resolves to the identical content.
    server.image("images", "o", &o);
    // X holds Boot.
    let x = h.image(&ArchiveSpec {
        marker: "claim-fault-x".into(),
        ..Default::default()
    });
    server.image("images", "x", &x);
    let x_tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&x_tag).status.success());
    // Y is approved but holds no role: a refresh claims none (R7), so the warm
    // claim below is a real change.
    let y = h.image(&ArchiveSpec {
        marker: "claim-fault-y".into(),
        ..Default::default()
    });
    let y_child = server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(h.refresh_as_ambient(&y_tag).status.success());
    assert!(
        h.record_in(&h.project, &y_tag)
            .unwrap()
            .get("roles")
            .is_none(),
        "refresh claims no role"
    );

    let before = fs::read(h.pins()).unwrap();
    let creates = create_invocations(&h);
    let authority =
        || -> serde_json::Value { serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap() };
    let old = authority();
    assert_eq!(
        old["sequence"],
        serde_json::json!(3),
        "import, X claim, Y refresh"
    );
    let record = |value: &serde_json::Value, reference: &str| -> serde_json::Value {
        value["pins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["reference"] == reference)
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };

    // (a) Acquisition failure for a never-approved reference: the selected source
    // cannot be acquired, so nothing may be claimed.
    let missing = format!("{}/images:absent", server.host);
    let out = h.launch(&missing);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("stale"),
        "an acquisition failure is not a stale approval: {}",
        stderr(&out)
    );
    assert_eq!(create_invocations(&h), creates, "no SDK create");
    assert_eq!(fs::read(h.pins()).unwrap(), before, "exact old bytes");

    // (b) The warm Boot claim for the approved-but-unheld Y cannot save.
    let mut gate = PinGate::new(h.root.path());
    let peer = PinPeer::spawn(
        h.command(),
        &gate,
        &["--image", &y_tag, "shell", "--", "true"],
    );
    gate.expect(PinStage::BeforePinLock).reply(Reply::Continue);
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinSave)
        .reply(Reply::FailBeforeSave);
    // A suppressed fault would save (and only then block on the next checkpoint):
    // assert the state oracles before collecting the child, so a wrong
    // implementation fails here rather than on a gate read timeout.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline && fs::read(h.pins()).unwrap() == before {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        before,
        "exact old bytes, sequence included"
    );
    assert_eq!(create_invocations(&h), creates, "no SDK create");
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("could not be accessed or saved"),
        "the failure must name the authority save: {}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("stale"), "{}", stderr(&out));

    // (c) The same fault on the first-pin path: a never-approved Z.
    let z = h.image(&ArchiveSpec {
        marker: "claim-fault-z".into(),
        ..Default::default()
    });
    server.image("images", "z", &z);
    let z_tag = format!("{}/images:z", server.host);
    let mut gate = PinGate::new(h.root.path());
    let peer = PinPeer::spawn(
        h.command(),
        &gate,
        &["--image", &z_tag, "shell", "--", "true"],
    );
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinLock).reply(Reply::Continue);
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinSave)
        .reply(Reply::FailBeforeSave);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline && fs::read(h.pins()).unwrap() == before {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(fs::read(h.pins()).unwrap(), before, "exact old bytes");
    assert_eq!(create_invocations(&h), creates, "no SDK create");
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("could not be accessed or saved"),
        "{}",
        stderr(&out)
    );

    // The whole-bytes comparisons above include these, named for the reader.
    let old = authority();
    assert_eq!(record(&old, &x_tag)["roles"], "boot");
    assert_eq!(record(&old, &o_tag)["roles"], "output");
    assert!(
        record(&old, &y_tag).get("roles").is_none(),
        "Y never held a role"
    );
    assert_eq!(old["scopes"][0]["resolved"], "boot-and-output");
    assert_eq!(old["sequence"], serde_json::json!(3));
    let _ = y_child;
}

/// AC10: a first pin whose lock cannot be opened before the CAS decision fails —
/// it may never fall back to the different winner a peer committed meanwhile.
///
/// The fault must precede `commit_decision`: with the peer's record present the
/// decision is already `Conflict`, so a `BeforePinSave` fault would never fire.
/// The stable lock is therefore made readable but not writable (mode 0400), which
/// breaks `begin`'s RDWR open while `lookup`'s RDONLY open still succeeds — so a
/// fallback would find the peer's winner. Root bypasses file permissions, so
/// there the gate closes at `BeforePinLock` instead: still before the decision,
/// and still with a readable store for a fallback to find.
#[test]
fn first_pin_io_failure_never_becomes_winner_success() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "io-fault-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "io", &a);
    let tag = format!("{}/images:io", server.host);

    let mut gate = PinGate::new(h.root.path());
    let loser = PinPeer::spawn(
        h.command(),
        &gate,
        &["--image", &tag, "shell", "--", "true"],
    );
    let ready = gate.expect(PinStage::CandidateReady);

    // The registry now serves B for the same key, and a peer in its own
    // state/cache root (so it cannot contend with the paused acquisition)
    // first-pins it in this same project: this is the winner a fallback would
    // boot. Its Boot claim also makes the loser's later warm claim a no-op, so
    // a fallback would succeed rather than fail again.
    let b = h.image(&ArchiveSpec {
        marker: "io-fault-b".into(),
        ..Default::default()
    });
    let b_child = server.image("images", "io", &b);
    assert_ne!(digest_of(&a_child), digest_of(&b_child));
    let peer_state = peer_state("iof");
    let out = peer_launch(&h, peer_state.path(), &tag);
    assert!(!out.status.success(), "the fake runtime cannot boot");
    let (winner, _) = h.pin_for(&tag).expect("the peer committed a winner");
    assert_eq!(winner, digest_of(&b_child), "the winner is the peer's B");
    let winner_bytes = fs::read(h.pins()).unwrap();
    let creates = create_invocations(&h);

    let root = unsafe { libc::geteuid() } == 0;
    let lock = config_dir(&h).join("image-pins.lock");
    let permissions = fs::metadata(&lock).unwrap().permissions();
    if !root {
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o400)).unwrap();
    }
    ready.reply(Reply::Continue);
    let checkpoint = gate.expect(PinStage::BeforePinLock);
    if root {
        drop(checkpoint);
    } else {
        checkpoint.reply(Reply::Continue);
    }
    let out = loser.wait();
    fs::set_permissions(&lock, permissions).unwrap();

    let text = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert_eq!(
        create_invocations(&h),
        creates,
        "a failed first pin must not reach SDK create: {text}"
    );
    assert!(
        !text.contains("stale"),
        "an I/O failure is not a stale approval: {text}"
    );
    let diagnostic = if root {
        "image pin gate closed without a reply"
    } else {
        "could not be accessed or saved"
    };
    assert!(
        text.contains(diagnostic),
        "the failure must name the save, not a winner: {text}"
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        winner_bytes,
        "the winner's authority is byte-identical"
    );
    assert_eq!(
        h.pin_for(&tag),
        Some((digest_of(&b_child), 1)),
        "the peer's first pin is the only allocation"
    );
}

/// AC22: a needed warm Boot claim paused before the pin lock loses to peers that
/// retire X and reinsert the same digest under a new allocation — stale, no
/// create, exact peer bytes.
///
/// The consumed tuple is what distinguishes the second lifetime; a caller that
/// re-read the tuple instead of passing the consumed one accepts the new one.
#[test]
fn warm_claim_rejects_retire_reinsert_same_digest_lifetime() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    // X holds Output (an import claims it) at digest A; Boot is still unknown.
    let a = archive_at(&h, "aba-warm-a.tar", "aba-warm-a");
    let x_tag = format!("{}/images:x", server.host);
    let o = archive_at(&h, "aba-warm-o.tar", "aba-warm-o");
    let o_tag = format!("{}/images:o", server.host);
    let out = h.import(&a.path, &x_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let (a_digest, a_revision) = h.pin_for(&x_tag).expect("X holds Output at A");
    // Y holds Boot, so X is not retired while it holds Output.
    let y = h.image(&ArchiveSpec {
        marker: "aba-warm-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!h.launch(&y_tag).status.success());
    assert_eq!(h.record_in(&h.project, &y_tag).unwrap()["roles"], "boot");

    // The suspended warm claim: X holds Output, so claiming Boot is a real change
    // and reaches the exclusive transaction.
    let mut gate = PinGate::new(h.root.path());
    let loser = PinPeer::spawn(
        h.command(),
        &gate,
        &["--image", &x_tag, "shell", "--", "true"],
    );
    let locked = gate.expect(PinStage::BeforePinLock);

    // Peers, on their own state/cache root: take Output away (retiring X), then
    // reinsert the same digest with the next global allocation.
    let peer_state = peer_state("abw");
    let out = peer_import(&h, peer_state.path(), &o.path, &o_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        h.pin_for(&x_tag).is_none(),
        "X is retired by the peer's Output claim"
    );
    let out = peer_import(&h, peer_state.path(), &a.path, &x_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let (reinserted_digest, reinserted) = h.pin_for(&x_tag).expect("the peer reinserted X");
    assert_eq!(reinserted_digest, a_digest, "the same digest comes back");
    assert!(
        reinserted > a_revision,
        "a new global allocation: {reinserted} > {a_revision}"
    );
    let peer_bytes = fs::read(h.pins()).unwrap();
    let creates = create_invocations(&h);

    locked.reply(Reply::Continue);
    // The stale decision happens under the lock and before any save: the last
    // stage is `PinLocked`, never `BeforePinSave`.
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    let out = loser.wait();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("stale"),
        "the second lifetime must not satisfy the old tuple: {}",
        stderr(&out)
    );
    assert_eq!(
        create_invocations(&h),
        creates,
        "a stale claim must not reach SDK create"
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        peer_bytes,
        "the peer's authority is byte-identical"
    );
    assert_eq!(h.pin_for(&x_tag), Some((a_digest, reinserted)));
    assert_eq!(
        h.record_in(&h.project, &y_tag).unwrap()["roles"],
        "boot",
        "the peer's Boot holder is untouched"
    );
}

/// AC22 (caller seam): the approval a warm preparation consumed **is** the
/// predecessor its Boot claim presents.
///
/// Peers retire X and reinsert the same digest while the approved content is
/// being acquired — after the tuple was read, before the claim is made — so the
/// claim is stale and no create happens. A caller that re-read the tuple at that
/// point would claim the reinserted lifetime instead.
#[test]
fn warm_claim_presents_the_consumed_tuple_after_a_reinsert() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = archive_at(&h, "seam-a.tar", "seam-a");
    let x_tag = format!("{}/images:x", server.host);
    let o = archive_at(&h, "seam-o.tar", "seam-o");
    let o_tag = format!("{}/images:o", server.host);
    let out = h.import(&a.path, &x_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let (a_digest, a_revision) = h.pin_for(&x_tag).expect("X holds Output at A");
    let y = h.image(&ArchiveSpec {
        marker: "seam-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!h.launch(&y_tag).status.success());

    // The tuple is read before the approved content is acquired: pause there,
    // with the fine-grained observation stages enabled so the pause is a real
    // cache hit rather than a guess.
    let mut gate = AcquisitionGate::new(h.root.path());
    let mut command = h.command();
    command.env("AGENT_VM_TEST_ACQUIRE_GATE_DETAIL", "1");
    let loser =
        acquisition_gate::Peer::spawn(command, &gate, &["--image", &x_tag, "shell", "--", "true"]);
    let hit = gate.expect_eventually(AcquisitionStage::CacheHit);

    let peer_state = peer_state("seam");
    let out = peer_import(&h, peer_state.path(), &o.path, &o_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(h.pin_for(&x_tag).is_none(), "X is retired");
    let out = peer_import(&h, peer_state.path(), &a.path, &x_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let (reinserted_digest, reinserted) = h.pin_for(&x_tag).expect("X is reinserted");
    assert_eq!(reinserted_digest, a_digest);
    assert!(reinserted > a_revision);
    let peer_bytes = fs::read(h.pins()).unwrap();
    let creates = create_invocations(&h);

    hit.reply(GateReply::Continue);
    // A claim that presented the reinserted lifetime would write the store and
    // then reach SDK create. Assert those two oracles *before* collecting the
    // child, so a wrong implementation fails here instead of on a read timeout.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline
        && create_invocations(&h) == creates
        && fs::read(h.pins()).unwrap() == peer_bytes
    {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        create_invocations(&h),
        creates,
        "the claim must not present the reinserted lifetime"
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        peer_bytes,
        "the peer's authority is byte-identical"
    );
    let out = loser.wait();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("stale"), "{}", stderr(&out));
}

/// AC21 (refresh): a changed-content refresh frozen against X=A pauses before the
/// pin lock; peers retire X and reinsert A; resuming is stale with no B commit and
/// exact peer bytes.
///
/// A per-key or reset-to-1 allocator reissues A's old token, which matches the
/// frozen predecessor and commits B here.
#[test]
fn refresh_cas_rejects_retire_reinsert_same_digest_lifetime() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "aba-refresh-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "x", &a);
    let x_tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&x_tag).status.success());
    let (a_digest, a_revision) = h.pin_for(&x_tag).expect("X holds Boot at A");
    assert_eq!(a_digest, digest_of(&a_child));
    // The tag now serves B, so the refresh freezes and renders A -> B.
    let b = h.image(&ArchiveSpec {
        marker: "aba-refresh-b".into(),
        ..Default::default()
    });
    let b_child = server.image("images", "x", &b);
    assert_ne!(digest_of(&b_child), a_digest);

    let mut gate = PinGate::new(h.root.path());
    let loser = PinPeer::spawn(h.command(), &gate, &["image", "refresh", "--image", &x_tag]);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let locked = gate.expect(PinStage::BeforePinLock);

    // Peers retire X: Output to O, then Boot to Y. Both slots are then resolved
    // and X holds neither, so the store retires it.
    let peer_state = peer_state("abr");
    let o = h.image(&ArchiveSpec {
        marker: "aba-refresh-o".into(),
        ..Default::default()
    });
    let o_tag = format!("{}/images:o", server.host);
    let out = peer_import(&h, peer_state.path(), &o.written.path, &o_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let y = h.image(&ArchiveSpec {
        marker: "aba-refresh-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!peer_launch(&h, peer_state.path(), &y_tag).status.success());
    assert!(h.pin_for(&x_tag).is_none(), "X is retired");
    // Reinsert A: the registry serves A again and refresh claims no role. The
    // peer's ambient refresh also covers its other holders, so the imported
    // Output reference is served with the identical content.
    server.image("images", "x", &a);
    server.image("images", "o", &o);
    let reinserted_out = peer_refresh(&h, peer_state.path(), &x_tag);
    assert!(
        reinserted_out.status.success(),
        "the peer reinserts A: {}{}",
        stdout_of(&reinserted_out),
        stderr(&reinserted_out)
    );
    let (reinserted_digest, reinserted) = h.pin_for(&x_tag).expect("the peer reinserted X");
    assert_eq!(reinserted_digest, a_digest);
    assert!(reinserted > a_revision);
    let peer_bytes = fs::read(h.pins()).unwrap();

    locked.reply(Reply::Continue);
    // The stale decision happens under the lock and before any save: the last
    // stage is `PinLocked`, never `BeforePinSave`.
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    let out = loser.wait();
    assert!(!out.status.success());
    assert!(
        stdout_of(&out).contains("stale"),
        "the frozen predecessor no longer exists: {}{}",
        stdout_of(&out),
        stderr(&out)
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        peer_bytes,
        "no B approval and no default change were committed"
    );
    assert!(
        h.pins_value().unwrap()["pins"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["manifest_digest"] != digest_of(&b_child)),
        "B is never committed"
    );
    assert_eq!(h.pin_for(&x_tag), Some((a_digest, reinserted)));
}

/// AC21 (publication): the same frozen-predecessor schedule for an explicit
/// import of B under X's key. The publication's Output claim resumes after peers
/// retired and reinserted X: stale, no B approval, no Output move, exact bytes.
#[test]
fn publication_cas_rejects_retire_reinsert_same_digest_lifetime() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "aba-pub-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "x", &a);
    let x_tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&x_tag).status.success());
    let (a_digest, a_revision) = h.pin_for(&x_tag).expect("X holds Boot at A");
    assert_eq!(a_digest, digest_of(&a_child));

    // The publication publishes B and freezes its rendered predecessor A.
    let b = archive_at(&h, "aba-pub-b.tar", "aba-pub-b");
    let mut gate = PinGate::new(h.root.path());
    let loser = PinPeer::spawn(
        h.command(),
        &gate,
        &[
            "image",
            "import",
            "--input",
            b.path.to_str().unwrap(),
            "--tag",
            &x_tag,
        ],
    );
    gate.expect(PinStage::Published).reply(Reply::Continue);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let locked = gate.expect(PinStage::BeforePinLock);

    let peer_state = peer_state("abp");
    let o = h.image(&ArchiveSpec {
        marker: "aba-pub-o".into(),
        ..Default::default()
    });
    let o_tag = format!("{}/images:o", server.host);
    let out = peer_import(&h, peer_state.path(), &o.written.path, &o_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let y = h.image(&ArchiveSpec {
        marker: "aba-pub-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!peer_launch(&h, peer_state.path(), &y_tag).status.success());
    assert!(h.pin_for(&x_tag).is_none(), "X is retired");
    // The registry still serves A under X's tag; a refresh reinserts it unheld.
    // The peer's ambient refresh covers its other holders too, so the imported
    // Output reference is served with the identical content.
    server.image("images", "o", &o);
    let reinserted_out = peer_refresh(&h, peer_state.path(), &x_tag);
    assert!(
        reinserted_out.status.success(),
        "reinsert A: {}{}",
        stdout_of(&reinserted_out),
        stderr(&reinserted_out)
    );
    let (reinserted_digest, reinserted) = h.pin_for(&x_tag).expect("the peer reinserted X");
    assert_eq!(reinserted_digest, a_digest);
    assert!(reinserted > a_revision);
    let peer_bytes = fs::read(h.pins()).unwrap();

    locked.reply(Reply::Continue);
    // The stale decision happens under the lock and before any save: the last
    // stage is `PinLocked`, never `BeforePinSave`.
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    let out = loser.wait();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("stale"),
        "the publication's predecessor no longer exists: {}",
        stderr(&out)
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        peer_bytes,
        "no B approval and no Output move were committed"
    );
    assert!(
        h.pins_value().unwrap()["pins"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["manifest_digest"] != b.manifest_digest.as_str()),
        "the published B is never approved"
    );
    assert_eq!(h.pin_for(&x_tag), Some((a_digest, reinserted)));
}

// ---------------------------------------------------------------------------
// The remaining acceptance-criterion fixtures (AC2, 5, 6, 7, 8, 13, 14, 19, 20).
// ---------------------------------------------------------------------------

/// Run one import with no gate at all: the only committed-bytes baseline that is
/// not derived from the implementation's own proposal.
fn gate_free_import(h: &Harness, archive: &Path, tag: &str) -> Vec<u8> {
    let _ = fs::remove_dir_all(config_dir(h));
    let out = h.import(archive, tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    fs::read(h.pins()).unwrap()
}

/// AC2: `setup` prepares X then Y with Output already resolved to a control O, so
/// X retires; without that Output resolution the same switch must protect X.
#[test]
fn setup_transitions_switch_boot_and_keep_an_unknown_output_control() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let o = archive_at(&h, "ac2-o.tar", "ac2-o");
    let o_tag = format!("{}/images:o", server.host);
    let out = h.import(&o.path, &o_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let x = h.image(&ArchiveSpec {
        marker: "ac2-x".into(),
        ..Default::default()
    });
    let x_tag = format!("{}/images:x", server.host);
    server.image("images", "x", &x);
    let y = h.image(&ArchiveSpec {
        marker: "ac2-y".into(),
        ..Default::default()
    });
    let y_tag = format!("{}/images:y", server.host);
    server.image("images", "y", &y);

    let setup = |reference: &str| {
        let mut command = h.command();
        command.args(["setup", "--image", reference, "--no-verify"]);
        bounded(command)
    };
    let first = setup(&x_tag);
    assert_eq!(
        h.record_in(&h.project, &x_tag).unwrap()["roles"],
        "boot",
        "{}",
        stderr(&first)
    );
    let second = setup(&y_tag);
    assert_eq!(
        h.record_in(&h.project, &y_tag).unwrap()["roles"],
        "boot",
        "{}",
        stderr(&second)
    );
    assert!(
        h.pin_for(&x_tag).is_none(),
        "X retires: Boot moved and Output was resolved elsewhere"
    );
    assert_eq!(h.record_in(&h.project, &o_tag).unwrap()["roles"], "output");

    // The control: the same switch order with Output unresolved must keep X, and
    // both references are in a fresh project so the first scope starts clean.
    let control = h.project_at("ac2-control");
    let control_state = h.root.path().join("ac2-state");
    fs::create_dir_all(&control_state).unwrap();
    let setup_in = |reference: &str| {
        let mut command = h.command_in(&control, &control_state);
        command.args(["setup", "--image", reference, "--no-verify"]);
        bounded(command)
    };
    let out = setup_in(&x_tag);
    assert_eq!(
        out.status.code(),
        Some(0),
        "setup records before it returns: {}",
        stderr(&out)
    );
    let switched = setup_in(&y_tag);
    let control_record = h
        .record_in(&control, &x_tag)
        .expect("?Output protects the displaced X");
    assert!(
        control_record.get("roles").is_none(),
        "X holds no role but is retained: {control_record}"
    );
    assert_eq!(
        h.record_in(&control, &y_tag).unwrap()["roles"],
        "boot",
        "{}",
        stderr(&switched)
    );
    assert_eq!(
        h.pins_value().unwrap()["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scope| scope["project"] == project_id(&control).as_str())
            .unwrap()["resolved"],
        "boot",
        "the control scope resolves Boot only"
    );
}

/// AC5: with Boot held by a distinct B, build X → import Y → build Z retires each
/// displaced output; B and the defaults are untouched; an archive alias gets no
/// role.
#[test]
fn build_and_import_share_one_output_after_scope_resolution() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let b = h.image(&ArchiveSpec {
        marker: "ac5-b".into(),
        ..Default::default()
    });
    let b_tag = format!("{}/images:b", server.host);
    let b_child = server.image("images", "b", &b);
    assert!(!h.launch(&b_tag).status.success());
    assert_eq!(h.pin_in(&h.project, &b_tag).unwrap().0, digest_of(&b_child));
    let b_record = h.record_in(&h.project, &b_tag).unwrap();

    let outputs = |h: &Harness| -> Vec<(String, String)> {
        h.pins_value().unwrap()["pins"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| record["project"] == project_id(&h.project).as_str())
            .filter_map(|record| {
                record.get("roles").map(|roles| {
                    (
                        record["reference"].as_str().unwrap().to_owned(),
                        roles.as_str().unwrap().to_owned(),
                    )
                })
            })
            .collect()
    };

    let x_archive = h.image(&ArchiveSpec {
        marker: "ac5-x".into(),
        ..Default::default()
    });
    let x_tag = format!("{}/images:x", server.host);
    let built = h.build(&x_archive.written.path, &x_tag);
    assert_eq!(built.status.code(), Some(0), "{}", stderr(&built));
    assert_eq!(h.record_in(&h.project, &x_tag).unwrap()["roles"], "output");

    let y = archive_at(&h, "ac5-y.tar", "ac5-y");
    let y_tag = format!("{}/images:y", server.host);
    let imported = h.import(&y.path, &y_tag);
    assert_eq!(imported.status.code(), Some(0), "{}", stderr(&imported));
    assert!(
        h.pin_for(&x_tag).is_none(),
        "the displaced sole output X retires"
    );
    assert_eq!(h.record_in(&h.project, &y_tag).unwrap()["roles"], "output");

    let z_archive = h.image(&ArchiveSpec {
        marker: "ac5-z".into(),
        ..Default::default()
    });
    let z_tag = format!("{}/images:z", server.host);
    let built = h.build(&z_archive.written.path, &z_tag);
    assert_eq!(built.status.code(), Some(0), "{}", stderr(&built));
    assert!(
        h.pin_for(&y_tag).is_none(),
        "the displaced output Y retires: each one is a sole output"
    );
    assert_eq!(h.record_in(&h.project, &z_tag).unwrap()["roles"], "output");
    // Boot and the defaults are untouched by publications.
    assert_eq!(h.record_in(&h.project, &b_tag).unwrap(), b_record);
    assert!(
        h.default_record_in(&h.project).is_none(),
        "an explicit build/import establishes no project default"
    );
    // An archive-carried name gets no role.
    assert_eq!(
        outputs(&h)
            .into_iter()
            .filter(|(_, roles)| roles != "none")
            .collect::<Vec<_>>()
            .len(),
        2,
        "one Boot holder and one Output holder"
    );
}

/// AC6: an equal-content, role-only save fault (content unchanged, only Output
/// moves) preserves the exact old active set and sequence.
#[test]
fn equal_content_role_only_save_fault_preserves_the_active_set() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    // The same content reachable two ways: a registry image and its own archive.
    let spec = ArchiveSpec {
        marker: "ac6".into(),
        ..Default::default()
    };
    let image = h.image(&spec);
    let digest = image.written.manifest_digest.clone();
    let x_tag = format!("{}/images:x", server.host);
    let y_tag = format!("{}/images:y", server.host);
    // X holds Output at that digest.
    let out = h.import(&image.written.path, &x_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(h.pin_for(&x_tag).unwrap().0, digest);
    // X's own reference is served with the identical content, so the ambient
    // seed refresh below also resolves X unchanged instead of failing on an
    // archive-only reference.
    server.image("images", "x", &image);
    // Y is approved at the same content but holds no role (refresh claims none).
    server.image("images", "y", &image);
    assert!(h.refresh_as_ambient(&y_tag).status.success());
    assert_eq!(h.pin_for(&y_tag).unwrap().0, digest);
    assert!(
        h.record_in(&h.project, &y_tag)
            .unwrap()
            .get("roles")
            .is_none()
    );

    let before = fs::read(h.pins()).unwrap();
    let sequence = h.pins_value().unwrap()["sequence"].as_u64();
    // Re-importing the identical content under Y needs a save *only* because the
    // Output role moves: the approval content and token do not change.
    let mut gate = PinGate::new(h.root.path());
    let peer = PinPeer::spawn(
        h.command(),
        &gate,
        &[
            "image",
            "import",
            "--input",
            image.written.path.to_str().unwrap(),
            "--tag",
            &y_tag,
        ],
    );
    gate.expect(PinStage::Published).reply(Reply::Continue);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinLock).reply(Reply::Continue);
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinSave)
        .reply(Reply::FailBeforeSave);
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("approval was not updated"),
        "a precommit publication failure keeps its context: {}",
        stderr(&out)
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        before,
        "roles, resolution and sequence are unchanged"
    );
    assert_eq!(h.pins_value().unwrap()["sequence"].as_u64(), sequence);
    assert_eq!(h.record_in(&h.project, &x_tag).unwrap()["roles"], "output");
    assert!(
        h.record_in(&h.project, &y_tag)
            .unwrap()
            .get("roles")
            .is_none()
    );
}

/// AC7 (cold C): a retired X re-resolved from a cleared owned cache requests its
/// mutable source, never the retired child, and approves the new content C.
#[test]
fn retired_return_resolves_current_source_from_cold_cache() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let o = archive_at(&h, "ac7c-o.tar", "ac7c-o");
    let o_tag = format!("{}/images:o", server.host);
    assert_eq!(h.import(&o.path, &o_tag).status.code(), Some(0));
    let a = h.image(&ArchiveSpec {
        marker: "ac7c-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "x", &a);
    let x_tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&x_tag).status.success());
    let (a_digest, a_revision) = h.pin_for(&x_tag).unwrap();
    // Retire X: Boot moves to Y while Output is resolved.
    let y = h.image(&ArchiveSpec {
        marker: "ac7c-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!h.launch(&y_tag).status.success());
    assert!(h.pin_for(&x_tag).is_none(), "X is absent before the return");

    // The tag now serves C, and only this fixture's cache is cleared: the return
    // must resolve the source, not the retired child.
    let c = h.image(&ArchiveSpec {
        marker: "ac7c-c".into(),
        ..Default::default()
    });
    let c_child = server.image("images", "x", &c);
    fs::remove_dir_all(h.cache()).unwrap();
    let before = server.count();
    let sequence = h.pins_value().unwrap()["sequence"].as_u64().unwrap();
    let back = h.launch(&x_tag);
    assert!(!back.status.success());
    assert_eq!(
        sdk_image(&back),
        c_child,
        "the return boots the new content C"
    );
    assert!(
        !stderr(&back).contains("old: "),
        "a fresh pin renders no old -> new replacement: {}",
        stderr(&back)
    );
    let since = &server.requests()[before..];
    assert!(
        since
            .iter()
            .any(|(_, path)| path == "/v2/images/manifests/x"),
        "the source is resolved: {since:?}"
    );
    assert!(
        !since
            .iter()
            .any(|(_, path)| path == &format!("/v2/images/manifests/{}", digest_of(&a_child))),
        "the retired child is never re-resolved: {since:?}"
    );
    let (digest, revision) = h
        .pin_for(&x_tag)
        .expect("the return approves fresh authority");
    assert_eq!(digest, digest_of(&c_child));
    assert_ne!(digest, a_digest);
    assert_eq!(
        revision,
        sequence + 1,
        "a fresh global allocation, not a restored token"
    );
    assert_ne!(revision, a_revision);
}

/// AC7 (same A): a retired X whose cached content is unchanged is approved again
/// under a fresh global allocation — the old approval is not restored, but the
/// digest may legitimately be the same.
#[test]
fn retired_return_can_approve_the_same_cached_digest() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let o = archive_at(&h, "ac7a-o.tar", "ac7a-o");
    let o_tag = format!("{}/images:o", server.host);
    assert_eq!(h.import(&o.path, &o_tag).status.code(), Some(0));
    let a = h.image(&ArchiveSpec {
        marker: "ac7a-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "x", &a);
    let x_tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&x_tag).status.success());
    let (a_digest, a_revision) = h.pin_for(&x_tag).unwrap();
    let a_record = h.record_in(&h.project, &x_tag).unwrap();
    let y = h.image(&ArchiveSpec {
        marker: "ac7a-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!h.launch(&y_tag).status.success());
    assert!(h.pin_for(&x_tag).is_none(), "X is absent before the return");
    // The registry serves the same A again.
    // The content is still cached, and the registry now serves *nothing* for this
    // reference: a return that needed the network would fail.
    server.remove("/v2/images/manifests/x");
    server.remove(&format!("/v2/images/manifests/{}", digest_of(&a_child)));
    let before = server.count();
    let sequence = h.pins_value().unwrap()["sequence"].as_u64().unwrap();
    let back = h.launch(&x_tag);
    assert!(!back.status.success(), "the fake runtime cannot boot");
    assert_eq!(
        sdk_image(&back),
        a_child,
        "the cached content comes back without the registry"
    );
    assert_eq!(
        server.count(),
        before,
        "offline: no registry request at all"
    );
    assert!(
        !stderr(&back).contains("old: "),
        "a fresh pin renders no old -> new replacement: {}",
        stderr(&back)
    );
    let (digest, revision) = h.pin_for(&x_tag).expect("fresh authority, not a restore");
    assert_eq!(digest, a_digest, "the digest may be unchanged (R8)");
    assert_eq!(
        revision,
        sequence + 1,
        "a reapproval draws the next global allocation"
    );
    assert_ne!(revision, a_revision);
    let record = h.record_in(&h.project, &x_tag).unwrap();
    assert_ne!(record, a_record, "the old approval is not restored");
    assert_eq!(record["roles"], "boot");
}

/// AC8: a record retained only by its unresolved Output survives a tag move and a
/// cache loss: warm offline use consumes A, and a cold return requests the
/// approved child A, never the mutable tag.
#[test]
fn retained_child_is_used_after_tag_move_and_cache_loss() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "ac8-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "x", &a);
    let a_digest = digest_of(&a_child);
    let x_tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&x_tag).status.success());
    // Boot moves away while Output is unresolved: X is retained, holding nothing.
    let y = h.image(&ArchiveSpec {
        marker: "ac8-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!h.launch(&y_tag).status.success());
    let retained = h
        .record_in(&h.project, &x_tag)
        .expect("?Output protects the record");
    assert!(retained.get("roles").is_none());
    assert_eq!(retained["manifest_digest"], a_digest);

    // The tag moves to B and only the owned cache is cleared.
    let b = h.image(&ArchiveSpec {
        marker: "ac8-b".into(),
        ..Default::default()
    });
    let b_child = server.image("images", "x", &b);
    fs::remove_dir_all(h.cache()).unwrap();
    let before = server.count();
    let again = h.launch(&x_tag);
    assert!(!again.status.success());
    assert_eq!(
        sdk_image(&again),
        a_child,
        "the approved child A is requested"
    );
    assert_ne!(sdk_image(&again), b_child);
    let since = &server.requests()[before..];
    assert!(
        since
            .iter()
            .any(|(_, path)| path == &format!("/v2/images/manifests/{a_digest}")),
        "the approved digest is requested: {since:?}"
    );
    assert!(
        !since
            .iter()
            .any(|(_, path)| path == "/v2/images/manifests/x"),
        "the mutable tag is never requested: {since:?}"
    );
    assert_eq!(
        h.record_in(&h.project, &x_tag).unwrap()["manifest_digest"],
        a_digest,
        "no replacement approval is minted for a tag move"
    );
    // A warm offline use also still consumes A.
    let offline = h.launch(&x_tag);
    assert!(!offline.status.success());
    assert_eq!(sdk_image(&offline), a_child);
}

/// AC13: the first warm claim of a legacy record writes role/scope/sequence and
/// recovers the pending journal in that same save — recovery never happens on an
/// observation or a complete no-op.
#[test]
fn first_warm_claim_writes_roles_and_recovers_the_journal() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "ac13-a".into(),
        ..Default::default()
    });
    let child = server.image("images", "ac13", &a);
    let tag = format!("{}/images:ac13", server.host);
    assert!(!h.launch(&tag).status.success());

    // Literal 0.7.49 pin shape with an S1 journal: the host record holds the
    // *proposed* bytes, and recovery must restore `previous`.
    let mut store = h.pins_value().unwrap();
    for record in store["pins"].as_array_mut().unwrap() {
        record.as_object_mut().unwrap().remove("roles");
        record["revision"] = serde_json::json!(7);
    }
    store.as_object_mut().unwrap().remove("scopes");
    store.as_object_mut().unwrap().remove("sequence");
    let previous = serde_json::json!({"version": 1, "image": child}).to_string();
    let proposed = serde_json::json!({
        "version": 1,
        "image": format!("{}/images@sha256:{}", server.host, "c".repeat(64))
    })
    .to_string();
    store["pending_default"] = serde_json::json!({
        "previous": previous,
        "proposed": proposed
    });
    seed_store(&h, &serde_json::to_vec(&store).unwrap());
    let host_record = h.home.join(".config/agent-vm/default-image.json");
    fs::write(&host_record, &proposed).unwrap();

    let out = h.launch(&tag);
    assert!(!out.status.success(), "the fake runtime cannot boot");
    assert_eq!(sdk_image(&out), child);
    let claimed = read_json(&h.pins());
    assert_eq!(claimed["pins"][0]["roles"], "boot");
    assert_eq!(claimed["pins"][0]["revision"], 7);
    assert_eq!(claimed["scopes"][0]["resolved"], "boot");
    // R9: clearing the journal is itself a pin save, so it allocates 8 and the
    // claim that follows allocates 9.
    assert_eq!(claimed["sequence"], serde_json::json!(9));
    assert!(
        claimed["pending_default"].is_null(),
        "the journal was cleared"
    );
    assert_eq!(
        fs::read_to_string(&host_record).unwrap(),
        previous,
        "recovery restored the previous host record"
    );
}

/// AC14: `image show` and `doctor` read every new store state, write nothing and
/// leak no reference.
#[test]
fn show_and_doctor_read_every_new_state_without_writing() {
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);
    // The shared file helpers, so this row and the #609 presentation rows build
    // their stores the same way.
    let platform = host_platform_json();
    let pin = |reference: &str, digest: &str, roles: Option<&str>| {
        pin_json(&project, reference, &platform, digest, 1, roles)
    };
    let scope = |resolved: &str| scope_json(&project, &platform, resolved);
    let a = digest('a');
    let b = digest('b');
    // Partial resolution, fully resolved, protected no-role, and a known-inactive
    // refresh record.
    let states = [
        (
            "partial",
            vec![pin("example.com/x:tag", &a, Some("boot"))],
            vec![scope("boot")],
        ),
        (
            "resolved",
            vec![
                pin("example.com/x:tag", &a, Some("boot")),
                pin("example.com/o:tag", &b, Some("output")),
            ],
            vec![scope("boot-and-output")],
        ),
        (
            "protected-no-role",
            vec![
                pin("example.com/k:tag", &b, Some("boot")),
                pin("example.com/x:tag", &a, None),
            ],
            vec![scope("boot")],
        ),
        (
            "known-inactive-refresh",
            vec![
                pin("example.com/x:tag", &a, Some("boot")),
                pin("example.com/o:tag", &b, Some("output")),
                pin("example.com/v:tag", &b, None),
            ],
            vec![scope("boot-and-output")],
        ),
    ];
    for (name, pins, scopes) in states {
        let store = serde_json::json!({
            "version": 2,
            "pins": pins,
            "pending_default": null,
            "scopes": scopes,
            "sequence": 1,
        });
        let bytes = serde_json::to_vec(&store).unwrap();
        seed_store(&h, &bytes);
        let before = store_snapshot(&h);
        assert_eq!(before.0.as_deref(), Some(bytes.as_slice()));
        for verb in [vec!["image", "show"], vec!["doctor"]] {
            let mut command = h.command();
            command.args(&verb);
            let out = bounded(command);
            assert!(out.status.success(), "{name} {verb:?}: {}", stderr(&out));
            assert_eq!(
                store_snapshot(&h),
                before,
                "{name} {verb:?} wrote the store or its coordination file"
            );
            assert!(
                !stdout_of(&out).contains("example.com") && !stderr(&out).contains("example.com"),
                "{name} {verb:?} leaked a reference: {}{}",
                stdout_of(&out),
                stderr(&out)
            );
        }
    }
}

/// AC19: a literal old-v2 last-boot record is claimed as Output only, displaced,
/// and then still supplies its approved child after the tag moves and the owned
/// cache is cleared.
#[test]
fn legacy_boot_survives_output_then_child_acquisition() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "ac19-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "x", &a);
    let a_digest = digest_of(&a_child);
    let x_tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&x_tag).status.success());
    // Literal old shape: no roles/scopes/sequence, revision 7.
    let mut store = h.pins_value().unwrap();
    for record in store["pins"].as_array_mut().unwrap() {
        record.as_object_mut().unwrap().remove("roles");
        record["revision"] = serde_json::json!(7);
    }
    store.as_object_mut().unwrap().remove("scopes");
    store.as_object_mut().unwrap().remove("sequence");
    seed_store(&h, &serde_json::to_vec(&store).unwrap());
    let old_record = read_json(&h.pins())["pins"][0].clone();

    // An unchanged build/import of X is an Output claim only: Boot stays unknown.
    let out = h.import(&a.written.path, &x_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let claimed = read_json(&h.pins());
    assert_eq!(claimed["pins"][0]["roles"], "output");
    assert_eq!(claimed["pins"][0]["revision"], 7);
    assert_eq!(claimed["scopes"][0]["resolved"], "output");
    // A different output displaces the slot; ?Boot keeps X.
    let y = archive_at(&h, "ac19-y.tar", "ac19-y");
    let y_tag = format!("{}/images:y", server.host);
    assert_eq!(h.import(&y.path, &y_tag).status.code(), Some(0));
    let displaced = read_json(&h.pins());
    let mut expected = old_record.clone();
    expected["roles"] = serde_json::json!("output");
    let x_record = displaced["pins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["reference"] == x_tag)
        .expect("X survives: Boot is unknown");
    assert_eq!(x_record["manifest_digest"], old_record["manifest_digest"]);
    assert_eq!(x_record["revision"], 7);
    assert!(
        x_record.get("roles").is_none(),
        "the Output role moved away"
    );

    // Move the tag to B and clear only the owned cache: the return requests the
    // approved child A, never the tag.
    let b = h.image(&ArchiveSpec {
        marker: "ac19-b".into(),
        ..Default::default()
    });
    server.image("images", "x", &b);
    fs::remove_dir_all(h.cache()).unwrap();
    let before = server.count();
    let back = h.launch(&x_tag);
    assert!(!back.status.success());
    assert_eq!(
        sdk_image(&back),
        a_child,
        "the SDK gets the approved child A"
    );
    let since = &server.requests()[before..];
    assert!(
        since
            .iter()
            .any(|(_, path)| path == &format!("/v2/images/manifests/{a_digest}")),
        "the approved digest is requested: {since:?}"
    );
    assert!(
        !since
            .iter()
            .any(|(_, path)| path == "/v2/images/manifests/x"),
        "the moved tag is never requested: {since:?}"
    );
    assert_eq!(
        h.pin_for(&x_tag).unwrap().0,
        a_digest,
        "no replacement approval is minted"
    );
    assert!(!stdout_of(&back).contains("old:"));
}

/// AC20: the symmetric literal old-v2 last-output record is claimed as Boot only,
/// displaced, and still supplies its approved child after a tag move.
#[test]
fn legacy_output_survives_boot_then_child_acquisition() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "ac20-a".into(),
        ..Default::default()
    });
    let a_child = server.image("images", "x", &a);
    let a_digest = digest_of(&a_child);
    let x_tag = format!("{}/images:x", server.host);
    assert!(!h.launch(&x_tag).status.success());
    let mut store = h.pins_value().unwrap();
    for record in store["pins"].as_array_mut().unwrap() {
        record.as_object_mut().unwrap().remove("roles");
        record["revision"] = serde_json::json!(7);
    }
    store.as_object_mut().unwrap().remove("scopes");
    store.as_object_mut().unwrap().remove("sequence");
    seed_store(&h, &serde_json::to_vec(&store).unwrap());

    // A successful launch/setup of X is a Boot claim only: Output stays unknown,
    // so no build/import may pre-resolve it.
    assert!(!h.launch(&x_tag).status.success());
    let claimed = read_json(&h.pins());
    assert_eq!(claimed["pins"][0]["roles"], "boot");
    assert_eq!(claimed["pins"][0]["revision"], 7);
    assert_eq!(claimed["scopes"][0]["resolved"], "boot");
    assert_eq!(
        h.pins_value().unwrap()["pins"].as_array().unwrap().len(),
        1,
        "no Output claim ran"
    );
    // A different Boot selection displaces it; ?Output keeps X.
    let y = h.image(&ArchiveSpec {
        marker: "ac20-y".into(),
        ..Default::default()
    });
    server.image("images", "y", &y);
    let y_tag = format!("{}/images:y", server.host);
    assert!(!h.launch(&y_tag).status.success());
    let record = h.record_in(&h.project, &x_tag).expect("?Output protects X");
    assert!(record.get("roles").is_none());
    assert_eq!(record["manifest_digest"], a_digest);
    assert_eq!(record["revision"], 7);

    let b = h.image(&ArchiveSpec {
        marker: "ac20-b".into(),
        ..Default::default()
    });
    server.image("images", "x", &b);
    fs::remove_dir_all(h.cache()).unwrap();
    let before = server.count();
    let back = h.launch(&x_tag);
    assert!(!back.status.success());
    assert_eq!(sdk_image(&back), a_child);
    let since = &server.requests()[before..];
    assert!(
        since
            .iter()
            .any(|(_, path)| path == &format!("/v2/images/manifests/{a_digest}")),
        "the approved digest is requested: {since:?}"
    );
    assert!(
        !since
            .iter()
            .any(|(_, path)| path == "/v2/images/manifests/x"),
        "the moved tag is never requested: {since:?}"
    );
}

/// AC18: killing the publication before and after the atomic rename leaves the
/// old and the new authority respectively, and a killed process is never claimed
/// to have produced an exit status.
#[test]
fn publication_kill_before_and_after_commit_has_expected_state() {
    let h = Harness::new(Mode::LaunchSeam);
    let b = archive_at(&h, "kill-b.tar", "kill-b");
    let a = archive_at(&h, "kill-a.tar", "kill-a");
    let tag = "example.com/team/kill:dev";
    // Old authority: an earlier publication of the other content under the same
    // result reference.
    let out = h.import(&b.path, tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let old = fs::read(h.pins()).unwrap();
    assert_eq!(h.pin_for(tag).unwrap().0, b.manifest_digest);

    let import = |gate: &PinGate| {
        PinPeer::spawn(
            h.command(),
            gate,
            &[
                "image",
                "import",
                "--input",
                a.path.to_str().unwrap(),
                "--tag",
                tag,
            ],
        )
    };
    // Before the rename: the child is blocked at the save, so the old authority
    // is what survives its death.
    let mut gate = PinGate::new(h.root.path());
    let peer = import(&gate);
    gate.expect(PinStage::Published).reply(Reply::Continue);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinLock).reply(Reply::Continue);
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    let blocked = gate.expect(PinStage::BeforePinSave);
    let killed = peer.kill_and_collect();
    drop(blocked);
    assert!(
        killed.status.code().is_none(),
        "a killed process has no exit status: {killed:?}"
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        old,
        "before the rename the old authority stays"
    );

    // The same operation run to completion defines the new authority.
    let out = h.import(&a.path, tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let new = fs::read(h.pins()).unwrap();
    assert_eq!(h.pin_for(tag).unwrap().0, a.manifest_digest);
    assert_ne!(new, old);

    // After the rename: the child is blocked at the commit checkpoint, i.e. the
    // rename already happened, and its death leaves exactly those bytes.
    seed_store(&h, &old);
    let mut gate = PinGate::new(h.root.path());
    let peer = import(&gate);
    gate.expect(PinStage::Published).reply(Reply::Continue);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinLock).reply(Reply::Continue);
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    gate.expect(PinStage::BeforePinSave).reply(Reply::Continue);
    let blocked = gate.expect(PinStage::PinCommitted);
    let killed = peer.kill_and_collect();
    drop(blocked);
    assert!(
        killed.status.code().is_none(),
        "a killed process has no exit status: {killed:?}"
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        new,
        "after the rename the committed authority stays"
    );
}

/// AC16: a launch build approves nothing, so it leaves an existing approval — and
/// a damaged store — byte-for-byte unchanged, and it reaches the SDK either way.
#[test]
fn a_launch_build_leaves_existing_or_corrupt_authority_bytes_unchanged() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "ac16-a".into(),
        ..Default::default()
    });
    server.image("images", "ac16", &a);
    let tag = format!("{}/images:ac16", server.host);
    assert!(!h.launch(&tag).status.success());
    let authority = fs::read(h.pins()).unwrap();
    assert_eq!(h.record_in(&h.project, &tag).unwrap()["roles"], "boot");
    fs::write(h.project.join("Dockerfile"), "FROM scratch\n").unwrap();
    let archive = archive_at(&h, "ac16-build.tar", "ac16-build");

    let build = || {
        let mut command = h.command();
        command.env("FAKE_DOCKER_ARCHIVE", &archive.path).args([
            "--dockerfile",
            "Dockerfile",
            "--",
            "true",
        ]);
        bounded(command)
    };
    let built = build();
    assert!(
        stderr(&built).contains("[debug] sandbox config JSON:"),
        "the launch build reached the SDK: {}",
        stderr(&built)
    );
    assert!(
        !stderr(&built).contains("image pin authority"),
        "a launch build never reads the approval store: {}",
        stderr(&built)
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        authority,
        "existing roles, resolution and sequence are untouched"
    );

    // A damaged store must not be read, repaired or rewritten either.
    fs::write(h.pins(), b"not-json\n").unwrap();
    let built = build();
    assert!(
        stderr(&built).contains("[debug] sandbox config JSON:"),
        "a damaged store does not stop a launch build: {}",
        stderr(&built)
    );
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        b"not-json\n",
        "a launch build neither repairs nor rewrites a damaged store"
    );
}

/// AC11a through the compiled CLI: at the 4096-pin bound, a publication that
/// cannot retire the Boot holder is refused as full — never damage — and the
/// old authority stays byte-identical. The store-level row proves the claim
/// plan; this one proves the command boundary a user actually sees.
#[test]
fn publication_at_the_pin_count_bound_fails_closed() {
    let h = Harness::new(Mode::LaunchSeam);
    let x = archive_at(&h, "bound-x.tar", "bound-x");
    let y = archive_at(&h, "bound-y.tar", "bound-y");
    let x_tag = "example.com/team/bound:x";
    let y_tag = "example.com/team/bound:y";
    let project = project_id(&h.project);
    let platform = serde_json::json!({
        "os": "linux",
        "architecture": image_archive::host_arch(),
        "variant": null,
    });
    let mut pins = vec![serde_json::json!({
        "project": project,
        "reference": x_tag,
        "platform": platform,
        "manifest_digest": x.manifest_digest,
        "revision": 1,
        "roles": "boot-and-output",
    })];
    for index in 0..4095u32 {
        pins.push(serde_json::json!({
            "project": format!("{index:064x}"),
            "reference": format!("example.com/foreign{index}:tag"),
            "platform": platform,
            "manifest_digest": format!("sha256:{}", "b".repeat(64)),
            "revision": 1,
        }));
    }
    let store = serde_json::json!({
        "version": 2,
        "pins": pins,
        "pending_default": null,
        "scopes": [{"project": project, "platform": platform, "resolved": "boot-and-output"}],
        "sequence": 1,
    });
    seed_store(&h, &serde_json::to_vec(&store).unwrap());
    assert_eq!(
        h.pins_value().unwrap()["pins"].as_array().unwrap().len(),
        4096
    );
    let before = fs::read(h.pins()).unwrap();

    let out = h.import(&y.path, y_tag);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("maximum number of approvals"),
        "a full store is reported as full: {}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("damaged"), "{}", stderr(&out));
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        before,
        "a refused publication commits not one byte"
    );
    assert!(h.pin_for(y_tag).is_none(), "no Y record was inserted");
    assert_eq!(
        h.pins_value().unwrap()["pins"].as_array().unwrap().len(),
        4096
    );
}

// ---------------------------------------------------------------------------
// S4 (#543): refresh the invocation's in-use references (ADR-0068 D10).
// ---------------------------------------------------------------------------

/// How many times the registry was asked for the manifest spelled `name` (a tag
/// or a digest), so "one source resolution per target" is measured rather than
/// inferred.
fn manifest_requests(server: &Server, from: usize, name: &str) -> usize {
    manifests_requested_since(server, from)
        .iter()
        .filter(|reference| reference.as_str() == name)
        .count()
}

/// The `roles` value of one record, or `None` when it holds none.
fn roles_of(h: &Harness, project: &Path, reference: &str) -> Option<String> {
    h.record_in(project, reference)
        .and_then(|record| record.get("roles").cloned())
        .map(|roles| roles.as_str().unwrap_or_default().to_owned())
}

/// One refresh's result rows and summary, without the adoption notice (each row
/// that must see the notice asserts it directly).
fn rows_of(out: &Output) -> Vec<String> {
    stdout_of(out)
        .lines()
        .filter(|line| !line.contains("now uses the host's default boot image"))
        .map(str::to_owned)
        .collect()
}

/// The literal, value-free nonmember refusal this command must print.
const NOT_A_MEMBER: &str = "`agent-vm image refresh --image REF` targets only references currently in use by this project on the host platform; the requested reference is not in that set. To acquire and approve a new boot reference, run `agent-vm setup --image REF --no-verify`; `image build` and `image import` approve their own output references. Nothing was acquired or approved.";

/// AC1: a bare refresh moves the recorded Boot holder, reports the unchanged
/// Output holder, resolves each source once, and neither creates a sandbox nor
/// runs Docker. Every role, scope and default is preserved.
#[test]
fn bare_refresh_reports_moving_boot_and_unchanged_output() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let boot_tag = format!("{}/images:ac1boot", server.host);
    let boot_a = server.image("images", "ac1boot", &a);
    assert!(!h.launch(&boot_tag).status.success(), "the create fails");
    assert_eq!(roles_of(&h, &h.project, &boot_tag).as_deref(), Some("boot"));

    let o = h.image(&ArchiveSpec {
        marker: "ac1-output".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac1output", server.host);
    let output_o = server.image("images", "ac1output", &o);
    let out = h.import(&o.written.path, &output_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        roles_of(&h, &h.project, &output_tag).as_deref(),
        Some("output")
    );
    let output_record = h.record_in(&h.project, &output_tag).unwrap();

    // Both sources move upstream; both are served again.
    let b = h.image(&ArchiveSpec {
        marker: "ac1-boot-b".into(),
        ..Default::default()
    });
    let boot_b = server.image("images", "ac1boot", &b);
    assert_ne!(boot_a, boot_b);
    let creates = create_invocations(&h);
    let scope_records = h.pins_value().unwrap()["scopes"].clone();
    let requests_before = server.count();
    // The Docker probe is armed for the refresh: the fake records a `buildx
    // build` in this marker file, and the calibration below proves it does.
    let marker = h.root.path().join("ac1-docker-ran");
    let _ = fs::remove_file(&marker);
    assert!(!marker.exists(), "the marker starts absent");
    let mut refresh_command = h.command();
    refresh_command
        .env("FAKE_DOCKER_MARKER", &marker)
        .env("AGENT_VM_IMAGE_TAG", &boot_tag)
        .args(["image", "refresh"]);
    let refresh = bounded(refresh_command);
    assert!(!marker.exists(), "a refresh never runs Docker");
    assert_eq!(refresh.status.code(), Some(0), "{}", stderr(&refresh));
    let text = stdout_of(&refresh);

    // Exactly two rows in worklist order: the ambient operation, then the
    // Output holder by canonical reference.
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert!(
        lines[0].starts_with(&format!("==> refresh [1/2] {boot_tag} (linux/")),
        "{text}"
    );
    assert!(
        lines[0].contains(&format!(
            "changed {} -> {}; default=unchanged",
            digest_of(&boot_a),
            digest_of(&boot_b)
        )),
        "{text}"
    );
    assert!(
        lines[1].starts_with("==> refresh [2/2] the latest output image (linux/"),
        "{text}"
    );
    assert!(
        lines[1].contains(&format!(
            "unchanged {}; default=unchanged",
            digest_of(&output_o)
        )),
        "{text}"
    );
    assert_eq!(lines[2], "==> image refresh: 2 succeeded, 0 failed");

    // The approvals are exactly what the rows say.
    assert_eq!(
        h.pin_in(&h.project, &boot_tag).map(|(digest, _)| digest),
        Some(digest_of(&boot_b))
    );
    assert_eq!(h.record_in(&h.project, &output_tag), Some(output_record));
    assert_eq!(
        roles_of(&h, &h.project, &boot_tag).as_deref(),
        Some("boot"),
        "refresh claims no role"
    );
    assert_eq!(
        h.pins_value().unwrap()["scopes"].clone(),
        scope_records,
        "role knowledge is untouched"
    );
    assert!(
        h.default_record_in(&h.project).is_none(),
        "the explicit tiers establish no project default"
    );
    assert!(h.host_record().is_none(), "and write no host record");

    // One resolution of each source; the unchanged holder re-downloads no layer.
    assert_eq!(manifest_requests(&server, requests_before, "ac1boot"), 1);
    assert_eq!(manifest_requests(&server, requests_before, "ac1output"), 1);
    let blob_requests: Vec<_> = server.requests()[requests_before..]
        .iter()
        .filter(|(_, path)| path.contains("/blobs/"))
        .cloned()
        .collect();
    assert!(
        blob_requests
            .iter()
            .all(|(_, path)| !path.contains(&o.written.layer_digest)),
        "the unchanged Output holder must not be re-downloaded: {blob_requests:?}"
    );
    assert!(
        server.count() > requests_before,
        "the refresh must really have talked to the registry"
    );
    assert_eq!(
        create_invocations(&h),
        creates,
        "a refresh never creates a sandbox: {}",
        h.msb_invocations()
    );
    // Calibrate the probe: a real build with the same marker must record its
    // Docker invocation, so the refresh's silence above is evidence.
    let build_archive = h.image(&ArchiveSpec {
        marker: "ac1-docker-build".into(),
        ..Default::default()
    });
    let build_tag = format!("{}/images:ac1docker", server.host);
    let mut build = h.command();
    build
        .env("FAKE_DOCKER_ARCHIVE", &build_archive.written.path)
        .env("FAKE_DOCKER_MARKER", &marker)
        .args(["image", "build", "--tag", &build_tag]);
    let built = bounded(build);
    assert_eq!(built.status.code(), Some(0), "{}", stderr(&built));
    assert!(
        marker.exists(),
        "the Docker probe must observe a real build invocation"
    );
}

/// AC2: bare refresh includes an ambient selection that has never been prepared
/// since the upgrade, refreshes a different recorded Boot and Output holder, and
/// excludes a historical unheld approval. A project with no record at all is the
/// first-use control.
#[test]
fn bare_refresh_includes_a_selection_never_prepared_since_upgrade() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let c = h.image(&ArchiveSpec {
        marker: "ac2-c".into(),
        ..Default::default()
    });
    let c_tag = format!("{}/images:ac2c", server.host);
    let c_child = server.image("images", "ac2c", &c);
    let b = h.image(&ArchiveSpec {
        marker: "ac2-b".into(),
        ..Default::default()
    });
    let b_tag = format!("{}/images:ac2b", server.host);
    server.image("images", "ac2b", &b);
    assert!(!h.launch(&b_tag).status.success());
    let o = h.image(&ArchiveSpec {
        marker: "ac2-o".into(),
        ..Default::default()
    });
    let o_tag = format!("{}/images:ac2o", server.host);
    server.image("images", "ac2o", &o);
    let imported = h.import(&o.written.path, &o_tag);
    assert_eq!(imported.status.code(), Some(0), "{}", stderr(&imported));
    // A historical approval for U that no live role holds.
    let u = h.image(&ArchiveSpec {
        marker: "ac2-u".into(),
        ..Default::default()
    });
    let u_tag = format!("{}/images:ac2u", server.host);
    server.image("images", "ac2u", &u);
    h.approve_ambient_fixture(&u_tag);
    assert_eq!(roles_of(&h, &h.project, &u_tag), None, "U holds no role");
    let u_record = h.record_in(&h.project, &u_tag).unwrap();

    let before = server.count();
    let scopes_before = h.pins_value().unwrap()["scopes"].clone();
    let refresh = h.refresh_as_ambient(&c_tag);
    assert_eq!(refresh.status.code(), Some(0), "{}", stderr(&refresh));
    let text = stdout_of(&refresh);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "{text}");
    assert!(
        lines[0].starts_with(&format!("==> refresh [1/3] {c_tag} (linux/"))
            && lines[0].contains("approved none ->"),
        "the never-prepared ambient selection comes first: {text}"
    );
    assert!(
        lines[0].contains("default=unchanged"),
        "an env selection establishes nothing: {text}"
    );
    assert!(
        lines[1].starts_with("==> refresh [2/3] the recorded boot image (linux/"),
        "{text}"
    );
    assert!(
        lines[2].starts_with("==> refresh [3/3] the latest output image (linux/"),
        "{text}"
    );
    assert_eq!(lines[3], "==> image refresh: 3 succeeded, 0 failed");
    // C is approved as a new, unheld record; the historical U is untouched.
    assert_eq!(
        h.pin_in(&h.project, &c_tag).map(|(digest, _)| digest),
        Some(digest_of(&c_child))
    );
    assert_eq!(roles_of(&h, &h.project, &c_tag), None);
    assert_eq!(h.record_in(&h.project, &u_tag), Some(u_record));
    assert_eq!(
        manifest_requests(&server, before, "ac2u"),
        0,
        "U is not refreshed"
    );
    assert_eq!(
        h.pins_value().unwrap()["scopes"].clone(),
        scopes_before,
        "refresh resolves no scope and claims no role"
    );
    // First-use control: no record at all, one ambient selection, one target.
    let fresh = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let only = fresh.image(&ArchiveSpec {
        marker: "ac2-only".into(),
        ..Default::default()
    });
    let only_tag = format!("{}/images:ac2only", server.host);
    let child = server.image("images", "ac2only", &only);
    let refresh = fresh.refresh_as_ambient(&only_tag);
    assert_eq!(refresh.status.code(), Some(0), "{}", stderr(&refresh));
    let text = stdout_of(&refresh);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.contains("==> refresh [1/1]"), "{text}");
    assert_eq!(
        fresh.pin_in(&fresh.project, &only_tag).map(|(d, _)| d),
        Some(digest_of(&child))
    );
    assert_eq!(roles_of(&fresh, &fresh.project, &only_tag), None);
}

/// AC3: only this project's exact host platform (and variant) qualifies; a
/// foreign project, a foreign architecture and a foreign variant are untouched,
/// and the registry sees only the planned reference.
#[test]
fn bare_refresh_leaves_foreign_authority_unchanged() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let tag = format!("{}/images:ac3", server.host);
    let child_a = server.image("images", "ac3", &a);
    let p2 = h.project_at("ac3-other-project");
    let peer = peer_state("ac3");
    assert!(
        h.refresh_as_ambient_in(&p2, peer.path(), &tag)
            .status
            .success(),
        "the other project approves the same tag"
    );
    let foreign_project_record = h.record_in(&p2, &tag).unwrap();
    h.approve_ambient_fixture(&tag);
    let mine = h.record_in(&h.project, &tag).unwrap();
    assert_eq!(mine["manifest_digest"], digest_of(&child_a));

    // Two literal foreign-platform records for this same project: another
    // architecture, and a variant of this architecture.
    let arch = if image_archive::host_arch() == "arm64" {
        "amd64"
    } else {
        "arm64"
    };
    let mut store: serde_json::Value =
        serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    let mut foreign_platform = mine.clone();
    foreign_platform["platform"]["architecture"] = arch.into();
    foreign_platform["manifest_digest"] = format!("sha256:{}", "c".repeat(64)).into();
    foreign_platform["revision"] = 1.into();
    let mut foreign_variant = mine.clone();
    foreign_variant["platform"]["variant"] = "v8".into();
    foreign_variant["manifest_digest"] = format!("sha256:{}", "d".repeat(64)).into();
    foreign_variant["revision"] = 1.into();
    store["pins"]
        .as_array_mut()
        .unwrap()
        .extend([foreign_platform.clone(), foreign_variant.clone()]);
    fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
    let before: serde_json::Value = serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();

    // Move the tag and refresh in this project only.
    let b = h.image(&ArchiveSpec {
        marker: "ac3-b".into(),
        ..Default::default()
    });
    let child_b = server.image("images", "ac3", &b);
    let requests_before = server.count();
    let refresh = h.refresh_as_ambient(&tag);
    assert_eq!(refresh.status.code(), Some(0), "{}", stderr(&refresh));

    let after: serde_json::Value = serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    let record_for = |value: &serde_json::Value, project: &str, digest: &str| {
        value["pins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["project"] == project && record["manifest_digest"] == digest)
            .cloned()
    };
    // The invoking project's host-platform record moved.
    assert_eq!(
        h.pin_in(&h.project, &tag).map(|(digest, _)| digest),
        Some(digest_of(&child_b))
    );
    // The foreign project, architecture and variant records are byte-identical.
    for record in [&foreign_project_record, &foreign_platform, &foreign_variant] {
        let project = record["project"].as_str().unwrap();
        let digest = record["manifest_digest"].as_str().unwrap();
        assert_eq!(
            record_for(&before, project, digest),
            record_for(&after, project, digest),
            "a foreign record changed: {record}"
        );
    }
    assert_eq!(
        before["scopes"], after["scopes"],
        "no scope was resolved or rewritten"
    );
    assert_eq!(before["defaults"], after["defaults"], "no default moved");
    // The registry saw the planned reference only.
    let requested = manifests_requested_since(&server, requests_before);
    assert_eq!(requested, vec!["ac3".to_owned()], "{requested:?}");
}

/// AC4: `--image O` refreshes only the in-use Output reference. The ambient
/// selection, the configuration, defaults, roles, the host record and
/// `image show` are all unchanged, and a reference that is both Boot and Output
/// holder is one target.
#[test]
fn targeted_refresh_updates_only_the_in_use_target() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "ac4-boot".into(),
        ..Default::default()
    });
    let boot_tag = format!("{}/images:ac4boot", server.host);
    server.image("images", "ac4boot", &a);
    // A configured (not default-tier) Boot selection.
    let dir = h.project.join(".agent-vm");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.toml"), format!("image = {boot_tag:?}\n")).unwrap();
    assert!(!h.launch_default().status.success(), "the create fails");
    assert_eq!(roles_of(&h, &h.project, &boot_tag).as_deref(), Some("boot"));

    let o = h.image(&ArchiveSpec {
        marker: "ac4-output".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac4output", server.host);
    let output_o = server.image("images", "ac4output", &o);
    let out = h.import(&o.written.path, &output_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let config_bytes = fs::read(dir.join("config.toml")).unwrap();
    let boot_record = h.record_in(&h.project, &boot_tag).unwrap();
    let show_before = {
        let mut cmd = h.command();
        cmd.args(["image", "show"]);
        bounded(cmd)
    };
    assert!(show_before.status.success());

    // Both sources move upstream.
    let b = h.image(&ArchiveSpec {
        marker: "ac4-boot-b".into(),
        ..Default::default()
    });
    server.image("images", "ac4boot", &b);
    let o1 = h.image(&ArchiveSpec {
        marker: "ac4-output-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac4output", &o1);
    assert_ne!(output_o, output_o1);

    let requests_before = server.count();
    let refresh = h.refresh(&output_tag);
    assert_eq!(refresh.status.code(), Some(0), "{}", stderr(&refresh));
    let text = stdout_of(&refresh);
    assert!(text.contains("==> refresh [1/1]"), "{text}");
    assert!(
        text.contains(&format!(
            "changed {} -> {}; default=unchanged",
            digest_of(&output_o),
            digest_of(&output_o1)
        )),
        "{text}"
    );
    // Only the targeted reference was resolved.
    assert_eq!(
        manifests_requested_since(&server, requests_before),
        vec!["ac4output".to_owned()]
    );
    // The ambient Boot holder, its record, the config and `image show` are
    // exactly as they were; no host record or default appeared.
    assert_eq!(
        h.record_in(&h.project, &boot_tag),
        Some(boot_record),
        "the Boot holder is not a target of a filter"
    );
    assert_eq!(fs::read(dir.join("config.toml")).unwrap(), config_bytes);
    assert!(h.host_record().is_none());
    assert!(h.default_record_in(&h.project).is_none());
    let show_after = {
        let mut cmd = h.command();
        cmd.args(["image", "show"]);
        bounded(cmd)
    };
    assert_eq!(stdout_of(&show_after), stdout_of(&show_before));
    assert_eq!(
        roles_of(&h, &h.project, &output_tag).as_deref(),
        Some("output")
    );

    // A reference that is both Boot and Output holder is one target.
    let shared = h.image(&ArchiveSpec {
        marker: "ac4-shared".into(),
        ..Default::default()
    });
    let shared_tag = format!("{}/images:ac4shared", server.host);
    let shared_a = server.image("images", "ac4shared", &shared);
    assert!(!h.launch(&shared_tag).status.success());
    let reimport = h.import(&shared.written.path, &shared_tag);
    assert_eq!(reimport.status.code(), Some(0), "{}", stderr(&reimport));
    assert_eq!(
        roles_of(&h, &h.project, &shared_tag).as_deref(),
        Some("boot-and-output")
    );
    let shared_b = h.image(&ArchiveSpec {
        marker: "ac4-shared-b".into(),
        ..Default::default()
    });
    let shared_child_b = server.image("images", "ac4shared", &shared_b);
    let requests_before = server.count();
    let refresh = h.refresh(&shared_tag);
    assert_eq!(refresh.status.code(), Some(0), "{}", stderr(&refresh));
    let text = stdout_of(&refresh);
    assert!(
        text.contains("==> refresh [1/1]") && !text.contains("[2/1]"),
        "a shared key is one target: {text}"
    );
    assert_eq!(
        manifest_requests(&server, requests_before, "ac4shared"),
        1,
        "{text}"
    );
    assert_eq!(
        h.pin_in(&h.project, &shared_tag).map(|(digest, _)| digest),
        Some(digest_of(&shared_child_b))
    );
    assert_eq!(
        roles_of(&h, &h.project, &shared_tag).as_deref(),
        Some("boot-and-output"),
        "refresh preserves both held roles"
    );
    assert!(server.count() > requests_before);
    let _ = shared_a;
}

/// AC5: a `--image` value that is not in use is refused with the exact
/// value-free text, exit 1, no registry request and no authority write. A
/// never-used reference, a retained unheld one and a foreign-project one are all
/// nonmembers; a held one is the positive control.
#[test]
fn targeted_refresh_refuses_nonmembers_without_acquiring() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fresh = h.image(&ArchiveSpec {
        marker: "ac5-fresh".into(),
        ..Default::default()
    });
    let fresh_tag = format!("{}/images:ac5fresh", server.host);
    server.image("images", "ac5fresh", &fresh);

    // (1) Never used anywhere: nothing can prove it is in use.
    let out = h.refresh(&fresh_tag);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stderr(&out).trim(), format!("Error: {NOT_A_MEMBER}"));
    assert!(!h.pins().exists(), "a refused refresh writes nothing");

    // (2) Retained but unheld: retention alone is not membership.
    h.approve_ambient_fixture(&fresh_tag);
    let retained = fs::read(h.pins()).unwrap();
    let requests_before = server.count();
    let out = h.refresh(&fresh_tag);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stderr(&out).trim(), format!("Error: {NOT_A_MEMBER}"));
    assert_eq!(fs::read(h.pins()).unwrap(), retained, "no authority write");
    assert_eq!(server.count(), requests_before, "no registry request");

    // (3) A reference that only another project holds: a **different** fresh
    // reference with no record here at all, genuinely claimed as Boot there.
    let foreign = h.image(&ArchiveSpec {
        marker: "ac5-foreign".into(),
        ..Default::default()
    });
    let foreign_tag = format!("{}/images:ac5foreign", server.host);
    server.image("images", "ac5foreign", &foreign);
    let p2 = h.project_at("ac5-other-project");
    let peer = peer_state("ac5");
    let mut setup = h.command_in(&p2, peer.path());
    setup.args(["setup", "--image", &foreign_tag, "--no-verify"]);
    let setup = bounded(setup);
    assert_eq!(setup.status.code(), Some(0), "{}", stderr(&setup));
    assert_eq!(
        roles_of(&h, &p2, &foreign_tag).as_deref(),
        Some("boot"),
        "the other project really holds it"
    );
    assert!(
        h.record_in(&h.project, &foreign_tag).is_none(),
        "this project has no record for it at all"
    );
    let before = fs::read(h.pins()).unwrap();
    let requests_before = server.count();
    let out = h.refresh(&foreign_tag);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stderr(&out).trim(), format!("Error: {NOT_A_MEMBER}"));
    assert_eq!(fs::read(h.pins()).unwrap(), before);
    assert_eq!(server.count(), requests_before);
    assert_eq!(
        roles_of(&h, &p2, &foreign_tag).as_deref(),
        Some("boot"),
        "the other project's holder is untouched"
    );

    // (4) Positive control: a recorded holder is a member.
    let o = h.image(&ArchiveSpec {
        marker: "ac5-output".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac5output", server.host);
    let child = server.image("images", "ac5output", &o);
    let imported = h.import(&o.written.path, &output_tag);
    assert_eq!(imported.status.code(), Some(0), "{}", stderr(&imported));
    let out = h.refresh(&output_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        h.pin_in(&h.project, &output_tag).map(|(digest, _)| digest),
        Some(digest_of(&child))
    );
}

/// AC6: `AGENT_VM_IMAGE_TAG` chooses the ambient boot reference and never
/// restricts the worklist; `--image` narrows it; an empty value falls through to
/// the configured tier; the same target through both inputs is one operation.
#[test]
fn refresh_env_selects_ambient_without_filtering_the_worklist() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    // Configured (not default-tier) Boot selection B.
    let b = h.image(&ArchiveSpec {
        marker: "ac6-b".into(),
        ..Default::default()
    });
    let boot_tag = format!("{}/images:ac6boot", server.host);
    let boot_b = server.image("images", "ac6boot", &b);
    let dir = h.project.join(".agent-vm");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.toml"), format!("image = {boot_tag:?}\n")).unwrap();
    assert!(!h.launch_default().status.success());
    assert_eq!(roles_of(&h, &h.project, &boot_tag).as_deref(), Some("boot"));
    // Output holder O.
    let o = h.image(&ArchiveSpec {
        marker: "ac6-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac6output", server.host);
    server.image("images", "ac6output", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    // Env-selected C.
    let c = h.image(&ArchiveSpec {
        marker: "ac6-c".into(),
        ..Default::default()
    });
    let env_tag = format!("{}/images:ac6env", server.host);
    server.image("images", "ac6env", &c);

    // (1) Env C is the ambient operation; the recorded Boot B and Output O are
    // still refreshed.
    let requests_before = server.count();
    let refresh = h.refresh_as_ambient(&env_tag);
    assert_eq!(refresh.status.code(), Some(0), "{}", stderr(&refresh));
    let text = stdout_of(&refresh);
    assert_eq!(text.lines().count(), 4, "{text}");
    assert!(
        text.lines()
            .next()
            .unwrap()
            .contains(&format!("[1/3] {env_tag}")),
        "the env-selected reference is the ambient operation: {text}"
    );
    assert_eq!(manifest_requests(&server, requests_before, "ac6env"), 1);
    assert_eq!(manifest_requests(&server, requests_before, "ac6boot"), 1);
    assert_eq!(manifest_requests(&server, requests_before, "ac6output"), 1);

    // (2) A typed output filter narrows to one target even though env selects C;
    // the env selection does not mask or expand the filter.
    let o1 = h.image(&ArchiveSpec {
        marker: "ac6-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac6output", &o1);
    let mut command = h.command();
    command
        .env("AGENT_VM_IMAGE_TAG", &env_tag)
        .args(["image", "refresh", "--image", &output_tag]);
    let filtered = bounded(command);
    assert_eq!(filtered.status.code(), Some(0), "{}", stderr(&filtered));
    let text = stdout_of(&filtered);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.contains("==> refresh [1/1]"), "{text}");
    assert!(
        text.contains(&digest_of(&output_o1)),
        "the typed filter refreshed its own target: {text}"
    );

    // (3) An empty env value is unset, so the configured tier selects B.
    let b1 = h.image(&ArchiveSpec {
        marker: "ac6-b1".into(),
        ..Default::default()
    });
    let boot_b1 = server.image("images", "ac6boot", &b1);
    let requests_before = server.count();
    let mut command = h.command();
    command
        .env("AGENT_VM_IMAGE_TAG", "")
        .args(["image", "refresh"]);
    let empty = bounded(command);
    assert_eq!(empty.status.code(), Some(0), "{}", stderr(&empty));
    let text = stdout_of(&empty);
    assert!(
        text.lines()
            .next()
            .unwrap()
            .starts_with(&format!("==> refresh [1/2] {boot_tag} (linux/")),
        "an empty env falls through to the configured selection: {text}"
    );
    assert!(
        text.contains(&digest_of(&boot_b1)),
        "the configured tier's moved content was refreshed: {text}"
    );
    assert_eq!(manifest_requests(&server, requests_before, "ac6env"), 0);

    // (4) The same reference through env and `--image` is one operation.
    let requests_before = server.count();
    let mut command = h.command();
    command
        .env("AGENT_VM_IMAGE_TAG", &env_tag)
        .args(["image", "refresh", "--image", &env_tag]);
    let same = bounded(command);
    assert_eq!(same.status.code(), Some(0), "{}", stderr(&same));
    let text = stdout_of(&same);
    assert!(text.contains("==> refresh [1/1]"), "{text}");
    assert_eq!(manifest_requests(&server, requests_before, "ac6env"), 1);
    let _ = (boot_b, o);
}

/// Two independent references with their own recorded roles, both served by the
/// registry: the fixture the partial-progress and contention rows order against.
struct TwoReferences {
    boot_tag: String,
    boot_child: String,
    output_tag: String,
    output_child: String,
}

impl TwoReferences {
    /// Resolve Output first (so a later Boot claim may retire), then Boot: the
    /// result is one Boot holder and one Output holder in this project, with
    /// both sources served from the registry.
    fn create(h: &Harness, server: &Server, prefix: &str) -> Self {
        let o = h.image(&ArchiveSpec {
            marker: format!("{prefix}-output"),
            ..Default::default()
        });
        let output_tag = format!("{}/images:{prefix}out", server.host);
        let output_child = server.image("images", &format!("{prefix}out"), &o);
        let imported = h.import(&o.written.path, &output_tag);
        assert_eq!(imported.status.code(), Some(0), "{}", stderr(&imported));

        let b = h.image(&ArchiveSpec {
            marker: format!("{prefix}-boot"),
            ..Default::default()
        });
        let boot_tag = format!("{}/images:{prefix}boot", server.host);
        let boot_child = server.image("images", &format!("{prefix}boot"), &b);
        assert!(!h.launch(&boot_tag).status.success());
        assert_eq!(roles_of(h, &h.project, &boot_tag).as_deref(), Some("boot"));
        assert_eq!(
            roles_of(h, &h.project, &output_tag).as_deref(),
            Some("output")
        );
        Self {
            boot_tag,
            boot_child,
            output_tag,
            output_child,
        }
    }

    /// Move both sources upstream and return their new children.
    fn move_both(&self, server: &Server, prefix: &str) -> (String, String) {
        let boot = self.move_boot(server, prefix);
        let output = self.move_output(server, prefix);
        (boot, output)
    }

    fn move_boot(&self, server: &Server, prefix: &str) -> String {
        let b1 = Image::from_archive(
            &std::env::temp_dir().join(format!("{prefix}-boot-b1.tar")),
            &ArchiveSpec {
                marker: format!("{prefix}-boot-b1"),
                ..Default::default()
            },
        );
        let boot_b1 = server.image("images", &format!("{prefix}boot"), &b1);
        assert_ne!(boot_b1, self.boot_child);
        boot_b1
    }

    fn move_output(&self, server: &Server, prefix: &str) -> String {
        let o1 = Image::from_archive(
            &std::env::temp_dir().join(format!("{prefix}-output-o1.tar")),
            &ArchiveSpec {
                marker: format!("{prefix}-output-o1"),
                ..Default::default()
            },
        );
        let output_o1 = server.image("images", &format!("{prefix}out"), &o1);
        assert_ne!(output_o1, self.output_child);
        output_o1
    }
}

/// AC7 schedule A: a failed first target does not suppress a later commit. The
/// first target's save is refused, then the second target really commits; only
/// that commit's bytes survive and the failed record is untouched.
#[test]
fn refresh_partial_progress_survives_failure_in_either_order() {
    // ---- schedule A: fail target 1, then commit target 2 ----
    {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let fixture = TwoReferences::create(&h, &server, "ac7a");
        let (boot_b1, output_o1) = fixture.move_both(&server, "ac7a");
        let boot_record = h.record_in(&h.project, &fixture.boot_tag).unwrap();
        let config_dir_before = fs::read(config_dir(&h).join("image-pins.json")).unwrap();
        let host_before = fs::read(h.home.join(".config/agent-vm/default-image.json")).ok();
        let requests_before = server.count();

        let mut gate = PinGate::new(h.root.path());
        let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
        gate.attach(&mut command);
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the gated refresh");
        // Target 1 (Boot): fail its save, never committing it.
        for stage in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
        ] {
            expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
        }
        expect_stage(&mut gate, PinStage::BeforePinSave, &mut child).reply(Reply::FailBeforeSave);
        // Target 2 (Output) then runs: the next stage must be its candidate, so a
        // committed target 1 would be a scheduling failure, not a silent pass.
        for stage in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
            PinStage::BeforePinSave,
        ] {
            expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
        }
        let committed = expect_stage(&mut gate, PinStage::PinCommitted, &mut child);
        let snapshot = fs::read(h.pins()).unwrap();
        committed.reply(Reply::Continue);
        drop(gate);
        let out = child.wait_with_output().expect("collect the refresh");

        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        let text = stdout_of(&out);
        assert!(
            text.lines()
                .next()
                .unwrap()
                .starts_with(&format!("==> refresh [1/2] {} (linux/", fixture.boot_tag))
                && text.lines().next().unwrap().contains("failed"),
            "{text}"
        );
        assert!(
            text.lines()
                .nth(1)
                .unwrap()
                .starts_with("==> refresh [2/2] the latest output image (linux/")
                && text.lines().nth(1).unwrap().contains(&format!(
                    "changed {} -> {}; default=unchanged",
                    digest_of(&fixture.output_child),
                    digest_of(&output_o1)
                )),
            "{text}"
        );
        assert_eq!(
            text.lines().nth(2).unwrap(),
            "==> image refresh: 1 succeeded, 1 failed"
        );
        // Only target 2's commit survives, byte for byte.
        assert_eq!(fs::read(h.pins()).unwrap(), snapshot);
        assert_eq!(
            h.record_in(&h.project, &fixture.boot_tag),
            Some(boot_record),
            "the failed target's record and roles are unchanged"
        );
        assert_eq!(
            h.pin_in(&h.project, &fixture.output_tag)
                .map(|(digest, _)| digest),
            Some(digest_of(&output_o1)),
            "the successful target really committed"
        );
        assert!(h.host_record().is_none());
        assert_eq!(
            fs::read(config_dir(&h).join("image-pins.json")).unwrap(),
            snapshot,
            "final authority equals the captured postcommit snapshot"
        );
        assert!(
            config_dir_before.len() != snapshot.len() || config_dir_before != snapshot,
            "the fixture must really have changed something"
        );
        assert_eq!(host_before, None);
        assert_eq!(manifest_requests(&server, requests_before, "ac7aboot"), 1);
        assert_eq!(manifest_requests(&server, requests_before, "ac7aout"), 1);
        let _ = boot_b1;
    }

    // ---- schedule B: commit target 1, then fail target 2 ----
    {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let fixture = TwoReferences::create(&h, &server, "ac7b");
        let (boot_b1, _output_o1) = fixture.move_both(&server, "ac7b");
        let output_record = h.record_in(&h.project, &fixture.output_tag).unwrap();
        let requests_before = server.count();

        let mut gate = PinGate::new(h.root.path());
        let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
        gate.attach(&mut command);
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the gated refresh");
        for stage in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
            PinStage::BeforePinSave,
        ] {
            expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
        }
        let committed = expect_stage(&mut gate, PinStage::PinCommitted, &mut child);
        let boot_snapshot = fs::read(h.pins()).unwrap();
        assert_eq!(
            h.pin_in(&h.project, &fixture.boot_tag)
                .map(|(digest, _)| digest),
            Some(digest_of(&boot_b1)),
            "the first target committed before its checkpoint"
        );
        committed.reply(Reply::Continue);
        // Target 2's save is refused; it must never report a commit.
        for stage in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
        ] {
            expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
        }
        expect_stage(&mut gate, PinStage::BeforePinSave, &mut child).reply(Reply::FailBeforeSave);
        drop(gate);
        let out = child.wait_with_output().expect("collect the refresh");

        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        let text = stdout_of(&out);
        assert!(
            text.lines().next().unwrap().contains(&format!(
                "changed {} -> {}",
                digest_of(&fixture.boot_child),
                digest_of(&boot_b1)
            )),
            "{text}"
        );
        assert!(
            text.lines()
                .nth(1)
                .unwrap()
                .starts_with("==> refresh [2/2] the latest output image (linux/")
                && text.lines().nth(1).unwrap().contains("failed"),
            "{text}"
        );
        assert_eq!(
            text.lines().nth(2).unwrap(),
            "==> image refresh: 1 succeeded, 1 failed"
        );
        // The successful first commit is intact and the failed second target's
        // record is untouched.
        assert_eq!(fs::read(h.pins()).unwrap(), boot_snapshot);
        assert_eq!(
            h.record_in(&h.project, &fixture.output_tag),
            Some(output_record)
        );
        assert!(h.host_record().is_none());
        assert_eq!(manifest_requests(&server, requests_before, "ac7bboot"), 1);
        assert_eq!(manifest_requests(&server, requests_before, "ac7bout"), 1);
    }
}

/// AC8: only the bare ambient default-tier target establishes a project default.
/// A failed ambient target cannot be replaced by a successful Output target, an
/// explicit filter never establishes, and the ADR-0067 D9 recommendation seed may
/// survive its own failed pin save while the project stays unestablished.
#[test]
fn refresh_establishment_belongs_only_to_the_ambient_default_target() {
    // (1) Success: the ambient default acquires and establishes in one save, with
    // the Output holder refreshed independently and the suffix stated.
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let d = h.image(&ArchiveSpec {
        marker: "ac8-default".into(),
        ..Default::default()
    });
    let recommended = server.image("images", "ac8default", &d);
    let o = h.image(&ArchiveSpec {
        marker: "ac8-output".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac8output", server.host);
    server.image("images", "ac8output", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &recommended)
        .args(["image", "refresh"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout_of(&out);
    assert!(
        text.lines().next().unwrap().contains("default=established"),
        "{text}"
    );
    assert!(
        h.default_record_in(&h.project).unwrap()["image"]
            == serde_json::Value::String(recommended.clone()),
        "the default tier established its own default"
    );
    assert_eq!(
        h.pin_in(&h.project, &recommended).map(|(digest, _)| digest),
        Some(digest_of(&recommended))
    );

    // (2) Failure: the ambient default's save is refused while Output succeeds;
    // nothing establishes and the failed default keeps no approval.
    let failed = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let d = failed.image(&ArchiveSpec {
        marker: "ac8-fail".into(),
        ..Default::default()
    });
    let recommended = server.image("images", "ac8fail", &d);
    let o = failed.image(&ArchiveSpec {
        marker: "ac8-fail-output".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac8failout", server.host);
    server.image("images", "ac8failout", &o);
    assert_eq!(
        failed.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let mut gate = PinGate::new(failed.root.path());
    let mut command = failed.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &recommended)
        .args(["image", "refresh"]);
    gate.attach(&mut command);
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforeDefaultSave,
        PinStage::DefaultSaved,
    ] {
        expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
    }
    expect_stage(&mut gate, PinStage::BeforePinSave, &mut child).reply(Reply::FailBeforeSave);
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    assert!(
        text.contains("==> image refresh: 1 succeeded, 1 failed"),
        "{text}"
    );
    assert!(
        failed.default_record_in(&failed.project).is_none(),
        "a successful Output target cannot establish in the default's place: {text}"
    );
    assert!(
        failed.pin_in(&failed.project, &recommended).is_none(),
        "the failed default target kept no approval"
    );
    // D9: the recommendation seed was written before the failed pin save.
    assert_eq!(
        failed.host_record().unwrap()["image"],
        serde_json::Value::String(recommended.clone()),
        "the documented host-first seed survives its own failed pin save"
    );
    assert!(roles_of(&failed, &failed.project, &output_tag).as_deref() == Some("output"));

    // (3) An explicit filter never establishes, even when it equals the ambient
    // default: the `--image` value is refreshed as content only.
    let explicit = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let d = explicit.image(&ArchiveSpec {
        marker: "ac8-explicit".into(),
        ..Default::default()
    });
    let recommended = server.image("images", "ac8explicit", &d);
    let mut command = explicit.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &recommended)
        .args(["image", "refresh", "--image", &recommended]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout_of(&out).contains("default=unchanged"),
        "{}",
        stdout_of(&out)
    );
    assert!(
        explicit.default_record_in(&explicit.project).is_none(),
        "explicit --image, even equal to the default, establishes nothing"
    );
    assert!(explicit.host_record().is_none(), "and seeds no host record");
}

/// Establish this project's default from the initial recommendation without
/// claiming any role, and return the recommended (immutable) child.
fn establish_default_unheld(h: &Harness, server: &Server, prefix: &str) -> String {
    let d = h.image(&ArchiveSpec {
        marker: format!("{prefix}-d"),
        ..Default::default()
    });
    let recommended = server.image("images", &format!("{prefix}d"), &d);
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &recommended)
        .args(["image", "refresh"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(recommended.clone())
    );
    assert_eq!(
        roles_of(h, &h.project, &recommended),
        None,
        "no role claimed"
    );
    recommended
}

/// The digest-spelled manifest route for an immutable child reference.
fn digest_route(child: &str) -> String {
    format!("/v2/images/manifests/{}", digest_of(child))
}

/// AC9: adoption supersedes an unheld project default without acquiring it: H is
/// acquired once, D gets no registry request at all, and the bookmark moves.
#[test]
fn refresh_adoption_supersedes_an_unheld_default_without_acquiring_it() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let default_child = establish_default_unheld(&h, &server, "ac9super");
    let h_image = h.image(&ArchiveSpec {
        marker: "ac9super-h".into(),
        ..Default::default()
    });
    let host_tag = format!("{}/images:ac9superh", server.host);
    let host_child = server.image("images", "ac9superh", &h_image);
    assert!(set_default(&h, &host_tag).status.success());
    assert_eq!(
        h.host_record().unwrap()["image"],
        serde_json::Value::String(host_child.clone())
    );

    // D's registry route disappears: a refresh of D would now fail, so a passing
    // run proves D was not attempted.
    server.remove(&digest_route(&default_child));
    let requests_before = server.count();
    let host_before = fs::read(h.home.join(".config/agent-vm/default-image.json")).unwrap();
    let out = h.refresh_default();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert_eq!(rows.len(), 2, "{text}");
    assert!(
        rows[0].starts_with("==> refresh [1/1] the default boot image (linux/"),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "approved none -> {}; default=adopted {} -> {}",
            digest_of(&host_child),
            digest_of(&default_child),
            digest_of(&host_child)
        )),
        "{text}"
    );
    assert_eq!(rows[1], "==> image refresh: 1 succeeded, 0 failed");
    assert!(
        text.lines().next().unwrap() == "==> this project now uses the host's default boot image",
        "the adoption notice precedes the row: {text}"
    );
    // The bookmark moved, H is unheld, and D was never resolved.
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(host_child.clone())
    );
    assert_eq!(roles_of(&h, &h.project, &host_child), None);
    assert_eq!(
        manifest_requests(&server, requests_before, &digest_of(&default_child)),
        0,
        "unheld D is not re-resolved"
    );
    assert_eq!(
        manifest_requests(&server, requests_before, &digest_of(&host_child)),
        1,
        "H is resolved once"
    );
    assert_eq!(
        fs::read(h.home.join(".config/agent-vm/default-image.json")).unwrap(),
        host_before,
        "adoption never replaces the host record"
    );
}

/// AC9: H is deduplicated with a holder, a held old default is refreshed
/// independently after adoption, and all roles survive.
#[test]
fn refresh_adoption_deduplicates_the_offer_and_preserves_old_holders() {
    // (a) Held D and a different H: Adopt(H) then Content(D).
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let default_child = establish_default_unheld(&h, &server, "ac9held");
    assert!(!h.launch(&default_child).status.success());
    assert_eq!(
        roles_of(&h, &h.project, &default_child).as_deref(),
        Some("boot"),
        "D is held"
    );
    let h_image = h.image(&ArchiveSpec {
        marker: "ac9held-h".into(),
        ..Default::default()
    });
    let host_tag = format!("{}/images:ac9heldh", server.host);
    let host_child = server.image("images", "ac9heldh", &h_image);
    assert!(set_default(&h, &host_tag).status.success());
    let scopes_before = h.pins_value().unwrap()["scopes"].clone();
    let requests_before = server.count();

    let out = h.refresh_default();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert_eq!(rows.len(), 3, "{text}");
    assert!(
        rows[0].contains(&format!(
            "default=adopted {} -> {}",
            digest_of(&default_child),
            digest_of(&host_child)
        )),
        "{text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the recorded boot image (linux/"),
        "the still-held old default is refreshed independently: {text}"
    );
    assert!(rows[1].contains("unchanged"), "{text}");
    assert_eq!(
        manifest_requests(&server, requests_before, &digest_of(&host_child)),
        1
    );
    assert_eq!(
        manifest_requests(&server, requests_before, &digest_of(&default_child)),
        1
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(host_child.clone())
    );
    assert_eq!(
        roles_of(&h, &h.project, &default_child).as_deref(),
        Some("boot"),
        "the old holder keeps its role"
    );
    assert_eq!(roles_of(&h, &h.project, &host_child), None);
    assert_eq!(h.pins_value().unwrap()["scopes"].clone(), scopes_before);

    // (b) H is already the Boot holder and D is unheld: one Adopt target for H
    // (never a second Content one), plus the independent Output holder.
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let default_child = establish_default_unheld(&h, &server, "ac9dedupe");
    let h_image = h.image(&ArchiveSpec {
        marker: "ac9dedupe-h".into(),
        ..Default::default()
    });
    let host_tag = format!("{}/images:ac9dedupeh", server.host);
    let host_child = server.image("images", "ac9dedupeh", &h_image);
    assert!(set_default(&h, &host_tag).status.success());
    let mut setup_command = h.command();
    // H is the immutable reference the host record names, so the Boot claim must
    // be made for exactly that key (the adoption target's key).
    setup_command.args(["setup", "--image", &host_child, "--no-verify"]);
    let setup = bounded(setup_command);
    assert_eq!(setup.status.code(), Some(0), "{}", stderr(&setup));
    assert_eq!(
        roles_of(&h, &h.project, &host_child).as_deref(),
        Some("boot"),
        "H holds Boot"
    );
    let o = h.image(&ArchiveSpec {
        marker: "ac9dedupe-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac9dedupeo", server.host);
    let output_child = server.image("images", "ac9dedupeo", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );

    let requests_before = server.count();
    let out = h.refresh_default();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert_eq!(rows.len(), 3, "two operations: {text}");
    assert!(
        rows[0].contains("[1/2] the default boot image"),
        "H is the ambient operation: {text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
            && rows[1].contains(&digest_of(&output_child)),
        "{text}"
    );
    // H is acquired once, not once as adoption plus once as holder.
    assert_eq!(
        manifest_requests(&server, requests_before, &digest_of(&host_child)),
        1,
        "{text}"
    );
    assert_eq!(
        roles_of(&h, &h.project, &host_child).as_deref(),
        Some("boot"),
        "H keeps its Boot role"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(host_child.clone())
    );
    assert_eq!(
        roles_of(&h, &h.project, &output_tag).as_deref(),
        Some("output")
    );
    // The Output claim resolved the second slot, so S3's retirement rule removes
    // the now-provably-unused old default; refresh itself never retires.
    assert!(
        h.pin_in(&h.project, &default_child).is_none(),
        "the unheld old default was retired by the Output claim, not by refresh"
    );
}

/// AC9/AC14: a successful adoption is not undone by a later failure on the old
/// default, and exit 1 can therefore accompany a moved project default.
#[test]
fn refresh_adoption_success_survives_held_default_failure() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let default_child = establish_default_unheld(&h, &server, "ac9after");
    assert!(!h.launch(&default_child).status.success());
    assert_eq!(
        roles_of(&h, &h.project, &default_child).as_deref(),
        Some("boot")
    );
    let h_image = h.image(&ArchiveSpec {
        marker: "ac9after-h".into(),
        ..Default::default()
    });
    let host_tag = format!("{}/images:ac9afterh", server.host);
    let host_child = server.image("images", "ac9afterh", &h_image);
    assert!(set_default(&h, &host_tag).status.success());
    let host_before = fs::read(h.home.join(".config/agent-vm/default-image.json")).unwrap();
    // The old default's route now fails, so its own refresh must fail.
    server.deny_manifest(&digest_route(&default_child));

    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    command.args(["image", "refresh"]);
    gate.attach(&mut command);
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    let committed = gate.expect(PinStage::PinCommitted);
    let adoption_snapshot = fs::read(h.pins()).unwrap();
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(host_child.clone()),
        "the adoption committed before its checkpoint"
    );
    committed.reply(Reply::Continue);
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert!(
        rows[0].contains("[1/2] the default boot image")
            && rows[0].contains(&format!(
                "default=adopted {} -> {}",
                digest_of(&default_child),
                digest_of(&host_child)
            )),
        "{text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the recorded boot image (linux/")
            && rows[1].contains("failed"),
        "{text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        adoption_snapshot,
        "the failed old-default target changed nothing"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(host_child.clone()),
        "the project default stays H"
    );
    assert_eq!(
        fs::read(h.home.join(".config/agent-vm/default-image.json")).unwrap(),
        host_before,
        "the host record is untouched"
    );
}

/// AC9/AC14: a failed adoption does not suppress a later, independent success of
/// the still-selected held default, which stays the project default.
#[test]
fn refresh_adoption_failure_allows_held_default_success() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let d = h.image(&ArchiveSpec {
        marker: "ac9fails-d".into(),
        ..Default::default()
    });
    let default_child = server.image("images", "ac9failsd", &d);
    // A default-tier launch establishes D *and* claims its Boot role.
    assert!(!h.launch_on_recommendation(&default_child).status.success());
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(default_child.clone())
    );
    assert_eq!(
        roles_of(&h, &h.project, &default_child).as_deref(),
        Some("boot")
    );
    let h_image = h.image(&ArchiveSpec {
        marker: "ac9fails-h".into(),
        ..Default::default()
    });
    let host_tag = format!("{}/images:ac9failsh", server.host);
    let host_child = server.image("images", "ac9failsh", &h_image);
    assert!(set_default(&h, &host_tag).status.success());

    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    command.args(["image", "refresh"]);
    gate.attach(&mut command);
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    gate.expect(PinStage::BeforePinSave)
        .reply(Reply::FailBeforeSave);
    // D then resolves its own approved child and confirms it unchanged.
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert!(
        rows[0].contains("[1/2] the default boot image") && rows[0].contains("failed"),
        "{text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the recorded boot image (linux/")
            && rows[1].contains(&format!("unchanged {}", digest_of(&default_child))),
        "{text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    assert!(
        h.pin_in(&h.project, &host_child).is_none(),
        "the refused adoption inserted no H approval"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(default_child.clone()),
        "the bookmark is still D"
    );
    assert_eq!(
        roles_of(&h, &h.project, &default_child).as_deref(),
        Some("boot")
    );
}

/// The exact command-level error a malformed host record produces.
fn damaged_host_error(h: &Harness) -> String {
    format!(
        "boot-image selection {} is not a valid version 1 digest record; restore the intended \
         digest record from backup, or deliberately move it aside to reinitialize from the \
         current recommendation",
        h.home.join(".config/agent-vm/default-image.json").display()
    )
}

/// AC9/AC12: with an established default, a malformed host record refuses the
/// whole unfiltered command before any registry request or write, prints no
/// target rows, and a filtered held reference still works.
#[test]
fn unfiltered_refresh_refuses_a_damaged_host_with_established_default() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let d = h.image(&ArchiveSpec {
        marker: "ac12est-d".into(),
        ..Default::default()
    });
    let default_child = server.image("images", "ac12estd", &d);
    assert!(!h.launch_on_recommendation(&default_child).status.success());
    let o = h.image(&ArchiveSpec {
        marker: "ac12est-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac12estout", server.host);
    let output_child = server.image("images", "ac12estout", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let o1 = h.image(&ArchiveSpec {
        marker: "ac12est-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac12estout", &o1);

    let host_path = h.home.join(".config/agent-vm/default-image.json");
    fs::write(&host_path, b"not a digest record\n").unwrap();
    let snapshot = |h: &Harness| {
        (
            fs::read(h.pins()).unwrap(),
            fs::read(h.home.join(".config/agent-vm/default-image.json")).unwrap(),
            fs::read(h.home.join(".config/agent-vm/config.toml")).ok(),
        )
    };
    let before = snapshot(&h);
    let requests_before = server.count();
    let out = h.refresh_default();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        stderr(&out).trim(),
        format!("Error: {}", damaged_host_error(&h))
    );
    assert_eq!(
        stdout_of(&out),
        "",
        "a pre-freeze refusal prints no target rows or summary"
    );
    assert_eq!(
        server.count(),
        requests_before,
        "no registry request at all"
    );
    assert_eq!(snapshot(&h), before, "no authority, host or config write");

    // A filtered held Output needs no host-default read and still refreshes.
    let out = h.refresh(&output_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout_of(&out).contains(&format!(
            "changed {} -> {}",
            digest_of(&output_child),
            digest_of(&output_o1)
        )),
        "{}",
        stdout_of(&out)
    );
    assert_eq!(
        fs::read(&host_path).unwrap(),
        b"not a digest record\n",
        "the filtered refresh left the damaged host record alone"
    );
    let _ = output_child;
}

/// AC9/AC12: with no project default the malformed host record refuses the
/// unfiltered command before a BootImage exists; a filtered held reference still
/// works without a default or host read.
#[test]
fn unfiltered_refresh_refuses_a_damaged_host_without_project_default() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let o = h.image(&ArchiveSpec {
        marker: "ac12unest-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac12unestout", server.host);
    let output_child = server.image("images", "ac12unestout", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let o1 = h.image(&ArchiveSpec {
        marker: "ac12unest-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac12unestout", &o1);
    assert!(h.default_record_in(&h.project).is_none());

    let host_path = h.home.join(".config/agent-vm/default-image.json");
    fs::write(&host_path, b"{ not even json }\n").unwrap();
    let pins_before = fs::read(h.pins()).unwrap();
    let requests_before = server.count();
    let out = h.refresh_default();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        stderr(&out).trim(),
        format!("Error: {}", damaged_host_error(&h))
    );
    assert_eq!(stdout_of(&out), "", "no fabricated ambient target");
    assert_eq!(
        server.count(),
        requests_before,
        "Output is not attempted either"
    );
    assert_eq!(fs::read(h.pins()).unwrap(), pins_before);
    assert!(h.default_record_in(&h.project).is_none());

    let out = h.refresh(&output_tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout_of(&out).contains(&digest_of(&output_o1)),
        "{}",
        stdout_of(&out)
    );
    assert_eq!(fs::read(&host_path).unwrap(), b"{ not even json }\n");
    let _ = output_child;
}

/// AC7/AC9: a post-freeze acquisition failure is an operation row, not a
/// command-level refusal: the independent recorded Output commits, the failing
/// transaction is unchanged, and the status is 1.
#[test]
fn refresh_default_failures_do_not_block_recorded_output() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let d = h.image(&ArchiveSpec {
        marker: "ac7fail-d".into(),
        ..Default::default()
    });
    let default_child = server.image("images", "ac7faild", &d);
    assert!(!h.launch_on_recommendation(&default_child).status.success());
    let o = h.image(&ArchiveSpec {
        marker: "ac7fail-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac7failout", server.host);
    let output_child = server.image("images", "ac7failout", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let o1 = h.image(&ArchiveSpec {
        marker: "ac7fail-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac7failout", &o1);
    let default_record = h.record_in(&h.project, &default_child).unwrap();
    let default_bytes = fs::read(h.pins()).unwrap();

    // The ambient operation's own source becomes unavailable after the freeze.
    server.remove(&digest_route(&default_child));
    let out = h.refresh_default();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    assert_eq!(text.lines().count(), 3, "{text}");
    assert!(
        text.lines()
            .next()
            .unwrap()
            .starts_with("==> refresh [1/2] the default boot image (linux/")
            && text.lines().next().unwrap().contains("failed"),
        "{text}"
    );
    assert!(
        text.lines()
            .nth(1)
            .unwrap()
            .starts_with("==> refresh [2/2] the latest output image (linux/")
            && text.lines().nth(1).unwrap().contains(&format!(
                "changed {} -> {}",
                digest_of(&output_child),
                digest_of(&output_o1)
            )),
        "{text}"
    );
    assert_eq!(
        text.lines().nth(2).unwrap(),
        "==> image refresh: 1 succeeded, 1 failed"
    );
    assert_eq!(
        h.record_in(&h.project, &default_child),
        Some(default_record),
        "the failing operation's approval and roles are unchanged"
    );
    assert_eq!(
        h.pin_in(&h.project, &output_tag).map(|(digest, _)| digest),
        Some(digest_of(&output_o1)),
        "the sibling really committed"
    );
    assert_ne!(fs::read(h.pins()).unwrap(), default_bytes);
    assert!(h.host_record().is_some(), "the host record is unchanged");
}

/// AC10: an observed H that a peer retires before the adoption's save is stale:
/// it is never reinserted, the bookmark does not move, and the unrelated sibling
/// still commits.
#[test]
fn refresh_adoption_rejects_a_retired_observed_host_pin() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let default_child = establish_default_unheld(&h, &server, "ac10ret");
    // H is this project's Boot holder, at its immutable key.
    let h_image = h.image(&ArchiveSpec {
        marker: "ac10ret-h".into(),
        ..Default::default()
    });
    let host_tag = format!("{}/images:ac10reth", server.host);
    let host_child = server.image("images", "ac10reth", &h_image);
    let mut setup = h.command();
    setup.args(["setup", "--image", &host_child, "--no-verify"]);
    assert_eq!(bounded(setup).status.code(), Some(0));
    assert_eq!(
        roles_of(&h, &h.project, &host_child).as_deref(),
        Some("boot")
    );
    // The host bookmark names H, so the ambient operation is an adoption of it.
    assert!(set_default(&h, &host_tag).status.success());
    assert_eq!(
        h.host_record().unwrap()["image"],
        serde_json::Value::String(host_child.clone())
    );
    // O is an unrelated Output holder that will move.
    let o = h.image(&ArchiveSpec {
        marker: "ac10ret-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac10retout", server.host);
    let output_child = server.image("images", "ac10retout", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let o1 = h.image(&ArchiveSpec {
        marker: "ac10ret-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac10retout", &o1);

    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    command.args(["image", "refresh"]);
    gate.attach(&mut command);
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    expect_stage(&mut gate, PinStage::CandidateReady, &mut child).reply(Reply::Continue);
    let before_lock = expect_stage(&mut gate, PinStage::BeforePinLock, &mut child);

    // The peer claims Boot for a new reference R, which retires H (converted to no
    // net change: Output is resolved, so both of H's slots are known-absent).
    let r = h.image(&ArchiveSpec {
        marker: "ac10ret-r".into(),
        ..Default::default()
    });
    let r_tag = format!("{}/images:ac10retr", server.host);
    server.image("images", "ac10retr", &r);
    let mut peer = h.command_in(&h.project, &h.state);
    peer.args(["setup", "--image", &r_tag, "--no-verify"]);
    let peer_out = bounded(peer);
    assert_eq!(peer_out.status.code(), Some(0), "{}", stderr(&peer_out));
    assert!(
        h.pin_in(&h.project, &host_child).is_none(),
        "the peer retired H"
    );
    assert_eq!(roles_of(&h, &h.project, &r_tag).as_deref(), Some("boot"));
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(default_child.clone()),
        "the peer moved no bookmark"
    );
    let peer_bytes = fs::read(h.pins()).unwrap();

    before_lock.reply(Reply::Continue);
    // H vanished: the adoption takes its lock, decides stale, and writes nothing.
    expect_stage(&mut gate, PinStage::PinLocked, &mut child).reply(Reply::Continue);
    // The sibling Output target then runs from its own frozen candidate.
    expect_stage(&mut gate, PinStage::CandidateReady, &mut child).reply(Reply::Continue);
    let sibling_lock = expect_stage(&mut gate, PinStage::BeforePinLock, &mut child);
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        peer_bytes,
        "the stale adoption changed nothing before the sibling ran"
    );
    sibling_lock.reply(Reply::Continue);
    for stage in [
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert!(
        rows[0].contains("[1/2] the default boot image")
            && rows[0].contains("failed")
            && rows[0].contains("image approval is stale; retry the explicit operation"),
        "{text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
            && rows[1].contains(&format!(
                "changed {} -> {}",
                digest_of(&output_child),
                digest_of(&output_o1)
            )),
        "{text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    // H is still absent, the peer's R records survive, and the bookmark is D.
    assert!(
        h.pin_in(&h.project, &host_child).is_none(),
        "no resurrection"
    );
    assert_eq!(roles_of(&h, &h.project, &r_tag).as_deref(), Some("boot"));
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(default_child.clone())
    );
    assert_eq!(
        h.pin_in(&h.project, &output_tag).map(|(digest, _)| digest),
        Some(digest_of(&output_o1))
    );
    assert_eq!(
        h.host_record().unwrap()["image"],
        serde_json::Value::String(host_child.clone()),
        "the host record is never rewritten by adoption"
    );
}

/// AC10: a genuinely absent H is inserted (never treated as a retired one), the
/// bookmark moves in the same save, and an unrelated peer change is preserved.
#[test]
fn refresh_adoption_inserts_a_genuinely_absent_host_pin() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let default_child = establish_default_unheld(&h, &server, "ac10ins");
    let h_image = h.image(&ArchiveSpec {
        marker: "ac10ins-h".into(),
        ..Default::default()
    });
    let host_tag = format!("{}/images:ac10insh", server.host);
    let host_child = server.image("images", "ac10insh", &h_image);
    assert!(set_default(&h, &host_tag).status.success());
    assert!(
        h.pin_in(&h.project, &host_child).is_none(),
        "H was never pinned"
    );
    let o = h.image(&ArchiveSpec {
        marker: "ac10ins-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac10insout", server.host);
    server.image("images", "ac10insout", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let o1 = h.image(&ArchiveSpec {
        marker: "ac10ins-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac10insout", &o1);

    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    command.args(["image", "refresh"]);
    gate.attach(&mut command);
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let before_lock = gate.expect(PinStage::BeforePinLock);

    // A peer changes an unrelated scope: another project sharing this HOME.
    let p2 = h.project_at("ac10ins-other-project");
    let peer = peer_state("ac10ins");
    assert!(
        h.refresh_as_ambient_in(&p2, peer.path(), &host_tag)
            .status
            .success(),
        "the peer approves the same reference for its own project"
    );
    let peer_record = h.record_in(&p2, &host_tag).unwrap();
    assert!(
        h.pin_in(&h.project, &host_child).is_none(),
        "the peer left H absent here"
    );
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(default_child.clone())
    );

    before_lock.reply(Reply::Continue);
    for stage in [
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    // The independent Output target then commits.
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert_eq!(rows.len(), 3, "{text}");
    assert!(
        rows[0].contains(&format!(
            "approved none -> {}; default=adopted {} -> {}",
            digest_of(&host_child),
            digest_of(&default_child),
            digest_of(&host_child)
        )),
        "{text}"
    );
    // H is inserted unheld, the bookmark moved, and the peer's record is intact.
    assert_eq!(
        h.pin_in(&h.project, &host_child).map(|(d, _)| d),
        Some(digest_of(&host_child))
    );
    assert_eq!(roles_of(&h, &h.project, &host_child), None, "H is unheld");
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(host_child.clone())
    );
    assert_eq!(h.record_in(&p2, &host_tag), Some(peer_record));
    assert_eq!(
        h.pin_in(&h.project, &output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );
}

/// AC10: each target freezes its own candidate. Repointing a source again after
/// it was resolved cannot change either approval, and each tag is resolved once.
#[test]
fn multi_refresh_freezes_each_candidate_independently() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac10fr");
    let (boot_b1, output_o1) = fixture.move_both(&server, "ac10fr");
    let requests_before = server.count();

    let mut gate = PinGate::new(h.root.path());
    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    gate.attach(&mut command);
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    // Target 1 has resolved B1 and is still paused there; move the tag to B2
    // **before** releasing it, so the frozen candidate is what commits.
    let first_candidate = expect_stage(&mut gate, PinStage::CandidateReady, &mut child);
    let b2 = h.image(&ArchiveSpec {
        marker: "ac10fr-boot-b2".into(),
        ..Default::default()
    });
    let boot_b2 = server.image("images", "ac10frboot", &b2);
    assert_ne!(boot_b2, boot_b1, "the second movement must differ");
    first_candidate.reply(Reply::Continue);
    for stage in [
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
    }
    // The same for the second target.
    let second_candidate = expect_stage(&mut gate, PinStage::CandidateReady, &mut child);
    let o2 = h.image(&ArchiveSpec {
        marker: "ac10fr-output-o2".into(),
        ..Default::default()
    });
    let output_o2 = server.image("images", "ac10frout", &o2);
    assert_ne!(output_o2, output_o1, "the second movement must differ");
    second_candidate.reply(Reply::Continue);
    for stage in [
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag)
            .map(|(digest, _)| digest),
        Some(digest_of(&boot_b1)),
        "the first resolved child is what commits"
    );
    assert_eq!(
        h.pin_in(&h.project, &fixture.output_tag)
            .map(|(digest, _)| digest),
        Some(digest_of(&output_o1)),
        "the second resolved child is what commits"
    );
    // One mutable-source resolve per target, and none after the candidate froze.
    assert_eq!(manifest_requests(&server, requests_before, "ac10frboot"), 1);
    assert_eq!(manifest_requests(&server, requests_before, "ac10frout"), 1);
}

/// AC10: a stale target does not cancel its siblings. The peer's retire/reinsert
/// of the first key is preserved, the second target commits, and the stale one
/// is never resurrected.
#[test]
fn multi_refresh_stale_target_does_not_cancel_other_targets() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac10st");
    let _boot_b1 = fixture.move_boot(&server, "ac10st");

    let mut gate = PinGate::new(h.root.path());
    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    gate.attach(&mut command);
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    expect_stage(&mut gate, PinStage::CandidateReady, &mut child).reply(Reply::Continue);
    let first_lock = expect_stage(&mut gate, PinStage::BeforePinLock, &mut child);

    // The peer claims Boot for R (retiring B) and reinserts B unheld: the frozen
    // predecessor no longer exists, and a fresh token proves it is a new lifetime.
    let r = h.image(&ArchiveSpec {
        marker: "ac10st-r".into(),
        ..Default::default()
    });
    let r_tag = format!("{}/images:ac10str", server.host);
    server.image("images", "ac10str", &r);
    let mut peer = h.command_in(&h.project, &h.state);
    peer.args(["setup", "--image", &r_tag, "--no-verify"]);
    assert_eq!(bounded(peer).status.code(), Some(0));
    assert!(h.pin_in(&h.project, &fixture.boot_tag).is_none());
    // The reinsertion carries different content again, so the frozen candidate is
    // not the live one: that is what makes this target stale rather than an
    // equal-live reconciliation.
    let b2 = h.image(&ArchiveSpec {
        marker: "ac10st-boot-b2".into(),
        ..Default::default()
    });
    server.image("images", "ac10stboot", &b2);
    let reinsert = h.refresh_as_ambient_in(&h.project, &h.state, &fixture.boot_tag);
    assert!(
        reinsert.status.success(),
        "the peer reinserts B: {}{}",
        stdout_of(&reinsert),
        stderr(&reinsert)
    );
    let reinserted = h.pin_in(&h.project, &fixture.boot_tag).unwrap();
    // Output moves only now: the peer's own refresh above covered this holder, so
    // moving it earlier would leave this target with nothing to commit.
    let output_o1 = fixture.move_output(&server, "ac10st");
    let peer_bytes = fs::read(h.pins()).unwrap();

    first_lock.reply(Reply::Continue);
    // The stale target takes its lock, decides stale, and writes nothing.
    expect_stage(&mut gate, PinStage::PinLocked, &mut child).reply(Reply::Continue);
    // Target 2 (Output) still runs: its own predecessor is live.
    expect_stage(&mut gate, PinStage::CandidateReady, &mut child).reply(Reply::Continue);
    let second_lock = expect_stage(&mut gate, PinStage::BeforePinLock, &mut child);
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        peer_bytes,
        "the stale first target changed nothing"
    );
    second_lock.reply(Reply::Continue);
    for stage in [
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert!(
        rows[0].contains("[1/2]") && rows[0].contains("failed") && rows[0].contains("stale"),
        "{text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
            && rows[1].contains(&digest_of(&output_o1)),
        "{text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    // The peer's reinserted record survives untouched, and the sibling committed.
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag),
        Some(reinserted),
        "the peer's B record is preserved, not resurrected from the frozen tuple"
    );
    assert_eq!(
        h.pin_in(&h.project, &fixture.output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );
    assert_eq!(roles_of(&h, &h.project, &r_tag).as_deref(), Some("boot"));
}

/// AC11: an immutable source whose content moved is a failed target with an
/// integrity reason — not a skip, not a success, and not an approvable
/// replacement. Its approval and default stay exact while a sibling commits.
#[test]
fn multi_refresh_immutable_integrity_failure_is_not_a_skip() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec {
        marker: "ac11-a".into(),
        ..Default::default()
    });
    server.image("images", "ac11childa", &a);
    // X is an immutable index approved at its resolved host child A.
    let index_pin = server.index("images", "ac11x", a.index.clone());
    let index_digest = digest_of(&index_pin);
    let x_route = format!("/v2/images/manifests/{index_digest}");
    h.approve_ambient_fixture(&index_pin);
    let x_record = h.record_in(&h.project, &index_pin).unwrap();
    let x_digest = x_record["manifest_digest"].as_str().unwrap().to_owned();

    // A sibling Output holder that really moves.
    let o = h.image(&ArchiveSpec {
        marker: "ac11-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac11out", server.host);
    let output_child = server.image("images", "ac11out", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let o1 = h.image(&ArchiveSpec {
        marker: "ac11-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac11out", &o1);

    // The immutable index now resolves to genuinely different host content, while
    // the registry keeps serving it under X's own digest.
    let b = h.image(&ArchiveSpec {
        marker: "ac11-b".into(),
        ..Default::default()
    });
    server.image("images", "ac11childb", &b);
    server.put_with_header(
        &x_route,
        &b.index,
        "application/vnd.oci.image.index.v1+json",
        &index_digest,
    );
    let defaults_before = h.default_record_in(&h.project);
    let host_before = h.host_record();

    let out = h.refresh_as_ambient(&index_pin);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert!(
        rows[0].contains("[1/2]")
            && rows[0].contains("failed")
            && rows[0].contains("Invalid digest"),
        "the immutable movement is an integrity failure, not a skip: {text}"
    );
    assert!(
        !rows[0].contains("unchanged"),
        "an integrity failure is never reported as unchanged: {text}"
    );
    assert!(
        rows[1].contains(&format!(
            "changed {} -> {}",
            digest_of(&output_child),
            digest_of(&output_o1)
        )),
        "the sibling still commits: {text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    // X's authority is exactly as it was.
    let x_after = h.record_in(&h.project, &index_pin).unwrap();
    assert_eq!(x_after, x_record, "the immutable approval is unchanged");
    assert_eq!(
        x_after["manifest_digest"],
        serde_json::Value::String(x_digest)
    );
    assert_eq!(h.default_record_in(&h.project), defaults_before);
    assert_eq!(h.host_record(), host_before);
    assert_eq!(
        h.pin_in(&h.project, &output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );
}

/// AC12: a damaged authority prevents every registry request and every write,
/// for a bare command and a filtered one alike, and prints no success summary.
#[test]
fn refresh_damaged_authority_fails_before_any_registry_request() {
    // Four kinds of damage, each with a readable ambient selection and an
    // apparent Output target available.
    #[derive(Debug)]
    enum Damage {
        BrokenJson,
        ForeignRoleJoin,
        MissingLock,
        UnknownVersion,
    }
    for damage in [
        Damage::BrokenJson,
        Damage::ForeignRoleJoin,
        Damage::MissingLock,
        Damage::UnknownVersion,
    ] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let c = h.image(&ArchiveSpec {
            marker: "ac12ambient".into(),
            ..Default::default()
        });
        let ambient_tag = format!("{}/images:ac12ambient", server.host);
        server.image("images", "ac12ambient", &c);
        let o = h.image(&ArchiveSpec {
            marker: "ac12output".into(),
            ..Default::default()
        });
        let output_tag = format!("{}/images:ac12output", server.host);
        server.image("images", "ac12output", &o);
        assert_eq!(
            h.import(&o.written.path, &output_tag).status.code(),
            Some(0)
        );

        // The four kinds take different decoder paths but share one **generic**
        // damage diagnostic by contract, so the oracle is its exact text rather
        // than a per-kind message (there is no per-kind wording to assert).
        const DAMAGED: &str = "image pin authority at $HOME/.config/agent-vm/image-pins.json is damaged; restore its intended records from backup or deliberately move it aside to reset approvals";
        match damage {
            Damage::BrokenJson => fs::write(h.pins(), b"{ this is not json").unwrap(),
            Damage::ForeignRoleJoin => {
                // A role held with no scope resolution is damage, even when the
                // record belongs to another project.
                let mut store: serde_json::Value =
                    serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
                store["pins"].as_array_mut().unwrap().push(serde_json::json!({
                    "project": project_id(&h.project_at("ac12-foreign")),
                    "reference": "example.com/team/foreign:tag",
                    "platform": {"os": "linux", "architecture": image_archive::host_arch(), "variant": null},
                    "manifest_digest": format!("sha256:{}", "e".repeat(64)),
                    "revision": 1,
                    "roles": "boot"
                }));
                fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
            }
            Damage::MissingLock => {
                fs::remove_file(h.pins().with_extension("lock")).unwrap();
            }
            Damage::UnknownVersion => {
                let mut store: serde_json::Value =
                    serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
                store["version"] = 3.into();
                fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
            }
        }
        let damaged = fs::read(h.pins()).unwrap();
        let requests_before = server.count();

        for (label, command) in [("bare", None), ("filtered", Some(&output_tag))] {
            let mut cmd = h.command();
            cmd.env("AGENT_VM_IMAGE_TAG", &ambient_tag);
            match command {
                None => cmd.args(["image", "refresh"]),
                Some(target) => cmd.args(["image", "refresh", "--image", target]),
            };
            let out = bounded(cmd);
            assert_eq!(out.status.code(), Some(1), "{label}: {}", stderr(&out));
            assert_eq!(
                stderr(&out).trim(),
                format!("Error: {DAMAGED}"),
                "{label}: the {damage:?} damage is refused with the exact generic text"
            );
            assert!(
                !stdout_of(&out).contains("==> image refresh:"),
                "{label}: no summary pretends work happened: {}",
                stdout_of(&out)
            );
            assert_eq!(server.count(), requests_before, "{label}: no request");
            assert_eq!(fs::read(h.pins()).unwrap(), damaged, "{label}: no write");
        }
    }
}

// ---------------------------------------------------------------- pipe control

/// One socket end the test keeps, so a child's sink can be closed at a chosen
/// moment rather than before it starts. A `UnixStream` pair (not a pipe) is the
/// mechanism the existing render-failure rows prove fails a write once the peer
/// is gone.
struct Sink {
    reader: std::os::unix::net::UnixStream,
}

impl Sink {
    /// A fresh pair; the returned `Stdio` is the child's write end.
    fn new() -> (Self, std::process::Stdio) {
        use std::os::fd::OwnedFd;
        let (reader, writer) =
            std::os::unix::net::UnixStream::pair().expect("create the socket pair");
        let writer: OwnedFd = writer.into();
        (Self { reader }, std::process::Stdio::from(writer))
    }

    /// Read whatever is buffered right now, without blocking.
    fn drain(&mut self) -> String {
        use std::io::Read as _;
        self.reader
            .set_nonblocking(true)
            .expect("nonblocking sink read");
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match self.reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => out.extend_from_slice(&buf[..read]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

/// Answer every pin checkpoint with `Continue` until `until` arrives, then hand
/// that paused checkpoint to the test and keep answering the rest.
fn pump_pin_gate(mut gate: PinGate, until: PinStage) -> std::sync::mpsc::Receiver<PinCheckpoint> {
    let (sender, receiver) = std::sync::mpsc::channel();
    // Detached on purpose: the pump ends by itself once the child stops
    // checkpointing (the gate goes quiet), and joining it would add that
    // quiet-period to every row.
    std::thread::spawn(move || {
        let mut delivered = false;
        while let Some((stage, checkpoint)) = gate.next() {
            if !delivered && stage == until {
                delivered = true;
                if sender.send(checkpoint).is_err() {
                    return;
                }
                continue;
            }
            checkpoint.reply(Reply::Continue);
        }
    });
    receiver
}

/// AC13: two moving targets read no stdin, on a pipe that holds a decline and on
/// a real terminal; no prompt token appears and `--yes` stays a usage error.
#[test]
fn multi_refresh_never_reads_pipe_or_terminal_input() {
    // A pipe holding a decline: nothing may read it.
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac13pipe");
    let (boot_b1, output_o1) = fixture.move_both(&server, "ac13pipe");
    let (out, unread) =
        with_unread_stdin(refresh_as_ambient_command(&h, &fixture.boot_tag), b"n\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(unread, b"n\n", "stdin must be left unread");
    assert_no_question(&stdout_of(&out));
    assert_no_question(&stderr(&out));
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1))
    );
    assert_eq!(
        h.pin_in(&h.project, &fixture.output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );

    // A real terminal: it exits without a single keystroke.
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac13pty");
    let (boot_b1, output_o1) = fixture.move_both(&server, "ac13pty");
    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    let mut terminal = Pty::spawn(&mut command, b"refresh").expect("open a pseudo-terminal");
    let (status, out) = terminal
        .drive(&Action::Write(b""), Duration::from_secs(60))
        .expect("wait for the refresh to exit");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(status.success(), "{text}");
    assert_no_question(&text);
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1)),
        "{text}"
    );
    assert_eq!(
        h.pin_in(&h.project, &fixture.output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );

    // No `--yes`: this command never asks, so the flag cannot exist.
    let mut command = h.command();
    command.args(["image", "refresh", "--yes"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

/// AC13: a consent render that cannot be written fails only its own operation.
/// A changed Boot render fails, the unchanged Output holder still reports, and
/// nothing is committed.
#[test]
fn multi_refresh_render_failure_preserves_that_target_only() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac13rend");
    // Only Boot moves: Output stays unchanged and needs no render.
    let boot_b1 = fixture.move_boot(&server, "ac13rend");
    let before = fs::read(h.pins()).unwrap();

    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    command.env_remove("AGENT_VM_DEBUG_CONFIG");
    let out = {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        let (writer, reader) = UnixStream::pair().expect("create the socket pair");
        drop(reader);
        let writer: OwnedFd = writer.into();
        bounded_with_stderr(command, std::process::Stdio::from(writer))
    };
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert!(
        rows[0].contains("[1/2]")
            && rows[0].contains("failed")
            && rows[0].contains(
                "the image approval change for this refresh operation could not be shown; this \
             operation committed no approval or project-default change"
            ),
        "{text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
            && rows[1].contains(&format!("unchanged {}", digest_of(&fixture.output_child))),
        "the unrelated unchanged target still reports: {text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    // Nothing was committed for either operation.
    assert_eq!(fs::read(h.pins()).unwrap(), before);
    assert_ne!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1))
    );
    let delivered = format!("{}{}", text, stderr(&out));
    assert!(
        !delivered.contains("nothing was approved")
            && !delivered.contains("nothing was acquired or approved"),
        "a per-operation render failure is not a batch-wide claim: {delivered}"
    );
}

/// AC13/AC14: a later consent-render failure is reported only for its own
/// operation, after an earlier target really committed. The batch keeps the
/// commit, exits 1, and never claims "nothing was approved".
#[test]
fn multi_refresh_later_render_failure_reports_only_that_operation() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac13later");
    let (boot_b1, output_o1) = fixture.move_both(&server, "ac13later");
    assert_ne!(
        fixture.output_child, output_o1,
        "the fixture must move Output"
    );
    let output_record = h.record_in(&h.project, &fixture.output_tag).unwrap();

    let (mut stderr_sink, child_stderr) = Sink::new();
    let mut gate = PinGate::new(h.root.path());
    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    gate.attach(&mut command);
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(child_stderr)
        .spawn()
        .expect("spawn the gated refresh");
    // B's replacement render (precommit) is on stderr; its commit is real.
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    let committed = gate.expect(PinStage::PinCommitted);
    let boot_snapshot = fs::read(h.pins()).unwrap();
    let render_bytes = stderr_sink.drain();
    assert!(
        render_bytes.contains("Replacing the approved image for"),
        "the first target's render must have been written before it committed: {render_bytes}"
    );
    // Close the only stderr reader before the second target's render, then let the
    // first target's commit checkpoint go.
    drop(stderr_sink);
    committed.reply(Reply::Continue);
    // The second target's candidate is resolved, then its render fails, so there
    // is no pin lock or save for it; the gate stays open until the child exits.
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let out = child.wait_with_output().expect("collect the refresh");
    drop(gate);
    assert_eq!(out.status.code(), Some(1), "{render_bytes}");
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert_eq!(rows.len(), 3, "{text}");
    assert!(
        rows[0].contains("[1/2]") && rows[0].contains("changed"),
        "{text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
            && rows[1].contains("failed")
            && rows[1].contains(
                "the image approval change for this refresh operation could not be shown; this \
                 operation committed no approval or project-default change"
            ),
        "{text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    // The first commit is intact; the second operation committed nothing.
    assert_eq!(fs::read(h.pins()).unwrap(), boot_snapshot);
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1))
    );
    assert_eq!(
        h.record_in(&h.project, &fixture.output_tag),
        Some(output_record)
    );
    let delivered = format!("{}{}", text, stderr(&out));
    for blanket in ["nothing was approved", "nothing was acquired or approved"] {
        assert!(
            !delivered.to_lowercase().contains(&blanket.to_lowercase()),
            "a committed sibling forbids the blanket claim: {delivered}"
        );
    }
}

/// The reference guard's real path inside the native cache, for holding it from
/// the test process.
fn reference_guard(h: &Harness, reference: &str) -> PathBuf {
    acquisition_gate::guard_path(
        &microsandbox_image::GlobalCache::new(&h.cache()).unwrap(),
        reference,
    )
}

/// Hold one reference's guard exclusively from this process.
fn hold_reference_guard(h: &Harness, reference: &str) -> fs::File {
    let path = reference_guard(h, reference);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("open the guard");
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .expect("this test must take the guard");
    file
}

/// Hold the native cache's real publication barrier exclusively from this
/// process, the mode an archive publisher takes.
fn hold_publication_barrier(h: &Harness) -> fs::File {
    let cache = h.cache();
    fs::create_dir_all(&cache).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(cache.join(".agent-vm-publication.lock"))
        .expect("open the publication lock");
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .expect("this test must take the publication barrier");
    file
}

/// Hold the pin store's stable exclusive lock from this process.
fn hold_authority_lock(h: &Harness) -> fs::File {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(h.pins().with_extension("lock"))
        .expect("open the pin lock");
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .expect("this test must take the pin lock");
    file
}

/// AC14: after a real commit, losing stderr under a later reference/publication
/// contention cannot panic or stop the remaining operation. The notice write is
/// attempted while the lock is still held, and the unchanged holder still
/// completes with a truthful status.
#[test]
fn multi_refresh_closed_stderr_contention_preserves_progress() {
    /// Which real lock the later acquisition is made to contend on.
    #[derive(Clone, Copy, Debug)]
    enum Contention {
        Reference,
        Publication,
    }
    for (contention, denied) in [
        (Contention::Reference, false),
        (Contention::Reference, true),
        (Contention::Publication, false),
        (Contention::Publication, true),
    ] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let prefix = match contention {
            Contention::Reference => "ac14ref",
            Contention::Publication => "ac14pub",
        };
        let fixture = TwoReferences::create(&h, &server, prefix);
        // Only Boot moves: the Output holder stays unchanged unless this leg
        // denies it, so the success and truthful-failure controls share a shape.
        let boot_b1 = fixture.move_boot(&server, prefix);
        let (mut sink, child_stderr) = Sink::new();
        let acquisition = AcquisitionGate::new(h.root.path());
        let pin_gate = PinGate::new(h.root.path());
        let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
        pin_gate.attach(&mut command);
        acquisition.attach(&mut command);
        // Both gates are pumped: the first target's commit checkpoint and the
        // later target's contention notice are singled out, everything else is
        // acknowledged so an unknown schedule cannot hide a hang.
        let committed = pump_pin_gate(pin_gate, PinStage::PinCommitted);
        let notice = pump_acquisition_gate(
            acquisition,
            match contention {
                Contention::Reference => AcquisitionStage::ReferenceNoticeAttempted,
                Contention::Publication => AcquisitionStage::PublicationNoticeAttempted,
            },
        );
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(child_stderr)
            .spawn()
            .expect("spawn the gated refresh");
        // The first target really commits, and its render reached stderr.
        let committed = committed
            .recv_timeout(Duration::from_secs(60))
            .expect("the first target must reach its commit checkpoint");
        let boot_snapshot = fs::read(h.pins()).unwrap();
        assert!(
            sink.drain().contains("Replacing the approved image for"),
            "the first target's render must be written before it commits"
        );
        // The later acquisition is made to contend on a real lock, and only now
        // does the test drop its stderr reader and let target 1 go.
        let guard = match contention {
            Contention::Reference => hold_reference_guard(&h, &fixture.output_tag),
            Contention::Publication => hold_publication_barrier(&h),
        };
        if denied {
            server.deny_manifest(&format!("/v2/images/manifests/{prefix}out"));
        }
        drop(sink);
        committed.reply(Reply::Continue);
        // The contention notice is attempted while the lock is still held. If it
        // never arrives, the child's own exit status and stderr are collected so
        // the evidence is causal (the notice write panicked) rather than "the gate
        // went quiet".
        let paused = match notice.recv_timeout(Duration::from_secs(60)) {
            Ok(paused) => paused,
            Err(error) => {
                // Bounded: a child still running after this poll is a scheduling
                // failure, not a caught mutant, and must fail rather than hang.
                let Some(code) = child_exit_within(&mut child, Duration::from_secs(10)) else {
                    panic!(
                        "the {contention:?} notice was never attempted ({error}) and the child \
                         was still running after 10 s: that is a scheduling failure, not a \
                         caught mutant"
                    );
                };
                let text = exited_child_output(&mut child);
                // A child that panicked on the notice write exits 101; that is the
                // causal evidence (its message cannot reach a closed stderr).
                assert_eq!(
                    code,
                    Some(101),
                    "the {contention:?} notice must be attempted while the lock is held; the \
                     child exited with {code:?} and output: {text}{error}"
                );
                panic!(
                    "the {contention:?} contention notice was never attempted ({error}); child \
                     exited Some(101) (panic on the notice write); output: {text}"
                );
            }
        };
        assert_eq!(
            unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&guard), libc::LOCK_UN) },
            0
        );
        paused.reply(GateReply::Continue);
        let out = child.wait_with_output().expect("collect the refresh");
        let text = stdout_of(&out);
        let rows = rows_of(&out);
        if denied {
            assert_eq!(out.status.code(), Some(1), "{text}");
            assert_eq!(rows.len(), 3, "{text}");
            assert!(rows[0].contains("changed"), "{text}");
            assert!(
                rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
                    && rows[1].contains("failed"),
                "a real failure is still reported after lost stderr: {text}"
            );
            assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
        } else {
            assert_eq!(out.status.code(), Some(0), "{text}");
            assert_eq!(rows.len(), 3, "{text}");
            assert!(rows[0].contains(&digest_of(&boot_b1)), "{text}");
            assert!(
                rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
                    && rows[1].contains(&format!("unchanged {}", digest_of(&fixture.output_child))),
                "{text}"
            );
            assert_eq!(rows[2], "==> image refresh: 2 succeeded, 0 failed");
        }
        // The first target's commit is byte-identical, and the whole file is that
        // snapshot: the later operation saved nothing.
        assert_eq!(fs::read(h.pins()).unwrap(), boot_snapshot);
        assert_eq!(
            h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
            Some(digest_of(&boot_b1))
        );
        assert!(out.status.code() != Some(101), "no panic status");
        assert!(
            manifest_requests(&server, 0, &format!("{prefix}out")) > 0,
            "the later target really ran"
        );
    }
}

/// AC14: after a real commit, losing stderr while a later target waits for the
/// **authority** lock cannot panic or stop it: the notice write is attempted
/// under real contention, and the operation still commits or fails truthfully.
#[test]
fn multi_refresh_closed_stderr_authority_contention_preserves_progress() {
    for fail_save in [false, true] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let fixture = TwoReferences::create(&h, &server, "ac14auth");
        let boot_b1 = fixture.move_boot(&server, "ac14auth");
        if fail_save {
            fixture.move_output(&server, "ac14auth");
        }
        let (mut sink, child_stderr) = Sink::new();
        let mut gate = PinGate::new(h.root.path());
        let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
        gate.attach(&mut command);
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(child_stderr)
            .spawn()
            .expect("spawn the gated refresh");
        for stage in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
            PinStage::BeforePinSave,
        ] {
            expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
        }
        let committed = expect_stage(&mut gate, PinStage::PinCommitted, &mut child);
        let boot_snapshot = fs::read(h.pins()).unwrap();
        assert!(
            sink.drain().contains("Replacing the approved image for"),
            "the first target's render must be written before stderr closes"
        );
        committed.reply(Reply::Continue);

        // Target 2's candidate is ready and it has not taken the pin lock yet.
        expect_stage(&mut gate, PinStage::CandidateReady, &mut child).reply(Reply::Continue);
        let before_lock = expect_stage(&mut gate, PinStage::BeforePinLock, &mut child);
        // The parent takes the real stable pin EX, then closes stderr.
        let authority = hold_authority_lock(&h);
        drop(sink);
        before_lock.reply(Reply::Continue);
        // The one-time wait notice is attempted at its normal threshold; release
        // the lock only after that attempt.
        expect_stage(&mut gate, PinStage::AuthorityNoticeAttempted, &mut child)
            .reply(Reply::Continue);
        assert_eq!(
            unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&authority), libc::LOCK_UN) },
            0
        );
        expect_stage(&mut gate, PinStage::PinLocked, &mut child).reply(Reply::Continue);
        if fail_save {
            expect_stage(&mut gate, PinStage::BeforePinSave, &mut child)
                .reply(Reply::FailBeforeSave);
        }
        let out = child.wait_with_output().expect("collect the refresh");
        drop(gate);
        let text = stdout_of(&out);
        let rows = rows_of(&out);
        if fail_save {
            assert_eq!(out.status.code(), Some(1), "{text}");
            assert_eq!(rows.len(), 3, "{text}");
            assert!(rows[0].contains("changed"), "{text}");
            assert!(
                rows[1].contains("failed"),
                "the real authority failure is reported: {text}"
            );
            assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
        } else {
            assert_eq!(out.status.code(), Some(0), "{text}");
            assert_eq!(rows.len(), 3, "{text}");
            assert!(
                rows[1].contains(&format!("unchanged {}", digest_of(&fixture.output_child))),
                "{text}"
            );
            assert_eq!(rows[2], "==> image refresh: 2 succeeded, 0 failed");
        }
        assert_eq!(fs::read(h.pins()).unwrap(), boot_snapshot);
        assert_eq!(
            h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
            Some(digest_of(&boot_b1))
        );
        assert_ne!(out.status.code(), Some(101), "no panic status");
    }
}

/// AC14: losing **stdout** after a commit is a bounded warning, not a failed
/// approval: the later target still resolves, renders on stderr and commits.
#[test]
fn multi_refresh_closed_stdout_preserves_progress() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac14out");
    let (boot_b1, output_o1) = fixture.move_both(&server, "ac14out");

    let (stdout_sink, child_stdout) = Sink::new();
    let mut gate = PinGate::new(h.root.path());
    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    gate.attach(&mut command);
    let mut child = command
        .stdout(child_stdout)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
    ] {
        expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
    }
    let committed = expect_stage(&mut gate, PinStage::PinCommitted, &mut child);
    // The first commit is real; only then does stdout go away.
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1))
    );
    drop(stdout_sink);
    committed.reply(Reply::Continue);
    // The later target still renders (stderr is open) and commits.
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        expect_stage(&mut gate, stage, &mut child).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stderr(&out);
    assert_eq!(
        text.matches("warning: image refresh outcomes could not all be written; completed approvals remain committed; do not retry it as a failed approval").count(),
        1,
        "exactly one bounded warning: {text}"
    );
    assert!(
        text.contains("Replacing the approved image for"),
        "the later consent render still happened: {text}"
    );
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1))
    );
    assert_eq!(
        h.pin_in(&h.project, &fixture.output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1)),
        "the later target committed despite lost stdout"
    );
    assert!(!text.contains("nothing was approved"), "{text}");
}

/// AC14: a peer that commits the same candidate makes this operation `unchanged`,
/// with the live digest kept and no new token; the sibling still succeeds.
#[test]
fn multi_refresh_same_candidate_peer_reports_unchanged() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac14peer");
    let boot_b1 = fixture.move_boot(&server, "ac14peer");

    let mut gate = PinGate::new(h.root.path());
    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    gate.attach(&mut command);
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let before_lock = gate.expect(PinStage::BeforePinLock);
    // A peer in the same project approves exactly this candidate in its own cache.
    let peer = peer_state("ac14peer");
    let approved = h.refresh_as_ambient_in(&h.project, peer.path(), &fixture.boot_tag);
    assert!(
        approved.status.success(),
        "the peer approves B1: {}{}",
        stdout_of(&approved),
        stderr(&approved)
    );
    let peer_tuple = h.pin_in(&h.project, &fixture.boot_tag).unwrap();
    assert_eq!(peer_tuple.0, digest_of(&boot_b1));
    // The sibling moves only now, so it has real work left.
    let output_o1 = fixture.move_output(&server, "ac14peer");

    before_lock.reply(Reply::Continue);
    // This operation reconciles on the live pin: `PinLocked` then no save for it.
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert!(
        rows[0].contains(&format!("unchanged {}", digest_of(&boot_b1))),
        "a peer's identical candidate is reported unchanged: {text}"
    );
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag),
        Some(peer_tuple),
        "the live tuple and its token are kept"
    );
    assert_eq!(
        h.pin_in(&h.project, &fixture.output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );
}

/// AC14: a record-sourced reference never reaches the report, progress text, the
/// debug-config copy, traces or an error chain; an explicit target may show its
/// own escaped reference.
#[test]
fn multi_refresh_redacts_record_sourced_references() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    // A private default (host + project) and a private holder, both served.
    let d = h.image(&ArchiveSpec {
        marker: "ac14priv-d".into(),
        ..Default::default()
    });
    let default_child = server.image("private-default", "edge", &d);
    let mut establish = h.command();
    establish
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &default_child)
        .args(["image", "refresh"]);
    assert_eq!(bounded(establish).status.code(), Some(0));
    assert!(
        default_child.contains("private-default"),
        "the fixture reference carries the sentinel"
    );
    let o = h.image(&ArchiveSpec {
        marker: "ac14priv-o".into(),
        ..Default::default()
    });
    let holder_tag = format!("{}/private-holder:edge", server.host);
    let holder_child = server.image("private-holder", "edge", &o);
    assert_eq!(
        h.import(&o.written.path, &holder_tag).status.code(),
        Some(0)
    );
    // Move both, so the report has changed/unchanged rows to leak through.
    let d1 = h.image(&ArchiveSpec {
        marker: "ac14priv-d1".into(),
        ..Default::default()
    });
    server.image("private-default", "edge", &d1);
    let o1 = h.image(&ArchiveSpec {
        marker: "ac14priv-o1".into(),
        ..Default::default()
    });
    server.image("private-holder", "edge", &o1);

    // Success leg with the debug dump and dependency tracing enabled.
    let mut command = h.command();
    command
        .env("AGENT_VM_DEBUG_CONFIG", "1")
        .env("RUST_LOG", "trace")
        .args(["image", "refresh"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let delivered = format!("{}{}", stdout_of(&out), stderr(&out));
    assert!(
        delivered.contains("the default boot image")
            && delivered.contains("the latest output image"),
        "the fixed labels carry the report: {delivered}"
    );
    for sentinel in ["private-default", "private-holder"] {
        assert!(
            !delivered.contains(sentinel),
            "a record-sourced reference leaked ({sentinel}): {delivered}"
        );
    }

    // An explicit filter is allowed to show its own escaped reference (before the
    // route is denied below).
    let mut command = h.command();
    command.args(["image", "refresh", "--image", &holder_tag]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout_of(&out).contains(&holder_tag),
        "an explicit target may name itself: {}",
        stdout_of(&out)
    );

    // Failure leg: the holder's route is denied, and its reason must stay
    // reference-free while the fixed label identifies it.
    server.deny_manifest("/v2/private-holder/manifests/edge");
    let o2 = h.image(&ArchiveSpec {
        marker: "ac14priv-o2".into(),
        ..Default::default()
    });
    server.image("private-holder", "edge", &o2);
    let mut command = h.command();
    command
        .env("AGENT_VM_DEBUG_CONFIG", "1")
        .env("RUST_LOG", "trace")
        .args(["image", "refresh"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let delivered = format!("{}{}", stdout_of(&out), stderr(&out));
    assert!(delivered.contains("the latest output image"), "{delivered}");
    for sentinel in ["private-default", "private-holder"] {
        assert!(
            !delivered.contains(sentinel),
            "a failed row leaked a record-sourced reference ({sentinel}): {delivered}"
        );
    }

    let _ = holder_child;
}

/// AC15: killing the process during a later target's download keeps the earlier
/// commit: no rollback, no partial second approval, free locks, and a retry works.
#[test]
fn multi_refresh_kill_during_later_download_keeps_earlier_commit() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac15kill");
    let boot_b1 = fixture.move_boot(&server, "ac15kill");
    let o1 = h.image(&ArchiveSpec {
        marker: "ac15kill-output-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac15killout", &o1);
    let output_record = h.record_in(&h.project, &fixture.output_tag).unwrap();
    let stall = server.stall_blob(&format!("/v2/images/blobs/{}", o1.written.layer_digest));

    let mut gate = PinGate::new(h.root.path());
    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    gate.attach(&mut command);
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    let committed = gate.expect(PinStage::PinCommitted);
    let snapshot = fs::read(h.pins()).unwrap();
    committed.reply(Reply::Continue);
    drop(gate);
    // The second target starts its download and stalls on a blob.
    stall
        .recv_timeout(Duration::from_secs(30))
        .expect("the stalled blob handshake must arrive");
    child.kill().expect("kill the refresh mid-download");
    let _ = child.wait();
    server.release_blob();

    // No rollback: the first commit is intact and the second approval untouched.
    assert_eq!(fs::read(h.pins()).unwrap(), snapshot);
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1))
    );
    assert_eq!(
        h.record_in(&h.project, &fixture.output_tag),
        Some(output_record)
    );
    // The killed process left no lock behind: an independent acquisition of the
    // same reference succeeds.
    acquisition_gate::assert_guard_free(&reference_guard(&h, &fixture.output_tag));
    let retry = h.refresh(&fixture.output_tag);
    assert_eq!(retry.status.code(), Some(0), "{}", stderr(&retry));
    assert_eq!(
        h.pin_in(&h.project, &fixture.output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );
}

/// Answer every acquisition checkpoint with `Continue` until `until` arrives,
/// then hand that paused checkpoint to the test and keep answering the rest.
///
/// The acquisition gate is sequential, so a whole acquisition under it must be
/// pumped; this is the bounded helper the closed-sink schedules need.
fn pump_acquisition_gate(
    mut gate: AcquisitionGate,
    until: AcquisitionStage,
) -> std::sync::mpsc::Receiver<acquisition_gate::Checkpoint> {
    let (sender, receiver) = std::sync::mpsc::channel();
    // Detached for the same reason as `pump_pin_gate`.
    std::thread::spawn(move || {
        let mut delivered = false;
        while let Some((stage, checkpoint)) = gate.next() {
            if !delivered && stage == until {
                delivered = true;
                if sender.send(checkpoint).is_err() {
                    return;
                }
                continue;
            }
            checkpoint.reply(GateReply::Continue);
        }
    });
    receiver
}

/// The store's record bound: one save that would add a record fails as full.
const STORE_PIN_BOUND: usize = 4096;

/// The fixture store's text with exactly `total_pins` pins and an optional write
/// sequence.
///
/// The pads are the **smallest** valid foreign records on purpose: this fixture
/// exists to reach the *record* bound, so it stays a few hundred kilobytes and
/// validates quickly (unlike byte-bound filler, which needs thousands of maximal
/// records).
fn store_padded_to_pin_count(h: &Harness, total_pins: usize, sequence: Option<u64>) -> String {
    let original = fs::read_to_string(h.pins()).expect("the fixture store");
    let mut store: serde_json::Value = serde_json::from_str(&original).expect("valid store");
    if let Some(sequence) = sequence {
        store["sequence"] = serde_json::json!(sequence);
    }
    let mut pins: Vec<serde_json::Value> = store["pins"].as_array().expect("pins").clone();
    let arch = image_archive::host_arch();
    while pins.len() < total_pins {
        let index = pins.len();
        pins.push(serde_json::json!({
            "project": format!("{:064x}", index + 1),
            "reference": format!("example.com/pad{}:tag", index + 1),
            "platform": {"os": "linux", "architecture": arch, "variant": null},
            "manifest_digest": format!("sha256:{}", "e".repeat(64)),
            "revision": 1,
        }));
    }
    store["pins"] = serde_json::json!(pins);
    String::from_utf8(serde_json::to_vec(&store).expect("serialize")).unwrap()
}

/// A1: a capacity failure is an operation row with update-local wording, and an
/// independent sibling still commits. Cheap and deterministic: the store is at
/// the **record** bound and the ambient target is the insertion that crosses it.
#[test]
fn refresh_capacity_failure_is_an_operation_row_and_siblings_continue() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac1cap");
    // The Output holder has real work to commit after the capacity failure.
    let output_o1 = fixture.move_output(&server, "ac1cap");
    // The ambient selection is a reference this project has never pinned, so its
    // save is an insertion — the one growth a refresh can make.
    let ambient = h.image(&ArchiveSpec {
        marker: "ac1cap-ambient".into(),
        ..Default::default()
    });
    let ambient_tag = format!("{}/images:ac1capamb", server.host);
    server.image("images", "ac1capamb", &ambient);

    let pad = store_padded_to_pin_count(&h, STORE_PIN_BOUND, None);
    let pinned_before = serde_json::from_str::<serde_json::Value>(&pad).unwrap()["pins"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(
        pinned_before, STORE_PIN_BOUND,
        "the fixture is at the bound"
    );
    seed_store(&h, pad.as_bytes());

    let out = h.refresh_as_ambient(&ambient_tag);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    // Ambient insertion, then the two recorded holders in canonical order.
    assert_eq!(rows.len(), 4, "{text}");
    assert!(
        rows[0].starts_with(&format!("==> refresh [1/3] {ambient_tag} (linux/"))
            && rows[0].contains("failed")
            && rows[0].contains("holds the maximum number of approvals")
            && rows[0].contains("this proposed pin-store update was not committed"),
        "a capacity failure is an operation row with update-local wording: {text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/3] the recorded boot image (linux/"),
        "{text}"
    );
    assert!(
        rows[2].starts_with("==> refresh [3/3] the latest output image (linux/"),
        "{text}"
    );
    assert!(
        rows[2].contains(&format!(
            "changed {} -> {}",
            digest_of(&fixture.output_child),
            digest_of(&output_o1)
        )),
        "{text}"
    );
    assert_eq!(rows[3], "==> image refresh: 2 succeeded, 1 failed");
    // Neither stream claims nothing was approved, and the sibling's commit is real.
    let delivered = format!("{}{}", text, stderr(&out));
    for blanket in ["nothing was approved", "nothing was acquired or approved"] {
        assert!(
            !delivered.to_lowercase().contains(blanket),
            "the blanket claim {blanket:?} must not appear: {delivered}"
        );
    }
    assert_eq!(
        h.pin_in(&h.project, &fixture.output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );
    assert!(
        h.pin_in(&h.project, &ambient_tag).is_none(),
        "the refused insertion added no record"
    );
    assert_eq!(
        h.pins_value().unwrap()["pins"].as_array().unwrap().len(),
        STORE_PIN_BOUND,
        "the refused insertion left the record count alone"
    );
}

/// A1: a success-first batch keeps its commit when a later save fails. Cheap and
/// deterministic: the write sequence is one short of exhaustion, so the first
/// target's save consumes the last token and the second target's save fails
/// update-locally before it writes.
#[test]
fn refresh_late_sequence_exhaustion_keeps_the_earlier_commit() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let fixture = TwoReferences::create(&h, &server, "ac1seq");
    let (boot_b1, output_o1) = fixture.move_both(&server, "ac1seq");
    let output_record = h.record_in(&h.project, &fixture.output_tag).unwrap();
    // One token left: the first target takes it, the second finds none.
    // Exactly the fixture's two pins: this leg is about the write sequence, not
    // the record bound.
    let existing = h.pins_value().unwrap()["pins"].as_array().unwrap().len();
    let pad = store_padded_to_pin_count(&h, existing, Some(u64::MAX - 1));
    seed_store(&h, pad.as_bytes());

    let mut gate = PinGate::new(h.root.path());
    let mut command = refresh_as_ambient_command(&h, &fixture.boot_tag);
    gate.attach(&mut command);
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforePinSave,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    let committed = gate.expect(PinStage::PinCommitted);
    let snapshot = fs::read(h.pins()).unwrap();
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1)),
        "the first target really committed"
    );
    // Let the first target finish, then require the second to be refused before
    // any write: no `BeforePinSave`, no second commit.
    committed.reply(Reply::Continue);
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert_eq!(rows.len(), 3, "{text}");
    assert!(
        rows[0].contains(&format!(
            "changed {} -> {}",
            digest_of(&fixture.boot_child),
            digest_of(&boot_b1)
        )),
        "{text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
            && rows[1].contains("failed")
            && rows[1].contains("this proposed pin-store update was not committed"),
        "the later save failure is update-local: {text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    let delivered = format!("{}{}", text, stderr(&out));
    for blanket in ["nothing was approved", "nothing was acquired or approved"] {
        assert!(
            !delivered.to_lowercase().contains(blanket),
            "the blanket claim {blanket:?} must not appear: {delivered}"
        );
    }
    // The earlier commit survives exactly; the refused target changed nothing.
    assert_eq!(fs::read(h.pins()).unwrap(), snapshot);
    assert_eq!(
        h.pin_in(&h.project, &fixture.boot_tag).map(|(d, _)| d),
        Some(digest_of(&boot_b1))
    );
    assert_eq!(
        h.record_in(&h.project, &fixture.output_tag),
        Some(output_record)
    );
    assert_ne!(digest_of(&output_o1), digest_of(&fixture.output_child));
}

/// A2: a *changed* observed H (not a vanished one) is a stale observation, the
/// bookmark does not move, and the unrelated sibling still commits. Integrity
/// failure is reserved for a live H that matches the observation.
#[test]
fn refresh_adoption_changed_observed_host_is_stale_and_siblings_continue() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let default_child = establish_default_unheld(&h, &server, "ac10chg");
    // H is this project's Boot holder at its immutable key, and the bookmark.
    let h_image = h.image(&ArchiveSpec {
        marker: "ac10chg-h".into(),
        ..Default::default()
    });
    let host_tag = format!("{}/images:ac10chgh", server.host);
    let host_child = server.image("images", "ac10chgh", &h_image);
    let mut setup = h.command();
    setup.args(["setup", "--image", &host_child, "--no-verify"]);
    assert_eq!(bounded(setup).status.code(), Some(0));
    assert!(set_default(&h, &host_tag).status.success());
    // An unrelated Output holder that moves, so the sibling has work to commit.
    let o = h.image(&ArchiveSpec {
        marker: "ac10chg-o".into(),
        ..Default::default()
    });
    let output_tag = format!("{}/images:ac10chgout", server.host);
    let output_child = server.image("images", "ac10chgout", &o);
    assert_eq!(
        h.import(&o.written.path, &output_tag).status.code(),
        Some(0)
    );
    let o1 = h.image(&ArchiveSpec {
        marker: "ac10chg-o1".into(),
        ..Default::default()
    });
    let output_o1 = server.image("images", "ac10chgout", &o1);

    let mut gate = PinGate::new(h.root.path());
    let mut command = h.command();
    command.args(["image", "refresh"]);
    gate.attach(&mut command);
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the gated refresh");
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let before_lock = gate.expect(PinStage::BeforePinLock);
    // A peer rewrites H's approval to different content: the observation is now
    // changed rather than absent, and both are stale.
    let mut store: serde_json::Value =
        serde_json::from_slice(&fs::read(h.pins()).unwrap()).unwrap();
    let changed = format!("sha256:{}", "d".repeat(64));
    for record in store["pins"].as_array_mut().unwrap() {
        if record["manifest_digest"]
            .as_str()
            .is_some_and(|digest| digest == digest_of(&host_child))
        {
            record["manifest_digest"] = serde_json::Value::String(changed.clone());
        }
    }
    fs::write(h.pins(), serde_json::to_vec(&store).unwrap()).unwrap();
    let peer_bytes = fs::read(h.pins()).unwrap();
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(default_child.clone()),
        "the peer moved no bookmark"
    );

    before_lock.reply(Reply::Continue);
    // The stale adoption takes its lock, decides stale and writes nothing; the
    // next stage is the sibling's candidate, never H's save.
    gate.expect(PinStage::PinLocked).reply(Reply::Continue);
    gate.expect(PinStage::CandidateReady).reply(Reply::Continue);
    let sibling_lock = gate.expect(PinStage::BeforePinLock);
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        peer_bytes,
        "the stale adoption changed nothing"
    );
    sibling_lock.reply(Reply::Continue);
    for stage in [
        PinStage::PinLocked,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    drop(gate);
    let out = child.wait_with_output().expect("collect the refresh");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout_of(&out);
    let rows = rows_of(&out);
    assert!(
        rows[0].contains("[1/2]")
            && rows[0].contains("failed")
            && rows[0].contains("image approval is stale; retry the explicit operation"),
        "a changed observation is stale, not an integrity failure: {text}"
    );
    assert!(
        !rows[0].contains("integrity"),
        "integrity is reserved for matching live content: {text}"
    );
    assert!(
        rows[1].starts_with("==> refresh [2/2] the latest output image (linux/")
            && rows[1].contains(&format!(
                "changed {} -> {}",
                digest_of(&output_child),
                digest_of(&output_o1)
            )),
        "{text}"
    );
    assert_eq!(rows[2], "==> image refresh: 1 succeeded, 1 failed");
    assert_eq!(
        h.default_record_in(&h.project).unwrap()["image"],
        serde_json::Value::String(default_child.clone()),
        "the bookmark did not move"
    );
    assert_eq!(
        h.pin_in(&h.project, &output_tag).map(|(d, _)| d),
        Some(digest_of(&output_o1))
    );
}

/// The uppercase-hex spelling of a `repo@algorithm:hex` reference: an accepted
/// alias that canonicalizes to the same key.
fn uppercase_hex(reference: &str) -> String {
    let (head, hex) = reference.rsplit_once(':').expect("repo@algorithm:hex");
    format!("{head}:{}", hex.to_ascii_uppercase())
}

/// AC3: two spellings of one canonical key are one key — through a `--image`
/// filter and through a bare refresh's deduplication.
#[test]
fn refresh_deduplicates_canonical_alias_spellings() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.image(&ArchiveSpec {
        marker: "ac3alias".into(),
        ..Default::default()
    });
    let canonical = server.image("images", "ac3alias", &image);
    // A genuine Boot holder, so the alias spelling has membership evidence to
    // match: the key is canonical identity, not the caller's spelling.
    let mut setup = h.command();
    setup.args(["setup", "--image", &canonical, "--no-verify"]);
    let setup = bounded(setup);
    assert_eq!(setup.status.code(), Some(0), "{}", stderr(&setup));
    assert_eq!(h.records_in(&h.project), 1);
    let alias = uppercase_hex(&canonical);
    assert_ne!(alias, canonical, "the fixture must use another spelling");

    // The alias spelling is a member of the canonical key's record.
    let requests_before = server.count();
    let out = h.refresh(&alias);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout_of(&out);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(
        text.contains(&canonical),
        "the row names the canonical spelling: {text}"
    );
    assert_eq!(
        manifest_requests(&server, requests_before, &digest_of(&canonical)),
        1
    );
    assert_eq!(h.records_in(&h.project), 1, "one record, not two");

    // A bare refresh with the alias as the ambient selection also dedupes to the
    // same single key.
    let requests_before = server.count();
    let out = h.refresh_as_ambient(&alias);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout_of(&out);
    assert_eq!(text.lines().count(), 2, "one target only: {text}");
    assert_eq!(
        manifest_requests(&server, requests_before, &digest_of(&canonical)),
        1
    );
    assert_eq!(h.records_in(&h.project), 1);
}

/// AC5/AC6: malformed, empty and non-Unicode inputs are refused value-free
/// **before any state exists** — process-level, not only at the preflight unit.
#[test]
fn refresh_input_refusals_precede_any_state() {
    for malformed in ["Foo/Bar:tag", "repo:bad tag", "repo@sha256:short", ""] {
        let h = Harness::new(Mode::StrictAcquisition);
        let out = h.refresh(malformed);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{malformed:?}: {}",
            stderr(&out)
        );
        let text = stderr(&out);
        assert!(
            text.contains("must not be empty")
                || text.contains("needs a valid OCI image reference"),
            "{malformed:?}: {text}"
        );
        if !malformed.is_empty() {
            assert!(
                !text.contains(malformed),
                "the rejected value is never echoed: {text}"
            );
        }
        for created in [".agent-vm-msb", ".microsandbox"] {
            assert!(
                !h.home.join(created).exists(),
                "{malformed:?}: a refused refresh created {created}"
            );
        }
        assert!(
            !h.pins().exists(),
            "{malformed:?}: no authority was created"
        );
    }

    // A present but non-Unicode environment value is a typed refusal, also
    // before any state.
    use std::os::unix::ffi::OsStrExt as _;
    let h = Harness::new(Mode::StrictAcquisition);
    let mut command = h.command();
    command
        .env("AGENT_VM_IMAGE_TAG", std::ffi::OsStr::from_bytes(b"\xff"))
        .args(["image", "refresh"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains(
            "AGENT_VM_IMAGE_TAG is set but is not usable as an image override; a Unicode value is \
             required"
        ),
        "{}",
        stderr(&out)
    );
    for created in [".agent-vm-msb", ".microsandbox"] {
        assert!(
            !h.home.join(created).exists(),
            "a refused refresh created {created}"
        );
    }
    assert!(!h.pins().exists(), "no authority was created");
}

/// Poll for a child to exit within `within`: `Some(code)` once it has, `None`
/// while it is still running. Never blocks past the bound, so a stuck child fails
/// a test instead of hanging CI.
fn child_exit_within(child: &mut std::process::Child, within: Duration) -> Option<Option<i32>> {
    let deadline = std::time::Instant::now() + within;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status.code());
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The output of a child that has already exited, read through its remaining pipe
/// ends (they EOF once it is gone, so this cannot block).
fn exited_child_output(child: &mut std::process::Child) -> String {
    use std::io::Read as _;
    let mut text = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut text);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut text);
    }
    text
}

/// A gated stage expectation that refuses to look like a schedule hang: if the
/// stage never arrives, the child's own exit status must show a panic (101). A
/// child still running at the deadline is a scheduling failure, not a caught
/// mutant, and fails with that distinction spelled out.
fn expect_stage(
    gate: &mut PinGate,
    stage: PinStage,
    child: &mut std::process::Child,
) -> PinCheckpoint {
    match gate.try_expect(stage) {
        Ok(checkpoint) => checkpoint,
        Err(why) => {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut code = None;
            while std::time::Instant::now() < deadline {
                if let Ok(Some(status)) = child.try_wait() {
                    code = status.code();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            // The child finishing is the causal evidence: the mutant ended the
            // batch early (a panic is 101, a mutant that aborts the batch is 1).
            // A child still running at the deadline is a scheduling failure.
            assert!(
                code.is_some(),
                "stage {stage:?} never arrived ({why}) and the child was still running after \
                 10s: that is a scheduling failure, not a caught mutant."
            );
            panic!("stage {stage:?} never arrived ({why}); child exited {code:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// #609: the two read-only projections — `image pins` and the active row.
//
// Every fixture below writes the store bytes directly. Presentation is not an
// acquisition, so a synthetic store needs no registry, archive or runtime, and
// the expected TSV/row text is built from the fixture's own inputs rather than
// from the renderer under test.
// ---------------------------------------------------------------------------

/// The documented header, pinned independently of the production renderer.
const PINS_HEADER: &str = "REFERENCE\tPLATFORM\tDIGEST\tREVISION\tROLES\tUNRESOLVED\n";

/// N1's literal access message. Spelled out here so an oracle built from the
/// production constructor cannot pass after the two messages are swapped.
const N1_ACCESS: &str =
    "image pin authority at $HOME/.config/agent-vm/image-pins.json could not be accessed or saved";

/// The store-owned damaged-authority text, pinned here rather than obtained from
/// the production constructor, so an oracle cannot agree with a swapped message.
const CORRUPT_MESSAGE: &str = "image pin authority at $HOME/.config/agent-vm/image-pins.json is damaged; restore its intended records from backup or deliberately move it aside to reset approvals";

/// The literal v1 refusal, likewise pinned.
const N1_V1: &str = "image pin authority at $HOME/.config/agent-vm/image-pins.json uses the host-wide version 1 format, which this agent-vm no longer reads: approvals are now per project. Archiving it resets approvals, and mutable tags may then resolve to newer content; see \"Upgrading from host-wide approvals\" in USAGE.md";

/// The architecture this host is *not*, so a foreign record can never be this
/// host's by accident.
fn foreign_arch() -> &'static str {
    if image_archive::host_arch() == "amd64" {
        "arm64"
    } else {
        "amd64"
    }
}

fn platform_json(architecture: &str, variant: Option<&str>) -> serde_json::Value {
    serde_json::json!({"os": "linux", "architecture": architecture, "variant": variant})
}

fn host_platform_json() -> serde_json::Value {
    platform_json(image_archive::host_arch(), None)
}

fn host_platform() -> String {
    format!("linux/{}", image_archive::host_arch())
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

/// One pin. `roles: None` omits the field, which is the "holds nothing" state —
/// not a stored empty mask.
fn pin_json(
    project: &str,
    reference: &str,
    platform: &serde_json::Value,
    digest: &str,
    revision: u64,
    roles: Option<&str>,
) -> serde_json::Value {
    let mut record = serde_json::json!({
        "project": project,
        "reference": reference,
        "platform": platform,
        "manifest_digest": digest,
        "revision": revision,
    });
    if let Some(roles) = roles {
        record["roles"] = serde_json::json!(roles);
    }
    record
}

fn scope_json(project: &str, platform: &serde_json::Value, resolved: &str) -> serde_json::Value {
    serde_json::json!({"project": project, "platform": platform, "resolved": resolved})
}

/// Exact v2 bytes: only the fields the fixture means to have. `sequence: None`
/// is the pre-0.7.51 file, which carried no roles, scopes or write sequence.
fn store_bytes(
    pins: Vec<serde_json::Value>,
    scopes: Vec<serde_json::Value>,
    sequence: Option<u64>,
) -> Vec<u8> {
    let mut store = serde_json::json!({
        "version": 2,
        "pins": pins,
        "pending_default": serde_json::Value::Null,
    });
    if !scopes.is_empty() {
        store["scopes"] = serde_json::json!(scopes);
    }
    if let Some(sequence) = sequence {
        store["sequence"] = serde_json::json!(sequence);
    }
    serde_json::to_vec(&store).unwrap()
}

/// One expected listing row, assembled from the fixture's own inputs.
fn pins_row(
    reference: &str,
    platform: &str,
    digest: &str,
    revision: u64,
    roles: &str,
    unresolved: &str,
) -> String {
    format!("{reference}\t{platform}\t{digest}\t{revision}\t{roles}\t{unresolved}\n")
}

/// The exact listing: the documented header plus the fixture's own rows.
fn expected_listing(rows: &[String]) -> String {
    let mut text = String::from(PINS_HEADER);
    for row in rows {
        text.push_str(row);
    }
    text
}

/// Every `active images:` row of one report. There must be exactly one, and its
/// bytes must match: the rest of doctor has unrelated sections.
#[track_caller]
fn assert_active_row(stdout: &str, expected: &str) {
    let rows: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("active images: "))
        .collect();
    assert_eq!(rows, [expected], "exactly one active row:\n{stdout}");
    let lines: Vec<&str> = stdout.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.starts_with("active images: "))
        .expect("the row was found above");
    assert!(
        lines[at - 1].starts_with("project default: "),
        "the row follows `project default:` immediately:\n{stdout}"
    );
    if let Some(selected) = lines
        .iter()
        .position(|line| line.starts_with("selected (without --image): "))
    {
        assert!(
            at < selected,
            "the row precedes `selected (without --image):`:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("==> agent-vm doctor: available operations"),
        "later sections still print:\n{stdout}"
    );
}

/// The `==> boot image` section: its heading plus every row up to the next blank
/// line. The rest of the report has unrelated sections and unrelated `user:`
/// rows, so placement assertions stay inside this one.
fn boot_image_section(stdout: &str) -> Vec<&str> {
    let mut lines = stdout.lines();
    let start = lines
        .by_ref()
        .position(|line| line == "==> boot image")
        .unwrap_or_else(|| panic!("no boot-image section:\n{stdout}"));
    stdout
        .lines()
        .skip(start)
        .take_while(|line| !line.is_empty())
        .collect()
}

/// Every entry of the authority directory as type, mode, inode, size and content
/// hash for regular files, and as its target for a symlink. A special store path
/// is compared by metadata only, never by reading it: a FIFO has no bytes to read
/// and would block. Content is included because an in-place rewrite preserves the
/// mode and the inode, so identity alone would not detect changed bytes.
fn authority_inventory(h: &Harness) -> std::collections::BTreeMap<String, String> {
    use std::os::unix::fs::MetadataExt as _;
    let mut entries = std::collections::BTreeMap::new();
    let directory = config_dir(h);
    let Ok(read) = fs::read_dir(&directory) else {
        return entries;
    };
    for entry in read {
        let entry = entry.unwrap();
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let file_type = metadata.file_type();
        let description = if file_type.is_symlink() {
            format!(
                "symlink {:o} {} {:?}",
                metadata.mode(),
                metadata.ino(),
                fs::read_link(&path).unwrap()
            )
        } else if file_type.is_dir() {
            format!("dir {:o} {}", metadata.mode(), metadata.ino())
        } else if file_type.is_file() {
            // Content as well as identity: an in-place rewrite keeps the mode and
            // the inode, so those alone would not prove the bytes are unchanged.
            let mut hasher = Sha256::new();
            hasher.update(fs::read(&path).unwrap());
            let content: String = hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            format!(
                "file {:o} {} {} {content}",
                metadata.mode(),
                metadata.ino(),
                metadata.len()
            )
        } else {
            // A FIFO, socket or device is described by metadata only: opening one
            // is what the product promises not to do, and a read would block.
            format!("special {:o} {}", metadata.mode(), metadata.ino())
        };
        entries.insert(
            entry.file_name().to_string_lossy().into_owned(),
            description,
        );
    }
    entries
}

/// The store's exact bytes and the coordination file's inode and mode. A read is
/// allowed to move atime, so it is excluded; `None` means the path is absent.
fn store_snapshot(h: &Harness) -> (Option<Vec<u8>>, Option<(u64, u32)>) {
    use std::os::unix::fs::MetadataExt as _;
    (
        fs::read(h.pins()).ok(),
        fs::symlink_metadata(config_dir(h).join("image-pins.lock"))
            .ok()
            .map(|metadata| (metadata.ino(), metadata.mode())),
    )
}

impl Harness {
    fn pins_listing(&self) -> Output {
        self.pins_listing_in(&self.project, &self.state)
    }

    fn pins_listing_in(&self, project: &Path, state: &Path) -> Output {
        let mut command = self.command_in(project, state);
        command.args(["image", "pins"]);
        bounded(command)
    }

    fn doctor(&self) -> Output {
        self.doctor_in(&self.project, &self.state)
    }

    fn doctor_in(&self, project: &Path, state: &Path) -> Output {
        let mut command = self.command_in(project, state);
        command.arg("doctor");
        bounded(command)
    }

    /// The exact `active images:` row this fixture must render, path included.
    fn active_row(&self, boot: &str, output: &str, unclaimed: usize) -> String {
        format!(
            "active images: boot={boot}, output={output}, unclaimed={unclaimed} [{}]",
            self.pins().display()
        )
    }
}

/// AC1/AC7: an absent store and a literal empty v2 store both list only the
/// header and report a zero-count row, and neither is created or rewritten.
#[test]
fn pins_and_doctor_fresh_and_empty_stores_are_read_only() {
    let h = Harness::new(Mode::LaunchSeam);
    assert!(
        !config_dir(&h).exists(),
        "the fixture starts without authority"
    );

    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    assert_eq!(stdout_of(&listing), PINS_HEADER);
    assert_eq!(stderr(&listing), "");
    assert!(!config_dir(&h).exists(), "a listing creates no authority");

    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));
    assert_active_row(
        &stdout_of(&doctor),
        &h.active_row("not recorded", "not recorded", 0),
    );
    assert!(
        !config_dir(&h).exists(),
        "the active row needs no authority to exist"
    );

    // The literal empty v2 file: version, pins and pending_default only.
    let empty = br#"{"version":2,"pins":[],"pending_default":null}"#.to_vec();
    seed_store(&h, &empty);
    let before = store_snapshot(&h);
    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    assert_eq!(stdout_of(&listing), PINS_HEADER);
    assert_eq!(stderr(&listing), "");
    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));
    assert_active_row(
        &stdout_of(&doctor),
        &h.active_row("not recorded", "not recorded", 0),
    );
    assert_eq!(store_snapshot(&h), before, "neither verb writes authority");
}

/// AC1/R4/D2: only a *present* authority needs its regular coordination file. A
/// stale directory, symlink or FIFO left at the lock path beside **no** record is
/// not damage: the projection is the same empty listing and zero-count row an
/// absent store produces, and nothing is created, replaced or repaired.
#[test]
fn pins_absent_record_with_a_stale_nonregular_lock_is_an_empty_listing() {
    for kind in ["symlink", "directory", "fifo"] {
        let h = Harness::new(Mode::LaunchSeam);
        let lock = config_dir(&h).join("image-pins.lock");
        let target = config_dir(&h).join("lock-target");
        fs::create_dir_all(config_dir(&h)).unwrap();
        match kind {
            "symlink" => std::os::unix::fs::symlink(&target, &lock).unwrap(),
            "directory" => fs::create_dir(&lock).unwrap(),
            _ => {
                let path = std::ffi::CString::new(lock.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        let before = authority_inventory(&h);

        let listing = h.pins_listing();
        assert_eq!(
            listing.status.code(),
            Some(0),
            "an absent store needs no lock ({kind}): {}",
            stderr(&listing)
        );
        assert_eq!(stdout_of(&listing), PINS_HEADER, "{kind}");
        assert_eq!(stderr(&listing), "", "{kind} is silent on success");
        assert!(!h.pins().exists(), "{kind}: the record stays absent");

        // Doctor's *active* row is the absent-store row. Its default rows read
        // the same directory through the locked path, so they still report the
        // bad lock and the command still exits 1; that is pre-existing behaviour
        // for an unusable coordination file, not this row's finding.
        let doctor = h.doctor();
        assert_active_row(
            &stdout_of(&doctor),
            &h.active_row("not recorded", "not recorded", 0),
        );
        assert!(!h.pins().exists(), "{kind}: doctor creates no record");
        assert_eq!(
            authority_inventory(&h),
            before,
            "{kind}: neither verb replaces, repairs or removes the lock"
        );
        assert!(!target.exists(), "{kind}: the symlink target stays absent");
    }
}

/// AC2: legacy uncertainty is rendered, never collapsed. A no-role record in an
/// unresolved scope is `none` with both slots unresolved; once a slot resolves
/// (with its own holder elsewhere in the scope) only the other stays unresolved.
#[test]
fn pins_and_doctor_preserve_legacy_uncertainty() {
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);

    // (a) The literal pre-roles v2 record: no roles, no scopes, no sequence.
    let legacy = store_bytes(
        vec![serde_json::json!({
            "project": project,
            "reference": "example.com/x:tag",
            "platform": host_platform_json(),
            "manifest_digest": digest('a'),
            "revision": 7,
        })],
        Vec::new(),
        None,
    );
    seed_store(&h, &legacy);
    let before = store_snapshot(&h);
    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    assert_eq!(
        stdout_of(&listing),
        expected_listing(&[pins_row(
            "example.com/x:tag",
            &host_platform(),
            &digest('a'),
            7,
            "none",
            "boot+output"
        )])
    );
    assert_eq!(stderr(&listing), "");
    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));
    assert_active_row(
        &stdout_of(&doctor),
        &h.active_row("not recorded", "not recorded", 1),
    );
    assert_eq!(store_snapshot(&h), before, "omitted fields stay omitted");

    // (b) Boot resolved, held by another record: the old row keeps `output`
    // unresolved and is still counted as unclaimed, never as safe to retire.
    let boot_resolved = store_bytes(
        vec![
            pin_json(
                &project,
                "example.com/k:tag",
                &host_platform_json(),
                &digest('b'),
                1,
                Some("boot"),
            ),
            pin_json(
                &project,
                "example.com/x:tag",
                &host_platform_json(),
                &digest('a'),
                2,
                None,
            ),
        ],
        vec![scope_json(&project, &host_platform_json(), "boot")],
        Some(2),
    );
    seed_store(&h, &boot_resolved);
    let before = store_snapshot(&h);
    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    assert_eq!(
        stdout_of(&listing),
        expected_listing(&[
            pins_row(
                "example.com/k:tag",
                &host_platform(),
                &digest('b'),
                1,
                "boot",
                "output"
            ),
            pins_row(
                "example.com/x:tag",
                &host_platform(),
                &digest('a'),
                2,
                "none",
                "output"
            ),
        ])
    );
    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));
    assert_active_row(
        &stdout_of(&doctor),
        &h.active_row("recorded", "not recorded", 1),
    );
    assert_eq!(store_snapshot(&h), before);

    // (c) The symmetric case: Output resolved and held elsewhere.
    let output_resolved = store_bytes(
        vec![
            pin_json(
                &project,
                "example.com/o:tag",
                &host_platform_json(),
                &digest('c'),
                1,
                Some("output"),
            ),
            pin_json(
                &project,
                "example.com/x:tag",
                &host_platform_json(),
                &digest('a'),
                2,
                None,
            ),
        ],
        vec![scope_json(&project, &host_platform_json(), "output")],
        Some(2),
    );
    seed_store(&h, &output_resolved);
    let before = store_snapshot(&h);
    let listing = h.pins_listing();
    assert_eq!(
        stdout_of(&listing),
        expected_listing(&[
            pins_row(
                "example.com/o:tag",
                &host_platform(),
                &digest('c'),
                1,
                "output",
                "boot"
            ),
            pins_row(
                "example.com/x:tag",
                &host_platform(),
                &digest('a'),
                2,
                "none",
                "boot"
            ),
        ])
    );
    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));
    assert_active_row(
        &stdout_of(&doctor),
        &h.active_row("not recorded", "recorded", 1),
    );
    assert_eq!(store_snapshot(&h), before);
}

/// AC3: one record holding both roles, one known-inactive refresh record. The
/// listing prints the record's own revision (not the file's sequence), and
/// doctor counts only the unheld record as unclaimed.
#[test]
fn pins_and_doctor_render_shared_roles_and_known_inactive() {
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);
    let bytes = store_bytes(
        vec![
            pin_json(
                &project,
                "example.com/x:tag",
                &host_platform_json(),
                &digest('a'),
                7,
                Some("boot-and-output"),
            ),
            pin_json(
                &project,
                "example.com/v:tag",
                &host_platform_json(),
                &digest('b'),
                11,
                None,
            ),
        ],
        vec![scope_json(
            &project,
            &host_platform_json(),
            "boot-and-output",
        )],
        Some(19),
    );
    seed_store(&h, &bytes);
    let before = store_snapshot(&h);

    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    assert_eq!(stderr(&listing), "");
    assert_eq!(
        stdout_of(&listing),
        expected_listing(&[
            pins_row(
                "example.com/v:tag",
                &host_platform(),
                &digest('b'),
                11,
                "none",
                "none"
            ),
            pins_row(
                "example.com/x:tag",
                &host_platform(),
                &digest('a'),
                7,
                "boot+output",
                "none"
            ),
        ]),
        "the stored sequence 19 is never substituted for a record's revision"
    );

    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));
    assert_active_row(
        &stdout_of(&doctor),
        &h.active_row("recorded", "recorded", 1),
    );
    assert_eq!(store_snapshot(&h), before);
}

/// AC4/AC7: the listing is every platform of this project; the row counts only
/// the measured host platform. The fixture's foreign Output holder and foreign
/// unclaimed record make a wrong filter change Output and unclaimed, not just
/// some other field.
#[test]
fn pins_lists_all_platforms_but_doctor_counts_only_host() {
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);
    let other_project = h.project_at("other");
    let other_id = project_id(&other_project);
    let host = host_platform_json();
    let foreign = platform_json(foreign_arch(), None);
    let variant = platform_json(image_archive::host_arch(), Some("v8"));

    // Shuffled on purpose: order is the listing's, not the file's.
    let bytes = store_bytes(
        vec![
            pin_json(
                &project,
                "example.com/q:tag",
                &foreign,
                &digest('e'),
                5,
                Some("boot"),
            ),
            pin_json(&project, "example.com/n:tag", &host, &digest('b'), 2, None),
            pin_json(
                &project,
                "example.com/p:tag",
                &variant,
                &digest('d'),
                4,
                None,
            ),
            pin_json(
                &project,
                "example.com/m:tag",
                &host,
                &digest('a'),
                1,
                Some("boot"),
            ),
            pin_json(
                &other_id,
                "example.com/zzz-private:tag",
                &host,
                &digest('f'),
                6,
                Some("boot"),
            ),
            pin_json(
                &project,
                "example.com/o:tag",
                &foreign,
                &digest('c'),
                3,
                Some("output"),
            ),
            // One reference on three platforms: the listing keeps every row, and
            // the order inside the reference is the rendered platform's bytes.
            pin_json(
                &project,
                "example.com/shared:tag",
                &variant,
                &digest('3'),
                9,
                None,
            ),
            pin_json(
                &project,
                "example.com/shared:tag",
                &host,
                &digest('1'),
                7,
                None,
            ),
            pin_json(
                &project,
                "example.com/shared:tag",
                &foreign,
                &digest('2'),
                8,
                None,
            ),
        ],
        vec![
            scope_json(&project, &host, "boot"),
            scope_json(&project, &foreign, "boot-and-output"),
            scope_json(&other_id, &host, "boot"),
        ],
        Some(9),
    );
    seed_store(&h, &bytes);
    let before = store_snapshot(&h);

    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    let foreign_platform = format!("linux/{}", foreign_arch());
    let variant_platform = format!("linux/{}/v8", image_archive::host_arch());
    // The same reference on three platforms, in raw rendered-platform order and
    // each with its own digest and knowledge: host = Boot resolved, foreign = both
    // resolved, variant = no scope at all.
    let mut shared = [
        (
            host_platform(),
            pins_row(
                "example.com/shared:tag",
                &host_platform(),
                &digest('1'),
                7,
                "none",
                "output",
            ),
        ),
        (
            foreign_platform.clone(),
            pins_row(
                "example.com/shared:tag",
                &foreign_platform,
                &digest('2'),
                8,
                "none",
                "none",
            ),
        ),
        (
            variant_platform.clone(),
            pins_row(
                "example.com/shared:tag",
                &variant_platform,
                &digest('3'),
                9,
                "none",
                "boot+output",
            ),
        ),
    ];
    shared.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let shared_rows: Vec<String> = shared.into_iter().map(|(_, row)| row).collect();
    assert_eq!(
        stdout_of(&listing),
        expected_listing(&[
            pins_row(
                "example.com/m:tag",
                &host_platform(),
                &digest('a'),
                1,
                "boot",
                "output"
            ),
            pins_row(
                "example.com/n:tag",
                &host_platform(),
                &digest('b'),
                2,
                "none",
                "output"
            ),
            pins_row(
                "example.com/o:tag",
                &foreign_platform,
                &digest('c'),
                3,
                "output",
                "none"
            ),
            pins_row(
                "example.com/p:tag",
                &variant_platform,
                &digest('d'),
                4,
                "none",
                "boot+output"
            ),
            pins_row(
                "example.com/q:tag",
                &foreign_platform,
                &digest('e'),
                5,
                "boot",
                "none"
            ),
            shared_rows[0].clone(),
            shared_rows[1].clone(),
            shared_rows[2].clone(),
        ]),
        "another project's approval never appears"
    );

    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));
    assert!(
        !stdout_of(&doctor).contains("zzz-private"),
        "the row carries no reference: {}",
        stdout_of(&doctor)
    );
    // Host: `n` and `example.com/shared:tag` are unclaimed; the two foreign
    // `shared` rows and the foreign Output holder never contribute.
    assert_active_row(
        &stdout_of(&doctor),
        &h.active_row("recorded", "not recorded", 2),
    );
    assert_eq!(store_snapshot(&h), before);

    // From a project with no approvals: header only, zero counts.
    let empty = h.project_at("empty");
    let state = h.project_at("empty-state");
    let listing = h.pins_listing_in(&empty, &state);
    assert_eq!(stdout_of(&listing), PINS_HEADER);
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    let doctor = h.doctor_in(&empty, &state);
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));
    assert_eq!(
        stdout_of(&doctor)
            .lines()
            .filter(|line| line.starts_with("active images: "))
            .collect::<Vec<_>>(),
        [format!(
            "active images: boot=not recorded, output=not recorded, unclaimed=0 [{}]",
            h.pins().display()
        )]
    );
    assert_eq!(store_snapshot(&h), before);
}

/// AC5: every damaged authority fails both surfaces safely. The sentinel proves
/// no offending byte, reference or digest reaches either stream.
#[test]
fn pins_and_doctor_reject_damaged_authority_without_disclosure() {
    const SENTINEL: &str = "PRIVATE-SENTINEL";
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);
    let host = host_platform_json();
    let valid_record = serde_json::json!({
        "project": project,
        "reference": format!("secret.example/{SENTINEL}:1"),
        "platform": host,
        "manifest_digest": digest('a'),
        "revision": 1,
    });
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "broken json",
            format!("{{\"pins\": [\"{SENTINEL}\"]").into_bytes(),
            CORRUPT_MESSAGE,
        ),
        (
            "duplicate key",
            store_bytes(
                vec![
                    valid_record.clone(),
                    pin_json(&project, &format!("secret.example/{SENTINEL}:1"), &host, &digest('b'), 2, None),
                ],
                Vec::new(),
                None,
            ),
            CORRUPT_MESSAGE,
        ),
        (
            "roles with no scope",
            store_bytes(
                vec![pin_json(&project, &format!("secret.example/{SENTINEL}:1"), &host, &digest('a'), 1, Some("boot"))],
                Vec::new(),
                Some(1),
            ),
            CORRUPT_MESSAGE,
        ),
        (
            "explicit null role",
            format!(
                "{{\"version\":2,\"pins\":[{{\"project\":\"{project}\",\"reference\":\"secret.example/{SENTINEL}:1\",\"platform\":{host},\"manifest_digest\":\"{}\",\"revision\":1,\"roles\":null}}],\"pending_default\":null,\"sequence\":1}}",
                digest('a')
            )
            .into_bytes(),
            CORRUPT_MESSAGE,
        ),
        (
            "explicit empty role",
            format!(
                "{{\"version\":2,\"pins\":[{{\"project\":\"{project}\",\"reference\":\"secret.example/{SENTINEL}:1\",\"platform\":{host},\"manifest_digest\":\"{}\",\"revision\":1,\"roles\":\"\"}}],\"pending_default\":null,\"sequence\":1}}",
                digest('a')
            )
            .into_bytes(),
            CORRUPT_MESSAGE,
        ),
        (
            "wrong version",
            format!(
                "{{\"version\":3,\"pins\":[],\"pending_default\":null,\"junk\":\"{SENTINEL}\"}}"
            )
            .into_bytes(),
            CORRUPT_MESSAGE,
        ),
        (
            "version 1",
            legacy_store(),
            N1_V1,
        ),
        (
            "oversized",
            vec![b' '; 4 * 1024 * 1024 + 1],
            CORRUPT_MESSAGE,
        ),
        (
            "malformed foreign record",
            store_bytes(
                vec![
                    pin_json(&project, &format!("secret.example/{SENTINEL}:1"), &host, &digest('a'), 1, None),
                    pin_json(&project_id(&h.project_at("other")), "not a reference", &host, &digest('b'), 2, None),
                ],
                Vec::new(),
                None,
            ),
            CORRUPT_MESSAGE,
        ),
    ];
    for (label, bytes, expected) in cases {
        seed_store(&h, &bytes);
        let before = store_snapshot(&h);
        let listing = h.pins_listing();
        assert_eq!(
            listing.status.code(),
            Some(1),
            "{label}: {}",
            stderr(&listing)
        );
        assert_eq!(stdout_of(&listing), "", "{label} prints no listing");
        let message = stderr(&listing);
        assert_eq!(
            message,
            format!("Error: {expected}\n"),
            "{label}: the store-owned message itself, exactly"
        );
        for leaked in [SENTINEL, "secret.example", "sha256:"] {
            assert!(
                !message.contains(leaked),
                "{label} leaks {leaked}: {message}"
            );
        }
        let doctor = h.doctor();
        assert_eq!(
            doctor.status.code(),
            Some(1),
            "{label}: {}",
            stdout_of(&doctor)
        );
        let stdout = stdout_of(&doctor);
        let rows: Vec<&str> = stdout
            .lines()
            .filter(|line| line.starts_with("active images: "))
            .collect();
        assert_eq!(rows.len(), 1, "{label}: exactly one row: {stdout}");
        assert_eq!(
            rows[0],
            format!("active images: error: {expected}"),
            "{label}: the store-owned message itself, exactly"
        );
        assert!(
            stdout.contains("==> agent-vm doctor: available operations"),
            "{label}: later sections still print"
        );
        for leaked in [SENTINEL, "secret.example", "sha256:"] {
            assert!(
                !stdout.contains(leaked) && !stderr(&doctor).contains(leaked),
                "{label} leaks {leaked}: {stdout}{}",
                stderr(&doctor)
            );
        }
        assert_eq!(store_snapshot(&h), before, "{label} is not repaired");
    }

    // A store path that is not a regular file: the bounded no-follow reader
    // refuses it, and a FIFO cannot hang the harness.
    for kind in ["symlink", "directory", "fifo"] {
        let h = Harness::new(Mode::LaunchSeam);
        seed_store(&h, b"{}");
        fs::remove_file(h.pins()).unwrap();
        let target = config_dir(&h).join("real-store.json");
        match kind {
            "symlink" => {
                fs::write(&target, b"{}").unwrap();
                std::os::unix::fs::symlink(&target, h.pins()).unwrap();
            }
            "directory" => fs::create_dir(h.pins()).unwrap(),
            _ => {
                let path = std::ffi::CString::new(h.pins().as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        let before = authority_inventory(&h);
        let listing = h.pins_listing();
        assert_eq!(
            listing.status.code(),
            Some(1),
            "{kind}: {}",
            stderr(&listing)
        );
        assert_eq!(stdout_of(&listing), "", "{kind} prints no listing");
        assert_eq!(
            stderr(&listing),
            format!("Error: {CORRUPT_MESSAGE}\n"),
            "{kind}: the store-owned message itself, exactly"
        );
        let doctor = h.doctor();
        assert_eq!(
            doctor.status.code(),
            Some(1),
            "{kind}: {}",
            stdout_of(&doctor)
        );
        assert_active_row(
            &stdout_of(&doctor),
            &format!("active images: error: {CORRUPT_MESSAGE}"),
        );
        assert_eq!(
            authority_inventory(&h),
            before,
            "{kind}: neither verb rewrites the special store path, the lock or              the symlink target"
        );
        assert_eq!(
            std::fs::symlink_metadata(&target).is_ok(),
            kind == "symlink"
        );
    }
}

/// AC5/AC9 N1: a directory coordination file must fail *access* before the
/// record is read, so a malformed or v1 record never supplies the message.
#[test]
fn pins_directory_lock_errors_precede_malformed_or_v1_record() {
    for bytes in [b"not json".to_vec(), legacy_store()] {
        let h = Harness::new(Mode::LaunchSeam);
        fs::create_dir_all(config_dir(&h)).unwrap();
        fs::write(h.pins(), &bytes).unwrap();
        fs::create_dir(config_dir(&h).join("image-pins.lock")).unwrap();
        let before = store_snapshot(&h);

        let listing = h.pins_listing();
        assert_eq!(listing.status.code(), Some(1), "{}", stderr(&listing));
        assert_eq!(stdout_of(&listing), "");
        assert_eq!(stderr(&listing), format!("Error: {N1_ACCESS}\n"));
        for absent in ["damaged", "version 1 format"] {
            assert!(
                !stderr(&listing).contains(absent),
                "the shape check precedes the read: {}",
                stderr(&listing)
            );
        }
        assert_eq!(store_snapshot(&h), before);
    }
    assert!(!N1_V1.is_empty());
}

/// AC5/AC8: a record without its stable lock is damage on both surfaces, and a
/// usage error is decided before any read — even with a damaged store.
#[test]
fn pins_missing_lock_is_damage_and_usage_precedes_read() {
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);
    let bytes = store_bytes(
        vec![pin_json(
            &project,
            "example.com/x:tag",
            &host_platform_json(),
            &digest('a'),
            1,
            Some("boot"),
        )],
        vec![scope_json(&project, &host_platform_json(), "boot")],
        Some(1),
    );
    seed_store(&h, &bytes);
    fs::remove_file(config_dir(&h).join("image-pins.lock")).unwrap();
    let before = store_snapshot(&h);

    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(1), "{}", stderr(&listing));
    assert_eq!(stdout_of(&listing), "");
    assert!(stderr(&listing).contains("damaged"), "{}", stderr(&listing));
    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(1), "{}", stdout_of(&doctor));
    assert!(
        stdout_of(&doctor).contains("active images: error: image pin authority"),
        "{}",
        stdout_of(&doctor)
    );

    for args in [
        vec!["image", "pins", "extra"],
        vec!["image", "pins", "--json"],
        vec!["image", "pins", "--yes"],
        vec!["image", "pins", "--image", "x:1"],
        vec!["--image", "x:1", "image", "pins"],
    ] {
        let mut command = h.command();
        command.args(&args);
        let out = bounded(command);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert_eq!(stdout_of(&out), "", "{args:?} prints nothing");
    }
    assert_eq!(store_snapshot(&h), before, "a missing lock stays missing");
}

/// AC6: the listing needs no configuration and the row survives a broken one.
#[test]
fn pins_ignores_broken_config_and_doctor_still_counts() {
    // (label, user config, project config, project config is a directory)
    for (label, user_config, project_config, project_directory) in [
        (
            "syntax-invalid user config",
            Some("broken = = toml\n"),
            None,
            false,
        ),
        (
            "syntax-invalid project config",
            None,
            Some("this is not = = toml\n"),
            false,
        ),
        ("config path is a directory", None, None, true),
        (
            "broken catalog with a usable image",
            None,
            Some(
                "image = \"127.0.0.1:1/project:dev\"\n[[tools]]\nname = \"t\"\ncommand = \"t\"\ntools = [\"missing\"]\n",
            ),
            false,
        ),
    ] {
        let h = Harness::new(Mode::LaunchSeam);
        if let Some(config) = user_config {
            fs::create_dir_all(config_dir(&h)).unwrap();
            fs::write(config_dir(&h).join("config.toml"), config).unwrap();
        }
        let project_config_path = h.project.join(".agent-vm/config.toml");
        if project_directory {
            fs::create_dir_all(&project_config_path).unwrap();
        } else if let Some(config) = project_config {
            fs::create_dir_all(project_config_path.parent().unwrap()).unwrap();
            fs::write(&project_config_path, config).unwrap();
        }
        let project = project_id(&h.project);
        let host = host_platform_json();
        let bytes = store_bytes(
            vec![pin_json(
                &project,
                "example.com/x:tag",
                &host,
                &digest('a'),
                1,
                Some("boot"),
            )],
            vec![scope_json(&project, &host, "boot")],
            Some(1),
        );
        seed_store(&h, &bytes);
        let before = store_snapshot(&h);

        let listing = h.pins_listing();
        assert_eq!(
            listing.status.code(),
            Some(0),
            "{label}: {}",
            stderr(&listing)
        );
        assert_eq!(stderr(&listing), "", "{label}");
        assert_eq!(
            stdout_of(&listing),
            expected_listing(&[pins_row(
                "example.com/x:tag",
                &host_platform(),
                &digest('a'),
                1,
                "boot",
                "output"
            )]),
            "{label}"
        );

        let doctor = h.doctor();
        assert_eq!(
            doctor.status.code(),
            Some(1),
            "{label}: {}",
            stdout_of(&doctor)
        );
        assert_active_row(
            &stdout_of(&doctor),
            &h.active_row("recorded", "not recorded", 0),
        );
        // The two configuration branches are distinct, and the row appears in
        // both: an unreadable configuration says so, a readable image with a
        // broken catalog still renders the tier rows.
        let stdout = stdout_of(&doctor);
        let broken_catalog = label == "broken catalog with a usable image";
        assert_eq!(
            stdout.contains("unknown (configuration could not be read)"),
            !broken_catalog,
            "{label} must take its own configuration branch:\n{stdout}"
        );
        assert_eq!(
            stdout.contains("user:    "),
            broken_catalog,
            "{label} must render the tier rows only when they are readable:\n{stdout}"
        );
        assert_eq!(store_snapshot(&h), before, "{label}");
    }
}

/// AC7/AC8: a location failure is status 1 with no listing; a usage error is
/// status 2 before anything is read.
#[test]
fn pins_location_and_argument_failures_have_exact_statuses() {
    let h = Harness::new(Mode::LaunchSeam);
    for home in ["", "relative/home"] {
        let mut command = h.command();
        command.env("HOME", home);
        command.args(["image", "pins"]);
        let out = bounded(command);
        assert_eq!(
            out.status.code(),
            Some(1),
            "HOME={home:?}: {}",
            stderr(&out)
        );
        assert_eq!(stdout_of(&out), "");
        assert!(
            stderr(&out).contains("could not be accessed or saved"),
            "HOME={home:?}: {}",
            stderr(&out)
        );
        // Doctor reports the same unlocatable authority as a safe error row —
        // never zero counts and never `unknown (the project could not be
        // captured)` — with no path suffix and no added failure.
        let mut command = h.command();
        command.env("HOME", home).arg("doctor");
        let doctor = bounded(command);
        let stdout = stdout_of(&doctor);
        let lines: Vec<&str> = stdout.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.starts_with("active images: "))
            .unwrap_or_else(|| panic!("HOME={home:?}: no active row:\n{stdout}"));
        assert_eq!(
            lines[at],
            "active images: error: image pin authority at $HOME/.config/agent-vm/image-pins.json could not be accessed or saved",
            "HOME={home:?}"
        );
        assert!(!lines[at].contains('['), "HOME={home:?}: no path suffix");
        assert!(
            !stderr(&doctor).contains("image pin authority"),
            "HOME={home:?}: an unlocatable store adds no failure: {}",
            stderr(&doctor)
        );
    }
    let mut command = h.command();
    command.env_remove("HOME");
    command.args(["image", "pins"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout_of(&out), "");
    assert!(stderr(&out).contains("could not be accessed or saved"));

    assert!(
        !config_dir(&h).exists(),
        "no failing location case creates authority"
    );
}

/// AC9: only stdout discloses. Trace logging and the debug dump must not carry
/// the stored reference or digest, and the row cannot either.
#[test]
fn pins_discloses_only_stdout_and_doctor_row_is_redacted() {
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);
    // A canonical reference: OCI repository names are lowercase, so a
    // sentinel that could not be stored would fail the file instead.
    let reference = "private.example/secret-ref:1";
    let stored = digest('d');
    let bytes = store_bytes(
        vec![pin_json(
            &project,
            reference,
            &host_platform_json(),
            &stored,
            3,
            Some("boot"),
        )],
        vec![scope_json(&project, &host_platform_json(), "boot")],
        Some(3),
    );
    seed_store(&h, &bytes);
    let before = store_snapshot(&h);

    let mut command = h.command();
    command
        .env("RUST_LOG", "trace")
        .env("AGENT_VM_DEBUG_CONFIG", "1")
        .args(["image", "pins"]);
    let out = bounded(command);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let tsv = expected_listing(&[pins_row(
        reference,
        &host_platform(),
        &stored,
        3,
        "boot",
        "output",
    )]);
    assert_eq!(stdout_of(&out), tsv);
    // The seeded values themselves, not a different sentinel: this is the one
    // surface allowed to print them, and nothing else may.
    for leak in [reference, stored.as_str()] {
        assert!(
            !stderr(&out).contains(leak),
            "listing stderr leaks {leak}: {}",
            stderr(&out)
        );
        let beyond_the_listing = stdout_of(&out).replace(&tsv, "");
        assert!(
            !beyond_the_listing.contains(leak),
            "the listing repeats {leak} outside its one TSV block: {beyond_the_listing:?}"
        );
    }

    let mut command = h.command();
    command
        .env("RUST_LOG", "trace")
        .env("AGENT_VM_DEBUG_CONFIG", "1")
        .arg("doctor");
    let doctor = bounded(command);
    assert_eq!(doctor.status.code(), Some(0), "{}", stderr(&doctor));
    for leak in [reference, stored.as_str()] {
        assert!(
            !stdout_of(&doctor).contains(leak),
            "the report leaks {leak}: {}",
            stdout_of(&doctor)
        );
        assert!(
            !stderr(&doctor).contains(leak),
            "doctor stderr leaks {leak}: {}",
            stderr(&doctor)
        );
    }
    assert_active_row(
        &stdout_of(&doctor),
        &h.active_row("recorded", "not recorded", 0),
    );
    assert_eq!(store_snapshot(&h), before);
}

/// AC6/AC9: the invalid-environment branch renders the row directly after its
/// refusal, invents no default/selected rows, and leaves the environment
/// diagnostic as the single stderr failure — even when the store is damaged.
#[test]
fn doctor_invalid_environment_still_reports_active_images() {
    let invalid = || {
        use std::os::unix::ffi::OsStringExt as _;
        std::ffi::OsString::from_vec(b"not-\xff-utf8".to_vec())
    };
    let expected_stderr = "Error: AGENT_VM_IMAGE_TAG is set but is not valid Unicode; doctor cannot report a selected image\n";

    // (a) Healthy store: the available row.
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);
    let bytes = store_bytes(
        vec![pin_json(
            &project,
            "example.com/x:tag",
            &host_platform_json(),
            &digest('a'),
            1,
            Some("boot"),
        )],
        vec![scope_json(&project, &host_platform_json(), "boot")],
        Some(1),
    );
    seed_store(&h, &bytes);
    let before = store_snapshot(&h);
    let mut command = h.command();
    command.env("AGENT_VM_IMAGE_TAG", invalid()).arg("doctor");
    let doctor = bounded(command);
    assert_eq!(doctor.status.code(), Some(1), "{}", stdout_of(&doctor));
    assert_eq!(stderr(&doctor), expected_stderr);
    let stdout = stdout_of(&doctor);
    let lines: Vec<&str> = stdout.lines().collect();
    let refusal = lines
        .iter()
        .position(|line| {
            *line == "AGENT_VM_IMAGE_TAG: <present but not valid Unicode; refusing to select>"
        })
        .unwrap_or_else(|| panic!("no refusal line:\n{stdout}"));
    assert_eq!(
        lines[refusal - 1],
        "==> boot image",
        "the refusal owns its section:\n{stdout}"
    );
    assert_eq!(
        Some(lines[refusal + 1]),
        Some(h.active_row("recorded", "not recorded", 0).as_str()),
        "the row follows the refusal immediately:\n{stdout}"
    );
    assert_eq!(
        boot_image_section(&stdout),
        [
            "==> boot image",
            "AGENT_VM_IMAGE_TAG: <present but not valid Unicode; refusing to select>",
            h.active_row("recorded", "not recorded", 0).as_str(),
        ],
        "no user/project/default/selected row is invented:\n{stdout}"
    );
    assert!(
        stdout.contains("==> agent-vm doctor: available operations"),
        "later sections still print:\n{stdout}"
    );
    assert_eq!(store_snapshot(&h), before);

    // (b) Damaged located store: the row reports it, the refusal still owns
    // stderr, and the status is unchanged.
    let h = Harness::new(Mode::LaunchSeam);
    fs::create_dir_all(config_dir(&h)).unwrap();
    fs::write(h.pins(), b"not json").unwrap();
    fs::write(config_dir(&h).join("image-pins.lock"), b"").unwrap();
    let before = store_snapshot(&h);
    let mut command = h.command();
    command.env("AGENT_VM_IMAGE_TAG", invalid()).arg("doctor");
    let doctor = bounded(command);
    assert_eq!(doctor.status.code(), Some(1), "{}", stdout_of(&doctor));
    assert_eq!(
        stderr(&doctor),
        expected_stderr,
        "the environment refusal keeps stderr precedence"
    );
    let stdout = stdout_of(&doctor);
    let lines: Vec<&str> = stdout.lines().collect();
    let refusal = lines
        .iter()
        .position(|line| {
            *line == "AGENT_VM_IMAGE_TAG: <present but not valid Unicode; refusing to select>"
        })
        .unwrap_or_else(|| panic!("no refusal line:\n{stdout}"));
    assert_eq!(
        Some(lines[refusal + 1]),
        Some(
            "active images: error: image pin authority at $HOME/.config/agent-vm/image-pins.json is damaged; restore its intended records from backup or deliberately move it aside to reset approvals"
        ),
        "{stdout}"
    );
    let section = boot_image_section(&stdout);
    assert!(
        stdout.contains("==> agent-vm doctor: available operations"),
        "later sections still print:\n{stdout}"
    );
    assert_eq!(
        section.len(),
        3,
        "the section ends after the row:\n{stdout}"
    );
    assert!(
        !section
            .iter()
            .any(|line| line.starts_with("selected (without --image):")),
        "{stdout}"
    );
    assert_eq!(store_snapshot(&h), before);
}

/// AC10: `image show` keeps reporting the ambient selection, not what was
/// recorded, before and after the listing exists.
#[test]
fn image_show_still_reports_ambient_not_recorded_boot() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.image(&ArchiveSpec::default());
    let recorded = server.image("images", "recorded", &image);
    let launch = h.launch(&recorded);
    assert!(!launch.status.success(), "the fake runtime cannot boot");
    assert_eq!(
        h.pin_for(&recorded).map(|(digest, _)| digest),
        Some(digest_of(&recorded)),
        "the launch recorded the immutable selection"
    );

    let ambient = "127.0.0.1:1/ambient:dev";
    let expected = format!("Image: {ambient}\nSource: AGENT_VM_IMAGE_TAG\n");
    let show = |h: &Harness| {
        let mut command = h.command();
        command
            .env("AGENT_VM_IMAGE_TAG", ambient)
            .args(["image", "show"]);
        bounded(command)
    };
    let first = show(&h);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert_eq!(stderr(&first), "", "a successful show is silent");
    assert_eq!(stdout_of(&first), expected);

    let before = store_snapshot(&h);
    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    assert_eq!(
        stdout_of(&listing),
        expected_listing(&[pins_row(
            &recorded,
            &host_platform(),
            &digest_of(&recorded),
            1,
            "boot",
            "output"
        )]),
        "the listing shows the approval history, not the ambient selection"
    );
    assert!(!stdout_of(&listing).contains(ambient));
    let doctor = h.doctor();
    assert_eq!(doctor.status.code(), Some(0), "{}", stdout_of(&doctor));

    let second = show(&h);
    assert_eq!(
        second.status.code(),
        Some(0),
        "the report and the status are unchanged: {}",
        stderr(&second)
    );
    assert_eq!(stderr(&second), "", "a successful show is silent");
    assert_eq!(stdout_of(&second), expected, "show's report is unchanged");
    assert_eq!(store_snapshot(&h), before, "neither verb writes the store");
}

/// AC11: the documented example is the shipped bytes.
#[test]
fn pins_usage_example_matches_literal_output() {
    const SAMPLE: &str = "registry.example/team/app:dev\tlinux/arm64\tsha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t7\tboot\toutput\n";
    let h = Harness::new(Mode::LaunchSeam);
    let project = project_id(&h.project);
    // The documented platform verbatim, even on a host that is not arm64: the
    // listing is platform-complete, so the sample is a valid store everywhere.
    let arm64 = platform_json("arm64", None);
    let bytes = store_bytes(
        vec![pin_json(
            &project,
            "registry.example/team/app:dev",
            &arm64,
            &digest('a'),
            7,
            Some("boot"),
        )],
        vec![scope_json(&project, &arm64, "boot")],
        Some(7),
    );
    seed_store(&h, &bytes);
    let before = store_snapshot(&h);
    let listing = h.pins_listing();
    assert_eq!(listing.status.code(), Some(0), "{}", stderr(&listing));
    assert_eq!(stdout_of(&listing), format!("{PINS_HEADER}{SAMPLE}"));

    // The USAGE console example, extracted by its command line rather than
    // retyped, must be those same bytes: a byte slice up to the closing fence, so
    // no line-ending normalization can hide a difference.
    let usage = include_str!("../../../USAGE.md");
    let section = usage
        .split_once("### Inspecting approved images")
        .expect("USAGE has the shipped section")
        .1;
    let after_command = section
        .split_once("$ agent-vm image pins\n")
        .expect("the section shows one pins invocation")
        .1;
    let (documented, _) = after_command
        .split_once("```")
        .expect("the console block is closed");
    assert_eq!(
        documented.as_bytes(),
        format!("{PINS_HEADER}{SAMPLE}").as_bytes(),
        "the shipped block is exactly the header and the one sample row"
    );
    assert_eq!(
        stdout_of(&listing).as_bytes(),
        documented.as_bytes(),
        "and the command prints those bytes unchanged"
    );
    assert_eq!(store_snapshot(&h), before);
}
