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

use fake_msb::{FakeMsb, Mode};
use image_archive::{ArchiveSpec, LayerContent, PlatformSpec};
use oci_registry::{Image, Server};
use pin_gate::{PinGate, PinPeer, PinStage, Reply};
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

    /// A pin for `reference` **and** a host record naming it: the fixture S1's
    /// `set-default` used to leave behind, now two explicit commands.
    fn pin_and_set_default(&self, reference: &str) {
        assert!(self.refresh(reference).status.success(), "pin the tag");
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
    assert!(h.refresh(&tag).status.success(), "first pin");
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
    assert!(h.refresh(&tag).status.success(), "first pin");
    let b = h.image(&ArchiveSpec {
        marker: "approval-terminal-b".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "terminal", &b);
    assert_ne!(pin_a, pin_b);

    let mut command = h.command();
    command.args(["image", "refresh", "--image", &tag]);
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

/// The exact command shape the pipe row needs: no stdin configured here, so the
/// helper can install its own recording pipe.
fn command_with_refresh(h: &Harness, tag: &str) -> Command {
    let mut command = h.command();
    command.args(["image", "refresh", "--image", tag]);
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
    assert!(h.refresh(&tag).status.success());
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

    // 1. Import A: revision 1.
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

    // 2. Import B: revision 2, rendered against A.
    let out = h.import(&b.path, &tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout_of(&out), import_notice(&tag));
    assert_render(&stderr(&out), &tag, &a.manifest_digest, &b.manifest_digest);
    assert_eq!(h.pin_for(&tag), Some((b.manifest_digest.clone(), 2)));
    assert_eq!(
        sdk_image(&h.launch(&tag)),
        format!("{}/images@{}", server.host, b.manifest_digest)
    );

    // 3. A rebuild under the same tag: revision 3, rendered against B.
    let out = h.build(&c.path, &tag);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout_of(&out), build_notice(&tag));
    assert_render(&stderr(&out), &tag, &b.manifest_digest, &c.manifest_digest);
    assert_eq!(h.pin_for(&tag), Some((c.manifest_digest.clone(), 3)));
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
    assert_eq!(h.pin_for(&tag), Some((c.manifest_digest.clone(), 3)));

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
    assert!(h.refresh(&tag).status.success(), "first pin");
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
    let refreshed = h.refresh(&tag);
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
        Some((b_digest.clone(), 1)),
        "the reference the command named is approved at the fixture's own manifest"
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
    assert_eq!(h.pin_for(&other), Some((b_digest, 1)));
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
        Some((b_digest.clone(), 1)),
        "the alias import approves its own result at the fixture's synthesized manifest"
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
        Some((digest_of(&child_b), 1)),
        "P2's own first pin, at revision 1"
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
        Some((digest_of(&child_c), 2)),
        "only P2's record is replaced, at revision 2"
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
        Some((digest_of(&child_b), 2)),
        "P1 replaces its own approval"
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
        Some((digest_of(&child_a), 1)),
        "a subdirectory's own first pin"
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
        Some((new.manifest_digest.clone(), 1)),
        "P1 approves its own result at revision 1"
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
        Some((new.manifest_digest.clone(), 1)),
        "P1 approves its own build result at revision 1"
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
    let mut command = h.command_in(&p2, &h.state);
    command.args(["image", "refresh", "--image", &tag]);
    let out = bounded(command);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(h.pin_in(&p2, &tag).unwrap().1, 1, "P2's own first approval");

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
    let out = h.refresh(&tag);
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
    assert!(h.refresh(&tag).status.success());
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
            assert!(h.refresh(&tag).status.success());
        }
        let b = h.image(&ArchiveSpec {
            marker: "frozen-b".into(),
            ..Default::default()
        });
        let child_b = server.image("images", "frozen", &b);
        let start = server.requests().len();
        let mut gate = PinGate::new(h.root.path());
        let peer = PinPeer::spawn(h.command(), &gate, &["image", verb, "--image", &tag]);
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
        assert!(h.refresh(&tag).status.success());
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
        let out = h.refresh(&tag);
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
    let peer = pin_gate::PinPeer::spawn(h.command(), &gate, &["image", "refresh", "--image", &tag]);
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
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(start.elapsed() >= Duration::from_secs(30));
    assert!(start.elapsed() < Duration::from_secs(38));
    assert_eq!(fs::read(h.pins()).unwrap(), old);
    assert_eq!(fs::read(default).unwrap(), old_default);
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    assert!(
        h.refresh(&tag).status.success(),
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
    let peer = pin_gate::PinPeer::spawn(h.command(), &gate, &["image", "refresh", "--image", &tag]);
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
    let out = peer.wait();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
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
    assert!(h.refresh(&tag).status.success());
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
    assert!(h.refresh(&tag).status.success());
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
        assert!(h.refresh(&child_a).status.success());
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
    assert!(
        stderr(&out).contains("requires recovery"),
        "{}",
        stderr(&out)
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
    assert!(h.refresh(&child_a).status.success());
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
    assert!(h.refresh(&source).status.success());
    assert_eq!(h.pinned_digest(), a.written.manifest_digest);
    assert_eq!(sdk_image(&h.launch(&source)), child);
    let old = fs::read(h.pins()).unwrap();
    index["manifests"][2]["digest"] = format!("sha256:{}", "d".repeat(64)).into();
    server.index("images", "filtered", serde_json::to_vec(&index).unwrap());
    let out = h.refresh(&source);
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
    assert!(h.refresh(&source).status.success());
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
    assert!(h.refresh(&child).status.success());
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
    assert_eq!(store["pins"], pins["pins"], "the approval is unchanged");
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
    assert!(h.refresh(&child).status.success());
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
    assert!(h.refresh(&child).status.success());
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
        Some((digest_of(&child_h), 1)),
        "the host reference's approval is inserted"
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
    assert!(h.refresh(&child).status.success());
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

    let mut command = h.command();
    command.arg("doctor");
    let doctor = bounded(command);
    assert!(!doctor.status.success(), "{}", stdout_of(&doctor));
    let text = stdout_of(&doctor);
    assert!(
        text.contains("default: error:"),
        "the host row reports the damage: {text}"
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

/// AC15: a bare refresh with an unreadable configuration refuses the
/// default-tier fall-through; `--image` and `AGENT_VM_IMAGE_TAG` still work and
/// establish nothing.
#[test]
fn a_bare_refresh_refuses_an_unreadable_config_but_an_explicit_one_works() {
    for tier in ["project", "user"] {
        for variant in ["bare", "cli", "env"] {
            let h = Harness::new(Mode::StrictAcquisition);
            let server = Server::new();
            let a = h.image(&ArchiveSpec::default());
            let child = server.image("images", "broken", &a);
            let reference = format!("{}/images:broken", server.host);
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

            let out = match variant {
                "bare" => h.refresh_default(),
                "cli" => h.refresh(&reference),
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
                "bare" => {
                    assert_eq!(out.status.code(), Some(1), "{tier}/{variant}: {text}");
                    assert!(
                        text.contains("does not fall back to the default boot image"),
                        "{tier}/{variant}: {text}"
                    );
                    assert_eq!(server.count(), 0, "{tier}/{variant}: no request");
                    assert!(!h.pins().exists(), "{tier}/{variant}: no pin store");
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
                    assert!(
                        stdout_of(&out).contains("configured image settings could not be read"),
                        "{tier}/{variant}: {}",
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

    let out = h.refresh(&child_b);
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
    assert!(h.refresh(&child_a).status.success());
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
    assert!(h.refresh(&child).status.success());
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
        Some((digest_of(&child_b), 1)),
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
