//! Host-wide OCI approval, driven through the compiled CLI (#390).
//!
//! Every row here is boot-free: a loopback OCI registry serves genuine tiny
//! images, the runtime is the complete fake `msb` + `libkrunfw` pair, and the
//! `create` call is expected to fail. That is the point — a pin records
//! *measured content*, not a successful boot, so a deliberate create failure is
//! the boundary these tests order against.
//!
//! The approval prompt rows run under a real pseudo-terminal (`support::pty`)
//! because the program requires both stdin and stderr to be terminals: a piped
//! run must refuse rather than answer for a human.

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

/// The prompt the approval path waits for. Asserted as a literal so a wording
/// change fails here rather than silently moving the expectation.
const PROMPT: &[u8] = b"Approve this exact image change? [y/N] ";

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

    fn refresh(&self, reference: &str, yes: bool) -> Output {
        let mut command = self.command();
        command.args(["image", "refresh", "--image", reference]);
        if yes {
            command.arg("--yes");
        }
        bounded(command)
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

fn bounded(mut command: Command) -> Output {
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
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

/// The full approval matrix for `image refresh`, through a real terminal.
fn approval_case(action: Action<'_>, expected_pin: PinChoice, label: &str) {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let b = h.image(&ArchiveSpec {
        marker: "approval-b".into(),
        ..Default::default()
    });
    let pin_a = server.image("images", "approve", &a);
    let tag = format!("{}/images:approve", server.host);
    assert!(h.refresh(&tag, false).status.success(), "first pin");
    let pin_b = server.image("images", "approve", &b);
    assert_ne!(pin_a, pin_b);

    let mut command = h.command();
    command.args(["image", "refresh", "--image", &tag]);
    let mut terminal = Pty::spawn(&mut command, PROMPT).expect("open a pseudo-terminal");
    let (status, out) = terminal
        .drive(&action, Duration::from_secs(60))
        .expect("drive the approval prompt");
    let text = String::from_utf8_lossy(&out);
    match expected_pin {
        PinChoice::Approved(()) => {
            assert!(status.success(), "{label}: {text}");
            assert!(text.contains("Replace the approved image for"), "{text}");
            assert!(text.contains("  old: sha256:"), "{text}");
            assert!(text.contains("  new: sha256:"), "{text}");
        }
        PinChoice::Declined => {
            // A refused answer exits 1; a signal that interrupts the prompt
            // terminates the process without publishing anything.
            assert!(
                !status.success(),
                "{label}: a declined or interrupted approval must fail: {text}"
            );
            assert!(
                !text.contains("acquired into the microsandbox image cache"),
                "{text}"
            );
        }
    }
    let expected = if expected_pin == PinChoice::Approved(()) {
        pin_b.rsplit_once('@').unwrap().1
    } else {
        pin_a.rsplit_once('@').unwrap().1
    };
    assert_eq!(
        h.pinned_digest(),
        expected,
        "{label}: pin unchanged/updated"
    );
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PinChoice {
    Approved(()),
    Declined,
}

#[test]
fn approval_prompt_yes_replaces_the_pin() {
    approval_case(Action::Write(b"y\n"), PinChoice::Approved(()), "y");
    approval_case(Action::Write(b"  YES  \n"), PinChoice::Approved(()), "YES");
}

#[test]
fn approval_prompt_no_empty_and_eof_decline() {
    approval_case(Action::Write(b"n\n"), PinChoice::Declined, "n");
    approval_case(Action::Write(b"\n"), PinChoice::Declined, "empty");
    // Ctrl-D on a canonical line is EOF with no answer.
    approval_case(Action::Write(b"\x04"), PinChoice::Declined, "ctrl-d");
    approval_case(
        Action::Write(b"yes please\n"),
        PinChoice::Declined,
        "invalid",
    );
}

#[test]
fn approval_prompt_interruption_declines() {
    approval_case(Action::Signal(libc::SIGINT), PinChoice::Declined, "sigint");
    approval_case(
        Action::Signal(libc::SIGTERM),
        PinChoice::Declined,
        "sigterm",
    );
}

/// `--yes` authorizes only the resolved candidate, and a piped run without it
/// refuses with actionable guidance instead of consuming stdin.
#[test]
fn noninteractive_refresh_refuses_and_yes_preauthorizes() {
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let pin_a = server.image("images", "piped", &a);
    let tag = format!("{}/images:piped", server.host);
    assert!(h.refresh(&tag, false).status.success());
    let b = h.image(&ArchiveSpec {
        marker: "piped-b".into(),
        ..Default::default()
    });
    let pin_b = server.image("images", "piped", &b);

    let refused = h.refresh(&tag, false);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    let text = stderr(&refused);
    assert!(text.contains("--yes"), "{text}");
    assert!(text.contains("image refresh --yes"), "{text}");
    assert!(
        text.contains("image set-default --image REF --yes"),
        "{text}"
    );
    assert_eq!(h.pinned_digest(), pin_a.rsplit_once('@').unwrap().1);

    let approved = h.refresh(&tag, true);
    assert!(approved.status.success(), "{}", stderr(&approved));
    assert_eq!(h.pinned_digest(), pin_b.rsplit_once('@').unwrap().1);
    // An unchanged refresh never asks again, with or without `--yes`.
    let unchanged = h.refresh(&tag, false);
    assert!(unchanged.status.success(), "{}", stderr(&unchanged));
    assert!(
        !stderr(&unchanged).contains("Approve"),
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
    assert!(h.refresh(&tag, false).status.success(), "first pin");
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
    let refreshed = h.refresh(&tag, true);
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
    command.args(["image", "refresh", "--image", &tag, "--yes"]);
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

/// Spec R4 through the prompt path: declining a replacement in P1 leaves every
/// other project's record untouched (it guards the prompt's key, not only the
/// `--yes` path's).
#[test]
fn a_declined_refresh_in_one_project_cannot_touch_another() {
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
    let p1_record = h.record_in(&h.project, &tag).unwrap();
    let p2_record = h.record_in(&p2, &tag).unwrap();
    assert_eq!(p2_record["manifest_digest"], digest_of(&child_a));

    // Move the tag, then decline the replacement in P1.
    let b = h.image(&ArchiveSpec {
        marker: "decline-b".into(),
        ..Default::default()
    });
    server.image("images", "decline", &b);
    let mut command = h.command();
    command.args(["image", "refresh", "--image", &tag]);
    let mut terminal = Pty::spawn(&mut command, PROMPT).expect("open a pseudo-terminal");
    let (status, out) = terminal
        .drive(&Action::Write(b"n\n"), Duration::from_secs(60))
        .expect("drive the approval prompt");
    let text = String::from_utf8_lossy(&out);
    assert!(!status.success(), "a declined approval fails: {text}");
    assert!(text.contains("Replace the approved image for"), "{text}");
    assert_eq!(h.record_in(&h.project, &tag).unwrap(), p1_record);
    assert_eq!(h.record_in(&p2, &tag).unwrap(), p2_record);
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
    command.args(["image", "refresh", "--image", &tag, "--yes"]);
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
/// changed. `--yes` changes nothing, a local path still reaches the runtime,
/// and once the store is archived the next launch makes a first pin.
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
        "refresh --yes",
        run(&["image", "refresh", "--image", &tag, "--yes"]),
    ));
    outputs.push((
        "set-default",
        run(&["image", "set-default", "--image", &tag]),
    ));
    outputs.push((
        "set-default --yes",
        run(&["image", "set-default", "--image", &tag, "--yes"]),
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
    let out = h.refresh(&tag, false);
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
    assert!(h.refresh(&tag, false).status.success());
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

#[test]
fn approval_freezes_b_when_the_displayed_tag_moves_to_c() {
    for verb in ["refresh", "set-default"] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        server.image("images", "frozen", &a);
        let tag = format!("{}/images:frozen", server.host);
        let mut cmd = h.command();
        cmd.args(["image", "set-default", "--image", &tag]);
        assert!(bounded(cmd).status.success());
        let b = h.image(&ArchiveSpec {
            marker: "frozen-b".into(),
            ..Default::default()
        });
        let child_b = server.image("images", "frozen", &b);
        let start = server.count();
        let mut cmd = h.command();
        cmd.args(["image", verb, "--image", &tag]);
        let mut terminal = Pty::spawn(&mut cmd, PROMPT).unwrap();
        let shown = terminal.wait_for_prompt(Duration::from_secs(60)).unwrap();
        let shown = String::from_utf8_lossy(&shown);
        assert!(shown.contains(&a.written.manifest_digest), "{shown}");
        assert!(shown.contains(&b.written.manifest_digest), "{shown}");
        let c = h.image(&ArchiveSpec {
            marker: "frozen-c".into(),
            ..Default::default()
        });
        server.image("images", "frozen", &c);
        let after_display = server.count();
        terminal.write_all(b"yes\n");
        let mut output = Vec::new();
        let status = terminal
            .wait_for_exit(&mut output, Duration::from_secs(60))
            .unwrap();
        assert!(status.success(), "{}", String::from_utf8_lossy(&output));
        assert_eq!(h.pinned_digest(), b.written.manifest_digest);
        assert_eq!(
            server.count(),
            after_display,
            "approval must not resolve the tag twice"
        );
        assert_eq!(
            server.requests()[start..]
                .iter()
                .filter(|(_, p)| p == "/v2/images/manifests/frozen")
                .count(),
            1
        );
        assert_eq!(sdk_image(&h.launch(&tag)), child_b);
        assert_eq!(
            server.count(),
            after_display,
            "future warm launch consumes B offline"
        );
        if verb == "set-default" {
            let default: serde_json::Value = serde_json::from_slice(
                &fs::read(h.home.join(".config/agent-vm/default-image.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(default, serde_json::json!({"version":1,"image":child_b}));
        }
    }
}

fn set_default(h: &Harness, tag: &str) -> Output {
    let mut cmd = h.command();
    cmd.args(["image", "set-default", "--image", tag, "--yes"]);
    bounded(cmd)
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn interrupted_pin_transactions_keep_old_logical_state_and_recover() {
    for stop in [
        PinStage::CandidateReady,
        PinStage::BeforeIntentSave,
        PinStage::IntentSaved,
        PinStage::DefaultSaved,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let child_a = server.image("images", "journal", &a);
        let tag = format!("{}/images:journal", server.host);
        assert!(set_default(&h, &tag).status.success());
        let old = fs::read(h.pins()).unwrap();
        let default = h.home.join(".config/agent-vm/default-image.json");
        let old_default = fs::read(&default).unwrap();
        let b = h.image(&ArchiveSpec {
            marker: "journal-b".into(),
            ..Default::default()
        });
        let child_b = server.image("images", "journal", &b);
        let mut gate = PinGate::new(h.root.path());
        let peer = pin_gate::PinPeer::spawn(
            h.command(),
            &gate,
            &["image", "set-default", "--image", &tag, "--yes"],
        );
        for stage in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
            PinStage::BeforeIntentSave,
            PinStage::IntentSaved,
            PinStage::DefaultSaved,
            PinStage::BeforePinSave,
            PinStage::PinCommitted,
        ] {
            let checkpoint = gate.expect(stage);
            if stage == stop {
                // PinPeer's Drop kills/reaps before the blocked connection is
                // closed: no child can run through the intended interruption.
                drop(peer);
                drop(checkpoint);
                break;
            }
            checkpoint.reply(Reply::Continue);
        }
        let committed = stop == PinStage::PinCommitted;
        let expected = if committed { &child_b } else { &child_a };
        let physical_pins = fs::read(h.pins()).unwrap();
        let physical_default = fs::read(&default).unwrap();
        let mut cmd = h.command();
        cmd.args(["image", "show"]);
        let show = bounded(cmd);
        assert!(show.status.success(), "{:?}: {}", stop, stderr(&show));
        assert!(
            String::from_utf8_lossy(&show.stdout).contains(expected),
            "{}",
            String::from_utf8_lossy(&show.stdout)
        );
        let mut cmd = h.command();
        cmd.arg("doctor");
        let doctor = bounded(cmd);
        assert!(doctor.status.success(), "{}", stderr(&doctor));
        assert!(
            String::from_utf8_lossy(&doctor.stdout).contains("default: retained default"),
            "{}",
            String::from_utf8_lossy(&doctor.stdout)
        );
        assert_eq!(
            fs::read(h.pins()).unwrap(),
            physical_pins,
            "observers must not recover"
        );
        assert_eq!(fs::read(&default).unwrap(), physical_default);
        if matches!(stop, PinStage::CandidateReady | PinStage::BeforeIntentSave) {
            assert_eq!(physical_pins, old);
            assert_eq!(physical_default, old_default);
        }
        // A mutator using a different source recovers without approving B for
        // the original tag. A second invocation proves recovery is idempotent.
        if !committed {
            for _ in 0..2 {
                assert!(h.refresh(&child_a, false).status.success());
                assert_eq!(fs::read(&default).unwrap(), old_default);
                assert!(read_json(&h.pins())["pending_default"].is_null());
            }
        }
        let start = server.count();
        assert_eq!(sdk_image(&h.launch(&tag)), *expected);
        assert_eq!(server.count(), start);
    }
}

/// A failure at either real write point leaves A and the previous fallback.
///
/// The seam is the atomic save as a whole, so a rename fault is indistinguishable
/// from an earlier save failure and there is no separate row for it: one injected
/// pre-write failure per write point is what this control can actually prove.
#[test]
fn pin_save_faults_preserve_approved_a_and_default() {
    for stage in [PinStage::BeforeIntentSave, PinStage::BeforePinSave] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let child_a = server.image("images", "fault", &a);
        let tag = format!("{}/images:fault", server.host);
        assert!(set_default(&h, &tag).status.success());
        let old = fs::read(h.pins()).unwrap();
        let default = h.home.join(".config/agent-vm/default-image.json");
        let old_default = fs::read(&default).unwrap();
        let b = h.image(&ArchiveSpec {
            marker: "fault-b".into(),
            ..Default::default()
        });
        server.image("images", "fault", &b);
        let mut gate = PinGate::new(h.root.path());
        let peer = pin_gate::PinPeer::spawn(
            h.command(),
            &gate,
            &["image", "set-default", "--image", &tag, "--yes"],
        );
        for next in [
            PinStage::CandidateReady,
            PinStage::BeforePinLock,
            PinStage::PinLocked,
            PinStage::BeforeIntentSave,
            PinStage::IntentSaved,
            PinStage::DefaultSaved,
            PinStage::BeforePinSave,
        ] {
            let checkpoint = gate.expect(next);
            if next == stage {
                checkpoint.reply(Reply::FailBeforeSave);
                break;
            }
            checkpoint.reply(Reply::Continue);
        }
        let out = peer.wait();
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        assert_eq!(fs::read(h.pins()).unwrap(), old);
        assert_eq!(fs::read(&default).unwrap(), old_default);
        let start = server.count();
        assert_eq!(sdk_image(&h.launch(&tag)), child_a);
        assert_eq!(server.count(), start);
    }
}

#[test]
fn alternate_manifest_algorithms_keep_equivalent_approval_bytes() {
    for algorithm in ["sha384", "sha512"] {
        let h = Harness::new(Mode::LaunchSeam);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        let child = server.image("images", "equivalent", &a);
        let tag = format!("{}/images:equivalent", server.host);
        assert!(h.refresh(&tag, false).status.success());
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
        let out = h.refresh(&tag, false);
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
    assert!(set_default(&h, &tag).status.success());
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
        h.refresh(&tag, false).status.success(),
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
    assert!(set_default(&h, &tag).status.success());
    let old = fs::read(h.pins()).unwrap();
    let b = h.image(&ArchiveSpec {
        marker: "permission-b".into(),
        ..Default::default()
    });
    server.image("images", "permission", &b);
    let mut gate = PinGate::new(h.root.path());
    let peer = pin_gate::PinPeer::spawn(
        h.command(),
        &gate,
        &["image", "refresh", "--image", &tag, "--yes"],
    );
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

#[test]
fn failed_default_restore_requires_recovery_without_losing_old_approval() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        // Root bypasses directory EACCES. CLI pre-write controls still execute;
        // store::tests::journal_real_write_failures_roll_back_or_require_recovery
        // supplies the deterministic failed-restore adapter case on CI root.
        eprintln!("root: CLI pre-write fault control, not a genuine EACCES restore failure");
        pin_save_faults_preserve_approved_a_and_default();
        return;
    }
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child_a = server.image("images", "restore", &a);
    let tag = format!("{}/images:restore", server.host);
    assert!(set_default(&h, &tag).status.success());
    let old = fs::read(h.pins()).unwrap();
    let default = h.home.join(".config/agent-vm/default-image.json");
    let old_default = fs::read(&default).unwrap();
    let b = h.image(&ArchiveSpec {
        marker: "restore-b".into(),
        ..Default::default()
    });
    server.image("images", "restore", &b);
    let mut gate = PinGate::new(h.root.path());
    let peer = pin_gate::PinPeer::spawn(
        h.command(),
        &gate,
        &["image", "set-default", "--image", &tag, "--yes"],
    );
    for stage in [
        PinStage::CandidateReady,
        PinStage::BeforePinLock,
        PinStage::PinLocked,
        PinStage::BeforeIntentSave,
        PinStage::IntentSaved,
        PinStage::DefaultSaved,
    ] {
        gate.expect(stage).reply(Reply::Continue);
    }
    let save = gate.expect(PinStage::BeforePinSave);
    let directory = h.pins().parent().unwrap().to_owned();
    let permissions = fs::metadata(&directory).unwrap().permissions();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    save.reply(Reply::Continue);
    let out = peer.wait();
    fs::set_permissions(&directory, permissions).unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("requires recovery"),
        "{}",
        stderr(&out)
    );
    let pending = fs::read(h.pins()).unwrap();
    let physical_default = fs::read(&default).unwrap();
    assert_ne!(physical_default, old_default);
    assert!(!read_json(&h.pins())["pending_default"].is_null());
    let mut cmd = h.command();
    cmd.args(["image", "show"]);
    let out = bounded(cmd);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains(&child_a));
    assert_eq!(fs::read(h.pins()).unwrap(), pending);
    assert_eq!(fs::read(&default).unwrap(), physical_default);
    // Pinned refresh A recovers but does not replace the original source key.
    assert!(h.refresh(&child_a, false).status.success());
    assert_eq!(fs::read(&default).unwrap(), old_default);
    let old: serde_json::Value = serde_json::from_slice(&old).unwrap();
    assert!(
        read_json(&h.pins())["pins"]
            .as_array()
            .unwrap()
            .contains(&old["pins"][0])
    );
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
    assert!(h.refresh(&source, false).status.success());
    assert_eq!(h.pinned_digest(), a.written.manifest_digest);
    assert_eq!(sdk_image(&h.launch(&source)), child);
    let old = fs::read(h.pins()).unwrap();
    index["manifests"][2]["digest"] = format!("sha256:{}", "d".repeat(64)).into();
    server.index("images", "filtered", serde_json::to_vec(&index).unwrap());
    let out = h.refresh(&source, false);
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
    assert!(h.refresh(&source, false).status.success());
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

/// `set-default` reports the fallback it initialized even when the approval for
/// the same key already existed, and says "already selected" only when neither
/// record moved.
#[test]
fn set_default_reports_the_fallback_it_initializes() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "select", &a);
    let tag = format!("{}/images:select", server.host);
    // An explicit refresh approves the tag's content without retaining it.
    assert!(h.refresh(&tag, false).status.success());
    assert_eq!(retained_default(&h), None, "a refesh never adopts");
    let pins = fs::read(h.pins()).unwrap();

    let first = set_default(&h, &tag);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(
        !stderr(&first).contains("already selected"),
        "the fallback moved, so nothing was already selected: {}",
        stderr(&first)
    );
    assert!(
        stderr(&first).contains("selected for future default-image sessions"),
        "{}",
        stderr(&first)
    );
    let retained: serde_json::Value =
        serde_json::from_slice(&retained_default(&h).expect("the fallback is initialized"))
            .unwrap();
    assert_eq!(retained, serde_json::json!({"version": 1, "image": child}));
    // The approval itself was equivalent, so its bytes are untouched.
    assert_eq!(fs::read(h.pins()).unwrap(), pins);

    let retained_bytes = retained_default(&h).expect("the fallback stays");
    // Repeating the same command moves nothing and says so.
    let again = set_default(&h, &tag);
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(
        stderr(&again).contains("already selected"),
        "{}",
        stderr(&again)
    );
    assert_eq!(fs::read(h.pins()).unwrap(), pins);
    assert_eq!(retained_default(&h).unwrap(), retained_bytes);

    let other = serde_json::json!({
        "version": 1,
        "image": format!("{}/images@sha256:{}", server.host, "b".repeat(64))
    });
    fs::write(
        h.home.join(".config/agent-vm/default-image.json"),
        serde_json::to_vec(&other).unwrap(),
    )
    .unwrap();
    let replaced = set_default(&h, &tag);
    assert!(replaced.status.success(), "{}", stderr(&replaced));
    assert!(!stderr(&replaced).contains("already selected"));
    assert!(stderr(&replaced).contains("selected for future default-image sessions"));
    assert_eq!(retained_default(&h).unwrap(), retained_bytes);
    assert_eq!(fs::read(h.pins()).unwrap(), pins);
}

/// A default-tier launch retains its own immutable selection even when the
/// approval for that key already exists: retention is write-once and
/// independent of the pin, and a launch that finds a retained fallback leaves
/// its bytes alone.
#[test]
fn default_tier_launch_adopts_an_absent_fallback_with_an_existing_pin() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "adopt", &a);
    // The same key is pinned by an explicit operation, which never adopts.
    assert!(h.refresh(&child, false).status.success());
    assert_eq!(retained_default(&h), None);
    let pins = fs::read(h.pins()).unwrap();

    let requests = server.count();
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child)
        .args(["shell", "--", "true"]);
    let cold = bounded(command);
    assert!(!cold.status.success(), "the fake runtime cannot boot");
    // The default tier is redacted, so the launch is proved by its own output
    // reaching the create with the approved content cached and no registry
    // request at all. (The fake runtime cannot accept the launch contract, so
    // every create here fails deliberately.)
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
    let retained: serde_json::Value = serde_json::from_slice(
        &retained_default(&h).expect("a default-tier launch retains its selection"),
    )
    .unwrap();
    assert_eq!(retained, serde_json::json!({"version": 1, "image": child}));
    assert_eq!(
        fs::read(h.pins()).unwrap(),
        pins,
        "an existing approval is not rewritten to retain the fallback"
    );

    // Write-once: the record is already there, so the next launch cannot move it.
    let retained_bytes = retained_default(&h).unwrap();
    let mut command = h.command();
    command
        .env("AGENT_VM_TEST_DEFAULT_IMAGE", &child)
        .args(["shell", "--", "true"]);
    let warm = bounded(command);
    assert!(!warm.status.success());
    assert_eq!(retained_default(&h).unwrap(), retained_bytes);
    assert_eq!(fs::read(h.pins()).unwrap(), pins);
}

/// An interrupted writer is observed, never recovered, by an approved warm
/// default launch. A missing gate socket makes *any* transaction stage fail.
#[test]
fn warm_default_launch_leaves_pending_intent_and_takes_no_pin_lock() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "warm-default", &a);
    assert!(h.refresh(&child, false).status.success());
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

// ------------------------------------------------------------ set-default UI

/// A second state root is a second cache: these rows need two real processes
/// whose only shared state is the host approval store.
fn state_root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("avpin-")
        .tempdir_in("/tmp")
        .unwrap()
}

/// `image set-default` asks exactly like `image refresh`: `n`, an empty answer
/// and EOF all leave both records untouched, and a nonterminal run refuses
/// without consuming stdin.
#[test]
fn set_default_prompt_declines_and_refuses_without_reading_stdin() {
    for (label, action) in [
        ("n", Action::Write(b"n\n")),
        ("empty", Action::Write(b"\n")),
        ("ctrl-d", Action::Write(b"\x04")),
        ("invalid", Action::Write(b"yeah\n")),
    ] {
        let h = Harness::new(Mode::StrictAcquisition);
        let server = Server::new();
        let a = h.image(&ArchiveSpec::default());
        server.image("images", "sd", &a);
        let tag = format!("{}/images:sd", server.host);
        assert!(set_default(&h, &tag).status.success());
        let pins = fs::read(h.pins()).unwrap();
        let retained = retained_default(&h).expect("set-default retains its child");
        let b = h.image(&ArchiveSpec {
            marker: format!("sd-b-{label}"),
            ..Default::default()
        });
        let child_b = server.image("images", "sd", &b);

        let mut command = h.command();
        command.args(["image", "set-default", "--image", &tag]);
        let mut terminal = Pty::spawn(&mut command, PROMPT).expect("open a pseudo-terminal");
        let (status, out) = terminal
            .drive(&action, Duration::from_secs(60))
            .expect("drive the approval prompt");
        let text = String::from_utf8_lossy(&out);
        assert!(!status.success(), "{label}: {text}");
        assert!(text.contains("Replace the approved image for"), "{text}");
        assert!(
            text.contains(&format!("new: {}", child_b.rsplit_once('@').unwrap().1)),
            "{text}"
        );
        assert_eq!(fs::read(h.pins()).unwrap(), pins, "{label}");
        assert_eq!(retained_default(&h).unwrap(), retained, "{label}");
    }

    // No terminal: refuse with status 1 before reading one byte of stdin.
    let h = Harness::new(Mode::StrictAcquisition);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    server.image("images", "sd", &a);
    let tag = format!("{}/images:sd", server.host);
    assert!(set_default(&h, &tag).status.success());
    let pins = fs::read(h.pins()).unwrap();
    let retained = retained_default(&h).unwrap();
    let b = h.image(&ArchiveSpec {
        marker: "sd-b-pipe".into(),
        ..Default::default()
    });
    server.image("images", "sd", &b);
    let mut command = h.command();
    command.args(["image", "set-default", "--image", &tag]);
    let (out, unread) = with_unread_stdin(command, b"y\n");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert_eq!(
        unread, b"y\n",
        "a nonterminal refusal must not consume stdin"
    );
    assert_eq!(fs::read(h.pins()).unwrap(), pins);
    assert_eq!(retained_default(&h).unwrap(), retained);
}

/// Run `command` with a pipe on stdin that already holds `input` and cannot be
/// read again, then report whatever the child left unread.
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

/// A peer that commits the same candidate first makes this operation report
/// "already selected", never "the first pin": the approval it found equivalent
/// is the record both processes measured.
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
        command.env("AGENT_VM_STATE_DIR", state).args([
            "image",
            "set-default",
            "--image",
            &tag,
            "--yes",
        ]);
        pin_gate::PinPeer::spawn(command, gate, &[])
    };

    // The loser reads an absent approval and freezes its candidate first.
    let loser = peer(&loser_gate, loser_state.path());
    let loser_ready = loser_gate.expect(PinStage::CandidateReady);
    // The winner then takes the lock before committing anything.
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
    for stage in [
        PinStage::BeforeIntentSave,
        PinStage::IntentSaved,
        PinStage::DefaultSaved,
        PinStage::BeforePinSave,
        PinStage::PinCommitted,
    ] {
        winner_gate.expect(stage).reply(Reply::Continue);
    }
    let winner_out = winner.wait();
    assert!(winner_out.status.success(), "{}", stderr(&winner_out));
    assert!(
        stderr(&winner_out).contains("selected for future default-image sessions"),
        "{}",
        stderr(&winner_out)
    );

    // The peer's equivalent candidate writes nothing.
    let pins = fs::read(h.pins()).unwrap();
    let retained = retained_default(&h).expect("the winner retained its child");
    loser_gate
        .expect(PinStage::PinLocked)
        .reply(Reply::Continue);
    loser_gate
        .expect(PinStage::PinCommitted)
        .reply(Reply::Continue);
    let loser_out = loser.wait();
    assert!(loser_out.status.success(), "{}", stderr(&loser_out));
    assert!(
        stderr(&loser_out).contains("already selected"),
        "a peer's identical candidate is not a first pin: {}",
        stderr(&loser_out)
    );
    assert_eq!(fs::read(h.pins()).unwrap(), pins);
    assert_eq!(retained_default(&h).unwrap(), retained);
    let store: serde_json::Value = serde_json::from_slice(&pins).unwrap();
    assert_eq!(store["pins"][0]["revision"], 1);
    assert_eq!(
        store["pins"][0]["manifest_digest"],
        child.rsplit_once('@').unwrap().1
    );
}
