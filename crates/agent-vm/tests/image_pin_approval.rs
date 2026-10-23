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
use pin_gate::{PinGate, PinStage, Reply};
use pty::{Action, Pty};

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

    fn msb_invocations(&self) -> String {
        fs::read_to_string(&self.runtime.invocations).unwrap_or_default()
    }

    fn cache(&self) -> PathBuf {
        self.state.join("msb-home/cache")
    }
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

/// Import may publish an alias, never an approval: a launch keeps consuming the
/// approved digest with no tag query, even when the alias now names B.
#[test]
fn import_alias_cannot_bypass_an_established_pin() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let child = server.image("images", "alias", &image_archive_image(&h, "alias-a"));
    let tag = format!("{}/images:alias", server.host);
    let _ = a;
    let cold = h.launch(&tag);
    assert!(!cold.status.success());
    assert_eq!(sdk_image(&cold), child);
    let pinned = h.pinned_digest();

    // Import B's archive under the SAME tag string.
    let archive_path = h.root.path().join("alias-b.tar");
    let _ = image_archive::write_docker_save(
        &archive_path,
        &[image_archive::DockerSaveImage {
            marker: "alias-b".into(),
            repo_tags: Some(vec![tag.clone()]),
        }],
    );
    let mut command = h.command();
    command.args([
        "image",
        "import",
        "--input",
        archive_path.to_str().unwrap(),
        "--tag",
        &tag,
    ]);
    let imported = bounded(command);
    assert!(imported.status.success(), "{}", stderr(&imported));

    let before = server.count();
    let warm = h.launch(&tag);
    assert!(!warm.status.success());
    assert_eq!(sdk_image(&warm), child, "the approval survives an import");
    assert_eq!(h.pinned_digest(), pinned);
    assert_eq!(
        server.count(),
        before,
        "an approved launch makes no registry request after an import"
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

#[test]
fn projects_and_independent_caches_share_one_approval() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.image(&ArchiveSpec::default());
    let approved_a = server.image("images", "shared", &a);
    let tag = format!("{}/images:shared", server.host);
    assert_eq!(sdk_image(&h.launch(&tag)), approved_a);
    let old = fs::read(h.pins()).unwrap();
    let project = h.root.path().join("second-project");
    fs::create_dir(&project).unwrap();
    let state = tempfile::Builder::new()
        .prefix("avshare-")
        .tempdir_in("/tmp")
        .unwrap();
    let second = || {
        let mut cmd = h.command();
        cmd.current_dir(&project)
            .env("AGENT_VM_STATE_DIR", state.path());
        cmd
    };
    let b = h.image(&ArchiveSpec {
        marker: "shared-b".into(),
        ..Default::default()
    });
    let approved_b = server.image("images", "shared", &b);
    let start = server.count();
    let mut cmd = second();
    cmd.args(["--image", &tag, "shell", "--", "true"]);
    assert_eq!(sdk_image(&bounded(cmd)), approved_a);
    assert_eq!(fs::read(h.pins()).unwrap(), old);
    let requests = server.requests();
    assert!(
        requests[start..]
            .iter()
            .any(|(_, p)| p == &format!("/v2/images/manifests/{}", a.written.manifest_digest))
    );
    assert!(
        !requests[start..]
            .iter()
            .any(|(_, p)| p == "/v2/images/manifests/shared")
    );
    let mut cmd = second();
    cmd.args(["image", "refresh", "--image", &tag, "--yes"]);
    let out = bounded(cmd);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(h.pinned_digest(), b.written.manifest_digest);
    let out = h.launch(&tag);
    assert_eq!(sdk_image(&out), approved_b);
    let start = server.count();
    assert_eq!(sdk_image(&h.launch(&tag)), approved_b);
    assert_eq!(
        server.count(),
        start,
        "approval applies across both projects"
    );
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
