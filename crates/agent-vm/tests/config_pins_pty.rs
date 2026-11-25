//! The interactive review under a real terminal (#736 V37, V38, V42, V45).
//!
//! Every row here drives the **real binary** under a real pty through
//! `support/pty.rs`, the same driver the secret prompt and the image-approval
//! prompt use. The rows exist because the interesting properties are not
//! "the prompt appears": they are that the diff is rendered against the
//! *recorded* active digest (not the newest file on disk), that a decline writes
//! nothing at all, that a source which changes between the question and the
//! reload refuses without asking twice, and that no other command — built-in,
//! help, `config …`, `doctor`, or a redirected stream — can reach a question.
//!
//! The child is given a pty on all three descriptors, a scratch `$HOME` and
//! `AGENT_VM_STATE_DIR`, the project under `CARGO_TARGET_TMPDIR`, and a fake
//! runtime that answers `--version` only. After an approval the launch
//! therefore stops at image preparation instead of booting, which is exactly
//! what makes these rows bounded.

#![cfg(unix)]
#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/pty.rs"]
mod pty;
#[path = "support/source_pins.rs"]
mod source_pins;
#[path = "support/mod.rs"]
mod support;

use pty::{Action, Pty, PtyOutput, PtyStdio};

const PROMPT: &[u8] = b"[y/N] ";
const INTERACTION: Duration = Duration::from_secs(30);

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// One project, one scratch home, one fake runtime.
struct Harness {
    _home: tempfile::TempDir,
    _state: tempfile::TempDir,
    _project: tempfile::TempDir,
    home_root: PathBuf,
    project_root: PathBuf,
    state_root: PathBuf,
    fake_msb: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let state = tempfile::tempdir_in("/tmp").unwrap();
        let project = support::project_tempdir();
        let home_root = home.path().canonicalize().unwrap();
        let state_root = state.path().canonicalize().unwrap();
        let project_root = project.path().canonicalize().unwrap();
        let fake_msb = fake_msb::install_pair(home.path(), fake_msb::Mode::VersionOnly).path;
        Self {
            _home: home,
            _state: state,
            _project: project,
            home_root,
            project_root,
            state_root,
            fake_msb,
        }
    }

    fn project_config(&self) -> PathBuf {
        support::project_config_path(&self.home_root, &self.project_root)
    }

    fn source(&self) -> PathBuf {
        self.project_root.join("conf/agent-vm.toml")
    }

    fn store_dir(&self) -> PathBuf {
        source_pins::store_dir(&self.home_root, &self.project_root)
    }

    fn write_project(&self, allow: bool) {
        let path = self.project_config();
        write(
            &path,
            &format!(
                "allow_tools = [\"repo:lint\"]\n\
                 [[sources]]\nname = \"repo\"\npath = \"./conf/agent-vm.toml\"\n{}",
                if allow { "allow = true\n" } else { "" }
            ),
        );
    }

    fn base_command(&self) -> Command {
        let mut cmd = Command::new(agent_vm_bin());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.home_root)
            .env("AGENT_VM_STATE_DIR", &self.state_root)
            .env("MSB_PATH", &self.fake_msb)
            .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
            .current_dir(&self.project_root);
        cmd
    }
}

/// The manifest's recorded active digest for the fixture's one source.
fn recorded_active(store: &Path) -> String {
    let bytes = source_pins::manifest_bytes(store).expect("the store has a manifest");
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).expect("manifest JSON");
    manifest["sources"][0]["active"]
        .as_str()
        .expect("an active digest")
        .to_owned()
}

/// Spawn the binary under a fresh pty, wait for the review question, and return
/// the driver plus everything printed up to and including it.
fn review(h: &Harness, args: &[&str], output: PtyStdio) -> (Pty, String) {
    let mut cmd = h.base_command();
    cmd.args(args);
    let mut pty = Pty::spawn_controlling(&mut cmd, PROMPT, output).expect("spawn under a pty");
    let printed = pty
        .wait_for_prompt(INTERACTION)
        .expect("the review question appears");
    (pty, String::from_utf8_lossy(&printed).into_owned())
}

/// Answer an already-visible prompt and read to the child's exit.
///
/// Production flushes the terminal's *queued* input immediately after writing
/// the question (`tcflush(TCIFLUSH)`), so an answer written before that flush is
/// discarded. Instead of sleeping for a guessed interval, this writes the answer
/// and waits: if the child has not consumed it, it writes again, and the only
/// termination condition is the child's exit. The flush happens once, so the
/// first write after it is the one that answers, and readiness is observed
/// rather than assumed. Bytes past the answer's LF stay queued and are never
/// read, because `read_answer` stops at the LF.
fn answer(pty: &mut Pty, reply: &str) -> (std::process::ExitStatus, String) {
    let mut output = Vec::new();
    let start = std::time::Instant::now();
    loop {
        pty.write_all(reply.as_bytes());
        match pty.wait_for_exit(&mut output, Duration::from_millis(50)) {
            Ok(status) => return (status, String::from_utf8_lossy(&output).into_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                assert!(
                    start.elapsed() < INTERACTION,
                    "the child never consumed the answer within {INTERACTION:?}: {error}"
                );
            }
            Err(error) => panic!("driving the pty answer: {error}"),
        }
    }
}

/// Run a non-review command under the pty and collect its whole output.
///
/// `drive` reads until the child exits whether or not the question ever
/// appears, so a command that must not prompt is driven exactly like one that
/// may; the assertion is on the bytes.
fn run_under_pty(h: &Harness, args: &[&str]) -> (std::process::ExitStatus, String) {
    let mut cmd = h.base_command();
    cmd.args(args);
    let mut pty = Pty::spawn_controlling(
        &mut cmd,
        PROMPT,
        PtyStdio {
            stdout: PtyOutput::Terminal,
            stderr: PtyOutput::Terminal,
        },
    )
    .expect("spawn under a pty");
    let (status, output) = pty
        .drive(&Action::Write(b""), INTERACTION)
        .expect("the child exits");
    (status, String::from_utf8_lossy(&output).into_owned())
}

/// V37: a changed source is diffed against the digest the store recorded as
/// active — not against the newest snapshot on disk, which this fixture makes
/// newer by mtime — and one `y` commits exactly the shown bytes.
#[test]
fn approving_a_changed_source_reviews_against_the_recorded_baseline() {
    let h = Harness::new();
    h.write_project(false);
    let source = h.source();
    let v1 = "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n# old baseline\n";
    let v2 = "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n# newer approved branch\n";
    let v3 = "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n# pending branch\n";
    write(&source, v1);
    // v1 is the recorded baseline; v2 is approved but inactive, and is the
    // *newest* snapshot on disk. v3 is what actually waits for review.
    let mut pins = source_pins::Pins::new(&h.home_root, &h.project_root);
    pins.approve_bytes(&source, v1.as_bytes())
        .approve_bytes_keeping_active(&source, v2.as_bytes())
        .write();
    let store = h.store_dir();
    let v1_hash = source_pins::sha256_hex(v1.as_bytes());
    let v2_hash = source_pins::sha256_hex(v2.as_bytes());
    let v3_hash = source_pins::sha256_hex(v3.as_bytes());
    let old = std::fs::metadata(source_pins::snapshot_path(&store, &v1_hash)).unwrap();
    let new = std::fs::metadata(source_pins::snapshot_path(&store, &v2_hash)).unwrap();
    assert!(
        new.modified().unwrap() >= old.modified().unwrap(),
        "the fixture's non-active snapshot is the newer one"
    );
    write(&source, v3);

    let (mut pty, printed) = review(
        &h,
        &["--image", "localhost:1/unused:latest", "lint"],
        PtyStdio {
            stdout: PtyOutput::Terminal,
            stderr: PtyOutput::Terminal,
        },
    );
    assert!(
        printed.contains(&format!(
            "==> source {}: changed since it was last approved",
            source.display()
        )),
        "{printed}"
    );
    assert!(
        printed.contains(&format!(
            "--- {}\t(last approved sha256:{v1_hash})",
            source.display()
        )),
        "the baseline is the recorded active digest, not the newest snapshot: {printed}"
    );
    assert!(
        printed.contains(&format!(
            "+++ {}\t(current sha256:{v3_hash})",
            source.display()
        )),
        "{printed}"
    );
    assert!(printed.contains("-# old baseline"), "{printed}");
    assert!(printed.contains("+# pending branch"), "{printed}");
    assert!(
        !printed.contains("+# newer approved branch"),
        "the inactive approved branch is not the baseline: {printed}"
    );

    let (status, after) = answer(&mut pty, "y\r");
    let _ = status;
    assert!(
        after.contains(&format!(
            "==> approved repo {} sha256:{v3_hash}",
            source.display()
        )),
        "the receipt names the key and digest: {after}"
    );
    let mut expected = vec![
        "config.toml".to_owned(),
        format!("pin-{}-{v1_hash}.toml", source_pins::STORE_ID),
        format!("pin-{}-{v2_hash}.toml", source_pins::STORE_ID),
        format!("pin-{}-{v3_hash}.toml", source_pins::STORE_ID),
        "pins.json".to_owned(),
        "pins.lock".to_owned(),
    ];
    expected.sort();
    assert_eq!(
        source_pins::entries(&store),
        expected,
        "the reviewed bytes' snapshot joined the two older ones"
    );
    assert_eq!(
        recorded_active(&store),
        v3_hash,
        "the reviewed branch is now the baseline"
    );
}

/// V37: declining writes nothing. The manifest and both snapshots keep their
/// bytes and inodes, and the refusal says nothing was recorded.
#[test]
fn declining_a_review_leaves_the_manifest_and_snapshots_untouched() {
    let h = Harness::new();
    h.write_project(false);
    let source = h.source();
    let v1 = "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n# old baseline\n";
    write(&source, v1);
    let mut pins = source_pins::Pins::new(&h.home_root, &h.project_root);
    pins.approve_bytes(&source, v1.as_bytes());
    pins.write();
    let store = h.store_dir();
    write(
        &source,
        "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n# pending change\n",
    );
    let before_manifest = source_pins::manifest_bytes(&store).unwrap();
    let before_entries = source_pins::entries(&store);
    let inodes: Vec<(String, u64)> = before_entries
        .iter()
        .map(|name| {
            let metadata = std::fs::metadata(store.join(name)).unwrap();
            (name.clone(), std::os::unix::fs::MetadataExt::ino(&metadata))
        })
        .collect();
    let before_snapshots: Vec<(String, Vec<u8>)> = before_entries
        .iter()
        .filter(|name| name.starts_with("pin-"))
        .map(|name| (name.clone(), std::fs::read(store.join(name)).unwrap()))
        .collect();
    assert!(
        !before_snapshots.is_empty(),
        "the fixture approved a baseline, so there is a snapshot to compare"
    );

    let (mut pty, printed) = review(
        &h,
        &["--image", "localhost:1/unused:latest", "lint"],
        PtyStdio {
            stdout: PtyOutput::Terminal,
            stderr: PtyOutput::Terminal,
        },
    );
    assert!(printed.contains("+# pending change"), "{printed}");
    let (status, after) = answer(&mut pty, "n\r");
    assert_eq!(status.code(), Some(1), "{after}");
    assert!(
        after.contains("the pinned source change was not approved; nothing was recorded"),
        "{after}"
    );
    assert_eq!(
        source_pins::manifest_bytes(&store).unwrap(),
        before_manifest,
        "a decline commits nothing"
    );
    assert_eq!(source_pins::entries(&store), before_entries);
    for (name, ino) in inodes {
        let metadata = std::fs::metadata(store.join(&name)).unwrap();
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&metadata),
            ino,
            "{name} was rewritten by a decline"
        );
    }
    for (name, bytes) in before_snapshots {
        assert_eq!(
            std::fs::read(store.join(&name)).unwrap(),
            bytes,
            "a decline left {name}'s snapshot bytes alone"
        );
    }
    assert_eq!(
        recorded_active(&store),
        source_pins::sha256_hex(v1.as_bytes())
    );
}

/// V37/V30(a): the question was asked about v1; v2 is written before the answer
/// arrives. The approval records v1, the single reload then refuses v2, and no
/// second question is asked.
#[test]
fn a_source_that_changes_after_the_question_refuses_without_asking_again() {
    let h = Harness::new();
    h.write_project(false);
    let source = h.source();
    let v1 = "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n# reviewed\n";
    write(&source, v1);
    let v1_hash = source_pins::sha256_hex(v1.as_bytes());

    let (mut pty, printed) = review(
        &h,
        &["--image", "localhost:1/unused:latest", "lint"],
        PtyStdio {
            stdout: PtyOutput::Terminal,
            stderr: PtyOutput::Terminal,
        },
    );
    assert_eq!(
        printed.matches("[y/N] ").count(),
        1,
        "one question for one launch: {printed}"
    );
    // The reviewed bytes are v1; the file on disk becomes v2 while the question
    // is waiting for an answer.
    let v2 = "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n# not reviewed\n";
    write(&source, v2);
    let v2_hash = source_pins::sha256_hex(v2.as_bytes());
    let (status, after) = answer(&mut pty, "y\r");

    assert_eq!(status.code(), Some(1), "{after}");
    assert!(
        !after.contains("[y/N] "),
        "no second question for the changed source: {after}"
    );
    assert!(
        after.contains(&format!(
            "differs from every approved version (current sha256:{v2_hash}; last approved sha256:{v1_hash})"
        )),
        "the reload's refusal names the committed baseline: {after}"
    );
    let store = h.store_dir();
    assert_eq!(
        recorded_active(&store),
        v1_hash,
        "the bytes that were reviewed are what was approved"
    );
}

/// V43 (B1): the review says which source is being approved — its declaration,
/// alias, route scope and `allow` value — and an `allow = true` source also
/// warns that approving it adopts the top-level keys it declares. This is a real
/// external-scope case: the source is an absolute path outside the checkout.
#[test]
fn a_review_names_the_source_scope_and_allow_value_and_warns_about_adoption() {
    let h = Harness::new();
    // An absolute path outside the project: `External` scope, still reviewable.
    let external = h.home_root.join("team.toml");
    let body = "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n";
    write(&external, body);
    write(
        &h.project_config(),
        &format!(
            "allow_tools = [\"repo:lint\"]\n\
             [[sources]]\nname = \"repo\"\npath = {:?}\nallow = true\n",
            external.display().to_string()
        ),
    );

    let (mut pty, printed) = review(
        &h,
        &["--image", "localhost:1/unused:latest", "lint"],
        PtyStdio {
            stdout: PtyOutput::Terminal,
            stderr: PtyOutput::Terminal,
        },
    );
    assert!(
        printed.contains("==> declared: sources[0] repo, scope external, allow = true"),
        "the review identifies what is being approved: {printed}"
    );
    assert!(
        printed.contains(
            "==> allow = true: approving also adopts this source's top-level `image`, `mounts`, \
             `network` and `allow_tools`"
        ),
        "the capability the approval grants is named: {printed}"
    );
    assert!(
        printed.contains(&format!(
            "+++ {}\t(current sha256:{})",
            external.display(),
            source_pins::sha256_hex(body.as_bytes())
        )),
        "the exact candidate digest is shown: {printed}"
    );
    let (status, after) = answer(&mut pty, "n\r");
    assert_eq!(status.code(), Some(1), "{after}");
    assert_eq!(
        source_pins::entries(&h.store_dir())[..],
        ["config.toml".to_owned()],
        "a decline writes nothing"
    );
}

/// V42: an oversized first approval is refused whole. No part of the diff is
/// shown, no `[y/N]` is printed, and nothing is written.
#[test]
fn a_truncated_first_approval_never_asks_and_writes_nothing() {
    let h = Harness::new();
    h.write_project(false);
    let source = h.source();
    let mut body = String::from("# 4001 lines: one past the per-source diff cap\n");
    for index in 0..4_001 {
        body.push_str(&format!("{index} = {}\n", index + 1));
    }
    write(&source, &body);

    let (status, printed) = run_under_pty(&h, &["--image", "localhost:1/unused:latest", "lint"]);
    assert_eq!(status.code(), Some(1), "{printed}");
    assert!(
        printed.contains("this review is too large to approve interactively"),
        "{printed}"
    );
    assert!(
        printed.contains("one source's diff is longer than 4000 lines"),
        "the cap is named: {printed}"
    );
    assert!(
        printed.contains(&format!("for \"{}\"", source.display())),
        "the exact key is named: {printed}"
    );
    assert!(
        printed.contains("agent-vm config diff"),
        "the refusal directs a full review first: {printed}"
    );
    assert!(!printed.contains("[y/N]"), "no question after a refusal");
    assert_eq!(
        source_pins::entries(&h.store_dir())[..],
        ["config.toml".to_owned()],
        "a truncated review writes no pin state"
    );
}

/// V45: a checkout-relative source that resolves outside the project refuses
/// before any question, discloses none of the sentinel's bytes, and creates no
/// store file.
#[test]
fn a_checkout_escape_never_prompts_and_discloses_nothing() {
    let outside = tempfile::tempdir_in("/tmp").unwrap();
    let sentinel = outside.path().canonicalize().unwrap().join("sentinel.toml");
    std::fs::write(&sentinel, "SECRET-SENTINEL-736\n").unwrap();
    let h = Harness::new();
    h.write_project(false);
    std::fs::create_dir_all(h.source().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&sentinel, h.source()).unwrap();

    let (status, printed) = run_under_pty(&h, &["--image", "localhost:1/unused:latest", "lint"]);
    assert_eq!(status.code(), Some(1), "{printed}");
    assert!(
        printed.contains("checkout source resolves outside the project directory"),
        "the route refusal, not a prompt: {printed}"
    );
    assert!(!printed.contains("SECRET-SENTINEL-736"), "{printed}");
    assert!(!printed.contains("[y/N]"), "{printed}");
    assert_eq!(
        source_pins::entries(&h.store_dir())[..],
        ["config.toml".to_owned()],
        "no pins.json, pins.lock or snapshot"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).unwrap(),
        "SECRET-SENTINEL-736\n"
    );
}

/// V38: control characters, bidi overrides, combining marks and homoglyph
/// neighbours render as distinct printable ASCII in the review, so a source
/// cannot rewrite the reviewer's terminal.
#[test]
fn the_review_escapes_terminal_control_characters() {
    let h = Harness::new();
    h.write_project(false);
    let source = h.source();
    // One line per shape, each in its own diff line so the escaping is visible
    // without neighbouring context hiding it.
    let body = "\u{1b}[2K\nliteral \\x1b[2K\nbare cr\rhere\nbidi \u{202E}\ncombining e\u{0301}\n\
                hebrew \u{05D0}\nsoft \u{00AD}\n";
    write(&source, body);

    let (mut pty, printed) = review(
        &h,
        &["--image", "localhost:1/unused:latest", "lint"],
        PtyStdio {
            stdout: PtyOutput::Terminal,
            stderr: PtyOutput::Terminal,
        },
    );
    for escaped in [
        "\\x1b[2K",
        "literal \\\\x1b[2K",
        "bare cr\\x0dhere",
        "\\u{202E}",
        "\\u{0301}",
        "\\u{05D0}",
        "\\u{00AD}",
    ] {
        assert!(
            printed.contains(escaped),
            "missing {escaped:?} in {printed}"
        );
    }
    assert!(
        !printed.contains('\u{1b}') && !printed.contains('\u{202E}'),
        "no raw control or bidi scalar reaches the terminal: {printed:?}"
    );
    let (status, _after) = answer(&mut pty, "n\r");
    assert_eq!(status.code(), Some(1));
}

/// V37/B3: no command that is not an eligible launch may ask the question,
/// whatever the terminal is — including `config …`, `doctor`, help, version and
/// the built-ins. Every row also leaves the store exactly as it was.
#[test]
fn no_other_command_can_prompt() {
    let h = Harness::new();
    h.write_project(false);
    write(
        &h.source(),
        "[[tools]]\nname = \"lint\"\ncommand = \"/bin/true\"\n",
    );

    for (argv, code) in [
        (vec!["--help"], 0),
        (vec!["-V"], 0),
        (vec!["help", "doctor"], 0),
        (vec!["doctor"], 1),
        (vec!["config", "diff"], 1),
        (vec!["config", "approve"], 1),
        (vec!["tools", "print"], 0),
        (vec!["image", "show"], 1),
        (vec!["-tV", "shell"], 0),
        (vec!["-th", "shell"], 0),
        (vec!["run"], 2),
        (vec!["-t", "lint"], 1),
    ] {
        let (status, printed) = run_under_pty(&h, &argv);
        assert!(
            !printed.contains("[y/N]"),
            "agent-vm {argv:?} must not prompt: {printed}"
        );
        assert_eq!(status.code(), Some(code), "agent-vm {argv:?}: {printed}");
        assert_eq!(
            source_pins::entries(&h.store_dir())[..],
            ["config.toml".to_owned()],
            "agent-vm {argv:?} created a store file"
        );
    }
}

/// V37: the same refusal with **stderr redirected to a file** — an eligible
/// stdin but no eligible output is not a reviewable terminal, so nothing is
/// printed and nothing is written.
#[test]
fn a_redirected_stderr_refuses_without_printing_the_question() {
    let h = Harness::new();
    h.write_project(false);
    write(&h.source(), "# pending\n");
    let log = h.home_root.join("stderr.log");
    let mut cmd = h.base_command();
    cmd.args(["--image", "localhost:1/unused:latest", "lint"]);
    let mut pty = Pty::spawn_controlling(
        &mut cmd,
        PROMPT,
        PtyStdio {
            stdout: PtyOutput::Terminal,
            stderr: PtyOutput::File(log.clone()),
        },
    )
    .expect("spawn with stderr redirected");
    let (status, _on_terminal) = pty
        .drive(&Action::Write(b"y\r"), INTERACTION)
        .expect("the child exits without a terminal to ask on");
    let file = std::fs::read_to_string(&log).unwrap();
    assert_eq!(status.code(), Some(1), "{file}");
    assert!(
        file.contains("1 pinned source is not approved for this project"),
        "the R8 refusal goes to the redirected stderr: {file}"
    );
    assert!(!file.contains("[y/N]"), "no question in the file: {file}");
    assert_eq!(
        source_pins::entries(&h.store_dir())[..],
        ["config.toml".to_owned()]
    );
}
