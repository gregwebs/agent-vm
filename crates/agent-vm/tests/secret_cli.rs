//! Black-box integration tests for `agent-vm secret` (issues #160, #159).
//!
//! Spawns the real compiled binary with a controlled `$HOME` /
//! `AGENT_VM_STATE_DIR`, following `doctor_reset.rs`'s harness. Every case here
//! is either an **argument-shape or pre-keychain failure**, or runs against the
//! debug-only test recording backend (`AGENT_VM_TEST_SECRET_RECORD`, see
//! `secret_store::RecordingKeychain`) which records only a length and SHA-256.
//! Nothing in this file touches the CI runner's credential store, so it is safe
//! on a machine with a real keychain and on one with no Secret Service at all;
//! when a case reaches the store it does so under a relocated `$HOME`.
//!
//! `MSB_PATH` is deliberately *not* set: `secret` is dispatched before
//! `main`'s msb setup, and leaving it unset is what proves that.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

struct Harness {
    home: tempfile::TempDir,
    state: tempfile::TempDir,
    project: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            state: tempfile::tempdir().unwrap(),
            project: tempfile::tempdir().unwrap(),
        }
    }

    /// The `Catalog::Broken` path builds a different clap command (no tool
    /// subcommands, external subcommands enabled), so every argv shape is
    /// exercised on both.
    fn with_broken_config() -> Self {
        let harness = Self::new();
        std::fs::create_dir_all(harness.project.path().join(".agent-vm")).unwrap();
        std::fs::write(
            harness.project.path().join(".agent-vm/config.toml"),
            "[[tools]\nnot toml",
        )
        .unwrap();
        harness
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(agent_vm_bin())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("AGENT_VM_STATE_DIR", self.state.path())
            .current_dir(self.project.path())
            .args(args)
            .output()
            .expect("failed to run agent-vm")
    }

    /// Where the debug-only recording backend writes its `len sha256` lines.
    fn recording_path(&self) -> PathBuf {
        self.home.path().join("secret-record.txt")
    }

    /// Run with the debug-only recording backend active, so a `set` never
    /// touches a real credential store. `probe`/`delete` report `Absent`, so
    /// `ls` shows every tracked name as `missing` and `rm` succeeds — all
    /// without an OS credential store.
    fn run_recording(&self, args: &[&str]) -> Output {
        Command::new(agent_vm_bin())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("AGENT_VM_STATE_DIR", self.state.path())
            .env("AGENT_VM_TEST_SECRET_RECORD", self.recording_path())
            .current_dir(self.project.path())
            .stdin(Stdio::null())
            .args(args)
            .output()
            .expect("failed to run agent-vm")
    }

    /// As [`Harness::run_recording`], with `input` piped to stdin (the
    /// documented `printf '%s' "$KEY" | agent-vm secret set SERVICE` form).
    fn run_recording_piped(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = Command::new(agent_vm_bin())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("AGENT_VM_STATE_DIR", self.state.path())
            .env("AGENT_VM_TEST_SECRET_RECORD", self.recording_path())
            .current_dir(self.project.path())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to run agent-vm");
        child
            .stdin
            .take()
            .expect("child stdin is piped")
            .write_all(input)
            .expect("writing the piped value");
        child.wait_with_output().expect("waiting for agent-vm")
    }

    fn config_dir(&self) -> PathBuf {
        self.home.path().join(".config/agent-vm")
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn both_streams(out: &Output) -> String {
    format!("{}{}", stdout_of(out), stderr_of(out))
}

/// No substring of the value may appear anywhere, in either stream.
fn assert_no_value_leak(out: &Output, value: &str) {
    let text = both_streams(out);
    assert!(!text.contains(value), "the value leaked: {text}");
    let bytes = value.as_bytes();
    for window in bytes.windows(4) {
        let window = std::str::from_utf8(window).unwrap();
        assert!(
            !text.contains(window),
            "the fragment {window:?} leaked: {text}"
        );
    }
}

fn assert_nothing_stored(harness: &Harness) {
    assert!(
        !harness.config_dir().exists(),
        "no store access may happen before the refusal: {}",
        harness.config_dir().display()
    );
}

/// I1 — a value passed positionally is refused, and neither stream nor the
/// filesystem shows any part of it.
#[test]
fn a_value_in_the_argument_list_is_refused_without_echo_or_side_effect() {
    for harness in [Harness::new(), Harness::with_broken_config()] {
        let out = harness.run(&["secret", "set", "svc", "sk-ant-REAL-VALUE"]);
        assert!(!out.status.success(), "must be refused");
        assert_no_value_leak(&out, "sk-ant-REAL-VALUE");
        let text = both_streams(&out);
        assert!(
            text.contains("must not be passed on the command line"),
            "{text}"
        );
        assert_nothing_stored(&harness);
    }
}

/// I2 — the clap defect's shape: an attached value on a flag clap itself
/// rejects. This is the end-to-end proof that the scrub replaces clap's
/// value-rendering error.
#[test]
fn an_attached_value_on_a_flag_is_refused_without_echo() {
    for harness in [Harness::new(), Harness::with_broken_config()] {
        for args in [
            vec!["secret", "set", "svc", "--help=sk-ant-REAL-VALUE"],
            vec!["secret", "--help=sk-ant-REAL-VALUE"],
            vec!["secret", "--sk-ant-REAL-VALUE"],
            vec!["secret", "bogus", "sk-ant-REAL-VALUE"],
        ] {
            let out = harness.run(&args);
            assert!(!out.status.success(), "{args:?} must be refused");
            assert_no_value_leak(&out, "sk-ant-REAL-VALUE");
        }
        assert_nothing_stored(&harness);
    }
}

/// I3 — the documented surface: stdin and the hidden prompt are named, and the
/// refuse-to-declare-it interface (`--token`, a value positional) is not
/// advertised anywhere.
#[test]
fn the_secret_help_names_stdin_and_the_hidden_prompt() {
    let harness = Harness::new();

    let long = harness.run(&["secret", "set", "--help"]);
    assert!(long.status.success(), "{}", stderr_of(&long));
    let text = both_streams(&long);
    assert!(text.contains("stdin"), "{text}");
    assert!(text.contains("hidden"), "{text}");

    for args in [
        vec!["secret", "--help"],
        vec!["secret", "set", "--help"],
        vec!["secret", "set", "-h"],
        vec!["secret", "rm", "--help"],
        vec!["secret", "ls", "--help"],
    ] {
        let out = harness.run(&args);
        assert!(out.status.success(), "{args:?}: {}", stderr_of(&out));
        let text = both_streams(&out);
        // `--token` and the refusal positional are `hide = true`: they must not
        // be advertised as an interface.
        assert!(!text.contains("--token"), "{args:?}: {text}");
        assert!(!text.contains("rejected"), "{args:?}: {text}");
        assert!(!text.contains("VALUE"), "{args:?}: {text}");
    }
}

/// I4 — an invalid service name fails before any store access and is not
/// echoed, because a user may have typed a *value* in the name slot.
#[test]
fn an_invalid_service_name_fails_before_any_store_access_and_is_not_echoed() {
    for harness in [Harness::new(), Harness::with_broken_config()] {
        // A `/` makes the name invalid; a key-shaped name made only of
        // letters, digits, `.`, `_` and `-` is *accepted* under O1, which
        // `a_key_shaped_name_is_accepted_so_the_value_error_fires` pins.
        for name in ["Bad/Name", "sk-ant-api03-REAL/VALUE", "a b"] {
            let out = harness.run(&["secret", "set", name]);
            assert!(!out.status.success(), "{name} must be refused");
            let text = both_streams(&out);
            assert!(text.contains("must be 1-64 characters"), "{name}: {text}");
            assert!(!text.contains(name), "{name} was echoed: {text}");
            // The `rm` verb validates the same way.
            let out = harness.run(&["secret", "rm", name]);
            assert!(!out.status.success(), "rm {name} must be refused");
            assert!(!both_streams(&out).contains(name), "rm {name} echoed it");
        }
        // A name shaped like a flag is caught by the argv scrub instead of the
        // name rule (clap parses it as an option first). The contract is the
        // same either way: refused, and never echoed. The name *rule* itself is
        // covered in-process by `secret_store`'s V1.
        for name in ["-lead", ".lead"] {
            for args in [["secret", "set", name], ["secret", "rm", name]] {
                let out = harness.run(&args);
                assert!(!out.status.success(), "{args:?} must be refused");
                assert!(
                    !both_streams(&out).contains(name),
                    "{args:?} echoed the name"
                );
            }
        }
        assert_nothing_stored(&harness);
    }
}

/// Finding 3 — a failed or aborted operation must not echo a user-supplied
/// name, in either the typed or the case-folded spelling. A key-shaped name is
/// accepted by O1, so this is exactly the case where a mistyped key would
/// otherwise be printed by a failure path.
#[test]
fn failures_do_not_echo_a_key_shaped_name() {
    for harness in [Harness::new(), Harness::with_broken_config()] {
        let typed = "sk-ant-API03-AbCdEf";
        let canonical = typed.to_ascii_lowercase();
        // `set` with no value: the read fails before any store access.
        let out = harness.run(&["secret", "set", typed]);
        assert!(!out.status.success(), "there is no value to store");
        let text = both_streams(&out);
        assert!(text.contains("no value was supplied"), "{text}");
        assert!(!text.contains(typed), "set echoed the typed name: {text}");
        assert!(
            !text.contains(&canonical),
            "set echoed the canonical name: {text}"
        );
        // `rm` for a name with no stored value: the failure must not name it
        // (on a machine with a reachable store this is the `NotStored` error;
        // otherwise it is the classified store failure — neither prints it).
        let out = harness.run(&["secret", "rm", typed]);
        assert!(!out.status.success(), "rm must fail for an unstored name");
        let text = both_streams(&out);
        assert!(!text.contains(typed), "rm echoed the typed name: {text}");
        assert!(
            !text.contains(&canonical),
            "rm echoed the canonical name: {text}"
        );
    }
}

/// The O1 trade-off, end to end: a key made only of the accepted alphabet is
/// a valid *name*, so the failure is "no value was supplied" rather than the
/// name rule — and even so nothing echoes the name or a value.
#[test]
fn a_key_shaped_name_is_accepted_so_the_value_error_fires() {
    for harness in [Harness::new(), Harness::with_broken_config()] {
        let out = harness.run(&["secret", "set", "sk-ant-API03-AbCdEf"]);
        assert!(!out.status.success(), "there is no value to store");
        let text = both_streams(&out);
        assert!(text.contains("no value was supplied"), "{text}");
        assert!(!text.contains("1-64 characters"), "{text}");
        // Reading the value failed, so nothing was written and nothing printed
        // the name.
        assert!(!text.contains("sk-ant"), "{text}");
        assert!(!harness.config_dir().exists());
    }
}

/// Finding 1 — clap's synthesized `help <verb> …` traversal reaches the
/// `secret` subtree and used to print an unexpected argument verbatim. Both
/// help entry paths must render the fixed scrub instead, on both catalog
/// paths, with neither stream leaking the argument. The successful forms must
/// still render help.
#[test]
fn help_traversal_of_the_secret_subtree_is_scrubbed() {
    for harness in [Harness::new(), Harness::with_broken_config()] {
        for args in [
            vec!["help", "secret", "sk-ant-REAL-VALUE"],
            vec!["help", "secret", "set", "sk-ant-REAL-VALUE"],
            vec!["help", "secret", "--sk-ant-REAL-VALUE"],
            vec!["secret", "help", "sk-ant-REAL-VALUE"],
            vec!["secret", "help", "set", "sk-ant-REAL-VALUE"],
        ] {
            let out = harness.run(&args);
            assert!(!out.status.success(), "{args:?} must be refused");
            assert_no_value_leak(&out, "sk-ant-REAL-VALUE");
            let text = both_streams(&out);
            assert!(
                text.contains("could not parse its arguments"),
                "{args:?}: {text}"
            );
        }
        // The successful help forms still render on both catalogs.
        for args in [vec!["help", "secret"], vec!["secret", "help"]] {
            let out = harness.run(&args);
            assert!(out.status.success(), "{args:?}: {}", stderr_of(&out));
            assert!(
                both_streams(&out).contains("keychain"),
                "{args:?}: {}",
                both_streams(&out)
            );
        }
    }
}

/// I5 — the empty store tells the truth on both catalog paths: a header, exit
/// zero, and no claim about keychain health (no probe ran).
///
/// This is the only test here that reaches the store layer at all, and it does
/// so with an **empty inventory**, which probes nothing — so it does not touch
/// the runner's credential store.
#[test]
fn an_empty_listing_prints_only_the_header_and_exits_zero() {
    for harness in [Harness::new(), Harness::with_broken_config()] {
        let out = harness.run(&["secret", "ls"]);
        assert!(out.status.success(), "{:?}", stderr_of(&out));
        assert_eq!(stdout_of(&out), "SERVICE  STORAGE\n");
        assert_eq!(stderr_of(&out), "");
    }
}

/// The shell-history motivation, stated as behaviour: `set` with no value and
/// no stdin terminal fails with the actionable message rather than hanging or
/// storing an empty value.
#[test]
fn set_with_no_value_and_no_stdin_reports_what_to_do() {
    let harness = Harness::new();
    let out = Command::new(agent_vm_bin())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", harness.home.path())
        .env("AGENT_VM_STATE_DIR", harness.state.path())
        .current_dir(harness.project.path())
        .args(["secret", "set", "anthropic"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to run agent-vm");
    assert!(!out.status.success(), "an empty stdin has no value");
    let text = both_streams(&out);
    assert!(text.contains("no value was supplied"), "{text}");
    // The *listing* must not have gained a row for a value never stored.
    let listed = harness.run(&["secret", "ls"]);
    assert_eq!(stdout_of(&listed), "SERVICE  STORAGE\n");
}

/// A `secret` command must not be deflected by a broken tool config: the same
/// failure and the same message as with a good one.
#[test]
fn a_broken_tool_config_does_not_change_the_secret_outcome() {
    let broken = Harness::with_broken_config();
    let out = broken.run(&["secret", "set", "svc", "sk-ant-REAL-VALUE"]);
    let text = both_streams(&out);
    assert!(
        text.contains("must not be passed on the command line"),
        "{text}"
    );
    assert!(
        !text.contains("could not be read"),
        "a broken config must not surface here: {text}"
    );
}

/// Guards the harness itself: the broken-config fixture really is broken.
#[test]
fn the_broken_config_fixture_is_actually_broken() {
    let broken = Harness::with_broken_config();
    assert!(Path::new(&broken.project.path().join(".agent-vm/config.toml")).is_file());
    let out = broken.run(&["doctor"]);
    // `doctor` reports the broken config rather than silently succeeding with
    // defaults; the shape of that report is doctor.rs's contract, so this only
    // asserts that the tier is acknowledged at all.
    let text = both_streams(&out);
    assert!(!text.is_empty(), "doctor must say something");
}

// ---------------------------------------------------------------------------
// Store-reaching cases, all via the debug-only recording backend and a
// relocated `$HOME`. These close gaps the in-process `secret_store`/`secret`
// unit suites cannot: the shipped stdin path, the process-boundary error
// rendering, the real cross-process `flock(2)`, and the documented O1
// consequence end to end.
// ---------------------------------------------------------------------------

/// The piped length boundary through the real binary: a value at exactly
/// `MAX_SECRET_VALUE_LEN` is delivered byte-for-byte (asserted with the
/// recording backend's length + SHA-256), one byte over is refused, and empty
/// stdin is refused. Complements the in-process `read_bounded_stdin` unit tests.
#[test]
fn a_piped_value_at_the_length_boundary_is_recorded_exactly_and_one_over_is_refused() {
    use sha2::{Digest as _, Sha256};

    let harness = Harness::new();

    let max = "a".repeat(4096);
    let out = harness.run_recording_piped(&["secret", "set", "svc"], max.as_bytes());
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_no_value_leak(&out, &max);
    let accepted = std::fs::read_to_string(harness.recording_path()).unwrap();
    assert_eq!(
        accepted,
        format!("4096 {:x}\n", Sha256::digest(max.as_bytes())),
        "the reader must deliver the value byte-for-byte"
    );

    // One byte over: refused, and *nothing* is recorded (no truncated prefix).
    let over = "a".repeat(4097);
    let out = harness.run_recording_piped(&["secret", "set", "svc2"], over.as_bytes());
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("longer than 4096 bytes"),
        "{}",
        stderr_of(&out)
    );
    assert_no_value_leak(&out, &over);

    // Empty stdin: refused.
    let out = harness.run_recording_piped(&["secret", "set", "svc3"], b"");
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("no value was supplied"),
        "{}",
        stderr_of(&out)
    );

    assert_eq!(
        std::fs::read_to_string(harness.recording_path()).unwrap(),
        accepted,
        "a rejected value must not add a record"
    );
}

/// The name length boundary through the real binary: 64 bytes is accepted and
/// recorded in the 0600 inventory; 65 is refused before any store access and is
/// never echoed. The rest of the alphabet is in-process in `secret_store`'s V1.
#[test]
fn the_service_name_length_boundary_is_enforced_end_to_end() {
    let harness = Harness::new();

    let ok = "a".repeat(64);
    let out = harness.run_recording_piped(&["secret", "set", &ok], b"v");
    assert!(out.status.success(), "{}", stderr_of(&out));
    let listed = harness.run_recording(&["secret", "ls"]);
    assert!(stdout_of(&listed).contains(&ok), "{}", stdout_of(&listed));
    let inventory =
        std::fs::read_to_string(harness.config_dir().join("secret-inventory.json")).unwrap();
    assert!(inventory.contains(&ok), "{inventory}");

    let too_long = "a".repeat(65);
    let out = harness.run_recording_piped(&["secret", "set", &too_long], b"v");
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("must be 1-64 characters"),
        "{}",
        stderr_of(&out)
    );
    assert!(
        !both_streams(&out).contains(&too_long),
        "the rejected name was echoed"
    );
}

/// The documented O1 consequence, pinned end to end: a key-shaped name is a
/// valid *name*, so `set` succeeds, `ls` prints the folded name, and the 0600
/// inventory records it — while the value itself is nowhere on disk or in
/// either stream. This is why USAGE.md says a key typed on the command line
/// must be treated as exposed.
#[test]
fn a_key_shaped_name_is_accepted_and_listed_folded() {
    let harness = Harness::new();
    let typed = "sk-ant-API03-AbCdEf";
    let folded = typed.to_ascii_lowercase();
    let value = "sk-9f3a2b-7QwZ";

    let out = harness.run_recording_piped(&["secret", "set", typed], value.as_bytes());
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_no_value_leak(&out, value);

    let listed = harness.run_recording(&["secret", "ls"]);
    assert!(
        stdout_of(&listed).contains(&folded),
        "{}",
        stdout_of(&listed)
    );

    let inventory =
        std::fs::read_to_string(harness.config_dir().join("secret-inventory.json")).unwrap();
    assert!(inventory.contains(&folded), "{inventory}");
    assert!(
        !inventory.contains(value),
        "the inventory must hold names only"
    );
    let record = std::fs::read_to_string(harness.recording_path()).unwrap();
    assert!(
        !record.contains(value),
        "the recording backend stores no value bytes"
    );
}

/// `$HOME` unset / empty / relative: an explicit error from every verb and no
/// store created. Uses its own `Command` because the shared harness always sets
/// a usable `HOME`; `AGENT_VM_TEST_SECRET_RECORD` is unset so the failure is the
/// `$HOME` check, before any store is even constructed.
#[test]
fn an_unusable_home_fails_every_verb_without_creating_a_store() {
    let harness = Harness::new();
    let base = |home: Option<&str>| {
        let mut command = Command::new(agent_vm_bin());
        command
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("AGENT_VM_STATE_DIR", harness.state.path())
            .current_dir(harness.project.path())
            .stdin(Stdio::null());
        if let Some(home) = home {
            command.env("HOME", home);
        }
        command
    };

    let cases: [(Option<&str>, &str); 3] = [
        (None, "$HOME is not set"),
        (Some(""), "$HOME is set but empty"),
        (Some("rel/path"), "is not absolute"),
    ];
    let verbs: [&[&str]; 3] = [
        &["secret", "set", "svc"],
        &["secret", "ls"],
        &["secret", "rm", "svc"],
    ];
    for (home, needle) in cases {
        for verb in verbs {
            let out = base(home).args(verb).output().expect("failed to run");
            assert!(!out.status.success(), "HOME={home:?} {verb:?}");
            assert!(
                stderr_of(&out).contains(needle),
                "HOME={home:?} {verb:?}: {}",
                stderr_of(&out)
            );
        }
    }
    assert!(
        !harness.config_dir().exists(),
        "no store may be created without a usable HOME"
    );
}

/// A corrupt inventory is a hard error on every verb: the message names the
/// path and the recovery, and quotes no part of the file. The process-boundary
/// counterpart of `secret_store`'s S9, exercising `main`'s error rendering.
#[test]
fn a_corrupt_inventory_names_the_path_and_the_recovery_and_quotes_nothing() {
    let harness = Harness::new();
    let needle = "sk-ant-SECRET-NEEDLE";
    std::fs::create_dir_all(harness.config_dir()).unwrap();
    std::fs::write(
        harness.config_dir().join("secret-inventory.json"),
        format!("not json {needle}"),
    )
    .unwrap();

    let verbs: [&[&str]; 3] = [
        &["secret", "ls"],
        &["secret", "set", "svc"],
        &["secret", "rm", "svc"],
    ];
    for verb in verbs {
        let out = harness.run_recording_piped(verb, b"v");
        assert!(!out.status.success(), "{verb:?} must fail");
        let text = both_streams(&out);
        assert!(text.contains("is not valid JSON"), "{verb:?}: {text}");
        assert!(text.contains("secret-inventory.json"), "{verb:?}: {text}");
        assert!(
            text.contains("delete this file to reset the listing"),
            "{verb:?}: {text}"
        );
        assert!(!text.contains(needle), "{verb:?} quoted the file: {text}");
    }
}

/// Concurrent `set`s from separate processes on one store: the real
/// cross-process `flock(2)` must not lose an inventory row. S17 covers the
/// locking logic with in-process threads; this runs the shipped binary.
#[test]
fn concurrent_secret_sets_do_not_lose_an_inventory_row() {
    let harness = Harness::new();
    let mut children = Vec::new();
    for index in 0..12 {
        let name = format!("svc-{index}");
        let mut child = Command::new(agent_vm_bin())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", harness.home.path())
            .env("AGENT_VM_STATE_DIR", harness.state.path())
            .env("AGENT_VM_TEST_SECRET_RECORD", harness.recording_path())
            .current_dir(harness.project.path())
            .args(["secret", "set", &name])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to run agent-vm");
        child
            .stdin
            .take()
            .expect("child stdin is piped")
            .write_all(b"v")
            .expect("writing the piped value");
        children.push((name, child));
    }
    for (name, child) in &mut children {
        let status = child.wait().expect("waiting for agent-vm");
        assert!(status.success(), "concurrent set {name} failed");
    }

    let listed = harness.run_recording(&["secret", "ls"]);
    let text = stdout_of(&listed);
    for (name, _) in &children {
        assert!(text.contains(name.as_str()), "{name} missing from:\n{text}");
    }
}
