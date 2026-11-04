//! Black-box tests for `agent-vm tools print` (#510).
//!
//! Why black-box: the claims are about the *compiled executable* — that the output
//! is the binary's own catalog rather than any config file's, and that the verb needs
//! no msb, no state directory and no runtime. A unit test of the renderer cannot
//! observe dispatch order or the process environment, so every run below also
//! asserts that the decoy `msb` never ran and the state directory was never created.

use std::{
    io::Read,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

mod support;

fn agent_vm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_agent-vm"))
}

/// Run `child` to completion, killing it if it doesn't exit in time. Reads both
/// pipes on threads so a full pipe can't deadlock. Twelve other harnesses in this
/// test directory already carry their own copy and the shared `support` module does
/// not carry this one; de-duplicating them is a separate change.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("failed to spawn the test command");
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait failed") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the test command did not exit within {timeout:?} (possible hang)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Output {
        status,
        stdout: stdout_handle.join().unwrap(),
        stderr: stderr_handle.join().unwrap(),
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_success(out: &Output) {
    assert!(
        out.status.success(),
        "agent-vm failed ({}): {}",
        out.status,
        stderr_of(out)
    );
    assert_eq!(stderr_of(out), "", "a successful print says nothing");
}

/// One isolated `$HOME`, project cwd and state dir, plus the decoy msb and the
/// empty `PATH` that would expose either of them being used.
struct Harness {
    _base: tempfile::TempDir,
    project: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    msb_ran: PathBuf,
    decoy_msb: PathBuf,
    empty_path: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let base = tempfile::tempdir().unwrap();
        let home = base.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let empty_path = base.path().join("empty-path");
        std::fs::create_dir(&empty_path).unwrap();
        // Deliberately *not* created: the assertion is that no run creates it.
        let state = base.path().join("state");
        let msb_ran = base.path().join("msb-ran");
        let decoy_msb = base.path().join("msb");
        // The shell's own redirection, not `touch`: `PATH` below is empty, so an
        // external command would fail and the marker would never appear — and an
        // oracle that cannot fire passes whatever the binary does.
        std::fs::write(&decoy_msb, "#!/bin/sh\n: > \"$MSB_DECOY_MARKER\"\nexit 1\n").unwrap();
        std::fs::set_permissions(&decoy_msb, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            _base: base,
            project: support::project_tempdir(),
            home,
            state,
            msb_ran,
            decoy_msb,
            empty_path,
        }
    }

    /// The environment every run gets, for `program`. Shared with the decoy self-test so
    /// that self-test cannot pass under wiring the real runs never receive.
    fn command_for(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            // An empty PATH: nothing this verb legitimately does can spawn a
            // program, and the decoy msb below is reached only through MSB_PATH.
            .env("PATH", &self.empty_path)
            .env("HOME", &self.home)
            .env("AGENT_VM_STATE_DIR", &self.state)
            .env("MSB_PATH", &self.decoy_msb)
            .env("MSB_DECOY_MARKER", &self.msb_ran)
            .env("COLUMNS", "100")
            .current_dir(self.project.path());
        cmd
    }

    fn command(&self) -> Command {
        self.command_for(&agent_vm_bin())
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = self.command();
        cmd.args(args);
        let out = run_with_timeout(cmd, Duration::from_secs(30));
        self.assert_needed_nothing(out)
    }

    fn run_without_home(&self, args: &[&str]) -> Output {
        let mut cmd = self.command();
        cmd.env_remove("HOME").args(args);
        let out = run_with_timeout(cmd, Duration::from_secs(30));
        self.assert_needed_nothing(out)
    }

    /// A6 for every case: the MSB prologue and state creation are both observable
    /// side effects, and this verb must reach neither.
    fn assert_needed_nothing(&self, out: Output) -> Output {
        assert!(
            !self.msb_ran.exists(),
            "`tools print` entered the MSB prologue: {}",
            stderr_of(&out)
        );
        assert!(
            !self.state.exists(),
            "`tools print` created the state directory: {}",
            stderr_of(&out)
        );
        out
    }

    fn user_config(&self) -> PathBuf {
        self.home.join(".config/agent-vm/config.toml")
    }

    fn write_user_config(&self, text: &str) {
        write(&self.user_config(), text);
    }

    fn write_project_config(&self, text: &str) {
        write(&self.project.path().join(".agent-vm/config.toml"), text);
    }
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// The tool names a printed document declares, in document order.
fn printed_names(document: &str) -> Vec<String> {
    let parsed: toml::Table = toml::from_str(document).expect("the output is TOML");
    assert_eq!(
        parsed.keys().collect::<Vec<_>>(),
        ["tools"],
        "only tool declarations are printed"
    );
    declared_names(&parsed)
}

/// The tool names a config declares, in file order.
fn declared_names(config: &toml::Table) -> Vec<String> {
    config["tools"]
        .as_array()
        .expect("`tools` is an array of tables")
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .expect("every block names its tool")
                .to_owned()
        })
        .collect()
}

#[test]
fn prints_every_builtin_tool() {
    let harness = Harness::new();
    let out = harness.run(&["tools", "print"]);
    assert_success(&out);
    let document = stdout_of(&out);
    assert_eq!(
        printed_names(&document),
        [
            "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell"
        ]
    );

    // The header names this exact build, the same string `--version` reports, so a
    // pasted catalog can be traced to the release that printed it.
    let version = harness.run(&["--version"]);
    assert_success(&version);
    let build = stdout_of(&version)
        .trim_end()
        .strip_prefix("agent-vm ")
        .expect("--version prints the binary name first")
        .to_owned();
    assert_eq!(
        document.lines().next().unwrap(),
        format!(
            "# Built-in tool definitions of agent-vm {build}, printed by `agent-vm tools print`."
        )
    );
}

/// A5 and A6: no configuration and no environment decides the output. Each state
/// below is one a user really hits — their own catalog, a typo, a dangling
/// reference (a *loadable* file whose catalog fails to resolve) and no `$HOME`.
#[test]
fn output_ignores_every_config_state() {
    let harness = Harness::new();
    let clean_out = harness.run(&["tools", "print"]);
    assert_success(&clean_out);
    let clean = stdout_of(&clean_out);
    assert_eq!(
        printed_names(&clean),
        [
            "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell"
        ]
    );

    harness.write_user_config("[[tools]]\nname = \"mine\"\ncommand = \"x\"\n");
    harness.write_project_config("[[tools]]\nname = \"theirs\"\ncommand = \"y\"\n");
    let declared = harness.run(&["tools", "print"]);
    assert_success(&declared);
    assert_eq!(stdout_of(&declared), clean);

    harness.write_user_config("[[tools]\n");
    let unparseable = harness.run(&["tools", "print"]);
    assert_success(&unparseable);
    assert_eq!(stdout_of(&unparseable), clean);

    harness.write_user_config("[[tools]]\nname = \"mine\"\ncommand = \"x\"\ntools = [\"nope\"]\n");
    let unresolvable = harness.run(&["tools", "print"]);
    assert_success(&unresolvable);
    assert_eq!(stdout_of(&unresolvable), clean);

    let without_home = harness.run_without_home(&["tools", "print"]);
    assert_success(&without_home);
    assert_eq!(stdout_of(&without_home), clean);
}

/// The decoy's marker *is* the A6 oracle, so prove the decoy can write it under the
/// very environment a `tools print` run gets: `PATH` cleared to an empty directory.
/// Without this the decoy silently fails to mark itself and every A6 assertion
/// passes no matter what the binary does. The command comes from `command_for`, the
/// same construction the real runs use, so dropping the marker export there fails
/// here rather than silently disarming the oracle.
#[test]
fn the_decoy_msb_writes_its_marker_without_a_path() {
    let harness = Harness::new();
    let out = run_with_timeout(
        harness.command_for(&harness.decoy_msb),
        Duration::from_secs(30),
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "the decoy must fail its caller: {}",
        stderr_of(&out)
    );
    assert!(
        harness.msb_ran.exists(),
        "the decoy ran but left no marker: the msb oracle is vacuous"
    );
}

#[test]
fn named_tools_print_in_the_requested_order() {
    let harness = Harness::new();
    let out = harness.run(&["tools", "print", "shell", "codex"]);
    assert_success(&out);
    assert_eq!(printed_names(&stdout_of(&out)), ["shell", "codex"]);
}

/// A1 from the user's side: the paste is not merely valid TOML, it produces the
/// same verb list a launch would have offered without any config file.
#[test]
fn pasted_output_is_the_same_verb_list() {
    let pasted_harness = Harness::new();
    let printed = stdout_of(&pasted_harness.run(&["tools", "print"]));
    pasted_harness.write_user_config(&printed);

    let with_paste = pasted_harness.run(&["-h"]);
    assert_success(&with_paste);
    let defaults_harness = Harness::new();
    let with_defaults = defaults_harness.run(&["-h"]);
    assert_success(&with_defaults);
    assert_eq!(stdout_of(&with_paste), stdout_of(&with_defaults));
}

/// The state USAGE warns about, edited the way it says to edit it: a file that
/// already holds a real `[network]` grant and a valid top-level `tools = []`, which
/// a bare `>>` would turn into an invalid document (taking the grant with it).
#[test]
fn the_documented_edit_keeps_a_config_that_already_says_tools_empty() {
    let harness = Harness::new();
    let printed = stdout_of(&harness.run(&["tools", "print"]));

    let config = harness.user_config();
    // Top-level keys come before the first table header, so `tools = []` sits above
    // `[network]`; below it, TOML would read a *network* setting of that name.
    harness.write_user_config("tools = []\n\n[network]\nallow_lan = true\n");
    let accepted = harness.run(&["-h"]);
    assert_success(&accepted);
    assert!(
        !stdout_of(&accepted).contains("could not be read"),
        "the starting file must be one a user really has: {}",
        stdout_of(&accepted)
    );

    // The documented sequence: drop the `tools = []` line, then append the output.
    let kept: String = std::fs::read_to_string(&config)
        .unwrap()
        .lines()
        .filter(|line| line.trim() != "tools = []")
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(&config, format!("{kept}\n{printed}")).unwrap();

    let merged = harness.run(&["-h"]);
    assert_success(&merged);
    let defaults_harness = Harness::new();
    let with_defaults = defaults_harness.run(&["-h"]);
    assert_success(&with_defaults);
    assert_eq!(stdout_of(&merged), stdout_of(&with_defaults));

    // `-h` equality proves the catalog loads; it cannot tell the documented edit
    // from an overwrite that drops everything else, so pin the rest of the file.
    let edited = std::fs::read_to_string(&config).unwrap();
    let parsed: toml::Table = toml::from_str(&edited).expect("the edited file is TOML");
    assert_eq!(
        parsed
            .get("network")
            .and_then(|network| network.get("allow_lan"))
            .and_then(toml::Value::as_bool),
        Some(true),
        "the documented edit must keep the file's other settings: {edited}"
    );
    assert_eq!(
        declared_names(&parsed),
        [
            "dsh", "pi", "codex", "opencode", "claude", "copilot", "shell"
        ],
        "the edit must declare every built-in tool: {edited}"
    );
}

/// The other state USAGE's recipe covers, and the one no test reached: a file that
/// already declares its **own** `[[tools]]` blocks. An array of tables can be
/// followed by more blocks, so the documented move is a plain `>>` of the names the
/// file lacks — no edit first. A user in this state is the one who most needs the
/// shipped definitions back, and a wrong recipe leaves them with a config that no
/// longer loads.
#[test]
fn appending_the_names_a_config_lacks_keeps_the_tools_it_declares() {
    let harness = Harness::new();
    let config = harness.user_config();
    harness.write_user_config("[[tools]]\nname = \"mine\"\ncommand = \"x\"\n");

    let printed = stdout_of(&harness.run(&["tools", "print", "codex"]));
    let mut document = std::fs::read_to_string(&config).unwrap();
    document.push_str(&printed);
    std::fs::write(&config, document).unwrap();

    let listed = harness.run(&["-h"]);
    assert_success(&listed);
    let help = stdout_of(&listed);
    assert!(
        !help.contains("could not be read"),
        "the appended file must load: {help}"
    );
    // The launch verbs a catalog resolves appear as `  <name>  Launch …` lines below
    // `Commands:`. Later sections indent too, so compare only the two names of
    // interest, in the order the file declares them.
    let commands: Vec<&str> = help
        .split("Commands:\n")
        .nth(1)
        .expect("the help lists commands")
        .lines()
        .filter(|line| line.starts_with("  "))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(
        commands
            .iter()
            .copied()
            .filter(|verb| ["mine", "codex"].contains(verb))
            .collect::<Vec<_>>(),
        ["mine", "codex"],
        "the file's own tool must survive the append: {help}"
    );

    // The appended block is the shipped definition, not merely a name: `codex`'s
    // `network_requests` are what a later `allow_egress = ["tool:codex"]` resolves
    // against the user file, which is the whole reason this command exists (#506).
    let edited = std::fs::read_to_string(&config).unwrap();
    let parsed: toml::Table = toml::from_str(&edited).expect("the appended file is TOML");
    assert_eq!(declared_names(&parsed), ["mine", "codex"]);
    let codex = &parsed["tools"].as_array().unwrap()[1];
    assert_eq!(codex["command"].as_str(), Some("codex"));
    let requests: Vec<&str> = codex["network_requests"]
        .as_array()
        .expect("codex declares its egress grants")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    assert_eq!(
        requests,
        ["api.openai.com", "auth.openai.com", "chatgpt.com"],
        "the appended definition must stay whole: {edited}"
    );
    assert_eq!(
        codex["env"]["CODEX_HOME"].as_str(),
        Some("/agent-vm-state/codex")
    );
}

/// R8: the sub-help is where a reader learns the default and the request order, so
/// it is pinned rather than left to the short summary clap derives from it.
#[test]
fn the_sub_help_states_the_default_the_order_and_the_target_file() {
    let harness = Harness::new();
    let out = harness.run(&["tools", "print", "--help"]);
    assert_success(&out);
    // clap wraps to `COLUMNS`, so compare on collapsed whitespace.
    let help = stdout_of(&out)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for expected in [
        "With no NAME, prints every built-in tool",
        "Named tools print in the order given",
        "~/.config/agent-vm/config.toml",
    ] {
        assert!(help.contains(expected), "{expected:?} missing from: {help}");
    }
}

/// A3 and A4: a rejected name is not a partial document on stdout.
#[test]
fn an_unknown_or_repeated_name_fails_with_empty_stdout() {
    let harness = Harness::new();

    let unknown = harness.run(&["tools", "print", "codex", "nope"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert_eq!(
        stdout_of(&unknown),
        "",
        "nothing is written before a refusal"
    );
    let text = stderr_of(&unknown);
    assert!(
        text.contains("no built-in tool is named \"nope\""),
        "{text}"
    );
    assert!(
        text.contains("dsh, pi, codex, opencode, claude, copilot, shell"),
        "{text}"
    );

    let repeated = harness.run(&["tools", "print", "codex", "codex"]);
    assert_eq!(repeated.status.code(), Some(1));
    assert_eq!(stdout_of(&repeated), "");
    assert!(
        stderr_of(&repeated).contains("\"codex\" is named more than once"),
        "{}",
        stderr_of(&repeated)
    );
}
