//! The direct-terminal driver: one launch, one case, one receipt (#400, #699).
//!
//! Ported from `script/test/lib/direct-terminal.py`. One invocation runs exactly
//! one case in one command form against a real launcher and a real VM, and writes
//! a JSON receipt plus raw captures into the caller's evidence directory. The
//! case inventory is fixed — no `eval`, no shell command text, no user program —
//! so the driver can be reviewed once and re-run for every candidate.
//!
//! Two oracles are kept apart, as in the Python: the **driver's** verdict (did
//! the observations I expect hold?) and the **launcher's** actual exit status,
//! which is recorded and never inferred. A guest marker, a hex dump or a
//! guest-reported size is the oracle for guest behaviour; a launcher's `==>`
//! notices never are, and the host terminal's echo is never counted as guest
//! output.
//!
//! The port is complete (#699): all 57 rows of the Python's matrix — identity,
//! input, resize, stream-input, argv, status, program, reject, wait,
//! legacy-detach, prompt and signal — are here, and the Python driver and its
//! contract script are gone. The pinned row counts below are asserted by
//! `harness direct-terminal --self-test`, so a row cannot be dropped by deleting
//! it, and [`Group::remaining_rows`] is the one place a new row would be declared
//! before it runs.
//!
//! Every wait is bounded: a case deadline, a marker deadline, a control's own
//! timeout, and `pty::OwnedChild` for the child. The failure mode of a PTY driver
//! is a hang, not a wrong answer.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs, io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    os::unix::fs::PermissionsExt,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use clap::ValueEnum;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{Mode, OFlags},
    io::Errno,
    process::Signal,
    termios::LocalModes,
};
use serde_json::{Map, Value, json};

use crate::{Outcome, pty};

pub mod controls;
pub mod prompt;
pub mod signal;

// --- Constants --------------------------------------------------------------

/// One case's whole interaction. A correct case takes seconds; the bound exists
/// so a hang fails loudly instead of blocking the matrix.
const DEFAULT_CASE_DEADLINE: f64 = 240.0;
/// One *observation* inside a case. The boot-free controls shorten it so a
/// "never delivers EOF" row fails fast.
const DEFAULT_MARKER_DEADLINE: f64 = 60.0;
/// The geometry the driver assigns, and the geometry the resize case asks for.
///
/// Not 24x80 on purpose: the stock SDK creates the guest PTY at 24x80 every
/// time, so a launcher that failed to send the host's own size would still pass
/// a 24x80 fixture. The guest reports its first size with `stty size`, and that
/// report is the oracle.
const INITIAL_SIZE: pty::WindowSize = pty::WindowSize::new(37, 111);
const RESIZED_SIZE: pty::WindowSize = pty::WindowSize::new(43, 119);
/// The canonical host input for the streamed-input case, as literal bytes.
const STREAM_INPUT_CHUNKS: [&[u8]; 3] = [b"stream-A\n", b"stream-B", b"\n"];
const STREAM_INPUT_EXPECTED: &[u8] = b"stream-A\nstream-B\n";
/// The input case's typed bytes, split so the escape byte travels alone.
const INPUT_CHUNKS: [&[u8]; 3] = [b"A", b"\x1d", b"B"];
const INPUT_EXPECTED_HEX: &str = "411d42";
/// How long [`Session::pump`] keeps reading after the launcher has exited, so a
/// last write that is still in flight is not mistaken for no write at all.
const EXIT_DRAIN: Duration = Duration::from_millis(500);

const PROBE_NAME: &str = "guest-probe.sh";

// --- The case inventory -----------------------------------------------------

/// The porting unit, and the shape a successor continues with. Every group is
/// ported now: [`Group::remaining_rows`] is the one place a not-yet-ported row
/// would be declared, and [`Group::ported`] follows from it. The pinned counts in
/// [`EXPECTED_ROWS`] keep both sides of the split honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Both descriptors' terminal status, the force-off option and legacy
    /// `shell` selection: what mode the launch selects and what the guest sees.
    Identity,
    /// Ctrl-] reaches the guest unchanged.
    Input,
    /// The resize handshake, including the guest's own first size.
    Resize,
    /// Streamed input from a terminal stdin, exact bytes and the host's VEOF.
    StreamInput,
    /// Tokens after the command boundary are guest argv.
    Argv,
    /// A guest's own exit status, through a PTY.
    Status,
    /// A missing and a non-executable program: 127 and 126.
    Program,
    /// Refused argument combinations: status 2 before any boot.
    Reject,
    /// Runtime loss while the command is pending.
    Wait,
    /// The legacy Ctrl-] detach and its sentinel-derived 255.
    LegacyDetach,
    /// The #501 in-terminal access prompt.
    Prompt,
    /// #401 host SIGINT/SIGTERM supervision.
    Signal,
}

impl Group {
    pub const ALL: [Group; 12] = [
        Group::Identity,
        Group::Input,
        Group::Resize,
        Group::StreamInput,
        Group::Argv,
        Group::Status,
        Group::Program,
        Group::Reject,
        Group::Wait,
        Group::LegacyDetach,
        Group::Prompt,
        Group::Signal,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Group::Identity => "identity",
            Group::Input => "input",
            Group::Resize => "resize",
            Group::StreamInput => "stream-input",
            Group::Argv => "argv",
            Group::Status => "status",
            Group::Program => "program",
            Group::Reject => "reject",
            Group::Wait => "wait",
            Group::LegacyDetach => "legacy-detach",
            Group::Prompt => "prompt",
            Group::Signal => "signal",
        }
    }

    /// Whether this group's rows are in [`cases`]. Every group is ported: the rust
    /// driver serves the Python's whole 57-row matrix.
    pub fn ported(self) -> bool {
        matches!(
            self,
            Group::Identity
                | Group::Input
                | Group::Resize
                | Group::StreamInput
                | Group::Argv
                | Group::Status
                | Group::Program
                | Group::Reject
                | Group::Wait
                | Group::LegacyDetach
                | Group::Prompt
                | Group::Signal
        )
    }

    /// Whether a boot-free control can certify this group's rows.
    ///
    /// A control can only prove a group whose subject the stand-in can play. The
    /// refusal, program, runtime-loss and legacy-detach groups are about the real
    /// launcher's own answers — a stand-in that exited 2 on demand would prove
    /// that the driver reads a status, not that the launcher refuses an argument
    /// combination before booting. Those rows are ported and runnable; they are
    /// *verified* only by the native e2e row, and the artifact names them.
    fn control_proven(self) -> bool {
        !matches!(
            self,
            Group::Program
                | Group::Reject
                | Group::Wait
                | Group::LegacyDetach
                | Group::Prompt
                | Group::Signal
        )
    }

    /// The rows of a group that this driver does not run yet, by the Python's own
    /// names. Empty for every group — the port is complete — so the partition
    /// control still has one source for "a row the Python had and this does not".
    pub fn remaining_rows(self) -> &'static [&'static str] {
        match self {
            Group::Identity
            | Group::Input
            | Group::Resize
            | Group::StreamInput
            | Group::Argv
            | Group::Status
            | Group::Program
            | Group::Reject
            | Group::Wait
            | Group::LegacyDetach
            | Group::Prompt
            | Group::Signal => &[],
        }
    }
}

/// Every row of the whole inventory, per group, pinned so a "port" cannot shrink
/// the matrix. Taken from the Python's own tables: `CASES` (18 + 16 prompt + 18
/// signal), `REJECT_CASES` (3) and `PROGRAM_CASES` (2).
pub const EXPECTED_ROWS: [(Group, usize); 12] = [
    (Group::Identity, 9),
    (Group::Input, 1),
    (Group::Resize, 1),
    (Group::StreamInput, 2),
    (Group::Argv, 1),
    (Group::Status, 2),
    (Group::Program, 2),
    (Group::Reject, 3),
    (Group::Wait, 1),
    (Group::LegacyDetach, 1),
    (Group::Prompt, 16),
    (Group::Signal, 18),
];

/// How a case's descriptors are assigned. `Tty` is the driver's own PTY; `Pipe`
/// and `File` are a real pipe and a real regular file, never `/dev/null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Tty,
    Pipe,
    File,
}

/// Where the guest's stderr marker is allowed to appear. Named evidence, so a
/// merged PTY stream and a separated stream are told apart by what arrived
/// rather than by a launcher notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrChannel {
    /// A PTY merges the guest's stderr into its stdout stream.
    MergedIntoStdout,
    /// The guest's stderr stayed on the host stderr channel or the terminal.
    Stderr,
    /// The guest's stderr shares the host terminal.
    Terminal,
}

/// A project fixture a row is about, written into the project before the launch.
/// The project owns it, so the driver writes it rather than trusting a leftover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixture {
    /// A regular file with no execute bit: a launcher that only checked existence
    /// would answer 127 for a program it should answer 126 for.
    NotExecutable,
}

impl Fixture {
    fn name(self) -> &'static str {
        match self {
            Fixture::NotExecutable => "not-executable",
        }
    }

    fn write(self, project: &Path) -> Result<(), String> {
        let path = project.join(self.name());
        fs::write(&path, "#!/bin/sh\nexit 0\n")
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let mode = match self {
            Fixture::NotExecutable => 0o644,
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("{}: {error}", path.display()))
    }
}

/// What one case must observe. The oracle is named here rather than chased
/// through a string-prefix dispatch, so a row cannot lose its expectation.
#[derive(Debug, Clone, Copy)]
pub enum Expect {
    /// An identity report, the guest's three tty bits and the channel split.
    Identity { guest_pty: bool, err: ErrChannel },
    /// The exact three bytes and the guest's own 7.
    Input,
    /// The initial size, the resize relay, and the guest's 7.
    Resize,
    /// The streamed payload's byte count, cksum and hex, and the guest's 23.
    StreamInput,
    /// The two suffix tokens as guest argv.
    Argv,
    /// The guest exited with this status and the launcher passed it through.
    Status(i32),
    /// A program the launcher cannot run: its own status, and nothing else. The
    /// words are the program itself, because the row is about the launcher's
    /// answer to it rather than about a guest.
    Program {
        words: &'static [&'static str],
        expect: i32,
        fixture: Option<Fixture>,
    },
    /// A refused launch: status 2 before any boot, an actionable diagnostic, and
    /// the caller's pipe left unread.
    Reject { stdin: Channel },
    /// Runtime loss while the command waits: 125, no false guest exit.
    Wait,
    /// The legacy Ctrl-] detach and the SDK's sentinel-derived 255.
    LegacyDetach,
    /// The #501 in-terminal access prompt: its own frames, its own keys, and the
    /// launcher's `access` command afterwards.
    Prompt(&'static prompt::Row),
    /// #401 host signal supervision: the signals to deliver, the markers the guest
    /// must report, and the teardown the row's status can be told apart by.
    Signal(&'static signal::Row),
}

pub struct Case {
    pub name: &'static str,
    pub group: Group,
    /// The launcher's launch options, before the command boundary.
    pub options: &'static [&'static str],
    /// The guest probe's mode and its arguments.
    pub probe: &'static [&'static str],
    pub stdin: Channel,
    pub stdout: Channel,
    pub stderr: Channel,
    /// The case's own environment overrides. A case's setting is the case's fact,
    /// not the operator's.
    pub env: &'static [(&'static str, &'static str)],
    /// A legacy route (`shell …`) instead of the direct `run`/`--` boundary.
    pub route: Option<&'static [&'static str]>,
    pub expect: Expect,
}

const IDENTITY: Expect = Expect::Identity {
    guest_pty: true,
    err: ErrChannel::MergedIntoStdout,
};
const STREAMED: Expect = Expect::Identity {
    guest_pty: false,
    err: ErrChannel::Stderr,
};
const STREAMED_TERMINAL_ERR: Expect = Expect::Identity {
    guest_pty: false,
    err: ErrChannel::Terminal,
};

/// The ported inventory. Each row's comment is the reason the row exists — the
/// shape it is the only row to discriminate.
const CASES: [Case; 57] = [
    // Both descriptors are terminals: auto must select a PTY, so the guest sees a
    // terminal on all three and one merged output stream.
    Case {
        name: "identity-auto",
        group: Group::Identity,
        options: &[],
        probe: &["identity"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: IDENTITY,
    },
    // A redirected stdout must stream even though stdin is a terminal: this is
    // the case a stdin-only predicate cannot pass.
    Case {
        name: "identity-redirected",
        group: Group::Identity,
        options: &[],
        probe: &["identity"],
        stdin: Channel::Tty,
        stdout: Channel::File,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: STREAMED_TERMINAL_ERR,
    },
    // stderr's terminal status is irrelevant: same stdin/stdout, stderr
    // redirected.
    Case {
        name: "identity-stderr-file",
        group: Group::Identity,
        options: &[],
        probe: &["identity"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: IDENTITY,
    },
    // Forced PTY with a redirected stdout: a PTY nonetheless, merged into the
    // file.
    Case {
        name: "identity-force-tty",
        group: Group::Identity,
        options: &["-t"],
        probe: &["identity"],
        stdin: Channel::Tty,
        stdout: Channel::File,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: IDENTITY,
    },
    // Forced streaming from a terminal: separate channels, no guest terminal.
    Case {
        name: "identity-force-stream",
        group: Group::Identity,
        options: &["-T"],
        probe: &["identity"],
        stdin: Channel::Tty,
        stdout: Channel::File,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: STREAMED,
    },
    // A piped stdin auto-selects streaming, even though stdout is a terminal.
    Case {
        name: "identity-stdin-pipe",
        group: Group::Identity,
        options: &[],
        probe: &["identity"],
        stdin: Channel::Pipe,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: STREAMED_TERMINAL_ERR,
    },
    // Forced streaming with *both* descriptors terminals, which auto would have
    // made a PTY: without this the force-off option could be ignored and the row
    // would still pass. The guest's stderr goes to a file so "separate channels"
    // is visible rather than assumed.
    Case {
        name: "identity-force-stream-both",
        group: Group::Identity,
        options: &["-T"],
        probe: &["identity"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: STREAMED,
    },
    // The second spelling of force-off, same shape: `--no-tty` cannot be a
    // parse-only option.
    Case {
        name: "identity-no-tty-both",
        group: Group::Identity,
        options: &["--no-tty"],
        probe: &["identity"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: STREAMED,
    },
    // The legacy `shell` route keeps its stdin-only PTY selection: stdout
    // redirected, still a PTY, still one merged stream in the file.
    Case {
        name: "legacy-shell-pty",
        group: Group::Identity,
        options: &[],
        probe: &["identity"],
        stdin: Channel::Tty,
        stdout: Channel::File,
        stderr: Channel::Tty,
        env: &[],
        route: Some(&["shell", "bash", "-c", "./guest-probe.sh identity"]),
        expect: IDENTITY,
    },
    // Ctrl-] reaches the guest unchanged and does not end the session.
    Case {
        name: "input",
        group: Group::Input,
        options: &["-t"],
        probe: &["input"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Input,
    },
    // Resizes come from stdin's terminal even when stdout is a file.
    Case {
        name: "resize",
        group: Group::Resize,
        options: &["-t"],
        probe: &["resize"],
        stdin: Channel::Tty,
        stdout: Channel::File,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Resize,
    },
    // Streamed input from a *terminal* stdin, selected by a redirected stdout.
    Case {
        name: "stream-input-auto",
        group: Group::StreamInput,
        options: &[],
        probe: &["stream-input"],
        stdin: Channel::Tty,
        stdout: Channel::File,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: Expect::StreamInput,
    },
    // Streamed input from a terminal stdin under the forced spelling.
    Case {
        name: "stream-input-no-tty",
        group: Group::StreamInput,
        options: &["-T"],
        probe: &["stream-input"],
        stdin: Channel::Tty,
        stdout: Channel::File,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: Expect::StreamInput,
    },
    // Tokens after the command boundary are guest argv, including the two
    // spellings that look like the launcher's own options.
    Case {
        name: "suffix-argv",
        group: Group::Argv,
        options: &["-T"],
        probe: &["argv", "--tty", "-T"],
        stdin: Channel::Pipe,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Argv,
    },
    Case {
        name: "status-exit0",
        group: Group::Status,
        options: &["-t"],
        probe: &["status", "0"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Status(0),
    },
    // Recording a status is not observing it: a launcher that answered 0 for
    // every guest would pass both status rows if only the 0 row existed.
    Case {
        name: "status-exit7",
        group: Group::Status,
        options: &["-t"],
        probe: &["status", "7"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Status(7),
    },
    // A program that does not exist: the launcher answers 127 itself. A row that
    // accepted any non-zero status would pass on a launcher that answered 64 for
    // its own failure.
    Case {
        name: "status-missing",
        group: Group::Program,
        options: &["-t"],
        probe: &[],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Program {
            words: &["no-such-program-400"],
            expect: 127,
            fixture: None,
        },
    },
    // A program that exists and has no execute bit: 126, which a launcher that
    // only checked existence would answer 127 for. The project owns the fixture.
    Case {
        name: "status-nonexec",
        group: Group::Program,
        options: &["-t"],
        probe: &[],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Program {
            words: &["./not-executable"],
            expect: 126,
            fixture: Some(Fixture::NotExecutable),
        },
    },
    // A refused option combination: status 2 before any boot, and the caller's
    // pipe still holds its payload afterwards. The program is `true` because a
    // refusal must never reach it.
    Case {
        name: "reject-pipe-tty",
        group: Group::Reject,
        options: &["-t"],
        probe: &[],
        stdin: Channel::Pipe,
        stdout: Channel::Pipe,
        stderr: Channel::Pipe,
        env: &[],
        route: None,
        expect: Expect::Reject {
            stdin: Channel::Pipe,
        },
    },
    // The same refusal with a real regular file stdin, and the other force-on
    // spelling: the check is about terminal-ness, not about one option.
    Case {
        name: "reject-file-tty",
        group: Group::Reject,
        options: &["--tty"],
        probe: &[],
        stdin: Channel::File,
        stdout: Channel::Pipe,
        stderr: Channel::Pipe,
        env: &[],
        route: None,
        expect: Expect::Reject {
            stdin: Channel::File,
        },
    },
    // Two options that contradict each other: refused as a usage error, not
    // resolved in either direction.
    Case {
        name: "reject-conflict",
        group: Group::Reject,
        options: &["--tty", "-T"],
        probe: &[],
        stdin: Channel::Pipe,
        stdout: Channel::Pipe,
        stderr: Channel::Pipe,
        env: &[],
        route: None,
        expect: Expect::Reject {
            stdin: Channel::Pipe,
        },
    },
    // The owned runtime dies while the command waits: 125, and no false guest
    // exit. The row kills the catalog's own runtime by identity, so it needs a
    // real launcher and a real catalog.
    Case {
        name: "wait",
        group: Group::Wait,
        options: &["-t"],
        probe: &["wait"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Wait,
    },
    // The legacy `shell` route still detaches on Ctrl-]: the key never reaches
    // the guest, and the SDK's own sentinel status is what comes back.
    Case {
        name: "legacy-detach",
        group: Group::LegacyDetach,
        options: &[],
        probe: &["wait"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: Some(&["shell", "bash", "-c", "./guest-probe.sh wait"]),
        expect: Expect::LegacyDetach,
    },
    // AC1: a refused connect prompts, `d` restores, the guest continues with its
    // 60 held lines in order, and `access` still lists the refusal.
    Case {
        name: "prompt-deny",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::DENY),
    },
    // AC2: `s` grants a session allowance at a confirmed revision >= 2, and the
    // same connect then succeeds without a restart.
    Case {
        name: "prompt-session",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse", "1.1.1.1", "443", "1"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::SESSION),
    },
    // AC3's other arm: the full offer's `p` applies now and records, which `s`
    // does not.
    Case {
        name: "prompt-project",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse", "1.1.1.1", "443", "1"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::PROJECT),
    },
    // AC3/#491: a destination only a record can admit offers "next launch", and
    // only the record is written.
    Case {
        name: "prompt-project-next",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse-dns"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::PROJECT_NEXT),
    },
    // AC4: a key typed before the guard, then `ss` in one write, never grants,
    // and no answer byte reaches the guest.
    Case {
        name: "prompt-guard",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::GUARD),
    },
    // AC12: a CLI `access allow` closes the shown prompt, and a `p` typed while
    // that grant is in flight must never write a project record.
    Case {
        name: "prompt-answered-elsewhere",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::ANSWERED_ELSEWHERE),
    },
    // AC7's alternate-screen half: DECRC, the host's final size, a redraw asked
    // for.
    Case {
        name: "prompt-alt-screen",
        group: Group::Prompt,
        options: &[],
        probe: &["alt"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::ALT_SCREEN),
    },
    // AC8: a stalled sequence is cut with CAN, and the prompt is up by 1.5 s.
    Case {
        name: "prompt-stall",
        group: Group::Prompt,
        options: &[],
        probe: &["stall"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::STALL),
    },
    // AC13's guest-exit half: unanswered, the guest's own exit ends it, with the
    // leave before its held output and its own status.
    Case {
        name: "prompt-exit",
        group: Group::Prompt,
        options: &[],
        probe: &["exit-during"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::EXIT),
    },
    // AC13's forced half: two external SIGINTs; the guest ignores INT/TERM, so
    // the second forces the launcher and its restore appears exactly once. The
    // launcher's notices go to a file, so "the stream ends at the restore" is a
    // statement about the terminal.
    Case {
        name: "prompt-forced",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse", "203.0.113.10", "443", "0", "ignore"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::FORCED),
    },
    // AC13's forced half on the alternate screen.
    Case {
        name: "prompt-forced-alt",
        group: Group::Prompt,
        options: &[],
        probe: &["alt", "ignore"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::FORCED_ALT),
    },
    // AC13's runtime-loss half: the owned runtime is killed while the question
    // is up; 125 and exactly one host restore.
    Case {
        name: "prompt-runtime-loss",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::RUNTIME_LOSS),
    },
    // The same on the alternate screen.
    Case {
        name: "prompt-runtime-loss-alt",
        group: Group::Prompt,
        options: &[],
        probe: &["alt"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::File,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::RUNTIME_LOSS_ALT),
    },
    // AC9 in its three shapes: the setting off, `TERM=dumb`, and `-t` with a
    // redirected stdout. No prompt bytes; the hint exactly once.
    Case {
        name: "prompt-off-env",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[("AGENT_VM_NO_ACCESS_PROMPT", "1")],
        route: None,
        expect: Expect::Prompt(&prompt::OFF_ENV),
    },
    Case {
        name: "prompt-off-dumb",
        group: Group::Prompt,
        options: &[],
        probe: &["refuse"],
        stdin: Channel::Tty,
        stdout: Channel::Tty,
        stderr: Channel::Tty,
        env: &[("TERM", "dumb")],
        route: None,
        expect: Expect::Prompt(&prompt::OFF_DUMB),
    },
    Case {
        name: "prompt-off-redirect",
        group: Group::Prompt,
        options: &["-t"],
        probe: &["refuse"],
        stdin: Channel::Tty,
        stdout: Channel::File,
        stderr: Channel::Tty,
        env: &[],
        route: None,
        expect: Expect::Prompt(&prompt::OFF_REDIRECT),
    },
    // --- #401 host signal supervision ---------------------------------------
    //
    // Both modes × both signals × the four outcomes #401 names, plus the
    // self-signalled row each mode owes. `signal::case` takes the row's options
    // and channels from the row's own mode, so a streaming row cannot claim a
    // guest terminal and a PTY row cannot claim separate channels.
    signal::case(
        "signal-pty-int-handled",
        &["signal-handle", "42"],
        &signal::PTY.int_handled,
    ),
    signal::case(
        "signal-pty-int-unhandled",
        &["signal-unhandled"],
        &signal::PTY.int_unhandled,
    ),
    signal::case(
        "signal-pty-int-ignored",
        &["signal-ignore"],
        &signal::PTY.int_ignored,
    ),
    signal::case(
        "signal-pty-int-second",
        &["signal-ignore"],
        &signal::PTY.int_second,
    ),
    signal::case(
        "signal-pty-term-handled",
        &["signal-handle", "42"],
        &signal::PTY.term_handled,
    ),
    signal::case(
        "signal-pty-term-unhandled",
        &["signal-unhandled"],
        &signal::PTY.term_unhandled,
    ),
    signal::case(
        "signal-pty-term-ignored",
        &["signal-ignore"],
        &signal::PTY.term_ignored,
    ),
    signal::case(
        "signal-pty-term-second",
        &["signal-ignore"],
        &signal::PTY.term_second,
    ),
    signal::case(
        "signal-pty-self-term",
        &["signal-self-term"],
        &signal::PTY.self_term,
    ),
    signal::case(
        "signal-stream-int-handled",
        &["signal-handle", "42"],
        &signal::STREAM.int_handled,
    ),
    signal::case(
        "signal-stream-int-unhandled",
        &["signal-unhandled"],
        &signal::STREAM.int_unhandled,
    ),
    signal::case(
        "signal-stream-int-ignored",
        &["signal-ignore"],
        &signal::STREAM.int_ignored,
    ),
    signal::case(
        "signal-stream-int-second",
        &["signal-ignore"],
        &signal::STREAM.int_second,
    ),
    signal::case(
        "signal-stream-term-handled",
        &["signal-handle", "42"],
        &signal::STREAM.term_handled,
    ),
    signal::case(
        "signal-stream-term-unhandled",
        &["signal-unhandled"],
        &signal::STREAM.term_unhandled,
    ),
    signal::case(
        "signal-stream-term-ignored",
        &["signal-ignore"],
        &signal::STREAM.term_ignored,
    ),
    signal::case(
        "signal-stream-term-second",
        &["signal-ignore"],
        &signal::STREAM.term_second,
    ),
    signal::case(
        "signal-stream-self-term",
        &["signal-self-term"],
        &signal::STREAM.self_term,
    ),
];

pub fn cases() -> BTreeMap<&'static str, &'static Case> {
    CASES.iter().map(|case| (case.name, case)).collect()
}

/// Every row `--case` accepts: the Python's whole matrix, ported.
pub fn ported_rows() -> Vec<&'static str> {
    let mut rows: Vec<&'static str> = CASES.iter().map(|case| case.name).collect();
    rows.sort_unstable();
    rows
}

// --- Guest reports ----------------------------------------------------------

/// The facts a guest report carries, so a value containing spaces is one value
/// and a line carrying two facts is two facts.
const REPORT_KEYS: [&str; 8] = ["tty0", "tty1", "tty2", "UID", "GID", "PWD", "PATH", "HOOK"];

/// Every `KEY=VALUE` fact in a guest report. A value runs to the next known key
/// or the end of the line: a PATH the project hook prepended may contain spaces,
/// and splitting those on whitespace would silently compare a truncated value.
pub fn parse_report(text: &str) -> BTreeMap<String, String> {
    let mut report = BTreeMap::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        let mut found: Vec<(usize, usize, &str)> = Vec::new();
        for (index, _) in line.bytes().enumerate() {
            let boundary = match index.checked_sub(1).and_then(|at| line.as_bytes().get(at)) {
                Some(byte) => !(byte.is_ascii_alphanumeric() || *byte == b'_'),
                None => true,
            };
            if !boundary {
                continue;
            }
            let Some(rest) = line.get(index..) else {
                continue;
            };
            for key in REPORT_KEYS {
                if let Some(tail) = rest.strip_prefix(key)
                    && tail.starts_with('=')
                {
                    found.push((index, index + key.len() + 1, key));
                }
            }
        }
        for (position, (_, after, key)) in found.iter().enumerate() {
            let end = found
                .get(position + 1)
                .map(|(start, _, _)| *start)
                .unwrap_or(line.len());
            if let Some(value) = line.get(*after..end) {
                report.insert((*key).to_owned(), value.trim().to_owned());
            }
        }
    }
    report
}

/// The `KEY=VALUE` fields of one `PREFIX k=v` report line.
pub fn parse_kv(line: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for token in line.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }
    fields
}

fn marker_line<'a>(text: &'a str, prefix: &str) -> Result<&'a str, String> {
    text.split('\n')
        .find(|line| line.starts_with(prefix))
        .ok_or_else(|| format!("no {prefix:?} line in {text:?}"))
}

fn require(condition: bool, message: impl FnOnce() -> String) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message()) }
}

fn tail(text: &str) -> String {
    let mut kept: String = text.chars().rev().take(2000).collect();
    kept = kept.chars().rev().collect();
    kept
}

/// The host `cksum` of these bytes, asked of the host program rather than
/// re-implemented here: the guest computes the same value with the guest's own
/// `cksum`, and two implementations of one checksum would be two oracles.
fn cksum_of(payload: &[u8]) -> Result<String, String> {
    let mut child = Command::new("cksum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot run cksum: {error}"))?;
    {
        use std::io::Write;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "cksum has no stdin".to_owned())?;
        stdin
            .write_all(payload)
            .map_err(|error| format!("cannot write to cksum: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot read cksum: {error}"))?;
    if !output.status.success() {
        return Err(format!("cksum exited {}", output.status));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| format!("cksum printed no checksum: {text:?}"))
}

// --- The host terminal ------------------------------------------------------

/// The terminal facts a raw-mode session must restore.
///
/// Read with `libc::tcgetattr` rather than `rustix::termios` because the
/// comparison includes the input and output *speeds*, which `rustix`'s
/// `Termios` does not expose. The Python compared them, so an oracle that
/// dropped them would be a smaller oracle, not a simpler one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalState {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    ispeed: u32,
    ospeed: u32,
    vmin: u8,
    vtime: u8,
}

impl TerminalState {
    /// Only the fields a session may legitimately change. Kernel bookkeeping
    /// (macOS `PENDIN`) reflects unread input at the terminal and is not part of
    /// what a session owns.
    ///
    /// Typed `tcflag_t`, which is 32-bit on Linux and 64-bit on macOS: the masks
    /// have the terminal's own width, so no cast has to be right on both.
    const LOCAL: libc::tcflag_t =
        libc::ICANON | libc::ECHO | libc::ECHONL | libc::ISIG | libc::IEXTEN;
    const INCOMING: libc::tcflag_t =
        libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP;
    const OUTPUT: libc::tcflag_t = libc::OPOST;
}

pub fn terminal_state(fd: BorrowedFd<'_>) -> io::Result<TerminalState> {
    let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `attributes` is a live `termios` this call fills in, and `fd` is a
    // descriptor the caller owns for the duration of the call.
    if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TerminalState {
        iflag: (attributes.c_iflag & TerminalState::INCOMING) as u32,
        oflag: (attributes.c_oflag & TerminalState::OUTPUT) as u32,
        cflag: attributes.c_cflag as u32,
        lflag: (attributes.c_lflag & TerminalState::LOCAL) as u32,
        ispeed: attributes.c_ispeed as u32,
        ospeed: attributes.c_ospeed as u32,
        vmin: attributes.c_cc[libc::VMIN],
        vtime: attributes.c_cc[libc::VTIME],
    })
}

use std::os::fd::AsRawFd;

// --- One session ------------------------------------------------------------

/// One launcher process with assigned descriptors, drained concurrently so a
/// chatty launcher cannot block on a full pipe while a case waits for its own
/// marker.
pub struct Session {
    argv: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    cwd: PathBuf,
    work: PathBuf,
    stdin: Channel,
    stdout: Channel,
    stderr: Channel,
    terminal: Option<pty::Pty>,
    baseline: Option<TerminalState>,
    stdout_path: Option<PathBuf>,
    stdin_read: Option<OwnedFd>,
    stdin_write: Option<OwnedFd>,
    child_stdout: Option<OwnedFd>,
    child_stderr: Option<OwnedFd>,
    child: Option<pty::OwnedChild>,
    /// The launcher's pid, for an observation that has to name it.
    pub launcher_pid: Option<i32>,
    tty: Vec<u8>,
    out: Vec<u8>,
    err: Vec<u8>,
    master_closed: bool,
    deadline: Instant,
}

impl Session {
    pub fn new(
        argv: Vec<OsString>,
        env: Vec<(OsString, OsString)>,
        cwd: PathBuf,
        work: PathBuf,
    ) -> Self {
        Self {
            argv,
            env,
            cwd,
            work,
            stdin: Channel::Tty,
            stdout: Channel::Tty,
            stderr: Channel::Tty,
            terminal: None,
            baseline: None,
            stdout_path: None,
            stdin_read: None,
            stdin_write: None,
            child_stdout: None,
            child_stderr: None,
            child: None,
            launcher_pid: None,
            tty: Vec::new(),
            out: Vec::new(),
            err: Vec::new(),
            master_closed: false,
            deadline: Instant::now() + Duration::from_secs_f64(case_deadline()),
        }
    }

    pub fn assign(
        &mut self,
        stdin: Channel,
        stdout: Channel,
        stderr: Channel,
        work: &Path,
    ) -> Result<(), String> {
        self.stdin = stdin;
        self.stdout = stdout;
        self.stderr = stderr;
        self.work = work.to_path_buf();
        if stdin == Channel::Tty || stdout == Channel::Tty {
            let terminal =
                pty::Pty::with_size(INITIAL_SIZE).map_err(|error| format!("no PTY: {error}"))?;
            self.baseline = Some(
                terminal_state(terminal.slave()).map_err(|error| format!("no modes: {error}"))?,
            );
            self.terminal = Some(terminal);
        }
        if stdout == Channel::File {
            self.stdout_path = Some(work.join("stdout.bin"));
        }
        if stdin == Channel::File {
            let path = work.join("stdin.bin");
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("{}: {error}", parent.display()))?;
            }
            if !path.exists() {
                fs::write(&path, b"unread")
                    .map_err(|error| format!("{}: {error}", path.display()))?;
            }
        }
        if stdin == Channel::Pipe {
            // A real pipe, not `/dev/null`: the case names a pipe, so a pipe is
            // what the launcher must receive, and both ends stay here so the
            // payload can be shown to be untouched afterwards.
            let (reader, writer) = pty::pipe().map_err(|error| format!("no pipe: {error}"))?;
            write_all(&writer, b"unread")?;
            self.stdin_read = Some(reader);
            self.stdin_write = Some(writer);
        }
        Ok(())
    }

    pub fn spawn(&mut self) -> Result<(), String> {
        let mut command = Command::new(&self.argv[0]);
        command.args(&self.argv[1..]);
        command.current_dir(&self.cwd);
        command.env_clear();
        command.envs(self.env.iter().map(|(key, value)| (key, value)));
        let slave = self.terminal.as_ref().map(pty::Pty::slave);

        let stdin: Stdio = match self.stdin {
            Channel::Tty => Stdio::from(clone_of(slave.ok_or("no slave for a terminal stdin")?)?),
            Channel::Pipe => Stdio::from(
                rustix::io::dup(self.stdin_read.as_ref().ok_or("no pipe to read from")?)
                    .map_err(|error| format!("cannot duplicate the guest's stdin: {error}"))?,
            ),
            Channel::File => Stdio::from(
                rustix::fs::open(
                    self.work.join("stdin.bin"),
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| format!("cannot open the case's stdin: {error}"))?,
            ),
        };
        let stdout: Stdio = match self.stdout {
            Channel::Tty => Stdio::from(clone_of(slave.ok_or("no slave for a terminal stdout")?)?),
            Channel::Pipe => {
                let (reader, writer) =
                    pty::pipe().map_err(|error| format!("no stdout pipe: {error}"))?;
                self.child_stdout = Some(reader);
                Stdio::from(writer)
            }
            Channel::File => Stdio::from(
                rustix::fs::open(
                    self.work.join("stdout.bin"),
                    OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o600),
                )
                .map_err(|error| format!("cannot open the case's stdout: {error}"))?,
            ),
        };
        let stderr: Stdio = match self.stderr {
            Channel::Tty => Stdio::from(clone_of(slave.ok_or("no slave for a terminal stderr")?)?),
            Channel::Pipe => {
                let (reader, writer) =
                    pty::pipe().map_err(|error| format!("no stderr pipe: {error}"))?;
                self.child_stderr = Some(reader);
                Stdio::from(writer)
            }
            Channel::File => Stdio::from(
                rustix::fs::open(
                    self.work.join("stderr.bin"),
                    OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o600),
                )
                .map_err(|error| format!("cannot open the case's stderr: {error}"))?,
            ),
        };
        command.stdin(stdin).stdout(stdout).stderr(stderr);
        // Deliberately *not* a new session: on macOS a session leader's death
        // revokes the PTY slave, which would destroy the attributes this driver
        // compares before and after. The driver asserts it has no controlling
        // terminal of its own, so the child inherits no terminal to reach for.
        let child = command
            .spawn()
            .map_err(|error| format!("cannot start {}: {error}", self.argv[0].to_string_lossy()))?;
        self.launcher_pid = Some(child.id() as i32);
        self.child = Some(pty::OwnedChild::new(child));
        // The slave stays open in this process on purpose: it is the restoration
        // observation, and it is what keeps the master from reading a hangup.
        if let Some(terminal) = self.terminal.as_ref() {
            rustix::io::ioctl_fionbio(terminal.master(), true)
                .map_err(|error| format!("cannot make the terminal non-blocking: {error}"))?;
        }
        for fd in [self.child_stdout.as_ref(), self.child_stderr.as_ref()]
            .into_iter()
            .flatten()
        {
            // A blocking read end would strand the bounded drain loop.
            rustix::io::ioctl_fionbio(fd, true)
                .map_err(|error| format!("cannot make a pipe non-blocking: {error}"))?;
        }
        Ok(())
    }

    // -- observation --

    /// Read whatever is waiting, bounded by `timeout`.
    pub fn poll_once(&mut self, timeout: Duration) -> Result<(), String> {
        let master = self
            .terminal
            .as_ref()
            .map(pty::Pty::master)
            .filter(|_| !self.master_closed);
        let mut candidates: Vec<BorrowedFd<'_>> = Vec::with_capacity(3);
        if let Some(master) = master {
            candidates.push(master);
        }
        if let Some(fd) = self.child_stdout.as_ref() {
            candidates.push(fd.as_fd());
        }
        if let Some(fd) = self.child_stderr.as_ref() {
            candidates.push(fd.as_fd());
        }
        if candidates.is_empty() {
            std::thread::sleep(timeout);
            return Ok(());
        }
        let mut fds: Vec<PollFd<'_>> = candidates
            .iter()
            .map(|fd| PollFd::new(fd, PollFlags::IN))
            .collect();
        match poll(&mut fds, Some(&timespec(timeout))) {
            Ok(_) => {}
            // A relayed resize interrupts the wait; the time left is retried by
            // the caller's own loop.
            Err(Errno::INTR) => return Ok(()),
            Err(error) => return Err(format!("cannot wait on the launcher: {error}")),
        }
        let ready: Vec<bool> = fds
            .iter()
            .map(|fd| {
                fd.revents()
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            })
            .collect();
        let mut slot = 0;
        if master.is_some() {
            if ready[slot] {
                match self.read_into_master()? {
                    Read::End => self.master_closed = true,
                    Read::Open => {}
                }
            }
            slot += 1;
        }
        if self.child_stdout.is_some() {
            if ready[slot] && self.read_into_stdout()? == Read::End {
                self.child_stdout = None;
            }
            slot += 1;
        }
        if self.child_stderr.is_some() && ready[slot] && self.read_into_stderr()? == Read::End {
            self.child_stderr = None;
        }
        Ok(())
    }

    fn read_into_master(&mut self) -> Result<Read, String> {
        let mut buffer = [0u8; 65536];
        let Some(terminal) = self.terminal.as_ref() else {
            return Ok(Read::End);
        };
        let fd = terminal.master();
        loop {
            match pty::read_chunk(fd, &mut buffer, Duration::ZERO) {
                Ok(Some(0)) => return Ok(Read::End),
                Ok(Some(read)) => self.tty.extend_from_slice(&buffer[..read]),
                Ok(None) => return Ok(Read::Open),
                Err(error) => return Err(format!("cannot read the launcher's terminal: {error}")),
            }
        }
    }

    fn read_into_stdout(&mut self) -> Result<Read, String> {
        let Some(fd) = self.child_stdout.as_ref() else {
            return Ok(Read::End);
        };
        let mut buffer = [0u8; 65536];
        loop {
            match pty::read_chunk(fd, &mut buffer, Duration::ZERO) {
                Ok(Some(0)) => return Ok(Read::End),
                Ok(Some(read)) => self.out.extend_from_slice(&buffer[..read]),
                Ok(None) => return Ok(Read::Open),
                Err(error) => return Err(format!("cannot read the launcher's stdout: {error}")),
            }
        }
    }

    fn read_into_stderr(&mut self) -> Result<Read, String> {
        let Some(fd) = self.child_stderr.as_ref() else {
            return Ok(Read::End);
        };
        let mut buffer = [0u8; 65536];
        loop {
            match pty::read_chunk(fd, &mut buffer, Duration::ZERO) {
                Ok(Some(0)) => return Ok(Read::End),
                Ok(Some(read)) => self.err.extend_from_slice(&buffer[..read]),
                Ok(None) => return Ok(Read::Open),
                Err(error) => return Err(format!("cannot read the launcher's stderr: {error}")),
            }
        }
    }

    /// Read until `until` holds on `view`, bounded, and never a sleep oracle.
    pub fn pump(
        &mut self,
        until: impl Fn(&str) -> bool,
        what: &str,
        bound: Duration,
        view: View,
    ) -> Result<(), String> {
        let limit = std::cmp::min(self.deadline, Instant::now() + bound);
        while Instant::now() < limit {
            self.poll_once(Duration::from_millis(50))?;
            if until(&self.view(view)) {
                return Ok(());
            }
            if let Some(status) = self.exited()? {
                // The launcher's last write can still be in the channel when its
                // exit is reaped, so draining once for 20 ms made a correct case
                // fail whenever the host was loaded (`the launcher exited with 7
                // first; stdout=""`). Drain until the predicate holds instead,
                // bounded: a silent launcher still fails here, not at the case
                // deadline.
                let drain = Instant::now() + EXIT_DRAIN;
                loop {
                    self.poll_once(Duration::from_millis(20))?;
                    if until(&self.view(view)) {
                        return Ok(());
                    }
                    if Instant::now() >= drain {
                        break;
                    }
                }
                return Err(format!(
                    "{what}: the launcher exited with {status} first; stdout={:?} stderr={:?}",
                    self.stdout_text(),
                    self.stderr_text()
                ));
            }
        }
        Err(format!(
            "{what}: not observed within {}s; got {}",
            bound.as_secs_f64().round() as u64,
            serde_json::to_string(&self.summary()).unwrap_or_default()
        ))
    }

    /// Wait for the launcher to exit, draining its channels while it runs, so a
    /// chatty launcher cannot block on a full pipe.
    pub fn wait(&mut self, bound: Duration) -> Result<i32, String> {
        let limit = std::cmp::min(self.deadline, Instant::now() + bound);
        while Instant::now() < limit {
            self.poll_once(Duration::from_millis(50))?;
            if let Some(status) = self.exited()? {
                for _ in 0..20 {
                    self.poll_once(Duration::from_millis(10))?;
                }
                return Ok(status);
            }
        }
        Err(format!(
            "the launcher did not exit within {}s",
            bound.as_secs_f64().round() as u64
        ))
    }

    /// The launcher's status if it has exited, without reaping it.
    fn exited(&mut self) -> Result<Option<i32>, String> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let status = child
            .try_wait()
            .map_err(|error| format!("cannot observe the launcher: {error}"))?;
        Ok(status.map(exit_code))
    }

    // -- convenience --

    fn view(&self, view: View) -> String {
        match view {
            View::LauncherOutput => self.launcher_output(),
            View::Merged => self.merged_text(),
        }
    }

    /// Where the guest's stdout went: a file or a pipe, else the terminal.
    pub fn guest_stdout_text(&self) -> String {
        if self.stdout_path.is_some() || self.stdout == Channel::Pipe {
            return self.stdout_text();
        }
        self.terminal_text()
    }

    /// Where the guest's stderr went: a file or a pipe, else the terminal.
    pub fn guest_stderr_text(&self) -> String {
        if self.stderr == Channel::File || self.stderr == Channel::Pipe {
            return self.stderr_text();
        }
        self.terminal_text()
    }

    /// Guest-visible text from every channel, including a redirected file.
    pub fn merged_text(&self) -> String {
        self.launcher_output() + &self.stdout_text() + &self.stderr_text()
    }

    /// Everything the launcher itself wrote: the terminal and the stderr stream.
    /// Guest output sharing the terminal is included, so callers match exact
    /// guest markers instead of assuming a channel.
    pub fn launcher_output(&self) -> String {
        decode(&self.tty) + &decode(&self.err)
    }

    pub fn stdout_text(&self) -> String {
        if let Some(path) = self.stdout_path.as_ref() {
            return fs::read(path)
                .map(|bytes| decode(&bytes))
                .unwrap_or_default();
        }
        decode(&self.out)
    }

    pub fn stderr_text(&self) -> String {
        if self.stderr == Channel::File {
            return fs::read(self.work.join("stderr.bin"))
                .map(|bytes| decode(&bytes))
                .unwrap_or_default();
        }
        decode(&self.err)
    }

    pub fn terminal_text(&self) -> String {
        decode(&self.tty)
    }

    pub fn stdout_is_redirected(&self) -> bool {
        self.stdout_path.is_some() || self.stdout == Channel::Pipe
    }

    pub fn summary(&self) -> Value {
        json!({
            "tty": tail(&self.terminal_text()),
            "stdout": tail(&self.stdout_text()),
            "stderr": tail(&self.stderr_text()),
        })
    }

    /// Persist every raw channel, not just its last 2,000 decoded characters: a
    /// failure whose evidence is only "the last 2,000 chars" cannot be diagnosed
    /// later.
    pub fn capture_files(&self, evidence: &Path) -> Map<String, Value> {
        let mut written = Map::new();
        for (name, raw) in [
            ("tty", &self.tty),
            ("stdout", &self.out),
            ("stderr", &self.err),
        ] {
            if raw.is_empty() {
                continue;
            }
            let file = format!("capture-{name}.bin");
            if fs::write(evidence.join(&file), raw).is_ok() {
                written.insert(name.to_owned(), Value::String(file));
            }
        }
        if self.stdout_path.is_some() && self.work.join("stdout.bin").exists() {
            written.insert(
                "stdout_file".to_owned(),
                Value::String("stdout.bin".to_owned()),
            );
        }
        if self.stderr == Channel::File && self.work.join("stderr.bin").exists() {
            written.insert(
                "stderr_file".to_owned(),
                Value::String("stderr.bin".to_owned()),
            );
        }
        written
    }

    /// What the launcher left unread in this case's pipe. A refused launch must
    /// not consume the caller's input.
    pub fn unconsumed_stdin(&self) -> Vec<u8> {
        let Some(fd) = self.stdin_read.as_ref() else {
            return Vec::new();
        };
        let mut unread = Vec::new();
        let mut buffer = [0u8; 65536];
        loop {
            match pty::read_chunk(fd, &mut buffer, Duration::ZERO) {
                Ok(Some(0)) => break,
                Ok(Some(read)) => unread.extend_from_slice(&buffer[..read]),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        unread
    }

    /// Type at the terminal. The master is non-blocking, so a write retries
    /// rather than failing a case.
    pub fn write_terminal(&mut self, payload: &[u8]) -> Result<(), String> {
        let terminal = self
            .terminal
            .as_ref()
            .ok_or_else(|| "this case has no terminal to type at".to_owned())?;
        let limit = Instant::now() + Duration::from_secs(10);
        let mut sent = 0;
        while sent < payload.len() {
            match rustix::io::write(terminal.master(), &payload[sent..]) {
                Ok(written) => sent += written,
                Err(Errno::AGAIN) => {
                    if Instant::now() > limit {
                        return Err("the terminal would not accept input".to_owned());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(format!("cannot write to the terminal: {error}")),
            }
        }
        Ok(())
    }

    /// Ask for a new geometry, the way an operator's terminal would: the kernel
    /// reports the size to whoever reads it, and `SIGWINCH` wakes the waiters.
    pub fn resize(&mut self, size: pty::WindowSize) -> Result<(), String> {
        let terminal = self
            .terminal
            .as_ref()
            .ok_or_else(|| "this case has no terminal to resize".to_owned())?;
        terminal
            .set_size(size)
            .map_err(|error| format!("cannot resize the terminal: {error}"))?;
        let pid = self
            .launcher_pid
            .ok_or_else(|| "no launcher to notify of the resize".to_owned())?;
        pty::send_signal(pid, Signal::WINCH)
            .map_err(|error| format!("cannot notify the launcher of the resize: {error}"))
    }

    pub fn raw_observed(&self) -> Result<bool, String> {
        let terminal = self
            .terminal
            .as_ref()
            .ok_or_else(|| "this case has no terminal".to_owned())?;
        let modes = pty::modes(terminal.slave())
            .map_err(|error| format!("cannot read the terminal's modes: {error}"))?;
        Ok(!modes.local_modes.contains(LocalModes::ICANON))
    }

    pub fn canonical_retained(&self) -> Result<bool, String> {
        let terminal = self
            .terminal
            .as_ref()
            .ok_or_else(|| "this case has no terminal".to_owned())?;
        let modes = pty::modes(terminal.slave())
            .map_err(|error| format!("cannot read the terminal's modes: {error}"))?;
        Ok(modes.local_modes.contains(LocalModes::ICANON))
    }

    pub fn final_state(&self) -> Option<TerminalState> {
        let terminal = self.terminal.as_ref()?;
        self.baseline.as_ref()?;
        terminal_state(terminal.slave()).ok()
    }

    /// The case's own scratch directory, for an observation that needs a file (the
    /// host process scan) instead of a pipe a bounded wait could not also drain.
    pub fn work_dir(&self) -> &Path {
        &self.work
    }

    pub fn baseline_state(&self) -> Option<TerminalState> {
        self.baseline.clone()
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.stop();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // `OwnedChild` stops a child the caller gave up on; everything else here
        // is an owned descriptor that closes with the struct.
        self.stop();
    }
}

#[derive(PartialEq, Eq)]
enum Read {
    Open,
    End,
}

/// What a predicate reads. `Merged` includes a redirected file, so a guest report
/// written to a file is not mistaken for a missing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// Everything the launcher wrote. The wait, legacy and prompt groups read it
    /// once they land (#699).
    #[allow(dead_code)]
    LauncherOutput,
    Merged,
}

fn decode(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn clone_of(fd: BorrowedFd<'_>) -> Result<OwnedFd, String> {
    fd.try_clone_to_owned()
        .map_err(|error| format!("cannot duplicate a terminal descriptor: {error}"))
}

fn write_all(fd: &OwnedFd, payload: &[u8]) -> Result<(), String> {
    let mut sent = 0;
    while sent < payload.len() {
        match rustix::io::write(fd, &payload[sent..]) {
            Ok(written) => sent += written,
            Err(error) => return Err(format!("cannot write to the pipe: {error}")),
        }
    }
    Ok(())
}

fn timespec(duration: Duration) -> Timespec {
    Timespec {
        tv_sec: duration.as_secs() as i64,
        tv_nsec: duration.subsec_nanos() as i64,
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0))
}

fn case_deadline() -> f64 {
    std::env::var("DIRECT_TERMINAL_CASE_DEADLINE")
        .ok()
        .and_then(|text| text.parse::<f64>().ok())
        .unwrap_or(DEFAULT_CASE_DEADLINE)
}

fn marker_deadline() -> Duration {
    let seconds = std::env::var("DIRECT_TERMINAL_MARKER_DEADLINE")
        .ok()
        .and_then(|text| text.parse::<f64>().ok())
        .unwrap_or(DEFAULT_MARKER_DEADLINE);
    Duration::from_secs_f64(seconds)
}

// --- Teardown ---------------------------------------------------------------

/// Catalog rows naming this launcher's own sandbox, never anyone else's. The
/// sandbox name includes the launcher's pid, so this is an ownership test rather
/// than a prefix or image match.
fn owned_catalog_rows(state_root: &Path, launcher_pid: Option<i32>) -> Result<Vec<Value>, String> {
    let Some(pid) = launcher_pid else {
        return Ok(Vec::new());
    };
    let rows = crate::msb_catalog::catalog_rows(&state_root.join("msb-home"))?;
    Ok(rows
        .into_iter()
        .filter(|row| row.name.contains(&pid.to_string()))
        .map(|row| {
            json!({
                "name": row.name,
                "pid": row.pid,
                "run_status": row.run_status,
            })
        })
        .collect())
}

/// The one running runtime process this launcher owns, as `{pid, start}`.
///
/// Identity comes from the private catalog — the row names *this* launcher's
/// sandbox — and is validated through the reviewed helper, so a pid the kernel
/// has reused can never be signalled. Nothing here matches on a name or a group.
fn owned_runtime_identity(
    state_root: &Path,
    launcher_pid: Option<i32>,
    label: &str,
) -> Result<Value, String> {
    let rows = owned_catalog_rows(state_root, launcher_pid)?;
    let running: Vec<&Value> = rows
        .iter()
        .filter(|row| {
            row.get("pid")
                .and_then(Value::as_i64)
                .is_some_and(|pid| pid > 0)
        })
        .filter(|row| {
            // The catalog capitalises the run status, so a lower-case-only
            // allowlist would match nothing and the row would never find its own
            // runtime.
            row.get("run_status")
                .and_then(Value::as_str)
                .is_none_or(|status| status.to_lowercase() == "running")
        })
        .collect();
    require(!running.is_empty(), || {
        format!("{label}: no catalog row names this launcher's sandbox (rows={rows:?})")
    })?;
    require(running.len() == 1, || {
        format!(
            "{label}: {} candidate runtimes; refusing to signal",
            running.len()
        )
    })?;
    let pid = running[0].get("pid").and_then(Value::as_i64).unwrap_or(0);
    let pid = u32::try_from(pid).map_err(|error| error.to_string())?;
    let identity = crate::egress_fixtures::process_identity(pid)?;
    require(identity.is_some(), || {
        format!("{label}: the catalog runtime {pid} is not executing")
    })?;
    Ok(json!({"pid": pid, "start": identity}))
}

/// What this one launch still owned afterwards, and stopping it if anything did.
///
/// A case that fails is exactly when the launcher cannot stop its own sandbox, so
/// cleanup happens here instead of only after a passing row. Only the row this
/// launcher names is ever signalled or stopped.
fn teardown_receipt(
    state_root: &Path,
    runtime: &Path,
    env: &[(OsString, OsString)],
    session: &Session,
) -> Value {
    let mut receipt = Map::new();
    receipt.insert("launcher_pid".to_owned(), json!(session.launcher_pid));
    let rows = match owned_catalog_rows(state_root, session.launcher_pid) {
        Ok(rows) => rows,
        Err(error) => {
            receipt.insert("observation".to_owned(), Value::String(error));
            return Value::Object(receipt);
        }
    };
    receipt.insert("catalog_rows".to_owned(), json!(rows.len()));
    let names: Vec<String> = rows
        .iter()
        .map(|row| {
            row.get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    receipt.insert("names".to_owned(), json!(names));
    let mut sockets: Vec<String> = Vec::new();
    for name in &names {
        for path in crate::egress_launch::socket_paths(&state_root.join("msb-home"), name) {
            if path.exists() {
                sockets.push(path.display().to_string());
            }
        }
    }
    receipt.insert("sockets".to_owned(), json!(sockets));
    let mut steps: Vec<Value> = Vec::new();
    for row in &rows {
        let name = row
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let pid = row.get("pid").and_then(Value::as_i64).unwrap_or(0);
        let identity = if pid > 0 {
            u32::try_from(pid)
                .map_err(|error| error.to_string())
                .and_then(crate::egress_fixtures::process_identity)
                .unwrap_or(None)
        } else {
            None
        };
        steps.push(json!({"name": name, "pid": pid, "running": identity.is_some()}));
        for arguments in [
            vec!["stop", "--timeout", "5", name.as_str()],
            vec!["stop", "--force", name.as_str()],
        ] {
            let mut command = Command::new(runtime);
            command.args(&arguments);
            command.env_clear();
            command.envs(env.iter().map(|(key, value)| (key, value)));
            command.stdin(Stdio::null());
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
            match command.spawn() {
                Ok(child) => {
                    let mut child = pty::OwnedChild::new(child);
                    match child.finish(Duration::from_secs(60)) {
                        Ok(status) => steps.push(json!({
                            "command": arguments,
                            "status": exit_code(status),
                        })),
                        Err(error) => steps.push(json!({
                            "command": arguments,
                            "error": error.to_string(),
                        })),
                    }
                }
                Err(error) => steps.push(json!({
                    "command": arguments,
                    "error": error.to_string(),
                })),
            }
        }
        if let Some(start) = identity {
            let identity = json!({"pid": pid, "start": start});
            if let Err(error) = crate::egress_fixtures::signal_identity(&identity, libc::SIGTERM) {
                steps.push(json!({"signal": "TERM", "error": error}));
            }
        }
    }
    receipt.insert("steps".to_owned(), json!(steps));
    let after = owned_catalog_rows(state_root, session.launcher_pid)
        .map(|rows| json!(rows.len()))
        .unwrap_or_else(|error| json!(format!("observation failed: {error}")));
    receipt.insert("catalog_rows_after".to_owned(), after);
    Value::Object(receipt)
}

/// A case passes only if its own launch left no VM behind.
fn own_teardown(teardown: &Value, label: &str) -> Result<(), String> {
    require(
        teardown.get("catalog_rows_after") == Some(&json!(0)),
        || format!("{label}: the launch left catalog rows behind: {teardown}"),
    )?;
    let sockets = teardown
        .get("sockets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    require(sockets.is_empty(), || {
        format!("{label}: the launch left owned sockets behind: {sockets:?}")
    })?;
    let lingering: Vec<i64> = teardown
        .get("steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|step| step.get("running") == Some(&json!(true)))
        .filter_map(|step| step.get("pid").and_then(Value::as_i64))
        .collect();
    let mut survivors = Vec::new();
    for pid in lingering {
        let Ok(pid) = u32::try_from(pid) else {
            continue;
        };
        let Ok(Some(start)) = crate::egress_fixtures::process_identity(pid) else {
            continue;
        };
        let identity = json!({"pid": pid, "start": start});
        let _ = crate::egress_fixtures::signal_identity(&identity, libc::SIGKILL);
        if crate::egress_fixtures::process_identity(pid)
            .unwrap_or(None)
            .is_some()
        {
            survivors.push(pid);
        }
    }
    require(survivors.is_empty(), || {
        format!("{label}: a runtime process survived this launch: {survivors:?}")
    })
}

// --- The invocation ---------------------------------------------------------

/// One checked case invocation: the caller's arguments after every one that can
/// be refused has been.
pub struct Invocation {
    bin: PathBuf,
    project: PathBuf,
    image: String,
    runtime: PathBuf,
    state_root: PathBuf,
    evidence: PathBuf,
    home: Option<PathBuf>,
    expect_hook: Option<String>,
    expect_hook_path: Option<String>,
    no_ambient_tty_check: bool,
    /// The launcher is a stand-in, so the `access` checks are recorded as skipped
    /// rather than run against a session it does not have.
    standin: bool,
    case: &'static Case,
    form: Form,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Form {
    Run,
    Separator,
}

impl Form {
    fn boundary(self) -> &'static str {
        match self {
            Form::Run => "run",
            Form::Separator => "--",
        }
    }
}

/// The direct command boundary: `[launch options] run|-- PROGRAM ARG…`.
///
/// One builder, so a case's argv and the inventory control that reads it cannot
/// disagree about where the boundary token sits. The program words are generic so
/// a row whose extra words only exist at run time (a self-signalled row's release)
/// goes through the same builder as a fixed one.
pub fn launch_argv<W: AsRef<OsStr>>(
    binary: &Path,
    options: &[&str],
    form: Form,
    program: &[W],
) -> Vec<OsString> {
    let mut argv = vec![binary.as_os_str().to_owned()];
    argv.extend(options.iter().map(OsString::from));
    argv.push(OsString::from(form.boundary()));
    argv.extend(program.iter().map(|word| word.as_ref().to_owned()));
    argv
}

/// A caller-supplied path that must be present and absolute: the launcher runs
/// with the case's project as its cwd, so a relative binary path would silently
/// not be the binary that was intended.
fn required_path(flag: &str, value: Option<&PathBuf>) -> Result<PathBuf, String> {
    let path = value.ok_or_else(|| format!("usage: {flag} is required"))?;
    if !path.is_absolute() {
        return Err(format!("usage: {flag} must be an absolute path"));
    }
    Ok(path.clone())
}

impl Invocation {
    fn from_args(args: &DirectTerminalArgs) -> Result<Self, String> {
        let bin = required_path("--bin", args.bin.as_ref())?;
        let project = required_path("--project", args.project.as_ref())?;
        let runtime = required_path("--runtime", args.runtime.as_ref())?;
        let state_root = required_path("--state-root", args.state_root.as_ref())?;
        let evidence = required_path("--evidence", args.evidence.as_ref())?;
        let image = args
            .image
            .clone()
            .ok_or_else(|| "usage: --image is required".to_owned())?;
        let wanted = args
            .case
            .as_deref()
            .ok_or_else(|| "usage: --case is required".to_owned())?;
        // A row whose group has not landed yet would be named as such, so a
        // successor could tell "still to port" from "no such case". Every group is
        // ported now, so only the unknown-row branch is reachable.
        let case = cases().get(wanted).copied().ok_or_else(|| {
            format!(
                "usage: unknown case {wanted:?}; the inventory is {:?}",
                ported_rows()
            )
        })?;
        Ok(Self {
            bin,
            project,
            image,
            runtime,
            state_root,
            evidence,
            home: args.home.clone(),
            expect_hook: args.expect_hook.clone(),
            expect_hook_path: args.expect_hook_path.clone(),
            no_ambient_tty_check: args.no_ambient_tty_check,
            standin: args.standin,
            case,
            form: args.form,
        })
    }

    fn label(&self) -> String {
        format!("{}/{}", self.case.name, self.form.value_name())
    }

    /// The case's environment: this process's, with the launch's own pins. `HOME`
    /// is the caller's when it names one, and the prompt's setting and `TERM` are
    /// the case's facts, never the operator's.
    fn child_env(&self) -> Vec<(OsString, OsString)> {
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        let set = |env: &mut Vec<(OsString, OsString)>, key: &str, value: OsString| {
            env.retain(|(name, _)| name != key);
            env.push((OsString::from(key), value));
        };
        let remove =
            |env: &mut Vec<(OsString, OsString)>, key: &str| env.retain(|(name, _)| name != key);
        set(&mut env, "MSB_PATH", self.runtime.clone().into_os_string());
        set(
            &mut env,
            "AGENT_VM_STATE_DIR",
            self.state_root.clone().into_os_string(),
        );
        // No `MSB_HOME`: the launcher pins it under the state root itself, so an
        // override would be silently ignored (and would move the catalog this
        // driver reads).
        remove(&mut env, "MSB_HOME");
        set(&mut env, "AGENT_VM_IMAGE_TAG", OsString::from(&self.image));
        remove(&mut env, "AGENT_VM_NO_CHROME_MCP");
        set(&mut env, "TERM", OsString::from("xterm-256color"));
        remove(&mut env, "AGENT_VM_NO_ACCESS_PROMPT");
        // No real banner: a desktop run would post one, and the notifications-off
        // line could then land in exact-byte terminal evidence.
        set(&mut env, "AGENT_VM_NO_NOTIFICATIONS", OsString::from("1"));
        if let Some(home) = self.home.as_ref() {
            set(&mut env, "HOME", home.clone().into_os_string());
        }
        for (key, value) in self.case.env {
            set(&mut env, key, (*value).into());
        }
        env
    }

    /// The literal argv for this case: a legacy route, or the direct boundary.
    ///
    /// `probe_extra` carries the words only *this attempt* can know — a
    /// self-signalled row's release-file name and unguessable token — so they are
    /// passed in rather than stored on the [`Case`]: [`CASES`] is shared, and
    /// mutating one would make two attempts in one process share them.
    fn argv(&self, probe_extra: &[String]) -> Vec<OsString> {
        if let Some(route) = self.case.route {
            let mut argv = vec![self.bin.as_os_str().to_owned()];
            argv.extend(self.case.options.iter().map(OsString::from));
            argv.extend(route.iter().map(OsString::from));
            return argv;
        }
        let program = self.program_words(probe_extra);
        launch_argv(&self.bin, self.case.options, self.form, &program)
    }

    /// The words after the command boundary.
    ///
    /// A refusal or program-status row names its own program, because the
    /// launcher's answer to *that* program is its subject; every other row runs
    /// the guest probe with its own mode and this attempt's extra words.
    fn program_words(&self, probe_extra: &[String]) -> Vec<OsString> {
        match self.case.expect {
            Expect::Reject { .. } => vec![OsString::from("true")],
            Expect::Program { words, .. } => words.iter().map(OsString::from).collect(),
            _ => {
                let mut words: Vec<OsString> = vec![OsString::from("bash")];
                words.push(OsString::from(format!("./{PROBE_NAME}")));
                words.extend(self.case.probe.iter().map(OsString::from));
                words.extend(probe_extra.iter().map(OsString::from));
                words
            }
        }
    }
}

impl Form {
    fn value_name(self) -> &'static str {
        match self {
            Form::Run => "run",
            Form::Separator => "separator",
        }
    }
}

/// Fail unless this process really is detached from an ambient terminal. A driver
/// that inherited the operator's terminal could look correct while a case's own
/// PTY was doing nothing, so this is a precondition, not a courtesy.
fn assert_no_controlling_terminal() -> Result<(), String> {
    match rustix::fs::open(
        c"/dev/tty",
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            drop(fd);
            Err(
                "this driver has a controlling terminal; run it detached (setsid) so a \
                 case's PTY is the only terminal"
                    .to_owned(),
            )
        }
        Err(Errno::NXIO | Errno::NODEV | Errno::NOENT | Errno::PERM) => Ok(()),
        Err(error) => Err(format!("cannot prove the driver is detached: {error}")),
    }
}

// --- The case bodies --------------------------------------------------------

/// One case's receipt and its verdict. The receipt is returned either way: a
/// failure's evidence is the case's own receipt, never a summary of it.
struct CaseOutcome {
    receipt: Map<String, Value>,
    verdict: Result<i32, String>,
}

fn run_case(invocation: &Invocation, work: &Path) -> Result<CaseOutcome, String> {
    let case = invocation.case;
    // A refusal or program-status row never reaches the probe, so the probe is
    // not its precondition.
    if !case.probe.is_empty() {
        let probe_path = invocation.project.join(PROBE_NAME);
        require(probe_path.exists(), || {
            format!("the guest probe is missing at {}", probe_path.display())
        })?;
    }
    if let Expect::Program {
        fixture: Some(fixture),
        ..
    } = case.expect
    {
        fixture.write(&invocation.project)?;
    }
    let mut receipt = Map::new();
    // A self-signalled row is released by a file only *this* attempt knows, so the
    // words are allocated before the argv is built and handed to the observation.
    // The release facts reach the receipt immediately, so a failure before the
    // handshake still shows which token was minted.
    let mut release = match case.expect {
        Expect::Signal(row) if row.behaviour == signal::Behaviour::SelfSignal => {
            Some(signal::Release::allocate(invocation, &mut receipt)?)
        }
        _ => None,
    };
    let probe_extra: Vec<String> = release
        .as_ref()
        .map(signal::Release::words)
        .unwrap_or_default();
    let argv = invocation.argv(&probe_extra);
    receipt.insert(
        "argv".to_owned(),
        json!(
            argv.iter()
                .map(|word| word.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        ),
    );
    let env = invocation.child_env();
    let mut session = Session::new(
        argv,
        env.clone(),
        invocation.project.clone(),
        work.to_path_buf(),
    );
    receipt.insert(
        "host_ttys".to_owned(),
        json!({
            "stdin": invocation.case.stdin == Channel::Tty,
            "stdout": invocation.case.stdout == Channel::Tty,
        }),
    );
    let label = invocation.label();
    let mut verdict = (|| -> Result<i32, String> {
        session.assign(
            invocation.case.stdin,
            invocation.case.stdout,
            invocation.case.stderr,
            work,
        )?;
        session.spawn()?;
        observe(invocation, &mut session, &mut receipt, release.as_mut())
    })();
    if let Some(release) = release.as_ref() {
        // The handshake's later facts (released, removed) land here: the entry
        // written at allocation is merged, not replaced.
        release.store(&mut receipt);
    }
    receipt.insert("launcher_status".to_owned(), json!(verdict.as_ref().ok()));
    receipt.insert(
        "terminal".to_owned(),
        json!({
            "baseline": session.baseline_state().map(state_json),
            "final": session.final_state().map(state_json),
        }),
    );
    // Both channels and every raw buffer are recorded even when the case failed:
    // a failure's evidence is the case's own receipt.
    receipt.insert("captures".to_owned(), session.summary());
    receipt.insert(
        "capture_files".to_owned(),
        Value::Object(session.capture_files(&invocation.evidence)),
    );
    receipt.insert(
        "teardown".to_owned(),
        teardown_receipt(&invocation.state_root, &invocation.runtime, &env, &session),
    );
    session.stop();
    let teardown = receipt.get("teardown").cloned().unwrap_or(Value::Null);
    // The restoration check comes after the case's own verdict, so a failing row
    // still says which of the two broke.
    let restored = receipt
        .get("terminal")
        .and_then(|terminal| terminal.get("baseline"))
        .zip(
            receipt
                .get("terminal")
                .and_then(|terminal| terminal.get("final")),
        )
        .map(|(baseline, final_state)| baseline == final_state)
        .unwrap_or(false);
    if verdict.is_ok() && !restored {
        verdict = Err(format!(
            "{label}: the host terminal was not restored: {}",
            receipt.get("terminal").cloned().unwrap_or(Value::Null)
        ));
    }
    if verdict.is_ok()
        && let Err(error) = own_teardown(&teardown, &label)
    {
        verdict = Err(error);
    }
    Ok(CaseOutcome { receipt, verdict })
}

fn state_json(state: TerminalState) -> Value {
    json!({
        "iflag": state.iflag,
        "oflag": state.oflag,
        "cflag": state.cflag,
        "lflag": state.lflag,
        "ispeed": state.ispeed,
        "ospeed": state.ospeed,
        "vmin": state.vmin,
        "vtime": state.vtime,
    })
}

/// Drive one case to its verdict and return the launcher's status.
fn observe(
    invocation: &Invocation,
    session: &mut Session,
    receipt: &mut Map<String, Value>,
    release: Option<&mut signal::Release>,
) -> Result<i32, String> {
    let case = invocation.case;
    let label = invocation.label();
    let marker = marker_deadline();
    match case.expect {
        Expect::Identity { guest_pty, err } => {
            session.pump(
                |out| out.contains("IDENTITY-DONE"),
                "the identity report",
                marker,
                View::Merged,
            )?;
            let status = session.wait(marker)?;
            let merged = session.merged_text();
            let identity = parse_report(&merged);
            require(status == 0, || {
                format!(
                    "{label}: status {status}; stderr={:?}",
                    session.stderr_text()
                )
            })?;
            let bits = if guest_pty { "111" } else { "000" };
            let seen = (
                identity.get("tty0").map(String::as_str),
                identity.get("tty1").map(String::as_str),
                identity.get("tty2").map(String::as_str),
            );
            require(
                seen == (Some(&bits[0..1]), Some(&bits[1..2]), Some(&bits[2..3])),
                || format!("{label}: the guest must see tty bits {bits}: {identity:?}"),
            )?;
            let out_text = session.guest_stdout_text();
            let err_text = session.guest_stderr_text();
            let terminal_text = session.terminal_text();
            require(out_text.contains("OUT marker"), || {
                format!("{label}: guest stdout: {out_text:?}")
            })?;
            match err {
                ErrChannel::MergedIntoStdout => require(out_text.contains("ERR marker"), || {
                    format!(
                        "{label}: a PTY must merge guest stderr into the terminal stream: \
                             {out_text:?}"
                    )
                })?,
                ErrChannel::Stderr => {
                    require(err_text.contains("ERR marker"), || {
                        format!("{label}: guest stderr did not stay on stderr: {err_text:?}")
                    })?;
                    require(!out_text.contains("ERR marker"), || {
                        format!(
                            "{label}: guest stderr leaked into the stdout channel: {out_text:?}"
                        )
                    })?;
                }
                ErrChannel::Terminal => require(terminal_text.contains("ERR marker"), || {
                    format!("{label}: guest stderr is missing from the terminal: {terminal_text:?}")
                })?,
            }
            if session.stdout_is_redirected() {
                require_stdout_envelope(&label, &out_text, err == ErrChannel::MergedIntoStdout)?;
            }
            if let Some(expected) = invocation.expect_hook.as_deref() {
                require(
                    identity.get("HOOK").map(String::as_str) == Some(expected),
                    || format!("{label}: the project hook export did not apply: {identity:?}"),
                )?;
            }
            if let Some(expected) = invocation.expect_hook_path.as_deref() {
                require(
                    identity
                        .get("PATH")
                        .is_some_and(|path| path.contains(expected)),
                    || {
                        format!(
                            "{label}: the hook's PATH export did not apply: {:?}",
                            identity.get("PATH")
                        )
                    },
                )?;
            }
            // SAFETY: `getuid`/`getgid` only read the process's own credentials.
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            let uid_text = uid.to_string();
            let gid_text = gid.to_string();
            require(
                identity.get("UID").map(String::as_str) == Some(uid_text.as_str()),
                || format!("{label}: guest uid: {identity:?}"),
            )?;
            require(
                identity.get("GID").map(String::as_str) == Some(gid_text.as_str()),
                || format!("{label}: guest gid: {identity:?}"),
            )?;
            let project = fs::canonicalize(&invocation.project)
                .map_err(|error| format!("cannot resolve the project: {error}"))?;
            let project = project.to_string_lossy().into_owned();
            require(
                identity.get("PWD").map(String::as_str) == Some(project.as_str()),
                || format!("{label}: guest cwd: {identity:?}"),
            )?;
            receipt.insert("guest_identity".to_owned(), json!(identity));
            Ok(status)
        }
        Expect::Input => {
            session.pump(
                |out| out.contains("INPUT-READY"),
                "the input case's readiness",
                marker,
                View::Merged,
            )?;
            require(session.raw_observed()?, || {
                format!("{label}: the launcher never made its terminal raw")
            })?;
            receipt.insert("raw_state".to_owned(), json!("observed"));
            for chunk in INPUT_CHUNKS {
                session.write_terminal(chunk)?;
            }
            session.pump(
                |out| out.contains("DONE"),
                "the input verdict",
                marker,
                View::Merged,
            )?;
            let status = session.wait(marker)?;
            let text = session.merged_text();
            require(
                text.contains(&format!("bytes={INPUT_EXPECTED_HEX}")),
                || format!("{label}: guest saw {text:?}"),
            )?;
            require(text.contains("DONE"), || {
                format!("{label}: the session ended before the guest finished: {text:?}")
            })?;
            require(status == 7, || {
                format!("{label}: status {status} (a detach would not be 7)")
            })?;
            Ok(status)
        }
        Expect::Resize => {
            session.pump(
                |out| out.contains("RESIZE-READY"),
                "the resize case's readiness",
                marker,
                View::Merged,
            )?;
            let merged = session.merged_text();
            let line = marker_line(&merged, "SIZE ")?;
            let reported = line
                .split_once(' ')
                .map(|(_, size)| size)
                .unwrap_or_default();
            let expected = [INITIAL_SIZE.rows, INITIAL_SIZE.cols]
                .map(|field| field.to_string())
                .join(" ");
            require(
                reported.split_whitespace().eq(expected.split_whitespace()),
                || {
                    format!(
                        "{label}: the guest's initial size was {reported:?}, not {}x{}",
                        INITIAL_SIZE.rows, INITIAL_SIZE.cols
                    )
                },
            )?;
            require(session.raw_observed()?, || {
                format!("{label}: the launcher never made its terminal raw")
            })?;
            receipt.insert("raw_state".to_owned(), json!("observed"));
            session.resize(RESIZED_SIZE)?;
            // Wake the blocking read immediately: the guest must not have to poll
            // for a report before its reader can finish.
            session.write_terminal(b"\n")?;
            session.pump(
                |out| out.contains("RESIZE-DONE") || out.contains("RESIZE-TIMEOUT"),
                "the resize verdict",
                marker,
                View::Merged,
            )?;
            let status = session.wait(marker)?;
            let text = session.merged_text();
            require(!text.contains("RESIZE-TIMEOUT"), || {
                format!("{label}: the guest timed out: {text:?}")
            })?;
            require(
                text.contains(&format!(
                    "RESIZED {} {}",
                    RESIZED_SIZE.rows, RESIZED_SIZE.cols
                )),
                || {
                    format!(
                        "{label}: the guest never observed {}x{}: {text:?}",
                        RESIZED_SIZE.rows, RESIZED_SIZE.cols
                    )
                },
            )?;
            require(status == 7, || format!("{label}: status {status}"))?;
            Ok(status)
        }
        Expect::StreamInput => {
            // The readiness and the report each get two minutes: the host's VEOF
            // is what ends the guest's read, and a short bound here would fail a
            // correct session on a loaded host.
            let generous = Duration::from_secs(120);
            session.pump(
                |out| out.contains("STREAM-READY"),
                "the streamed-input readiness",
                generous,
                View::Merged,
            )?;
            receipt.insert(
                "canonical_state".to_owned(),
                Value::String(if session.canonical_retained()? {
                    "retained".to_owned()
                } else {
                    "raw".to_owned()
                }),
            );
            require(session.canonical_retained()?, || {
                format!("{label}: the launcher put a streamed terminal stdin into raw mode")
            })?;
            for chunk in STREAM_INPUT_CHUNKS {
                session.write_terminal(chunk)?;
            }
            // The empty-line VEOF is the host's EOF; the master is never closed.
            session.write_terminal(b"\x04")?;
            session.pump(
                |out| out.contains("STREAM-DONE"),
                "the streamed-input report",
                generous,
                View::Merged,
            )?;
            let status = session.wait(generous)?;
            let text = session.stdout_text();
            require(status == 23, || {
                format!(
                    "{label}: status {status}; launcher output {:?}",
                    session.launcher_output()
                )
            })?;
            let fields = parse_kv(marker_line(&text, "STREAM ")?);
            let expected = STREAM_INPUT_EXPECTED;
            require(
                fields.get("bytes") == Some(&expected.len().to_string()),
                || format!("{label}: bytes={:?}", fields.get("bytes")),
            )?;
            require(fields.get("cksum") == Some(&cksum_of(expected)?), || {
                format!("{label}: cksum={:?}", fields.get("cksum"))
            })?;
            let hex = expected
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            require(fields.get("hex") == Some(&hex), || {
                format!("{label}: hex={:?}", fields.get("hex"))
            })?;
            require(text.contains("STREAM-DONE"), || {
                format!("{label}: no completion sentinel in {text:?}")
            })?;
            let stderr = session.stderr_text();
            require(stderr.contains("STREAM-STDERR marker"), || {
                format!("{label}: the guest's stderr marker did not stay on stderr: {stderr:?}")
            })?;
            require(!stderr.contains("stream-A"), || {
                format!("{label}: guest stdin bytes leaked to stderr")
            })?;
            receipt.insert("guest_stream".to_owned(), json!(fields));
            Ok(status)
        }
        Expect::Argv => {
            session.pump(
                |out| out.contains("ARGV-DONE"),
                "the argv report",
                marker,
                View::Merged,
            )?;
            let status = session.wait(marker)?;
            let text = session.merged_text();
            require(status == 0, || format!("{label}: status {status}"))?;
            require(text.contains("ARGV n=2"), || {
                format!("{label}: the suffix tokens did not reach the guest: {text:?}")
            })?;
            require(text.contains("ARGV[0]=--tty"), || {
                format!("{label}: argv[0]: {text:?}")
            })?;
            require(text.contains("ARGV[1]=-T"), || {
                format!("{label}: argv[1]: {text:?}")
            })?;
            Ok(status)
        }
        Expect::Status(expected) => {
            session.pump(
                |out| out.contains("STATUS-EXIT"),
                "the status marker",
                marker,
                View::Merged,
            )?;
            let status = session.wait(marker)?;
            require(status == expected, || {
                format!("{label}: launcher status {status}, but the guest exited {expected}")
            })?;
            Ok(status)
        }
        Expect::Program { expect, .. } => {
            let status = session.wait(Duration::from_secs(180))?;
            require(status == expect, || {
                format!(
                    "{label}: the launcher answered {status}, not {expect}, for a program it \
                     could not run; output={:?}",
                    session.launcher_output()
                )
            })?;
            Ok(status)
        }
        Expect::Reject { stdin } => {
            receipt.insert("expect".to_owned(), json!("usage error 2"));
            receipt.insert("stdin_kind".to_owned(), json!(channel_name(stdin)));
            let status = session.wait(Duration::from_secs(120))?;
            let stderr = session.stderr_text();
            require(status == 2, || {
                format!("{label}: status {status}, not a usage error; {stderr:?}")
            })?;
            // Either refusal spelling is actionable; anything else leaves the
            // caller without a way to fix the launch.
            require(
                stderr.contains("--tty (-t) requires terminal stdin")
                    || stderr.contains("cannot be used with"),
                || format!("{label}: unhelpful diagnostic: {stderr:?}"),
            )?;
            // A notice line means the launch booted anyway, which is exactly what
            // a refusal before boot must not do.
            require(!stderr.contains("==>"), || {
                format!("{label}: a refused launch booted anyway: {stderr:?}")
            })?;
            if stdin == Channel::Pipe {
                // The caller's own input: a refusal that consumed it would look
                // identical from the status alone.
                let leftover = session.unconsumed_stdin();
                receipt.insert("stdin_unconsumed".to_owned(), json!(decode(&leftover)));
                require(leftover == b"unread", || {
                    format!(
                        "{label}: the refused launch consumed the caller's pipe input: \
                         {leftover:?}"
                    )
                })?;
            }
            receipt.insert("stderr".to_owned(), json!(stderr));
            Ok(status)
        }
        Expect::Wait => {
            session.pump(
                |out| out.contains("WAIT-READY"),
                "the wait case's readiness",
                marker,
                View::Merged,
            )?;
            require(session.raw_observed()?, || {
                format!("{label}: the launcher never made its terminal raw")
            })?;
            receipt.insert("raw_state".to_owned(), json!("observed"));
            let identity =
                owned_runtime_identity(&invocation.state_root, session.launcher_pid, &label)?;
            receipt.insert(
                "runtime_pid".to_owned(),
                identity.get("pid").cloned().unwrap_or(Value::Null),
            );
            // Recheck immediately before signalling, and never signal a name or a
            // group: the catalog row this launcher names is the only target.
            crate::egress_fixtures::signal_identity(&identity, libc::SIGKILL)?;
            let status = session.wait(Duration::from_secs(120))?;
            require(status == 125, || {
                format!("{label}: runtime loss reported {status}, not 125")
            })?;
            require(!session.launcher_output().contains("WAIT-EOF"), || {
                format!("{label}: a false guest exit was reported")
            })?;
            Ok(status)
        }
        Expect::LegacyDetach => {
            session.pump(
                |out| out.contains("WAIT-READY"),
                "the legacy wait's readiness",
                marker,
                View::Merged,
            )?;
            // The legacy session still enters raw mode and still detaches on
            // Ctrl-], so the key must not be forwarded.
            require(session.raw_observed()?, || {
                format!("{label}: the legacy session never made its terminal raw")
            })?;
            receipt.insert("raw_state".to_owned(), json!("observed"));
            session.write_terminal(b"\x1d")?;
            let status = session.wait(Duration::from_secs(120))?;
            let text = session.launcher_output();
            require(!text.contains("WAIT-EOF"), || {
                format!("{label}: the detach key reached the guest instead of detaching: {text:?}")
            })?;
            // Not a guest status: the SDK's attach reports its own
            // sentinel-derived 255 when Ctrl-] detaches. Recording the status is
            // not observing it, so a legacy launch that started reporting the
            // guest's status (or 0) has to fail here.
            require(status == 255, || {
                format!("{label}: a detached legacy session reported {status}, not its 255")
            })?;
            Ok(status)
        }
        Expect::Prompt(row) => prompt::observe(invocation, session, receipt, row),
        Expect::Signal(row) => signal::observe(invocation, session, receipt, row, release),
    }
}

fn channel_name(channel: Channel) -> &'static str {
    match channel {
        Channel::Tty => "tty",
        Channel::Pipe => "pipe",
        Channel::File => "file",
    }
}

/// The redirected guest stdout holds the guest's report and nothing else.
///
/// A **streamed** stdout channel is the guest's own fd 1, so anything else there
/// — a launcher notice or another channel's bytes — fails. A **merged PTY**
/// stream is the guest's stdout *and* stderr, so the guest bootstrap's own
/// `==> ` notices are expected there; nothing else is.
fn require_stdout_envelope(label: &str, text: &str, merged: bool) -> Result<(), String> {
    const PREFIXES: [&str; 9] = [
        "IDENTITY tty0=",
        "UID=",
        "GID=",
        "PWD=",
        "PATH=",
        "HOOK=",
        "OUT marker",
        "ERR marker",
        "IDENTITY-DONE",
    ];
    const REQUIRED: [&str; 5] = [
        "IDENTITY tty0=",
        "UID=",
        "PWD=",
        "OUT marker",
        "IDENTITY-DONE",
    ];
    let lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.trim().is_empty())
        .collect();
    require(!lines.is_empty(), || {
        format!("{label}: the guest stdout channel is empty")
    })?;
    for line in &lines {
        require(
            PREFIXES.iter().any(|prefix| line.starts_with(prefix))
                || (merged && line.starts_with("==> ")),
            || format!("{label}: unexpected bytes on the guest stdout channel: {line:?}"),
        )?;
    }
    for prefix in REQUIRED {
        require(lines.iter().any(|line| line.starts_with(prefix)), || {
            format!("{label}: no {prefix:?} line in the guest stdout envelope: {text:?}")
        })?;
    }
    require(text.contains("ERR marker") == merged, || {
        format!(
            "{label}: the guest stderr marker must appear on the merged stream only under a \
             PTY: {text:?}"
        )
    })
}

// --- The command ------------------------------------------------------------

#[derive(Debug, clap::Args)]
pub struct DirectTerminalArgs {
    /// The launcher binary under test. Absolute.
    #[arg(long, value_name = "PATH")]
    bin: Option<PathBuf>,
    /// The owned test project (its cwd, and where `guest-probe.sh` lives).
    #[arg(long, value_name = "PATH")]
    project: Option<PathBuf>,
    /// The image tag the launch must select.
    #[arg(long, value_name = "TAG")]
    image: Option<String>,
    /// The runtime binary the launch must use.
    #[arg(long, value_name = "PATH")]
    runtime: Option<PathBuf>,
    /// The launch's private state root.
    #[arg(long = "state-root", value_name = "PATH")]
    state_root: Option<PathBuf>,
    /// One case from the inventory.
    #[arg(long, value_name = "NAME")]
    case: Option<String>,
    /// The command boundary the launch is spelled with.
    #[arg(long, value_enum, default_value = "run")]
    form: Form,
    /// The evidence directory. Absolute, and created if absent.
    #[arg(long, value_name = "PATH")]
    evidence: Option<PathBuf>,
    /// A private guest HOME for this case.
    #[arg(long, value_name = "PATH")]
    home: Option<PathBuf>,
    /// The project hook's export value the guest must report.
    #[arg(long = "expect-hook", value_name = "VALUE")]
    expect_hook: Option<String>,
    /// A PATH fragment the hook adds and the guest must report.
    #[arg(long = "expect-hook-path", value_name = "FRAGMENT")]
    expect_hook_path: Option<String>,
    /// Skip the detached-terminal precondition. A control's own escape hatch.
    #[arg(long = "no-ambient-tty-check")]
    no_ambient_tty_check: bool,
    /// The launcher is a stand-in: no session, refusal log or allowance store.
    #[arg(long)]
    standin: bool,
    /// Run the boot-free controls instead of a case. Each is also a `cargo test`
    /// name.
    #[arg(long = "self-test")]
    self_test: bool,
    /// Run only the controls whose name contains this string. Repeatable.
    #[arg(long, value_name = "NAME")]
    only: Vec<String>,
}

pub fn run(args: DirectTerminalArgs) -> Result<Outcome, String> {
    if args.self_test {
        controls::self_test(&args.only)?;
        return Ok(Outcome::Report(
            "direct-terminal controls passed: the driver's exact-byte, resize, argv and \
             restoration oracles reject every broken stand-in"
                .to_owned(),
        ));
    }
    let invocation = Invocation::from_args(&args)?;
    if !invocation.no_ambient_tty_check {
        assert_no_controlling_terminal()?;
    }
    fs::create_dir_all(&invocation.evidence)
        .map_err(|error| format!("{}: {error}", invocation.evidence.display()))?;
    let work = invocation.evidence.join(format!(
        "work-{}-{}",
        invocation.case.name,
        invocation.form.value_name()
    ));
    fs::create_dir_all(&work).map_err(|error| format!("{}: {error}", work.display()))?;
    let label = invocation.label();
    let receipt_path = invocation.evidence.join(format!(
        "{}-{}.json",
        invocation.case.name,
        invocation.form.value_name()
    ));
    let outcome = match run_case(&invocation, &work) {
        Ok(outcome) => outcome,
        // A failure before the case could start is the case's evidence too: the
        // receipt says what the driver refused, and the verdict status is 1.
        Err(error) => {
            let mut receipt = Map::new();
            receipt.insert("argv".to_owned(), Value::Array(Vec::new()));
            CaseOutcome {
                receipt,
                verdict: Err(error),
            }
        }
    };
    let CaseOutcome {
        mut receipt,
        verdict,
    } = outcome;
    receipt.insert("case".to_owned(), json!(invocation.case.name));
    receipt.insert("form".to_owned(), json!(invocation.form.value_name()));
    match verdict {
        Ok(status) => {
            receipt.insert("verdict".to_owned(), json!("pass"));
            write_receipt(&receipt_path, &receipt)?;
            fs::write(
                invocation.evidence.join(format!(
                    "{}-{}.status",
                    invocation.case.name,
                    invocation.form.value_name()
                )),
                format!("{status}\n"),
            )
            .map_err(|error| format!("cannot write the status file: {error}"))?;
            Ok(Outcome::Report(format!("PASS {label} status={status}")))
        }
        Err(error) => {
            // A case's own refusal is the driver's verdict, not the harness's
            // failure: the receipt is the evidence and the status is the answer.
            receipt.insert("verdict".to_owned(), json!("fail"));
            receipt.insert("error".to_owned(), json!(error));
            write_receipt(&receipt_path, &receipt)?;
            println!("FAIL {label}: {error}");
            Ok(Outcome::Exit(1))
        }
    }
}

fn write_receipt(path: &Path, receipt: &Map<String, Value>) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&Value::Object(receipt.clone()))
        .map_err(|error| format!("cannot encode the receipt: {error}"))?;
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inventory_is_pinned_and_partitioned() {
        let mut total = 0;
        for (group, expected) in EXPECTED_ROWS {
            let ported = CASES.iter().filter(|case| case.group == group).count();
            let remaining = group.remaining_rows().len();
            assert_eq!(
                ported + remaining,
                expected,
                "the {:?} group has {ported} ported and {remaining} remaining rows, not {expected}",
                group.name()
            );
            assert_eq!(
                group.ported(),
                remaining == 0,
                "the {:?} group's ported flag and its remaining rows disagree",
                group.name()
            );
            total += expected;
        }
        assert_eq!(total, 57, "the whole inventory is 57 rows");
    }

    #[test]
    fn every_ported_row_is_unique_and_its_group_is_ported() {
        let mut names: Vec<&str> = Vec::new();
        for case in &CASES {
            assert!(!names.contains(&case.name), "{} appears twice", case.name);
            names.push(case.name);
            assert!(
                case.group.ported(),
                "{} is in the unported {:?} group",
                case.name,
                case.group.name()
            );
        }
        assert_eq!(names.len(), 57, "the whole inventory runs");
    }

    #[test]
    fn a_guest_report_keeps_its_values_whole() {
        let report = parse_report(
            "IDENTITY tty0=1 tty1=1 tty2=1\r\nUID=501 GID=20\r\nPATH=/bin dir:/usr/bin\r\n\
             HOOK=absent\r\n",
        );
        assert_eq!(report.get("tty1").map(String::as_str), Some("1"));
        assert_eq!(report.get("UID").map(String::as_str), Some("501"));
        assert_eq!(report.get("GID").map(String::as_str), Some("20"));
        assert_eq!(
            report.get("PATH").map(String::as_str),
            Some("/bin dir:/usr/bin")
        );
        // A key that is the tail of a longer word is not a fact.
        let nested = parse_report("SOMEPATH=/nowhere\n");
        assert_eq!(nested.get("PATH"), None);
    }

    #[test]
    fn an_unknown_row_is_refused_and_the_whole_inventory_is_accepted() {
        let args = |case: &str| DirectTerminalArgs {
            bin: Some(PathBuf::from("/launcher")),
            project: Some(PathBuf::from("/project")),
            image: Some("image".to_owned()),
            runtime: Some(PathBuf::from("/runtime")),
            state_root: Some(PathBuf::from("/state")),
            case: Some(case.to_owned()),
            form: Form::Run,
            evidence: Some(PathBuf::from("/evidence")),
            home: None,
            expect_hook: None,
            expect_hook_path: None,
            no_ambient_tty_check: true,
            standin: false,
            self_test: false,
            only: Vec::new(),
        };
        // A row the Python had, and this driver refused to silently skip, is now a
        // ported row: refusing it would mean the matrix lost a case.
        let accepted = Invocation::from_args(&args("signal-pty-int-handled"))
            .expect("a ported signal row is accepted");
        assert_eq!(accepted.label(), "signal-pty-int-handled/run");
        assert_eq!(
            accepted.argv(&[])[3..],
            [
                OsString::from("bash"),
                OsString::from("./guest-probe.sh"),
                OsString::from("signal-handle"),
                OsString::from("42"),
            ]
        );
        let unknown = Invocation::from_args(&args("no-such-case"))
            .err()
            .expect("an unknown row is refused");
        assert!(unknown.contains("unknown case"), "{unknown}");
        assert!(unknown.contains("identity-auto"), "{unknown}");
        // A ported row still spells the boundary, and every row is ported.
        let accepted = Invocation::from_args(&args("identity-auto")).expect("a ported row");
        assert_eq!(accepted.label(), "identity-auto/run");
        assert_eq!(
            accepted.argv(&[])[1..3],
            [OsString::from("run"), OsString::from("bash")]
        );
        for row in ported_rows() {
            Invocation::from_args(&args(row))
                .unwrap_or_else(|error| panic!("{row} is listed but refused: {error}"));
        }
    }

    #[test]
    fn the_form_names_the_boundary_it_writes() {
        assert_eq!(Form::Run.boundary(), "run");
        assert_eq!(Form::Separator.boundary(), "--");
        assert_eq!(Form::Run.value_name(), "run");
        assert_eq!(Form::Separator.value_name(), "separator");
    }
}
