//! The `agent-vm secret` verbs: argument surface, input acquisition, rendering.
//!
//! Thin by design. `secret_store` owns the store, the credential-store
//! namespace, the inventory and the ordering invariants; this module owns what
//! the user types, what they see, and — the part that needs the most care —
//! what is *refused* so a mistaken value is never stored and never reaches this
//! process's own output (`docs/specs/credential-shielding.md` §"Secret-value
//! CLI", AC 10).
//!
//! # Two refusal layers, because declared arguments are not enough
//!
//! Layer 1 declares the mistaken shapes (`set SERVICE VALUE` and `set SERVICE
//! --token VALUE`) so they produce a helpful message instead of "unexpected
//! argument", and then refuses them without ever echoing the value.
//!
//! Layer 2 lives in [`crate::cli`]: clap itself *does* print supplied values on
//! some parse errors (`secret set svc --help=SECRET` renders `unexpected value
//! 'SECRET' for '--help'`), and `cli::parse_from` calls `error.exit()` on those,
//! so no handler here could intervene. The fix is an unconditional scrub of the
//! whole `secret` subtree's clap errors in `cli::parse_from`, which is why the
//! two layers are in different modules: this one cannot see a clap error.
//!
//! # Never reads or renders a *stored value* — but names are not secret
//!
//! The precise guarantee is narrower than "no secret can appear". Nothing here
//! reads a stored value back or renders one: `ls` prints [`render_rows`]'s three
//! fixed status words, and every error is a fixed string.
//!
//! A **service name, however, is user-controlled metadata that is displayed by
//! design**: `set`/`rm` echo the validated name on success and `ls` lists every
//! name. Under O1 a realistic API key is made of the name alphabet, so a key
//! typed into the name slot is *accepted* as a name and printed. Treat a key
//! typed on the command line as **exposed**: the shell records argv in its
//! history before this process starts, and the name then reaches the terminal,
//! listings and any log that captures them. Refusal keeps a mistaken value out
//! of agent-vm's own storage and output; it cannot un-type it.
//!
//! Consequently no failure diagnostic in this module or in [`crate::secret_store`]
//! interpolates the supplied identifier, and the hidden prompt is generic (it
//! names no service), so a name is echoed only on the successful paths the user
//! already knows about.
//!
//! # Service names are case-folded
//!
//! `ServiceName::parse` ASCII-lowercases the name, so `Anthropic`,
//! `ANTHROPIC` and `anthropic` are one credential rather than three invisible
//! duplicates in a case-sensitive keychain (`secret_store.rs`). The
//! consequence to keep in mind: a realistic API key is made of the same
//! characters a name may contain, so a key typed in the name slot is *accepted*
//! as a name (see `secret_store`'s `a_key_shaped_name_is_accepted_after_o1`).

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, RawFd};

use anyhow::{Context, Result, anyhow};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use vstd::prelude::*;

use crate::secret_store::{
    KeychainBackend, MAX_SECRET_VALUE_LEN, RemoveOutcome, SecretEntry, SecretStore, ServiceName,
    StorageStatus,
};

verus! {

/// The resource bound for one hidden line: [`MAX_SECRET_VALUE_LEN`] bytes.
///
/// The state after one more input byte: the length and whether the buffer has
/// overflowed. The overflow bit is **sticky** — once a byte has been dropped the
/// prefix can never be recovered, so a later backspace must not turn a rejected
/// paste into an accepted value.
pub(crate) open spec fn hidden_line_len_after_byte(len: nat, overflow: bool) -> nat {
    if overflow || len >= MAX_SECRET_VALUE_LEN {
        len
    } else {
        (len + 1) as nat
    }
}

pub(crate) open spec fn hidden_line_overflow_after_byte(len: nat, overflow: bool) -> bool {
    overflow || len >= MAX_SECRET_VALUE_LEN
}

/// The exec body of the resource-limit decision. Verified: the returned pair *is*
/// the specified transition, so the reader stores a byte only while the buffer
/// is under the limit and the overflow bit never clears. The outer reader
/// ([`HiddenLine::push_byte`]) is the thin trusted adapter that pushes the byte.
fn hidden_line_byte_step(len: usize, overflow: bool) -> (out: (usize, bool))
    ensures
        out.0 as nat == hidden_line_len_after_byte(len as nat, overflow),
        out.1 == hidden_line_overflow_after_byte(len as nat, overflow),
{
    if overflow || len >= MAX_SECRET_VALUE_LEN {
        (len, true)
    } else {
        (len + 1, false)
    }
}

/// Index safety for the backspace path: the byte count drops by one, floored at
/// zero, so the caller can never truncate past the start of the buffer. The
/// previous hand-rolled index arithmetic walked off the front for a one-byte
/// buffer holding a UTF-8 continuation byte, which panicked with
/// `attempt to subtract with overflow` (review finding N4).
pub(crate) open spec fn hidden_line_after_backspace(len: nat) -> nat {
    if len == 0 {
        0
    } else {
        (len - 1) as nat
    }
}

fn hidden_line_backspace_len(len: usize) -> (out: usize)
    ensures
        out as nat == hidden_line_after_backspace(len as nat),
        out <= len,
{
    if len == 0 { 0 } else { len - 1 }
}

} // verus!

/// The fixed refusal for a value supplied on the command line. Names no part of
/// the value, and explains the one thing the user needs to know.
const SECRET_VALUE_ON_ARGV: &str = "a secret value must not be passed on the command line: the \
                                   shell history and the process argument list would both expose \
                                   it. Pipe it on stdin, or run `agent-vm secret set SERVICE` with \
                                   no value for a hidden prompt";

const SERVICE_HEADER: &str = "SERVICE";
const STORAGE_HEADER: &str = "STORAGE";
const COLUMN_GAP: usize = 2;

#[derive(clap::Args)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) op: Op,
}

#[derive(clap::Subcommand)]
pub(crate) enum Op {
    /// Store or replace the value for SERVICE in the system keychain.
    Set {
        /// The credential's service name (e.g. `anthropic`).
        ///
        /// 1-64 characters from `[a-zA-Z0-9._-]`, starting with a letter or
        /// digit. Letters are folded to ASCII lowercase, so `Anthropic` and
        /// `anthropic` are the *same* credential: the name you give here (folded)
        /// is what `secret ls` prints and what the host keychain stores.
        ///
        /// The value is never an argument: pipe it on stdin
        /// (`printf '%s' "$KEY" | agent-vm secret set SERVICE`) or omit it here
        /// for a hidden interactive prompt.
        service: String,

        // --- refusal surface: declared so we can give a GOOD error, ---
        // --- not so that clap can be trusted with the value.        ---
        // Both are hidden: they exist only to be refused, and are never part of
        // the documented interface (`secret set --help` must not mention
        // `--token` or a value argument — test I3).
        #[arg(hide = true, num_args = 0.., trailing_var_arg = true)]
        rejected_positional: Vec<String>,
        #[arg(long = "token", hide = true, value_name = "VALUE")]
        rejected_token: Option<String>,
    },
    /// List the service names agent-vm has stored, and their storage status.
    Ls,
    /// Remove agent-vm's stored value for SERVICE.
    Rm {
        /// The credential's service name (e.g. `anthropic`); letters are folded
        /// to ASCII lowercase, so any spelling addresses the same credential.
        service: String,
    },
}

/// Run the requested verb and return the process exit status.
///
/// A `Result` *plus* a status, rather than either alone: `ls` must print its
/// rows and then exit non-zero when any row is `Unavailable`, because a zero
/// exit would tell a script everything is fine when agent-vm could not see the
/// store. An error (rather than a status) is reserved for a verb that could not
/// produce a listing at all.
pub(crate) fn run(args: Args) -> Result<i32> {
    // A debug-only test seam: `tests/secret_pty.rs` points this at a recording
    // backend so it can assert the exact bytes the hidden reader delivered
    // without touching a real credential store (review finding N3). Compiled out
    // of release builds.
    #[cfg(debug_assertions)]
    if let Some(store) = crate::secret_store::test_recording_store()? {
        return run_with(&store, args);
    }
    let store = crate::secret_store::system_store()?;
    run_with(&store, args)
}

fn run_with<B: KeychainBackend>(store: &SecretStore<B>, args: Args) -> Result<i32> {
    match args.op {
        Op::Set {
            service,
            rejected_positional,
            rejected_token,
        } => {
            set(
                store,
                &service,
                &rejected_positional,
                rejected_token.as_deref(),
            )?;
            Ok(0)
        }
        Op::Ls => list(store),
        Op::Rm { service } => {
            remove(store, &service)?;
            Ok(0)
        }
    }
}

fn set<B: KeychainBackend>(
    store: &SecretStore<B>,
    service: &str,
    rejected_positional: &[String],
    rejected_token: Option<&str>,
) -> Result<()> {
    // Refuse first: the cheapest check, and it must not depend on anything that
    // touches the value.
    reject_argv_value(rejected_positional, rejected_token)?;
    // Validate the name *before* reading the value, so `agent-vm secret set
    // BadName` fails before any store access and before any prompt.
    let service = ServiceName::parse(service)?;
    // The value is read before the store lock is taken, so a hidden prompt
    // never blocks holding the inventory lock.
    let value = read_secret_value(std::io::stdin().is_terminal())?;
    store.set(&service, &value)?;
    // stderr, not stdout: `set` is scriptable and stdout must stay empty for
    // a caller that pipes it somewhere.
    if store.is_test_recording() {
        // The debug-only recording seam stores nothing (only a length and
        // SHA-256), and `script/build/macos.sh --dev` ships debug-assertion
        // builds, so a stale or hostile AGENT_VM_TEST_SECRET_RECORD must not
        // read as success (review finding R5).
        eprintln!("warning: the test recording backend is active; nothing was stored");
    } else {
        eprintln!("stored a value for '{service}' in the system keychain");
    }
    eprintln!("note: storing a value does not authorize its use");
    Ok(())
}

fn list<B: KeychainBackend>(store: &SecretStore<B>) -> Result<i32> {
    let rows = store.list()?;
    let mut stdout = std::io::stdout();
    stdout
        .write_all(render_rows(&rows).as_bytes())
        .context("writing the secret listing to stdout")?;
    stdout.flush().context("flushing the secret listing")?;
    Ok(list_exit_code(&rows))
}

fn remove<B: KeychainBackend>(store: &SecretStore<B>, service: &str) -> Result<()> {
    let service = ServiceName::parse(service)?;
    match store.remove(&service)? {
        RemoveOutcome::Removed => {
            eprintln!("removed the stored value for '{service}'");
            Ok(())
        }
        // No identifier in the failure: a name is user-supplied, and a key
        // typed in the name slot must not be echoed back (review finding 3).
        RemoveOutcome::NotStored => Err(anyhow!("no agent-vm secret is stored under that name")),
    }
}

/// Layer 1: refuse any argument shape that could have carried the value.
fn reject_argv_value(rejected_positional: &[String], rejected_token: Option<&str>) -> Result<()> {
    if !rejected_positional.is_empty() || rejected_token.is_some() {
        return Err(anyhow!(SECRET_VALUE_ON_ARGV));
    }
    Ok(())
}

/// `ls` exits non-zero iff some row could not be probed. An **empty** inventory
/// exits zero and means only "no names are tracked" — no probe ran, so it is
/// *not* evidence the credential store is healthy (USAGE.md says so).
fn list_exit_code(rows: &[SecretEntry]) -> i32 {
    if rows
        .iter()
        .any(|row| matches!(row.status, StorageStatus::Unavailable(_)))
    {
        1
    } else {
        0
    }
}

/// The two-column listing. Pure, so its exact bytes are unit-tested: the column
/// width follows the longest rendered name (never narrower than the header), and
/// the only value-shaped datum available to it is the status word.
fn render_rows(rows: &[SecretEntry]) -> String {
    let width = rows
        .iter()
        .map(|row| row.service.as_str().len())
        .chain(std::iter::once(SERVICE_HEADER.len()))
        .max()
        .unwrap_or(SERVICE_HEADER.len());
    let mut out = String::new();
    write_cell(&mut out, SERVICE_HEADER, width);
    out.push_str(STORAGE_HEADER);
    out.push('\n');
    for row in rows {
        write_cell(&mut out, row.service.as_str(), width);
        out.push_str(&storage_text(&row.status));
        out.push('\n');
    }
    out
}

fn write_cell(out: &mut String, text: &str, width: usize) {
    out.push_str(text);
    for _ in text.len()..width + COLUMN_GAP {
        out.push(' ');
    }
}

fn storage_text(status: &StorageStatus) -> String {
    match status {
        StorageStatus::Stored => "stored".to_owned(),
        StorageStatus::Missing => "missing".to_owned(),
        StorageStatus::Unavailable(failure) => format!("unavailable: {}", failure.message()),
    }
}

/// Read the value the user supplied, from a pipe or a hidden prompt.
///
/// The two branches do **not** share a terminator rule, deliberately: the
/// interactive reader ends at `Enter` and can never contain a newline, while
/// the piped branch strips exactly one trailing terminator and rejects any
/// other control byte. Both end at
/// [`crate::secret_store::SecretValue::parse`], which is the one place the
/// accepted shape is defined.
fn read_secret_value(stdin_is_tty: bool) -> Result<crate::secret_store::SecretValue> {
    if !stdin_is_tty {
        return parse_piped_input(&read_bounded_stdin(std::io::stdin().lock())?);
    }
    let stdin = std::io::stdin();
    let mut stderr = std::io::stderr();
    // The prompt goes to stderr; if that is not a terminal the user cannot see
    // it, so reading hidden input here would be a guess. Refuse instead, the
    // same way the previous `console`-based reader did.
    if !stderr.is_terminal() {
        return Err(anyhow!(
            "no terminal is available for hidden input; pipe the value on stdin instead"
        ));
    }
    // Arm the termination-signal guard **first**, so the window in which a
    // caught signal could find the terminal raw is as small as possible: a
    // signal in that window only records itself, and the guard's `Drop`
    // restores the previous handlers.
    let signals = SignalGuard::enable()?;
    // Put the terminal into hidden raw mode **before** the prompt is written, so
    // a paste that arrives the instant the prompt appears is read
    // non-canonically and is never echoed by the line discipline. The guard
    // flush-and-restores on every exit path below, including cancellation and a
    // caught signal.
    let guard = RawHiddenTerminal::enable(stdin.as_raw_fd())?;
    // Generic on purpose: it names no service, because a name is user-supplied
    // metadata and a key typed in the name slot must not be printed before any
    // value is entered (review finding 3).
    stderr
        .write_all(b"Enter the value (input is hidden): ")
        .context("writing the secret prompt")?;
    stderr.flush().context("flushing the secret prompt")?;
    let outcome = read_hidden_value(stdin.as_raw_fd(), &signals);
    // Raw mode does not echo the terminating `Enter`; emit the newline the
    // terminal would otherwise have produced, whatever the outcome.
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
    // Restore the terminal **and** the previous signal handlers before acting on
    // the outcome: a caught signal must be re-raised only once the terminal is
    // no longer raw (review finding N2).
    drop(guard);
    drop(signals);
    match outcome? {
        HiddenRead::Value(bytes) => crate::secret_store::SecretValue::parse(bytes),
        HiddenRead::Aborted => Err(anyhow!("no value was supplied")),
        HiddenRead::Interrupted(signal) => {
            // `pending` yields a signal only when its disposition *before*
            // agent-vm installed a handler was the default action (an inherited
            // `SIG_IGN` is consumed and the read continues), so reproducing the
            // process's disposition here is reproducing the default: re-raise
            // and let it terminate with the signal's status rather than a
            // generic error.
            let _ = signal_hook::low_level::emulate_default_handler(signal);
            // Reached only if the signal did not terminate (it does for all four
            // caught signals); report rather than continue with a partial read.
            Err(anyhow!(
                "the hidden input was interrupted by signal {signal}"
            ))
        }
    }
}

/// Read one hidden line from `fd`, byte by byte, bounded to
/// [`MAX_SECRET_VALUE_LEN`] bytes.
///
/// `console::Term::read_secure_line` clears `ECHO` but leaves `ICANON` set, so
/// the terminal's canonical line buffer fills before the application ever sees
/// the bytes: on macOS a paste of 1024 bytes or more never reaches the length
/// validation and the command appears to hang while the terminal driver emits
/// BELs. `console::Term::read_key` is not a fix either — it restores the
/// original attributes after **every** key, so a paste that arrives between two
/// keys is still canonicalized and echoed. This reader holds hidden raw mode for
/// the whole line (via [`RawHiddenTerminal`]) and reads bytes directly, so a
/// paste of any supported length is delivered to [`HiddenLine`] and an
/// oversized one is rejected instead of hanging (review finding 4).
/// What the hidden read produced before shape validation.
enum HiddenRead {
    /// The line ended at `Enter`, `Ctrl-D` or EOF; the bytes still have to pass
    /// the value shape rule.
    Value(Vec<u8>),
    /// The user cancelled (`Escape`/`Ctrl-C`).
    Aborted,
    /// A catchable termination signal arrived with its *default* disposition;
    /// the number is re-raised with that default action once the terminal is
    /// restored. A signal the process inherited as `SIG_IGN` never reaches here
    /// — [`SignalGuard::pending`] consumes it and the read continues, so the
    /// hidden prompt does not turn an ignored signal into a fatal one (review
    /// finding R2).
    Interrupted(libc::c_int),
}

/// Read one hidden line, watching a self-pipe for a caught termination signal at
/// the same time (see [`SignalGuard`]).
///
/// Both event sources are polled together so a signal never has to wait for the
/// next keystroke: the moment the guard's pipe is readable the read stops. The
/// terminal byte stream itself is read one byte at a time, so a paste of any
/// supported length arrives without passing through the canonical buffer.
fn read_hidden_value(fd: RawFd, signals: &SignalGuard) -> Result<HiddenRead> {
    let mut line = HiddenLine::new();
    let mut byte = [0_u8; 1];
    loop {
        if let Some(signal) = signals.pending() {
            return Ok(HiddenRead::Interrupted(signal));
        }
        let mut pollfds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.read_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // No timeout: block until a byte, EOF, or a caught signal. The handler
        // writes to the pipe, so `poll` always returns and the `pending` check
        // turns it into `Interrupted` instead of a raw process termination.
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("waiting for the hidden secret value");
        }
        if pollfds[1].revents != 0
            && let Some(signal) = signals.pending()
        {
            return Ok(HiddenRead::Interrupted(signal));
        }
        // Read whenever the tty is readable *or* its peer is gone, so a
        // POLLHUP carrying a final buffered byte is not missed and an EOF does
        // not busy-loop on a repeated HUP.
        if pollfds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let read = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
            if read < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    // The pty peer is gone: end the line rather than erroring.
                    Some(libc::EIO) => break,
                    _ if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    _ => return Err(error).context("reading the hidden secret value"),
                }
            }
            // EOF on the terminal: treat the line as finished.
            if read == 0 {
                break;
            }
            match line.push(byte[0]) {
                HiddenKey::Next => {}
                HiddenKey::Finish => break,
                // The user cancelled: store nothing and report it the same way an
                // empty line is reported.
                HiddenKey::Abort => return Ok(HiddenRead::Aborted),
            }
        }
    }
    Ok(HiddenRead::Value(line.finish()?))
}

/// A terminal fd held in hidden raw mode for as long as the guard lives.
///
/// `cfmakeraw` clears `ICANON` and `ECHO` (and `ISIG`, so control bytes reach
/// the application instead of the line discipline), which is what makes a paste
/// of any length arrive byte-by-byte rather than through the 1024-byte
/// canonical buffer. Output post-processing is restored so the prompt's own
/// newline still moves the cursor. `Drop` restores the saved attributes, so the
/// terminal is left usable even when reading fails or the user cancels.
struct RawHiddenTerminal {
    fd: std::os::fd::RawFd,
    original: libc::termios,
}

impl RawHiddenTerminal {
    fn enable(fd: std::os::fd::RawFd) -> Result<Self> {
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(anyhow!(
                "no terminal is available for hidden input; pipe the value on stdin instead"
            ));
        }
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        raw.c_oflag = original.c_oflag;
        // `TCSANOW`, not `TCSADRAIN`: no output has been written before this
        // point, so there is nothing to drain, and an immediate change cannot
        // block on a peer that is not reading the pty. (Entry is after the
        // signal guard is armed, but before the read loop, so blocking here
        // would still leave the terminal in whatever the old mode was.)
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error()).context("enabling hidden terminal input");
        }
        Ok(Self { fd, original })
    }
}

impl RawHiddenTerminal {
    /// Restore the saved attributes, **discarding all unread input first**.
    ///
    /// The reader stops at the first terminator or cancellation byte and never
    /// drains the rest of a paste, so the input queue can still hold the tail of
    /// what the user gave to the hidden field. Restoring `ECHO`/`ICANON` before
    /// that tail is discarded is exactly how a cancelled `secret set` could echo
    /// a pasted suffix and hand it to the caller's shell as its next command
    /// (review finding N1). The explicit `tcflush(TCIFLUSH)` discards every
    /// received-but-unread byte *before* the attributes change, so the queue
    /// cannot survive a restored line discipline.
    ///
    /// The attribute change is `TCSANOW`, deliberately **not** `TCSAFLUSH` or
    /// `TCSADRAIN`: those wait for the terminal's *output* queue to drain, and on
    /// a pty whose master is not being read that wait blocks here with the
    /// terminal still raw and the signal handlers still registered — only
    /// `SIGKILL` would work until the peer drained (review finding R3). Applying
    /// the attributes immediately does not wait on output; the input-discard
    /// guarantee comes from the explicit flush above, which is exactly why the
    /// flush is a separate call rather than folded into the `tcsetattr` action.
    ///
    /// A second flush *after* the mode change clears macOS's `PENDIN` ("retype
    /// pending") bookkeeping bit, which `TCSAFLUSH` used to clear as a side
    /// effect and `TCSANOW` does not. The queue is already empty from the first
    /// flush, so this only restores the full `c_lflag` word rather than leaving a
    /// mode change visible to a shell that compares the whole word.
    ///
    /// The policy is the same on **every** exit path — success, cancellation,
    /// EOF and I/O error — so a suffix the reader did not consume is never
    /// replayed. All of the hidden input is discarded, never echoed, never
    /// handed to the caller.
    ///
    /// Failure is best effort: by the time this runs the process is finishing,
    /// and there is no safe place left to report an errno. If the change fails
    /// the terminal stays raw; that is why a catchable signal is routed through
    /// [`SignalGuard`] and restored *before* the process returns to the default
    /// disposition, and why an uncatchable `SIGKILL`/`SIGSTOP` remains the one
    /// documented way to leave a terminal raw.
    fn restore(&self) {
        unsafe { libc::tcflush(self.fd, libc::TCIFLUSH) };
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
        unsafe { libc::tcflush(self.fd, libc::TCIFLUSH) };
    }
}

impl Drop for RawHiddenTerminal {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Wakes the hidden reader when a catchable termination signal arrives, so the
/// terminal can be restored before the process exits with the signal's default
/// disposition.
///
/// Raw mode clears `ISIG`, so a `Ctrl-C` **typed at the terminal** is a byte the
/// reader handles itself. An externally delivered `SIGINT`/`SIGTERM`/`SIGHUP`/
/// `SIGQUIT` is a different path: the kernel runs a handler, and a default one
/// terminates the process without unwinding Rust, so [`RawHiddenTerminal`]'s
/// `Drop` never runs and the terminal is left raw (review finding N2). This guard
/// registers a handler that records the signal's arrival in its own flag and
/// writes one byte to a self-pipe the reader polls. The reader then restores the
/// terminal, drops both guards and, for a signal that was *not* already ignored,
/// re-raises it with its default disposition.
///
/// # Restoring the previous dispositions
///
/// `signal_hook::low_level::unregister` deliberately does **not** restore the
/// disposition a signal had before agent-vm ran; it only removes our action from
/// the registry, leaving a signal-hook handler installed that swallows the
/// signal (`signal-hook-registry`'s own `unregister` warning). On its own that
/// would make the process ignore `SIGINT`/`SIGTERM`/`SIGHUP`/`SIGQUIT` for the
/// rest of its life — `secret set` continues past the read into the store, whose
/// first act is a blocking `flock` on the inventory lock, so a concurrent
/// `secret set` would make it unkillable except with `SIGKILL` (review finding
/// R1). This guard therefore captures each signal's prior `sigaction` in
/// [`SignalGuard::enable`] and restores it in `Drop`, after unregistering.
///
/// # An inherited `SIG_IGN` is not a request to die
///
/// A shell gives background jobs `SIG_IGN` for `SIGINT`/`SIGQUIT`, and `nohup`
/// does so for `SIGHUP`. The saved prior action is what tells
/// [`SignalGuard::pending`] whether the signal was already ignored: an ignored
/// signal is consumed and the read continues rather than being converted into a
/// termination the process never asked for (review finding R2).
///
/// `SIGKILL` and `SIGSTOP` cannot be caught, so `kill -9` still leaves the
/// terminal raw; no in-process mechanism can change that, and it is stated here
/// rather than claimed otherwise.
struct SignalGuard {
    read_fd: std::io::PipeReader,
    /// One arrival flag per caught signal, set by that signal's own action.
    ///
    /// Deliberately **not** a single shared slot. A shared last-writer-wins
    /// value lets a signal the caller ignores, arriving after one whose prior
    /// disposition was the default, overwrite it; signal-hook has already
    /// absorbed that default-disposition signal, so its default action can no
    /// longer run and the reader blocks on `poll(-1)` with the terminal raw
    /// (review finding D1). A flag per signal keeps every arrival, so
    /// [`SignalGuard::pending`] can still find the default-disposition one.
    flags: Vec<(libc::c_int, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
    registrations: Vec<signal_hook::SigId>,
    /// Each caught signal's `sigaction` as it was *before* agent-vm installed its
    /// handler, so `Drop` can restore it (R1) and `pending` can honour an
    /// inherited `SIG_IGN` (R2).
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

/// The catchable termination signals whose default action must be reproduced
/// after the terminal is restored.
const CAUGHT_SIGNALS: [libc::c_int; 4] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT];

impl SignalGuard {
    fn enable() -> Result<Self> {
        let (read_fd, writer) = std::io::pipe().context("creating the signal pipe")?;
        set_nonblocking(read_fd.as_raw_fd())?;
        set_nonblocking(writer.as_raw_fd())?;
        let mut guard = Self {
            read_fd,
            flags: Vec::new(),
            registrations: Vec::new(),
            previous: Vec::new(),
        };
        for signal in CAUGHT_SIGNALS {
            // Capture the disposition the process has *before* agent-vm installs
            // anything. `unregister` will not restore it (see the type docs), so
            // `Drop` needs it to put the signal back the way it was found (R1);
            // it is also how `pending` recognises an inherited `SIG_IGN` (R2).
            let mut old = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
            if unsafe { libc::sigaction(signal, std::ptr::null(), old.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("reading the previous termination-signal disposition");
            }
            guard.previous.push((signal, unsafe { old.assume_init() }));
            // Set this signal's own flag first, then wake the pipe: the
            // self-pipe only says *some* caught signal arrived, so the flag
            // must be visible no later than the wake byte. `pending` drains the
            // pipe before reading any flag, so a signal delivered in the gap
            // between these two registrations is still seen (R4).
            let seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            guard.flags.push((signal, seen.clone()));
            let flag = signal_hook::flag::register(signal, seen)
                .context("registering a termination-signal flag")?;
            guard.registrations.push(flag);
            let duplicate = unsafe { libc::dup(writer.as_raw_fd()) };
            if duplicate < 0 {
                return Err(std::io::Error::last_os_error()).context("duplicating the signal pipe");
            }
            let wake = signal_hook::low_level::pipe::register_raw(signal, duplicate)
                .context("registering the signal wake pipe")?;
            guard.registrations.push(wake);
        }
        // `writer` closes here; the per-signal duplicates stay open until the
        // registrations are unregistered in `Drop`.
        Ok(guard)
    }

    /// Whether a *default-disposition* termination signal has arrived, draining
    /// the wake pipe.
    ///
    /// The pipe is drained **first** and the flags are read afterwards: each
    /// signal's flag action is registered before its pipe action, so a signal
    /// delivered in that gap sets its flag without writing a byte. Reading the
    /// pipe first and bailing out on an empty read would then lose the signal and
    /// block the reader in raw mode forever (review finding R4). Draining first
    /// and then consulting the flags unconditionally catches both a flag-only
    /// signal and a signalled pipe.
    ///
    /// Only a signal whose *prior* disposition was the default action is
    /// reported. An inherited `SIG_IGN` is consumed and the read continues, so
    /// the hidden prompt does not change the process's signal contract (review
    /// finding R2). A prior *handler* likewise already ran through
    /// `signal-hook-registry`'s chaining, so the read also continues.
    ///
    /// Every signal has its **own** flag (see the field docs), and the first set
    /// flag whose prior disposition was the default is returned. An ignored
    /// signal arriving in the same window therefore cannot mask a
    /// default-disposition one (review finding D1).
    fn pending(&self) -> Option<libc::c_int> {
        let mut byte = [0_u8; 1];
        loop {
            let read = unsafe { libc::read(self.read_fd.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
            if read <= 0 {
                break;
            }
        }
        self.flags
            .iter()
            .filter(|(_, seen)| seen.load(std::sync::atomic::Ordering::SeqCst))
            .map(|(signal, _)| *signal)
            .find(|signal| self.prior_was_default(*signal))
    }

    /// Whether `signal` had the default action before agent-vm installed its
    /// handler — as opposed to `SIG_IGN` or a caller-installed handler.
    fn prior_was_default(&self, signal: libc::c_int) -> bool {
        self.previous
            .iter()
            .find(|(registered, _)| *registered == signal)
            .is_some_and(|(_, action)| action.sa_sigaction == libc::SIG_DFL)
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // Unregister our actions first — this closes each per-signal pipe write
        // end — then restore the captured dispositions. Unregistration alone
        // leaves a signal-hook handler installed that swallows the signal, so
        // without the restore the process would ignore SIGINT/SIGTERM/SIGHUP/
        // SIGQUIT for the rest of its life (review finding R1).
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
        for (signal, action) in self.previous.drain(..) {
            unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
        }
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error()).context("reading the signal pipe flags");
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error()).context("setting the signal pipe nonblocking");
    }
    Ok(())
}

/// The hidden line, accumulated one byte at a time and bounded to
/// [`MAX_SECRET_VALUE_LEN`].
///
/// Split from the terminal read so the boundary behaviour — accept exactly the
/// limit, reject one byte past it, delete on backspace, cancel on a control
/// key — is unit-testable without a real terminal. It works on raw bytes, not
/// `char`s, so a non-ASCII paste is passed to
/// [`crate::secret_store::SecretValue::parse`] unchanged and rejected there
/// rather than being silently altered.
struct HiddenLine {
    data: Vec<u8>,
    /// Set once input passes the limit. Sticky: the over-limit bytes have
    /// already been discarded, so the prefix cannot be un-truncated and the
    /// value must be rejected even if the user then deletes.
    overflow: bool,
}

/// What the reader should do after a key.
enum HiddenKey {
    /// Keep reading.
    Next,
    /// The line is complete (`Enter`, `Ctrl-D`/EOF).
    Finish,
    /// The user cancelled (`Escape`, `Ctrl-C`).
    Abort,
}

impl HiddenLine {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            overflow: false,
        }
    }

    /// Control bytes are handled deliberately rather than appended:
    /// `CR`/`LF` finish the line, `DEL`/`BS` delete the previous **byte**,
    /// `Ctrl-D` finishes (EOF), and `Escape`/`Ctrl-C` cancel. Any other byte,
    /// including a non-ASCII one, is kept so the value shape rejects it exactly
    /// as the piped branch would.
    fn push(&mut self, byte: u8) -> HiddenKey {
        match byte {
            b'\n' | b'\r' => return HiddenKey::Finish,
            0x7f | 0x08 => self.delete_last_byte(),
            0x04 => return HiddenKey::Finish,
            0x1b | 0x03 => return HiddenKey::Abort,
            _ => self.push_byte(byte),
        }
        HiddenKey::Next
    }

    /// Append one byte while the buffer is under the limit.
    ///
    /// [`hidden_line_byte_step`] is the verified resource-limit decision (see
    /// the `verus!` block): the returned `(length, overflow)` is the specified
    /// transition, and this method is the thin trusted adapter that pushes the
    /// byte when that transition grew the buffer.
    fn push_byte(&mut self, byte: u8) {
        let (new_len, overflow) = hidden_line_byte_step(self.data.len(), self.overflow);
        if new_len > self.data.len() {
            self.data.push(byte);
        }
        self.overflow = overflow;
    }

    /// Delete exactly the last byte.
    ///
    /// The accepted value alphabet is printable ASCII, so a multi-byte UTF-8
    /// character can never be stored: deleting it one byte at a time can only
    /// leave bytes the shape rule already rejects, and it can never make an
    /// accepted value out of a rejected one. That is a deliberately simpler
    /// policy than recognising a trailing UTF-8 scalar, whose index arithmetic
    /// was the source of a subtract-with-overflow panic on arbitrary bytes
    /// (review finding N4). [`hidden_line_backspace_len`] is the verified
    /// index-safety kernel — the count is floored at zero and can never exceed
    /// the buffer, so the truncate below cannot go past the front.
    fn delete_last_byte(&mut self) {
        let new_len = hidden_line_backspace_len(self.data.len());
        self.data.truncate(new_len);
    }

    fn finish(self) -> Result<Vec<u8>> {
        if self.overflow {
            return Err(anyhow!(
                "the value is longer than {MAX_SECRET_VALUE_LEN} bytes"
            ));
        }
        Ok(self.data)
    }
}

/// The pure decision for piped input: strip exactly one trailing `\n` or
/// `\r\n`, and nothing else. `b"sk\r"` is rejected rather than stripped, because
/// a bare `\r` is not a terminator any shell writes.
fn parse_piped_input(raw: &[u8]) -> Result<crate::secret_store::SecretValue> {
    let stripped = raw
        .strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw);
    crate::secret_store::SecretValue::parse(stripped.to_vec())
}

/// Read at most [`MAX_SECRET_VALUE_LEN`] bytes plus a terminator, and report an
/// overflow rather than silently storing a truncated prefix: a value whose tail
/// was cut off would be stored as a *different, wrong* credential.
fn read_bounded_stdin(mut reader: impl std::io::Read) -> Result<Vec<u8>> {
    let limit = MAX_SECRET_VALUE_LEN + 2;
    let mut data = Vec::new();
    {
        let mut limited = (&mut reader).take(limit as u64);
        limited
            .read_to_end(&mut data)
            .context("reading the secret value from stdin")?;
    }
    if data.len() == limit {
        // Exactly at the limit is legitimate (a maximum-length value plus
        // `\r\n`), so ask for one more byte to tell "at" from "past".
        let mut extra = [0_u8; 1];
        if reader
            .read(&mut extra)
            .context("reading the secret value from stdin")?
            != 0
        {
            return Err(anyhow!(
                "the value is longer than {MAX_SECRET_VALUE_LEN} bytes"
            ));
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::fake::FakeKeychain;
    use crate::secret_store::{InventoryPaths, KeychainFailure, Presence, SecretValue};

    fn name(raw: &str) -> ServiceName {
        ServiceName::parse(raw).unwrap()
    }

    fn value(raw: &str) -> SecretValue {
        SecretValue::parse(raw.as_bytes().to_vec()).unwrap()
    }

    fn row(service: &str, status: StorageStatus) -> SecretEntry {
        SecretEntry {
            service: name(service),
            status,
        }
    }

    fn store(dir: &std::path::Path, backend: FakeKeychain) -> SecretStore<FakeKeychain> {
        SecretStore::new(backend, InventoryPaths::new(dir.to_path_buf()))
    }

    /// C1 — exact rendering, including alignment past the header width and the
    /// empty case (header only, exit zero).
    #[test]
    fn render_rows_pins_the_exact_listing() {
        // With no rows the column is the header's own width, so the only
        // padding is the two-space gap.
        assert_eq!(render_rows(&[]), "SERVICE  STORAGE\n");

        let one = [row("anthropic", StorageStatus::Stored)];
        assert_eq!(render_rows(&one), "SERVICE    STORAGE\nanthropic  stored\n");

        let mixed = [
            row("anthropic", StorageStatus::Stored),
            row("openai", StorageStatus::Missing),
            // A name wider than the header pushes the column, and the failure
            // text is the row's whole second column.
            row(
                "a-very-long-service-name",
                StorageStatus::Unavailable(KeychainFailure::AccessDenied),
            ),
        ];
        // The column is the longest name plus the two-space gap. Spelled as a
        // `format!` field width rather than a hand-counted run of spaces, so
        // the expectation is an independent statement of the column layout.
        let field = "a-very-long-service-name".len() + 2;
        let unavailable = format!("unavailable: {}", KeychainFailure::AccessDenied.message());
        let expected = format!(
            "{:<field$}{}\n{:<field$}{}\n{:<field$}{}\n{:<field$}{}\n",
            "SERVICE",
            "STORAGE",
            "anthropic",
            "stored",
            "openai",
            "missing",
            "a-very-long-service-name",
            unavailable,
            field = field,
        );
        assert_eq!(render_rows(&mixed), expected);
    }

    /// C4 — the exit status is non-zero exactly when a row could not be probed.
    #[test]
    fn list_exit_status_is_nonzero_only_for_unavailable_rows() {
        assert_eq!(list_exit_code(&[]), 0);
        assert_eq!(
            list_exit_code(&[
                row("a", StorageStatus::Stored),
                row("b", StorageStatus::Missing),
            ]),
            0
        );
        assert_eq!(
            list_exit_code(&[
                row("a", StorageStatus::Stored),
                row(
                    "b",
                    StorageStatus::Unavailable(KeychainFailure::Unavailable)
                ),
            ]),
            1
        );
        assert_eq!(
            list_exit_code(&[row(
                "b",
                StorageStatus::Unavailable(KeychainFailure::Ambiguous)
            )]),
            1
        );
    }

    /// C3 — every layer-1 shape is refused by a fixed message that contains no
    /// part of the value. The shapes are the *parsed* forms clap hands us, so
    /// this pins the refusal itself, not clap's parse.
    #[test]
    fn argument_supplied_values_are_refused_without_echoing_them() {
        const SECRET: &str = "sk-ant-REAL-VALUE";
        let cases: [(Vec<String>, Option<&str>); 4] = [
            (vec![SECRET.to_owned()], None),
            (Vec::new(), Some(SECRET)),
            (
                vec!["a".to_owned(), "b".to_owned(), SECRET.to_owned()],
                None,
            ),
            // `set svc --token VALUE` swallows both into the trailing
            // positional (the flag is past the first positional), and
            // `set svc --token VALUE` with `--token` *before* the value still
            // lands one of the two here.
            (vec!["--token".to_owned(), SECRET.to_owned()], None),
        ];
        for (positional, token) in cases {
            let error = reject_argv_value(&positional, token).expect_err("must refuse");
            let text = format!("{error:#}");
            assert!(
                text.contains("must not be passed on the command line"),
                "{text}"
            );
            assert!(!text.contains("sk-ant"), "the value was echoed: {text}");
            assert!(!text.contains("REAL"), "the value was echoed: {text}");
        }
        reject_argv_value(&[], None).expect("no value supplied is not an argument error");
    }

    /// C2 — the listing can never disclose a value, not even a *substring* of
    /// one. A whole-value check would miss partial disclosure, which AC 10 also
    /// forbids.
    #[test]
    fn rendering_a_store_holding_a_value_discloses_no_substring_of_it() {
        const SECRET: &str = "SUPERSECRET";
        let dir = tempfile::tempdir().unwrap();
        let backend = FakeKeychain::new();
        let store = store(dir.path(), backend);
        store.set(&name("anthropic"), &value(SECRET)).unwrap();

        let rows = store.list().unwrap();
        let rendered = render_rows(&rows);
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(
            !contains_substring_of_len(&rendered, SECRET, 4),
            "a 4+ character substring of the value leaked: {rendered}"
        );
    }

    fn contains_substring_of_len(haystack: &str, needle: &str, len: usize) -> bool {
        needle.as_bytes().windows(len).any(|window| {
            let window = std::str::from_utf8(window).expect("the needle is ASCII");
            haystack.contains(window)
        })
    }

    /// Finding 3 — `rm` of an unstored name fails without echoing the name in
    /// either the typed or the case-folded spelling.
    #[test]
    fn removing_an_unstored_name_does_not_echo_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), FakeKeychain::new());
        let typed = "sk-ant-API03-AbCdEf";
        let canonical = typed.to_ascii_lowercase();
        let error = remove(&store, typed).expect_err("nothing is stored under that name");
        let text = format!("{error:#}");
        assert!(
            text.contains("no agent-vm secret is stored under that name"),
            "{text}"
        );
        assert!(!text.contains(typed), "the typed name was echoed: {text}");
        assert!(
            !text.contains(&canonical),
            "the canonical name was echoed: {text}"
        );
    }

    /// V3 — exactly one trailing terminator (`\n` or `\r\n`) is stripped, and
    /// nothing else is tolerated.
    #[test]
    fn piped_input_strips_exactly_one_terminator() {
        for raw in [&b"sk"[..], b"sk\n", b"sk\r\n"] {
            let parsed = parse_piped_input(raw).unwrap();
            assert_eq!(parsed.expose_for_test(), "sk");
        }
        for raw in [&b""[..], b"sk\n\n", b"sk\nmore\n", b"sk\r", b"sk\nmore"] {
            assert!(
                parse_piped_input(raw).is_err(),
                "{raw:?} must not be accepted"
            );
        }
        // A trailing space is a *shape* rejection, not a terminator.
        assert!(parse_piped_input(b"sk \n").is_err());
    }

    /// V4 — the bounded reader accepts the exact limit (with and without a
    /// terminator) and rejects one byte past it, assembles short reads, and
    /// propagates a mid-read error.
    #[test]
    fn bounded_stdin_accepts_the_limit_and_rejects_more() {
        let max = MAX_SECRET_VALUE_LEN;
        // A maximum-length value, with and without a terminator, is the raw
        // input the reader must accept: `max` bytes, `max + 1` with `\n`, and
        // `max + 2` with `\r\n`.
        let mut inputs = vec![vec![b'a'; max]];
        let mut lf = vec![b'a'; max];
        lf.push(b'\n');
        inputs.push(lf);
        let mut crlf = vec![b'a'; max];
        crlf.extend_from_slice(b"\r\n");
        inputs.push(crlf);
        for raw in inputs {
            let read = read_bounded_stdin(raw.as_slice()).unwrap();
            assert_eq!(read, raw, "the exact limit must survive: {}", raw.len());
            assert!(parse_piped_input(&read).is_ok());
        }
        // One or two bytes past the maximum are still *read* -- the extra
        // bytes may be a terminator -- and are then rejected by the shape rule
        // rather than being truncated into a shorter stored value.
        for extra in 1..=2 {
            let raw = vec![b'a'; max + extra];
            let read = read_bounded_stdin(raw.as_slice()).unwrap();
            let error = parse_piped_input(&read).expect_err("past the limit");
            assert!(
                format!("{error:#}").contains("longer than 4096 bytes"),
                "{error:#}"
            );
        }
        // Past the reader's own limit (`max + 2`) the read fails outright.
        for extra in 3..=5 {
            let raw = vec![b'a'; max + extra];
            let error = read_bounded_stdin(raw.as_slice()).expect_err("past the reader limit");
            assert!(
                format!("{error:#}").contains("longer than 4096 bytes"),
                "{error:#}"
            );
        }

        /// Hands out one byte per `read`, so `read_to_end` must loop.
        struct Dribble {
            data: Vec<u8>,
            position: usize,
        }
        impl std::io::Read for Dribble {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.position == self.data.len() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.data[self.position];
                self.position += 1;
                Ok(1)
            }
        }
        let dribbled = read_bounded_stdin(Dribble {
            data: b"short-reads\n".to_vec(),
            position: 0,
        })
        .unwrap();
        assert_eq!(dribbled, b"short-reads\n");

        // A reader that produces bytes and *then* fails: the error must
        // propagate instead of the partial prefix being returned as a shorter
        // (wrong) value. Erroring on the very first read would not exercise the
        // partial-read path.
        struct PartialThenFailing {
            remaining: &'static [u8],
        }
        impl std::io::Read for PartialThenFailing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.remaining.is_empty() {
                    return Err(std::io::Error::other("injected read failure"));
                }
                let n = self.remaining.len().min(buf.len());
                buf[..n].copy_from_slice(&self.remaining[..n]);
                self.remaining = &self.remaining[n..];
                Ok(n)
            }
        }
        let error = read_bounded_stdin(PartialThenFailing {
            remaining: b"sk-partial",
        })
        .expect_err("a mid-read error must propagate");
        assert!(
            format!("{error:#}").contains("injected read failure"),
            "{error:#}"
        );
    }

    /// Finding 4 — the hidden reader's boundary behaviour, driven with
    /// synthetic bytes so the terminal is not involved. The 1023/1024 pair is
    /// the boundary the old canonical-mode reader hung on; 4096/4097 is the
    /// advertised value limit.
    #[test]
    fn hidden_line_accepts_the_limit_and_rejects_one_byte_past_it() {
        for len in [1_usize, 1023, 1024, 4096] {
            let mut line = HiddenLine::new();
            for _ in 0..len {
                assert!(matches!(line.push(b'q'), HiddenKey::Next));
            }
            assert!(matches!(line.push(b'\n'), HiddenKey::Finish));
            let value = line.finish().expect("exactly the limit is accepted");
            assert_eq!(value.len(), len, "no truncation at {len} bytes");
            assert!(value.iter().all(|&b| b == b'q'));
        }
        for len in [4097_usize, 5000, 100_000] {
            let mut line = HiddenLine::new();
            for _ in 0..len {
                let _ = line.push(b'q');
            }
            let error = line.finish().expect_err("past the limit must be rejected");
            assert!(
                format!("{error:#}").contains("longer than 4096 bytes"),
                "{error:#}"
            );
        }
    }

    /// Finding 4 — control bytes are handled deliberately: backspace deletes,
    /// `CR`/`LF` and `Ctrl-D` finish, `Escape`/`Ctrl-C` cancel, a non-ASCII
    /// byte is preserved for the shape rule to reject, and a trailing newline
    /// is never part of the stored value.
    #[test]
    fn hidden_line_handles_editing_and_control_bytes() {
        let mut line = HiddenLine::new();
        for byte in [b'a', b'b', 0x7f, b'c', b'\r'] {
            if byte == b'\r' {
                assert!(matches!(line.push(byte), HiddenKey::Finish));
            } else {
                assert!(matches!(line.push(byte), HiddenKey::Next));
            }
        }
        assert_eq!(line.finish().unwrap(), b"ac");

        // Backspace deletes exactly the last byte. For a multi-byte UTF-8
        // character that leaves a partial sequence, which the printable-ASCII
        // value shape rejects; it is never silently reinterpreted or allowed to
        // move the deletion point (the old UTF-8-aware walk is what underflowed).
        let mut utf8 = HiddenLine::new();
        utf8.push(b'a');
        for byte in "é".as_bytes() {
            assert!(matches!(utf8.push(*byte), HiddenKey::Next));
        }
        utf8.push(0x08);
        assert!(matches!(utf8.push(b'\n'), HiddenKey::Finish));
        assert_eq!(utf8.finish().unwrap(), b"a\xc3");

        assert!(matches!(HiddenLine::new().push(0x1b), HiddenKey::Abort));
        assert!(matches!(HiddenLine::new().push(0x03), HiddenKey::Abort));
        assert!(matches!(HiddenLine::new().push(0x04), HiddenKey::Finish));
    }

    /// Finding N4 — the exact underflow inputs: a lone UTF-8 continuation byte
    /// and an ASCII byte followed by an invalid tail each delete exactly one
    /// byte, with no panic and no unchecked subtraction.
    #[test]
    fn backspace_handles_malformed_byte_tails() {
        for (input, expected) in [
            (vec![0x80_u8], &b""[..]),
            (vec![0xbf_u8], &b""[..]),
            (vec![0xc3_u8], &b""[..]),
            (b"a\x80".to_vec(), &b"a"[..]),
            (b"ab\xc3".to_vec(), &b"ab"[..]),
            (b"abc".to_vec(), &b"ab"[..]),
            (b"a\xc3\xa9".to_vec(), &b"a\xc3"[..]),
        ] {
            let mut line = HiddenLine::new();
            for byte in input {
                line.push_byte(byte);
            }
            line.delete_last_byte();
            assert_eq!(line.data, expected);
        }
        // An empty buffer is a no-op rather than a panic.
        let mut empty = HiddenLine::new();
        empty.delete_last_byte();
        assert!(empty.data.is_empty());
    }

    proptest::proptest! {
        /// Finding N4 — arbitrary bytes: the backspace path is total and
        /// index-safe, removing exactly one byte from a non-empty buffer and
        /// never panicking, whatever the byte pattern.
        #[test]
        fn backspace_is_total_and_removes_exactly_one_byte(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64),
        ) {
            let mut line = HiddenLine::new();
            for &byte in &bytes {
                line.push_byte(byte);
            }
            line.delete_last_byte();
            let expected_len = bytes.len().saturating_sub(1);
            proptest::prelude::prop_assert_eq!(line.data.len(), expected_len);
            proptest::prelude::prop_assert_eq!(&line.data[..], &bytes[..expected_len]);
        }
    }

    /// Finding N4 (cleanup) — a panic while the raw-mode guard is alive still
    /// restores the terminal, because `Drop` runs during unwinding. A throwaway
    /// pty keeps the developer's real terminal out of it.
    #[test]
    fn raw_mode_is_restored_when_the_guard_unwinds() {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
        let read_flags = |fd| {
            let mut attrs = std::mem::MaybeUninit::<libc::termios>::uninit();
            assert_eq!(unsafe { libc::tcgetattr(fd, attrs.as_mut_ptr()) }, 0);
            unsafe { attrs.assume_init() }.c_lflag
        };
        let before = read_flags(slave);
        let unwound = std::panic::catch_unwind(|| {
            let _guard = RawHiddenTerminal::enable(slave).expect("raw mode");
            panic!("injected panic to exercise unwind cleanup");
        });
        assert!(unwound.is_err(), "the closure must have panicked");
        let after = read_flags(slave);
        // macOS flips its PENDIN bookkeeping bit during a mode change, so the
        // user flags are compared rather than the whole word.
        let user_flags = libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN;
        assert_eq!(before & user_flags, after & user_flags);
        unsafe {
            libc::close(slave);
            libc::close(master);
        }
    }

    /// The fake backend's presence probe is the only value-shaped datum that
    /// reaches rendering; this pins the type-level claim behind C2.
    #[test]
    fn a_probe_returns_presence_not_a_value() {
        let backend = FakeKeychain::new();
        backend.seed("anthropic", "SUPERSECRET");
        assert_eq!(
            KeychainBackend::probe(&backend, &name("anthropic")).unwrap(),
            Presence::Present
        );
    }

    /// S18 — every verb fails on an unusable `$HOME`, before any I/O: the store
    /// is constructed first, so `set` never reaches stdin and `ls`/`rm` never
    /// reach the filesystem or the keychain.
    #[test]
    fn unusable_home_fails_every_verb_before_any_io() {
        let mut env = crate::test_env::guard();
        for home in [None, Some(""), Some("relative/path")] {
            match home {
                None => env.remove_var("HOME"),
                Some(value) => env.set_var("HOME", value),
            }
            for (label, op) in [
                (
                    "set",
                    Op::Set {
                        service: "anthropic".to_owned(),
                        rejected_positional: Vec::new(),
                        rejected_token: None,
                    },
                ),
                ("ls", Op::Ls),
                (
                    "rm",
                    Op::Rm {
                        service: "anthropic".to_owned(),
                    },
                ),
            ] {
                match run(Args { op }) {
                    Ok(code) => panic!("{label} with HOME={home:?} must fail, got {code}"),
                    Err(error) => {
                        let text = format!("{error:#}");
                        assert!(text.contains("$HOME"), "{label} {home:?}: {text}");
                        assert!(text.contains("cannot locate"), "{label} {home:?}: {text}");
                    }
                }
            }
        }
    }
}
