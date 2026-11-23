//! What a click on a banner opens: one host terminal running
//! `agent-vm access --session <ID>`.
//!
//! A click **approves nothing**. It shows the same report the operator would get
//! by typing the command, in that session's project and state root, and leaves
//! the shell open for an `access allow`. Every operand is launcher-originated —
//! the session ID, the project, the effective state root, this binary — so a
//! guest cannot choose a directory, a shell word or a program to run.
//!
//! # Why the script lives in `$HOME/.cache/agent-vm/notify-click`
//!
//! The click is executed by macOS, not read by a human, so the directory that
//! holds it is an execution surface:
//!
//! * `XDG_CACHE_HOME` is deliberately **ignored** ([`crate::host_paths::cache_root`]
//!   honours it). A cache env var can be set per launch, and a guest-writable or
//!   repo-local value would redirect a `.command` file that macOS then runs.
//! * A directory that resolves inside the project is refused (fail closed): the
//!   project is what the guest can write, and `../.cache` in a repository would
//!   otherwise make every click execute guest content.
//! * Each component is opened with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and
//!   created with `mkdirat`, and `notify-click` must be this euid's own `0700`
//!   directory. A symlinked ancestor is an error, never silently resolved.
//! * Pruning stats with `AT_SYMLINK_NOFOLLOW` and deletes with `unlinkat`, so a
//!   symlink left in the directory is never followed and its target is never
//!   removed.
//!
//! `$HOME` itself is the one component opened *following* symlinks: it is the
//! host's own environment value (the same rule `host_paths::atomic_write`
//! documents for its first parent), and refusing a symlinked home would make
//! every click fail on a host that has one. Nothing below it is followed.
//!
//! # Why the terminal choice is an environment variable
//!
//! [`TERMINAL_SETTING`] is read by the launcher and written into the banner's
//! `userInfo`, precisely so a click that LaunchServices relaunches hours later
//! still opens the terminal the operator configured. It is not a CLI flag and
//! not a `config.toml` key: a click is not an interactive command, so there is
//! nowhere to put an override flag, and the setting is host presentation rather
//! than sandbox policy.
//!
//! # Why no shell in the launcher
//!
//! The `.command` file *is* the shell. `open` starts it without any Apple-events
//! permission, which is why the default terminal needs no permission prompt at
//! all; the other three are named explicitly because they cannot run a
//! `.command` file on their own. Rendering the script here (rather than passing
//! a command string to a shell) keeps the quoting rule in one place: the raw
//! project and state-root bytes go through
//! [`crate::shell::guest_script_word`], and the only text a human *reads* — the
//! fallback line — goes through [`crate::one_line::path`], so no control byte or
//! ANSI escape in a project path can ever reach the terminal.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use clap::Args as ClapArgs;
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::one_line;
use crate::refusal::SessionId;
use crate::shell;

/// The setting that picks the terminal a click opens.
///
/// Read by the launcher (never by `_notify-click`, which is told) but named here
/// because this module owns the accepted values.
pub(crate) const TERMINAL_SETTING: &str = "AGENT_VM_NOTIFY_TERMINAL";

/// The program macOS uses to open a terminal for a `.command` file.
#[cfg(target_os = "macos")]
const OPEN_PROGRAM: &str = "/usr/bin/open";

/// A debug-build hatch: when set, its value is run instead of `/usr/bin/open`.
///
/// The click launcher's argv is otherwise only observable through
/// LaunchServices, which no CI host has. A release build cannot be diverted, so
/// this cannot become a way to make a shipped binary run something else.
#[cfg(debug_assertions)]
const TEST_OPEN_SETTING: &str = "AGENT_VM_TEST_OPEN";

/// The click directory's components below `$HOME`, walked one at a time.
const CACHE_DIR: &str = ".cache";
const APP_DIR: &str = "agent-vm";
const CLICK_DIR: &str = "notify-click";

/// One script's name: `click-<sid>-<8hex>.command`.
const SCRIPT_PREFIX: &str = "click-";
const SCRIPT_SUFFIX: &str = ".command";

/// How long a written script is kept. A banner can outlive its launcher (macOS
/// keeps Notification Center entries), so a script is not deleted on use; a day
/// is longer than a banner stays actionable and bounds the directory.
const SCRIPT_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// `0700` for the directory and for every script in it: nothing else on the host
/// may read or replace what macOS is about to execute. `RawMode` is `u16` on
/// macOS, so the constant is too; [`raw_mode`] widens it for comparison.
const SCRIPT_MODE: rfs::RawMode = 0o700;

/// Bounded retries for an unlucky random name, so a name collision can never
/// spin.
const SCRIPT_NAME_ATTEMPTS: u32 = 8;

/// Bytes of randomness in a script name: 8 hex digits.
const SCRIPT_NAME_RANDOM_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TerminalChoice {
    /// The `.command` file itself, which macOS opens in Terminal.app. The default
    /// because it needs no Apple-events permission.
    #[default]
    Terminal,
    Ghostty,
    WezTerm,
    Alacritty,
}

impl TerminalChoice {
    /// The choice `value` names; `None` when it names no supported terminal.
    ///
    /// Unset and empty both mean the default rather than an error: the setting is
    /// optional. Nothing else falls back — a typo is reported, because guessing
    /// would open a terminal the operator did not ask for.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "terminal" => Some(Self::Terminal),
            "ghostty" => Some(Self::Ghostty),
            "wezterm" => Some(Self::WezTerm),
            "alacritty" => Some(Self::Alacritty),
            _ => None,
        }
    }
}

/// The hidden `_notify-click` verb: what the notification helper spawns.
#[derive(ClapArgs, Debug)]
pub(crate) struct ClickArgs {
    #[arg(long)]
    pub(crate) session: String,
    /// Launcher's canonical project: the directory the script `cd`s into.
    #[arg(long)]
    pub(crate) project: PathBuf,
    /// Launcher's effective absolute state root (always passed; B8).
    #[arg(long)]
    pub(crate) state_dir: PathBuf,
    #[arg(long, default_value = "terminal")]
    pub(crate) terminal: String,
}

/// The validated inputs of one click. Constructing it is what turns three
/// strings into values the script writer may use as operands.
pub(crate) struct ClickPlan {
    pub(crate) session: SessionId,
    pub(crate) project: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) agent_vm_exe: PathBuf,
    pub(crate) terminal: TerminalChoice,
}

impl ClickPlan {
    fn from_args(args: ClickArgs) -> Result<Self> {
        let session = SessionId::parse(&args.session)
            .ok_or_else(|| anyhow!("a session ID is exactly 8 lowercase hex digits"))?;
        let terminal = TerminalChoice::parse(&args.terminal).ok_or_else(|| {
            anyhow!("{TERMINAL_SETTING} accepts terminal, ghostty, wezterm or alacritty")
        })?;
        Ok(Self {
            session,
            project: script_operand_path(&args.project, "--project")?,
            state_dir: script_operand_path(&args.state_dir, "--state-dir")?,
            agent_vm_exe: std::env::current_exe().context("locating this executable")?,
            terminal,
        })
    }
}

/// A path the script may quote as an operand: absolute, and valid UTF-8.
///
/// [`crate::shell::guest_script_word`] takes `str`, and a lossy conversion would
/// name a directory that does not exist, so a non-UTF-8 path is refused here
/// rather than mangled (R8).
fn script_operand_path(path: &Path, what: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{what} must be an absolute path");
    }
    operand(path, what)?;
    Ok(path.to_path_buf())
}

/// The `.command` file's contents (B7, B8).
///
/// Two renderings of the project coexist on purpose: the `cd` operand is the raw
/// path (quoted, so any byte is a valid word, and the project the operator named
/// is the one entered), while the fallback message is
/// [`crate::one_line::path`] (escaped, because a human and a terminal read it).
///
/// The `cd` diagnostic is discarded (`2>/dev/null`) for that reason: a failing
/// `cd` makes `/bin/sh` print the operand it was given, raw — ESC, newline and all
/// — which is the one path the escaped `printf` exists to keep off the terminal.
pub(crate) fn render_click_script(plan: &ClickPlan) -> Result<String> {
    let exe = plan
        .agent_vm_exe
        .to_str()
        .ok_or_else(|| anyhow!("this executable's path is not valid UTF-8"))?;
    let bin_dir = plan
        .agent_vm_exe
        .parent()
        .ok_or_else(|| anyhow!("this executable has no parent directory"))?
        .to_str()
        .ok_or_else(|| anyhow!("this executable's directory is not valid UTF-8"))?;
    let session = plan.session.as_str();
    let cd_word = shell::guest_script_word(operand(&plan.project, "--project")?);
    let state_word = shell::guest_script_word(operand(&plan.state_dir, "--state-dir")?);
    let bin_word = shell::guest_script_word(bin_dir);
    let exe_word = shell::guest_script_word(exe);
    let session_word = shell::guest_script_word(session);
    let project_diagnostic = shell::guest_script_word(&one_line::path(&plan.project).to_string());
    Ok(format!(
        concat!(
            "#!/bin/sh\n",
            "if cd {} 2>/dev/null; then\n",
            "  export {}={}\n",
            "  export PATH={}:\"$PATH\"\n",
            "  {} access --session {}\n",
            "else\n",
            "  printf 'agent-vm: project directory is no longer available: %s\\n' {} >&2\n",
            "fi\n",
            "printf '\\n'\n",
            "exec \"${{SHELL:-/bin/zsh}}\"\n",
        ),
        cd_word,
        crate::host_paths::AGENT_VM_STATE_DIR_ENV_NAME,
        state_word,
        bin_word,
        exe_word,
        session_word,
        project_diagnostic
    ))
}

/// The UTF-8 bytes of an operand path.
fn operand<'a>(path: &'a Path, what: &str) -> Result<&'a str> {
    path.to_str()
        .ok_or_else(|| anyhow!("{what} is not valid UTF-8: {}", one_line::path(path)))
}

/// The `/usr/bin/open` arguments that start one terminal on `script_path`.
///
/// `-n` opens a new instance instead of asking the running one to open a window:
/// Ghostty, WezTerm and Alacritty each restore saved state or linger otherwise,
/// which would leave the click with no visible window. Ghostty additionally needs
/// its two flags so a click does not resurrect the previous session's windows.
pub(crate) fn open_args(terminal: TerminalChoice, script_path: &Path) -> Vec<OsString> {
    let script = script_path.as_os_str().to_owned();
    let argv = |program: &str, extra: &[&str]| {
        let mut argv: Vec<OsString> = vec![
            OsString::from("-na"),
            OsString::from(program),
            OsString::from("--args"),
        ];
        argv.extend(extra.iter().map(OsString::from));
        argv.push(script.clone());
        argv
    };
    match terminal {
        // LaunchServices runs a `.command` file in Terminal.app; naming the
        // application stops a third-party handler registered for the type from
        // claiming it.
        TerminalChoice::Terminal => vec![OsString::from("-a"), OsString::from("Terminal"), script],
        TerminalChoice::Ghostty => argv(
            "Ghostty",
            &[
                "--window-save-state=never",
                "--quit-after-last-window-closed=true",
                "-e",
            ],
        ),
        TerminalChoice::WezTerm => argv("WezTerm", &["start", "--always-new-process", "--"]),
        TerminalChoice::Alacritty => argv("Alacritty", &["-e"]),
    }
}

/// Writes `script` as a fresh `0700` `click-<sid>-<8hex>.command` in
/// `$HOME/.cache/agent-vm/notify-click` and returns its path.
///
/// `home` is passed rather than read so a test never touches the real `~/.cache`.
/// `project` is the launcher's canonical project: a directory that resolves inside
/// it is refused, so a repository cannot hold the file macOS executes.
pub(crate) fn write_click_script(
    home: &Path,
    project: &Path,
    session: &SessionId,
    script: &str,
) -> Result<PathBuf> {
    let root = click_root(home);
    // Both checks come before anything is created, so a refused directory is not
    // even a pair of empty directories inside the project.
    refuse_inside_project(&root, project)?;
    let resolved_project = resolved(project).unwrap_or_else(|_| project.to_path_buf());
    refuse_inside_project(&resolved(home)?, &resolved_project)?;
    let dir = open_click_dir(home, &root)?;
    verify_click_dir(&dir, &root)?;
    prune_old_scripts(&dir)?;
    let name = create_script(&dir, session, script)?;
    Ok(root.join(name))
}

/// `$HOME/.cache/agent-vm/notify-click`. Constructed from `$HOME` alone: an
/// `XDG_CACHE_HOME` (or any other env) must not be able to move it.
fn click_root(home: &Path) -> PathBuf {
    home.join(CACHE_DIR).join(APP_DIR).join(CLICK_DIR)
}

/// A lexical refusal, the first of the two checks in [`write_click_script`].
///
/// The second compares the *resolved* `$HOME` against the resolved project,
/// because `$HOME` itself is opened following symlinks: a home that is a link
/// into the project has to be refused too, and before the walk creates anything.
fn refuse_inside_project(root: &Path, project: &Path) -> Result<()> {
    if root.starts_with(project) {
        bail!(
            "refusing to write a click script inside the project: {}",
            one_line::path(root)
        );
    }
    Ok(())
}

fn resolved(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .map_err(|error| anyhow!(error))
        .with_context(|| format!("resolving {}", one_line::path(path)))
}

/// Opens (creating as needed) the click directory, one component at a time.
///
/// `$HOME` is opened following symlinks (the host's own environment value, like
/// `host_paths::atomic_write`'s first parent); every component below it is opened
/// `O_NOFOLLOW`, so an existing symlink is an error instead of a redirection.
fn open_click_dir(home: &Path, root: &Path) -> Result<OwnedFd> {
    let mut dir = rfs::openat(
        rfs::CWD,
        home,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| anyhow!(error))
    .with_context(|| {
        format!(
            "opening $HOME to write the click script: {}",
            one_line::path(home)
        )
    })?;
    for name in [CACHE_DIR, APP_DIR, CLICK_DIR] {
        dir = open_or_create_child(&dir, name, root)?;
    }
    Ok(dir)
}

fn open_or_create_child(parent: &OwnedFd, name: &str, root: &Path) -> Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let open = |parent: &OwnedFd| {
        rfs::openat(parent, name, flags, Mode::empty())
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("opening {}", one_line::path(root)))
    };
    match rfs::openat(parent, name, flags, Mode::empty()) {
        Ok(dir) => Ok(dir),
        // A symlink (`ELOOP` under `O_NOFOLLOW`) or a non-directory is named as
        // the refusal it is; it is never resolved to find out what it points at.
        Err(error) if error == Errno::LOOP || error == Errno::NOTDIR => bail!(
            "refusing the click-script directory: {} is a symlink or not a directory",
            one_line::path(root)
        ),
        Err(Errno::NOENT) => {
            match rfs::mkdirat(parent, name, Mode::from_raw_mode(SCRIPT_MODE)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => {
                    return Err(anyhow!(error))
                        .with_context(|| format!("creating {}", one_line::path(root)));
                }
            }
            open(parent)
        }
        Err(error) => {
            Err(anyhow!(error)).with_context(|| format!("opening {}", one_line::path(root)))
        }
    }
}

/// The one rule the click directory must satisfy: this euid's own `0700`
/// directory. Pure, so the owner case — which a test cannot stage without root —
/// is still stated where the rule lives.
fn dir_refusal(uid: u32, mode: u32, euid: u32) -> Option<&'static str> {
    if uid != euid {
        return Some("it is owned by another user");
    }
    if mode & 0o7777 != raw_mode(SCRIPT_MODE) {
        return Some("its mode is not 0700");
    }
    None
}

fn verify_click_dir(dir: &OwnedFd, root: &Path) -> Result<()> {
    let stat = rfs::fstat(dir)
        .map_err(|error| anyhow!(error))
        .with_context(|| format!("measuring {}", one_line::path(root)))?;
    match dir_refusal(
        stat.st_uid,
        raw_mode(stat.st_mode),
        crate::host_paths::current_euid(),
    ) {
        Some(reason) => bail!(
            "refusing the click-script directory {}: {reason}",
            one_line::path(root)
        ),
        None => Ok(()),
    }
}

fn raw_mode(mode: rfs::RawMode) -> u32 {
    // RawMode is u16 on macOS, u32 on Linux.
    #[allow(clippy::useless_conversion)]
    u32::from(mode)
}

/// Removes `click-*.command` regular files older than [`SCRIPT_RETENTION`].
///
/// Stats never follow a symlink and only regular files are unlinked, so an entry
/// another process substituted cannot redirect the deletion. A missing entry
/// between the stat and the unlink is not an error; the goal was for it to be
/// gone.
fn prune_old_scripts(dir: &OwnedFd) -> Result<()> {
    let now = now_seconds()?;
    let mut entries = rfs::Dir::read_from(dir)
        .map_err(|error| anyhow!(error))
        .context("reading the click-script directory")?;
    for entry in &mut entries {
        let entry = entry
            .map_err(|error| anyhow!(error))
            .context("reading the click-script directory")?;
        let name = entry.file_name();
        if !is_script_name(name.to_bytes()) {
            continue;
        }
        let stat = match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue,
            Err(error) => return Err(anyhow!(error)).context("measuring a click script"),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            continue;
        }
        if !is_expired(mtime_seconds(&stat), now) {
            continue;
        }
        match rfs::unlinkat(dir, name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => return Err(anyhow!(error)).context("removing an old click script"),
        }
    }
    Ok(())
}

fn is_script_name(name: &[u8]) -> bool {
    name.len() > SCRIPT_PREFIX.len() + SCRIPT_SUFFIX.len()
        && name.starts_with(SCRIPT_PREFIX.as_bytes())
        && name.ends_with(SCRIPT_SUFFIX.as_bytes())
}

fn is_expired(modified_seconds: i64, now_seconds: u64) -> bool {
    (now_seconds as i64).saturating_sub(modified_seconds) > SCRIPT_RETENTION.as_secs() as i64
}

#[allow(clippy::unnecessary_cast)]
fn mtime_seconds(stat: &rfs::Stat) -> i64 {
    // `st_mtime` is `i64` on some targets and `c_long` on others.
    stat.st_mtime as i64
}

fn now_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("reading the host clock")?
        .as_secs())
}

/// Creates the script under a name that no click has used before.
///
/// The name is never reused, so a concurrent click cannot replace a script
/// another `open` is about to run; `O_EXCL` makes even a collision harmless.
/// A failed write removes the partial file: it is executable, so a half-written
/// script must not survive to be clicked.
fn create_script(dir: &OwnedFd, session: &SessionId, script: &str) -> Result<String> {
    create_script_named_by(dir, session, script, &random_hex)
}

/// [`create_script`] with the name's random suffix supplied by `suffix`.
///
/// The suffix is the only input that varies between two writes of the same
/// session, so it is the seam a test needs: without it no test could make two
/// writes collide, and removing `O_EXCL` would clobber an existing script
/// silently. Production always passes [`random_hex`].
fn create_script_named_by(
    dir: &OwnedFd,
    session: &SessionId,
    script: &str,
    suffix: &dyn Fn() -> String,
) -> Result<String> {
    for _ in 0..SCRIPT_NAME_ATTEMPTS {
        let name = format!(
            "{SCRIPT_PREFIX}{}-{}{SCRIPT_SUFFIX}",
            session.as_str(),
            suffix()
        );
        let fd = match rfs::openat(
            dir,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(SCRIPT_MODE),
        ) {
            Ok(fd) => fd,
            Err(Errno::EXIST) => continue,
            Err(error) => return Err(anyhow!(error)).context("creating the click script"),
        };
        // The mode is requested at creation and re-applied here because a
        // restrictive umask could mask it, and a script without the owner execute
        // bit cannot be run. No test stages that umask on purpose: the umask is
        // process-wide, so setting one would make the rest of the suite flaky.
        let written = rfs::fchmod(&fd, Mode::from_raw_mode(SCRIPT_MODE))
            .map_err(|error| anyhow!(error))
            .and_then(|()| {
                File::from(fd)
                    .write_all(script.as_bytes())
                    .map_err(|error| anyhow!(error))
            });
        if let Err(error) = written {
            let _ = rfs::unlinkat(dir, name.as_str(), AtFlags::empty());
            return Err(error).context("writing the click script");
        }
        return Ok(name);
    }
    bail!("could not find an unused click-script name")
}

fn random_hex() -> String {
    let mut bytes = [0u8; SCRIPT_NAME_RANDOM_BYTES];
    getrandom::fill(&mut bytes).expect("the kernel CSPRNG is available");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs one click: render, write, open. Host-only (R8).
pub(crate) fn run_click(args: ClickArgs) -> Result<i32> {
    let plan = ClickPlan::from_args(args)?;
    let script = render_click_script(&plan)?;
    let home = crate::config::absolute_home_from(std::env::var_os("HOME").as_deref())?
        .ok_or_else(|| anyhow!("$HOME is not set, so there is nowhere to write a click script"))?;
    let script_path = write_click_script(&home, &plan.project, &plan.session, &script)?;
    open_terminal(plan.terminal, &script_path)
}

/// The program to start: `/usr/bin/open`, unless a debug build named another one
/// in [`TEST_OPEN_SETTING`], or the host cannot open a terminal at all.
fn open_program() -> Result<OsString> {
    #[cfg(debug_assertions)]
    if let Some(program) = std::env::var_os(TEST_OPEN_SETTING) {
        return Ok(program);
    }
    #[cfg(target_os = "macos")]
    {
        Ok(OsString::from(OPEN_PROGRAM))
    }
    #[cfg(not(target_os = "macos"))]
    {
        bail!(
            "a notification click opens a host terminal, which only macOS has; \
             run `agent-vm access --session <ID>` instead"
        )
    }
}

/// Starts the terminal and returns the status the verb exits with.
///
/// A failure is never answered by starting a different terminal: the operator
/// chose one, and a silent substitution would hide that their choice did not
/// work. `open`'s own stderr is inherited so the reason is visible where the
/// click came from.
fn open_terminal(terminal: TerminalChoice, script_path: &Path) -> Result<i32> {
    let program = open_program()?;
    let status = std::process::Command::new(&program)
        .args(open_args(terminal, script_path))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| anyhow!(error))
        .with_context(|| {
            format!(
                "running {} to open the terminal",
                one_line::path(Path::new(&program))
            )
        })?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    const SID: &str = "3f9a12c4";

    fn session() -> SessionId {
        SessionId::parse(SID).expect("a valid session ID")
    }

    fn plan() -> ClickPlan {
        ClickPlan {
            session: session(),
            project: PathBuf::from("/Users/me/proj"),
            state_dir: PathBuf::from("/Users/me/.local/state/agent-vm"),
            agent_vm_exe: PathBuf::from("/Users/me/agent-vm/lib/../bin/agent-vm"),
            terminal: TerminalChoice::Ghostty,
        }
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    fn click_dir(home: &Path) -> PathBuf {
        home.join(".cache/agent-vm/notify-click")
    }

    /// The directory the writer must accept: `create_dir_all` honours the umask,
    /// which is not `0700` on every host.
    fn prepare_click_dir(home: &Path) -> PathBuf {
        let dir = click_dir(home);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    // -- the rendered script ------------------------------------------------

    /// The whole file, so the shape the plan pins — including the `else`
    /// fallback that keeps a vanished project readable — cannot drift.
    #[test]
    fn the_click_script_is_the_planned_shape() {
        let script = render_click_script(&plan()).unwrap();
        assert_eq!(
            script,
            concat!(
                "#!/bin/sh\n",
                "if cd '/Users/me/proj' 2>/dev/null; then\n",
                "  export AGENT_VM_STATE_DIR='/Users/me/.local/state/agent-vm'\n",
                "  export PATH='/Users/me/agent-vm/lib/../bin':\"$PATH\"\n",
                "  '/Users/me/agent-vm/lib/../bin/agent-vm' access --session '3f9a12c4'\n",
                "else\n",
                "  printf 'agent-vm: project directory is no longer available: %s\\n' ",
                "'/Users/me/proj' >&2\n",
                "fi\n",
                "printf '\\n'\n",
                "exec \"${SHELL:-/bin/zsh}\"\n",
            )
        );
    }

    #[test]
    fn a_project_with_a_control_byte_reaches_the_diagnostic_escaped_only() {
        // A project path can carry ESC and a newline; neither may reach the
        // terminal as itself, and both are legal in a `cd` operand.
        let project = PathBuf::from(format!("/tmp/{}/p\u{1b}[2Jq\n{}", "a".repeat(4096), "b"));
        let mut plan = plan();
        plan.project = project.clone();
        let script = render_click_script(&plan).unwrap();

        let raw = project.to_str().unwrap();
        assert!(
            script.contains(&format!(
                "if cd {} 2>/dev/null; then\n",
                shell::guest_script_word(raw)
            )),
            "the cd operand is the raw path as one quoted word"
        );
        let diagnostic = format!(
            "  printf 'agent-vm: project directory is no longer available: %s\\n' {} >&2",
            shell::guest_script_word(&one_line::path(&project).to_string())
        );
        assert!(script.contains(&diagnostic), "the fallback is escaped");
        assert!(
            !diagnostic.chars().any(char::is_control),
            "no control byte survives into the text a terminal prints"
        );
        assert!(diagnostic.len() < 4096 + 200, "and it stays one line");
    }

    /// The failure branch, executed by a real `/bin/sh`. A failing `cd` makes the
    /// shell print the operand it was given, so without `2>/dev/null` the raw
    /// path — ESC, newline and all — would reach the terminal before the escaped
    /// line that exists to replace it.
    #[test]
    fn a_missing_project_prints_only_the_escaped_diagnostic() {
        let home = tempfile::tempdir().unwrap();
        let missing = PathBuf::from(format!(
            "/nonexistent-agent-vm/{}/p\u{1b}[2Jq\nb",
            "a".repeat(200)
        ));
        let mut plan = plan();
        plan.project = missing.clone();
        let script = render_click_script(&plan).unwrap();
        let path = write_click_script(home.path(), &missing, &session(), &script).unwrap();

        let output = std::process::Command::new("/bin/sh")
            .arg(&path)
            // The script ends by exec'ing `$SHELL`; a test must not start an
            // interactive shell, and `/bin/sh` with a closed stdin exits.
            .env("SHELL", "/bin/sh")
            .output()
            .unwrap();

        assert!(output.status.success(), "{:?}", output.status);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr,
            format!(
                "agent-vm: project directory is no longer available: {}\n",
                one_line::path(&missing)
            )
        );
        assert!(
            !stderr.trim_end_matches('\n').chars().any(char::is_control),
            "nothing the shell would print verbatim reached stderr: {stderr:?}"
        );
        assert_eq!(output.stdout, b"\n", "the blank line before the shell");
    }

    #[test]
    fn a_non_utf8_project_is_refused_rather_than_mangled() {
        let mut plan = plan();
        plan.project = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xffproj"));
        let error = render_click_script(&plan).unwrap_err();
        assert!(
            format!("{error:#}").contains("not valid UTF-8"),
            "{error:#}"
        );
    }

    // -- the /usr/bin/open argv, one test per terminal ----------------------

    fn argv(terminal: TerminalChoice) -> Vec<String> {
        open_args(
            terminal,
            Path::new("/Users/me/.cache/agent-vm/click-a.command"),
        )
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn terminal_opens_a_command_file_in_terminal() {
        assert_eq!(
            argv(TerminalChoice::Terminal),
            [
                "-a",
                "Terminal",
                "/Users/me/.cache/agent-vm/click-a.command"
            ]
        );
    }

    #[test]
    fn ghostty_opens_the_script_in_a_new_instance() {
        assert_eq!(
            argv(TerminalChoice::Ghostty),
            [
                "-na",
                "Ghostty",
                "--args",
                "--window-save-state=never",
                "--quit-after-last-window-closed=true",
                "-e",
                "/Users/me/.cache/agent-vm/click-a.command"
            ]
        );
    }

    #[test]
    fn wezterm_opens_the_script_in_a_new_process() {
        assert_eq!(
            argv(TerminalChoice::WezTerm),
            [
                "-na",
                "WezTerm",
                "--args",
                "start",
                "--always-new-process",
                "--",
                "/Users/me/.cache/agent-vm/click-a.command"
            ]
        );
    }

    #[test]
    fn alacritty_opens_the_script_in_a_new_instance() {
        assert_eq!(
            argv(TerminalChoice::Alacritty),
            [
                "-na",
                "Alacritty",
                "--args",
                "-e",
                "/Users/me/.cache/agent-vm/click-a.command"
            ]
        );
    }

    #[test]
    fn the_terminal_setting_is_trimmed_and_case_insensitive() {
        assert_eq!(TerminalChoice::parse(""), Some(TerminalChoice::Terminal));
        assert_eq!(
            TerminalChoice::parse(" Terminal "),
            Some(TerminalChoice::Terminal)
        );
        assert_eq!(
            TerminalChoice::parse("Ghostty"),
            Some(TerminalChoice::Ghostty)
        );
        assert_eq!(
            TerminalChoice::parse("wezterm"),
            Some(TerminalChoice::WezTerm)
        );
        assert_eq!(
            TerminalChoice::parse("ALACRITTY"),
            Some(TerminalChoice::Alacritty)
        );
        assert_eq!(TerminalChoice::parse("iterm"), None);
    }

    // -- the anchored writer -----------------------------------------------

    /// A project root that does not contain the scratch home.
    ///
    /// `std::env::temp_dir()` would not do: on Linux it is `/tmp`, every
    /// `tempdir()` lives under it, and the inside-the-project refusal would fire
    /// on a home that is legitimately outside the project.
    fn outside_project() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_new_script_is_created_0700_under_home_with_a_fresh_name() {
        let home = tempfile::tempdir().unwrap();
        let first =
            write_click_script(home.path(), outside_project().path(), &session(), "one\n").unwrap();
        let second =
            write_click_script(home.path(), outside_project().path(), &session(), "two\n").unwrap();

        assert_eq!(first.parent().unwrap(), click_dir(home.path()));
        let name = first.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            is_script_name(name.as_bytes()),
            "{name} is not click-<sid>-<8hex>.command"
        );
        assert!(name.starts_with(&format!("click-{SID}-")), "{name}");
        assert_ne!(first, second, "a click never reuses a live script's name");
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "one\n");
        assert_eq!(mode_of(&first), 0o700);
        assert_eq!(mode_of(&second), 0o700);
        assert_eq!(mode_of(&click_dir(home.path())), 0o700);
        assert_eq!(mode_of(&home.path().join(".cache/agent-vm")), 0o700);
    }

    /// A colliding name is retried, never written over: the sentinel file a
    /// previous click wrote is still what `open` would run.
    #[test]
    fn a_name_collision_retries_to_a_free_name_and_keeps_the_old_script() {
        let home = tempfile::tempdir().unwrap();
        let dir_path = prepare_click_dir(home.path());
        let dir = open_click_dir(home.path(), &dir_path).unwrap();
        let taken = dir_path.join(format!("click-{SID}-deadbeef.command"));
        std::fs::write(&taken, "sentinel\n").unwrap();
        std::fs::set_permissions(&taken, std::fs::Permissions::from_mode(0o700)).unwrap();

        let names = ["deadbeef", "cafe0001"];
        let calls = std::cell::Cell::new(0usize);
        let suffix = || {
            let index = calls.get().min(names.len() - 1);
            calls.set(calls.get() + 1);
            names[index].to_owned()
        };

        let name = create_script_named_by(&dir, &session(), "new\n", &suffix).unwrap();

        assert_eq!(name, format!("click-{SID}-cafe0001.command"));
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "sentinel\n");
        assert_eq!(
            std::fs::read_to_string(dir_path.join(&name)).unwrap(),
            "new\n"
        );
    }

    /// Every attempt colliding is a failure, not an overwrite.
    #[test]
    fn a_collision_that_never_clears_fails_instead_of_overwriting() {
        let home = tempfile::tempdir().unwrap();
        let dir_path = prepare_click_dir(home.path());
        let dir = open_click_dir(home.path(), &dir_path).unwrap();
        let taken = dir_path.join(format!("click-{SID}-deadbeef.command"));
        std::fs::write(&taken, "sentinel\n").unwrap();

        let error = create_script_named_by(&dir, &session(), "new\n", &|| "deadbeef".to_owned())
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("unused click-script name"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "sentinel\n");
    }

    #[test]
    fn a_symlinked_cache_directory_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        symlink(elsewhere.path(), home.path().join(".cache")).unwrap();

        let error = write_click_script(home.path(), outside_project().path(), &session(), "x\n")
            .unwrap_err();
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
        assert!(
            std::fs::read_dir(elsewhere.path())
                .unwrap()
                .next()
                .is_none(),
            "nothing was written through the symlink"
        );
    }

    #[test]
    fn a_symlinked_notify_click_directory_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".cache/agent-vm")).unwrap();
        symlink(elsewhere.path(), click_dir(home.path())).unwrap();

        let error = write_click_script(home.path(), outside_project().path(), &session(), "x\n")
            .unwrap_err();
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
        assert!(
            std::fs::read_dir(elsewhere.path())
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn a_cache_directory_inside_the_project_is_refused() {
        let project = tempfile::tempdir().unwrap();
        let home = project.path().join("home");
        std::fs::create_dir(&home).unwrap();

        let error = write_click_script(&home, project.path(), &session(), "x\n").unwrap_err();
        assert!(
            format!("{error:#}").contains("inside the project"),
            "{error:#}"
        );
        assert!(
            !click_dir(&home).exists(),
            "the refusal happens before anything is created"
        );
    }

    /// `$HOME` itself is opened following symlinks, so a home that *is* a link
    /// into the project is caught by the resolved comparison rather than by the
    /// lexical one.
    #[test]
    fn a_symlinked_home_inside_the_project_is_refused() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let inside_the_project = project.path().join("home");
        std::fs::create_dir(&inside_the_project).unwrap();
        let home = outside.path().join("home");
        symlink(&inside_the_project, &home).unwrap();

        let error = write_click_script(&home, project.path(), &session(), "x\n").unwrap_err();
        assert!(
            format!("{error:#}").contains("inside the project"),
            "{error:#}"
        );
        assert!(!click_dir(&inside_the_project).exists());
    }

    /// The owner half of the same rule. A test cannot `chown`, so the pure rule is
    /// what states it; the mode half is staged for real below.
    #[test]
    fn only_this_euid_owns_the_directory_and_its_mode_is_0700() {
        assert_eq!(dir_refusal(501, 0o700, 501), None);
        assert_eq!(
            dir_refusal(0, 0o700, 501),
            Some("it is owned by another user")
        );
        assert_eq!(dir_refusal(501, 0o755, 501), Some("its mode is not 0700"));
        assert_eq!(dir_refusal(501, 0o2700, 501), Some("its mode is not 0700"));
    }

    #[test]
    fn a_click_directory_with_the_wrong_mode_is_refused() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(click_dir(home.path())).unwrap();
        std::fs::set_permissions(
            click_dir(home.path()),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let error = write_click_script(home.path(), outside_project().path(), &session(), "x\n")
            .unwrap_err();
        assert!(format!("{error:#}").contains("0700"), "{error:#}");
    }

    #[test]
    fn old_scripts_are_pruned_and_live_ones_are_kept() {
        let home = tempfile::tempdir().unwrap();
        let dir = prepare_click_dir(home.path());
        let stale = dir.join("click-3f9a12c4-0000000a.command");
        let fresh = dir.join("click-3f9a12c4-0000000b.command");
        let untouched = dir.join("notes.txt");
        for path in [&stale, &fresh, &untouched] {
            std::fs::write(path, "#!/bin/sh\n").unwrap();
        }
        set_mtime_seconds_ago(&stale, 25 * 60 * 60);
        set_mtime_seconds_ago(&fresh, 60 * 60);
        set_mtime_seconds_ago(&untouched, 25 * 60 * 60);

        write_click_script(home.path(), outside_project().path(), &session(), "x\n").unwrap();

        assert!(!stale.exists(), "a script older than 24 h is pruned");
        assert!(fresh.exists(), "a script younger than 24 h is kept");
        assert!(
            untouched.exists(),
            "only click-*.command entries are pruned"
        );
    }

    #[test]
    fn a_symlinked_script_entry_is_neither_pruned_nor_followed() {
        let home = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let dir = prepare_click_dir(home.path());
        let outside = target.path().join("victim.command");
        std::fs::write(&outside, "#!/bin/sh\n").unwrap();
        set_mtime_seconds_ago(&outside, 25 * 60 * 60);
        let link = dir.join("click-3f9a12c4-0000000c.command");
        symlink(&outside, &link).unwrap();

        write_click_script(home.path(), outside_project().path(), &session(), "x\n").unwrap();

        assert!(link.exists(), "the symlink itself is left alone");
        assert!(outside.exists(), "and its target is never unlinked");
    }

    #[test]
    fn the_retention_window_is_one_day() {
        let now = 1_000_000u64;
        assert!(!is_expired(now as i64, now));
        assert!(!is_expired(now as i64 - 23 * 60 * 60, now));
        assert!(is_expired(now as i64 - 25 * 60 * 60, now));
        assert!(is_expired(-1, now), "a pre-epoch mtime is old, not young");
    }

    // -- the verb ----------------------------------------------------------

    /// The whole verb, with `AGENT_VM_TEST_OPEN` standing in for LaunchServices:
    /// a temp `$HOME` is written to, and the program is run with exactly the argv
    /// [`open_args`] names.
    #[cfg(debug_assertions)]
    #[test]
    fn run_click_writes_the_script_and_runs_the_terminal_with_the_planned_argv() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        let project = outside_project();
        let record = home.path().join("argv.txt");
        let opener = home.path().join("opener.sh");
        std::fs::write(
            &opener,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
                record.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o700)).unwrap();
        env.set_var("HOME", home.path());
        env.set_var(TEST_OPEN_SETTING, &opener);

        let status = run_click(ClickArgs {
            session: SID.to_owned(),
            project: project.path().to_path_buf(),
            state_dir: PathBuf::from("/tmp/state"),
            terminal: "alacritty".to_owned(),
        })
        .unwrap();

        assert_eq!(status, 0);
        let script = only_script(home.path());
        let recorded = std::fs::read_to_string(&record).unwrap();
        let expected: Vec<String> = open_args(TerminalChoice::Alacritty, &script)
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(recorded.lines().collect::<Vec<_>>(), expected);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn run_click_reports_a_nonzero_status_instead_of_another_terminal() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        let project = outside_project();
        let opener = home.path().join("opener.sh");
        std::fs::write(&opener, "#!/bin/sh\nexit 3\n").unwrap();
        std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o700)).unwrap();
        env.set_var("HOME", home.path());
        env.set_var(TEST_OPEN_SETTING, &opener);

        let status = run_click(ClickArgs {
            session: SID.to_owned(),
            project: project.path().to_path_buf(),
            state_dir: PathBuf::from("/tmp/state"),
            terminal: "terminal".to_owned(),
        })
        .unwrap();

        assert_eq!(status, 3);
        assert!(
            only_script(home.path()).exists(),
            "the script is still written"
        );
    }

    #[test]
    fn run_click_refuses_a_bad_session_and_a_bad_terminal() {
        let mut env = crate::test_env::guard();
        let home = tempfile::tempdir().unwrap();
        let project = outside_project();
        env.set_var("HOME", home.path());

        let bad_session = run_click(ClickArgs {
            session: "not-a-session".to_owned(),
            project: project.path().to_path_buf(),
            state_dir: PathBuf::from("/tmp/state"),
            terminal: "terminal".to_owned(),
        })
        .unwrap_err();
        assert!(
            format!("{bad_session:#}").contains("8 lowercase hex"),
            "{bad_session:#}"
        );

        let bad_terminal = run_click(ClickArgs {
            session: SID.to_owned(),
            project: project.path().to_path_buf(),
            state_dir: PathBuf::from("/tmp/state"),
            terminal: "iterm".to_owned(),
        })
        .unwrap_err();
        assert!(
            format!("{bad_terminal:#}").contains(TERMINAL_SETTING),
            "{bad_terminal:#}"
        );

        let relative = run_click(ClickArgs {
            session: SID.to_owned(),
            project: PathBuf::from("proj"),
            state_dir: PathBuf::from("/tmp/state"),
            terminal: "terminal".to_owned(),
        })
        .unwrap_err();
        assert!(format!("{relative:#}").contains("absolute"), "{relative:#}");
    }

    #[cfg(debug_assertions)]
    fn only_script(home: &Path) -> PathBuf {
        let mut scripts: Vec<PathBuf> = std::fs::read_dir(click_dir(home))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| is_script_name(name.as_bytes()))
            })
            .collect();
        assert_eq!(scripts.len(), 1, "{scripts:?}");
        scripts.pop().unwrap()
    }

    fn set_mtime_seconds_ago(path: &Path, seconds: u64) {
        use std::ffi::CString;
        let now = now_seconds().unwrap();
        let when = libc::timeval {
            tv_sec: (now - seconds) as libc::time_t,
            tv_usec: 0,
        };
        let times = [when, when];
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` outlives the call and `times` holds the two values
        // `utimes` reads.
        let result = unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
        assert_eq!(result, 0, "setting the mtime of {path:?}");
    }
}
