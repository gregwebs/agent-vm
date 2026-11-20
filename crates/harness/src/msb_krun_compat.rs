use std::{
    ffi::OsString,
    fs::{self, File},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

use clap::Args;

#[derive(Debug, Args)]
pub struct MsbKrunCompatArgs {
    /// Run boot-free timeout controls.
    #[arg(long)]
    self_test: bool,

    /// Seconds before the compatibility boot is stopped.
    #[arg(long, value_name = "SECONDS")]
    timeout_seconds: Option<u64>,

    /// File receiving the child standard output.
    #[arg(long, value_name = "PATH")]
    stdout: Option<PathBuf>,

    /// File receiving the child standard error.
    #[arg(long, value_name = "PATH")]
    stderr: Option<PathBuf>,

    /// The msb executable.
    #[arg(long, value_name = "PATH")]
    binary: Option<PathBuf>,

    /// Firmware passed to msb.
    #[arg(long, value_name = "PATH")]
    firmware: Option<PathBuf>,

    /// Isolated msb home directory.
    #[arg(long, value_name = "PATH")]
    home: Option<PathBuf>,

    /// Arguments passed to msb after `--`.
    #[arg(last = true)]
    command: Vec<OsString>,
}

struct TimeoutCommand {
    timeout: Duration,
    stdout: PathBuf,
    stderr: PathBuf,
    binary: PathBuf,
    firmware: PathBuf,
    home: PathBuf,
    command: Vec<OsString>,
}

enum TimeoutResult {
    Exited(i32),
    TimedOut,
}

pub fn run(args: MsbKrunCompatArgs) -> Result<String, String> {
    if args.self_test {
        return run_self_test();
    }
    let command = TimeoutCommand::try_from(args)?;
    match run_timeout(command)? {
        TimeoutResult::Exited(0) => Ok(String::new()),
        TimeoutResult::Exited(code) => std::process::exit(code),
        TimeoutResult::TimedOut => {
            eprintln!("compatibility boot timed out");
            std::process::exit(124);
        }
    }
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("missing --{name}"))
}

impl TryFrom<MsbKrunCompatArgs> for TimeoutCommand {
    type Error = String;

    fn try_from(args: MsbKrunCompatArgs) -> Result<Self, Self::Error> {
        let seconds = required(args.timeout_seconds, "timeout-seconds")?;
        if seconds == 0 {
            return Err("--timeout-seconds must be positive".to_owned());
        }
        if args.command.is_empty() {
            return Err("pass msb arguments after --".to_owned());
        }
        Ok(Self {
            timeout: Duration::from_secs(seconds),
            stdout: required(args.stdout, "stdout")?,
            stderr: required(args.stderr, "stderr")?,
            binary: required(args.binary, "binary")?,
            firmware: required(args.firmware, "firmware")?,
            home: required(args.home, "home")?,
            command: args.command,
        })
    }
}

fn run_timeout(command: TimeoutCommand) -> Result<TimeoutResult, String> {
    let stdout = File::create(&command.stdout)
        .map_err(|error| format!("cannot create {}: {error}", command.stdout.display()))?;
    let stderr = File::create(&command.stderr)
        .map_err(|error| format!("cannot create {}: {error}", command.stderr.display()))?;
    let mut child = Command::new(&command.binary)
        .args(&command.command)
        .env("MSB_HOME", &command.home)
        .env("MSB_LIBKRUNFW_PATH", &command.firmware)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("cannot run {}: {error}", command.binary.display()))?;
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot wait for {}: {error}", command.binary.display()))?
        {
            return Ok(TimeoutResult::Exited(status.code().unwrap_or(1)));
        }
        if started.elapsed() >= command.timeout {
            child
                .kill()
                .map_err(|error| format!("cannot stop {}: {error}", command.binary.display()))?;
            child.wait().map_err(|error| {
                format!(
                    "cannot wait for stopped {}: {error}",
                    command.binary.display()
                )
            })?;
            return Ok(TimeoutResult::TimedOut);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn run_self_test() -> Result<String, String> {
    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);
    let directory = std::env::temp_dir().join(format!(
        "msb-krun-compat-timeout-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
    let result = (|| {
        let output = directory.join("stdout");
        let stderr = directory.join("stderr");
        let completed = run_timeout(TimeoutCommand {
            timeout: Duration::from_secs(1),
            stdout: output.clone(),
            stderr: stderr.clone(),
            binary: PathBuf::from("/bin/sh"),
            firmware: PathBuf::from("firmware"),
            home: PathBuf::from("home"),
            command: vec![
                "-c".into(),
                "printf '%s|%s' \"$MSB_HOME\" \"$MSB_LIBKRUNFW_PATH\"; printf error >&2; exit 7"
                    .into(),
            ],
        })?;
        if !matches!(completed, TimeoutResult::Exited(7)) {
            return Err("completed control did not preserve the child exit status".to_owned());
        }
        if fs::read(&output)
            .map_err(|error| format!("cannot read {}: {error}", output.display()))?
            != b"home|firmware"
        {
            return Err("completed control did not preserve the msb environment".to_owned());
        }
        if fs::read(&stderr)
            .map_err(|error| format!("cannot read {}: {error}", stderr.display()))?
            != b"error"
        {
            return Err("completed control did not capture standard error".to_owned());
        }

        let timed_out = run_timeout(TimeoutCommand {
            timeout: Duration::from_secs(1),
            stdout: directory.join("timed-out-stdout"),
            stderr: directory.join("timed-out-stderr"),
            binary: PathBuf::from("/bin/sh"),
            firmware: PathBuf::from("firmware"),
            home: PathBuf::from("home"),
            command: vec!["-c".into(), "exec sleep 2".into()],
        })?;
        if !matches!(timed_out, TimeoutResult::TimedOut) {
            return Err("timeout control did not stop the child".to_owned());
        }
        Ok(())
    })();
    fs::remove_dir_all(&directory)
        .map_err(|error| format!("cannot remove {}: {error}", directory.display()))?;
    result?;
    Ok("msb-krun compatibility timeout controls passed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_controls_pass() {
        run_self_test().expect("timeout controls pass");
    }
}
