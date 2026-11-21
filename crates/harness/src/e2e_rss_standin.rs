//! The streaming-stand-in process the RSS sensitivity control measures (#700,
//! from #399 R2-1).
//!
//! `harness-negative`'s h18 control proves the launcher-RSS criterion is
//! **sensitive**: a stand-in that keeps a whole stream live must be rejected and
//! a stand-in that streams must be accepted, both through the same sampler,
//! parser and limit the `large` row uses. The stand-in therefore has to be a real
//! process with a stable identity — the control samples `ps -o rss=,comm=` and
//! rejects any sample whose comm changed — which is why this is a subcommand and
//! not an inline heredoc that `exec`s an interpreter:
//!
//! * `buffer` reads the whole input into memory and holds it there, so the
//!   criterion must see ~256 MiB of growth;
//! * `stream` reads 1 MiB at a time and drops each chunk, so the criterion must
//!   see no growth at all.
//!
//! Both report the byte count on stderr, which is what a real transfer leaves
//! behind; nothing goes to stdout, which the rows reserve for guest bytes.

use std::{
    io::{Read, Write},
    thread,
    time::Duration,
};

use clap::Args;

/// The window between process start and the first read. The sampler starts
/// asynchronously, so a stand-in that read immediately could finish inside one
/// 50 ms sample interval.
const SETTLE: Duration = Duration::from_millis(300);
/// How long `buffer` keeps the input live after reading it. The sampler must get
/// several samples while the memory is held, not just one.
const HOLD: Duration = Duration::from_secs(3);
/// The pause between streamed chunks: a real transfer takes real time, and a
/// stand-in that finished in microseconds would give the sampler nothing.
const TICK: Duration = Duration::from_millis(10);
/// One streamed chunk. 1 MiB is the launcher's own relay size, so the stand-in's
/// footprint looks like the launcher's rather than like a copy of its input.
const CHUNK: usize = 1_048_576;

#[derive(Debug, Args)]
pub struct E2eRssStandinArgs {
    /// `buffer` holds the whole input; `stream` drops each chunk.
    #[arg(long, value_name = "MODE", required_unless_present = "self_test")]
    mode: Option<String>,

    /// Bytes to read before holding (`buffer`); informational for `stream`, which
    /// ends at EOF just as the real transfer does.
    #[arg(long, value_name = "BYTES", required_unless_present = "self_test")]
    bytes: Option<u64>,

    /// Run the boot-free controls for the stand-in's counting.
    #[arg(long)]
    self_test: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandinMode {
    Buffer,
    Stream,
}

impl StandinMode {
    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "buffer" => Ok(Self::Buffer),
            "stream" => Ok(Self::Stream),
            other => Err(format!("usage: unknown RSS stand-in mode {other:?}")),
        }
    }
}

pub fn run(args: E2eRssStandinArgs) -> Result<crate::Outcome, String> {
    if args.self_test {
        self_test()?;
        return Ok(crate::Outcome::Report(
            "e2e rss-standin controls passed".to_owned(),
        ));
    }
    let mode = StandinMode::parse(args.mode.as_deref().ok_or("--mode MODE is required")?)?;
    let bytes = args.bytes.ok_or("--bytes BYTES is required")?;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut report = std::io::stderr();
    transfer(
        mode,
        bytes,
        &mut input,
        &mut report,
        Timing {
            settle: SETTLE,
            hold: HOLD,
            tick: TICK,
        },
    )
    .map_err(|error| format!("FAIL: the RSS stand-in could not run: {error}"))?;
    Ok(crate::Outcome::Exit(0))
}

/// The timings, injectable so the controls do not spend 3.3 s each.
#[derive(Clone, Copy)]
struct Timing {
    settle: Duration,
    hold: Duration,
    tick: Duration,
}

fn transfer(
    mode: StandinMode,
    limit: u64,
    input: &mut impl Read,
    report: &mut impl Write,
    timing: Timing,
) -> std::io::Result<usize> {
    thread::sleep(timing.settle);
    let (label, count) = match mode {
        StandinMode::Buffer => {
            let mut buffer = Vec::new();
            input.take(limit).read_to_end(&mut buffer)?;
            thread::sleep(timing.hold);
            ("buffered", buffer.len())
        }
        StandinMode::Stream => {
            let mut total = 0;
            let mut chunk = vec![0_u8; CHUNK];
            loop {
                let read = input.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                total += read;
                thread::sleep(timing.tick);
            }
            ("streamed", total)
        }
    };
    writeln!(report, "{label}={count}")?;
    report.flush()?;
    Ok(count)
}

fn self_test() -> Result<(), String> {
    let instant = Timing {
        settle: Duration::ZERO,
        hold: Duration::ZERO,
        tick: Duration::ZERO,
    };
    let mut report = Vec::new();
    let count = transfer(
        StandinMode::Buffer,
        CHUNK as u64,
        &mut &vec![0_u8; CHUNK][..],
        &mut report,
        instant,
    )
    .map_err(|error| format!("the buffer stand-in failed: {error}"))?;
    if count != CHUNK || report != b"buffered=1048576\n" {
        return Err(format!(
            "the buffer stand-in reported {count} bytes as {:?}",
            String::from_utf8_lossy(&report)
        ));
    }

    // A short input is not a failure: the limit bounds the read, EOF ends it, and
    // the count is what actually arrived.
    let mut report = Vec::new();
    let count = transfer(
        StandinMode::Buffer,
        CHUNK as u64,
        &mut &b"0123456789"[..],
        &mut report,
        instant,
    )
    .map_err(|error| format!("the truncated buffer stand-in failed: {error}"))?;
    if count != 10 || report != b"buffered=10\n" {
        return Err(format!("a truncated buffer was reported as {count}"));
    }

    // Streaming ends at EOF and sums every chunk, including a partial last one.
    let input = vec![7_u8; CHUNK + 5];
    let mut report = Vec::new();
    let count = transfer(
        StandinMode::Stream,
        0,
        &mut input.as_slice(),
        &mut report,
        instant,
    )
    .map_err(|error| format!("the stream stand-in failed: {error}"))?;
    if count != CHUNK + 5 || report != b"streamed=1048581\n" {
        return Err(format!(
            "the stream stand-in reported {count} bytes as {:?}",
            String::from_utf8_lossy(&report)
        ));
    }

    if StandinMode::parse("buffered").is_ok() {
        return Err("an unknown stand-in mode was accepted".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rss_standin_controls_hold() {
        self_test().expect("e2e rss-standin controls pass");
    }
}
