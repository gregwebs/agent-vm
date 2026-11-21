//! `e2e.sh`'s literal-argv oracle (#700).
//!
//! The direct-launch rows hand the launcher a deliberately hostile argv (an empty
//! argument, spaces, quotes, Unicode, shell metacharacters, a literal `$HOME`,
//! `--help`, a later `--`, duplicates, an embedded newline) and assert the guest
//! received those *bytes* in that order. The expected vector lives here, not in
//! the shell that builds the launch argv: an oracle written from the same list
//! the launcher is given grades the launcher against itself.
//!
//! The vector is spelled out below and compared byte for byte, so a launcher that
//! re-splits, unquotes, drops an empty argument or reorders one fails on the exact
//! byte that differs.

use std::{fs, path::PathBuf};

use clap::Args;

/// The argv the direct-launch rows send: 13 arguments, one of them empty.
pub const EXPECTED_ARGUMENTS: [&str; 13] = [
    "",
    "a b",
    "q'\"uote",
    "日本語",
    "$HOME",
    "*",
    ";",
    "|",
    "--help",
    "--",
    "x",
    "x",
    "line\nbreak",
];

/// The guest's completion sentinel, which follows the argv dump.
pub const SENTINEL: &str = "direct-probe-398=ok\n";

#[derive(Debug, Args)]
pub struct E2eDirectArgvArgs {
    /// The captured guest stdout to compare with the exact argv bytes.
    #[arg(long, value_name = "PATH", conflicts_with = "self_test")]
    capture: Option<PathBuf>,

    /// Run the boot-free controls for the argv oracle.
    #[arg(long)]
    self_test: bool,
}

pub fn run(args: E2eDirectArgvArgs) -> Result<String, String> {
    if args.self_test {
        self_test()?;
        return Ok("e2e direct-argv controls passed".to_owned());
    }
    let capture = args.capture.ok_or("choose --capture PATH or --self-test")?;
    let actual = fs::read(&capture)
        .map_err(|error| format!("cannot read {}: {error}", capture.display()))?;
    check_argv_bytes(&actual)
}

/// The exact bytes a successful launch must produce: the count, then each
/// argument followed by a NUL, then the sentinel.
pub fn expected_bytes() -> Vec<u8> {
    let mut expected = format!("argv-count={}\n", EXPECTED_ARGUMENTS.len()).into_bytes();
    for argument in EXPECTED_ARGUMENTS {
        expected.extend_from_slice(argument.as_bytes());
        expected.push(0);
    }
    expected.extend_from_slice(SENTINEL.as_bytes());
    expected
}

/// The verdict, with the first difference named: a byte-level "these differ" is
/// unactionable when every argument is whitespace-sensitive.
fn check_argv_bytes(actual: &[u8]) -> Result<String, String> {
    let expected = expected_bytes();
    if actual == expected {
        return Ok(format!(
            "argv: {} arguments byte-exact",
            EXPECTED_ARGUMENTS.len()
        ));
    }
    Err(format!(
        "FAIL: direct argv bytes differ from the exact expected vector ({})",
        describe_difference(&expected, actual)
    ))
}

fn describe_difference(expected: &[u8], actual: &[u8]) -> String {
    if let Some((offset, (want, got))) = expected
        .iter()
        .zip(actual)
        .enumerate()
        .find(|(_, (want, got))| want != got)
    {
        return format!(
            "at byte {offset}: expected 0x{want:02x}, got 0x{got:02x}; \
             expected {} bytes, got {}",
            expected.len(),
            actual.len()
        );
    }
    format!(
        "expected {} bytes, got {}; the shorter one ends at byte {}",
        expected.len(),
        actual.len(),
        expected.len().min(actual.len())
    )
}

fn self_test() -> Result<(), String> {
    let expected = expected_bytes();
    check_argv_bytes(&expected)
        .map_err(|error| format!("the exact vector was rejected: {error}"))?;

    let mut no_trailing_newline = expected.clone();
    no_trailing_newline.pop();
    let mut missing_empty_argument = expected.clone();
    missing_empty_argument.drain(.."argv-count=13\n".len() + 1);

    let mut swapped = expected.clone();
    let x = swapped.iter().position(|byte| *byte == b'x').unwrap_or(0);
    swapped[x] = b'y';

    for (label, mutated) in [
        ("a short capture", no_trailing_newline),
        ("a missing empty argument", missing_empty_argument),
        ("a changed argument byte", swapped),
    ] {
        let error = check_argv_bytes(&mutated)
            .err()
            .ok_or_else(|| format!("{label} was accepted"))?;
        if !error.starts_with("FAIL: direct argv bytes differ") {
            return Err(format!("{label} failed without the argv verdict: {error}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_argv_controls_hold() {
        self_test().expect("e2e direct-argv controls pass");
    }

    #[test]
    fn the_expected_vector_is_the_printed_one() {
        let expected = String::from_utf8(expected_bytes()).expect("UTF-8");
        assert!(expected.starts_with("argv-count=13\n"));
        assert!(expected.contains("日本語\0"));
        assert!(expected.ends_with(SENTINEL));
    }
}
