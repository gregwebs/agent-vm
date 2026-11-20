use std::{fs, path::PathBuf};

use clap::Args;

#[derive(Debug, Args)]
pub struct BuildProvenanceArgs {
    /// Run the boot-free build-provenance controls.
    #[arg(long, conflicts_with = "evidence")]
    self_test: bool,

    /// The version report, expected full revision, and tracked-status report.
    #[arg(value_names = ["VERSION_FILE", "EXPECTED_FULL_SHA", "TRACKED_STATUS_FILE"])]
    evidence: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Clean,
    Dirty,
    Unknown,
}

#[derive(Debug, Eq, PartialEq)]
struct ReportedBuild {
    revision: Option<String>,
    state: State,
}

pub fn run(args: BuildProvenanceArgs) -> Result<String, String> {
    if args.self_test {
        self_test()?;
        return Ok("build-provenance controls passed".to_owned());
    }
    if args.evidence.len() != 3 {
        return Err(concat!(
            "usage: build-provenance.",
            "py VERSION_FILE EXPECTED_FULL_SHA TRACKED_STATUS_FILE"
        )
        .to_owned());
    }
    let version_path = PathBuf::from(&args.evidence[0]);
    let status_path = PathBuf::from(&args.evidence[2]);
    let version = read_evidence(&version_path)?;
    let status = read_evidence(&status_path)?;
    let build = parse_version(&version).map_err(|reason| format!("provenance: {reason}"))?;
    assert_committed_build(&build, &args.evidence[1], &status)
        .map_err(|reason| format!("provenance: {reason}"))?;
    Ok("provenance: clean binary matches source HEAD".to_owned())
}

fn read_evidence(path: &PathBuf) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "provenance: cannot read evidence ({})",
            match error.kind() {
                std::io::ErrorKind::NotFound => "FileNotFoundError",
                std::io::ErrorKind::PermissionDenied => "PermissionError",
                std::io::ErrorKind::IsADirectory => "IsADirectoryError",
                _ => "OSError",
            }
        )
    })?;
    String::from_utf8(bytes)
        .map_err(|_| "provenance: cannot read evidence (UnicodeDecodeError)".to_owned())
}

fn parse_version(text: &str) -> Result<ReportedBuild, &'static str> {
    let Some(body) = text.strip_suffix('\n') else {
        return Err("not one agent-vm version line");
    };
    if body.contains('\n') || body.contains('\r') {
        return Err("not one agent-vm version line");
    }
    let Some((release, parenthesized)) = body
        .strip_prefix("agent-vm ")
        .and_then(|line| line.split_once(" ("))
    else {
        return Err("not one agent-vm version line");
    };
    if release.is_empty() || release.chars().any(char::is_whitespace) {
        return Err("not one agent-vm version line");
    }
    let Some(parenthesized) = parenthesized.strip_suffix(')') else {
        return Err("not one agent-vm version line");
    };
    let (revision, label) = match parenthesized.split_once(", ") {
        Some((revision, label)) => (revision, Some(label)),
        None => (parenthesized, None),
    };
    let valid_revision = revision == "unknown"
        || ((revision.len() == 40 || revision.len() == 64)
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    if !valid_revision || label.is_some_and(|label| label != "dirty" && label != "state unknown") {
        return Err("not one agent-vm version line");
    }
    let state = match (revision, label) {
        ("unknown", Some("dirty")) => State::Dirty,
        ("unknown", _) => State::Unknown,
        (_, None) => State::Clean,
        (_, Some("dirty")) => State::Dirty,
        (_, Some("state unknown")) => State::Unknown,
        _ => return Err("not one agent-vm version line"),
    };
    Ok(ReportedBuild {
        revision: (revision != "unknown").then(|| revision.to_owned()),
        state,
    })
}

fn assert_committed_build(
    build: &ReportedBuild,
    expected_sha: &str,
    tracked_status: &str,
) -> Result<(), &'static str> {
    let revision = build
        .revision
        .as_deref()
        .ok_or("the binary does not name a commit")?;
    if revision != expected_sha.trim().to_ascii_lowercase() {
        return Err("the binary commit does not match source HEAD");
    }
    if build.state != State::Clean {
        return Err(match build.state {
            State::Dirty => "the binary reports state dirty",
            State::Unknown => "the binary reports state unknown",
            State::Clean => unreachable!(),
        });
    }
    if !tracked_status.is_empty() {
        return Err("the tracked source tree is dirty");
    }
    Ok(())
}

fn accepts(text: &str, expected: &str, status: &str) -> bool {
    parse_version(text)
        .and_then(|build| assert_committed_build(&build, expected, status))
        .is_ok()
}

fn self_test() -> Result<(), String> {
    let sha_a = "a".repeat(40);
    let sha_b = "b".repeat(40);
    if !accepts(&format!("agent-vm 0.3.4 ({sha_a})\n"), &sha_a, "") {
        return Err("P1 positive clean full SHA control failed".to_owned());
    }
    println!("build-provenance mutation PASS: P1 accepts a clean exact full SHA");

    let full64 = format!("abcdef1{}", "0".repeat(57));
    let other64 = format!("{}1", &full64[..63]);
    if !accepts(&format!("agent-vm 0.3.4 ({full64})\n"), &full64, "")
        || accepts(&format!("agent-vm 0.3.4 ({full64})\n"), &other64, "")
        || accepts(&format!("agent-vm 0.3.4 ({sha_a})\n"), &sha_b, "")
    {
        return Err("P2 full revision equality control failed".to_owned());
    }
    println!("build-provenance mutation PASS: P2 rejects a mismatched 40/64-hex revision");

    let rejected = [
        (format!("agent-vm 0.3.4 ({sha_a}, dirty)\n"), ""),
        (format!("agent-vm 0.3.4 ({sha_a})\n"), " M x\n"),
        (format!("agent-vm 0.3.4 ({sha_a}, state unknown)\n"), ""),
        ("agent-vm 0.3.4 (unknown)\n".to_owned(), ""),
        ("agent-vm 0.3.3\n".to_owned(), ""),
        (format!("agent-vm 0.3.4 ({sha_a})"), ""),
        (format!("agent-vm 0.3.4 ({sha_a})\n\n"), ""),
        (format!("agent-vm 0.3.4 ({})\n", &sha_a[..7]), ""),
        (format!("agent-vm 0.3.4 ({sha_a}) trailing\n"), ""),
    ];
    if rejected
        .iter()
        .any(|(text, status)| accepts(text, &sha_a, status))
    {
        return Err("P3/P4 refusal control accepted a malformed or dirty report".to_owned());
    }
    println!(
        "build-provenance mutation PASS: P3/P4 reject dirty, unknown, abbreviated, and malformed reports"
    );

    if !accepts(&format!("agent-vm 0.3.4 ({sha_a})\n"), &sha_a, "") {
        return Err("P5 untracked-only control failed".to_owned());
    }
    println!("build-provenance mutation PASS: P5 permits an empty tracked-status receipt");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_hold() {
        self_test().expect("build provenance controls pass");
    }

    #[test]
    fn only_lowercase_full_ids_parse() {
        let sha = "a".repeat(40);
        assert!(parse_version(&format!("agent-vm 1 ({sha})\n")).is_ok());
        assert!(parse_version(&format!("agent-vm 1 ({})\n", sha.to_uppercase())).is_err());
        assert!(parse_version("agent-vm 1 (unknown, dirty)\n").is_ok());
    }
}
