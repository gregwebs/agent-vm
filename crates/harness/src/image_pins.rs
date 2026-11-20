use std::{fs, path::PathBuf};

use clap::Args;

const LIVE_SEED_ANCHOR: &str = "live_id=\"$(pins_project_id \"$live\")\"";
const LIVE_SEED_END_ANCHOR: &str =
    "if ! jq -e --arg p \"$live_id\" --arg r \"$tag\" --arg d \"$digest_a\" \\";
const EXPECTED_PULL: &str =
    "pins_avm_ambient \"$live\" \"$tag\" image pull >\"$WORK/pins-live-pin.out\" 2>&1 || {";

#[derive(Debug, Args)]
pub struct ImagePinsArgs {
    /// Check e2e.sh's live-seed dispatch.
    #[arg(long, value_name = "PATH", conflicts_with = "self_test")]
    e2e: Option<PathBuf>,

    /// Run the boot-free image-pins controls.
    #[arg(long)]
    self_test: bool,
}

pub fn run(args: ImagePinsArgs) -> Result<String, String> {
    if args.self_test {
        self_test()?;
        return Ok("image pins controls passed".to_owned());
    }
    let e2e = args.e2e.ok_or("choose --e2e PATH or --self-test")?;
    let source = fs::read_to_string(&e2e)
        .map_err(|error| format!("FAIL: cannot read {}: {error}", e2e.display()))?;
    check_live_seed_dispatch(&source).map_err(|error| format!("FAIL: {error}"))
}

fn check_live_seed_dispatch(source: &str) -> Result<String, String> {
    let lines = source.lines().collect::<Vec<_>>();
    let starts = matching_lines(&lines, LIVE_SEED_ANCHOR);
    if starts.len() != 1 {
        return Err(format!(
            "expected exactly one live-seed anchor, found {}",
            starts.len()
        ));
    }
    let start = starts[0];
    let end_limit = (start + 13).min(lines.len());
    let ends = (start + 1..end_limit)
        .filter(|&index| lines[index].trim() == LIVE_SEED_END_ANCHOR)
        .collect::<Vec<_>>();
    if ends.len() != 1 {
        return Err(format!(
            "expected exactly one jq anchor within 12 lines, found {}",
            ends.len()
        ));
    }
    let end = ends[0];
    let calls = (start + 1..end)
        .filter(|&index| lines[index].contains("image pull"))
        .collect::<Vec<_>>();
    if calls.len() != 1 {
        let found = calls
            .iter()
            .map(|&index| format!("({}, {:?})", index, lines[index].trim()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "expected exactly one live-seed pull call, found [{found}]"
        ));
    }
    if lines[calls[0]].trim() != EXPECTED_PULL {
        return Err(format!(
            "the live-seed dispatch must be the ambient helper form {EXPECTED_PULL:?}, found {:?}",
            lines[calls[0]].trim()
        ));
    }
    if !(calls[0] + 1..end).any(|index| lines[index].trim() == "}") {
        return Err(
            "the live-seed failure block has no closing brace before the jq check".to_owned(),
        );
    }
    Ok("live-seed dispatch uses the ambient helper".to_owned())
}

fn matching_lines(lines: &[&str], expected: &str) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == expected).then_some(index))
        .collect()
}

fn self_test() -> Result<(), String> {
    let source = live_seed_fixture(EXPECTED_PULL, "}");
    check_live_seed_dispatch(&source)?;

    for (label, source, expected) in [
        (
            "missing live-seed anchor",
            source.replacen(LIVE_SEED_ANCHOR, "live_id=missing", 1),
            "expected exactly one live-seed anchor, found 0",
        ),
        (
            "duplicate live-seed anchor",
            format!("{LIVE_SEED_ANCHOR}\n{source}"),
            "expected exactly one live-seed anchor, found 2",
        ),
        (
            "missing jq anchor",
            source.replacen(LIVE_SEED_END_ANCHOR, "if false", 1),
            "expected exactly one jq anchor within 12 lines, found 0",
        ),
        (
            "duplicate jq anchor",
            source.replacen(
                LIVE_SEED_END_ANCHOR,
                &format!("{LIVE_SEED_END_ANCHOR}\n{LIVE_SEED_END_ANCHOR}"),
                1,
            ),
            "expected exactly one jq anchor within 12 lines, found 2",
        ),
        (
            "missing pull",
            live_seed_fixture("no pull", "}"),
            "expected exactly one live-seed pull call, found []",
        ),
        (
            "wrong helper",
            live_seed_fixture("pins_avm \"$live\" image pull", "}"),
            "the live-seed dispatch must be the ambient helper form",
        ),
        (
            "missing failure close",
            live_seed_fixture(EXPECTED_PULL, "echo no-close"),
            "the live-seed failure block has no closing brace before the jq check",
        ),
    ] {
        let error = check_live_seed_dispatch(&source)
            .err()
            .ok_or_else(|| format!("{label} mutation was accepted"))?;
        if !error.contains(expected) {
            return Err(format!(
                "{label} mutation failed without {expected:?}: {error}"
            ));
        }
    }
    let two_pulls = live_seed_fixture(EXPECTED_PULL, "}").replacen(
        "\n}\n",
        "\npins_avm_ambient \"$live\" \"$tag\" image pull\n}\n",
        1,
    );
    let error = check_live_seed_dispatch(&two_pulls)
        .err()
        .ok_or("duplicate pull mutation was accepted")?;
    if !error.contains("expected exactly one live-seed pull call, found") {
        return Err(format!(
            "duplicate pull mutation failed unexpectedly: {error}"
        ));
    }
    Ok(())
}

fn live_seed_fixture(pull: &str, close: &str) -> String {
    format!(
        "{LIVE_SEED_ANCHOR}\n\
         one\n\
         two\n\
         {pull}\n\
         {close}\n\
         {LIVE_SEED_END_ANCHOR}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_seed_mutation_controls_hold() {
        self_test().expect("image-pins controls pass");
    }
}
