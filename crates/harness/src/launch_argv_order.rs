use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use clap::Args;

const LAUNCH_OPTIONS: &[&str] = &[
    "--memory",
    "--cpus",
    "--no-git",
    "--repo",
    "--allow-missing-credentials",
    "--mount",
    "--no-config-mounts",
    "--git-mount",
    "--publish",
    "--auto-publish",
    "--allow-egress",
    "--allow-internet-egress",
    "--allow-lan",
    "--allow-host",
    "--image",
    "--root",
];
const TOOL_VERBS: &[&str] = &[
    "shell", "dsh", "pi", "codex", "opencode", "claude", "copilot",
];

#[derive(Debug, Args)]
pub struct LaunchArgvOrderArgs {
    /// Run the boot-free launch-argument-order checks.
    #[arg(long)]
    self_test: bool,

    /// Repository root used by --self-test.
    #[arg(long, value_name = "PATH", requires = "self_test")]
    repo_root: Option<PathBuf>,
}

pub fn run(args: LaunchArgvOrderArgs) -> Result<String, String> {
    if !args.self_test {
        return Err("choose --self-test --repo-root PATH".to_owned());
    }
    let repo_root = args
        .repo_root
        .ok_or("--self-test requires --repo-root PATH")?;
    run_self_test(&repo_root)?;
    Ok(
        "launch-argv-order: OK (no old-order caller; create() puts --memory before shell)"
            .to_owned(),
    )
}

// Known blind spots: a verb held in a shell/Python variable cannot be seen by
// this literal-token sweep, and a launch option on a backslash-continued shell
// line is missed. The doc sweep deliberately excludes docs/adr/ (historical
// records) and counter-example lines that show the wrong form.
fn run_self_test(repo_root: &Path) -> Result<(), String> {
    check_line_matching_controls()?;
    sweep_tracked_callers(repo_root)?;
    check_measure_variants_create_argv(repo_root)?;
    run_mutation_controls(repo_root)
}

fn is_tool_boundary(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'.' | b'-')
}

fn is_launch_boundary(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && byte != b'-'
}

fn matching_positions<'a>(
    line: &str,
    candidates: &'a [&'a str],
    boundary: fn(u8) -> bool,
) -> Vec<(usize, &'a str)> {
    let bytes = line.as_bytes();
    let mut matches = Vec::new();
    for &candidate in candidates {
        if candidate.len() > bytes.len() {
            continue;
        }
        for start in 0..=bytes.len() - candidate.len() {
            let end = start + candidate.len();
            if &bytes[start..end] == candidate.as_bytes()
                && (start == 0 || boundary(bytes[start - 1]))
                && (end == bytes.len() || boundary(bytes[end]))
            {
                matches.push((start, candidate));
            }
        }
    }
    matches
}

fn shell_line_hits(line: &str) -> Vec<String> {
    let tools = matching_positions(line, TOOL_VERBS, is_tool_boundary);
    let launch_options = matching_positions(line, LAUNCH_OPTIONS, is_launch_boundary);
    tools
        .iter()
        .flat_map(|(tool_start, tool)| {
            launch_options
                .iter()
                .filter(move |(launch_start, _)| launch_start > tool_start)
                .map(move |(_, launch)| format!("`{tool} … {launch}`"))
        })
        .collect()
}

fn check_line_matching_controls() -> Result<(), String> {
    let accepted = [
        "(cd \"$tmp/project\" && run env GIT_CEILING_DIRECTORIES=\"$tmp\" \"$binary\" --no-git --image localhost:1/does-not-exist:latest --mount \"$home/.config\" shell) >\"$tmp/out\" 2>\"$tmp/err\" || status=$?",
        "agent-vm run probe --mount /guest --root",
        "agent-vm --memory 4 run probe --mount /9",
        "agent-vm --no-config-mounts shell",
        "agent-vm --no-config-mounts run probe",
        "agent-vm --git-mount=rw shell",
        "agent-vm --git-mount ro run probe",
    ];
    for line in accepted {
        let hits = shell_line_hits(line);
        if !hits.is_empty() {
            return Err(format!("control line wrongly flagged {hits:?}: {line}"));
        }
    }

    for line in [
        "agent-vm shell --memory 4",
        "agent-vm claude --root",
        "agent-vm shell --no-config-mounts",
        "agent-vm shell --git-mount=rw",
    ] {
        if shell_line_hits(line).is_empty() {
            return Err(format!("control line missed the old order: {line}"));
        }
    }
    Ok(())
}

fn tracked_files(repo_root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("ls-files")
        .output()
        .map_err(|error| format!("cannot list tracked files: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cannot list tracked files: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "tracked file list is not UTF-8".to_owned())
        .map(|files| files.lines().map(str::to_owned).collect())
}

fn sweep_tracked_callers(repo_root: &Path) -> Result<(), String> {
    let mut hits = Vec::new();
    for path in tracked_files(repo_root)? {
        if path.ends_with(".sh") {
            let source = read_source(repo_root, &path)?;
            collect_shell_hits(&path, &source, &mut hits);
        } else if path.ends_with(".md") && !path.starts_with("docs/adr/") {
            let source = read_source(repo_root, &path)?;
            collect_doc_hits(&path, &source, &mut hits);
        }
    }
    if hits.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "old launch-option order found (launch options go BEFORE the verb):\n  {}",
            hits.join("\n  ")
        ))
    }
}

fn read_source(repo_root: &Path, path: &str) -> Result<String, String> {
    fs::read_to_string(repo_root.join(path)).map_err(|error| format!("cannot read {path}: {error}"))
}

fn collect_shell_hits(path: &str, source: &str, hits: &mut Vec<String>) {
    for (line_number, line) in source.lines().enumerate() {
        for hit in shell_line_hits(line) {
            hits.push(format!("{}:{}: {hit}", path, line_number + 1));
        }
    }
}

fn collect_doc_hits(path: &str, source: &str, hits: &mut Vec<String>) {
    for (line_number, line) in source.lines().enumerate() {
        for (start, rendered) in doc_line_hits(line) {
            let preceding = line[..start]
                .chars()
                .rev()
                .take(6)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>();
            if preceding.to_lowercase().contains("not") {
                continue;
            }
            hits.push(format!("{}:{}: `{rendered}`", path, line_number + 1));
        }
    }
}

fn doc_line_hits(line: &str) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    let bytes = line.as_bytes();
    let mut search_from = 0;
    while let Some(offset) = line[search_from..].find("agent-vm") {
        let start = search_from + offset;
        search_from = start + "agent-vm".len();
        let mut at = search_from;
        if at == bytes.len() || !bytes[at].is_ascii_whitespace() {
            continue;
        }
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        loop {
            let token_start = at;
            while at < bytes.len() && !bytes[at].is_ascii_whitespace() && bytes[at] != b'`' {
                at += 1;
            }
            if token_start == at {
                break;
            }
            let token = &line[token_start..at];
            if TOOL_VERBS.contains(&token) {
                let mut launch_start = at;
                while launch_start < bytes.len() && bytes[launch_start].is_ascii_whitespace() {
                    launch_start += 1;
                }
                for launch in LAUNCH_OPTIONS {
                    let launch_end = launch_start + launch.len();
                    if launch_end <= bytes.len()
                        && &bytes[launch_start..launch_end] == launch.as_bytes()
                        && (launch_end == bytes.len() || is_launch_boundary(bytes[launch_end]))
                    {
                        hits.push((start, format!("agent-vm {token} {launch}")));
                    }
                }
                break;
            }
            if at == bytes.len() || bytes[at] == b'`' {
                break;
            }
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
        }
    }
    hits
}

fn create_body(source: &str) -> Result<&str, String> {
    let start = source
        .find("create() {")
        .ok_or("could not find create() in profiling/measure_variants.sh")?;
    let tail = &source[start..];
    let mut end = 0;
    for line in tail.split_inclusive('\n') {
        end += line.len();
        if line.trim_end().ends_with('}') {
            return Ok(&tail[..end]);
        }
    }
    Err("could not find the end of create() in profiling/measure_variants.sh".to_owned())
}

fn check_measure_variants_create_argv(repo_root: &Path) -> Result<(), String> {
    let source = read_source(repo_root, "profiling/measure_variants.sh")?;
    let body = create_body(&source)?;
    for memory in ["1", "4"] {
        check_create_argv(body, memory)?;
    }
    Ok(())
}

fn check_create_argv(body: &str, memory: &str) -> Result<(), String> {
    let got = run_create_body(body, memory)?;
    let expected = ["--memory", memory, "shell", "true"];
    if got.iter().map(String::as_str).eq(expected) {
        Ok(())
    } else {
        Err(format!(
            "create {memory} launched with argv {got:?}, expected {expected:?} (--memory must precede the shell verb)"
        ))
    }
}

fn run_create_body(body: &str, memory: &str) -> Result<Vec<String>, String> {
    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);
    let temporary = std::env::temp_dir().join(format!(
        "launch-argv-order-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    let stub = temporary.join("stub-agent-vm");
    let argv = temporary.join("argv");
    let result = (|| {
        fs::write(
            &stub,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGV_OUT\"\nprintf '[profile] create:  0.123s\\n'\n",
        )
        .map_err(|error| format!("cannot write {}: {error}", stub.display()))?;
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot make {} executable: {error}", stub.display()))?;
        let output = Command::new("bash")
            .arg("-c")
            .arg(format!("{body}\ncreate {memory} >/dev/null"))
            .env("AGENTVM", &stub)
            .env("ARGV_OUT", &argv)
            .output()
            .map_err(|error| format!("cannot run create {memory}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "create {memory} exited {}\nstdout: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        fs::read_to_string(&argv)
            .map_err(|error| format!("cannot read {}: {error}", argv.display()))
            .map(|output| output.lines().map(str::to_owned).collect())
    })();
    fs::remove_dir_all(&temporary)
        .map_err(|error| format!("cannot remove {}: {error}", temporary.display()))?;
    result
}

fn run_mutation_controls(repo_root: &Path) -> Result<(), String> {
    let source = read_source(repo_root, "profiling/measure_variants.sh")?;
    let old = "--memory \"$mem\" shell true";
    let mutated = source.replacen(old, "shell --memory \"$mem\" true", 1);
    if mutated == source {
        return Err("could not mutate create() into the old launch-option order".to_owned());
    }
    let mut hits = Vec::new();
    collect_shell_hits("profiling/measure_variants.sh", &mutated, &mut hits);
    if hits.is_empty() {
        return Err(
            "tracked-file sweep mutation did not find the old launch-option order".to_owned(),
        );
    }
    println!("tracked-file sweep mutation PASS: {}", hits[0]);

    let body = create_body(&mutated)?;
    if check_create_argv(body, "1").is_ok() {
        return Err("behavioural mutation did not reject --memory after shell".to_owned());
    }
    println!("behavioural mutation PASS: create 1 rejects --memory after shell");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_matching_controls_hold() {
        check_line_matching_controls().expect("line-matching controls pass");
    }

    #[test]
    fn doc_sweep_ignores_counter_examples_only() {
        let mut hits = Vec::new();
        collect_doc_hits("test.md", "not `agent-vm shell --memory 4`", &mut hits);
        assert!(hits.is_empty());
        collect_doc_hits("test.md", "write `agent-vm shell --memory 4`", &mut hits);
        assert_eq!(hits.len(), 1);
    }
}
