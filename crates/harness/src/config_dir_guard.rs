use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

use clap::Args;
use sha2::{Digest, Sha256};

#[derive(Debug, Args)]
pub struct ConfigDirGuardArgs {
    /// Print the number of hard links to PATH.
    #[arg(long, value_name = "PATH", conflicts_with = "self_test")]
    hard_link_count: Option<PathBuf>,

    /// Print the project hash for PATH.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["hard_link_count", "self_test"])]
    project_hash: Option<PathBuf>,

    /// Print the UTF-8 byte and Unicode scalar-value lengths of STATE.
    #[arg(long, value_name = "STATE", conflicts_with_all = ["hard_link_count", "project_hash", "self_test"])]
    lengths: Option<String>,

    /// Run the boot-free configuration-directory guard controls.
    #[arg(long, conflicts_with_all = ["hard_link_count", "project_hash", "lengths"])]
    self_test: bool,

    /// Repository root used by --self-test.
    #[arg(long, value_name = "PATH", requires = "self_test")]
    repo_root: Option<PathBuf>,
}

pub fn run(args: ConfigDirGuardArgs) -> Result<String, String> {
    match (
        args.hard_link_count,
        args.project_hash,
        args.lengths,
        args.self_test,
    ) {
        (Some(path), None, None, false) => hard_link_count(&path).map(|count| count.to_string()),
        (None, Some(path), None, false) => project_hash(&path),
        (None, None, Some(state), false) => Ok(state_lengths(&state)),
        (None, None, None, true) => {
            let repo_root = args
                .repo_root
                .ok_or("--self-test requires --repo-root PATH")?;
            run_self_test(&repo_root)?;
            Ok("config-dir guard tests passed".to_owned())
        }
        _ => Err(
            "choose --hard-link-count PATH, --project-hash PATH, --lengths STATE, or --self-test --repo-root PATH"
                .to_owned(),
        ),
    }
}

// GNU and BSD stat use incompatible format flags for st_nlink, so the portable
// shell control delegates this filesystem query to the harness.
fn hard_link_count(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.nlink())
        .map_err(|error| format!("cannot stat {}: {error}", path.display()))
}

// Shell's `wc -m` and `${#value}` follow the caller's locale; the former
// Python `len()` check instead counted Unicode code points. Keep that invariant
// in Rust so the control behaves identically under C and UTF-8 locales.
fn state_lengths(state: &str) -> String {
    format!("{} {}", state.len(), state.chars().count())
}

fn project_hash(path: &Path) -> Result<String, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize {}: {error}", path.display()))?;
    let digest = Sha256::digest(canonical.as_os_str().as_bytes());
    Ok(digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn run_self_test(repo_root: &Path) -> Result<(), String> {
    let source_path = repo_root.join("script/test/ci-contracts.sh");
    let source = fs::read_to_string(&source_path)
        .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
    let run_list = source
        .split_once("# --- Shell guard rail")
        .map(|(run_list, _)| run_list)
        .ok_or("ci-contracts.sh has no shell guard rail section")?;
    if !run_list.contains("bash \"$REPO_ROOT/script/test/config-dir-guard-contract.sh\"") {
        return Err("ci-contracts.sh does not invoke the host controls".to_owned());
    }

    let files = [
        "script/test/lib/config-dir-guard.sh",
        "script/test/config-dir-guard-live.sh",
        "script/test/config-dir-guard-contract.sh",
        "script/test/fixtures/config-dir-guard/guest-n1a.sh",
        "script/test/fixtures/config-dir-guard/guest-n1b.sh",
        "script/test/fixtures/config-dir-guard/guest-n3.sh",
        "script/test/fixtures/config-dir-guard/guest-n4.sh",
        "script/test/fixtures/config-dir-guard/guest-n5.sh",
        "script/test/fixtures/config-dir-guard/guest-n7.sh",
    ];
    for (array, label) in [
        ("syntax_check", "bash -n"),
        ("shellcheck_files", "shellcheck"),
    ] {
        for script in files {
            let mutated = remove_guard_list_entry(&source, array, script)?;
            let output = run_mutated_guard(&mutated)?;
            if output.status.code() != Some(1) {
                return Err(format!(
                    "removing {script} from {array} exited {}; expected 1\nstdout: {}\nstderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                ));
            }
            let expected = format!("({script}) is missing from the {label} guard list");
            if !String::from_utf8_lossy(&output.stderr).contains(&expected) {
                return Err(format!(
                    "removing {script} from {array} failed without {expected:?}\nstderr: {}",
                    String::from_utf8_lossy(&output.stderr),
                ));
            }
            println!("host-only removal mutation PASS: {array}: {script}");
        }
    }
    Ok(())
}

fn remove_guard_list_entry(source: &str, array: &str, script: &str) -> Result<String, String> {
    let start = source
        .find(&format!("{array}=("))
        .ok_or_else(|| format!("ci-contracts.sh has no {array} list"))?;
    let end = source[start..]
        .find("\n)")
        .map(|offset| start + offset + 1)
        .ok_or_else(|| format!("ci-contracts.sh has an unterminated {array} list"))?;
    let entry = format!("    {script}\n");
    let list = &source[start..end];
    if list.matches(&entry).count() != 1 {
        return Err(format!("{array} does not list {script} exactly once"));
    }
    Ok(format!(
        "{}{}{}",
        &source[..start],
        list.replacen(&entry, "", 1),
        &source[end..]
    ))
}

fn run_mutated_guard(source: &str) -> Result<Output, String> {
    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);
    let temporary = std::env::temp_dir().join(format!(
        "cfg-guard-mutation-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let script_parent = temporary.join("script/test");
    let script = script_parent.join("ci-contracts.sh");
    fs::create_dir_all(&script_parent)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    fs::write(&script, source)
        .map_err(|error| format!("cannot write {}: {error}", script.display()))?;

    let result = run_with_timeout(&script);
    fs::remove_dir_all(&temporary)
        .map_err(|error| format!("cannot remove {}: {error}", temporary.display()))?;
    result
}

fn run_with_timeout(script: &Path) -> Result<Output, String> {
    let mut child = Command::new("bash")
        .arg(script)
        .arg("--guard-only")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run {}: {error}", script.display()))?;
    let start = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("cannot wait for {}: {error}", script.display()))?
            .is_some()
        {
            return child
                .wait_with_output()
                .map_err(|error| format!("cannot read {} output: {error}", script.display()));
        }
        if start.elapsed() >= Duration::from_secs(10) {
            child
                .kill()
                .map_err(|error| format!("cannot stop timed-out {}: {error}", script.display()))?;
            let _ = child.wait();
            return Err(format!("{} timed out after 10 seconds", script.display()));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_hard_links() {
        let temporary =
            std::env::temp_dir().join(format!("config-dir-guard-links-{}", std::process::id()));
        fs::create_dir_all(&temporary).expect("create temporary directory");
        let original = temporary.join("original");
        let linked = temporary.join("linked");
        fs::write(&original, "fixture").expect("write fixture");
        fs::hard_link(&original, &linked).expect("create hard link");
        assert_eq!(hard_link_count(&original).expect("count hard links"), 2);
        fs::remove_dir_all(&temporary).expect("remove temporary directory");
    }

    #[test]
    fn counts_utf8_bytes_and_unicode_scalar_values() {
        assert_eq!(state_lengths("/é"), "3 2");
    }

    #[test]
    fn hashes_the_canonical_path() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let hash = project_hash(&path).expect("hash project path");
        assert_eq!(hash.len(), 12);
        assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn removes_one_list_entry() {
        let source = "syntax_check=(\n    one\n)\nshellcheck_files=(\n    one\n)\n";
        assert_eq!(
            remove_guard_list_entry(source, "syntax_check", "one").expect("remove entry"),
            "syntax_check=(\n)\nshellcheck_files=(\n    one\n)\n"
        );
    }
}
