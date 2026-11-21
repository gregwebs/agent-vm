//! The config-mounts native rows (#394 / ADR-0046, #397 / ADR-0048) and the tool
//! (#396) and automatic Git-metadata (#535, ADR-0062) rows that ride the same
//! launches.
//!
//! Ported from `script/test/lib/config-mounts.py`, its last host Python. Every
//! row boots the digest-pinned image through the real candidate and reads what
//! the guest printed; boot-free fake-`msb` assertions are never counted here, and
//! the launch mechanics, ownership receipts and bounded teardown are the egress
//! fixtures' (#693), imported rather than copied. Only the rows are new.
//!
//! Four properties are load-bearing:
//!
//! * The receipt tells BLOCKED from FAIL from PASS. A row that could not run (an
//!   image without `git`) is recorded, counted apart from `passed`, and never
//!   dressed up as a pass.
//! * Host oracles are read only after a launch's cleanup proved the VM absent, and
//!   they compare two measurements rather than asserting a constant twice.
//! * Oracles are not produced by what they judge. The GM commit oracle reads the
//!   branch, the parent, the file and the object *from the host repository*;
//!   `harness config-mounts-controls` drives it over fake launches, because a row
//!   a fake launch can satisfy is exactly the row that cannot catch a faked
//!   commit.
//! * Every wait is the fixtures' bounded one. Nothing here waits on a socket, a
//!   thread or a child without a deadline.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command as Process,
    sync::atomic::{AtomicI32, Ordering},
};

use clap::Args;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    egress_cases as cases, egress_fixtures as fixtures, egress_launch as launch, egress_run,
};

/// The one launch option every row carries, so the whole suite proves
/// independence from the GitHub-credential flag.
const LAUNCH_OPTIONS: [&str; 1] = ["--no-git"];
/// The guest probes, copied into the owned project (and, for the GM rows, into
/// the fixture worktree) so the project bind carries them.
const PROBE: &str = "guest-cm-probe.sh";
const GM_PROBE: &str = "guest-gm-probe.sh";
/// A native row's own bound, and the grace its launcher gets after it.
const ROW_TIMEOUT: f64 = 300.0;
const ROW_GRACE: f64 = 10.0;
/// The guest path of the second, explicitly writable route GM-N4 compares to the
/// automatic read-only bind.
const GM_ALIAS: &str = "/gm-alt";
/// What a row records when the image has no `git` at all.
pub const BLOCKED_NOTE: &str = "BLOCKED: guest image has no git";
/// Every GM row, in order. `GM-N3` has no host oracle: "absent" is a guest-only
/// observation (the host path is there by definition), which the host-only
/// controls state rather than imitate.
pub const GM_ROWS: [&str; 7] = [
    "GM-N1",
    "GM-N1-host",
    "GM-N2",
    "GM-N2-host",
    "GM-N3",
    "GM-N4",
    "GM-N4-host",
];
/// `sockaddr_un.sun_path` is a 104-byte buffer on macOS (103 usable) and 108 on
/// Linux. The state-dir budget is checked before a launch, not after one fails.
const SUN_PATH_USABLE: usize = if cfg!(target_os = "macos") { 103 } else { 107 };

// --- The config documents ---------------------------------------------------

/// The named-mount-set document (#397). Declared only, it selects nothing; with
/// `mounts = ["all-set"]` prepended it selects the three leaves, and a repeated
/// reference inside `all-set` must change nothing.
const SETS_TABLE: &str = r#"[mount_sets]
all-set = ["ro-set", "rw-set", "fork-set", "ro-set"]
ro-set = ["~/cm/ro:/cm/ro:ro"]
rw-set = ["~/cm/rw:/cm/rw:rw"]
fork-set = ["~/cm/fork:/cm/fork:fork"]
"#;
const SETS_DEFAULT: &str = "mounts = [\"all-set\"]\n";
/// The three leaves, in the order the default config declares them.
const DEFAULTS_CONFIG: &str =
    "mounts = [\"~/cm/ro:/cm/ro:ro\", \"~/cm/rw:/cm/rw:rw\", \"~/cm/fork:/cm/fork:fork\"]\n";

/// The tool-mount topology (#396). Every synthetic tool executes `bash` with the
/// probe as its argument vector, so these rows test catalog *selection* — never
/// an image's installed Pi version or login state — and the probe itself is the
/// guest program.
const PROBE_ARGS: &str = "args = [\"./guest-cm-probe.sh\"]\n";
const AGENT_SET: &str = "[mount_sets]\nagent = [\"~/cm-tool/agent:/cm/tool/agent:rw\", \
     \"~/cm-tool/agent/skills:/cm/tool/agent/skills:ro\", \
     \"~/cm-tool/readonly:/cm/tool/readonly:ro\"]\n";
const TOOL_DEFAULT: &str = "mounts = [\"~/cm-tool/default:/cm/tool/default:ro\"]\n";
const SHELL_OWN: &str = "mounts = [\"~/cm-tool/shell-own:/cm/tool/shell-own:ro\"]\n";

fn tool(name: &str, tools: &str, mounts: Option<&str>) -> String {
    let mut body =
        format!("[[tools]]\nname = \"{name}\"\ncommand = \"bash\"\n{PROBE_ARGS}tools = {tools}\n");
    if let Some(mounts) = mounts {
        body.push_str(&format!("mounts = {mounts}\n"));
    }
    body
}

fn shell_tool(tools_line: &str, mounts_line: &str) -> String {
    format!(
        "[[tools]]\nname = \"shell\"\ncommand = \"bash\"\nargs = [\"-O\", \"histappend\"]\n\
         interactive_shell = true\n{tools_line}{mounts_line}"
    )
}

/// Pi's own list is the fork only: `agent` reaches a Pi launch *through* `tools`,
/// so a run that dropped the mount edges could not still produce CM-T3's agent
/// topology.
fn tools_base() -> String {
    [
        tool("pi", "[\"claude\", \"codex\"]", Some("[\"~/.pi:fork\"]")),
        tool("claude", "[]", Some("[\"agent\"]")),
        tool("codex", "[]", Some("[\"agent\"]")),
        tool("bridge", "[\"pi\"]", None),
        tool("plain", "[]", None),
    ]
    .concat()
}

/// T1-T5: a wildcard shell (its `tools` line is omitted on purpose, which is what
/// makes it deliberately broad — it inherits every same-tier tool's mounts).
fn tools_wildcard_shell() -> String {
    format!("{AGENT_SET}{}{}", tools_base(), shell_tool("", SHELL_OWN))
}

/// T6: the same shell with inheritance switched off, plus a user-wide default.
fn tools_empty_shell() -> String {
    format!(
        "{TOOL_DEFAULT}{AGENT_SET}{}{}",
        tools_base(),
        shell_tool("tools = []\n", SHELL_OWN)
    )
}

/// T7: no declared shell at all, so the built-in fallback runs.
fn tools_fallback_shell() -> String {
    format!("{TOOL_DEFAULT}{AGENT_SET}{}", tools_base())
}

/// T8-T10: a *wildcard* declared shell, so the opt-out has a non-empty inherited
/// facet to suppress on the shell route too.
fn tools_optout() -> String {
    tools_wildcard_shell()
}

/// A tool named exactly like the set `agent`. Its own leaf and its own `persist`
/// link are the independently observable provisioning facts that make "selecting
/// a set provisions no tool" discriminating.
const TOOLS_SAME_NAME_TOOL: &str = "[[tools]]\nname = \"agent\"\ncommand = \"bash\"\n\
     args = [\"./guest-cm-probe.sh\"]\ntools = []\npersist = [\"agent-tool-state\"]\n\
     mounts = [\"~/cm-tool/agent-tool:/cm/tool/agent-tool:ro\"]\n";

/// T11: the same Pi declaration reached as a top-level default and through a
/// nested set, so the *route* is the only difference between the two launches.
fn tools_default_fork() -> String {
    format!(
        "mounts = [\"~/.pi:fork\"]\n{}{}{}",
        tool("pi", "[\"claude\", \"codex\"]", None),
        tool("claude", "[]", None),
        tool("codex", "[]", None)
    )
}

fn tools_nested_set() -> String {
    format!(
        "[mount_sets]\nouter = [\"inner\"]\ninner = [\"~/.pi:fork\"]\n{}{}{}",
        tool("pi", "[\"claude\", \"codex\"]", Some("[\"outer\"]")),
        tool("claude", "[]", None),
        tool("codex", "[]", None)
    )
}

// --- Observations -----------------------------------------------------------

/// One recorded value. Rows compare whole guest lines, and the host oracles
/// compare small tables, so the receipt carries both without a JSON number
/// surprise: counts are counts, flags are flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observed {
    Text(String),
    Count(usize),
    Flag(bool),
    Table(BTreeMap<String, Observed>),
}

impl Observed {
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    pub fn count(value: usize) -> Self {
        Self::Count(value)
    }

    pub fn flag(value: bool) -> Self {
        Self::Flag(value)
    }

    pub fn table(pairs: impl IntoIterator<Item = (&'static str, Observed)>) -> Self {
        Self::pairs(
            pairs
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        )
    }

    /// A table whose keys are data rather than literals: a fork identity, a
    /// digest map, a read-only tree set.
    pub fn pairs(entries: Vec<(String, Observed)>) -> Self {
        Self::Table(entries.into_iter().collect())
    }

    /// The evidence rendering: a row's expected and actual columns, unquoted so
    /// the summary reads as the row does.
    pub fn render(&self) -> String {
        match self {
            Self::Text(value) => value.clone(),
            Self::Count(value) => value.to_string(),
            Self::Flag(value) => value.to_string(),
            Self::Table(pairs) => {
                let rendered: Vec<String> = pairs
                    .iter()
                    .map(|(name, value)| format!("{name}: {}", value.render()))
                    .collect();
                format!("{{{}}}", rendered.join(", "))
            }
        }
    }

    /// The human rendering: text quoted, so a trailing space or an empty line is
    /// visible in the failure the receipt prints.
    fn describe(&self) -> String {
        match self {
            Self::Text(value) => format!("{value:?}"),
            Self::Count(value) => value.to_string(),
            Self::Flag(value) => value.to_string(),
            Self::Table(pairs) => {
                let rendered: Vec<String> = pairs
                    .iter()
                    .map(|(name, value)| format!("{name}: {}", value.describe()))
                    .collect();
                format!("{{{}}}", rendered.join(", "))
            }
        }
    }
}

/// One row of the evidence receipt.
struct Entry {
    row: String,
    expected: Observed,
    actual: Observed,
    passed: bool,
    blocked: bool,
}

/// The evidence receipt: one line per assertion, and a status never inferred from
/// silence.
///
/// `BLOCKED` is the third status because a native row that could not run must
/// read as neither of the other two: `PASS` would be a claim nothing measured
/// (CONTRIBUTING.md: never a pass) and `FAIL` would report the product for a
/// missing thing in the image. A blocked row is therefore not counted in
/// `passed`, and `totals()` lists it apart from `failed`.
pub struct Receipt {
    summary: PathBuf,
    quiet: bool,
    entries: Vec<Entry>,
}

impl Receipt {
    pub fn new(summary: &Path, quiet: bool) -> Self {
        Self {
            summary: summary.to_path_buf(),
            quiet,
            entries: Vec::new(),
        }
    }

    /// Record one row. A row that does not match is an error *after* it is
    /// written to the summary, so the evidence always holds the failure.
    pub fn record(
        &mut self,
        row: &str,
        expected: Observed,
        actual: Observed,
    ) -> Result<(), String> {
        self.record_with(row, expected, actual, false)
    }

    /// Record a row that could not run. A result that arrives while the row is
    /// blocked is still blocked: the receipt may never be turned into a pass by
    /// what the row happened to say.
    pub fn blocked(&mut self, row: &str) -> Result<(), String> {
        self.record_with(
            row,
            Observed::text(BLOCKED_NOTE),
            Observed::text(BLOCKED_NOTE),
            true,
        )
    }

    pub fn record_with(
        &mut self,
        row: &str,
        expected: Observed,
        actual: Observed,
        blocked: bool,
    ) -> Result<(), String> {
        let passed = expected == actual && !blocked;
        let status = if blocked {
            "BLOCKED"
        } else if passed {
            "PASS"
        } else {
            "FAIL"
        };
        let line = format!(
            "{row}\t{}\t{}\t{status}\n",
            expected.render(),
            actual.render()
        );
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.summary)
            .map_err(|error| format!("{}: {error}", self.summary.display()))?;
        file.write_all(line.as_bytes())
            .map_err(|error| format!("{}: {error}", self.summary.display()))?;
        self.entries.push(Entry {
            row: row.to_owned(),
            expected,
            actual,
            passed,
            blocked,
        });
        if !self.quiet {
            let entry = self.entries.last().expect("the row just pushed");
            println!(
                "{status} {row}: expected {} actual {}",
                entry.expected.describe(),
                entry.actual.describe()
            );
        }
        if !passed && !blocked {
            let entry = self.entries.last().expect("the row just pushed");
            return Err(format!(
                "{row}: expected {}, got {}",
                entry.expected.describe(),
                entry.actual.describe()
            ));
        }
        Ok(())
    }

    /// `rows`, `passed`, `blocked` and `failed` as `totals.json` writes them.
    pub fn totals(&self) -> Value {
        let blocked: Vec<&str> = self
            .entries
            .iter()
            .filter(|entry| entry.blocked)
            .map(|entry| entry.row.as_str())
            .collect();
        let failed: Vec<&str> = self
            .entries
            .iter()
            .filter(|entry| !entry.passed && !entry.blocked)
            .map(|entry| entry.row.as_str())
            .collect();
        json!({
            "rows": self.entries.len(),
            "passed": self.entries.iter().filter(|entry| entry.passed).count(),
            "blocked": blocked,
            "failed": failed,
        })
    }
}

// --- Small observations -----------------------------------------------------

fn canonical(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    text.push('\n');
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One file's digest, streamed: a native cache may hold a whole disk image, and a
/// snapshot that reads it into memory is not an observation a host can afford.
fn digest_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut block = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut block)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&block[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Every path under `root`, without following a symlink out of it.
fn walk(root: &Path, prefix: &Path, out: &mut Vec<(PathBuf, PathBuf)>) -> Result<(), String> {
    let entries = fs::read_dir(root).map_err(|error| format!("{}: {error}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", root.display()))?;
        let path = entry.path();
        let relative = prefix.join(entry.file_name());
        out.push((relative.clone(), path.clone()));
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if metadata.is_dir() {
            walk(&path, &relative, out)?;
        }
    }
    Ok(())
}

/// Mode, size and content digest per path — the persisted-network shape the rows'
/// refusals and absences are read through.
fn snapshot_validation(work: &Path) -> Result<Value, String> {
    let mut snapshot = Map::new();
    for directory in ["home", "config", "state", "proj", "gm"] {
        let root = work.join(directory);
        if !root.is_dir() {
            continue;
        }
        let mut paths = Vec::new();
        walk(&root, Path::new(""), &mut paths)?;
        paths.sort();
        for (relative, path) in paths {
            if relative
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.ends_with("-shm") || name.ends_with("-wal") || name.ends_with("-journal")
                })
            {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let value = if metadata.file_type().is_symlink() {
                fs::read_link(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?
                    .to_string_lossy()
                    .into_owned()
            } else if metadata.is_file() {
                digest_file(&path)?
            } else {
                String::new()
            };
            snapshot.insert(
                format!("{directory}/{}", relative.to_string_lossy()),
                json!([metadata.mode(), metadata.len(), value]),
            );
        }
    }
    Ok(Value::Object(snapshot))
}

/// One digest over a directory's names and contents, for the read-only oracles.
pub fn tree_digest(path: &Path) -> Result<String, String> {
    let mut entries = Vec::new();
    walk(path, Path::new(""), &mut entries)?;
    entries.sort();
    let mut hasher = Sha256::new();
    for (relative, entry_path) in entries {
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        let metadata = fs::symlink_metadata(&entry_path)
            .map_err(|error| format!("{}: {error}", entry_path.display()))?;
        if metadata.file_type().is_symlink() {
            hasher.update(b"link\0");
            hasher.update(
                fs::read_link(&entry_path)
                    .map_err(|error| format!("{}: {error}", entry_path.display()))?
                    .to_string_lossy()
                    .as_bytes(),
            );
        } else if metadata.is_file() {
            hasher.update(
                fs::read(&entry_path)
                    .map_err(|error| format!("{}: {error}", entry_path.display()))?,
            );
        }
        hasher.update(b"\0");
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// A marker file's bytes, or `absent`. Never an exception in a row.
/// A name/digest map as one observed table.
fn text_pairs(entries: impl IntoIterator<Item = (String, String)>) -> Observed {
    Observed::pairs(
        entries
            .into_iter()
            .map(|(name, value)| (name, Observed::text(value)))
            .collect(),
    )
}

/// A marker file's bytes, or `absent`. Never an exception in a row.
fn marker(path: &Path) -> String {
    if path.is_file() {
        fs::read_to_string(path).unwrap_or_else(|_| "absent".to_owned())
    } else {
        "absent".to_owned()
    }
}

/// The one line a probe rendered for `prefix`, or `<missing>`.
pub fn guest_line(text: &str, prefix: &str) -> String {
    text.lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or("<missing>")
        .to_owned()
}

/// Every published fork's directory name and manifest digest, sorted.
///
/// Read after a launch's cleanup proved absence. The comparison is the point:
/// selecting a set, nesting it or renaming it must not create a second copy or
/// reseed this one, which would change both values.
fn fork_identity(work: &Path) -> Result<Vec<(String, String)>, String> {
    let mut identity = Vec::new();
    let state = work.join("state");
    let Ok(entries) = fs::read_dir(&state) else {
        return Ok(identity);
    };
    let mut manifests = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", state.display()))?;
        if !entry.file_name().to_string_lossy().ends_with(".mounts") {
            continue;
        }
        let forks_path = entry.path().join("forks");
        let Ok(forks) = fs::read_dir(&forks_path) else {
            continue;
        };
        for fork in forks {
            let fork = fork.map_err(|error| format!("{}: {error}", forks_path.display()))?;
            let manifest = fork.path().join("manifest.json");
            if manifest.is_file() {
                manifests.push(manifest);
            }
        }
    }
    manifests.sort();
    for manifest in manifests {
        let bytes =
            fs::read(&manifest).map_err(|error| format!("{}: {error}", manifest.display()))?;
        let name = manifest
            .parent()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        identity.push((name, digest_bytes(&bytes)));
    }
    Ok(identity)
}

/// The **Pi lineage's** fork identity: directory name and manifest digest.
///
/// Filtered by the declaration's guest destination rather than asserting the
/// whole run holds one fork: the #394/#397 rows publish their own `/cm/fork` fork
/// in the same state root, and rewriting those rows to make this one pass would
/// destroy their evidence. Within the Pi lineage there is exactly one.
fn pi_fork_identity(work: &Path) -> Result<Vec<(String, String)>, String> {
    let mut identity = Vec::new();
    let state = work.join("state");
    let Ok(entries) = fs::read_dir(&state) else {
        return Ok(identity);
    };
    let mut manifests = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", state.display()))?;
        if !entry.file_name().to_string_lossy().ends_with(".mounts") {
            continue;
        }
        let forks_path = entry.path().join("forks");
        let Ok(forks) = fs::read_dir(&forks_path) else {
            continue;
        };
        for fork in forks {
            let fork = fork.map_err(|error| format!("{}: {error}", forks_path.display()))?;
            let manifest = fork.path().join("manifest.json");
            if manifest.is_file() {
                manifests.push(manifest);
            }
        }
    }
    manifests.sort();
    for manifest in manifests {
        let bytes =
            fs::read(&manifest).map_err(|error| format!("{}: {error}", manifest.display()))?;
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{}: {error}", manifest.display()))?;
        if !document
            .get("guest")
            .and_then(Value::as_str)
            .is_some_and(|guest| guest.ends_with("/.pi"))
        {
            continue;
        }
        let name = manifest
            .parent()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        identity.push((name, digest_bytes(&bytes)));
    }
    Ok(identity)
}

/// The state-dir budget, checked before a launch rather than after one fails: the
/// runtime derives `<state>/msb-home/run/sandboxes/<24 hex>/control.sock`, and
/// `sockaddr_un.sun_path` is what it has to fit.
fn state_dir_fits(state: &Path) -> Result<(), String> {
    let socket = format!(
        "{}/msb-home/run/sandboxes/{}/control.sock",
        state.display(),
        "0".repeat(24)
    );
    let length = socket.len();
    if length > SUN_PATH_USABLE {
        return Err(format!(
            "state directory does not fit the control socket budget ({length} > {SUN_PATH_USABLE}): {}",
            state.display()
        ));
    }
    Ok(())
}

// --- The Git-metadata fixture (#535, ADR-0062) ------------------------------

/// Run `git` for the GM fixture with an environment built from scratch.
///
/// Never inherits `GIT_*`: a `GIT_DIR`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE` or
/// `GIT_CONFIG_COUNT`/`GIT_CONFIG_PARAMETERS` in the caller's environment would
/// redirect Git despite `-C` and change the `.git` shape every GM row is about.
/// Global and system config are pinned to `/dev/null` so a developer's
/// `worktree.useRelativePaths` cannot rewrite the pointer either.
pub fn gm_git(home: &Path, cwd: &Path, args: &[&str]) -> Result<String, String> {
    let output = Process::new("git")
        .env_clear()
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned()),
        )
        .env("HOME", home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|error| format!("git {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The GM rows' fixture: one real linked worktree and the paths the rows drive.
pub struct GmFixture {
    pub home: PathBuf,
    pub main: PathBuf,
    pub worktree: PathBuf,
    /// The common directory, canonical: the guest path the automatic bind must
    /// reproduce exactly.
    pub common: PathBuf,
    pub tracked: PathBuf,
}

/// Build the fixture. Everything happens before any baseline snapshot: the
/// repo-local identity, signing and hook policy are written with `git config`
/// *before* the first commit, so the fixture commits without whatever the host or
/// the image says.
pub fn build_gm_fixture(work: &Path, gm_probe: &Path) -> Result<GmFixture, String> {
    let home = work.join("home");
    let main = work.join("gm/main");
    let worktree = work.join("gm/wt");
    for directory in [&main, &worktree] {
        fs::create_dir_all(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
    }
    gm_git(&home, &main, &["init", "-q"])?;
    for (key, value) in [
        ("user.name", "gm"),
        ("user.email", "gm@example.invalid"),
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
        ("core.hooksPath", "/dev/null"),
    ] {
        gm_git(&home, &main, &["config", key, value])?;
    }
    fs::write(main.join("tracked.txt"), "seed\n")
        .map_err(|error| format!("{}: {error}", main.display()))?;
    gm_git(&home, &main, &["add", "tracked.txt"])?;
    gm_git(&home, &main, &["commit", "-q", "-m", "seed"])?;
    gm_git(
        &home,
        &main,
        &[
            "worktree",
            "add",
            "-q",
            &worktree.to_string_lossy(),
            "-b",
            "gm",
        ],
    )?;
    let probe = worktree.join(GM_PROBE);
    fs::copy(gm_probe, &probe).map_err(|error| format!("{}: {error}", probe.display()))?;
    Ok(GmFixture {
        home,
        main: main.clone(),
        worktree: worktree.clone(),
        common: canonical(&main.join(".git"))?,
        tracked: worktree.join("tracked.txt"),
    })
}

impl GmFixture {
    /// The fixture's `gm` branch object id, or `<absent>`.
    fn branch_oid(&self) -> String {
        self.rev_parse("gm")
            .unwrap_or_else(|| "<absent>".to_owned())
    }

    /// One revision as text, or `None` — never an exception in a row.
    fn rev_parse(&self, revision: &str) -> Option<String> {
        gm_git(&self.home, &self.main, &["rev-parse", revision])
            .ok()
            .map(|out| out.trim().to_owned())
    }

    /// `name` at `oid`, or `<absent>`.
    fn show(&self, oid: &str, name: &str) -> String {
        gm_git(&self.home, &self.main, &["show", &format!("{oid}:{name}")])
            .unwrap_or_else(|_| "<absent>".to_owned())
    }

    /// Whether the host repository can read `oid` — the "host sees the object"
    /// oracle.
    fn has_object(&self, oid: &str) -> bool {
        gm_git(&self.home, &self.main, &["cat-file", "-e", oid]).is_ok()
    }

    fn tree(&self) -> Result<String, String> {
        tree_digest(&self.common)
    }
}

/// The GM rows' host-side oracle: everything measured on the host repository
/// after a launch's cleanup proved the VM absent.
///
/// The launch seam is replaceable (the boot-free controls do that); the oracle is
/// not, because the oracle is the half a faked launch must not be able to
/// satisfy.
pub struct GmHost {
    pub fixture: GmFixture,
}

impl GmHost {
    pub fn common_path(&self) -> &Path {
        &self.fixture.common
    }

    pub fn common_tree(&self) -> Result<String, String> {
        self.fixture.tree()
    }

    pub fn branch(&self) -> String {
        self.fixture.branch_oid()
    }

    pub fn parent_of(&self, oid: &str) -> String {
        self.fixture
            .rev_parse(&format!("{oid}^"))
            .unwrap_or_else(|| "<absent>".to_owned())
    }

    pub fn file_at(&self, oid: &str, name: &str) -> String {
        self.fixture.show(oid, name)
    }

    pub fn has_object(&self, oid: &str) -> bool {
        self.fixture.has_object(oid)
    }

    pub fn probe(&self) -> String {
        marker(&self.fixture.common.join("objects/gm-probe"))
    }
}

/// The GM group's pre-launch measurement.
pub struct Baseline {
    pub common_tree: String,
    pub branch: String,
}

impl Baseline {
    pub fn measure(host: &GmHost) -> Result<Self, String> {
        Ok(Self {
            common_tree: host.common_tree()?,
            branch: host.branch(),
        })
    }
}

/// The GM group's launch half. The live driver implements it over the real
/// candidate; the boot-free controls implement it over canned guest output.
pub trait Seam {
    fn launch(
        &mut self,
        row: &str,
        phase: &str,
        flags: &[String],
        extra: &[String],
    ) -> Result<String, String>;

    fn cleanup(&mut self, row: &str) -> Result<(), String>;
}

/// What the GM group concluded.
#[derive(Debug, PartialEq, Eq)]
pub enum GmOutcome {
    /// The image has no `git`, so no GM row measured anything.
    Blocked,
    /// Every GM row ran.
    Measured,
}

/// The GM rows' control flow (#535), with every side effect injected.
///
/// `launch(row, phase, flags, extra)` returns what the guest printed,
/// `cleanup(row)` tears that launch down, and `host` is the real host oracle. The
/// launch half is injected so the boot-free controls can drive *this* dispatch: the
/// blocked-versus-measured branch and the commit oracle are where this group
/// regressed before, not the rows themselves.
pub fn run_gm_group(
    seam: &mut dyn Seam,
    host: &GmHost,
    receipt: &mut Receipt,
    baseline: &Baseline,
) -> Result<GmOutcome, String> {
    let text = seam.launch("GM-N1", "ro", &[], &[])?;
    let missing = text.contains("GM-MISSING");
    seam.cleanup("GM-N1")?;
    if missing {
        // No `git` in the image: no GM phase can say anything. Every row and its
        // host oracle is BLOCKED — recorded, counted apart from `passed`, and never
        // dressed up as a pass. The remaining launches are skipped because each
        // would measure the same absence.
        for row in GM_ROWS {
            receipt.blocked(row)?;
        }
        return Ok(GmOutcome::Blocked);
    }

    receipt.record(
        "GM-N1",
        Observed::text("GM-N1 log=seed diff=tracked.txt write=denied add=denied"),
        Observed::text(guest_line(&text, "GM-N1")),
    )?;
    if !text.contains("==> Git metadata: linked worktree, read-only") {
        return Err("GM-N1: the read-only notice did not print".to_owned());
    }
    receipt.record(
        "GM-N1-host",
        Observed::table([
            ("common-tree", Observed::text(baseline.common_tree.clone())),
            ("probe", Observed::text("absent")),
        ]),
        Observed::table([
            ("common-tree", Observed::text(host.common_tree()?)),
            ("probe", Observed::text(host.probe())),
        ]),
    )?;

    // GM-N2: `--git-mount=rw` lets the guest commit, and the host sees the ref,
    // the parent and the guest's edit.
    let text = seam.launch("GM-N2", "rw", &["--git-mount=rw".to_owned()], &[])?;
    let (expected, actual, oid) = gm_commit_row(&guest_line(&text, "GM-N2"));
    receipt.record("GM-N2", expected, actual)?;
    let Some(oid) = oid else {
        return Err(format!(
            "GM-N2: the guest did not commit: {}",
            guest_line(&text, "GM-N2")
        ));
    };
    seam.cleanup("GM-N2")?;
    let (expected, actual) = gm_n2_host_row(
        &oid,
        &baseline.branch,
        &[
            ("branch", host.branch()),
            ("parent", host.parent_of(&oid)),
            ("tracked", host.file_at(&oid, "tracked.txt")),
            (
                "object",
                if host.has_object(&oid) {
                    "present".to_owned()
                } else {
                    "absent".to_owned()
                },
            ),
        ],
    );
    receipt.record("GM-N2-host", expected, actual)?;

    // GM-N3: `--git-mount=off` binds nothing, so the host path is absent.
    let text = seam.launch("GM-N3", "off", &["--git-mount=off".to_owned()], &[])?;
    receipt.record(
        "GM-N3",
        Observed::text("GM-N3 absent"),
        Observed::text(guest_line(&text, "GM-N3")),
    )?;
    if text.contains("==> Git metadata:") {
        return Err("GM-N3: `off` printed a Git metadata notice".to_owned());
    }
    seam.cleanup("GM-N3")?;

    // GM-N4: in ONE launch the same relative write is denied through the automatic
    // read-only bind and allowed through an explicit `:rw` alias. Recorded as "ro
    // is not repository-wide protection", never as an enforcement failure.
    let text = seam.launch(
        "GM-N4",
        "control",
        &[],
        &[
            "--mount".to_owned(),
            format!("{}:{GM_ALIAS}:rw", host.common_path().display()),
        ],
    )?;
    receipt.record(
        "GM-N4",
        Observed::text("GM-N4 automatic=denied alias=allowed"),
        Observed::text(guest_line(&text, "GM-N4")),
    )?;
    seam.cleanup("GM-N4")?;
    receipt.record(
        "GM-N4-host",
        Observed::text("gm-probe\n"),
        Observed::text(host.probe()),
    )?;
    Ok(GmOutcome::Measured)
}

/// The GM-N2 row: the probe committed, so its line carries a full object id.
pub fn gm_commit_row(guest_line: &str) -> (Observed, Observed, Option<String>) {
    let expected = Observed::text("GM-N2 commit=<40-hex object id>");
    let rest = guest_line.strip_prefix("GM-N2 commit=");
    let oid = rest.filter(|rest| {
        rest.len() == 40
            && rest
                .chars()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
    });
    match oid {
        Some(oid) => (expected.clone(), expected, Some(oid.to_owned())),
        None => (expected, Observed::text(guest_line.to_owned()), None),
    }
}

/// The GM-N2-host oracle: the guest's commit is the branch tip, it **moved** the
/// branch off the baseline, it descends from the baseline, and it carries the
/// edit the guest made.
///
/// Comparing the branch with the object id the guest reported is not enough on its
/// own — that pair says nothing about the branch having moved, and nothing about
/// what the commit contains.
pub fn gm_n2_host_row(
    oid: &str,
    baseline: &str,
    observed: &[(&'static str, String)],
) -> (Observed, Observed) {
    let table = |pairs: Vec<(&'static str, Observed)>| Observed::table(pairs);
    let expected = table(vec![
        ("branch", Observed::text(oid)),
        ("moved", Observed::flag(true)),
        ("parent", Observed::text(baseline)),
        ("tracked", Observed::text("guest-commit")),
        ("object", Observed::text("present")),
    ]);
    let get = |name: &str| {
        observed
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    let branch = get("branch");
    let actual = table(vec![
        ("branch", Observed::text(branch.clone())),
        ("moved", Observed::flag(branch != baseline)),
        ("parent", Observed::text(get("parent"))),
        (
            "tracked",
            Observed::text(if get("tracked").contains("guest-commit") {
                "guest-commit"
            } else {
                "absent"
            }),
        ),
        ("object", Observed::text(get("object"))),
    ]);
    (expected, actual)
}

// --- Interruption -----------------------------------------------------------

/// The signal that interrupted the run, if any: a handler cannot unwind, so the
/// row loop asks between rows and the `finally` cleanup still runs.
static INTERRUPTED: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_interrupt(signal: libc::c_int) {
    INTERRUPTED.store(signal, Ordering::SeqCst);
}

fn install_signal_handlers() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the action is zeroed field by field below, its mask is emptied
        // with `sigemptyset`, and the handler only stores into an atomic.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_interrupt as *const () as libc::sighandler_t;
            action.sa_flags = 0;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                eprintln!(
                    "config mounts: cannot install the signal handler: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

fn interrupted() -> Result<(), String> {
    match INTERRUPTED.load(Ordering::SeqCst) {
        0 => Ok(()),
        signal => Err(format!("signal {signal}")),
    }
}

// --- The driver -------------------------------------------------------------

#[derive(Debug, Args)]
pub struct ConfigMountsArgs {
    /// The checkout whose `script/test/fixtures` the rows copy from.
    #[arg(long)]
    repo_root: PathBuf,

    /// ROOT EVIDENCE BINARY IMAGE MSB, in that order.
    #[arg(value_names = ["ROOT", "EVIDENCE", "BINARY", "IMAGE", "MSB"])]
    inputs: Vec<PathBuf>,
}

struct Driver {
    root: PathBuf,
    work: PathBuf,
    evidence: PathBuf,
    fixtures: PathBuf,
    binary: String,
    image: String,
    env: Vec<(String, String)>,
    launches: Vec<launch::OwnedLaunch>,
    errors: Vec<String>,
    home: PathBuf,
    config: PathBuf,
    project: PathBuf,
    rw_marker: PathBuf,
    fork_marker: PathBuf,
    ro_tree: String,
    tool: PathBuf,
    pi_source: PathBuf,
    tool_ro: BTreeMap<String, String>,
    protected: BTreeMap<String, String>,
}

impl Driver {
    fn new(
        root: PathBuf,
        evidence: PathBuf,
        fixtures: PathBuf,
        binary: String,
        image: String,
        msb: String,
    ) -> Self {
        let work = root.join("cm");
        let home = work.join("home");
        let mut env = fixtures_env(&work);
        env.push(("MSB_PATH".to_owned(), msb));
        Self {
            root,
            work: work.clone(),
            evidence,
            fixtures,
            binary,
            image,
            env,
            launches: Vec::new(),
            errors: Vec::new(),
            config: home.join(".config/agent-vm/config.toml"),
            project: work.join("proj"),
            rw_marker: home.join("cm/rw/marker"),
            fork_marker: home.join("cm/fork/marker"),
            ro_tree: String::new(),
            tool: home.join("cm-tool"),
            pi_source: home.join(".pi"),
            home,
            tool_ro: BTreeMap::new(),
            protected: BTreeMap::new(),
        }
    }

    /// Short-state setup, the shape `pn_fresh_state` gave these rows.
    ///
    /// `state/msb-home` is created here as well: the owned launch resolves its
    /// private root through `within`, which canonicalizes, so the directory has to
    /// exist before the first launch rather than after it.
    fn fresh_state(&self) -> Result<(), String> {
        for directory in [
            self.home.join(".config/agent-vm"),
            self.work.join("state/msb-home"),
            self.project.clone(),
        ] {
            fs::create_dir_all(&directory)
                .map_err(|error| format!("{}: {error}", directory.display()))?;
        }
        fs::set_permissions(
            self.home.join(".config/agent-vm"),
            fs::Permissions::from_mode(0o700),
        )
        .map_err(|error| format!("{}: {error}", self.home.display()))?;
        state_dir_fits(&self.work.join("state"))
    }

    /// One launch, its receipts and its log.
    fn run_row(
        &mut self,
        row: &str,
        argv: Vec<String>,
        tool_name: &str,
        cwd: Option<&Path>,
    ) -> Result<String, String> {
        interrupted()?;
        write_json(
            &self.evidence.join(format!("{row}-before.json")),
            &json!({
                "snapshot": snapshot_validation(&self.work)?,
                "fixtures": {
                    "ro": self.ro_tree,
                    "rw": marker(&self.rw_marker),
                    "fork": marker(&self.fork_marker),
                },
            }),
        )?;
        let command = cases::Command {
            case: row.to_owned(),
            variant: "native".to_owned(),
            tool: Some(tool_name.to_owned()),
            kind: "guest".to_owned(),
            env: self.env.clone(),
            argv,
            cwd: cwd.unwrap_or(&self.project).to_string_lossy().into_owned(),
            timeout: ROW_TIMEOUT,
            grace: ROW_GRACE,
            declared_extras: Vec::new(),
            prerequisites: Vec::new(),
            controls: None,
            setup: Vec::new(),
            expected_attempts: Vec::new(),
            attempt_expectations: None,
            attempt_protocols: None,
            supervisor: cases::SUPERVISOR.to_owned(),
        };
        self.launches.push(launch::OwnedLaunch::new(
            &self.work,
            &command,
            row.to_owned(),
        )?);
        let index = self.launches.len() - 1;
        write_json(
            &self.evidence.join(format!("{row}-command.json")),
            &command.plan(),
        )?;
        let status = self.launches[index].run()?;
        let text = fs::read(self.launches[index].log())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        let observed = self.launches[index].errors();
        if matches!(status, 124 | 130 | 143) || !observed.is_empty() {
            return Err(format!(
                "{row}: timeout/interrupt/observation error: {status} {observed:?}"
            ));
        }
        if status != 0 {
            let start = text.len().saturating_sub(2000);
            let tail = String::from_utf8_lossy(&text.as_bytes()[start..]).into_owned();
            return Err(format!("{row}: launch exited {status}: {tail}"));
        }
        let guest: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("CM-") || line.starts_with("GM-"))
            .collect();
        write_json(
            &self.evidence.join(format!("{row}-after.json")),
            &json!({
                "snapshot": snapshot_validation(&self.work)?,
                "status": status,
                "guest": guest,
            }),
        )?;
        Ok(text)
    }

    fn base_argv(&self, flags: &[String]) -> Vec<String> {
        let mut argv = vec![self.binary.clone()];
        argv.extend(LAUNCH_OPTIONS.iter().map(|option| (*option).to_owned()));
        argv.push("--image".to_owned());
        argv.push(self.image.clone());
        argv.extend(flags.iter().cloned());
        argv
    }

    /// A #394/#397 row: the historical explicit `bash -c` argv, unchanged.
    fn launch(&mut self, row: &str, phase: &str, flags: &[String]) -> Result<String, String> {
        let mut argv = self.base_argv(flags);
        for argument in [
            "shell".to_owned(),
            "bash".to_owned(),
            "-c".to_owned(),
            format!("bash ./{PROBE} {phase}"),
        ] {
            argv.push(argument);
        }
        self.run_row(row, argv, "shell", None)
    }

    /// A #396 declared/fallback shell row: the phase is a separate argv token and
    /// the product itself builds interactive bash's `-c` argument from it
    /// (`run::inner_argv` → `shell::guest_script_word`), so these rows exercise the
    /// shipped shell route rather than a copy of it.
    fn launch_script_shell(
        &mut self,
        row: &str,
        phase: &str,
        flags: &[String],
    ) -> Result<String, String> {
        let mut argv = self.base_argv(flags);
        for argument in [
            "shell".to_owned(),
            "bash".to_owned(),
            format!("./{PROBE}"),
            phase.to_owned(),
        ] {
            argv.push(argument);
        }
        self.run_row(row, argv, "shell", None)
    }

    /// A #396 tool row: the synthetic tool's own command and args run the probe.
    fn launch_tool(
        &mut self,
        row: &str,
        phase: &str,
        verb: &str,
        flags: &[String],
    ) -> Result<String, String> {
        let mut argv = self.base_argv(flags);
        argv.push(verb.to_owned());
        argv.push(phase.to_owned());
        self.run_row(row, argv, verb, None)
    }

    fn launch_gm(
        &mut self,
        gm: &GmFixture,
        row: &str,
        phase: &str,
        flags: &[String],
        extra: &[String],
    ) -> Result<String, String> {
        let mut argv = vec![self.binary.clone()];
        argv.extend(LAUNCH_OPTIONS.iter().map(|option| (*option).to_owned()));
        argv.extend(flags.iter().cloned());
        argv.push("--image".to_owned());
        argv.push(self.image.clone());
        argv.extend(extra.iter().cloned());
        for argument in [
            "shell".to_owned(),
            "bash".to_owned(),
            format!("./{GM_PROBE}"),
            phase.to_owned(),
            gm.common.to_string_lossy().into_owned(),
        ] {
            argv.push(argument);
        }
        if phase == "control" {
            argv.push(GM_ALIAS.to_owned());
        }
        self.run_row(row, argv, "shell", Some(&gm.worktree))
    }

    /// Tear one launch down, refusing while a VM that holds the fixtures may
    /// exist. Fixtures are never touched before this.
    fn cleanup(&mut self, row: &str) -> Result<(), String> {
        let index = self
            .launches
            .len()
            .checked_sub(1)
            .ok_or_else(|| format!("{row}: no launch to clean up"))?;
        let problems = self.launches[index].cleanup(None);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(format!("{row}: cleanup {problems:?}"))
        }
    }

    fn write_config(&self, row: &str, body: &str) -> Result<(), String> {
        self.write_config_at(&self.config, row, body)
    }

    fn write_config_at(&self, path: &Path, row: &str, body: &str) -> Result<(), String> {
        fs::write(path, body).map_err(|error| format!("{}: {error}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let kept = self.evidence.join(format!("{row}-config.toml"));
        fs::copy(path, &kept).map_err(|error| format!("{}: {error}", kept.display()))?;
        Ok(())
    }

    fn pi_fork_identity(&self) -> Result<Observed, String> {
        Ok(text_pairs(pi_fork_identity(&self.work)?))
    }

    fn ro_now(&self) -> Result<Observed, String> {
        let mut pairs = Vec::new();
        for name in ["agent/skills", "readonly", "agent-tool"] {
            pairs.push((name, Observed::text(tree_digest(&self.tool.join(name))?)));
        }
        Ok(Observed::table(pairs))
    }

    fn protected_now(&self) -> Result<Observed, String> {
        let mut digests: BTreeMap<String, String> = BTreeMap::new();
        for name in ["auth.json", "models.json"] {
            let path = self.pi_source.join("agent").join(name);
            let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            digests.insert(name.to_owned(), digest_bytes(&bytes));
        }
        Ok(Observed::text(if digests == self.protected {
            "unchanged"
        } else {
            "changed"
        }))
    }

    /// The whole run, in the order the rows depend on each other.
    fn rows(&mut self, receipt: &mut Receipt) -> Result<(), String> {
        self.fresh_state()?;
        let probe = self.project.join(PROBE);
        for (name, seed) in [("ro", "seed-ro"), ("rw", "seed-rw"), ("fork", "seed-fork")] {
            let source = self.home.join("cm").join(name);
            fs::create_dir_all(&source)
                .map_err(|error| format!("{}: {error}", source.display()))?;
            fs::write(source.join("marker"), seed)
                .map_err(|error| format!("{}: {error}", source.display()))?;
        }
        fs::write(self.project.join("project-marker"), "project\n")
            .map_err(|error| format!("{}: {error}", self.project.display()))?;
        fs::copy(self.fixtures.join(PROBE), &probe)
            .map_err(|error| format!("{}: {error}", probe.display()))?;
        self.write_config("L1", DEFAULTS_CONFIG)?;
        self.ro_tree = tree_digest(&self.home.join("cm/ro"))?;

        // ---- L1: ro, rw and fork under the default selection ----------------
        let l1 = self.launch("L1", "all", &[])?;
        receipt.record(
            "CM-N1",
            Observed::text("CM-N1 read=seed-ro write=denied"),
            Observed::text(guest_line(&l1, "CM-N1")),
        )?;
        receipt.record(
            "CM-N2",
            Observed::text("CM-N2 wrote"),
            Observed::text(guest_line(&l1, "CM-N2")),
        )?;
        receipt.record(
            "CM-N3a",
            Observed::text("CM-N3a read=seed-fork wrote"),
            Observed::text(guest_line(&l1, "CM-N3a")),
        )?;
        if !l1.contains("==> Mounts: 3 (config \"") {
            return Err("L1: the selected notice did not name the three declarations".to_owned());
        }
        // Host oracles, read only after the launch's cleanup proved absence. The
        // expected value is the retained pre-launch observation, so the row
        // compares two measurements rather than asserting a constant twice.
        self.cleanup("L1")?;
        receipt.record(
            "CM-N1-host",
            Observed::text(self.ro_tree.clone()),
            Observed::text(tree_digest(&self.home.join("cm/ro"))?),
        )?;
        receipt.record(
            "CM-N2-host",
            Observed::text("guest-rw"),
            Observed::text(marker(&self.rw_marker)),
        )?;
        receipt.record(
            "CM-N3a-host",
            Observed::text("seed-fork"),
            Observed::text(marker(&self.fork_marker)),
        )?;

        // The launch's own first pin is the approval record: a fresh private HOME
        // has no store, so an absent record means this launch was not what it says.
        self.check_image_pins()?;

        // ---- the host changes its own seed between launches -----------------
        fs::write(&self.fork_marker, "host-later")
            .map_err(|error| format!("{}: {error}", self.fork_marker.display()))?;

        // ---- L2: the fork keeps the guest's own write -----------------------
        let l2 = self.launch("L2", "n3b", &[])?;
        receipt.record(
            "CM-N3b",
            Observed::text("CM-N3b read=guest-fork"),
            Observed::text(guest_line(&l2, "CM-N3b")),
        )?;
        self.cleanup("L2")?;
        receipt.record(
            "CM-N3b-host",
            Observed::text("host-later"),
            Observed::text(marker(&self.fork_marker)),
        )?;

        // ---- L3: the opt-out removes every config mount ----------------------
        let l3 = self.launch("L3", "n4", &["--no-config-mounts".to_owned()])?;
        receipt.record(
            "CM-N4",
            Observed::text("CM-N4 ro=absent rw=absent fork=absent project=present"),
            Observed::text(guest_line(&l3, "CM-N4")),
        )?;
        if !l3.contains("==> Mounts: skipped 3 from") {
            return Err("CM-N4: the skipped notice did not name the three declarations".to_owned());
        }
        self.cleanup("L3")?;

        // ---- L4: an equivalent --mount reuses the config fork ----------------
        // The opt-out is what proves the config entry did not supply it.
        let l4 = self.launch(
            "L4",
            "n5",
            &[
                "--no-config-mounts".to_owned(),
                "--mount".to_owned(),
                format!("{}/cm/fork:/cm/fork:fork", self.home.display()),
            ],
        )?;
        receipt.record(
            "CM-N5",
            Observed::text("CM-N5 read=guest-fork"),
            Observed::text(guest_line(&l4, "CM-N5")),
        )?;
        self.cleanup("L4")?;

        self.named_set_rows(receipt)?;
        self.tool_rows(receipt)?;
        self.git_metadata_rows(receipt)?;

        // The read-only trees are the last thing measured: every row that had a
        // chance to write them is finished and its VM proven absent.
        receipt.record("CM-T-host-ro", self.retained_tool_ro(), self.ro_now()?)?;
        receipt.record(
            "CM-T-host-protected",
            Observed::text("unchanged"),
            self.protected_now()?,
        )?;
        receipt.record(
            "CM-T-host-fork-identity",
            self.pi_fork_identity()?,
            self.pi_fork_identity()?,
        )?;
        Ok(())
    }

    fn check_image_pins(&self) -> Result<(), String> {
        let pins = self.home.join(".config/agent-vm/image-pins.json");
        if !pins.is_file() {
            return Err(
                "L1: no image-pins.json; the digest-pinned acquisition left no approval".to_owned(),
            );
        }
        let kept = self.evidence.join("image-pins.json");
        fs::copy(&pins, &kept).map_err(|error| format!("{}: {error}", kept.display()))?;
        let bytes = fs::read(&pins).map_err(|error| format!("{}: {error}", pins.display()))?;
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{}: {error}", pins.display()))?;
        let requested = self
            .image
            .rsplit_once('@')
            .map(|(_, digest)| digest)
            .unwrap_or(self.image.as_str());
        let records = document
            .get("pins")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let recorded = records
            .iter()
            .map(|pin| {
                format!(
                    "{} {}",
                    pin.get("reference").and_then(Value::as_str).unwrap_or(""),
                    pin.get("manifest_digest")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                )
            })
            .collect::<Vec<String>>()
            .join(" ");
        if !recorded.contains(requested) {
            return Err(format!(
                "image-pins.json does not name the requested digest {requested}: {recorded:?}"
            ));
        }
        if records.len() != 1 {
            return Err(format!(
                "image-pins.json has {} pins, expected 1",
                records.len()
            ));
        }
        Ok(())
    }

    // ---- named mount sets (#397) -------------------------------------------

    fn named_set_rows(&mut self, receipt: &mut Receipt) -> Result<(), String> {
        let absent_line = "CM-S ro=absent rw=absent fork=absent project=present";
        let access_line = "CM-S access ro=seed-ro ro-write=denied rw=wrote fork=guest-fork \
                           project=present";
        let fork_before = fork_identity(&self.work)?;

        // S1: definitions alone must mount nothing.
        self.write_config("S1", SETS_TABLE)?;
        let s1 = self.launch("S1", "sets-absent", &[])?;
        receipt.record(
            "CM-S1",
            Observed::text(absent_line),
            Observed::text(guest_line(&s1, "CM-S")),
        )?;
        self.cleanup("S1")?;

        // S2: the defaults select the set's three leaves.
        self.write_config("S2", &format!("{SETS_DEFAULT}{SETS_TABLE}"))?;
        let s2 = self.launch("S2", "sets", &[])?;
        receipt.record(
            "CM-S2",
            Observed::text(access_line),
            Observed::text(guest_line(&s2, "CM-S")),
        )?;
        self.cleanup("S2")?;
        if !s2.contains("==> Reusing fork") || s2.contains("Initialized fork") {
            return Err("CM-S2: the set-selected fork was not reused".to_owned());
        }

        // S3: the opt-out removes all three again, project still visible.
        let s3 = self.launch("S3", "sets-absent", &["--no-config-mounts".to_owned()])?;
        receipt.record(
            "CM-S3",
            Observed::text(absent_line),
            Observed::text(guest_line(&s3, "CM-S")),
        )?;
        self.cleanup("S3")?;

        // S4: the opt-out plus an explicit name grants exactly S2's access.
        let s4 = self.launch(
            "S4",
            "sets",
            &[
                "--no-config-mounts".to_owned(),
                "--mount".to_owned(),
                "all-set".to_owned(),
            ],
        )?;
        receipt.record(
            "CM-S4",
            Observed::text(access_line),
            Observed::text(guest_line(&s4, "CM-S")),
        )?;
        self.cleanup("S4")?;
        if !s4.contains("==> Reusing fork") || s4.contains("Initialized fork") {
            return Err("CM-S4: the explicitly selected set reseeded the fork".to_owned());
        }

        // Host oracles, read only after the last launch's cleanup proved absence.
        receipt.record(
            "CM-S-host-ro",
            Observed::text(self.ro_tree.clone()),
            Observed::text(tree_digest(&self.home.join("cm/ro"))?),
        )?;
        receipt.record(
            "CM-S-host-rw",
            Observed::text("set-rw"),
            Observed::text(marker(&self.rw_marker)),
        )?;
        receipt.record(
            "CM-S-host-fork",
            Observed::text("host-later"),
            Observed::text(marker(&self.fork_marker)),
        )?;
        receipt.record(
            "CM-S-host-fork-identity",
            text_pairs(fork_before),
            text_pairs(fork_identity(&self.work)?),
        )?;
        Ok(())
    }

    // ---- tool mounts (#396) -------------------------------------------------

    fn tool_rows(&mut self, receipt: &mut Receipt) -> Result<(), String> {
        // A topology of its own, over the same owned scratch: an agent parent with
        // a read-only child, a second read-only directory, a declared shell's own
        // leaf and a user-wide default. Every source, sentinel and protected file
        // is unmistakable — the operator's real config, real Pi home and real
        // credentials are never read or written.
        for (name, seed) in [
            ("agent", "agent-seed"),
            ("agent/skills", "skills-seed"),
            ("readonly", "readonly-seed"),
            ("shell-own", "shell-own"),
            ("default", "default"),
            ("agent-tool", "agent-tool-seed"),
        ] {
            let directory = self.tool.join(name);
            fs::create_dir_all(&directory)
                .map_err(|error| format!("{}: {error}", directory.display()))?;
            fs::write(directory.join("marker"), seed)
                .map_err(|error| format!("{}: {error}", directory.display()))?;
        }
        fs::create_dir_all(self.pi_source.join("agent"))
            .map_err(|error| format!("{}: {error}", self.pi_source.display()))?;
        fs::write(self.pi_source.join("marker"), "pi-seed")
            .map_err(|error| format!("{}: {error}", self.pi_source.display()))?;
        for (name, bytes) in [
            ("auth.json", "{\"synthetic\": \"pi-auth-sentinel-396\"}"),
            ("models.json", "{\"synthetic\": \"pi-models-sentinel-396\"}"),
        ] {
            fs::write(self.pi_source.join("agent").join(name), bytes)
                .map_err(|error| format!("{}: {error}", self.pi_source.display()))?;
        }
        for name in ["agent/skills", "readonly", "agent-tool"] {
            self.tool_ro
                .insert(name.to_owned(), tree_digest(&self.tool.join(name))?);
        }
        for name in ["auth.json", "models.json"] {
            let path = self.pi_source.join("agent").join(name);
            let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            self.protected.insert(name.to_owned(), digest_bytes(&bytes));
        }

        // T1..T5 share this catalog: a wildcard shell, per-tool sets and the Pi
        // fork, which is what makes each row a *selection* difference.
        self.write_config("T1", &tools_wildcard_shell())?;

        let t1 = self.launch_tool("T1", "tool-plain", "plain", &[])?;
        receipt.record(
            "CM-T1",
            Observed::text(
                "CM-T1 agent=absent skills=absent readonly=absent pi=absent project=present",
            ),
            Observed::text(guest_line(&t1, "CM-T1")),
        )?;
        if t1.contains("==> Mounts:") {
            return Err("CM-T1: the plain tool selected no mount, so no notice is due".to_owned());
        }
        self.cleanup("T1")?;
        // The generic `.pi` guest-home link exists without the fork; what must be
        // absent is a Pi-lineage fork in the state root.
        receipt.record(
            "CM-T1-host",
            Observed::table(Vec::new()),
            self.pi_fork_identity()?,
        )?;

        let t2 = self.launch_tool("T2", "tool-claude", "claude", &[])?;
        receipt.record(
            "CM-T2",
            Observed::text(
                "CM-T2 agent=agent-seed agent-write=wrote skills=skills-seed skills-write=denied \
                 readonly=readonly-seed readonly-write=denied pi=absent",
            ),
            Observed::text(guest_line(&t2, "CM-T2")),
        )?;
        self.cleanup("T2")?;
        receipt.record(
            "CM-T2-host",
            Observed::table([
                ("parent-write", Observed::text("claude-note")),
                ("ro", self.retained_tool_ro()),
            ]),
            Observed::table([
                (
                    "parent-write",
                    Observed::text(marker(&self.tool.join("agent/new"))),
                ),
                ("ro", self.ro_now()?),
            ]),
        )?;

        let t3 = self.launch_tool("T3", "tool-pi", "pi", &[])?;
        receipt.record(
            "CM-T3",
            Observed::text(
                "CM-T3 agent=agent-seed skills=skills-seed readonly=readonly-seed pi=pi-seed \
                 pi-write=wrote auth=absent models=absent guest-file=wrote",
            ),
            Observed::text(guest_line(&t3, "CM-T3")),
        )?;
        self.cleanup("T3")?;
        let identity = self.pi_fork_identity()?;
        receipt.record(
            "CM-T3-host",
            Observed::table([
                ("pi-source", Observed::text("pi-seed")),
                ("protected", Observed::text("unchanged")),
                ("guest-only", Observed::text("absent")),
                ("parent-write", Observed::text("claude-note")),
            ]),
            Observed::table([
                (
                    "pi-source",
                    Observed::text(marker(&self.pi_source.join("marker"))),
                ),
                ("protected", self.protected_now()?),
                (
                    "guest-only",
                    Observed::text(if self.pi_source.join("guest-only").exists() {
                        "present"
                    } else {
                        "absent"
                    }),
                ),
                (
                    "parent-write",
                    Observed::text(marker(&self.tool.join("agent/new"))),
                ),
            ]),
        )?;
        receipt.record(
            "CM-T3-host-identity",
            Observed::count(1),
            self.pi_fork_identity_count()?,
        )?;

        // The host changes its own source between launches: the fork must not
        // follow, and must not be reseeded.
        fs::write(self.pi_source.join("marker"), "pi-host-later")
            .map_err(|error| format!("{}: {error}", self.pi_source.display()))?;
        let t4 = self.launch_tool("T4", "tool-bridge", "bridge", &[])?;
        receipt.record(
            "CM-T4",
            Observed::text("CM-T4 pi=pi-guest guest-file=present"),
            Observed::text(guest_line(&t4, "CM-T4")),
        )?;
        self.cleanup("T4")?;
        if !t4.contains("==> Reusing fork") || t4.contains("Initialized fork") {
            return Err("CM-T4: the inherited Pi fork was not reused".to_owned());
        }
        receipt.record(
            "CM-T4-host",
            Observed::table([
                ("identity", identity.clone()),
                ("pi-source", Observed::text("pi-host-later")),
            ]),
            Observed::table([
                ("identity", self.pi_fork_identity()?),
                (
                    "pi-source",
                    Observed::text(marker(&self.pi_source.join("marker"))),
                ),
            ]),
        )?;

        let t5 = self.launch_script_shell("T5", "tool-shell", &[])?;
        receipt.record(
            "CM-T5",
            Observed::text(
                "CM-T5 agent=agent-seed skills=skills-seed ro-write=denied pi=pi-guest \
                 project=present",
            ),
            Observed::text(guest_line(&t5, "CM-T5")),
        )?;
        self.cleanup("T5")?;
        receipt.record(
            "CM-T5-host",
            Observed::table([
                ("ro", self.retained_tool_ro()),
                ("pi-source", Observed::text("pi-host-later")),
            ]),
            Observed::table([
                ("ro", self.ro_now()?),
                (
                    "pi-source",
                    Observed::text(marker(&self.pi_source.join("marker"))),
                ),
            ]),
        )?;

        // T6: the declared shell switches inheritance off; its own leaf and the
        // user-wide default survive, both read-only.
        self.write_config("T6", &tools_empty_shell())?;
        let t6 = self.launch_script_shell("T6", "tool-shell-own", &[])?;
        receipt.record(
            "CM-T6",
            Observed::text(
                "CM-T6 agent=absent skills=absent readonly=absent pi=absent \
                 shell-own=shell-own shell-own-write=denied default=default default-write=denied",
            ),
            Observed::text(guest_line(&t6, "CM-T6")),
        )?;
        self.cleanup("T6")?;
        receipt.record(
            "CM-T6-host",
            Observed::table([
                ("shell-own", Observed::text("shell-own")),
                ("default", Observed::text("default")),
            ]),
            Observed::table([
                (
                    "shell-own",
                    Observed::text(marker(&self.tool.join("shell-own/marker"))),
                ),
                (
                    "default",
                    Observed::text(marker(&self.tool.join("default/marker"))),
                ),
            ]),
        )?;

        // T7: with no declared shell the built-in fallback runs in its own scope.
        self.write_config("T7", &tools_fallback_shell())?;
        let t7 = self.launch_script_shell("T7", "tool-shell-fallback", &[])?;
        receipt.record(
            "CM-T7",
            Observed::text(
                "CM-T7 agent=absent skills=absent pi=absent shell-own=absent default=default \
                 default-write=denied project=present",
            ),
            Observed::text(guest_line(&t7, "CM-T7")),
        )?;
        self.cleanup("T7")?;

        // T8: the automatic opt-out removes defaults, the shell's own leaf and
        // every inherited facet, on both a tool launch and the declared shell.
        self.write_config("T8", &tools_optout())?;
        for verb in ["pi", "shell"] {
            let row = format!("T8-{verb}");
            let text = if verb == "shell" {
                self.launch_script_shell(&row, "tool-optout", &["--no-config-mounts".to_owned()])?
            } else {
                self.launch_tool(
                    &row,
                    "tool-optout",
                    verb,
                    &["--no-config-mounts".to_owned()],
                )?
            };
            receipt.record(
                &format!("CM-T8-{verb}"),
                Observed::text(
                    "CM-T8 agent=absent skills=absent readonly=absent pi=absent \
                     shell-own=absent default=absent project=present",
                ),
                Observed::text(guest_line(&text, "CM-T8")),
            )?;
            if !text.contains("==> Mounts: skipped") {
                return Err(format!("{row}: the opt-out left no skipped notice"));
            }
            self.cleanup(&row)?;
        }

        // T9: the explicit set returns exactly the agent topology, including the
        // separate read-only leaf; selecting a set named like a tool provisions no
        // tool, judged by that tool's own `persist` link.
        self.write_config("T9", &format!("{}{}", tools_optout(), TOOLS_SAME_NAME_TOOL))?;
        let t9 = self.launch_tool(
            "T9",
            "tool-set-explicit",
            "pi",
            &[
                "--no-config-mounts".to_owned(),
                "--mount".to_owned(),
                "agent".to_owned(),
            ],
        )?;
        receipt.record(
            "CM-T9",
            Observed::text(
                "CM-T9 agent=agent-seed agent-write=wrote skills=skills-seed ro-write=denied \
                 readonly=readonly-seed readonly-write=denied pi=absent default=absent \
                 agent-tool=absent agent-tool-state=absent",
            ),
            Observed::text(guest_line(&t9, "CM-T9")),
        )?;
        self.cleanup("T9")?;
        receipt.record(
            "CM-T9-host",
            Observed::table([
                ("ro", self.retained_tool_ro()),
                ("parent-write", Observed::text("explicit-note")),
            ]),
            Observed::table([
                ("ro", self.ro_now()?),
                (
                    "parent-write",
                    Observed::text(marker(&self.tool.join("agent/new"))),
                ),
            ]),
        )?;

        // T9-control: the positive control for both observables.
        let t9c = self.launch_tool("T9-control", "tool-agent-name", "agent", &[])?;
        receipt.record(
            "CM-T9-control",
            Observed::text("CM-T9-control agent-tool=agent-tool-seed agent-tool-state=present"),
            Observed::text(guest_line(&t9c, "CM-T9-control")),
        )?;
        self.cleanup("T9-control")?;

        // T10: the equivalent explicit fork declaration reuses the inherited Pi
        // fork even though the automatic sources are suppressed.
        let t10 = self.launch_tool(
            "T10",
            "tool-pi-explicit",
            "pi",
            &[
                "--no-config-mounts".to_owned(),
                "--mount".to_owned(),
                format!(
                    "{}:{}:fork",
                    self.pi_source.display(),
                    self.pi_source.display()
                ),
            ],
        )?;
        receipt.record(
            "CM-T10",
            Observed::text("CM-T10 pi=pi-guest guest-file=present agent=absent"),
            Observed::text(guest_line(&t10, "CM-T10")),
        )?;
        self.cleanup("T10")?;
        if !t10.contains("==> Reusing fork") || t10.contains("Initialized fork") {
            return Err("T10: the explicit Pi fork was not reused".to_owned());
        }
        receipt.record(
            "CM-T10-host",
            Observed::table([
                ("identity", identity.clone()),
                ("pi-source", Observed::text("pi-host-later")),
            ]),
            Observed::table([
                ("identity", self.pi_fork_identity()?),
                (
                    "pi-source",
                    Observed::text(marker(&self.pi_source.join("marker"))),
                ),
            ]),
        )?;

        // T11: the same declaration as a top-level default, then through a nested
        // set — the route is the only difference, so no reseed and no new identity.
        for (row, document) in [
            ("T11-default", tools_default_fork()),
            ("T11-set", tools_nested_set()),
        ] {
            self.write_config(row, &document)?;
            let text = self.launch_tool(row, "tool-fork", "pi", &[])?;
            let suffix = row
                .split_once('-')
                .map(|(_, s)| s)
                .unwrap_or(row)
                .to_owned();
            receipt.record(
                &format!("CM-T11-{suffix}"),
                Observed::text("CM-T11 pi=pi-guest guest-file=present agent=absent"),
                Observed::text(guest_line(&text, "CM-T11")),
            )?;
            self.cleanup(row)?;
            if !text.contains("==> Reusing fork") || text.contains("Initialized fork") {
                return Err(format!("{row}: the fork was reseeded"));
            }
            receipt.record(
                &format!("CM-T11-host-{suffix}"),
                Observed::table([
                    ("identity", identity.clone()),
                    ("pi-source", Observed::text("pi-host-later")),
                ]),
                Observed::table([
                    ("identity", self.pi_fork_identity()?),
                    (
                        "pi-source",
                        Observed::text(marker(&self.pi_source.join("marker"))),
                    ),
                ]),
            )?;
        }
        Ok(())
    }

    fn retained_tool_ro(&self) -> Observed {
        text_pairs(
            self.tool_ro
                .iter()
                .map(|(name, digest)| (name.clone(), digest.clone())),
        )
    }

    fn pi_fork_identity_count(&self) -> Result<Observed, String> {
        Ok(Observed::count(pi_fork_identity(&self.work)?.len()))
    }

    // ---- the automatic Git metadata rows (#535, ADR-0062) -------------------

    fn git_metadata_rows(&mut self, receipt: &mut Receipt) -> Result<(), String> {
        // A real linked worktree, built by `git` before any baseline snapshot.
        // Every row also carries `LAUNCH_OPTIONS` (`--no-git`), so the whole group
        // proves independence from the GitHub-credential flag.
        let gm = build_gm_fixture(&self.work, &self.fixtures.join(GM_PROBE))?;
        let host = GmHost { fixture: gm };
        let baseline = Baseline::measure(&host)?;
        write_json(
            &self.evidence.join("gm-before.json"),
            &json!({"common-tree": baseline.common_tree, "branch": baseline.branch}),
        )?;
        let mut seam = LiveSeam {
            driver: self,
            host: &host,
        };
        let outcome = run_gm_group(&mut seam, &host, receipt, &baseline)?;
        if outcome == GmOutcome::Blocked {
            eprintln!("BLOCKED (guest image has no git): {}", GM_ROWS.join(", "));
        }
        Ok(())
    }

    /// The `finally` block: teardown, then the evidence, then the scratch.
    ///
    /// Receipts and logs survive even when a row fails; nothing here snapshots the
    /// host's policy state into the evidence instead of the launch's own files.
    fn finish(&mut self, totals: &Value) -> Result<(), String> {
        self.errors.extend(egress_run::cleanup_run(
            &self.work,
            &self.binary,
            &self.launches,
            None,
        ));
        let entries = fs::read_dir(&self.work)
            .map_err(|error| format!("{}: {error}", self.work.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", self.work.display()))?;
            if entry.path().is_file() {
                let kept = self.evidence.join(entry.file_name());
                fs::copy(entry.path(), &kept)
                    .map_err(|error| format!("{}: {error}", kept.display()))?;
            }
        }
        write_json(&self.evidence.join("errors.json"), &json!(self.errors))?;
        write_json(&self.evidence.join("totals.json"), totals)?;
        if self.errors.is_empty() {
            fs::remove_dir_all(&self.root)
                .map_err(|error| format!("{}: {error}", self.root.display()))?;
        } else {
            eprintln!(
                "Owned scratch retained after failure: {}",
                self.root.display()
            );
        }
        Ok(())
    }
}

/// The live launch half of the GM group: the real candidate, into the fixture
/// worktree.
struct LiveSeam<'a> {
    driver: &'a mut Driver,
    host: &'a GmHost,
}

impl Seam for LiveSeam<'_> {
    fn launch(
        &mut self,
        row: &str,
        phase: &str,
        flags: &[String],
        extra: &[String],
    ) -> Result<String, String> {
        let fixture = &self.host.fixture;
        self.driver.launch_gm(fixture, row, phase, flags, extra)
    }

    fn cleanup(&mut self, row: &str) -> Result<(), String> {
        self.driver.cleanup(row)
    }
}

/// The environment every row launches with: the egress fixtures' own base, with
/// the runtime named explicitly (resolution rung 1) so no inherited `MSB_*`
/// variable can redirect it.
fn fixtures_env(work: &Path) -> Vec<(String, String)> {
    fixtures::base_environment(work)
}

pub fn run(args: ConfigMountsArgs) -> Result<crate::Outcome, String> {
    if args.inputs.len() != 5 {
        return Err(
            "usage: config-mounts ROOT EVIDENCE BINARY IMAGE MSB (five positional arguments)"
                .to_owned(),
        );
    }
    let root = canonical(&args.inputs[0])?;
    let evidence = canonical(&args.inputs[1])?;
    let binary = args.inputs[2].to_string_lossy().into_owned();
    let image = args.inputs[3].to_string_lossy().into_owned();
    let msb = args.inputs[4].to_string_lossy().into_owned();
    let fixtures_dir = args.repo_root.join("script/test/fixtures/config-mounts");

    install_signal_handlers();
    let mut driver = Driver::new(root, evidence.clone(), fixtures_dir, binary, image, msb);
    let mut receipt = Receipt::new(&evidence.join("summary.tsv"), false);
    if let Err(error) = driver.rows(&mut receipt) {
        driver.errors.push(error);
    }
    let totals = receipt.totals();
    if let Err(error) = driver.finish(&totals) {
        driver.errors.push(error);
    }
    for error in &driver.errors {
        eprintln!("{error}");
    }
    Ok(crate::Outcome::Exit(if driver.errors.is_empty() {
        0
    } else {
        1
    }))
}
