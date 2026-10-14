//! Build-time identity for `agent-vm --version` (issue #335).
//!
//! A version number identifies a release; a commit identifies the source
//! revision a particular binary was built from. During #305 verification an
//! older binary was cited against newer source and only filesystem mtimes
//! exposed it. Emitting the commit in the version string turns a provenance
//! *record* into a provenance *assertion*: `script/test/persisted-network-live.sh`
//! can reject a stale candidate before it boots a VM.
//!
//! The identity is measured **once, at build time**, and passed to the crate as
//! the single constant `AGENT_VM_BUILD_VERSION`. Nothing in `cli.rs`/`main.rs`
//! learns about git, and no runtime git is ever invoked (see
//! `script/test/no-image-source-dependency-test.sh`). A fabricated binary can
//! print any string, so this is build metadata, not authenticity.
//!
//! # Invalidation is a policy choice, not a Cargo capability
//!
//! Cargo's `rerun-if-changed` compares mtimes, not file modes or ctime. The
//! user mandated a cheap default: precise watchers for every Git-resolved path
//! that decides the identity (HEAD, index, packed refs, each symbolic-ref link,
//! the worktree marker, every tracked path, and recursively every initialized
//! submodule). Unchanged complete builds stay fresh. The accepted residual is
//! that a mode-only `chmod` or an older-mtime symlink replacement is invisible
//! to mtimes; `AGENT_VM_BUILD_PROVENANCE_STRICT=1` closes that gap by adding an
//! unsatisfiable ENOTDIR dependency, at the measured cost of recompiling the
//! launcher every build. See CONTRIBUTING.md's "Build identity" section.

use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// The always-rerun dependency for strict/fallback mode.
///
/// A child beneath mandatory `build.rs` can never be a filesystem entry (stat
/// resolves to ENOTDIR), so Cargo always considers it stale and always reruns
/// the probe. The withdrawn design used a *creatable* reserved filename; a
/// preserved-timestamp file at that name could make a cached build look fresh
/// and silently skip its own guard.
const FALLBACK_DEPENDENCY: &str = "build.rs/agent-vm-provenance-always-rerun";

/// Git routing variables a caller may have set. A `-C root` does not override
/// them, so a parent could otherwise make the probe measure a *different*
/// checkout while the harness source stays put.
const GIT_ROUTING_VARS: [&str; 5] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
];

/// A validated full git object id, normalized to lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GitSha(String);

impl GitSha {
    /// Accept exactly 40 or 64 ASCII hex characters. Abbreviated ids, ref
    /// names, whitespace and control characters are rejected; the full id is
    /// what lets the harness assert exact equality rather than a prefix.
    fn parse(text: &str) -> Result<Self, InvalidSha> {
        let bytes = text.as_bytes();
        if bytes.len() != 40 && bytes.len() != 64 {
            return Err(InvalidSha);
        }
        if !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(InvalidSha);
        }
        Ok(GitSha(text.to_ascii_lowercase()))
    }
}

/// Which source revision the build claims. `Unknown` is a real measured state,
/// not a clean default.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Revision {
    Known(GitSha),
    Unknown,
}

/// Whether the tracked tree matched the commit when the probe ran. `Unknown`
/// means the measurement could not be trusted, never "clean".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeState {
    Clean,
    Dirty,
    Unknown,
}

struct BuildInfo {
    revision: Revision,
    tree: TreeState,
}

impl BuildInfo {
    /// The total rendering of `(Revision, TreeState)`. `agent-vm ` is supplied
    /// by clap, so it is not part of this string.
    fn version(&self, package_version: &str) -> String {
        match (&self.revision, self.tree) {
            (Revision::Known(sha), TreeState::Clean) => format!("{package_version} ({})", sha.0),
            (Revision::Known(sha), TreeState::Dirty) => {
                format!("{package_version} ({}", sha.0) + ", dirty)"
            }
            (Revision::Known(sha), TreeState::Unknown) => {
                format!("{package_version} ({}", sha.0) + ", state unknown)"
            }
            (Revision::Unknown, TreeState::Dirty) => format!("{package_version} (unknown, dirty)"),
            (Revision::Unknown, TreeState::Clean | TreeState::Unknown) => {
                format!("{package_version} (unknown)")
            }
        }
    }
}

/// Trusted build inputs. They intentionally can name a different commit than
/// the local checkout; the PN harness later rejects a disagreement.
struct BuildOverrides {
    explicit: Option<OsString>,
    github: Option<OsString>,
}

impl BuildOverrides {
    fn from_env() -> Self {
        Self {
            explicit: env::var_os("AGENT_VM_GIT_SHA"),
            github: env::var_os("GITHUB_SHA"),
        }
    }

    fn candidates(&self) -> [(&'static str, &Option<OsString>); 2] {
        [
            ("AGENT_VM_GIT_SHA", &self.explicit),
            ("GITHUB_SHA", &self.github),
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeMode {
    Default,
    Strict,
}

struct InvalidStrictMode;

/// Strict is opt-in and value-precise. Only unset/empty/`0`/`1` are accepted;
/// every other value, Unicode or not, is a hard value-free error *when the
/// probe executes*. Cargo's env fingerprint collapses absent and non-Unicode to
/// the same `None`, so an absent-to-non-Unicode-only transition may reuse a
/// cached default build with no diagnostic; that residual is documented.
fn probe_mode(value: Option<OsString>) -> Result<ProbeMode, InvalidStrictMode> {
    match value {
        None => Ok(ProbeMode::Default),
        Some(value) => match value.to_str() {
            None => Err(InvalidStrictMode),
            Some("") | Some("0") => Ok(ProbeMode::Default),
            Some("1") => Ok(ProbeMode::Strict),
            Some(_) => Err(InvalidStrictMode),
        },
    }
}

/// A watcher path Cargo will parse back to exactly this value.
///
/// The private constructor is the seam: no raw Git path, `Path::display()` or
/// OUT_DIR ever reaches Cargo's line protocol. The value is a normalized,
/// package-relative ASCII spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SafeWatchPath(String);

impl SafeWatchPath {
    fn as_str(&self) -> &str {
        &self.0
    }
}

struct Observation {
    info: BuildInfo,
    watch_paths: Vec<SafeWatchPath>,
    discovery_incomplete: bool,
}

struct WatchContext {
    package_dir: PathBuf,
    repo_root: PathBuf,
}

enum WatchError {
    Discovery(Vec<SafeWatchPath>),
    UnrepresentablePath(Vec<SafeWatchPath>),
}

enum GitError {
    Unavailable,
    Failed,
}

struct InvalidSha;

struct GitOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

/// Run git with all inherited routing removed and read-only locking disabled.
/// Both spawn and exit status are checked; git's stderr is never surfaced
/// because it can carry checkout contents.
fn git_run(root: &Path, args: &[&str]) -> Result<GitOutput, GitError> {
    let mut command = Command::new("git");
    command.arg("--no-optional-locks").arg("-C").arg(root);
    command.args(args);
    for var in GIT_ROUTING_VARS {
        command.env_remove(var);
    }
    let output = command.output().map_err(|_| GitError::Unavailable)?;
    Ok(GitOutput {
        status: output.status,
        stdout: output.stdout,
    })
}

fn git_output(root: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let output = git_run(root, args)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(GitError::Failed)
    }
}

/// Whether `worktree`'s Git top-level is exactly that worktree. This stops a
/// tarball nested in an unrelated checkout from adopting the outer repository's
/// identity.
fn is_own_git_root(worktree: &Path) -> bool {
    let Ok(raw) = git_output(worktree, &["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let bytes = strip_single_lf(&raw);
    if bytes.iter().any(|b| *b == b'\r' || *b == b'\n' || *b == 0) {
        return false;
    }
    let discovered = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    match fs::canonicalize(discovered) {
        Ok(canonical) => canonical == worktree,
        Err(_) => false,
    }
}

fn select_revision(context: &WatchContext, overrides: &BuildOverrides) -> Revision {
    for (name, candidate) in overrides.candidates() {
        let Some(value) = candidate.as_ref() else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        match value.to_str() {
            Some(text) => match GitSha::parse(text) {
                Ok(sha) => return Revision::Known(sha),
                Err(_) => warn(&format!(
                    "{name} is not a full 40- or 64-digit hexadecimal commit id; ignoring it"
                )),
            },
            None => warn(&format!("{name} is not valid Unicode; ignoring it")),
        }
    }
    if is_own_git_root(&context.repo_root)
        && let Ok(raw) = git_output(&context.repo_root, &["rev-parse", "--verify", "HEAD"])
    {
        let bytes = strip_single_lf(&raw);
        if let Ok(text) = std::str::from_utf8(bytes)
            && let Ok(sha) = GitSha::parse(text)
        {
            return Revision::Known(sha);
        }
    }
    Revision::Unknown
}

/// Measure tracked dirt independently of the chosen revision. `status` reports
/// staged and unstaged tracked changes, gitlink changes and tracked changes
/// inside initialized submodules; untracked and ignored files do not mark the
/// tree dirty.
fn measure_tree(context: &WatchContext) -> TreeState {
    if !is_own_git_root(&context.repo_root) {
        return TreeState::Unknown;
    }
    let args = [
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=no",
        "--ignore-submodules=untracked",
    ];
    match git_output(&context.repo_root, &args) {
        Ok(bytes) if bytes.is_empty() => TreeState::Clean,
        Ok(_) => TreeState::Dirty,
        Err(_) => TreeState::Unknown,
    }
}

/// Discover every Git-resolved input that decides the identity, convert each to
/// a validated package-relative watcher, and report whether discovery was
/// complete. An unrepresentable candidate is omitted and requests the
/// conservative fallback rather than being silently dropped.
fn collect_watch_paths(context: &WatchContext) -> Result<Vec<SafeWatchPath>, WatchError> {
    let mut collector = Collector::new(context);
    collector.include_literal("build.rs");
    if !is_own_git_root(&context.repo_root) {
        return Err(WatchError::Discovery(collector.finish()));
    }
    collector.collect_repository(&context.repo_root);
    collector.finish_result()
}

struct Collector<'a> {
    context: &'a WatchContext,
    paths: Vec<SafeWatchPath>,
    seen: HashSet<String>,
    unrepresentable: bool,
}

impl<'a> Collector<'a> {
    fn new(context: &'a WatchContext) -> Self {
        Self {
            context,
            paths: Vec::new(),
            seen: HashSet::new(),
            unrepresentable: false,
        }
    }

    /// Record a compile-time literal that is already known to be safe.
    fn include_literal(&mut self, literal: &str) {
        if self.seen.insert(literal.to_string()) {
            self.paths.push(SafeWatchPath(literal.to_string()));
        }
    }

    /// Add an absolute candidate through the validated, package-relative seam.
    /// A candidate that cannot be represented safely makes discovery
    /// incomplete; it is omitted, never printed raw or trimmed into a
    /// different name.
    fn add(&mut self, absolute: &Path) {
        match safe_relative_watch(self.context, absolute) {
            Ok(path) => {
                if self.seen.insert(path.0.clone()) {
                    self.paths.push(path);
                }
            }
            Err(WatchError::UnrepresentablePath(_)) | Err(WatchError::Discovery(_)) => {
                self.unrepresentable = true;
            }
        }
    }

    fn collect_repository(&mut self, worktree: &Path) {
        // Marker file for a linked worktree or submodule routes the worktree to
        // its shared/common git dir; in the main worktree `.git` is a directory.
        let marker = worktree.join(".git");
        if let Ok(meta) = fs::symlink_metadata(&marker)
            && meta.file_type().is_file()
        {
            self.add(&marker);
        }
        let index = self.git_path(worktree, "index");
        match index {
            Some(path) => self.add(&path),
            None => self.unrepresentable = true,
        }
        if let Some(packed) = self.git_path(worktree, "packed-refs") {
            // An intentionally absent packed-refs is not a watcher: that would
            // force every ordinary no-op build. The refs walk below watches an
            // existing refs parent for loose creation instead.
            match fs::metadata(&packed) {
                Ok(_) => self.add(&packed),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => self.unrepresentable = true,
            }
        }
        let refs_tree = self.git_common_dir(worktree).map(|dir| dir.join("refs"));
        self.collect_symbolic_chain(worktree, refs_tree.as_deref());
        self.collect_tracked(worktree);
    }

    fn git_path(&mut self, root: &Path, name: &str) -> Option<PathBuf> {
        let raw = git_output(
            root,
            &["rev-parse", "--path-format=absolute", "--git-path", name],
        )
        .inspect_err(|_| {
            self.unrepresentable = true;
        })
        .ok()?;
        let bytes = strip_single_lf(&raw);
        if bytes.is_empty() || bytes.iter().any(|b| *b == b'\r' || *b == b'\n' || *b == 0) {
            self.unrepresentable = true;
            return None;
        }
        Some(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }

    fn git_common_dir(&mut self, root: &Path) -> Option<PathBuf> {
        let raw = git_output(
            root,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        )
        .inspect_err(|_| {
            self.unrepresentable = true;
        })
        .ok()?;
        let bytes = strip_single_lf(&raw);
        if bytes.is_empty() || bytes.iter().any(|b| *b == b'\r' || *b == b'\n' || *b == 0) {
            self.unrepresentable = true;
            return None;
        }
        Some(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }

    /// Walk `HEAD -> alias -> ... -> terminal` with `--no-recurse`, watching
    /// every link and the terminal's loose file (or an existing refs parent for
    /// a packed terminal). Git dereferences recursively by default, which would
    /// hide an intermediate alias retarget from Cargo.
    fn collect_symbolic_chain(&mut self, worktree: &Path, refs_tree: Option<&Path>) {
        let mut visited = HashSet::new();
        let mut current = String::from("HEAD");
        let mut steps = 0;
        loop {
            if !visited.insert(current.clone()) || steps > 64 {
                self.unrepresentable = true;
                return;
            }
            steps += 1;
            let Some(loose) = self.git_path(worktree, &current) else {
                return;
            };
            if loose.exists() {
                self.add(&loose);
            } else if current == "HEAD" {
                self.unrepresentable = true;
                return;
            } else if let Some(parent) = nearest_existing_parent(&loose, refs_tree) {
                self.add(&parent);
            } else {
                self.unrepresentable = true;
                return;
            }
            match git_run(worktree, &["symbolic-ref", "--no-recurse", "-q", &current]) {
                Ok(output) if output.status.success() => {
                    let bytes = strip_single_lf(&output.stdout);
                    match std::str::from_utf8(bytes) {
                        Ok(name) if !name.is_empty() => current = name.to_string(),
                        _ => {
                            self.unrepresentable = true;
                            return;
                        }
                    }
                }
                // Exit 1 is an ordinary non-symbolic terminal, including a
                // detached HEAD; not an error.
                Ok(output) if output.status.code() == Some(1) => return,
                Ok(_) => {
                    self.unrepresentable = true;
                    return;
                }
                Err(_) => {
                    self.unrepresentable = true;
                    return;
                }
            }
        }
    }

    /// Every tracked pathname decides identity. Files outside the crate belong
    /// too: the claim is about the whole tracked tree. Gitlink entries recurse
    /// into initialized submodules; untracked and ignored files are never
    /// watched (they do not make the tree dirty).
    fn collect_tracked(&mut self, worktree: &Path) {
        let Ok(raw) = git_output(worktree, &["ls-files", "--stage", "-z"]) else {
            self.unrepresentable = true;
            return;
        };
        for entry in raw.split(|b| *b == 0) {
            if entry.is_empty() {
                continue;
            }
            let Some(tab) = entry.iter().position(|b| *b == b'\t') else {
                self.unrepresentable = true;
                return;
            };
            let meta = &entry[..tab];
            let path_bytes = &entry[tab + 1..];
            let mode = &meta[..meta.iter().position(|b| *b == b' ').unwrap_or(meta.len())];
            let absolute = worktree.join(OsStr::from_bytes(path_bytes));
            if mode == b"160000" {
                self.collect_gitlink(&absolute);
            } else if is_dangling_symlink(&absolute) {
                self.collect_dangling_parent(worktree, &absolute);
            } else {
                self.add(&absolute);
            }
        }
    }

    fn collect_dangling_parent(&mut self, worktree: &Path, link: &Path) {
        let Some(parent) = link.parent() else {
            self.unrepresentable = true;
            return;
        };
        let Ok(canonical) = fs::canonicalize(parent) else {
            self.unrepresentable = true;
            return;
        };
        let output = env::var_os("OUT_DIR").and_then(|path| fs::canonicalize(path).ok());
        // Cargo recursively scans directory dependencies. A localized parent
        // detects unlink/rename/create without following the dangling link;
        // a worktree/package/output ancestor would scan generated build trees
        // and cannot preserve bounded, fresh default builds. Fall back instead.
        if canonical == worktree
            || self.context.package_dir.starts_with(&canonical)
            || output.is_none_or(|dir| dir.starts_with(&canonical))
        {
            self.unrepresentable = true;
        } else {
            self.add(parent);
        }
    }

    fn collect_gitlink(&mut self, submodule: &Path) {
        if submodule.join(".git").exists() {
            let Ok(canonical) = fs::canonicalize(submodule) else {
                self.unrepresentable = true;
                return;
            };
            if !is_own_git_root(&canonical) {
                self.unrepresentable = true;
                return;
            }
            self.collect_repository(&canonical);
        } else if submodule.is_dir() {
            // Uninitialized but present: watch it so initialization is seen.
            self.add(submodule);
        } else {
            // Missing or inaccessible: conservative rebuild until it appears.
            self.unrepresentable = true;
        }
    }

    fn finish(self) -> Vec<SafeWatchPath> {
        self.paths
    }

    fn finish_result(self) -> Result<Vec<SafeWatchPath>, WatchError> {
        if self.unrepresentable {
            Err(WatchError::UnrepresentablePath(self.paths))
        } else {
            Ok(self.paths)
        }
    }
}

/// A symlink whose target does not resolve. Cargo treats it as a missing
/// `rerun-if-changed` dependency, so it needs a parent watch or conservative retry.
fn is_dangling_symlink(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_symlink() && fs::metadata(path).is_err(),
        Err(_) => false,
    }
}

/// Watch the nearest existing ancestor of a packed loose ref, but never escape
/// the refs tree into the object database.
fn nearest_existing_parent(loose: &Path, refs_tree: Option<&Path>) -> Option<PathBuf> {
    let refs_tree = refs_tree?;
    let mut current = loose.parent()?;
    loop {
        if !current.starts_with(refs_tree) {
            return None;
        }
        if current.is_dir() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

fn observe(context: &WatchContext, overrides: &BuildOverrides) -> Observation {
    let info = BuildInfo {
        revision: select_revision(context, overrides),
        tree: measure_tree(context),
    };
    let (watch_paths, discovery_incomplete) = match collect_watch_paths(context) {
        Ok(paths) => (paths, false),
        Err(WatchError::Discovery(paths)) | Err(WatchError::UnrepresentablePath(paths)) => {
            warn("Git metadata discovery was incomplete; adding a conservative rebuild");
            (paths, true)
        }
    };
    Observation {
        info,
        watch_paths,
        discovery_incomplete,
    }
}

/// Convert an absolute candidate to a package-relative ASCII spelling and prove
/// Cargo's whole-line trim plus directive-value extraction returns it byte for
/// byte. Leading or trailing ASCII whitespace is rejected: Cargo would trim it
/// to a *different* filename. Interior spaces are safe.
fn safe_relative_watch(
    context: &WatchContext,
    absolute: &Path,
) -> Result<SafeWatchPath, WatchError> {
    let relative = lexical_relative(&context.package_dir, absolute)
        .ok_or(WatchError::UnrepresentablePath(Vec::new()))?;
    let bytes = relative.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Err(WatchError::UnrepresentablePath(Vec::new()));
    }
    if bytes.iter().any(|b| *b < 0x20 || *b == 0x7f || *b >= 0x80) {
        return Err(WatchError::UnrepresentablePath(Vec::new()));
    }
    let is_ascii_whitespace = |b: u8| b == b' ' || (0x09..=0x0d).contains(&b);
    if is_ascii_whitespace(bytes[0]) || is_ascii_whitespace(bytes[bytes.len() - 1]) {
        return Err(WatchError::UnrepresentablePath(Vec::new()));
    }
    let value = String::from_utf8(bytes.to_vec())
        .map_err(|_| WatchError::UnrepresentablePath(Vec::new()))?;
    let line = format!("cargo:rerun-if-changed={value}");
    let parsed = line
        .trim()
        .strip_prefix("cargo:rerun-if-changed=")
        .map(str::as_bytes);
    if parsed != Some(bytes) {
        return Err(WatchError::UnrepresentablePath(Vec::new()));
    }
    Ok(SafeWatchPath(value))
}

/// A purely lexical relative path that does not require `target` to exist (a
/// deleted tracked file is still a required watcher).
fn lexical_relative(base: &Path, target: &Path) -> Option<OsString> {
    if !base.is_absolute() || !target.is_absolute() {
        return None;
    }
    let base_components: Vec<_> = base.components().collect();
    let target_components: Vec<_> = target.components().collect();
    let mut shared = 0;
    while shared < base_components.len()
        && shared < target_components.len()
        && base_components[shared] == target_components[shared]
    {
        shared += 1;
    }
    if shared == 0 {
        return None;
    }
    let mut out = OsString::new();
    let mut first = true;
    for _ in shared..base_components.len() {
        if !first {
            out.push("/");
        }
        out.push("..");
        first = false;
    }
    for component in &target_components[shared..] {
        if !first {
            out.push("/");
        }
        out.push(component.as_os_str());
        first = false;
    }
    Some(out)
}

/// Remove exactly Git's single terminating LF. No `trim()`, no lossy UTF-8.
fn strip_single_lf(bytes: &[u8]) -> &[u8] {
    match bytes.last() {
        Some(b'\n') => &bytes[..bytes.len() - 1],
        _ => bytes,
    }
}

/// Emit a fixed diagnostic that never includes an override value or Git output.
fn warn(message: &str) {
    println!("cargo:warning=agent-vm build provenance: {message}");
}

#[cfg(feature = "embedded-runtime")]
#[path = "build_embedded_runtime.rs"]
mod embedded_runtime;

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by Cargo for build scripts");
    let package_dir =
        fs::canonicalize(&manifest_dir).unwrap_or_else(|_| PathBuf::from(manifest_dir));
    let repo_root = package_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| package_dir.clone());
    let context = WatchContext {
        package_dir,
        repo_root,
    };

    let mode = match probe_mode(env::var_os("AGENT_VM_BUILD_PROVENANCE_STRICT")) {
        Ok(mode) => mode,
        Err(InvalidStrictMode) => {
            eprintln!(
                "agent-vm build provenance: AGENT_VM_BUILD_PROVENANCE_STRICT must be unset, \
                 empty, 0, or 1"
            );
            std::process::exit(1);
        }
    };

    let observation = observe(&context, &BuildOverrides::from_env());

    println!("cargo:rerun-if-env-changed=AGENT_VM_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-env-changed=PATH");
    println!("cargo:rerun-if-env-changed=AGENT_VM_BUILD_PROVENANCE_STRICT");
    println!("cargo:rerun-if-changed=build.rs");
    for path in &observation.watch_paths {
        println!("cargo:rerun-if-changed={}", path.as_str());
    }
    if mode == ProbeMode::Strict || observation.discovery_incomplete {
        println!("cargo:rerun-if-changed={FALLBACK_DEPENDENCY}");
    }

    let package_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    println!(
        "cargo:rustc-env=AGENT_VM_BUILD_VERSION={}",
        observation.info.version(&package_version)
    );
    #[cfg(feature = "embedded-runtime")]
    embedded_runtime::emit(&context.repo_root);
}
