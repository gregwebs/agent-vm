//! The host files agent-vm must keep out of every guest mount, and the
//! decision that says whether a mount would hand one over.
//!
//! Pi (issue #90/#95/#96) keeps imported host credentials **host-side** and
//! gives the guest placeholders (ADR-0011). A mount that put Pi's real
//! `~/.pi/agent/auth.json` in front of the guest would defeat that for the one
//! tool agent-vm is about to launch, so this module owns the whole of "which
//! host files must never reach the guest, and is this mount one of the ways
//! they would".
//!
//! A caller hands in a path or an `fstat` result and gets a verdict; it never
//! sees `dev`/`ino`, the route set, or Pi's on-disk layout.
//! [`ProtectedHostFiles::measure`] is the trusted adapter (all the I/O);
//! [`exposing_index`]/[`byte_path_contains`] are the pure decisions,
//! machine-checked per ADR-0018.
//!
//! **Why not `host_paths.rs`** (which the issue lists): that module is the
//! `GuestStateDir`/`atomic_write` primitive for *state* files. Pi path
//! knowledge there would couple unrelated concerns.

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use vstd::prelude::*;

/// `$HOME`-relative directory Pi calls its home.
const PI_HOME_NAME: &str = ".pi";

/// A host file whose bytes must never be reachable from a guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtectedFile {
    /// `~/.pi/agent/auth.json` — the provider credential material.
    PiAuth,
    /// `~/.pi/agent/models.json` — the provider/endpoint configuration.
    PiModels,
}

impl ProtectedFile {
    pub(crate) const ALL: [ProtectedFile; 2] = [Self::PiAuth, Self::PiModels];

    /// The single source of truth for these paths. `#93`/`#94` spell the same
    /// two files; when a host-Pi resolver lands there it should import this
    /// table rather than re-spell the paths.
    fn home_relative(self) -> &'static str {
        match self {
            Self::PiAuth => ".pi/agent/auth.json",
            Self::PiModels => ".pi/agent/models.json",
        }
    }

    /// For operator-facing messages.
    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::PiAuth => "host Pi credential file",
            Self::PiModels => "host Pi provider-configuration file",
        }
    }
}

/// How bad an exposure is, decided once by whether `$HOME/.pi` exists.
///
/// Without this split, *every* user who mounts `$HOME` or `/` — including
/// users who have never installed Pi — would get a hard error about Pi
/// credentials. With no `~/.pi` there is nothing to leak today, so that same
/// route only advises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Severity {
    /// `$HOME/.pi` exists: refuse the launch, whatever the two files' own
    /// existence. A live bind is a window onto bytes written *after* boot, and
    /// `pi auth login` on the host can create `auth.json` inside it.
    Refuse,
    /// `$HOME/.pi` is absent: a named, narrow residual risk, not a leak.
    Advise,
}

/// One measured route: a real directory that physically contains a protected
/// file — or the file itself — and where the file sits inside it.
#[derive(Debug)]
struct Route {
    dev: u64,
    ino: u64,
    canonical: PathBuf,
    file: ProtectedFile,
    relative: PathBuf,
}

/// The measured physical route set of every protected file, plus Pi's home.
#[derive(Debug)]
pub(crate) struct ProtectedHostFiles {
    /// `$HOME/.pi`, once `$HOME` is known — `None` only when `$HOME` is unset.
    pi_home: Option<PathBuf>,
    severity: Severity,
    routes: Vec<Route>,
    /// `(dev, ino)` of the protected files themselves (not their ancestors),
    /// parallel to [`Self::identity_files`] so the copy engine's per-node
    /// lookup needs no temporary allocation. ADR-0018's contract is stated
    /// over this slice.
    identity_ids: Vec<(u64, u64)>,
    identity_files: Vec<ProtectedFile>,
}

/// What a mount root would expose.
#[derive(Debug)]
pub(crate) struct Exposure {
    pub(crate) file: ProtectedFile,
    /// The protected file's own path, for the message.
    pub(crate) host_path: PathBuf,
    /// Its path inside this mount root (`""` = the root *is* the file).
    pub(crate) relative: PathBuf,
    pub(crate) severity: Severity,
}

impl ProtectedHostFiles {
    /// Measure from the host `$HOME`. Fails closed on an undecidable ancestor.
    ///
    /// The route set is the **ancestor chain of each protected file's resolved
    /// path**, deepest first: a directory physically contains the file exactly
    /// when it is an ancestor of the path the file's `$HOME`-relative spelling
    /// resolves to. Resolving as the walk descends is what makes
    /// `~/.pi -> /Volumes/ext/pi` protected at the target *and* at the
    /// target's parents, while correctly **not** recording `$HOME`: the guest
    /// resolves a `~/.pi` symlink in guest space, where it dangles.
    pub(crate) fn measure(host_home: Option<&Path>) -> Result<Self> {
        let Some(home) = host_home else {
            return Ok(Self {
                pi_home: None,
                severity: Severity::Advise,
                routes: Vec::new(),
                identity_ids: Vec::new(),
                identity_files: Vec::new(),
            });
        };
        let base = match fs::canonicalize(home) {
            Ok(path) => path,
            // A `$HOME` that does not exist cannot contain Pi state. Treated as
            // an empty route set, not an error: `require_home` is about `$HOME`
            // being *unset*, and a nonexistent source is already rejected by
            // the pre-existing "validating --mount source" check.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => home.to_path_buf(),
            Err(error) => {
                return Err(error).context(cannot_determine(&home.display().to_string()));
            }
        };
        let pi_home = base.join(PI_HOME_NAME);
        let severity = match fs::symlink_metadata(&pi_home) {
            // Existence of the *files* is irrelevant: the Pi home is what makes
            // a live window dangerous (see `Severity`).
            Ok(_) => Severity::Refuse,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Severity::Advise,
            Err(error) => {
                return Err(error).context(cannot_determine(&pi_home.display().to_string()));
            }
        };
        let mut routes = Vec::new();
        for file in ProtectedFile::ALL {
            routes.extend(measure_file(&base, file)?);
        }
        let mut identity_ids = Vec::new();
        let mut identity_files = Vec::new();
        for route in routes
            .iter()
            .filter(|route| route.relative.as_os_str().is_empty())
        {
            let identity = (route.dev, route.ino);
            if identity_ids.contains(&identity) {
                continue;
            }
            identity_ids.push(identity);
            identity_files.push(route.file);
        }
        Ok(Self {
            pi_home: Some(pi_home),
            severity,
            routes,
            identity_ids,
            identity_files,
        })
    }

    /// Fail closed when a launch declares mounts we cannot reason about:
    /// without `$HOME` we cannot locate the Pi home (it may still exist on disk
    /// under a daemon or CI), so we cannot decide.
    pub(crate) fn require_home(&self, mount_count: usize) -> Result<()> {
        if self.pi_home.is_none() && mount_count > 0 {
            bail!(
                "$HOME is not set, so agent-vm cannot tell whether a --mount would expose host \
                 Pi credential files. Set HOME, or drop --mount."
            );
        }
        Ok(())
    }

    /// Would binding `root` expose a protected file? Deepest route wins.
    pub(crate) fn exposure(&self, root: &Path) -> Result<Option<Exposure>> {
        Ok(self.matches(root)?.into_iter().next())
    }

    /// Every protected file's path relative to `root`, including files that do
    /// not exist yet — the fork copier's second signal. A protected file this
    /// root cannot reach is absent.
    pub(crate) fn relatives_under(&self, root: &Path) -> Result<Vec<(PathBuf, ProtectedFile)>> {
        let mut relatives: Vec<(PathBuf, ProtectedFile)> = Vec::new();
        for exposure in self.matches(root)? {
            let entry = (exposure.relative, exposure.file);
            if !relatives.contains(&entry) {
                relatives.push(entry);
            }
        }
        Ok(relatives)
    }

    /// Advisory-only: is `root` at/inside the host Pi home? Path-based, so an
    /// aliased spelling may miss a *warning*; it is never a refusal.
    pub(crate) fn inside_pi_home(&self, root: &Path) -> bool {
        self.pi_home
            .as_ref()
            .is_some_and(|pi_home| root == pi_home || root.starts_with(pi_home))
    }

    /// The identity set the fork copier consults per `fstat`ed node.
    pub(crate) fn identities(&self) -> ProtectedIdentities<'_> {
        ProtectedIdentities {
            ids: &self.identity_ids,
            files: &self.identity_files,
        }
    }

    pub(crate) fn pi_home(&self) -> Option<&Path> {
        self.pi_home.as_deref()
    }

    /// Human-readable refusal for an explicit or `follow-links`-discovered
    /// live bind. One place, so tests assert one string.
    pub(crate) fn message(
        &self,
        source_spelling: &str,
        exposure: &Exposure,
        discovered_from: Option<&str>,
    ) -> String {
        if exposure.severity == Severity::Advise {
            return format!(
                "==> {source_spelling} would expose host Pi credentials if you run `pi auth \
                 login` on the host; there is no ~/{PI_HOME_NAME} today"
            );
        }
        let discovered = match discovered_from {
            Some(from) => format!(" (discovered by --mount {from}:follow-links)"),
            None => String::new(),
        };
        format!(
            "--mount {source_spelling} would expose the {} {}{}{discovered}\n\
             agent-vm keeps host Pi credentials host-side and gives the guest placeholders.\n\
             Use `--mount {source_spelling}:fork` (a fork copies the source once and omits that \
             file), or mount a path that does not contain it.",
            exposure.file.description(),
            exposure.host_path.display(),
            inside(exposure),
        )
    }

    /// Human-readable refusal for one of agent-vm's own binds. Names the remedy
    /// in *cwd* terms: the project bind is the canonicalized cwd, so a launch
    /// from `$HOME` (or from inside `~/.pi`) is what exposes the file.
    pub(crate) fn core_message(&self, source: &Path, exposure: &Exposure) -> String {
        let remedy = match self.pi_home() {
            Some(pi_home) if pi_home.parent() == Some(source) => {
                "run agent-vm from a project directory instead of $HOME".to_string()
            }
            Some(pi_home) => format!(
                "run agent-vm from a project directory outside {}",
                pi_home.display()
            ),
            None => "run agent-vm from a project directory that does not contain it".to_string(),
        };
        format!(
            "the project directory {} contains the {} {}{}; {remedy}",
            source.display(),
            exposure.file.description(),
            exposure.host_path.display(),
            inside(exposure),
        )
    }

    /// Every route `root` hits, deepest first. Pure over the measured routes.
    fn matches(&self, root: &Path) -> Result<Vec<Exposure>> {
        let metadata = match fs::metadata(root) {
            Ok(metadata) => metadata,
            // The pre-existing "validating --mount source" check reports a
            // missing source; this is not an exposure.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).context(cannot_determine(&root.display().to_string()));
            }
        };
        let dev = metadata.dev();
        let ino = metadata.ino();
        let canonical =
            fs::canonicalize(root).context(cannot_determine(&root.display().to_string()))?;
        let mut hits = Vec::new();
        for route in &self.routes {
            // Identity folds aliases paths cannot: `canonicalize` does not fold
            // macOS firmlinks or Linux host bind mounts. Containment covers
            // filesystems where inode identity is unreliable.
            let identity = route.dev == dev && route.ino == ino;
            let contained = byte_path_contains(
                canonical.as_os_str().as_bytes(),
                route.canonical.as_os_str().as_bytes(),
            );
            if !identity && !contained {
                continue;
            }
            let relative = relative_from(
                route
                    .canonical
                    .strip_prefix(&canonical)
                    .unwrap_or(Path::new("")),
                &route.relative,
            );
            hits.push(Exposure {
                file: route.file,
                host_path: relative_from(&route.canonical, &route.relative),
                relative,
                severity: self.severity,
            });
        }
        Ok(hits)
    }
}

/// The traversal half of `measure`: the ancestor chain of one protected file's
/// resolved path, deepest first.
fn measure_file(base: &Path, file: ProtectedFile) -> Result<Vec<Route>> {
    let relative = Path::new(file.home_relative());
    let components: Vec<OsString> = relative.iter().map(|part| part.to_os_string()).collect();
    let mut resolved = fs::canonicalize(base).ok();
    let mut consumed = 0usize;
    let mut cursor = base.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        // `cursor` is canonical at every step after the first, so the only
        // symlink this can cross is a new one at the last component — and
        // `canonicalize` restarts the ancestor chain at its target.
        let candidate = cursor.join(component);
        match fs::symlink_metadata(&candidate) {
            Ok(_) => match candidate.canonicalize() {
                Ok(target) => {
                    cursor = target;
                    resolved = Some(cursor.clone());
                    consumed = index + 1;
                }
                // A **dangling** symlink: the component exists, but resolves
                // nowhere, so there is nothing at the target to protect. Stop
                // descending exactly as for `ENOENT` — the last resolvable
                // ancestor keeps the literal remainder, and it is that
                // ancestor (not the link's target) a mount could still expose.
                // Any other resolution error stays a hard failure.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(error).context(cannot_determine(&candidate.display().to_string()));
                }
            },
            // The file does not exist yet: the last existing ancestor carries
            // the literal remainder. This is what protects a Pi home whose
            // `auth.json` appears only later (`pi auth login` during a boot).
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error).context(cannot_determine(&candidate.display().to_string()));
            }
        }
    }
    let Some(mut node) = resolved else {
        return Ok(Vec::new());
    };
    let mut remainder: PathBuf = components[consumed..].iter().collect();
    let mut routes = Vec::new();
    loop {
        let metadata =
            fs::symlink_metadata(&node).context(cannot_determine(&node.display().to_string()))?;
        // Every canonical ancestor is a real directory; the file itself is
        // recorded even when it is not, because it carries the empty remainder.
        if metadata.is_dir() || remainder.as_os_str().is_empty() {
            routes.push(Route {
                dev: metadata.dev(),
                ino: metadata.ino(),
                canonical: node.clone(),
                file,
                relative: remainder.clone(),
            });
        }
        let Some(parent) = node.parent() else { break };
        match node.file_name() {
            // `Path::join` with an empty tail would add a trailing separator,
            // which must never reach a `relative` compared against a
            // copier-built path.
            Some(name) if remainder.as_os_str().is_empty() => {
                remainder = PathBuf::from(name);
            }
            Some(name) => remainder = Path::new(name).join(&remainder),
            None => break,
        }
        node = parent.to_path_buf();
    }
    Ok(routes)
}

fn cannot_determine(path: &str) -> String {
    format!("cannot determine whether a mount would expose {path}")
}

/// `base` extended by `remaining`, without `Path::join`'s trailing separator
/// when `remaining` is empty — a `relative` is compared against copier-built
/// paths, where `.pi/agent/auth.json/` and `.pi/agent/auth.json` differ.
fn relative_from(base: &Path, remaining: &Path) -> PathBuf {
    if remaining.as_os_str().is_empty() {
        base.to_path_buf()
    } else {
        base.join(remaining)
    }
}

/// `--mount {src} would expose … (as {relative} inside that mount)`.
fn inside(exposure: &Exposure) -> String {
    if exposure.relative.as_os_str().is_empty() {
        String::new()
    } else {
        format!(" (as {} inside that mount)", exposure.relative.display())
    }
}

/// Copy-engine view: identity membership only — no paths, no I/O.
pub(crate) struct ProtectedIdentities<'a> {
    ids: &'a [(u64, u64)],
    files: &'a [ProtectedFile],
}

impl ProtectedIdentities<'_> {
    pub(crate) fn matched(&self, dev: u64, ino: u64) -> Option<ProtectedFile> {
        if self.is_empty() {
            return None;
        }
        exposing_index(dev, ino, self.ids).map(|index| self.files[index])
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

verus! {

/// The index of the first entry in `ids` whose `(dev, ino)` identity matches —
/// the identity half of "would this mount root expose a protected file".
/// Stated plainly: what is proved is that the decision **is** that comparison
/// (no false negative, and the returned index is the *first*, i.e. most
/// specific, match), not that a root's identity means what the caller thinks.
pub fn exposing_index(dev: u64, ino: u64, ids: &[(u64, u64)]) -> (result: Option<usize>)
    ensures
        match result {
            None => forall|j: int| 0 <= j < ids@.len() ==> ids@[j] != (dev, ino),
            Some(i) => i < ids@.len()
                && ids@[i as int] == (dev, ino)
                && forall|j: int| 0 <= j < i as int ==> ids@[j] != (dev, ino),
        },
{
    let mut i: usize = 0;
    while i < ids.len()
        invariant
            i <= ids.len(),
            forall|j: int| 0 <= j < i ==> ids@[j] != (dev, ino),
        decreases ids.len() - i,
    {
        if ids[i] == (dev, ino) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// `ancestor` is `descendant` itself, or a whole **component-wise** prefix of
/// it: `a/b` is one of `a/b/c` but `a/b` is *not* one of `a/bc`. The
/// containment half of the exposure decision, reusing `config.rs`'s already
/// proved `is_separator_prefix` so the sibling-prefix property is
/// machine-checked rather than re-tested. Byte-level so the decision is
/// translatable; the `Path` → bytes measurement is the trusted adapter in
/// `ProtectedHostFiles::matches`.
pub fn byte_path_contains(ancestor: &[u8], descendant: &[u8]) -> (result: bool)
    ensures
        result == (ancestor@ == descendant@
            || crate::config::is_separator_prefix(ancestor@, descendant@)),
{
    let alen = ancestor.len();
    let dlen = descendant.len();
    assert(alen == ancestor@.len());
    assert(dlen == descendant@.len());
    // A longer "ancestor" is never a prefix of its descendant.
    if alen > dlen {
        assert(ancestor@ != descendant@);
        assert(!crate::config::is_separator_prefix(ancestor@, descendant@));
        return false;
    }
    let mut i: usize = 0;
    while i < alen
        invariant
            i <= alen,
            alen <= dlen,
            alen == ancestor@.len(),
            dlen == descendant@.len(),
            forall|j: int| 0 <= j < i ==> ancestor@[j] == descendant@[j],
        decreases alen - i,
    {
        if ancestor[i] != descendant[i] {
            assert(ancestor@ != descendant@);
            assert(!crate::config::is_separator_prefix(ancestor@, descendant@));
            return false;
        }
        i += 1;
    }
    if alen == dlen {
        assert(ancestor@ =~= descendant@);
        true
    } else {
        assert(forall|j: int| 0 <= j < alen ==> ancestor@[j] == descendant@[j]);
        descendant[alen] == crate::config::GUEST_PATH_SEPARATOR
    }
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    /// A `$HOME` tempdir plus the canonical path to point assertions at (macOS
    /// resolves `/var` → `/private/var`).
    fn home() -> (tempfile::TempDir, PathBuf) {
        let home = tempfile::tempdir().unwrap();
        let canonical = home.path().canonicalize().unwrap();
        (home, canonical)
    }

    fn write(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn relative_of(exposure: &Option<Exposure>) -> String {
        exposure
            .as_ref()
            .expect("expected an exposure")
            .relative
            .display()
            .to_string()
    }

    #[test]
    fn measure_records_routes_deepest_first() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        write(&home.join(".pi/agent/models.json"), "{}");
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        assert_eq!(
            relative_of(&protected.exposure(&home).unwrap()),
            ".pi/agent/auth.json"
        );
        assert_eq!(
            relative_of(&protected.exposure(&home.join(".pi")).unwrap()),
            "agent/auth.json"
        );
        assert_eq!(
            relative_of(&protected.exposure(&home.join(".pi/agent")).unwrap()),
            "auth.json"
        );
        assert_eq!(
            relative_of(
                &protected
                    .exposure(&home.join(".pi/agent/auth.json"))
                    .unwrap()
            ),
            ""
        );
        // Both files, not just the first route that happens to match.
        let relatives = protected.relatives_under(&home.join(".pi")).unwrap();
        assert!(relatives.contains(&(PathBuf::from("agent/models.json"), ProtectedFile::PiModels)));
        assert!(relatives.contains(&(PathBuf::from("agent/auth.json"), ProtectedFile::PiAuth)));
    }

    /// The TOCTOU-defeating case: an implementation that measured only existing
    /// *files* would pass every other test and fail this one.
    #[test]
    fn missing_pi_files_still_protect_their_ancestors() {
        let (_home, home) = home();
        fs::create_dir(home.join(".pi")).unwrap();
        assert!(!home.join(".pi/agent").exists());
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        for root in [home.clone(), home.join(".pi")] {
            let exposure = protected
                .exposure(&root)
                .unwrap()
                .unwrap_or_else(|| panic!("{} must expose a protected file", root.display()));
            assert_eq!(exposure.severity, Severity::Refuse);
        }
        assert_eq!(
            relative_of(&protected.exposure(&home).unwrap()),
            ".pi/agent/auth.json"
        );
        assert_eq!(
            relative_of(&protected.exposure(&home.join(".pi")).unwrap()),
            "agent/auth.json"
        );
    }

    /// Asymmetric pair with `measure_records_routes_deepest_first`: the guest
    /// resolves a `~/.pi` symlink in guest space, where it dangles, so the
    /// route set is the *target's* branch — the ancestor chain, not `$HOME`.
    #[test]
    fn symlinked_pi_home_is_protected_at_its_target_not_at_home() {
        let (_home, home) = home();
        let target_root = tempfile::tempdir().unwrap();
        let target_canonical = target_root.path().canonicalize().unwrap();
        fs::create_dir(target_canonical.join("pi")).unwrap();
        std::os::unix::fs::symlink(target_canonical.join("pi"), home.join(".pi")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        assert!(
            protected.exposure(&home).unwrap().is_none(),
            "$HOME dangles"
        );
        assert!(
            protected
                .exposure(&target_canonical.join("pi"))
                .unwrap()
                .is_some()
        );
        assert!(protected.exposure(&target_canonical).unwrap().is_some());
    }

    #[test]
    fn symlinked_credential_file_out_of_home_is_protected_at_its_target() {
        let (_home, home) = home();
        let secrets = tempfile::tempdir().unwrap();
        let secrets_canonical = secrets.path().canonicalize().unwrap();
        write(&secrets_canonical.join("auth.json"), "{\"token\":\"t\"}");
        fs::create_dir_all(home.join(".pi/agent")).unwrap();
        std::os::unix::fs::symlink(
            secrets_canonical.join("auth.json"),
            home.join(".pi/agent/auth.json"),
        )
        .unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        let exposure = protected.exposure(&secrets_canonical).unwrap().unwrap();
        assert_eq!(exposure.file, ProtectedFile::PiAuth);
        assert_eq!(exposure.severity, Severity::Refuse);
    }

    #[test]
    fn hardlink_and_symlink_aliases_hit_by_identity() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        // A hardlink under an unrelated name, and a symlink alias to the Pi
        // home. Neither alias path is a string prefix of the real path, so a
        // purely lexical check would miss both.
        fs::create_dir(home.join("backup")).unwrap();
        fs::hard_link(
            home.join(".pi/agent/auth.json"),
            home.join("backup/copy.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink(home.join(".pi"), home.join("pi-link")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        for alias in [home.join("backup/copy.json"), home.join("pi-link")] {
            let exposure = protected
                .exposure(&alias)
                .unwrap()
                .unwrap_or_else(|| panic!("{} must expose by identity", alias.display()));
            assert_eq!(exposure.file, ProtectedFile::PiAuth);
            assert!(
                !exposure.host_path.starts_with(&alias),
                "a lexical check would have missed {}",
                alias.display()
            );
        }
        // The accepted residual gap (ADR-0020): a hardlink *inside* an
        // otherwise-unrelated live bind is not detectable at the root level —
        // catching it would need an unbounded walk of every bind root. The
        // fork copier's per-node `fstat` does catch it.
        assert!(protected.exposure(&home.join("backup")).unwrap().is_none());
    }

    /// One assertion for the whole refusal text: `mount.rs` has no message of
    /// its own, and this is the string a test elsewhere can rely on.
    #[test]
    fn refusal_message_names_the_file_and_the_fork_remedy() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();
        let exposure = protected.exposure(&home.join(".pi")).unwrap().unwrap();

        assert_eq!(
            protected.message("~/.pi", &exposure, None),
            format!(
                "--mount ~/.pi would expose the host Pi credential file {}/.pi/agent/auth.json \
                 (as agent/auth.json inside that mount)\n\
                 agent-vm keeps host Pi credentials host-side and gives the guest placeholders.\n\
                 Use `--mount ~/.pi:fork` (a fork copies the source once and omits that file), \
                 or mount a path that does not contain it.",
                home.display()
            )
        );
        // A discovered bind names the declaration it came from.
        assert!(
            protected
                .message("~/.pi", &exposure, Some("~/code"))
                .contains("(discovered by --mount ~/code:follow-links)")
        );
    }

    /// A dangling link is not an undecidable ancestor: it resolves nowhere, so
    /// there is nothing at the target to protect, and the last *resolvable*
    /// ancestor is what a mount could still expose. Reporting it as "cannot
    /// determine" would fail every launch with a `--mount` for a user whose
    /// credential lives on a volume that is not mounted today.
    #[test]
    fn dangling_symlink_stops_the_descent_without_an_error() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/other.json"), "{}");
        let missing = home.join("nowhere/auth.json");
        std::os::unix::fs::symlink(&missing, home.join(".pi/agent/auth.json")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        // The link's own directory and every ancestor above it are still routes.
        assert!(protected.exposure(&home).unwrap().is_some());
        assert_eq!(
            relative_of(&protected.exposure(&home.join(".pi")).unwrap()),
            "agent/auth.json"
        );
        // Resolving the link itself finds nothing, so it exposes nothing.
        assert!(
            protected
                .exposure(&home.join(".pi/agent/auth.json"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sibling_prefix_is_not_a_hit() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        fs::create_dir(home.join(".pistachio")).unwrap();
        fs::create_dir(home.join(".pi-old")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        // Guard the naive `starts_with` byte-prefix version of containment.
        assert!(!byte_path_contains(b"/a/pi", b"/a/pistachio"));
        for sibling in [home.join(".pistachio"), home.join(".pi-old")] {
            assert!(
                protected.exposure(&sibling).unwrap().is_none(),
                "{} must not be a hit",
                sibling.display()
            );
        }
    }

    #[test]
    fn unreadable_ancestor_fails_closed() {
        if unsafe { libc::geteuid() } == 0 {
            return; // mode 0 is not restrictive for root
        }
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        use std::os::unix::fs::PermissionsExt;
        let agent = home.join(".pi/agent");
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o000)).unwrap();

        let error = ProtectedHostFiles::measure(Some(&home))
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot determine"), "{error}");
        assert!(error.contains(&agent.display().to_string()), "{error}");
    }

    #[test]
    fn absent_pi_home_downgrades_to_advice() {
        let (_home, home) = home();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        let exposure = protected.exposure(&home).unwrap().unwrap();
        assert_eq!(exposure.severity, Severity::Advise);
        // The other side of the boundary: once `~/.pi` exists the same route
        // is a hard refusal, and the two files need not exist.
        fs::create_dir(home.join(".pi")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();
        assert_eq!(
            protected.exposure(&home).unwrap().unwrap().severity,
            Severity::Refuse
        );
    }

    #[test]
    fn no_home_is_inert_until_a_mount_is_declared() {
        let protected = ProtectedHostFiles::measure(None).unwrap();
        assert!(protected.require_home(0).is_ok());
        let error = protected.require_home(1).unwrap_err().to_string();
        assert!(error.contains("$HOME is not set"), "{error}");
        assert!(protected.exposure(Path::new("/")).unwrap().is_none());
        assert!(!protected.inside_pi_home(Path::new("/.pi")));
    }

    #[test]
    fn models_json_is_protected_independently() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/models.json"), "{}");
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        let exposure = protected
            .exposure(&home.join(".pi/agent/models.json"))
            .unwrap()
            .unwrap();
        assert_eq!(exposure.file, ProtectedFile::PiModels);
        assert_eq!(exposure.relative, PathBuf::new());
        assert_eq!(exposure.severity, Severity::Refuse);
    }

    proptest::proptest! {
        #[test]
        fn exposing_index_matches_naive_position(
            ids in proptest::collection::vec((0u64..8, 0u64..8), 0..8),
            dev in 0u64..8,
            ino in 0u64..8,
        ) {
            let naive = ids.iter().position(|entry| *entry == (dev, ino));
            proptest::prop_assert_eq!(exposing_index(dev, ino, &ids), naive);
        }

        /// A genuinely independent oracle: `Path::components` rather than a
        /// re-implementation of the loop.
        #[test]
        fn byte_path_contains_matches_components_oracle(
            ancestor in proptest::collection::vec("[a-z]{1,3}", 1..4),
            extra in proptest::collection::vec("[a-z]{1,3}", 0..3),
            other in proptest::collection::vec("[a-z]{1,3}", 1..4),
        ) {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let descendant = ancestor.iter().chain(&extra).cloned().collect::<Vec<_>>().join("/");
            let ancestor_path = ancestor.join("/");
            for candidate in [descendant.as_str(), other.join("/").as_str()] {
                let a = Path::new(OsStr::from_bytes(ancestor_path.as_bytes()));
                let d = Path::new(OsStr::from_bytes(candidate.as_bytes()));
                proptest::prop_assert_eq!(
                    byte_path_contains(a.as_os_str().as_bytes(), candidate.as_bytes()),
                    d.starts_with(a),
                );
            }
        }
    }
}
