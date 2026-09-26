//! The host files agent-vm must keep out of every guest mount, and the
//! decision that says whether a mount would hand one over.
//!
//! Pi (issue #90/#95/#96) keeps imported host credentials **host-side** and
//! gives the guest placeholders — Pi's mixed credential ownership, an ADR in
//! another workstream (see #91, still open). A mount that put Pi's real
//! `~/.pi/agent/auth.json` in front of the guest would defeat that for the one
//! tool agent-vm is about to launch, so this module owns the whole of "which
//! host files must never reach the guest, and is this mount one of the ways
//! they would".
//!
//! A caller hands in a path or an `fstat` result and gets a verdict; it never
//! sees `dev`/`ino`, the route set, or Pi's on-disk layout.
//! [`ProtectedHostFiles::measure`] is the trusted adapter (all the I/O);
//! [`exposing_index`] and `config::byte_path_contains` are the pure decisions,
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

    /// The single source of truth for these paths. The guest-side Pi scanner
    /// (`#93`) derives `pi/<relative>` from them; a future host-Pi resolver
    /// (`#91`) should import this table rather than re-spell the paths.
    fn home_relative(self) -> &'static str {
        match self {
            Self::PiAuth => ".pi/agent/auth.json",
            Self::PiModels => ".pi/agent/models.json",
        }
    }

    /// The same path relative to the Pi home (`~/.pi`) rather than `$HOME` —
    /// used by the static fork-omission signal, which positions the file under
    /// a *resolved* `~/.pi` target as well as under `$HOME`, and by the
    /// project-scoped guest Pi scanner (#93), which derives `pi/<relative>`.
    /// Derived from [`Self::home_relative`] so the two spellings cannot drift.
    pub(crate) fn pi_home_relative(self) -> PathBuf {
        Path::new(self.home_relative())
            .strip_prefix(PI_HOME_NAME)
            .expect("home_relative is always under ~/.pi")
            .to_path_buf()
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
#[derive(Clone, Debug)]
struct Route {
    dev: u64,
    ino: u64,
    canonical: PathBuf,
    file: ProtectedFile,
    relative: PathBuf,
}

/// One of agent-vm's own binds: *which* bind it is. The role is load-bearing
/// for the refusal text, not decoration — agent-vm makes three core binds
/// (guest home, project, state) and only one of them is the project, so a
/// broad `AGENT_VM_STATE_DIR` must not be reported as "the project directory"
/// or get the cwd-specific remedy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoreBind {
    /// The project bind: the canonicalized cwd.
    ProjectDir,
    /// The `<state dir> -> /agent-vm-state` bind.
    StateDir,
    /// The guest-`$HOME` bind, whose source is agent-vm's own state directory.
    GuestHome,
}

impl CoreBind {
    fn description(self) -> &'static str {
        match self {
            Self::ProjectDir => "project directory",
            Self::StateDir => "state directory",
            Self::GuestHome => "guest home bind",
        }
    }

    /// The remedy for an *exposure* of this bind, in the terms the user
    /// actually controls (the cwd for the project bind, `AGENT_VM_STATE_DIR`
    /// for state).
    fn remedy(self, source: &Path, pi_home: Option<&Path>) -> String {
        match (self, pi_home) {
            // The common case: the project bind *is* `$HOME`.
            (Self::ProjectDir, Some(pi_home)) if pi_home.parent() == Some(source) => {
                "run agent-vm from a project directory instead of $HOME".to_string()
            }
            (Self::ProjectDir, Some(pi_home)) => format!(
                "run agent-vm from a project directory outside {}",
                pi_home.display()
            ),
            (Self::StateDir, Some(pi_home)) => {
                format!("point AGENT_VM_STATE_DIR outside {}", pi_home.display())
            }
            (Self::GuestHome, Some(pi_home)) => format!(
                "move agent-vm's state directory outside {}",
                pi_home.display()
            ),
            (_, None) => "run agent-vm from a directory that does not contain it".to_string(),
        }
    }
}

/// One of agent-vm's own binds: the role, and the host directory it exposes.
#[derive(Clone, Debug)]
pub(crate) struct CoreHostSource {
    pub(crate) bind: CoreBind,
    pub(crate) path: PathBuf,
}

impl CoreHostSource {
    pub(crate) fn new(bind: CoreBind, path: PathBuf) -> Self {
        Self { bind, path }
    }
}

/// The measured physical route set of every protected file, plus Pi's home.
#[derive(Debug)]
pub(crate) struct ProtectedHostFiles {
    /// The home this measurement was taken from, so the fork copier can
    /// re-measure under its lock without being handed the path a second time.
    /// Kept raw (not canonicalized): `measure` canonicalizes it itself.
    host_home: Option<PathBuf>,
    /// `canonicalize($HOME)/.pi` — where the Pi home is *named*. `None` only
    /// when neither `$HOME` nor the account record could name a home, which is
    /// what [`Self::require_home`] refuses on.
    pi_home: Option<PathBuf>,
    /// Where that name *resolves*, when `~/.pi` is itself a symlink. One
    /// `canonicalize` of one measurement, not an enumeration of spellings
    /// (R4.4.5). The configured spelling above and this one answer two
    /// different questions, each with its own signal-isolating test (§7.7.3):
    /// a `:fork:follow-links` materializes the *named* `.pi/…` spelling, while
    /// a fork root spelled through the target needs the resolved one.
    resolved_pi_home: Option<PathBuf>,
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
    /// The protected file's own **canonical** path, for the message.
    pub(crate) host_path: PathBuf,
    /// The root's canonical path. Printed, so a `--mount /tmp/…` spelling on
    /// macOS does not read as a different directory from the canonical file
    /// path beside it, and consulted for the remedy below.
    pub(crate) root: PathBuf,
    /// Its path inside this mount root (`""` = the root *is* the file).
    pub(crate) relative: PathBuf,
    /// Whether the root is a regular file. A file root has **no** `:fork`
    /// remedy: `:fork` sources must be directories.
    pub(crate) is_file: bool,
    pub(crate) severity: Severity,
}

/// A fork root as the copier resolved it, at the point it is about to open it:
/// one `canonicalize` and one `metadata` of the result. `resolve` is the only
/// constructor, so the omission signal can never be derived from a declaration
/// spelling — the unbounded-alias problem four rounds of spelling enumeration
/// failed to close (ADR-0020).
///
/// It proves that resolution **succeeded at that instant**. It does not pin the
/// directory, its identity, or its relationship to Pi's home for any later
/// instant; the `(dev, ino, is_file)` are the root's values *at resolve time*
/// and are stale the moment anything changes. `Clone` is deliberately not
/// derived: a clone would copy "this was canonicalized once", not existence or
/// freshness. See R3.1 for the ordering this participates in.
pub(crate) struct ResolvedRoot {
    path: PathBuf,
    dev: u64,
    ino: u64,
    is_file: bool,
}

impl ResolvedRoot {
    /// The only constructor: one `canonicalize` plus one `metadata` of the
    /// result, at the point the copier is about to open the root. The
    /// `canonicalize` message matches `copy_root`'s pre-existing one, so a root
    /// that vanishes between the source-kind check and the copy keeps failing
    /// closed with the same error.
    pub(crate) fn resolve(source: &Path) -> Result<Self> {
        let path = source
            .canonicalize()
            .with_context(|| format!("resolving fork root {}", source.display()))?;
        let metadata = fs::metadata(&path)
            .with_context(|| format!("resolving fork root {}", path.display()))?;
        Ok(Self {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
            is_file: metadata.is_file(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
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
                host_home: None,
                pi_home: None,
                resolved_pi_home: None,
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
        // Where that name resolves, when `~/.pi` is itself a symlink. One
        // `canonicalize` of one measurement; not a spelling enumeration. It is
        // not a substitute for the configured spelling (the route set is the
        // resolver's job); it exists so the *remedy* and the advisories
        // recognise the target spelling too, and so a fork root spelled
        // through the target still gets the static signal.
        let resolved_pi_home = pi_home.canonicalize().ok();
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
            host_home: Some(home.to_path_buf()),
            pi_home: Some(pi_home),
            resolved_pi_home,
            severity,
            routes,
            identity_ids,
            identity_files,
        })
    }

    /// Re-measure the host state and union it with this snapshot (see
    /// [`Self::union`]). The fork copier takes this under the per-fork lock, so
    /// a root or credential created since the launch's first measurement is
    /// seen. Retention is **identity-only**: a positively identified inode is
    /// never forgotten, but the routes, the configured Pi home and the resolved
    /// Pi home come from the fresh measurement, so a historical *pathname* is
    /// deliberately not retained (R3.5).
    pub(crate) fn refreshed(&self) -> Result<Self> {
        Ok(self.union(&Self::measure(self.host_home.as_deref())?))
    }

    /// The union of two measurements, for the fork copier. `measure` is a
    /// snapshot, and host state can change between two of them: an atomic
    /// credential replacement can make a later snapshot *forget* an inode an
    /// earlier one positively identified (a surviving hardlink still holds the
    /// old credential bytes). Omission is a safety property, so the copier keeps
    /// every **identity** either snapshot saw (R1, R3.5).
    ///
    /// Identities are deduplicated by `(dev, ino, file)`, which is their key.
    ///
    /// The routes, the configured Pi home and the resolved Pi home are
    /// **fresh-wins** — `other`'s (`refreshed` measures the copy point last)
    /// (R3.5). A historical *pathname* is deliberately never retained: a
    /// positively identified inode is omitted wherever it appears, but a path
    /// that named a credential earlier in the same launch is not omitted by
    /// that history alone, so a new unrelated inode at a former credential path
    /// is copied (the drop ruling's cost, pinned in §7.7.4).
    pub(crate) fn union(&self, other: &Self) -> Self {
        let mut identity_ids = self.identity_ids.clone();
        let mut identity_files = self.identity_files.clone();
        for (identity, file) in other.identity_ids.iter().zip(&other.identity_files) {
            if !identity_ids.contains(identity) {
                identity_ids.push(*identity);
                identity_files.push(*file);
            }
        }
        Self {
            // `refreshed` re-measures from *this* snapshot's home, so both
            // agree here; the first is what `refreshed` handed to `measure`.
            host_home: self.host_home.clone().or_else(|| other.host_home.clone()),
            // Fresh-wins (R3.5): the copy point's measurement describes the
            // world the copy is about to read.
            pi_home: other.pi_home.clone(),
            resolved_pi_home: other.resolved_pi_home.clone(),
            // The more protective verdict wins; a `~/.pi` present in either
            // snapshot is enough to make a live window dangerous.
            severity: if self.severity == Severity::Refuse || other.severity == Severity::Refuse {
                Severity::Refuse
            } else {
                Severity::Advise
            },
            routes: other.routes.clone(),
            identity_ids,
            identity_files,
        }
    }

    /// Fail closed when a launch declares mounts we cannot reason about:
    /// without a home we cannot locate the Pi home (it may still exist on disk
    /// under a daemon or CI), so we cannot decide.
    ///
    /// This is the **fallback** path only. `run.rs` resolves the launch's home
    /// as `$HOME`, or the account record's `pw_dir` when `$HOME` is unset, so
    /// an `env -i`/daemon/CI launch still gets a real home and this refusal is
    /// reached only when *both* sources fail (no passwd entry for the uid).
    pub(crate) fn require_home(&self, mount_count: usize) -> Result<()> {
        if self.pi_home.is_none() && mount_count > 0 {
            bail!(
                "neither $HOME nor the account record could name your home directory, so agent-vm \
                 cannot tell whether a --mount would expose host Pi credential files. Set HOME, \
                 or drop --mount."
            );
        }
        Ok(())
    }

    /// Would binding `root` expose a protected file? Deepest route wins.
    pub(crate) fn exposure(&self, root: &Path) -> Result<Option<Exposure>> {
        Ok(self.matches(root)?.into_iter().next())
    }

    /// Every protected file's path relative to the copier's resolved `root`,
    /// including files that do not exist yet — the fork copier's second signal.
    /// A protected file this root cannot reach is absent.
    ///
    /// Two independent sources, unioned: the **measured routes** (which catch a
    /// symlink target, a hardlink, a mount alias, or any branch the `$HOME`
    /// spelling does not name) and the **static path table** relative to
    /// `root`. The route half is also the only one that can fold an *aliased*
    /// root spelling, because a route is a hit by canonical containment **or**
    /// by `(dev, ino)` identity (R4.3). The static table is pure pathname
    /// arithmetic and deliberately makes no identity claim: it keeps omission
    /// effective when no measurement saw `root` (a fork root renamed away and
    /// recreated leaves the route set with no entry for it, while the identity
    /// set sees only the inode that is there now).
    ///
    /// No syscalls: a reviewed property of this body and its callees
    /// ([`Self::matches_at`], [`Self::static_relatives`], [`push_relative`]),
    /// pinned by the `relatives_under_does_not_re_resolve_the_captured_root`
    /// test (R4.5) — **not** enforced by the `Vec` return type.
    pub(crate) fn relatives_under(&self, root: &ResolvedRoot) -> Vec<(PathBuf, ProtectedFile)> {
        let mut relatives: Vec<(PathBuf, ProtectedFile)> = Vec::new();
        for exposure in self.matches_at(root.path(), root.dev, root.ino, root.is_file) {
            push_relative(&mut relatives, exposure.relative, exposure.file);
        }
        for (relative, file) in self.static_relatives(root.path()) {
            push_relative(&mut relatives, relative, file);
        }
        relatives
    }

    /// The static half of [`Self::relatives_under`]: where each protected file
    /// *would* sit under `root`, from the path table alone — the configured
    /// `~/.pi` and, when `~/.pi` is a symlink, the target it resolved to. It
    /// reads no measured route and no `(dev, ino)`, so it holds for a root no
    /// measurement saw. It is a *supplement*: a hardlink or a symlinked
    /// credential target the table cannot name is still covered only by the
    /// measured identity, and an *aliased* root spelling is folded by
    /// `matches_at`'s identity arm, never here (R4.3, S6′).
    fn static_relatives(&self, root: &Path) -> Vec<(PathBuf, ProtectedFile)> {
        let mut relatives = Vec::new();
        for pi_home in [self.pi_home.as_deref(), self.resolved_pi_home.as_deref()]
            .into_iter()
            .flatten()
        {
            for file in ProtectedFile::ALL {
                if let Ok(relative) = pi_home.join(file.pi_home_relative()).strip_prefix(root) {
                    push_relative(&mut relatives, relative.to_path_buf(), file);
                }
            }
        }
        relatives
    }

    /// Advisory-only: is `root` at/inside the host Pi home? Recognises the two
    /// Pi-home spellings of one measurement (`~/.pi` and, when it is a symlink,
    /// its canonical target). Path-based, so an alias reached any other way may
    /// miss a *warning*; it is never a refusal.
    /// `Path::starts_with` is true for equal paths, so the Pi home itself is
    /// covered without a separate equality test.
    pub(crate) fn inside_pi_home(&self, root: &Path) -> bool {
        [self.pi_home.as_deref(), self.resolved_pi_home.as_deref()]
            .into_iter()
            .flatten()
            .any(|pi_home| root.starts_with(pi_home))
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
    ///
    /// `discovered_by` is the *rendered* provenance of a discovered bind
    /// (e.g. ``--mount ~/code:follow-links``), not a spelling to wrap: two
    /// `:follow-links` declarations can discover one bind, and the caller is
    /// the only place that knows whether the attribution is unambiguous.
    pub(crate) fn message(
        &self,
        source_spelling: &str,
        exposure: &Exposure,
        discovered_by: Option<&str>,
    ) -> String {
        if exposure.severity == Severity::Advise {
            return format!(
                "==> {source_spelling} would expose host Pi credentials if you run `pi auth \
                 login` on the host; there is no ~/{PI_HOME_NAME} today"
            );
        }
        let discovered = match discovered_by {
            Some(from) => format!(" (discovered by {from})"),
            None => String::new(),
        };
        format!(
            "--mount {source_spelling} would expose the {} {}{}{discovered}\n\
             agent-vm keeps host Pi credentials host-side and gives the guest placeholders.\n\
             {}",
            exposure.file.description(),
            exposure.host_path.display(),
            inside(exposure),
            self.remedy(source_spelling, exposure),
        )
    }

    /// The remedy sentence for one exposure, **conditional on the root**.
    ///
    /// A blind `:fork` recommendation is harmful or impossible for two common
    /// roots: forking `$HOME` copies every *other* secret in it into project
    /// state (a worse exposure than the live bind being refused), and a
    /// regular file cannot be forked at all — `:fork` sources must be
    /// directories. `:fork` is exactly right at or inside the Pi home, which
    /// is the case it was written for.
    fn remedy(&self, source_spelling: &str, exposure: &Exposure) -> String {
        if exposure.is_file {
            return "Mount a different source instead: this file cannot be mounted at all."
                .to_string();
        }
        if self.inside_pi_home(&exposure.root) {
            return format!(
                "Use `--mount {source_spelling}:fork` (a fork copies the source once and omits \
                 that file), or mount a path that does not contain it."
            );
        }
        // Broad (an ancestor *above* the Pi home: `$HOME`, `/`) or an
        // unrelated branch (a symlinked Pi home's target parent). Forking it
        // would copy everything under the source — including every other
        // secret there — into writable project state.
        format!(
            "Mount a narrower path that does not contain it. `--mount {source_spelling}:fork` is \
             not a substitute here: it copies everything under {source_spelling} into project \
             state."
        )
    }

    /// Human-readable refusal for one of agent-vm's own binds. Names the bind's
    /// role (project / state / guest home) and the remedy in the terms the user
    /// controls, because the project bind is the canonicalized cwd while the
    /// other two come from agent-vm's own state directory.
    pub(crate) fn core_message(&self, source: &CoreHostSource, exposure: &Exposure) -> String {
        format!(
            "agent-vm's {} {} contains the {} {}{}; {}",
            source.bind.description(),
            source.path.display(),
            exposure.file.description(),
            exposure.host_path.display(),
            inside(exposure),
            source.bind.remedy(&source.path, self.pi_home()),
        )
    }

    /// The advisories for a `--mount` declaration at/inside the Pi home:
    /// `live_bind` adds the `:fork` recommendation (a fork's *content* is
    /// already handled by the copy engine, so it needs only the
    /// platform-artifact warning). Advisory-only — never a refusal.
    pub(crate) fn mount_advisories(
        &self,
        declaration: &Path,
        source_spelling: &str,
        live_bind: bool,
    ) -> Vec<String> {
        if !self.inside_pi_home(declaration) {
            return Vec::new();
        }
        let mut advisories = Vec::new();
        if live_bind {
            advisories.push(format!(
                "==> {source_spelling} is a live bind of host Pi state; :fork is recommended so \
                 the guest cannot write host Pi state and host changes cannot leak in"
            ));
        }
        advisories.extend(self.platform_artifact_advisories());
        advisories
    }

    /// The advisories for one of agent-vm's own binds at/inside the Pi home.
    /// `~/.pi/extensions` as the *project* bind is a writable live window onto
    /// host Pi state with no `--mount` at all, which is exactly the case #90's
    /// warning deliverable is about.
    pub(crate) fn core_advisories(&self, source: &CoreHostSource) -> Vec<String> {
        if !self.inside_pi_home(&source.path) {
            return Vec::new();
        }
        let mut advisories = vec![format!(
            "==> agent-vm's {} {} is a live bind of host Pi state; {} so the guest cannot write \
             host Pi state and host changes cannot leak in",
            source.bind.description(),
            source.path.display(),
            source.bind.remedy(&source.path, self.pi_home()),
        )];
        advisories.extend(self.platform_artifact_advisories());
        advisories
    }

    /// Host Pi artifacts may be built for this host's OS/arch. Fires for every
    /// mount or core bind at/inside the Pi home, on every launch — including a
    /// reused fork, whose `host` `preflight_forks` has repointed at committed
    /// data.
    fn platform_artifact_advisories(&self) -> Vec<String> {
        self.pi_home()
            .map(|pi_home| {
                vec![format!(
                    "==> Host Pi extensions and installed packages under {} may be built for this \
                     host's OS/arch and may not run in the Linux guest",
                    pi_home.display()
                )]
            })
            .unwrap_or_default()
    }

    /// Every route `root` hits, deepest first — the live-bind path
    /// (advisories, refusals, [`Self::exposure`]). Stats and canonicalizes the
    /// caller's spelling, then delegates to [`Self::matches_at`].
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
        let canonical =
            fs::canonicalize(root).context(cannot_determine(&root.display().to_string()))?;
        Ok(self.matches_at(
            &canonical,
            metadata.dev(),
            metadata.ino(),
            metadata.is_file(),
        ))
    }

    /// The pure decision: every measured route a root described by its
    /// canonical pathname and `(dev, ino, is_file)` hits, deepest first. No
    /// syscalls — the copier's path calls this with the values
    /// [`ResolvedRoot::resolve`] captured, and no body here re-resolves.
    fn matches_at(&self, canonical: &Path, dev: u64, ino: u64, is_file: bool) -> Vec<Exposure> {
        let mut hits = Vec::new();
        for route in &self.routes {
            // Identity folds aliases paths cannot: `canonicalize` does not fold
            // macOS firmlinks or Linux host bind mounts, so an aliased root
            // spelling shares `(dev, ino)` with a route while neither pathname
            // is a prefix of the other (R4.3). Containment decides the ordinary
            // case, and the case a root's canonical path equals a route's while
            // `(dev, ino)` differ — see ADR-0020.
            let identity = route.dev == dev && route.ino == ino;
            let contained = crate::config::byte_path_contains(
                canonical.as_os_str().as_bytes(),
                route.canonical.as_os_str().as_bytes(),
            );
            if !identity && !contained {
                continue;
            }
            // The `unwrap_or` is load-bearing behaviour, not a defensive
            // default: a firmlink-spelled root shares `(dev, ino)` with a route
            // while its canonical pathname is disjoint, so `strip_prefix`
            // fails for every route the identity arm just matched. Falling back
            // to the empty prefix uses the route's own remainder
            // (`agent/auth.json`) directly, which is what names both protected
            // files under the aliased root. Early-`continue` here would
            // silently drop firmlink/bind protection while every
            // canonical-spelling test stayed green (ADR-0020).
            let relative = relative_from(
                route
                    .canonical
                    .strip_prefix(canonical)
                    .unwrap_or(Path::new("")),
                &route.relative,
            );
            hits.push(Exposure {
                file: route.file,
                host_path: relative_from(&route.canonical, &route.relative),
                root: canonical.to_path_buf(),
                relative,
                is_file,
                severity: self.severity,
            });
        }
        hits
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

/// Append `(relative, file)` unless an identical pair is already present — the
/// two sources of [`ProtectedHostFiles::relatives_under`] deliberately overlap.
fn push_relative(
    relatives: &mut Vec<(PathBuf, ProtectedFile)>,
    relative: PathBuf,
    file: ProtectedFile,
) {
    let entry = (relative, file);
    if !relatives.contains(&entry) {
        relatives.push(entry);
    }
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

/// `--mount {src} would expose … (as {relative} inside {root})`. The root is
/// printed **canonically**, so on macOS a `--mount /tmp/…` spelling (whose real
/// path is `/private/tmp/…`) does not read as a different directory from the
/// canonical file path beside it.
fn inside(exposure: &Exposure) -> String {
    if exposure.relative.as_os_str().is_empty() {
        String::new()
    } else {
        format!(
            " (as {} inside {})",
            exposure.relative.display(),
            exposure.root.display()
        )
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
        let relatives = protected.relatives_under(&resolve_root(&home.join(".pi")));
        assert!(relatives.contains(&(PathBuf::from("agent/models.json"), ProtectedFile::PiModels)));
        assert!(relatives.contains(&(PathBuf::from("agent/auth.json"), ProtectedFile::PiAuth)));
    }

    /// M13: a fork root that did not exist when the route set was measured
    /// still gets a relative-path signal. The `$HOME` spelling's last existing
    /// ancestor is `$HOME` itself, so the measured routes can only name
    /// `.pi/agent/auth.json` (relative to `$HOME`) — never `agent/auth.json`,
    /// which is what a copier of `~/.pi` sees. The static table answers for the
    /// recreated root, for **both** protected files.
    #[test]
    fn relatives_under_names_protected_files_the_measurement_never_saw() {
        let (_home, home) = home();
        // No `~/.pi` at measurement time: the route set ends at `$HOME`.
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();
        // A host writer recreates the Pi home with a credential *after*
        // measurement and before the copy.
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        write(&home.join(".pi/agent/models.json"), "{}");

        let relatives = protected.relatives_under(&resolve_root(&home.join(".pi")));
        assert!(
            relatives.contains(&(PathBuf::from("agent/auth.json"), ProtectedFile::PiAuth)),
            "{relatives:?}"
        );
        assert!(
            relatives.contains(&(PathBuf::from("agent/models.json"), ProtectedFile::PiModels)),
            "{relatives:?}"
        );
    }

    /// The static half must stay component-wise: an unrelated root and a
    /// sibling whose name is a byte prefix of the Pi home get no signal.
    #[test]
    fn relatives_under_static_signal_respects_component_boundaries() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        let unrelated = tempfile::tempdir().unwrap();
        let unrelated = unrelated.path().canonicalize().unwrap();
        assert!(
            protected
                .relatives_under(&resolve_root(&unrelated))
                .is_empty()
        );

        // `$HOME/.pistachio` is a byte prefix of `$HOME/.pi/agent/auth.json`
        // but not a component prefix of it.
        let sibling = home.join(".pistachio");
        fs::create_dir(&sibling).unwrap();
        assert!(
            protected
                .relatives_under(&resolve_root(&sibling))
                .is_empty()
        );
    }

    /// R1/R3.5: `union` keeps every **identity** either snapshot saw (so an
    /// atomic credential replacement cannot make the copier forget an inode a
    /// hardlink still holds), while the **routes, `pi_home` and
    /// `resolved_pi_home` come from the copy point** — the historical route a
    /// launch measured is deliberately *not* retained, because a new unrelated
    /// inode at a former credential path must be copied (the drop ruling's
    /// cost, §7.7.4).
    #[test]
    fn union_keeps_every_identity_and_takes_the_fresh_measurement() {
        let self_route = Route {
            dev: 1,
            ino: 2,
            canonical: PathBuf::from("/alias/pi"),
            file: ProtectedFile::PiAuth,
            relative: PathBuf::from("agent/auth.json"),
        };
        let fresh_route = Route {
            dev: 3,
            ino: 4,
            canonical: PathBuf::from("/host-bind/pi"),
            file: ProtectedFile::PiModels,
            relative: PathBuf::from("agent/models.json"),
        };
        let self_snapshot = ProtectedHostFiles {
            host_home: Some(PathBuf::from("/home")),
            pi_home: Some(PathBuf::from("/home/.pi")),
            resolved_pi_home: Some(PathBuf::from("/ext/pi")),
            severity: Severity::Advise,
            routes: vec![self_route],
            identity_ids: vec![(1, 2)],
            identity_files: vec![ProtectedFile::PiAuth],
        };
        let fresh = ProtectedHostFiles {
            host_home: Some(PathBuf::from("/home")),
            pi_home: Some(PathBuf::from("/home/.pi")),
            resolved_pi_home: Some(PathBuf::from("/other/pi")),
            severity: Severity::Refuse,
            routes: vec![fresh_route],
            identity_ids: vec![(3, 4)],
            identity_files: vec![ProtectedFile::PiModels],
        };

        let unioned = self_snapshot.union(&fresh);
        // Identities are additive, both halves survive.
        assert_eq!(unioned.identity_ids, vec![(1, 2), (3, 4)]);
        assert_eq!(
            unioned.identity_files,
            vec![ProtectedFile::PiAuth, ProtectedFile::PiModels]
        );
        // Fresh-wins: exactly the copy point's single route — the launch-only
        // `/alias/pi` route is not retained.
        assert_eq!(
            unioned.routes.len(),
            1,
            "the launch-only route must be dropped"
        );
        assert_eq!(unioned.routes[0].canonical, PathBuf::from("/host-bind/pi"));
        assert_eq!(unioned.pi_home(), Some(Path::new("/home/.pi")));
        assert_eq!(
            unioned.resolved_pi_home.as_deref(),
            Some(Path::new("/other/pi"))
        );
        assert_eq!(unioned.severity, Severity::Refuse);
    }

    /// Anti-over-omission control (§7.7.4): 50 `refreshed` rounds over
    /// unchanged host state must leave the relative set bounded and unchanged.
    ///
    /// This pins boundedness, not freshness. Because the host state does not
    /// change, a union that accumulated routes or Pi-home spellings would
    /// re-add *identical* values, which dedup by whole-value equality — the
    /// set would stay identical and this test would still pass. The fresh-wins
    /// property is pinned instead by the `union` unit test
    /// (`union_keeps_every_identity_and_takes_the_fresh_measurement`) and by
    /// the S3-B / S4 / S5 mutation kills for `resolved_pi_home`, `pi_home` and
    /// the routes (§7.7.5).
    #[test]
    fn refreshes_do_not_grow_the_relative_set() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{}");
        let root = resolve_root(&home.join(".pi"));
        let mut snapshot = ProtectedHostFiles::measure(Some(&home)).unwrap();
        let first = snapshot.relatives_under(&root);
        assert!(!first.is_empty(), "the fixture must name the credential");
        for _ in 0..50 {
            snapshot = snapshot.refreshed().unwrap();
        }
        assert_eq!(
            snapshot.relatives_under(&root),
            first,
            "refreshed grew the relative set"
        );
    }

    /// Construct a genuine [`ResolvedRoot`] through its only constructor
    /// against a real directory (R3.3: never a struct literal).
    fn resolve_root(path: &Path) -> ResolvedRoot {
        ResolvedRoot::resolve(path).unwrap()
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

        // The Pi home itself: `:fork` is exactly the remedy (a fork omits the
        // protected files and copies everything else).
        assert_eq!(
            protected.message("~/.pi", &exposure, None),
            format!(
                "--mount ~/.pi would expose the host Pi credential file {home}/.pi/agent/auth.json \
                 (as agent/auth.json inside {home}/.pi)\n\
                 agent-vm keeps host Pi credentials host-side and gives the guest placeholders.\n\
                 Use `--mount ~/.pi:fork` (a fork copies the source once and omits that file), \
                 or mount a path that does not contain it.",
                home = home.display()
            )
        );
        // A discovered bind names the declaration it came from.
        assert!(
            protected
                .message("~/.pi", &exposure, Some("--mount ~/code:follow-links"))
                .contains("(discovered by --mount ~/code:follow-links)")
        );

        // A root *above* the Pi home ($HOME, `/`, …): forking it would copy
        // every other secret under it into project state, so the message must
        // lead with a narrower path and must not present `:fork` as the fix.
        let broad = protected.exposure(&home).unwrap().unwrap();
        let message = protected.message(&home.display().to_string(), &broad, None);
        assert!(message.contains("Mount a narrower path"), "{message}");
        assert!(
            !message.contains(&format!("Use `--mount {}:fork`", home.display())),
            "a broad root must not recommend forking itself: {message}"
        );
        assert!(
            message.contains(&format!(
                "it copies everything under {} into project state",
                home.display()
            )),
            "{message}"
        );

        // A root that *is* the credential file: `:fork` is impossible (a
        // `:fork` source must be a directory), so it must not be mentioned.
        let file = protected
            .exposure(&home.join(".pi/agent/auth.json"))
            .unwrap()
            .unwrap();
        let message = protected.message("~/.pi/agent/auth.json", &file, None);
        assert!(message.contains("cannot be mounted at all"), "{message}");
        assert!(!message.contains(":fork"), "{message}");
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
        // Guard the naive `starts_with` byte-prefix version of containment.
        assert!(!crate::config::byte_path_contains(
            b"/a/pi",
            b"/a/pistachio"
        ));
        assert!(crate::config::byte_path_contains(b"/a/pi", b"/a/pi"));
        assert!(crate::config::byte_path_contains(b"/a/pi", b"/a/pi/x"));

        // The `exposure` half needs a root that a naive byte-prefix
        // implementation would actually get wrong. `exposure(~/pistachio)`
        // cannot be that case: every route is an ancestor of the *file*, so a
        // plain sibling under `$HOME` is either longer than the route or
        // mismatches before the separator. A route whose canonical path merely
        // *begins with* the root's bytes has to be constructed: make `~/.pi` a
        // symlink to `<tmp>/pistachio/pi` and mount the sibling `<tmp>/pi`.
        let (_home, home) = home();
        let target_root = tempfile::tempdir().unwrap();
        let target = target_root.path().canonicalize().unwrap();
        write(&target.join("pistachio/pi/agent/auth.json"), "{}");
        std::os::unix::fs::symlink(target.join("pistachio/pi"), home.join(".pi")).unwrap();
        fs::create_dir(target.join("pi")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        assert!(
            protected
                .exposure(&target.join("pistachio/pi"))
                .unwrap()
                .is_some(),
            "the symlink target itself is the Pi home"
        );
        assert!(
            protected.exposure(&target.join("pi")).unwrap().is_none(),
            "<tmp>/pi is a byte prefix of <tmp>/pistachio but not a containing component"
        );
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
        assert!(
            error.contains("neither $HOME nor the account record"),
            "{error}"
        );
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

    /// A refusal of one of agent-vm's own binds names *that* bind's role and
    /// remedy, not "the project directory" for all three. A broad
    /// `AGENT_VM_STATE_DIR` is the case that made this a defect: the project
    /// bind's cwd remedy would be useless advice for it.
    #[test]
    fn core_refusals_name_the_bind_role_and_its_own_remedy() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();
        let exposure = protected.exposure(&home.join(".pi")).unwrap().unwrap();

        let state = CoreHostSource::new(CoreBind::StateDir, home.join(".pi"));
        let message = protected.core_message(&state, &exposure);
        assert!(message.contains("state directory"), "{message}");
        assert!(message.contains("AGENT_VM_STATE_DIR"), "{message}");
        assert!(!message.contains("project directory"), "{message}");

        let guest_home = CoreHostSource::new(CoreBind::GuestHome, home.join(".pi"));
        let message = protected.core_message(&guest_home, &exposure);
        assert!(message.contains("guest home bind"), "{message}");
        assert!(message.contains("outside"), "{message}");

        // The advisories use the same role vocabulary, for the binds that
        // expose no protected file.
        let advisories = protected.core_advisories(&guest_home).join("\n");
        assert!(advisories.contains("guest home bind"), "{advisories}");
        assert!(
            advisories.contains("Host Pi extensions and installed packages"),
            "{advisories}"
        );
    }

    /// S2 (unit): the **configured** `pi_home` static entry names the protected
    /// files when the root is an ancestor of `~/.pi` even though the route
    /// chain restarted at the link target, so **no measured route** is under
    /// `$HOME`. Nothing else can answer: the identity of `$HOME` matches no
    /// route, containment is false, and `resolved_pi_home` does not strip under
    /// `$HOME`.
    #[test]
    fn static_relatives_names_the_configured_pi_home_for_a_root_above_it() {
        let (_home, home) = home();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        // `~/.pi -> /ext/pi`: a real directory, no credential.
        fs::create_dir(ext.join("pi")).unwrap();
        std::os::unix::fs::symlink(ext.join("pi"), home.join(".pi")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        let root = resolve_root(&home);
        assert!(
            protected
                .matches_at(root.path(), root.dev, root.ino, root.is_file)
                .is_empty(),
            "measure restarts the chain at the link target: no route is under $HOME"
        );
        for file in ProtectedFile::ALL {
            let relative = Path::new(PI_HOME_NAME).join(file.pi_home_relative());
            assert!(
                protected
                    .static_relatives(&home)
                    .contains(&(relative.clone(), file)),
                "the configured pi_home names {relative:?}"
            );
            assert!(
                protected.relatives_under(&root).contains(&(relative, file)),
                "it reaches relatives_under through the static half"
            );
        }
    }

    /// S6′ (unit): the pure `matches_at` folds a root that is **identity-equal**
    /// to a route while its canonical pathname is disjoint — the shape of a
    /// macOS firmlink or a Linux host bind. Both protected files come back with
    /// the route's own remainder, and the static half is silent for that
    /// disjoint pathname, so the identity arm is demonstrably the only answer
    /// (R4.3, must-fix 1). Portable: no privileges, no platform alias, and no
    /// forged `ResolvedRoot` — the `(dev, ino)` came from a real directory.
    #[test]
    fn matches_at_folds_a_root_that_is_identity_equal_to_a_route() {
        let (_home, home) = home();
        let ext = tempfile::tempdir().unwrap();
        let ext = ext.path().canonicalize().unwrap();
        fs::create_dir(ext.join("pi")).unwrap();
        std::os::unix::fs::symlink(ext.join("pi"), home.join(".pi")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        let metadata = fs::metadata(ext.join("pi")).unwrap();
        // A *different, disjoint* canonical pathname with the same (dev, ino).
        let alias = Path::new("/System/Volumes/Data/disjoint/pi");
        let relatives: Vec<(PathBuf, ProtectedFile)> = protected
            .matches_at(alias, metadata.dev(), metadata.ino(), metadata.is_file())
            .into_iter()
            .map(|exposure| (exposure.relative, exposure.file))
            .collect();
        assert!(
            relatives.contains(&(PathBuf::from("agent/auth.json"), ProtectedFile::PiAuth)),
            "{relatives:?}"
        );
        assert!(
            relatives.contains(&(PathBuf::from("agent/models.json"), ProtectedFile::PiModels)),
            "{relatives:?}"
        );
        assert!(
            protected.static_relatives(alias).is_empty(),
            "the static half names nothing under a disjoint alias"
        );
    }

    /// S7: [`ProtectedHostFiles::relatives_under`] performs no I/O. A body that
    /// re-stats or re-canonicalizes the captured root and falls back to an
    /// empty set fails the second assertion. The `Vec` return type does not
    /// enforce this; the test does (R4.5).
    #[test]
    fn relatives_under_does_not_re_resolve_the_captured_root() {
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{}");
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();
        let root = resolve_root(&home.join(".pi/agent"));
        let first = protected.relatives_under(&root);
        assert!(!first.is_empty(), "the fixture must name the credential");

        // Make the root's pathname unavailable while retaining the captured
        // `ResolvedRoot` (its `(dev, ino)` are T1's values).
        fs::rename(home.join(".pi/agent"), home.join(".pi/gone")).unwrap();
        assert!(root.path().canonicalize().is_err());
        let second = protected.relatives_under(&root);
        assert_eq!(
            second, first,
            "relatives_under re-resolved the captured root"
        );
    }

    /// The macOS firmlink pin (R4.1–R4.3): a root spelled through the data
    /// volume's firmlink canonicalizes to a string **different** from the
    /// canonical route path while sharing `(dev, ino)`, so containment is false
    /// and the identity fold is the only thing that names the files. Exercises
    /// the real [`ProtectedHostFiles::matches`] and [`ProtectedHostFiles::matches_at`].
    /// Skipped where the firmlink does not exist (Linux/CI).
    #[test]
    fn a_firmlink_spelled_root_names_both_files_through_the_real_matches() {
        let firmlink_root = Path::new("/System/Volumes/Data");
        if !firmlink_root.exists() {
            return;
        }
        let (_home, home) = home();
        write(&home.join(".pi/agent/auth.json"), "{\"token\":\"t\"}");
        write(&home.join(".pi/agent/models.json"), "{}");
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();

        // The firmlink spelling of `$HOME`: same directory, different string.
        let alias_home = firmlink_root.join(home.strip_prefix("/").unwrap());
        let canonical = home.canonicalize().unwrap();
        let alias_canonical = alias_home.canonicalize().unwrap();
        assert_ne!(
            alias_canonical, canonical,
            "the firmlink spelling must canonicalize differently"
        );
        let canonical_stat = fs::metadata(&canonical).unwrap();
        let alias_stat = fs::metadata(&alias_canonical).unwrap();
        assert_eq!(
            (canonical_stat.dev(), canonical_stat.ino()),
            (alias_stat.dev(), alias_stat.ino()),
            "the firmlink shares (dev, ino) with the canonical path"
        );

        // The live-bind adapter (`matches`) and the copier's pure `matches_at`
        // both name both protected files through the aliased root. Containment
        // is false (the strings are disjoint); only identity can answer.
        for hits in [
            protected.matches(&alias_home).unwrap(),
            protected.matches_at(
                &alias_canonical,
                alias_stat.dev(),
                alias_stat.ino(),
                alias_stat.is_file(),
            ),
        ] {
            let relatives: Vec<(PathBuf, ProtectedFile)> = hits
                .into_iter()
                .map(|exposure| (exposure.relative, exposure.file))
                .collect();
            assert!(
                relatives.contains(&(PathBuf::from(".pi/agent/auth.json"), ProtectedFile::PiAuth)),
                "{relatives:?}"
            );
            assert!(
                relatives.contains(&(
                    PathBuf::from(".pi/agent/models.json"),
                    ProtectedFile::PiModels
                )),
                "{relatives:?}"
            );
        }
        // The static half is silent for the disjoint alias, so the identity
        // arm is demonstrably what answers.
        assert!(protected.static_relatives(&alias_canonical).is_empty());
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
    }
}
