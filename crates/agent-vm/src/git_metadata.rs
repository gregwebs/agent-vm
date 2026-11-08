//! Automatic Git metadata mounts for a linked worktree (#535).
//!
//! A guest sees only what is bind-mounted. A linked worktree's source is the
//! project bind, but its `.git` is a *pointer file* naming a directory outside
//! that bind — so `git log` in the guest fails with "not a git repository" even
//! though the host resolves the same directory fine.
//!
//! This module reads the pointer and, when it describes Git's own
//! linked-worktree layout *for this launch directory*, asks
//! [`crate::mount::prepare`] for one or two extra live binds at the paths Git
//! itself computed. It decides nothing about whether those binds are *allowed*:
//! claims, protected files, the writable config directory, persisted-HOME
//! collisions and the topology plan are the existing pipeline's job, so an
//! automatic bind is refused exactly as the equivalent `--mount` would be.
//!
//! # The `.git` file is a claim, not authority
//!
//! Accepting a pointer because it *looks* like Git's is how a hand-written
//! `.git` file becomes a bind of `/etc` at a read-only guest path. So the
//! decision is narrower: the claimed directory must be Git's own registration
//! for *this* directory (registered under `<common>/worktrees/`, back-pointer
//! `gitdir` naming this launch directory's `.git`), both directories must pass
//! the Git-directory validity contract in [`git_dir_contract`] and
//! [`head_is_valid`], and the guest must resolve the same relationship the host
//! does (§[`guest_spelling_consistent`]). What that proves is that Git would open
//! the directory as this worktree's repository — **not** that the user may read
//! it, and not that a directory forged to satisfy every one of Git's rules is
//! not attacker content. A forgery needs prior write access to the target
//! directory; ADR-0062 records the trade-off, and [`GitMetadataReport`] narrows
//! (does not close) the window between discovery and binding.
//!
//! # Discovery runs before `prepare`, and writes nothing
//!
//! `prepare` is the first boundary allowed to create host state (fork
//! publication), so discovery sits on its near side: every step here is
//! `symlink_metadata`, a bounded no-follow read, `read_link` or `canonicalize`.
//! No Git process runs, so no repository config — `core.fsmonitor`, hooks — is
//! executed to validate a repository.

use crate::mount::{
    BindAccess, ExtraMount, GitMetadataRole, MountOrigin, MountPolicy, MountRequest,
    PreparedMountPlan, PreparedVolumeSource,
};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use vstd::prelude::*;

/// `--git-mount`, read once from the launch options (the `--no-config-mounts`
/// precedent: one policy value, derived at one site, and deliberately no
/// environment variable — write access to a repository is a per-launch choice).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum GitMountMode {
    #[default]
    #[value(name = "ro")]
    ReadOnly,
    #[value(name = "rw")]
    ReadWrite,
    #[value(name = "off")]
    Off,
}

/// What `launch` needs to place metadata binds next to the core binds.
///
/// Named fields, not three positional `&Path`s: `project_dir` and `project_guest`
/// are equal for every ordinary launch, so transposing them would be invisible
/// until a remapped project silently mounted the wrong spellings.
pub(crate) struct LaunchTopology<'a> {
    /// Canonical host launch directory (`ProjectSession::for_cwd`).
    pub(crate) project_dir: &'a Path,
    /// The guest path the project is mirrored at — `/workspace` when remapped.
    pub(crate) project_guest: &'a Path,
    /// Guest paths of agent-vm's own binds, for the collision fact. The refusal
    /// itself is `mount::claim`'s, so an *equal* path is left to it.
    pub(crate) core_guest_mounts: &'a [PathBuf],
    /// The **host** sources of those same binds, canonical where the path exists
    /// (see [`canonical_host_source`]).
    ///
    /// A guest spelling is a lexical string: a symlinked alias can make a bind
    /// look unrelated to the directory it really exposes. Measured here, an
    /// automatic bind that would enclose the launcher's own state, home or project
    /// source is refused whatever the guest spelled.
    pub(crate) core_host_sources: &'a [PathBuf],
    /// The declarations this launch already selected, config then argv, in
    /// selection order.
    ///
    /// The automatic requests are appended after them, and the runtime mounts a
    /// parent before its child, so an automatic bind *inside* an explicit or
    /// config route would silently outrank the access the user declared for it
    /// (spec: a mode "does not make another explicit writable route
    /// read-only"). Discovery is where that is visible, so it is where it is
    /// decided.
    pub(crate) selected: &'a [MountRequest],
}

/// The automatic requests for one launch, plus what the launch must say about
/// them. Empty for `off`, for a directory that is not a linked worktree, and for
/// metadata the guest already reaches through another route.
#[derive(Debug, Default)]
pub(crate) struct GitMetadataMounts {
    requests: Vec<MountRequest>,
    report: GitMetadataReport,
}

impl GitMetadataMounts {
    /// Split the requests from the report so `launch` can append the requests
    /// without cloning them and still describe them afterwards.
    pub(crate) fn into_parts(self) -> (Vec<MountRequest>, GitMetadataReport) {
        (self.requests, self.report)
    }
}

/// What the launch says about the requests once they are handed to `prepare`.
#[derive(Debug, Default)]
pub(crate) struct GitMetadataReport {
    /// The launch directory, so a race refusal names the worktree the reader
    /// would repair rather than the metadata path it was told about.
    worktree: PathBuf,
    /// What the guest ends up with. [`MetadataState::Silent`] iff this launch has
    /// no automatic requests and nothing to report, which is what keeps every
    /// existing launch's diagnostics byte-identical.
    state: MetadataState,
    /// `(guest, canonical host)` for each request, measured at discovery.
    expected: Vec<(PathBuf, PathBuf)>,
}

/// What the guest can do with the metadata after this launch, and therefore what
/// the notice may claim.
///
/// A field of the report rather than an `Option<BindAccess>`: "no automatic bind"
/// has two distinct causes — the metadata is inside the writable project bind, or
/// a declaration the user wrote already carries it — and saying "read-only" for
/// either would misstate the access the guest actually has.
#[derive(Debug, Default)]
enum MetadataState {
    /// No automatic request and nothing to say.
    #[default]
    Silent,
    /// Automatic binds, with this access.
    Bound(BindAccess),
    /// Inside the writable project bind, so the guest already reaches it and an
    /// `ro` bind there would carve a read-only hole in the project.
    InProjectBind,
    /// Carried by an enclosing declaration of the user's, which keeps its own
    /// access.
    Enclosing(MountOrigin),
}

impl MetadataState {
    /// Record that one metadata directory was skipped, without displacing a bind.
    ///
    /// Two directories can be placed differently — one carried by a declaration,
    /// the other bound — and a launch that added *any* automatic request has to
    /// describe that: "no automatic mount was added" would be false. The first
    /// skip reason is kept otherwise, so the notice does not flip between two
    /// equally true sentences.
    fn skip(&mut self, candidate: Self) {
        if matches!(self, Self::Silent) {
            *self = candidate;
        }
    }
}

impl GitMetadataReport {
    /// The launch notice, or `None` when this launch has no automatic binds and
    /// nothing to report.
    ///
    /// Printed after `selection.notice()`, so a rejected topology emits nothing
    /// at all: the notice describes a plan that reached the builder.
    pub(crate) fn notice(&self) -> Option<String> {
        match &self.state {
            MetadataState::Silent => None,
            MetadataState::Bound(BindAccess::ReadOnly) => Some(
                "==> Git metadata: linked worktree, read-only (--git-mount=rw|off to change)"
                    .to_string(),
            ),
            // Says what `rw` actually grants, because these are the *shared*
            // directories: a hook or config the guest writes runs on the host.
            MetadataState::Bound(BindAccess::ReadWrite) => Some(
                "==> Git metadata: linked worktree, writable: the guest can change refs, objects, \
                 hooks and config shared by every worktree of this repository"
                    .to_string(),
            ),
            MetadataState::InProjectBind => Some(
                "==> Git metadata: linked worktree, inside the project bind (writable); no \
                 automatic mount was added"
                    .to_string(),
            ),
            MetadataState::Enclosing(origin) => Some(format!(
                "==> Git metadata: linked worktree, reachable through {origin}; no automatic \
                 mount was added"
            )),
        }
    }

    /// Whether this report describes automatic requests that `prepare` will see.
    /// The two skipped states hold no request, so a `prepare` failure on such a
    /// launch keeps exactly the chain it had before the feature.
    fn has_requests(&self) -> bool {
        matches!(self.state, MetadataState::Bound(_))
    }

    /// Wrap a [`crate::mount::prepare`] failure with the one fact the refusal
    /// cannot know — that automatic binds were part of this plan and one flag
    /// removes them.
    ///
    /// Returns the error unchanged when there are no automatic requests, so an
    /// ordinary launch's chain has exactly the frames it always had.
    pub(crate) fn annotate(&self, error: anyhow::Error) -> anyhow::Error {
        if !self.has_requests() {
            return error;
        }
        error.context(
            "preparing mounts (including automatic Git metadata mounts for this linked worktree; \
             --git-mount=off launches without them, and every other check still applies)",
        )
    }

    /// Narrows — does not close — the gap between discovery and binding: every
    /// prepared volume at an expected guest path must still carry the canonical
    /// host discovery validated.
    ///
    /// `prepare` canonicalizes each live bind again (`expand_follow_links`), so a
    /// spelling repointed in between is observable here. A *deterministic*
    /// rejection never reaches this call. This is not TOCTOU protection: a
    /// repoint after `prepare`, or at bind time, is the accepted residual of
    /// ADR-0038's stable-tree assumption (ADR-0062 D2b).
    pub(crate) fn verify_prepared(&self, plan: &PreparedMountPlan) -> Result<(), GitMetadataError> {
        for (guest, expected) in &self.expected {
            let prepared = plan
                .volumes
                .iter()
                .find(|volume| &volume.guest == guest)
                .map(|volume| match &volume.source {
                    PreparedVolumeSource::ReadOnlyBind(host)
                    | PreparedVolumeSource::WritableBind(host) => host.clone(),
                });
            if prepared.as_deref() == Some(expected.as_path()) {
                continue;
            }
            return Err(GitMetadataError {
                worktree: self.worktree.clone(),
                reason: Refusal::ChangedWhilePreparing {
                    guest: guest.clone(),
                    expected: expected.clone(),
                    prepared,
                },
            });
        }
        Ok(())
    }
}

/// The only entry point. Reads host metadata; writes nothing.
pub(crate) fn discover(
    mode: GitMountMode,
    topology: LaunchTopology<'_>,
) -> Result<GitMetadataMounts, GitMetadataError> {
    let access = match git_mount_access(mode.facts()) {
        MountAccessDecision::Skip => return Ok(GitMetadataMounts::default()),
        MountAccessDecision::ReadOnly => BindAccess::ReadOnly,
        MountAccessDecision::ReadWrite => BindAccess::ReadWrite,
    };

    let measured = measure(topology.project_dir);
    match worktree_verdict(measured.facts) {
        // Not a linked worktree at all: a submodule gitfile, `--separate-git-dir`,
        // a plain directory, a symlink. Byte-identical to today's plan.
        WorktreeVerdict::NotLinked => return Ok(GitMetadataMounts::default()),
        WorktreeVerdict::Linked => {}
        broken => {
            return Err(GitMetadataError::relationship(
                topology.project_dir,
                broken,
                &measured,
            ));
        }
    }
    let (Some(worktree), Some(common)) = (&measured.worktree, &measured.common) else {
        // Unreachable while the verdict is `Linked` (it requires both), but a
        // fail-closed default beats an unwrap in a security path.
        return Err(GitMetadataError::relationship(
            topology.project_dir,
            WorktreeVerdict::NotRegistered,
            &measured,
        ));
    };

    let coverage = worktree_coverage(CoverageFacts {
        worktree_under_common: byte_contains(&common.guest, &worktree.guest),
        common_under_worktree: byte_contains(&worktree.guest, &common.guest),
        // Both spellings are the host spellings for a mirrored project, so the
        // guest-relative suffix must name the same host directory.
        host_matches: match worktree.guest.strip_prefix(&common.guest) {
            Ok(suffix) => common.host.join(suffix) == worktree.host,
            Err(_) => false,
        },
    });

    // Common first: it is the directory the per-worktree one lives inside, so a
    // reader of the plan meets the container before its child.
    let mut placed: Vec<(GitMetadataRole, &MetadataDir)> = Vec::new();
    match coverage {
        Coverage::Covered => placed.push((GitMetadataRole::Common, common)),
        Coverage::Separate => {
            placed.push((GitMetadataRole::Common, common));
            placed.push((GitMetadataRole::Worktree, worktree));
        }
        Coverage::Refuse => {
            return Err(GitMetadataError::layout(
                topology.project_dir,
                Refusal::NestedCoverage {
                    worktree: worktree.guest.clone(),
                    common: common.guest.clone(),
                },
            ));
        }
    }

    let mut requests = Vec::new();
    let mut expected = Vec::new();
    let mut state = MetadataState::Silent;
    for (role, dir) in placed {
        // Measured against the *canonical* directories: the guest spelling is a
        // lexical string, so a symlinked alias can hide what the host contains.
        let contained = containing_checkout(&dir.host, topology.project_dir);
        let placement = metadata_placement(PlacementFacts {
            remapped: topology.project_guest != topology.project_dir,
            guest_safe: crate::run::guest_path_is_safe(&dir.guest),
            // Both halves of one fact: the guest spelling decides what the plan
            // says, the canonical host source decides what it really reaches. An
            // equal guest path is `claim`'s collision to refuse; a core *host*
            // source that equals the metadata directory is not a bind this feature
            // may make at all, so equality counts there.
            covers_core: topology
                .core_guest_mounts
                .iter()
                .any(|core| core != &dir.guest && byte_contains(&dir.guest, core))
                || topology
                    .core_host_sources
                    .iter()
                    .any(|source| byte_contains(&dir.host, source)),
            contains_checkout: contained.is_some(),
            inside_project: byte_contains(topology.project_guest, &dir.guest),
            literal: dir.guest == dir.host,
        });
        match placement {
            Placement::Bind => {}
            // Already inside the writable project bind; an `ro` bind there would
            // make part of the project read-only, which the spec forbids.
            Placement::CoveredByProject => {
                state.skip(MetadataState::InProjectBind);
                continue;
            }
            Placement::Remapped => {
                return Err(GitMetadataError::layout(
                    topology.project_dir,
                    Refusal::Remapped {
                        project_guest: topology.project_guest.to_path_buf(),
                    },
                ));
            }
            Placement::UnderTmpfs => {
                return Err(GitMetadataError::layout(
                    topology.project_dir,
                    Refusal::UnderTmpfs {
                        metadata: dir.guest.clone(),
                    },
                ));
            }
            Placement::CoversCoreMount => {
                // Named as the host resolved it: the fact can be true of a
                // symlinked guest spelling whose host path is what contains the
                // core source, and that is the directory the reader has to look at.
                return Err(GitMetadataError::layout(
                    topology.project_dir,
                    Refusal::CoversCoreMount {
                        metadata: dir.host.clone(),
                    },
                ));
            }
            Placement::ContainsCheckout => {
                return Err(GitMetadataError::layout(
                    topology.project_dir,
                    Refusal::ContainsCheckout {
                        metadata: dir.host.clone(),
                        // `contains_checkout` is true only where this is `Some`.
                        checkout: contained.unwrap_or_else(|| dir.host.clone()),
                    },
                ));
            }
            Placement::SymlinkInsideProject => {
                return Err(GitMetadataError::layout(
                    topology.project_dir,
                    Refusal::SymlinkInsideProject {
                        metadata: dir.guest.clone(),
                    },
                ));
            }
        }
        // The user's own declarations were selected first and are mounted first,
        // so an automatic bind below one of them would outrank it. Nothing in
        // `claim` sees that: the two guest paths differ, so it is not a conflict.
        match enclosing_declaration(topology.selected, &dir.guest, &dir.host) {
            // `Unrelated` is the kernel's answer for `!encloses`, which the
            // adapter filters before returning, so it never arrives here.
            None | Some((_, Enclosure::Unrelated)) => {}
            Some((request, Enclosure::Reachable)) => {
                state.skip(MetadataState::Enclosing(request.origin.clone()));
                continue;
            }
            Some((request, Enclosure::Shadowed)) => {
                return Err(GitMetadataError::layout(
                    topology.project_dir,
                    Refusal::ShadowedDeclaration {
                        metadata: dir.guest.clone(),
                        role,
                        declaration: request.origin.clone(),
                    },
                ));
            }
        }
        // The spelling is the guest path *and* the host path: the project is
        // mirrored, so `guest_spelling_consistent` already proved the guest
        // resolves this spelling to `dir.host`, and `prepare` canonicalizes it
        // exactly as it canonicalizes a `--mount`.
        let Some(mount) = ExtraMount::automatic_bind(&dir.guest, access) else {
            return Err(GitMetadataError::layout(
                topology.project_dir,
                Refusal::NonUtf8 {
                    metadata: dir.guest.clone(),
                },
            ));
        };
        expected.push((dir.guest.clone(), dir.host.clone()));
        requests.push(MountRequest {
            origin: MountOrigin::GitMetadata { role },
            mount,
        });
        state = MetadataState::Bound(access);
    }

    Ok(GitMetadataMounts {
        requests,
        report: GitMetadataReport {
            worktree: topology.project_dir.to_path_buf(),
            state,
            expected,
        },
    })
}

/// The first declaration that encloses `guest`, and what it means for the
/// automatic bind — the measurement [`declaration_enclosure`] decides on.
///
/// A declaration whose source cannot be canonicalized is **skipped**, not treated
/// as a different directory: `prepare` canonicalizes every live bind before it
/// binds anything and refuses a missing or unreadable one, so the launch fails
/// either way — and with the skip the reader gets the error that names the
/// problem (`canonicalizing --mount host …`) instead of a shadow refusal that
/// would send them looking at the wrong declaration.
fn enclosing_declaration<'a>(
    selected: &'a [MountRequest],
    guest: &Path,
    host: &Path,
) -> Option<(&'a MountRequest, Enclosure)> {
    let mut reachable: Option<(&MountRequest, Enclosure)> = None;
    for request in selected {
        let declared = &request.mount;
        let encloses = declared.guest != *guest && byte_contains(&declared.guest, guest);
        if !encloses {
            continue;
        }
        // Both sides are component-wise ancestors of the same spelling, so the
        // suffix is what the declaration's guest path does not spell.
        let suffix = guest.strip_prefix(&declared.guest).unwrap_or(Path::new(""));
        // `prepare` refuses a source that does not resolve, so this declaration
        // cannot mount anything: skipping it leaves that refusal to report itself.
        let Ok(source) = fs::canonicalize(&declared.host) else {
            continue;
        };
        let same_host = source.join(suffix) == *host;
        let live = matches!(
            declared.policy,
            MountPolicy::BindReadOnly {
                follow_links: false
            } | MountPolicy::BindReadWrite
        );
        match declaration_enclosure(EnclosureFacts {
            encloses,
            same_host,
            live,
        }) {
            // `:fork` and `:follow-links` do not hand the guest this directory at
            // this path, so a same-host match for them proves nothing.
            Enclosure::Shadowed => return Some((request, Enclosure::Shadowed)),
            Enclosure::Reachable => reachable = reachable.or(Some((request, Enclosure::Reachable))),
            Enclosure::Unrelated => {}
        }
    }
    reachable
}

/// The checkouts `dir` contains: the launch directory itself, or a worktree this
/// repository registered under `<dir>/worktrees`.
///
/// A `.git`-entry rule cannot answer this. A bare repository's directory *is* all
/// metadata, so [`git_dir_contract`] accepts it whole — and `git worktree add`
/// inside that directory is ordinary Git, not a forgery: the bind would carry
/// another worktree's source, which no metadata mount needs (spec: non-goal
/// "any other checkout's source").
///
/// Residual, recorded in ADR-0062: a checkout inside the directory that Git does
/// *not* register (a hand-placed clone) is not detected.
fn containing_checkout(dir: &Path, project_dir: &Path) -> Option<PathBuf> {
    if byte_contains(dir, project_dir) {
        return Some(project_dir.to_path_buf());
    }
    // Every entry is a no-follow bounded read of one `gitdir` line; a stale entry
    // is compared by its spelling (`back_pointer_target` canonicalizes when it
    // can), so a registered checkout whose directory has since moved is still
    // seen where it was registered.
    for entry in fs::read_dir(dir.join("worktrees")).ok()?.flatten() {
        let Some(target) = back_pointer_target(&entry.path().join("gitdir")) else {
            continue;
        };
        let Some(checkout) = target.parent() else {
            continue;
        };
        if byte_contains(dir, checkout) {
            return Some(checkout.to_path_buf());
        }
    }
    None
}

impl GitMountMode {
    /// The kernel's input, measured by an exhaustive `match` with no wildcard so
    /// a new mode has to say what it means here.
    fn facts(self) -> GitMountModeFacts {
        match self {
            Self::ReadOnly => GitMountModeFacts {
                off: false,
                writable: false,
            },
            Self::ReadWrite => GitMountModeFacts {
                off: false,
                writable: true,
            },
            Self::Off => GitMountModeFacts {
                off: true,
                writable: false,
            },
        }
    }
}

/// The whole user message. `Display` is what a launch prints; the typed
/// [`Refusal`] is what tests match, so a test never parses prose.
#[derive(Debug)]
pub(crate) struct GitMetadataError {
    worktree: PathBuf,
    reason: Refusal,
}

impl GitMetadataError {
    fn relationship(project_dir: &Path, verdict: WorktreeVerdict, m: &Measured) -> Self {
        Self {
            worktree: project_dir.to_path_buf(),
            reason: Refusal::from_verdict(verdict, m),
        }
    }

    fn layout(project_dir: &Path, reason: Refusal) -> Self {
        Self {
            worktree: project_dir.to_path_buf(),
            reason,
        }
    }
}

impl std::fmt::Display for GitMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let worktree = crate::one_line::quoted_path(&self.worktree);
        let reason = self.reason.render();
        if self.reason.is_race() {
            // A race is not a broken repository, so `git worktree repair` would
            // be advice about the wrong thing.
            return write!(
                f,
                "linked worktree metadata for {worktree} changed while preparing the launch: \
                 {reason}. Pass --git-mount=off to launch without automatic Git metadata mounts."
            );
        }
        if self.reason.is_layout() {
            write!(
                f,
                "linked worktree metadata for {worktree} cannot be mounted at its host paths: \
                 {reason}. Pass --git-mount=off to launch without automatic Git metadata mounts."
            )
        } else {
            write!(
                f,
                "linked worktree metadata for {worktree} is unusable: {reason}. Run `git worktree \
                 repair` in the main checkout or in {worktree}, or pass --git-mount=off to \
                 launch without automatic Git metadata mounts."
            )
        }
    }
}

impl std::error::Error for GitMetadataError {}

/// Why one discovery step did not produce a bind. Typed so tests assert the
/// reason rather than the prose, and so the message can name the exact path that
/// failed.
#[derive(Debug)]
enum Refusal {
    MalformedPointer,
    MissingGitDir {
        gitdir: PathBuf,
    },
    MissingCommonDirFile {
        commondir: PathBuf,
    },
    MalformedCommonDir {
        commondir: PathBuf,
    },
    MissingCommonDir {
        common: PathBuf,
    },
    CommonNotAGitDirectory {
        common: PathBuf,
    },
    WorktreeNotAGitDirectory {
        worktree: PathBuf,
    },
    NotRegistered {
        worktree: PathBuf,
        common: PathBuf,
    },
    BackPointerMismatch {
        gitdir: PathBuf,
    },
    SymlinkedLayout {
        worktree: PathBuf,
        common: PathBuf,
    },
    Remapped {
        project_guest: PathBuf,
    },
    UnderTmpfs {
        metadata: PathBuf,
    },
    CoversCoreMount {
        metadata: PathBuf,
    },
    ContainsCheckout {
        metadata: PathBuf,
        checkout: PathBuf,
    },
    ShadowedDeclaration {
        metadata: PathBuf,
        role: GitMetadataRole,
        declaration: MountOrigin,
    },
    SymlinkInsideProject {
        metadata: PathBuf,
    },
    NestedCoverage {
        worktree: PathBuf,
        common: PathBuf,
    },
    NonUtf8 {
        metadata: PathBuf,
    },
    ChangedWhilePreparing {
        guest: PathBuf,
        expected: PathBuf,
        prepared: Option<PathBuf>,
    },
}

impl Refusal {
    fn from_verdict(verdict: WorktreeVerdict, m: &Measured) -> Self {
        let worktree = m.worktree.as_ref().map(|dir| dir.host.clone());
        let common = m.common.as_ref().map(|dir| dir.host.clone());
        match verdict {
            WorktreeVerdict::MalformedPointer | WorktreeVerdict::NotLinked => {
                Self::MalformedPointer
            }
            WorktreeVerdict::MissingGitDir => Self::MissingGitDir {
                gitdir: m.spelled_gitdir.clone(),
            },
            WorktreeVerdict::MissingCommonDirFile => Self::MissingCommonDirFile {
                commondir: worktree
                    .map(|dir| dir.join("commondir"))
                    .unwrap_or_else(|| m.spelled_gitdir.clone()),
            },
            WorktreeVerdict::MalformedCommonDir => Self::MalformedCommonDir {
                commondir: worktree
                    .map(|dir| dir.join("commondir"))
                    .unwrap_or_else(|| m.spelled_gitdir.clone()),
            },
            WorktreeVerdict::MissingCommonDir => Self::MissingCommonDir {
                common: m.spelled_common.clone(),
            },
            WorktreeVerdict::CommonNotAGitDirectory => Self::CommonNotAGitDirectory {
                common: common.unwrap_or_else(|| m.spelled_common.clone()),
            },
            WorktreeVerdict::WorktreeNotAGitDirectory => Self::WorktreeNotAGitDirectory {
                worktree: worktree.unwrap_or_else(|| m.spelled_gitdir.clone()),
            },
            WorktreeVerdict::NotRegistered => Self::NotRegistered {
                worktree: worktree.unwrap_or_else(|| m.spelled_gitdir.clone()),
                common: common.unwrap_or_else(|| m.spelled_common.clone()),
            },
            WorktreeVerdict::BackPointerMismatch => Self::BackPointerMismatch {
                gitdir: worktree
                    .map(|dir| dir.join("gitdir"))
                    .unwrap_or_else(|| m.spelled_gitdir.clone()),
            },
            WorktreeVerdict::SymlinkedLayout => Self::SymlinkedLayout {
                worktree: worktree.unwrap_or_else(|| m.spelled_gitdir.clone()),
                common: common.unwrap_or_else(|| m.spelled_common.clone()),
            },
            WorktreeVerdict::Linked => Self::MalformedPointer,
        }
    }

    /// Whether this refusal is about the layout instead of the relationship, and
    /// therefore must not suggest `git worktree repair`.
    ///
    /// `SymlinkedLayout` is here even though the state machine reaches it through
    /// the relationship facts: what failed is that the *guest* would resolve a
    /// different directory than the host, which `git worktree repair` cannot fix.
    /// The spec lists "symlink-dependent nesting" among the unmountable layouts
    /// (R9), so that is the sentence the reader needs. `ContainsCheckout` is a
    /// layout for the same reason: the registration is intact, so there is
    /// nothing to repair — only a flag that drops the mount.
    fn is_layout(&self) -> bool {
        matches!(
            self,
            Self::Remapped { .. }
                | Self::UnderTmpfs { .. }
                | Self::CoversCoreMount { .. }
                | Self::ContainsCheckout { .. }
                | Self::ShadowedDeclaration { .. }
                | Self::SymlinkInsideProject { .. }
                | Self::NestedCoverage { .. }
                | Self::NonUtf8 { .. }
                | Self::SymlinkedLayout { .. }
        )
    }

    fn is_race(&self) -> bool {
        matches!(self, Self::ChangedWhilePreparing { .. })
    }

    /// The reason clause. Every path here came from an untrusted pointer file, so
    /// it is rendered with the one-line escaping policy — [`crate::one_line::quoted_path`]
    /// already wraps the path in quotes, so no arm adds its own.
    fn render(&self) -> String {
        let quoted = crate::one_line::quoted_path;
        match self {
            Self::MalformedPointer => {
                "the `.git` pointer is not a usable `gitdir: ` line".to_string()
            }
            Self::MissingGitDir { gitdir } => {
                format!("{} is not a directory", quoted(gitdir))
            }
            Self::MissingCommonDirFile { commondir } => {
                format!("{} is missing", quoted(commondir))
            }
            Self::MalformedCommonDir { commondir } => {
                format!("{} is not a usable relative path", quoted(commondir))
            }
            Self::MissingCommonDir { common } => {
                format!("{} is not a directory", quoted(common))
            }
            Self::CommonNotAGitDirectory { common } => {
                format!("{} is not a Git directory", quoted(common))
            }
            Self::WorktreeNotAGitDirectory { worktree } => {
                format!(
                    "{} is not a Git directory (no valid HEAD)",
                    quoted(worktree)
                )
            }
            Self::NotRegistered { worktree, common } => format!(
                "{} is not registered under {}",
                quoted(worktree),
                quoted(&common.join("worktrees"))
            ),
            Self::BackPointerMismatch { gitdir } => {
                format!("{} does not name this worktree's `.git`", quoted(gitdir))
            }
            Self::SymlinkedLayout { worktree, common } => format!(
                "a `..` in the relationship reaches a different directory in the guest than on \
                 the host ({} and {})",
                quoted(worktree),
                quoted(common)
            ),
            Self::Remapped { project_guest } => format!(
                "Git's relative pointers would resolve against the guest project path {}",
                quoted(project_guest)
            ),
            Self::UnderTmpfs { metadata } => format!(
                "{} is under a guest tmpfs mount, which is wiped at boot",
                quoted(metadata)
            ),
            Self::CoversCoreMount { metadata } => {
                format!("{} contains one of agent-vm's own mounts", quoted(metadata))
            }
            Self::ContainsCheckout { metadata, checkout } => format!(
                "{} contains the checkout {}, so the bind would include another worktree's \
                 source",
                quoted(metadata),
                quoted(checkout)
            ),
            Self::ShadowedDeclaration {
                metadata,
                role,
                declaration,
            } => format!(
                "the automatic Git metadata mount ({}) at {} would shadow {declaration}, which \
                 does not hand the guest that same directory",
                role.name(),
                quoted(metadata)
            ),
            Self::SymlinkInsideProject { metadata } => format!(
                "{} is inside the writable project bind only through a symlink",
                quoted(metadata)
            ),
            Self::NestedCoverage { worktree, common } => format!(
                "{} and {} nest in a way the guest cannot mirror",
                quoted(worktree),
                quoted(common)
            ),
            Self::NonUtf8 { metadata } => {
                format!("{} does not spell a UTF-8 guest path", quoted(metadata))
            }
            Self::ChangedWhilePreparing {
                guest,
                expected,
                prepared,
            } => {
                let prepared = match prepared {
                    Some(host) => quoted(host).to_string(),
                    None => "no prepared volume".to_string(),
                };
                format!(
                    "the prepared bind at {} names {prepared} instead of {}",
                    quoted(guest),
                    quoted(expected)
                )
            }
        }
    }
}

/// One metadata directory as Git sees it in each namespace.
///
/// `guest` is the *lexical* spelling the guest will resolve, `host` the
/// canonical directory the host resolved. For a mirrored project they are equal;
/// keeping both is what makes layout C (a symlinked spelling) expressible and
/// layout D (a `..` that crosses a symlink) refusable.
#[derive(Debug)]
struct MetadataDir {
    guest: PathBuf,
    host: PathBuf,
}

/// The measured facts one discovery pass produces. Kept beside the directories
/// so a refusal can name the exact path that failed.
#[derive(Debug)]
struct Measured {
    facts: WorktreeFacts,
    worktree: Option<MetadataDir>,
    common: Option<MetadataDir>,
    spelled_gitdir: PathBuf,
    spelled_common: PathBuf,
}

/// `PATH_MAX` plus `"gitdir: "` and one line ending: the pointer file cannot be
/// a path the host could resolve, so a longer one is malformed rather than large.
const MAX_POINTER_BYTES: u64 = 4096 + 64;
/// A bounded `HEAD` read; the kernel sees at most [`MAX_HEADREF_BYTES`] of it,
/// which is what Git's `validate_headref` reads.
const MAX_HEAD_BYTES: u64 = 4096;
/// Git reads `sizeof(refname) - 1` bytes of `HEAD`; a longer `HEAD` cannot be a
/// ref name it would accept, so the tail is never inspected.
const MAX_HEADREF_BYTES: usize = 255;

fn measure(project_dir: &Path) -> Measured {
    let mut facts = WorktreeFacts {
        dot_git_regular: false,
        pointer_parsed: false,
        gitdir_is_dir: false,
        commondir_present: false,
        linked_evidence: false,
        commondir_parsed: false,
        common_resolved: false,
        common_is_git_dir: false,
        worktree_is_git_dir: false,
        registered_under_common: false,
        back_pointer_matches: false,
        guest_spelling_consistent: false,
    };
    let mut measured = Measured {
        facts,
        worktree: None,
        common: None,
        spelled_gitdir: project_dir.join(".git"),
        spelled_common: project_dir.join(".git"),
    };

    let dot_git = project_dir.join(".git");
    facts.dot_git_regular = fs::symlink_metadata(&dot_git)
        .map(|meta| meta.file_type().is_file())
        .unwrap_or(false);
    if !facts.dot_git_regular {
        measured.facts = facts;
        return measured;
    }

    let Ok((pointer_bytes, _)) =
        crate::host_paths::read_bounded_regular_file_no_follow(&dot_git, MAX_POINTER_BYTES)
    else {
        measured.facts = facts;
        return measured;
    };
    let Some(span) = pointer_span(&pointer_bytes, b"gitdir: ") else {
        measured.facts = facts;
        return measured;
    };
    let pointer_text = &pointer_bytes[span.start..span.end];
    let pointer = Path::new(OsStr::from_bytes(pointer_text));
    let spelled_gitdir = spelled_against(project_dir, pointer);
    measured.spelled_gitdir = spelled_gitdir.clone();
    let Some(worktree_guest) = resolve_lexically(project_dir, pointer) else {
        measured.facts = facts;
        return measured;
    };
    facts.pointer_parsed = true;
    let Ok(worktree_host) = fs::canonicalize(&spelled_gitdir) else {
        measured.facts = facts;
        return measured;
    };
    facts.gitdir_is_dir = worktree_host.is_dir();
    measured.worktree = Some(MetadataDir {
        guest: worktree_guest.clone(),
        host: worktree_host.clone(),
    });
    if !facts.gitdir_is_dir {
        measured.facts = facts;
        return measured;
    }

    let commondir_path = worktree_host.join("commondir");
    let commondir_bytes = crate::host_paths::read_optional_bounded_regular_file_no_follow(
        &commondir_path,
        MAX_POINTER_BYTES,
    );
    let commondir_span = match &commondir_bytes {
        Ok(Some(bytes)) => {
            facts.commondir_present = true;
            pointer_span(bytes, b"")
        }
        Ok(None) => {
            // No `commondir`: either this is not a linked worktree at all
            // (submodule, `--separate-git-dir`) or it is a damaged one. Git's own
            // layout leaves one of two marks behind, and only those distinguish
            // the two cases without reading a `config` nobody has validated.
            facts.linked_evidence = linked_evidence(&worktree_host);
            measured.facts = facts;
            return measured;
        }
        Err(_) => {
            facts.commondir_present = true;
            None
        }
    };
    if !facts.commondir_present {
        measured.facts = facts;
        return measured;
    }

    let Some(commondir_span) = commondir_span else {
        measured.facts = facts;
        return measured;
    };
    let commondir_text = match &commondir_bytes {
        Ok(Some(bytes)) => &bytes[commondir_span.start..commondir_span.end],
        _ => &[][..],
    };
    let commondir = Path::new(OsStr::from_bytes(commondir_text));
    let spelled_common = spelled_against(&worktree_guest, commondir);
    measured.spelled_common = spelled_common.clone();
    let Some(common_guest) = resolve_lexically(&worktree_guest, commondir) else {
        measured.facts = facts;
        return measured;
    };
    facts.commondir_parsed = true;
    let Ok(common_host) = fs::canonicalize(&spelled_common) else {
        measured.facts = facts;
        return measured;
    };
    facts.common_resolved = true;
    measured.common = Some(MetadataDir {
        guest: common_guest.clone(),
        host: common_host.clone(),
    });

    facts.common_is_git_dir = git_dir_contract(&common_host);
    facts.worktree_is_git_dir = head_is_valid(&worktree_host);
    facts.registered_under_common = worktree_host.parent() == Some(&common_host.join("worktrees"));

    let back_pointer = worktree_host.join("gitdir");
    facts.back_pointer_matches = back_pointer_target(&back_pointer)
        .map(|target| target == canonical_or_self(&dot_git))
        .unwrap_or(false);

    facts.guest_spelling_consistent = fs::canonicalize(&worktree_guest).ok().as_deref()
        == Some(&worktree_host)
        && fs::canonicalize(&common_guest).ok().as_deref() == Some(&common_host);

    measured.facts = facts;
    measured
}

/// `path` interpreted against `base` when relative, left alone when absolute —
/// the *spelled* form, for filesystem calls that must see `..` and symlinks.
fn spelled_against(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn canonical_or_self(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// A core bind's host source, canonical as far as it exists.
///
/// The state directory, its `home` and the persisted tree under it are created
/// *after* discovery, so the leaf is usually missing. Canonicalizing the deepest
/// ancestor that exists and re-appending the rest is what still compares them
/// against a canonical metadata directory — on macOS `$TMPDIR` is a symlink to
/// `/private/tmp`, so a literal comparison of the two spellings would miss the
/// very case this measurement exists for.
pub(crate) fn canonical_host_source(path: &Path) -> PathBuf {
    let mut rest: Vec<&OsStr> = Vec::new();
    let mut current = path;
    loop {
        if let Ok(canonical) = fs::canonicalize(current) {
            let mut out = canonical;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                current = parent;
            }
            // `/` itself always canonicalizes, so what arrives here is a spelling
            // with no ancestor left to try: a relative one, or an absolute one whose
            // unresolved `..` component has no file name (`alias/missing/../s`).
            // The caller gets the original spelling unchanged, and `prepare` fails
            // closed on it rather than this helper guessing.
            _ => return path.to_path_buf(),
        }
    }
}

/// Whether a layout with no `commondir` is a *damaged* linked worktree rather
/// than a different kind of gitfile.
///
/// Measured: `git submodule add` and `git init --separate-git-dir` leave neither
/// mark, so this cannot silently disable the feature for a worktree whose
/// `commondir` was deleted, nor refuse a submodule (ADR-0062 D2).
fn linked_evidence(worktree_host: &Path) -> bool {
    if fs::symlink_metadata(worktree_host.join("gitdir")).is_ok() {
        return true;
    }
    match worktree_host
        .parent()
        .and_then(|parent| parent.parent().map(|grand| (parent, grand)))
    {
        Some((parent, grand)) => {
            parent.file_name() == Some(OsStr::new("worktrees")) && git_dir_contract(grand)
        }
        None => false,
    }
}

/// The Git-directory validity contract for the *common* directory: what
/// `is_git_directory` accepts, plus the two storage rules this feature relies on.
///
/// Stricter than Git in three places, each named: a common directory must have a
/// valid `HEAD` and a regular `config` (both are always created by `git init` and
/// `git clone`, but Git itself tolerates their absence once a repository has
/// been opened), and must not contain a `.git` entry — a checkout root or an
/// ancestor of one does, which is what keeps the project bind's own directory out
/// of the automatic set. A bare repository passes: it is all metadata.
fn git_dir_contract(common: &Path) -> bool {
    common.join("objects").is_dir()
        && common.join("refs").is_dir()
        && head_is_valid(common)
        && fs::symlink_metadata(common.join("config"))
            .map(|meta| meta.file_type().is_file())
            .unwrap_or(false)
        && fs::symlink_metadata(common.join(".git")).is_err()
}

/// `HEAD` validity, the way Git's `validate_headref` measures it: a symlink whose
/// *target text* starts `refs/`, or a file whose first 255 bytes are a symbolic
/// ref or 40 hex digits.
///
/// No-follow and bounded, so a hostile `HEAD` cannot redirect the read or make it
/// unbounded.
fn head_is_valid(dir: &Path) -> bool {
    let head = dir.join("HEAD");
    match fs::symlink_metadata(&head) {
        Ok(meta) if meta.file_type().is_symlink() => fs::read_link(&head)
            .map(|target| headref_link_valid(target.as_os_str().as_bytes()))
            .unwrap_or(false),
        Ok(meta) if meta.file_type().is_file() => {
            match crate::host_paths::read_bounded_regular_file_no_follow(&head, MAX_HEAD_BYTES) {
                Ok((bytes, _)) => headref_valid(&bytes[..bytes.len().min(MAX_HEADREF_BYTES)]),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

/// Read a `gitdir`/`commondir`-shaped file and return the path it names.
fn back_pointer_target(path: &Path) -> Option<PathBuf> {
    let bytes =
        crate::host_paths::read_optional_bounded_regular_file_no_follow(path, MAX_POINTER_BYTES)
            .ok()
            .flatten()?;
    let span = pointer_span(&bytes, b"")?;
    let spelled = spelled_against(
        path.parent()?,
        Path::new(OsStr::from_bytes(&bytes[span.start..span.end])),
    );
    Some(canonical_or_self(&spelled))
}

fn pointer_span(bytes: &[u8], prefix: &[u8]) -> Option<Span> {
    pointer_path_span(bytes, prefix)
}

/// `a` is `b` itself or a component-wise ancestor of it, over the raw bytes —
/// the same proved predicate the protected-file guards use.
fn byte_contains(a: &Path, b: &Path) -> bool {
    crate::config::byte_path_contains(a.as_os_str().as_bytes(), b.as_os_str().as_bytes())
}

/// Lexical resolution of an untrusted path against a canonical base.
///
/// The trust boundary of [`resolve_components`]: `Path::components` splits the
/// text into the kinds the kernel decides on, and the rebuild walks the kept
/// prefix and the kept indices. Absolute input restarts at `/` (so the base is
/// ignored); relative input starts from the base's own components. `.` is a
/// no-op, `a//b` and a trailing `/` never reach the kernel, and `..` above `/` is
/// **refused** rather than clamped, which is what makes layout D a refusal.
fn resolve_lexically(base: &Path, path: &Path) -> Option<PathBuf> {
    if !base.is_absolute() {
        return None;
    }
    // The base is canonical, so it has no `.` or `..` of its own; anything else
    // means the caller handed a spelling rather than a measured directory.
    let mut base_parts: Vec<&OsStr> = Vec::new();
    for component in base.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => base_parts.push(part),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    let mut kinds: Vec<ComponentKind> = Vec::new();
    let mut texts: Vec<Option<&OsStr>> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {
                base_parts.clear();
                kinds.clear();
                texts.clear();
            }
            Component::CurDir => {
                kinds.push(ComponentKind::CurDir);
                texts.push(None);
            }
            Component::ParentDir => {
                kinds.push(ComponentKind::ParentDir);
                texts.push(None);
            }
            Component::Normal(part) => {
                kinds.push(ComponentKind::Normal);
                texts.push(Some(part));
            }
            // Unreachable on Unix; refused rather than guessed at.
            Component::Prefix(_) => return None,
        }
    }
    let resolved = resolve_components(base_parts.len(), &kinds);
    if resolved.escaped {
        return None;
    }
    let mut out = PathBuf::from("/");
    for part in base_parts.iter().take(resolved.base_kept) {
        out.push(part);
    }
    // A kept index can only name a `Normal` kind, which is the only kind the
    // adapter stored text for.
    for index in &resolved.kept {
        out.push(texts.get(*index).copied().flatten()?);
    }
    Some(out)
}

// The pure decisions this module makes about untrusted input. Each one is a
// kernel: the measurement that produces its facts (`symlink_metadata`, bounded
// no-follow reads, `read_link`, `canonicalize`, `Path::components`) is the trusted
// adapter, and every refusal is a decision over those measured facts.
verus! {
/// The two facts `--git-mount` measures. Named fields rather than two adjacent
/// booleans, whose polarity differs.
#[derive(Clone, Copy, Debug)]
pub struct GitMountModeFacts {
    pub off: bool,
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum MountAccessDecision {
    Skip,
    ReadOnly,
    ReadWrite,
}

/// Whether automatic Git metadata reaches the guest, and how. `Skip` is the only
/// value that means "do not look at the host at all", and `ReadWrite` is the only
/// one that means writable, so neither can be produced by the other's facts.
pub fn git_mount_access(mode: GitMountModeFacts) -> (d: MountAccessDecision)
    ensures
        (d == MountAccessDecision::Skip) == mode.off,
        (d == MountAccessDecision::ReadWrite) == (!mode.off && mode.writable),
{
    if mode.off {
        MountAccessDecision::Skip
    } else if mode.writable {
        MountAccessDecision::ReadWrite
    } else {
        MountAccessDecision::ReadOnly
    }
}

pub open spec fn starts_with(b: Seq<u8>, p: Seq<u8>) -> bool {
    b.len() >= p.len() && b.subrange(0, p.len() as int) =~= p
}

/// Git's `sane_ctype` space set, and nothing else: `isspace` over a signed
/// `char` also accepts other locales' bytes, which is not what Git accepts.
pub open spec fn is_space(byte: u8) -> bool {
    byte == 0x20u8 || byte == 0x09u8 || byte == 0x0au8 || byte == 0x0du8
}

pub open spec fn is_control(byte: u8) -> bool {
    byte < 0x20u8 || byte == 0x7fu8
}

pub open spec fn is_line_end(byte: u8) -> bool {
    byte == 0x0au8 || byte == 0x0du8
}

/// The length of `b` with trailing `\n`/`\r` bytes removed — Git's one-line
/// convention, and `\r\n` as well as a bare `\n`.
pub open spec fn trimmed_len(b: Seq<u8>) -> int
    decreases b.len(),
{
    if b.len() == 0 {
        0
    } else if is_line_end(b[b.len() as int - 1]) {
        trimmed_len(b.subrange(0, b.len() as int - 1))
    } else {
        b.len() as int
    }
}

pub open spec fn no_control(b: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < b.len() ==> !is_control(b[i])
}

/// One-line pointer file: `prefix`, then a non-empty path, with line endings
/// stripped and no control byte inside the path.
///
/// The control-byte rule is what keeps a pointer from carrying a newline (which
/// would forge a diagnostic line) or a tab (which would break the boot-params
/// framing a guest path travels in).
pub open spec fn pointer_accepts(bytes: Seq<u8>, prefix: Seq<u8>) -> bool {
    starts_with(bytes, prefix) && trimmed_len(bytes) > prefix.len()
        && no_control(bytes.subrange(prefix.len() as int, trimmed_len(bytes)))
}

pub struct Span {
    pub start: usize,
    pub end: usize,
}

pub open spec fn span_is_correct(r: Option<Span>, bytes: Seq<u8>, prefix: Seq<u8>) -> bool {
    match r {
        Some(s) => s.start == prefix.len() && s.end == trimmed_len(bytes),
        None => true,
    }
}

pub fn pointer_path_span(bytes: &[u8], prefix: &[u8]) -> (r: Option<Span>)
    ensures
        r.is_some() == pointer_accepts(bytes@, prefix@),
        span_is_correct(r, bytes@, prefix@),
{
    if prefix.len() > bytes.len() {
        assert(!starts_with(bytes@, prefix@));
        return None;
    }
    let mut i: usize = 0;
    while i < prefix.len()
        invariant
            i <= prefix.len(),
            prefix.len() <= bytes.len(),
            forall|j: int| 0 <= j < i ==> bytes@[j] == prefix@[j],
        decreases prefix.len() - i,
    {
        if bytes[i] != prefix[i] {
            assert(!(bytes@.subrange(0, prefix@.len() as int) =~= prefix@));
            assert(!starts_with(bytes@, prefix@));
            return None;
        }
        i += 1;
    }
    assert(bytes@.subrange(0, prefix@.len() as int) =~= prefix@);
    let end = trimmed_len_exec(bytes);
    if end <= prefix.len() {
        assert(!(trimmed_len(bytes@) > prefix@.len()));
        return None;
    }
    let mut j: usize = prefix.len();
    while j < end
        invariant
            prefix.len() <= j <= end,
            end <= bytes.len(),
            end as int == trimmed_len(bytes@),
            forall|k: int| prefix.len() <= k < j ==> !is_control(bytes@[k]),
        decreases end - j,
    {
        if is_control_byte(bytes[j]) {
            // The witness for `!no_control`: `j` is inside the surviving span, so
            // the control byte it holds is one the kernel's `forall` denies.
            assert(j < end);
            assert(bytes@.subrange(prefix@.len() as int, trimmed_len(bytes@))
                [(j - prefix.len()) as int] == bytes@[j as int]);
            assert(is_control(
                bytes@.subrange(prefix@.len() as int, trimmed_len(bytes@))[(j - prefix.len()) as int]
            ));
            assert(!no_control(bytes@.subrange(prefix@.len() as int, trimmed_len(bytes@))));
            return None;
        }
        j += 1;
    }
    assert(no_control(bytes@.subrange(prefix@.len() as int, trimmed_len(bytes@))));
    Some(Span {
        start: prefix.len(),
        end,
    })
}

// `len() == 0` rather than `is_empty()`: the body restates `trimmed_len`'s spec
// clause for clause, and the two spellings must stay visibly identical.
#[allow(clippy::len_zero)]
fn trimmed_len_exec(bytes: &[u8]) -> (n: usize)
    ensures n as int == trimmed_len(bytes@), n <= bytes.len(),
    decreases bytes.len(),
{
    if bytes.len() == 0 {
        0
    } else if is_line_end_byte(bytes[bytes.len() - 1]) {
        trimmed_len_exec(&bytes[..bytes.len() - 1])
    } else {
        bytes.len()
    }
}

fn is_space_byte(byte: u8) -> (r: bool)
    ensures r == is_space(byte),
{
    byte == 0x20u8 || byte == 0x09u8 || byte == 0x0au8 || byte == 0x0du8
}

fn is_control_byte(byte: u8) -> (r: bool)
    ensures r == is_control(byte),
{
    byte < 0x20u8 || byte == 0x7fu8
}

fn is_line_end_byte(byte: u8) -> (r: bool)
    ensures r == is_line_end(byte),
{
    byte == 0x0au8 || byte == 0x0du8
}

// Range comparisons, not `contains`: this body is restated byte for byte by
// `is_hex_byte`, so the accepted alphabet reads the same in the spec and the exec.
#[allow(clippy::manual_range_contains)]
pub open spec fn is_hex(byte: u8) -> bool {
    (0x30u8 <= byte && byte <= 0x39u8)
        || (0x61u8 <= byte && byte <= 0x66u8)
        || (0x41u8 <= byte && byte <= 0x46u8)
}

/// Git's `validate_headref` over bytes Git itself reads (callers pass at most the
/// first 255); the symlink form is [`headref_link_valid`], decided by the link's
/// target text alone.
///
/// Written as byte predicates rather than prefix helpers so the executable form
/// restates it exactly: a symbolic ref is the four bytes `ref:`, then Git's
/// `sane_ctype` space set, then `refs/`; a detached `HEAD` is 40 hex digits, the
/// SHA-1 width, which is also the first 40 of a SHA-256 object id.
/// `ref:` then Git's `sane_ctype` space set then `refs/`, as nested tests rather
/// than one conjunction: the executable form nests identically, so the
/// postcondition is definitional instead of needing a Boolean case split.
pub open spec fn headref_symbolic(b: Seq<u8>) -> bool {
    if b.len() >= 4 {
        if b[0] == 0x72u8 {
            if b[1] == 0x65u8 {
                if b[2] == 0x66u8 {
                    if b[3] == 0x3au8 {
                        refs_after_space(b, 4)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    }
}

pub open spec fn headref_accepts(b: Seq<u8>) -> bool {
    headref_symbolic(b) || leading_hex(b, 40)
}

/// `refs/` at the first non-space position at or after `i`.
pub open spec fn refs_after_space(b: Seq<u8>, i: int) -> bool
    decreases b.len() - i,
{
    if i >= b.len() {
        false
    } else if is_space(b[i]) {
        refs_after_space(b, i + 1)
    } else {
        b.len() - i >= 5 && b[i] == 0x72u8 && b[i + 1] == 0x65u8 && b[i + 2] == 0x66u8
            && b[i + 3] == 0x73u8 && b[i + 4] == 0x2fu8
    }
}

pub open spec fn link_accepts(t: Seq<u8>) -> bool {
    t.len() >= 5 && t[0] == 0x72u8 && t[1] == 0x65u8 && t[2] == 0x66u8 && t[3] == 0x73u8
        && t[4] == 0x2fu8
}

pub open spec fn leading_hex(b: Seq<u8>, n: int) -> bool {
    b.len() >= n && forall|i: int| 0 <= i < n ==> is_hex(b[i])
}

pub fn headref_valid(bytes: &[u8]) -> (r: bool)
    ensures r == headref_accepts(bytes@),
{
    let symbolic = headref_symbolic_exec(bytes);
    let hex = leading_hex_exec(bytes);
    symbolic || hex
}

// The nested `if`s are the point: each one mirrors a branch of
// `headref_symbolic`, and collapsing the equal arms into one conjunction is what
// made the postcondition unprovable.
#[allow(clippy::if_same_then_else)]
fn headref_symbolic_exec(bytes: &[u8]) -> (r: bool)
    ensures r == headref_symbolic(bytes@),
{
    if bytes.len() >= 4 {
        if bytes[0] == 0x72u8 {
            if bytes[1] == 0x65u8 {
                if bytes[2] == 0x66u8 {
                    if bytes[3] == 0x3au8 {
                        refs_after_space_exec(bytes, 4)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    }
}

fn leading_hex_exec(bytes: &[u8]) -> (r: bool)
    ensures r == leading_hex(bytes@, 40),
{
    if bytes.len() < 40 {
        assert(!leading_hex(bytes@, 40));
        return false;
    }
    let mut i: usize = 0;
    while i < 40
        invariant i <= 40, 40 <= bytes.len(), forall|j: int| 0 <= j < i ==> is_hex(bytes@[j]),
        decreases 40 - i,
    {
        if !is_hex_byte(bytes[i]) {
            assert(!leading_hex(bytes@, 40));
            return false;
        }
        i += 1;
    }
    assert(leading_hex(bytes@, 40));
    true
}

fn refs_after_space_exec(bytes: &[u8], i: usize) -> (r: bool)
    requires i <= bytes.len(),
    ensures r == refs_after_space(bytes@, i as int),
    decreases bytes.len() - i,
{
    if i >= bytes.len() {
        false
    } else if is_space_byte(bytes[i]) {
        refs_after_space_exec(bytes, i + 1)
    } else {
        bytes.len() - i >= 5
            && bytes[i] == 0x72u8
            && bytes[i + 1] == 0x65u8
            && bytes[i + 2] == 0x66u8
            && bytes[i + 3] == 0x73u8
            && bytes[i + 4] == 0x2fu8
    }
}

pub fn headref_link_valid(target: &[u8]) -> (r: bool)
    ensures r == link_accepts(target@),
{
    target.len() >= 5
        && target[0] == 0x72u8
        && target[1] == 0x65u8
        && target[2] == 0x66u8
        && target[3] == 0x73u8
        && target[4] == 0x2fu8
}

// See `is_hex`: the two bodies are the same expression on purpose.
#[allow(clippy::manual_range_contains)]
fn is_hex_byte(byte: u8) -> (r: bool)
    ensures r == is_hex(byte),
{
    (0x30u8 <= byte && byte <= 0x39u8)
        || (0x61u8 <= byte && byte <= 0x66u8)
        || (0x41u8 <= byte && byte <= 0x46u8)
}

/// What `Path::components` measured, one entry per component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum ComponentKind {
    CurDir,
    ParentDir,
    Normal,
}

pub struct Resolved {
    /// How many of the base's own components survive.
    pub base_kept: usize,
    /// The surviving `Normal` components, as indices into the measured kinds.
    pub kept: Vec<usize>,
    /// A `..` with nothing left to pop. The caller must refuse, not clamp.
    pub escaped: bool,
}

/// The fold's state, so the specification can talk about a partial walk.
///
/// Built only by [`resolve_from`]'s spec body, which erases under a plain
/// `cargo build`, so rustc sees a type nothing constructs. It is alive in full
/// under `cargo verus verify`.
#[allow(dead_code)]
pub struct FoldState {
    pub base_kept: usize,
    pub kept: Seq<usize>,
    pub escaped: bool,
}

/// The one lexical resolution rule: `.` is a no-op, a normal component is pushed,
/// `..` pops the last surviving normal component, else one base component, else
/// it escapes.
///
/// Deliberately stricter than POSIX, where `/..` is `/`: clamping would let a
/// pointer walk out of the directory Git resolved and back into a *different*
/// one (toy layout D).
/// `escaped` is an accumulator parameter rather than a `None` result, so an
/// escaped walk can carry on consuming components and the loop that mirrors this
/// recursion keeps a definitional invariant instead of needing a lemma about
/// where the walk stopped.
pub open spec fn resolve_from(
    base_kept: usize,
    kept: Seq<usize>,
    escaped: bool,
    kinds: Seq<ComponentKind>,
    i: int,
) -> FoldState
    decreases kinds.len() - i,
{
    if i >= kinds.len() {
        FoldState { base_kept, kept, escaped }
    } else if escaped {
        FoldState { base_kept, kept, escaped: true }
    } else if kinds[i] == ComponentKind::CurDir {
        resolve_from(base_kept, kept, escaped, kinds, i + 1)
    } else if kinds[i] == ComponentKind::Normal {
        resolve_from(base_kept, kept.push(i as usize), false, kinds, i + 1)
    } else if kept.len() > 0 {
        resolve_from(base_kept, kept.drop_last(), false, kinds, i + 1)
    } else if base_kept > 0 {
        resolve_from((base_kept - 1) as usize, kept, false, kinds, i + 1)
    } else {
        FoldState { base_kept, kept, escaped: true }
    }
}

pub open spec fn resolve_is_correct(
    r: Resolved,
    base_depth: usize,
    kinds: Seq<ComponentKind>,
) -> bool {
    r.escaped == resolve_from(base_depth, Seq::empty(), false, kinds, 0).escaped
        && r.base_kept == resolve_from(base_depth, Seq::empty(), false, kinds, 0).base_kept
        && r.kept@ == resolve_from(base_depth, Seq::empty(), false, kinds, 0).kept
}

// `kept.len() > 0` restates the spec's own clause, and the equal arms are the
// point: each branch advances the cursor exactly once so the invariant's
// `i + 1` is the spec's `i + 1`. Collapsing them would obscure which component
// kind did what.
#[allow(clippy::len_zero, clippy::if_same_then_else)]
pub fn resolve_components(base_depth: usize, kinds: &[ComponentKind]) -> (r: Resolved)
    ensures resolve_is_correct(r, base_depth, kinds@),
{
    let mut base_kept: usize = base_depth;
    let mut kept: Vec<usize> = Vec::new();
    let mut escaped = false;
    let mut i: usize = 0;
    while i < kinds.len()
        invariant
            i <= kinds.len(),
            resolve_from(base_depth, Seq::empty(), false, kinds@, 0)
                == resolve_from(base_kept, kept@, escaped, kinds@, i as int),
        decreases kinds.len() - i,
    {
        let kind = kinds[i];
        if escaped {
            i += 1;
        } else if kind == ComponentKind::CurDir {
            i += 1;
        } else if kind == ComponentKind::Normal {
            kept.push(i);
            i += 1;
        } else if kept.len() > 0 {
            kept.pop();
            i += 1;
        } else if base_kept > 0 {
            base_kept -= 1;
            i += 1;
        } else {
            escaped = true;
            i += 1;
        }
    }
    assert(resolve_from(base_kept, kept@, escaped, kinds@, i as int)
        == FoldState { base_kept, kept: kept@, escaped });
    Resolved { base_kept, kept, escaped }
}

/// The facts one discovery pass measured, in the order they were measured
/// (short-circuiting), so "all earlier facts held" is inherent in the value.
#[derive(Clone, Copy, Debug)]
pub struct WorktreeFacts {
    pub dot_git_regular: bool,
    pub pointer_parsed: bool,
    pub gitdir_is_dir: bool,
    pub commondir_present: bool,
    pub linked_evidence: bool,
    pub commondir_parsed: bool,
    pub common_resolved: bool,
    pub common_is_git_dir: bool,
    pub worktree_is_git_dir: bool,
    pub registered_under_common: bool,
    pub back_pointer_matches: bool,
    pub guest_spelling_consistent: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum WorktreeVerdict {
    NotLinked,
    Linked,
    MalformedPointer,
    MissingGitDir,
    MissingCommonDirFile,
    MalformedCommonDir,
    MissingCommonDir,
    CommonNotAGitDirectory,
    WorktreeNotAGitDirectory,
    NotRegistered,
    BackPointerMismatch,
    SymlinkedLayout,
}

/// The discovery state machine, as one total decision over measured facts.
///
/// The only `Linked` row is the one where every fact holds, and every broken row
/// names the single fact that failed after all earlier ones held. `linked_evidence`
/// is consulted only where `commondir` is absent, which is why it is the one fact
/// that is irrelevant whenever `commondir_present`.
pub fn worktree_verdict(f: WorktreeFacts) -> (v: WorktreeVerdict)
    ensures
        (v == WorktreeVerdict::Linked) == (f.dot_git_regular && f.pointer_parsed
            && f.gitdir_is_dir && f.commondir_present && f.commondir_parsed
            && f.common_resolved && f.common_is_git_dir && f.worktree_is_git_dir
            && f.registered_under_common && f.back_pointer_matches
            && f.guest_spelling_consistent),
        (v == WorktreeVerdict::NotLinked) == (!f.dot_git_regular
            || (f.dot_git_regular && f.pointer_parsed && f.gitdir_is_dir
                && !f.commondir_present && !f.linked_evidence)),
        (v == WorktreeVerdict::MalformedPointer) == (f.dot_git_regular && !f.pointer_parsed),
        (v == WorktreeVerdict::MissingGitDir) == (f.dot_git_regular && f.pointer_parsed
            && !f.gitdir_is_dir),
        (v == WorktreeVerdict::MissingCommonDirFile) == (f.dot_git_regular && f.pointer_parsed
            && f.gitdir_is_dir && !f.commondir_present && f.linked_evidence),
        (v == WorktreeVerdict::MalformedCommonDir) == (f.dot_git_regular && f.pointer_parsed
            && f.gitdir_is_dir && f.commondir_present && !f.commondir_parsed),
        (v == WorktreeVerdict::MissingCommonDir) == (f.dot_git_regular && f.pointer_parsed
            && f.gitdir_is_dir && f.commondir_present && f.commondir_parsed
            && !f.common_resolved),
        (v == WorktreeVerdict::CommonNotAGitDirectory) == (f.dot_git_regular && f.pointer_parsed
            && f.gitdir_is_dir && f.commondir_present && f.commondir_parsed
            && f.common_resolved && !f.common_is_git_dir),
        (v == WorktreeVerdict::WorktreeNotAGitDirectory) == (f.dot_git_regular
            && f.pointer_parsed && f.gitdir_is_dir && f.commondir_present
            && f.commondir_parsed && f.common_resolved && f.common_is_git_dir
            && !f.worktree_is_git_dir),
        (v == WorktreeVerdict::NotRegistered) == (f.dot_git_regular && f.pointer_parsed
            && f.gitdir_is_dir && f.commondir_present && f.commondir_parsed
            && f.common_resolved && f.common_is_git_dir && f.worktree_is_git_dir
            && !f.registered_under_common),
        (v == WorktreeVerdict::BackPointerMismatch) == (f.dot_git_regular && f.pointer_parsed
            && f.gitdir_is_dir && f.commondir_present && f.commondir_parsed
            && f.common_resolved && f.common_is_git_dir && f.worktree_is_git_dir
            && f.registered_under_common && !f.back_pointer_matches),
        (v == WorktreeVerdict::SymlinkedLayout) == (f.dot_git_regular && f.pointer_parsed
            && f.gitdir_is_dir && f.commondir_present && f.commondir_parsed
            && f.common_resolved && f.common_is_git_dir && f.worktree_is_git_dir
            && f.registered_under_common && f.back_pointer_matches
            && !f.guest_spelling_consistent),
{
    if !f.dot_git_regular {
        return WorktreeVerdict::NotLinked;
    }
    if !f.pointer_parsed {
        return WorktreeVerdict::MalformedPointer;
    }
    if !f.gitdir_is_dir {
        return WorktreeVerdict::MissingGitDir;
    }
    if !f.commondir_present {
        return if f.linked_evidence {
            WorktreeVerdict::MissingCommonDirFile
        } else {
            WorktreeVerdict::NotLinked
        };
    }
    if !f.commondir_parsed {
        return WorktreeVerdict::MalformedCommonDir;
    }
    if !f.common_resolved {
        return WorktreeVerdict::MissingCommonDir;
    }
    if !f.common_is_git_dir {
        return WorktreeVerdict::CommonNotAGitDirectory;
    }
    if !f.worktree_is_git_dir {
        return WorktreeVerdict::WorktreeNotAGitDirectory;
    }
    if !f.registered_under_common {
        return WorktreeVerdict::NotRegistered;
    }
    if !f.back_pointer_matches {
        return WorktreeVerdict::BackPointerMismatch;
    }
    if !f.guest_spelling_consistent {
        return WorktreeVerdict::SymlinkedLayout;
    }
    WorktreeVerdict::Linked
}

/// The facts [`metadata_placement`] decides on.
#[derive(Clone, Copy, Debug)]
pub struct PlacementFacts {
    /// The project is mirrored somewhere other than its host path, so a relative
    /// pointer would resolve against the wrong base.
    pub remapped: bool,
    /// The path survives the guest's tmpfs and framing rules.
    pub guest_safe: bool,
    /// The directory contains one of agent-vm's own mounts — measured on the guest
    /// spelling *and* on the canonical host source.
    pub covers_core: bool,
    /// The directory contains a checkout: the project itself, or a worktree the
    /// repository registered inside it. Measured on canonical host paths, so a
    /// symlinked guest spelling cannot hide it.
    pub contains_checkout: bool,
    /// The directory is already inside the writable project bind.
    pub inside_project: bool,
    /// Its guest spelling is its canonical path.
    pub literal: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum Placement {
    Bind,
    CoveredByProject,
    Remapped,
    UnderTmpfs,
    CoversCoreMount,
    ContainsCheckout,
    SymlinkInsideProject,
}

/// Where one metadata directory may go. `Bind` is the only row that adds a
/// declaration; the other six are refusals *except* `CoveredByProject`, which is
/// already reachable through the project bind.
///
/// Covered-by-project is skipped rather than bound because an `ro` bind inside
/// the `rw` project bind would make part of the project read-only; the symlinked
/// spelling of an in-project directory is refused because the `guest` spelling
/// and the host path would then disagree inside the one bind. `ContainsCheckout`
/// sits after `CoversCoreMount` because a checkout created *inside* the common
/// directory also contains the project's own core bind, and that is the fact the
/// reader can act on (`--git-mount=off` is the same remedy for both).
pub fn metadata_placement(f: PlacementFacts) -> (p: Placement)
    ensures
        (p == Placement::Bind) == (!f.remapped && f.guest_safe && !f.covers_core
            && !f.contains_checkout && !f.inside_project),
        (p == Placement::CoveredByProject) == (!f.remapped && f.guest_safe
            && !f.covers_core && !f.contains_checkout && f.inside_project && f.literal),
        (p == Placement::Remapped) == f.remapped,
        (p == Placement::UnderTmpfs) == (!f.remapped && !f.guest_safe),
        (p == Placement::CoversCoreMount) == (!f.remapped && f.guest_safe && f.covers_core),
        (p == Placement::ContainsCheckout) == (!f.remapped && f.guest_safe
            && !f.covers_core && f.contains_checkout),
        (p == Placement::SymlinkInsideProject) == (!f.remapped && f.guest_safe
            && !f.covers_core && !f.contains_checkout && f.inside_project && !f.literal),
{
    if f.remapped {
        return Placement::Remapped;
    }
    if !f.guest_safe {
        return Placement::UnderTmpfs;
    }
    if f.covers_core {
        return Placement::CoversCoreMount;
    }
    if f.contains_checkout {
        return Placement::ContainsCheckout;
    }
    if f.inside_project {
        return if f.literal {
            Placement::CoveredByProject
        } else {
            Placement::SymlinkInsideProject
        };
    }
    Placement::Bind
}

/// The facts [`worktree_coverage`] decides on: how the two directories nest in
/// the guest, and whether the guest-relative suffix names the same host directory.
#[derive(Clone, Copy, Debug)]
pub struct CoverageFacts {
    pub worktree_under_common: bool,
    pub common_under_worktree: bool,
    pub host_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum Coverage {
    /// The common bind already carries the per-worktree directory.
    Covered,
    /// Neither contains the other; both need a bind.
    Separate,
    /// They nest in a way no pair of binds reproduces.
    Refuse,
}

/// One bind when the per-worktree directory lives under the common one *and* the
/// guest resolves the same nesting the host does; two binds when neither contains
/// the other; a refusal otherwise.
///
/// The host half is load-bearing: a guest path that nests while the host path does
/// not means the guest would look inside the common bind for a directory that is
/// somewhere else entirely.
pub fn worktree_coverage(f: CoverageFacts) -> (c: Coverage)
    ensures
        (c == Coverage::Covered) == (f.worktree_under_common && !f.common_under_worktree
            && f.host_matches),
        (c == Coverage::Separate) == (!f.worktree_under_common && !f.common_under_worktree),
        (c == Coverage::Refuse) == (f.common_under_worktree
            || (f.worktree_under_common && !f.host_matches)),
{
    if f.common_under_worktree {
        return Coverage::Refuse;
    }
    if f.worktree_under_common {
        return if f.host_matches {
            Coverage::Covered
        } else {
            Coverage::Refuse
        };
    }
    Coverage::Separate
}

/// The facts [`declaration_enclosure`] decides on, measured for one already
/// selected declaration against one placed metadata directory.
#[derive(Clone, Copy, Debug)]
pub struct EnclosureFacts {
    /// The declaration's guest path is a component-wise ancestor of the metadata
    /// guest path.
    pub encloses: bool,
    /// The declaration's canonical source joined with the guest suffix is the
    /// canonical metadata directory, so both routes name one host directory.
    /// Measured only for a source that resolves: an unmeasurable declaration is
    /// left to `prepare`, which refuses it (see `enclosing_declaration`).
    pub same_host: bool,
    /// A plain live bind: neither `:fork` nor `:follow-links`, so the guest sees
    /// exactly that host directory at that guest path.
    pub live: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Structural)]
pub enum Enclosure {
    /// The declaration does not enclose this path.
    Unrelated,
    /// It already hands the guest this host directory at this path, so an
    /// automatic bind would only restate it — with access the user did not ask
    /// for.
    Reachable,
    /// An automatic bind here would outrank part of the declaration's route and
    /// map it somewhere else.
    Shadowed,
}

/// Whether an automatic bind may be added below a declaration the user wrote.
///
/// Both skipped and refused outcomes drop the automatic request, so the guest
/// keeps exactly the access the declaration gives — the spec's rule that a mode
/// "does not make another explicit writable route read-only" and its converse.
/// A `:fork` or `:follow-links` declaration is `Shadowed` even when the host
/// directory matches, because the guest then sees a copy (or a second
/// discovery), not this directory.
pub fn declaration_enclosure(f: EnclosureFacts) -> (e: Enclosure)
    ensures
        (e == Enclosure::Unrelated) == !f.encloses,
        (e == Enclosure::Reachable) == (f.encloses && f.same_host && f.live),
        (e == Enclosure::Shadowed) == (f.encloses && !(f.same_host && f.live)),
{
    if !f.encloses {
        Enclosure::Unrelated
    } else if f.same_host && f.live {
        Enclosure::Reachable
    } else {
        Enclosure::Shadowed
    }
}
} // verus!

#[cfg(test)]
mod tests;
