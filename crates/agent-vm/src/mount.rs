//! `--mount HOST[:GUEST][:MODE][:MODE]...` parsing and the volume-builder
//! preparation it feeds. [`parse_extra_mounts`] and [`prepare`] are the
//! entry points `run.rs`'s `launch()` calls; everything else here is a
//! private implementation detail of the mount contract.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
#[cfg(test)]
use microsandbox::sandbox::MountBuilder;

#[cfg(test)]
use crate::protected_host_files::CoreBind;
use crate::protected_host_files::{
    CoreHostSource, ProtectedFile, ProtectedHostFiles, ProtectedIdentities, Severity,
};
use crate::run::guest_path_is_mountable;

/// A recognized `--mount` mode keyword: `ro`, `rw`, `fork`, or `follow-links`
/// (issue #11 — auto-discover and bind-mount the real directories that
/// symlinks under `HOST` transitively resolve to; see
/// [`discover_followed_targets`]/[`expand_follow_links`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountMode {
    ReadOnly,
    ReadWrite,
    FollowLinks,
    Fork,
}

impl MountMode {
    /// Classify one trailing suffix segment as a mode keyword.
    /// `None` = not a known keyword (caller raises "unknown mode").
    fn from_keyword(kw: &str) -> Option<MountMode> {
        match kw {
            "ro" => Some(MountMode::ReadOnly),
            "rw" => Some(MountMode::ReadWrite),
            "follow-links" => Some(MountMode::FollowLinks),
            "fork" => Some(MountMode::Fork),
            _ => None,
        }
    }

    /// The canonical keyword, for error messages that name the offending
    /// token (matches the `parse_publish_args` idiom).
    fn keyword(self) -> &'static str {
        match self {
            MountMode::ReadOnly => "ro",
            MountMode::ReadWrite => "rw",
            MountMode::FollowLinks => "follow-links",
            MountMode::Fork => "fork",
        }
    }
}

/// Mode-keyword pairs that cannot appear together on one mount. This is the
/// single place the conflict policy lives. Note `ro`+`follow-links` is
/// intentionally NOT listed, because they coexist (follow-links implies
/// read-only) — which is precisely why a single mutually-exclusive
/// `Option<MountMode>` slot would be wrong.
const INCOMPATIBLE_MODES: &[(MountMode, MountMode)] = &[
    (MountMode::ReadOnly, MountMode::ReadWrite),
    (MountMode::ReadWrite, MountMode::FollowLinks),
    (MountMode::Fork, MountMode::ReadOnly),
    (MountMode::Fork, MountMode::ReadWrite),
];

/// True iff `a` and `b` may not appear on the same mount (order-independent).
fn modes_conflict(a: MountMode, b: MountMode) -> bool {
    INCOMPATIBLE_MODES
        .iter()
        .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a))
}

/// The closed set of valid mount policies. Parsing is the only place that
/// constructs it, so contradictory combinations never reach preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountPolicy {
    BindReadWrite,
    BindReadOnly { follow_links: bool },
    Fork { follow_links: bool },
}

/// One `--mount HOST[:GUEST][:MODE][:MODE]...` argument resolved into
/// separate paths plus its validated policy.
#[derive(Clone, Debug)]
pub(crate) struct ExtraMount {
    /// Exact source spelling. It is part of fork identity and deliberately not canonicalized.
    pub(crate) source_spelling: String,
    pub(crate) host: PathBuf,
    pub(crate) guest: PathBuf,
    pub(crate) policy: MountPolicy,
    /// Normalized relative entries omitted from a `:fork` seed. Empty for
    /// every live bind: `:exclude` is fork-only (issue #113).
    pub(crate) exclusions: Vec<PathBuf>,
}

impl ExtraMount {
    fn is_readonly(&self) -> bool {
        matches!(self.policy, MountPolicy::BindReadOnly { .. })
    }
    fn follows_links(&self) -> bool {
        matches!(
            self.policy,
            MountPolicy::BindReadOnly { follow_links: true }
                | MountPolicy::Fork { follow_links: true }
        )
    }
    fn is_fork(&self) -> bool {
        matches!(self.policy, MountPolicy::Fork { .. })
    }
}

/// A `GUEST` segment must start with `/` or `.`; anything trailing that
/// doesn't is a mode keyword. This is the sole rule that disambiguates
/// `HOST:GUEST` from `HOST:MODE` (e.g. `HOST:ro`) since both are a single
/// segment right after `HOST`.
fn segment_is_guest_path(seg: &str) -> bool {
    seg.starts_with('/') || seg.starts_with('.')
}

/// Parse the raw `--mount` argv strings into `ExtraMount`s.
///
/// Grammar: `HOST[:GUEST][:MODE][:MODE]...`. `HOST` alone defaults `GUEST`
/// to the same absolute path (mirror), read-write. `GUEST`, if present,
/// must be the segment immediately after `HOST` and must start with `/` or
/// `.` (see [`segment_is_guest_path`]); everything after that is a mode
/// keyword (`ro`/`rw` — see [`MountMode`]). Path validity is checked before
/// mode keywords so `relativehost:bogus` reports the host error, not
/// "unknown mode". `ro`+`rw` together, and any keyword `MountMode` doesn't
/// recognize, are hard parse-time errors.
///
/// Known, deliberate deviation from the pre-mode-suffix grammar: previously
/// `HOST:GUEST` split on the *first* colon only, so a `GUEST` could contain
/// literal trailing colons (e.g. `/h:/g:x` kept `guest = "/g:x"`). The new
/// grammar splits on every colon, so trailing colon-separated tokens are
/// now interpreted as mode keywords instead — `/h:/g:x` now fails as
/// "unknown mode keyword \"x\"". Colon-bearing guest paths were
/// undocumented/pathological; this change is intentional and pinned by
/// `parse_extra_mounts_colon_in_guest_now_mode_error`.
///
/// Second deliberate deviation, same bucket: a relative `GUEST` with no
/// leading `/` or `.` (e.g. `/abs-host:relative-guest`) used to fail with
/// "guest path must be absolute". Since a bare trailing segment is now
/// classified as a mode keyword rather than a guest path, it instead fails
/// as "unknown mode keyword \"relative-guest\"" — still a hard error, just a
/// different message. Pinned by `parse_extra_mounts_rejects_relative_paths`.
pub(crate) fn parse_extra_mounts(raw: &[String]) -> Result<Vec<ExtraMount>> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let mut segs = entry.split(':').map(str::trim);
        let host_s = segs.next().unwrap_or_default().to_string();
        let mut tail: Vec<&str> = segs.collect();

        // Optional GUEST: only the first tail segment, and only if it
        // looks like a path. Otherwise GUEST mirrors HOST (today's default).
        let guest_s = if tail.first().is_some_and(|s| segment_is_guest_path(s)) {
            tail.remove(0).to_string()
        } else {
            host_s.clone()
        };

        // --- Path validation first, so path errors beat mode errors. ---
        if host_s.is_empty() {
            anyhow::bail!("--mount value {entry:?} must be HOST[:GUEST] (non-empty)");
        }
        let host = PathBuf::from(&host_s);
        let guest = PathBuf::from(&guest_s);
        if !host.is_absolute() {
            anyhow::bail!("--mount host path {host_s:?} must be absolute");
        }
        if !guest.is_absolute() {
            anyhow::bail!("--mount guest path {guest_s:?} must be absolute");
        }
        // The guest mount point reaches agentd via the boot-params side
        // channel (not the kernel command line), so non-ASCII and spaces
        // are fine — but a control character (TAB/newline) would break the
        // `KEY\tVALUE\n` framing, so reject those. See
        // `guest_path_is_mountable`.
        if !guest_path_is_mountable(&guest_s) {
            anyhow::bail!(
                "--mount guest path {guest_s:?} contains control characters that can't be \
                 carried into the guest; pass a guest path without tabs/newlines"
            );
        }

        // --- Then classify the remaining tail segments as mode keywords. ---
        let mut modes: Vec<MountMode> = Vec::new();
        for kw in tail {
            if kw.is_empty() {
                // e.g. `/h::ro` — a stray `::`. Point at it rather than
                // reporting "unknown mode keyword \"\"".
                anyhow::bail!(
                    "--mount {entry:?}: empty segment (stray `:`); expected \
                     HOST[:GUEST][:MODE]..."
                );
            }
            if kw.strip_prefix("exclude=").is_some() {
                continue;
            }
            let mode = MountMode::from_keyword(kw).ok_or_else(|| {
                anyhow::anyhow!(
                    "--mount {entry:?}: unknown mode keyword {kw:?} \
                     (expected `ro`, `rw`, `fork`, `follow-links`, or `exclude=REL`)"
                )
            })?;
            if let Some(&prev) = modes.iter().find(|&&prev| modes_conflict(prev, mode)) {
                anyhow::bail!(
                    "--mount {entry:?}: conflicting modes `{}` and `{}` — pick one",
                    prev.keyword(),
                    mode.keyword()
                );
            }
            modes.push(mode);
        }
        let follow_links = modes.contains(&MountMode::FollowLinks);
        // follow-links implies read-only; bare follow-links behaves as ro.
        let readonly = modes.contains(&MountMode::ReadOnly) || follow_links;

        let fork = modes.contains(&MountMode::Fork);
        let mut exclusions = Vec::new();
        // Exclusion values share the suffix list with modes.  They are parsed
        // here (before any source I/O) so an already READY fork can be reused
        // after its source has disappeared.
        for suffix in entry.split(':').skip(
            if segment_is_guest_path(entry.split(':').nth(1).unwrap_or("")) {
                2
            } else {
                1
            },
        ) {
            let suffix = suffix.trim();
            if let Some(value) = suffix.strip_prefix("exclude=") {
                exclusions.push(
                    normalize_exclusion(value).with_context(|| format!("--mount {entry:?}"))?,
                );
            }
        }
        exclusions.sort();
        exclusions.dedup();
        let mut collapsed = Vec::new();
        for path in exclusions {
            if !collapsed
                .iter()
                .any(|parent: &PathBuf| path.starts_with(parent))
            {
                collapsed.push(path);
            }
        }
        let exclusions = collapsed;
        let policy = if fork {
            MountPolicy::Fork { follow_links }
        } else if readonly {
            MountPolicy::BindReadOnly { follow_links }
        } else {
            MountPolicy::BindReadWrite
        };
        // `:exclude` omits entries from a fork seed. On a live bind there is
        // no seed to omit from, and the old opaque-mask substitute is removed
        // (issue #113), so reject the declaration here — after normalization
        // and mode-conflict precedence, but before any source I/O.
        if !exclusions.is_empty() && !matches!(policy, MountPolicy::Fork { .. }) {
            anyhow::bail!(
                "--mount {entry}: :exclude is only supported on :fork mounts;\n\
                 live binds cannot hide nested paths."
            );
        }
        out.push(ExtraMount {
            source_spelling: host_s,
            host,
            guest,
            policy,
            exclusions,
        });
    }
    Ok(out)
}

/// Validate an exclusion without allowing Path's lexical normalization to
/// hide an escaping or empty component.
fn normalize_exclusion(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() || raw.contains(':') || raw.chars().any(char::is_control) {
        anyhow::bail!("exclude must be a non-empty relative path");
    }
    let mut out = PathBuf::new();
    for component in raw.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            anyhow::bail!("exclude must contain only normal relative components");
        }
        out.push(component);
    }
    Ok(out)
}

/// Configure a bind-mount `MountBuilder` for an `ExtraMount`: bind the host
/// path and apply `.readonly()` when the mount was parsed `:ro`. Factored
/// out of the `.volume(...)` closure so the readonly wiring has a boot-free
/// unit seam (see `extra_mount_ro_propagates_readonly_into_built_volume`).
#[cfg(test)]
pub(crate) fn configure_extra_mount(
    m: MountBuilder,
    host: PathBuf,
    readonly: bool,
) -> MountBuilder {
    let m = m.bind(host);
    if readonly { m.readonly() } else { m }
}

/// Depth cap on symlink-*follow* chains specifically — NOT on plain
/// directory nesting under `HOST` or a discovered target (see the
/// `link_depth` bookkeeping in [`discover_followed_targets`], which only
/// increments when a symlink is followed). The `visited` set stops the
/// walk revisiting a host/guest pair, which alone bounds every layout
/// whose guest paths come from a finite set — but a literal alias derives
/// a *new* guest path from link text, so a pathological chain of relative
/// links could keep minting pairs. This cap is what bounds that; 40 is
/// deep enough for any real skill farm while still stopping a runaway.
const MAX_LINK_DEPTH: usize = 40;

/// A directory in both the worlds the follow-links walk straddles: where
/// it really lives on the host, and the path the guest reaches it by.
///
/// The two coincide for an ordinary mirror bind. They diverge inside a
/// *literal alias* — a second bind of one host directory at the path some
/// link's raw text names (see [`literal_guest_path`]) — and the walk has
/// to carry both, because a relative symlink found inside that directory
/// resolves against whichever path the guest entered by, not against the
/// host's canonical one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BindPath {
    host: PathBuf,
    guest: PathBuf,
    /// Exclusions projected into this bind root's logical tree. A followed
    /// directory receives only the suffixes below the link that reached it.
    exclusions: Vec<PathBuf>,
}

impl BindPath {
    /// One host directory bound at its own real path — the ordinary case.
    #[cfg(test)]
    fn mirrored(path: PathBuf) -> BindPath {
        BindPath {
            host: path.clone(),
            guest: path,
            exclusions: Vec::new(),
        }
    }

    /// Descend into `name` on both sides at once.
    fn join(&self, name: &std::ffi::OsStr) -> BindPath {
        BindPath {
            host: self.host.join(name),
            guest: self.guest.join(name),
            exclusions: self.exclusions.clone(),
        }
    }
}

impl From<BindPath> for ExtraMount {
    /// Discovered binds retain their read-only follow policy. They are
    /// appended after discovery, so the marker cannot trigger another pass.
    fn from(p: BindPath) -> ExtraMount {
        ExtraMount {
            source_spelling: p.host.display().to_string(),
            host: p.host,
            guest: p.guest,
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: p.exclusions,
        }
    }
}

/// Join a symlink's raw target text against the directory holding the link
/// and fold `.`/`..` *lexically*, i.e. as pure string surgery with no
/// filesystem lookups.
///
/// Folding this way models a kernel's resolution only while no `..`
/// crosses a symlinked component — the kernel expands a symlink *before*
/// applying the `..` that follows it, so the two answers part company
/// exactly there. [`literal_guest_path`] is what detects that divergence;
/// this function's contract is only the string operation. `None` when the
/// link has no parent or a `..` escapes above the root.
fn lexical_link_path(link: &Path, raw_target: &Path) -> Option<PathBuf> {
    use std::path::Component;

    let joined = if raw_target.is_absolute() {
        raw_target.to_path_buf()
    } else {
        link.parent()?.join(raw_target)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(seg) => out.push(seg),
        }
    }
    Some(out)
}

/// What [`literal_guest_path`] concluded about one symlink's raw target
/// text. `Declined` is not a failure — the walk carries on and surfaces
/// the warning — which is why this is an enum and not a `Result`.
enum LiteralPath {
    /// The mirror bind at the canonical path already covers this link:
    /// the guest resolves the text to exactly the directory the host did.
    AlreadyCovered,
    /// The guest resolves the text to this path instead, so the same host
    /// directory needs a second bind here.
    MirrorAt(PathBuf),
    /// Cannot be mirrored safely; carries the warning to surface.
    Declined(String),
}

/// One `Declined` warning, phrased alike for every reason: name the
/// symlink, give the reason, state what it costs the user.
fn declined(link: &Path, reason: String) -> String {
    format!(
        "not mirroring symlink {} — {reason}; it may not resolve inside the sandbox",
        link.display()
    )
}

/// Where the guest will look when it resolves the symlink `link`, given
/// that the host resolves it to `canonical`.
///
/// The guest sees the link verbatim through an enclosing bind, so its
/// `readlink()` returns the raw target text and the guest kernel resolves
/// *that*, starting from `link.guest`'s parent. The host's canonicalized
/// answer names the same directory only when every component of the text
/// is already a real directory the guest can walk. When an intermediate
/// component is itself a symlink, the guest never reaches the canonical
/// path at all:
///
/// ```text
/// ~/.claude/skills/implement -> ~/code/conf/.agents/skills/implement   (raw text)
/// ~/code/conf/.agents/skills -> ../skills                              (parent link)
/// canonical                   = ~/code/conf/skills/implement
/// ```
///
/// Binding only `~/code/conf/skills/implement` leaves the guest looking up
/// `~/code/conf/.agents/…`, which nothing is mounted at. A second bind of
/// the same real directory at the literal path closes the gap: agentd
/// creates a mount point's missing ancestors before binding it, so the
/// `.agents/skills` directories come into being on the way. (Ancestors
/// that would land inside an already-read-only bind cannot be created;
/// that surfaces as a boot error rather than as silent breakage.)
///
/// [`LiteralPath::Declined`] covers text we will not mirror:
/// - text whose `..` cannot be folded without consulting the filesystem,
///   because a `..` crosses a symlinked component. The kernel expands the
///   symlink first, so no single mount point reproduces its answer and
///   the honest move is to warn rather than bind somewhere merely
///   plausible. Detected by folding on the host side, where the result
///   can be checked against `canonical`.
/// - a mount point outside `home`, which would let a link inside `$HOME`
///   place a bind anywhere in the guest's filesystem.
fn literal_guest_path(link: &BindPath, canonical: &Path, home: &Path) -> LiteralPath {
    let raw = match fs::read_link(&link.host) {
        Ok(r) => r,
        Err(e) => {
            return LiteralPath::Declined(declined(
                &link.host,
                format!("its target text could not be read: {e}"),
            ));
        }
    };
    // The same fold applied twice: on the host side purely so the result
    // can be checked against `canonical`, on the guest side for the answer
    // we actually want. Agreement on the host therefore transfers to the
    // guest, which is what lets an alias deep inside the walk be trusted.
    let (Some(on_host), Some(on_guest)) = (
        lexical_link_path(&link.host, &raw),
        lexical_link_path(&link.guest, &raw),
    ) else {
        return LiteralPath::Declined(declined(
            &link.host,
            format!(
                "its target {} folds above the filesystem root",
                raw.display()
            ),
        ));
    };
    if on_guest == canonical {
        return LiteralPath::AlreadyCovered;
    }
    if on_host.canonicalize().ok().as_deref() != Some(canonical) {
        return LiteralPath::Declined(declined(
            &link.host,
            format!(
                "its target text does not name {} on the host",
                canonical.display()
            ),
        ));
    }
    if !on_guest.starts_with(home) {
        return LiteralPath::Declined(declined(
            &link.host,
            format!(
                "the guest would look it up at {}, outside your $HOME ({})",
                on_guest.display(),
                home.display()
            ),
        ));
    }
    LiteralPath::MirrorAt(on_guest)
}

/// Walk `root` (already canonicalized) on the host side and return the
/// binds needed to make the symlinks it transitively contains resolve
/// inside the guest, plus warnings for anything skipped along the way
/// (symlink-to-file, dangling symlink, unreadable subdirectory, depth-cap
/// hit, un-mirrorable literal path).
///
/// Every canonicalized *directory* target gets a mirror bind at its own
/// real path, and a target whose link text reaches it through a symlinked
/// parent gets a second bind at that literal path as well — the guest
/// resolves link text, not canonical paths (see [`literal_guest_path`]).
/// A target bound at such an alias is then walked *again* under that
/// alias, because a relative symlink inside it resolves against the path
/// the guest entered by. Entries are distinct by guest path.
///
/// `root` carries both sides for the same reason: the mount it came from
/// may name a guest path that differs from the host directory — either
/// explicitly (`--mount HOST:GUEST:follow-links`) or, far more commonly,
/// because `HOST` was itself a symlink and `parse_extra_mounts`
/// canonicalized it while leaving `GUEST` as typed. A relative link
/// directly under such a root resolves against the guest side, so that is
/// what the walk has to track.
///
/// Returning warnings as data instead of `eprintln!`ing them keeps this
/// function side-effect-free so tests can assert on the warning text, not
/// just on what got left out of the returned target list — see
/// `discover_file_target_skipped`/`discover_dangling_skipped`. The caller
/// (`expand_follow_links`, and ultimately `launch()`) decides how/whether
/// to print them.
///
/// `home` is the invoking user's already-canonicalized `$HOME`. A resolved
/// directory target outside it is a hard error naming both the symlink and
/// the target (safety guardrail — see issue #9/#11).
fn discover_followed_targets(root: &BindPath, home: &Path) -> Result<(Vec<BindPath>, Vec<String>)> {
    let mut visited: std::collections::HashSet<BindPath> = std::collections::HashSet::new();
    let mut out: Vec<BindPath> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    // (directory to scan — host side, plus the guest path it is reached
    // by — and the symlink-follow depth so far).
    let mut worklist: Vec<(BindPath, PathBuf, usize)> = vec![(root.clone(), PathBuf::new(), 0)];

    while let Some((dir, logical_relative, link_depth)) = worklist.pop() {
        // Keyed on the host/guest pair, not the host path alone: one real
        // directory reached by two different guest paths has to be walked
        // twice, since a relative symlink inside it resolves against the
        // path the guest entered by. Two symlinks resolving to the same
        // pair (or a symlink back to an already-walked ancestor) collapse
        // to one entry here, which is what actually terminates cycles —
        // the depth cap above is a secondary bound.
        if !visited.insert(dir.clone()) {
            continue;
        }
        let entries = match fs::read_dir(&dir.host) {
            Ok(e) => e,
            Err(e) => {
                // A permission-denied (or otherwise unreadable) subdir must
                // not abort the whole launch — warn and move on.
                warnings.push(format!(
                    "skipping unreadable directory {}: {e}",
                    dir.host.display()
                ));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warnings.push(format!(
                        "skipping unreadable entry under {}: {e}",
                        dir.host.display()
                    ));
                    continue;
                }
            };
            let path = dir.join(&entry.file_name());
            // Exclusions are evaluated in the declaration's logical tree
            // before metadata or link resolution.  In particular, a hidden
            // symlink cannot cause a follow-links bind to widen visibility.
            let child_relative = logical_relative.join(entry.file_name());
            if is_excluded(&child_relative, &dir.exclusions) {
                continue;
            }
            // lstat (no follow) so we can tell "is a symlink" from "is a
            // real dir/file" without resolving anything yet.
            let meta = match fs::symlink_metadata(&path.host) {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!("skipping {}: {e}", path.host.display()));
                    continue;
                }
            };
            if !meta.file_type().is_symlink() {
                if meta.is_dir() {
                    // Already visible via the HOST bind (or a discovered
                    // parent's own bind) — don't add it to `out`, just
                    // descend to find symlinks nested further down.
                    // Directory nesting does not consume `link_depth`.
                    worklist.push((path, child_relative.clone(), link_depth));
                }
                // A plain file is already visible via the HOST bind too;
                // nothing to do.
                continue;
            }
            if link_depth >= MAX_LINK_DEPTH {
                warnings.push(format!(
                    "skipping symlink {} — exceeded max follow depth ({MAX_LINK_DEPTH}); \
                     possible pathological symlink chain",
                    path.host.display()
                ));
                continue;
            }
            let target = match path.host.canonicalize() {
                Ok(t) => t,
                Err(_) => {
                    warnings.push(format!("skipping dangling symlink {}", path.host.display()));
                    continue;
                }
            };
            let target_meta = match fs::metadata(&target) {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!(
                        "skipping symlink {} -> {}: {e}",
                        path.host.display(),
                        target.display()
                    ));
                    continue;
                }
            };
            if !target_meta.is_dir() {
                warnings.push(format!(
                    "skipping symlink {} -> {} (not a directory)",
                    path.host.display(),
                    target.display()
                ));
                continue;
            }
            if !target.starts_with(home) {
                anyhow::bail!(
                    "--mount follow-links: symlink {} resolves to {}, which is outside your \
                     $HOME ({}); refusing to mount it",
                    path.host.display(),
                    target.display(),
                    home.display()
                );
            }
            // Dedup within this walk on the guest path — the one thing
            // that has to be unique, since it is the mount point. Note
            // this does not special-case a target that lands *inside*
            // `root` or another already-discovered target (see
            // `expand_follow_links` doc) — that's a redundant-but-harmless
            // extra bind at its own real path, not a correctness issue.
            let mut push_unique_guest = |b: BindPath| {
                if let Some(existing) = out.iter_mut().find(|d| d.guest == b.guest) {
                    // One target can be reached through more than one
                    // logical link. Keep the union: dropping the later
                    // projected exclusion would let that alias bypass its
                    // opaque mask.
                    for exclusion in b.exclusions {
                        if !existing.exclusions.contains(&exclusion) {
                            existing.exclusions.push(exclusion);
                        }
                    }
                    existing.exclusions.sort();
                    existing.exclusions.dedup();
                } else {
                    out.push(b);
                }
            };
            let projected_exclusions = project_exclusions(&dir.exclusions, &child_relative);
            let mirror = BindPath {
                host: target.clone(),
                guest: target.clone(),
                exclusions: projected_exclusions.clone(),
            };
            push_unique_guest(mirror.clone());
            worklist.push((mirror, PathBuf::new(), link_depth + 1));
            // …and again at the path the guest's own `readlink()` will
            // name, when a symlinked parent makes that differ. The alias
            // is walked too: a relative symlink inside `target` resolves
            // against whichever of the two paths the guest came in by, so
            // the alias needs its own pass to discover its own aliases.
            match literal_guest_path(&path, &target, home) {
                LiteralPath::AlreadyCovered => {}
                LiteralPath::MirrorAt(guest) => {
                    let alias = BindPath {
                        host: target,
                        guest,
                        exclusions: projected_exclusions,
                    };
                    push_unique_guest(alias.clone());
                    worklist.push((alias, PathBuf::new(), link_depth + 1));
                }
                LiteralPath::Declined(w) => warnings.push(w),
            }
        }
    }
    Ok((out, warnings))
}

/// Given the parsed mounts, append the auto-discovered read-only mounts for
/// every `follow_links` entry, then dedup identical mounts and reject
/// guest-path collisions. `home` is the invoking user's `$HOME` (or `None`
/// when unset). If any entry has `follow_links` and `home` is `None`, this
/// is a hard error (the guardrail can't run without a `$HOME`); when no
/// entry follows links, `home` is unused and `None` is fine. Pure w.r.t.
/// the sandbox; touches only the filesystem under the mounted trees.
///
/// Returns the finalized mount list plus every warning collected while
/// discovering targets, for the caller to print (see `launch()`).
///
/// Each walk is rooted at the entry's host *and* guest path, so relative
/// link text under a root whose two sides differ — a remapped
/// `--mount HOST:GUEST`, or a `HOST` that was itself a symlink — resolves
/// the way the guest will resolve it.
pub(crate) fn expand_follow_links(
    mounts: Vec<ExtraMount>,
    home: Option<&Path>,
) -> Result<(Vec<ExtraMount>, Vec<String>)> {
    let mut mounts = mounts;
    // Live bind roots retain historical canonical-path behavior. Fork data
    // is already an owned committed path and is intentionally not resolved.
    for mount in mounts.iter_mut().filter(|m| !m.is_fork()) {
        mount.host = mount
            .host
            .canonicalize()
            .with_context(|| format!("canonicalizing --mount host {:?}", mount.source_spelling))?;
    }
    if !mounts.iter().any(|m| m.follows_links() && !m.is_fork()) {
        return Ok((mounts, Vec::new()));
    }
    let home = home.context(
        "$HOME is not set — required for --mount follow-links (pass --root to run as root \
         instead, or drop follow-links)",
    )?;
    // Canonicalize once so the guardrail's `starts_with` comparison is
    // real-path vs. real-path (macOS `/var` vs `/private/var`, etc.).
    let home_canon = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());

    let mut warnings = Vec::new();
    let mut expanded = mounts;
    let mut discovered_targets: Vec<BindPath> = Vec::new();
    for m in &expanded {
        if !m.follows_links() || m.is_fork() {
            continue;
        }
        let root = BindPath {
            host: m.host.clone(),
            guest: m.guest.clone(),
            exclusions: m.exclusions.clone(),
        };
        let (targets, mut w) = discover_followed_targets(&root, &home_canon)?;
        warnings.append(&mut w);
        discovered_targets.extend(targets);
    }
    // The original follow-links mount (the HOST bind itself) stays in the
    // list unchanged; this appends one read-only mount per distinct
    // discovered guest path — the target's own real path, plus the literal
    // path a symlinked parent makes the guest look up (see
    // `literal_guest_path`).
    expanded.extend(discovered_targets.into_iter().map(ExtraMount::from));

    // Finalize across the whole resulting list: dedup a guest path that
    // repeats with the *same* host (two symlinks resolving to the same
    // real path, or the same target discovered from two separate
    // `--mount …:follow-links` entries); hard-error a guest path claimed
    // by two *different* hosts. Preserve first-seen order for stable,
    // testable output and stable `==> Mounting …` log ordering.
    let mut finalized = Vec::with_capacity(expanded.len());
    for mount in expanded {
        if let Some(existing) = finalized
            .iter_mut()
            .find(|existing: &&mut ExtraMount| existing.guest == mount.guest)
        {
            // A target can be both an explicit declaration and a discovered
            // canonical/literal alias.  Keep the logical exclusions from
            // every route: dropping those on the already-present explicit
            // declaration lets an alias bypass an opaque mask.  `ro` and
            // discovered `ro:follow-links` have the same bind access; retain
            // follow-links if either route needs its safe alias behavior.
            if existing.host == mount.host && existing.is_readonly() && mount.is_readonly() {
                existing.policy = MountPolicy::BindReadOnly {
                    follow_links: existing.follows_links() || mount.follows_links(),
                };
                merge_exclusions(&mut existing.exclusions, mount.exclusions);
                continue;
            }
            if existing.host == mount.host && existing.policy == mount.policy {
                merge_exclusions(&mut existing.exclusions, mount.exclusions);
                continue;
            }
            anyhow::bail!(
                "--mount: guest path {} is claimed by different declarations ({} and {})",
                mount.guest.display(),
                existing.host.display(),
                mount.host.display()
            );
        }
        finalized.push(mount);
    }
    Ok((finalized, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_extra_mounts ───────────────────────────────────────

    #[test]
    fn parse_extra_mounts_mirror_form() {
        // Mirror form: HOST alone → guest = host. Resolve against
        // cwd so the host path canonicalize succeeds in the test.
        // Use `/` which always exists.
        let parsed = parse_extra_mounts(&["/".into()]).expect("ok");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].host, std::path::Path::new("/"));
        assert_eq!(parsed[0].guest, std::path::Path::new("/"));
    }

    #[test]
    fn parse_extra_mounts_remap_form() {
        let parsed = parse_extra_mounts(&["/:/guest-mount".into()]).expect("ok");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].host, std::path::Path::new("/"));
        assert_eq!(parsed[0].guest, std::path::Path::new("/guest-mount"));
    }

    #[test]
    fn parse_extra_mounts_rejects_relative_paths() {
        assert!(parse_extra_mounts(&["relative-host".into()]).is_err());
        assert!(parse_extra_mounts(&["/abs-host:relative-guest".into()]).is_err());
        assert!(parse_extra_mounts(&["relative-host:/abs-guest".into()]).is_err());
    }

    #[test]
    fn parse_extra_mounts_rejects_empty_side() {
        assert!(parse_extra_mounts(&[":/guest".into()]).is_err());
        assert!(parse_extra_mounts(&["/host:".into()]).is_err());
        assert!(parse_extra_mounts(&["".into()]).is_err());
    }

    #[test]
    fn parse_extra_mounts_defers_missing_source_for_ready_fork_reuse() {
        // Parsing is intentionally source-I/O free: a READY fork can be
        // reused after its original source disappears.
        let r = parse_extra_mounts(&["/this/path/does/not/exist/anywhere:fork".into()]);
        assert!(r.is_ok());
    }

    #[test]
    fn parse_extra_mounts_allows_non_ascii_guest_rejects_control_chars() {
        // A non-ASCII guest mount point now travels via the boot-params
        // side channel (not the cmdline), so it is accepted and mirrored.
        // Host `/` exists so canonicalize succeeds.
        let parsed = parse_extra_mounts(&["/:/монтаж".into()]).expect("non-ASCII guest is ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/монтаж"));
        // Plain ASCII guest path still works.
        assert!(parse_extra_mounts(&["/:/mnt/ref".into()]).is_ok());
        // A control char (TAB) would break the KEY\tVALUE boot-params
        // framing, so it's rejected with guidance.
        let err = parse_extra_mounts(&["/:/mnt/a\tb".into()])
            .expect_err("control char in guest path must be rejected")
            .to_string();
        assert!(
            err.contains("control characters"),
            "error should call out control characters, got: {err}"
        );
    }

    // ── parse_extra_mounts: `[:ro|:rw]` mode suffixes ─────────────

    #[test]
    fn parse_extra_mounts_mode_defaults_readwrite() {
        // AC-1: unchanged behavior for the pre-existing forms, plus the
        // new `readonly` field defaulting false.
        let parsed = parse_extra_mounts(&["/".into()]).expect("ok");
        assert!(!parsed[0].is_readonly());
        let parsed = parse_extra_mounts(&["/:/g".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(!parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_ro_no_guest() {
        let parsed = parse_extra_mounts(&["/:ro".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/"));
        assert!(parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_rw_no_guest() {
        let parsed = parse_extra_mounts(&["/:rw".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/"));
        assert!(!parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_guest_and_ro() {
        let parsed = parse_extra_mounts(&["/:/g:ro".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_guest_and_rw() {
        let parsed = parse_extra_mounts(&["/:/g:rw".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(!parsed[0].is_readonly());
    }

    #[test]
    fn parse_extra_mounts_conflicting_modes_ro_then_rw() {
        let err = parse_extra_mounts(&["/:ro:rw".into()])
            .expect_err("ro:rw must conflict")
            .to_string();
        assert!(err.contains("conflicting"), "got: {err}");
        assert!(err.contains("ro") && err.contains("rw"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_conflicting_modes_rw_then_ro() {
        // Same assertion, reversed order — proves order-independence.
        let err = parse_extra_mounts(&["/:rw:ro".into()])
            .expect_err("rw:ro must conflict")
            .to_string();
        assert!(err.contains("conflicting"), "got: {err}");
        assert!(err.contains("ro") && err.contains("rw"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_unknown_mode() {
        let err = parse_extra_mounts(&["/:bogus-mode".into()])
            .expect_err("unknown mode must error")
            .to_string();
        assert!(err.contains("bogus-mode"), "got: {err}");
        assert!(err.contains("unknown"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_guest_vs_mode_disambiguation() {
        // Leading '/' -> classified as GUEST, then ':ro' is a mode.
        let parsed = parse_extra_mounts(&["/:/mnt/ref:ro".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/mnt/ref"));
        assert!(parsed[0].is_readonly());

        // Leading '.' -> classified as GUEST too, then rejected by the
        // existing absolute-path check (not "unknown mode").
        let err = parse_extra_mounts(&["/:./rel:ro".into()])
            .expect_err("relative GUEST must be rejected")
            .to_string();
        assert!(err.contains("absolute"), "got: {err}");
        assert!(!err.contains("unknown mode"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_extra_path_in_mode_position() {
        // Only one GUEST segment is accepted (the first); a second
        // path-shaped segment in mode position is an unknown keyword.
        let err = parse_extra_mounts(&["/:/g:/g2".into()])
            .expect_err("second path segment must be rejected")
            .to_string();
        assert!(err.contains("unknown mode keyword"), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_empty_middle_segment() {
        // A stray `::` should not surface as `unknown mode keyword ""`.
        let err = parse_extra_mounts(&["/::ro".into()])
            .expect_err("empty middle segment must be rejected")
            .to_string();
        assert!(!err.contains("unknown mode keyword \"\""), "got: {err}");
    }

    #[test]
    fn parse_extra_mounts_colon_in_guest_now_mode_error() {
        // Deliberate, documented deviation from the old first-colon-only
        // split: a trailing colon-separated token on a GUEST path is now
        // parsed as a mode separator, not kept literal in the guest path.
        let err = parse_extra_mounts(&["/:/mnt/ref:x".into()])
            .expect_err("trailing 'x' must be an unknown mode")
            .to_string();
        assert!(err.contains("unknown mode"), "got: {err}");
    }

    #[test]
    fn parse_fork_and_normalizes_exclusions() {
        // Both fork policies accept exclusions, regardless of suffix order.
        for entry in [
            "/:/guest:fork:exclude=cache:exclude=cache/a",
            "/:exclude=cache:exclude=cache/a:fork",
            "/:/guest:exclude=cache:fork",
        ] {
            let parsed = parse_extra_mounts(&[entry.into()]).expect("fork syntax");
            assert!(parsed[0].is_fork(), "{entry}");
            assert!(!parsed[0].is_readonly(), "{entry}");
            // Ancestor collapse keeps only `cache`.
            assert_eq!(
                parsed[0].exclusions,
                vec![PathBuf::from("cache")],
                "{entry}"
            );
        }
        // Duplicate and sibling entries dedup/sort without swallowing siblings.
        let parsed =
            parse_extra_mounts(&["/:fork:exclude=b:exclude=a:exclude=b:exclude=a/b".into()])
                .unwrap();
        assert_eq!(
            parsed[0].exclusions,
            vec![PathBuf::from("a"), PathBuf::from("b")]
        );
        // A nonexistent source never reaches the filesystem at parse time.
        assert!(parse_extra_mounts(&["/no/such/source:fork:exclude=x".into()]).is_ok());
        // Mode conflicts still win over exclusion validity.
        assert!(parse_extra_mounts(&["/:fork:rw:exclude=x".into()]).is_err());
        assert!(parse_extra_mounts(&["/:rw:follow-links:exclude=x".into()]).is_err());
        // Invalid REL values are rejected with the normalization error.
        for bad in [
            "exclude=",
            "exclude=/abs",
            "exclude=..",
            "exclude=a/../b",
            "exclude=.",
        ] {
            let error = parse_extra_mounts(&[format!("/:fork:{bad}")]).unwrap_err();
            assert!(error.to_string().contains("exclude"), "{bad}: {error:#}");
        }
    }

    #[test]
    fn parse_extra_mounts_rejects_live_exclusions_before_any_io() {
        // `:exclude` is fork-only. Every live-bind form rejects at parse,
        // including a nonexistent source (proving no filesystem lookup), and
        // regardless of where the suffix lands.
        for entry in [
            "/no/such/source:exclude=x",
            "/no/such/source:rw:exclude=x",
            "/no/such/source:ro:exclude=x",
            "/no/such/source:follow-links:exclude=x",
            "/no/such/source:exclude=x:ro",
            "/no/such/source:/guest:ro:exclude=x",
        ] {
            let error = parse_extra_mounts(&[entry.into()]).unwrap_err().to_string();
            assert!(
                error.contains(":exclude is only supported on :fork mounts"),
                "{entry}: {error}"
            );
        }
    }

    #[test]
    fn fork_is_seeded_once_and_exclusions_are_not_copied() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("visible"), "one").unwrap();
        fs::write(source.path().join("secret"), "no").unwrap();
        let store = tempfile::tempdir().unwrap();
        let raw = format!("{}:/guest:fork:exclude=secret", source.path().display());
        let mut mounts = parse_extra_mounts(&[raw]).unwrap();
        prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &ProtectedHostFiles::measure(None).unwrap(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(mounts[0].host.join("visible")).unwrap(),
            "one"
        );
        assert!(!mounts[0].host.join("secret").exists());
        fs::write(source.path().join("visible"), "two").unwrap();
        let mut again = parse_extra_mounts(&[format!(
            "{}:/guest:fork:exclude=secret",
            source.path().display()
        )])
        .unwrap();
        prepare_forks(
            &mut again,
            store.path(),
            &std::collections::HashMap::new(),
            &ProtectedHostFiles::measure(None).unwrap(),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(again[0].host.join("visible")).unwrap(),
            "one"
        );
    }

    // ── AC-5: parsed `ro` reaches the volume builder (boot-free) ──

    fn built_readonly(host: &str, ro: bool) -> bool {
        use microsandbox::sandbox::VolumeMount;
        let vm = configure_extra_mount(MountBuilder::new("/g"), host.into(), ro)
            .build()
            .expect("bind mount builds");
        match vm {
            VolumeMount::Bind { options, .. } => options.readonly,
            other => panic!("expected Bind mount, got {other:?}"),
        }
    }

    #[test]
    fn extra_mount_ro_propagates_readonly_into_built_volume() {
        let em = &parse_extra_mounts(&["/:ro".into()]).unwrap()[0];
        assert!(em.is_readonly());
        assert!(built_readonly(em.host.to_str().unwrap(), em.is_readonly()));

        let em_rw = &parse_extra_mounts(&["/:rw".into()]).unwrap()[0];
        assert!(!em_rw.is_readonly());
        assert!(!built_readonly(
            em_rw.host.to_str().unwrap(),
            em_rw.is_readonly()
        ));

        let em_def = &parse_extra_mounts(&["/".into()]).unwrap()[0];
        assert!(!built_readonly(
            em_def.host.to_str().unwrap(),
            em_def.is_readonly()
        ));
    }

    // ── follow-links: grammar/parse (issue #11) ────────────────────

    #[test]
    fn parse_follow_links_implies_readonly() {
        let parsed = parse_extra_mounts(&["/:follow-links".into()]).expect("ok");
        assert!(parsed[0].is_readonly());
        assert!(parsed[0].follows_links());
    }

    #[test]
    fn parse_follow_links_with_ro_ok() {
        let parsed =
            parse_extra_mounts(&["/:ro:follow-links".into()]).expect("ok, ro+follow-links coexist");
        assert!(parsed[0].is_readonly());
        assert!(parsed[0].follows_links());
    }

    #[test]
    fn parse_rw_follow_links_conflicts() {
        for entry in ["/:rw:follow-links", "/:follow-links:rw"] {
            let err = parse_extra_mounts(&[entry.into()])
                .expect_err("rw+follow-links must conflict")
                .to_string();
            assert!(err.contains("conflicting"), "got: {err}");
            assert!(
                err.contains("rw") && err.contains("follow-links"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn parse_follow_links_with_guest() {
        let parsed = parse_extra_mounts(&["/:/g:follow-links".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(parsed[0].is_readonly());
        assert!(parsed[0].follows_links());
    }

    #[test]
    fn parse_unknown_mode_lists_follow_links() {
        let err = parse_extra_mounts(&["/:bogus-mode".into()])
            .expect_err("unknown mode must error")
            .to_string();
        assert!(err.contains("follow-links"), "got: {err}");
    }

    // ── follow-links: discovery / expand (issue #11) ────────────────

    use std::os::unix::fs::symlink;

    /// Canonicalize a freshly-created tempdir's path up front — macOS
    /// resolves `/var` -> `/private/var`, so anything compared against
    /// `discover_followed_targets`'s (canonicalized) output needs to start
    /// from a canonical base.
    fn canon(p: &Path) -> PathBuf {
        p.canonicalize().expect("canonicalize")
    }

    /// Walk a root whose two sides coincide — the shape almost every
    /// discovery test wants. Tests about a root that was itself a symlink
    /// call `discover_followed_targets` with an explicit [`BindPath`].
    fn walk(host: &Path, home: &Path) -> Result<(Vec<BindPath>, Vec<String>)> {
        discover_followed_targets(&BindPath::mirrored(host.to_path_buf()), home)
    }

    /// The real host directories a walk found. Most discovery tests only
    /// care about that set; the ones about literal guest paths assert on
    /// [`BindPath::guest`] directly instead.
    fn hosts(found: &[BindPath]) -> Vec<PathBuf> {
        found.iter().map(|d| d.host.clone()).collect()
    }

    #[test]
    fn discover_direct_dir_symlink() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let outside = home_path.join("outside_dir");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, host.join("foo")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert_eq!(hosts(&found), vec![outside]);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn discover_transitive() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let a = home_path.join("a");
        let b = home_path.join("b");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        symlink(&a, host.join("foo")).unwrap();
        symlink(&b, a.join("bar")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        let mut targets = hosts(&found);
        targets.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(
            targets, expected,
            "both the direct and transitive target must be discovered"
        );
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    // ── lexical_link_path: properties ───────────────────────────────

    proptest::proptest! {
        /// Whatever text a symlink holds, a folded path is usable as a
        /// mount point: absolute, and free of the `.`/`..` components a
        /// bind target cannot carry. Folding is also a fixed point, which
        /// is the property that makes it safe to fold the same raw text
        /// against two different directories (host and guest) and trust
        /// that agreement on one transfers to the other.
        #[test]
        fn lexical_link_path_folds_to_a_clean_absolute_fixed_point(
            link_segs in proptest::collection::vec("[a-z]{1,4}", 1..5),
            raw_segs in proptest::collection::vec("[a-z]{1,4}|\\.|\\.\\.", 0..6),
            raw_is_absolute in proptest::bool::ANY,
        ) {
            use proptest::prop_assert;
            use std::path::Component;

            let link = link_segs.iter().fold(PathBuf::from("/"), |a, s| a.join(s));
            let base = if raw_is_absolute { PathBuf::from("/") } else { PathBuf::new() };
            let raw = raw_segs.iter().fold(base, |a, s| a.join(s));

            if let Some(folded) = lexical_link_path(&link, &raw) {
                prop_assert!(folded.is_absolute(), "{folded:?}");
                prop_assert!(
                    folded
                        .components()
                        .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
                    "{folded:?} still carries . or .. components"
                );
                prop_assert!(
                    lexical_link_path(&link, &folded).as_ref() == Some(&folded),
                    "folding {folded:?} again changed it"
                );
            }
        }
    }

    #[test]
    fn discover_binds_literal_path_through_a_symlinked_parent() {
        // The `~/.claude/skills` shape: the link's raw target text runs
        // through `.agents/skills`, which is itself a symlink, so the
        // canonical path the host resolves to is NOT the path the guest
        // will look up.
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let conf = home_path.join("conf");
        let real = conf.join("skills").join("implement");
        let literal = conf.join(".agents").join("skills").join("implement");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&real).unwrap();
        fs::create_dir_all(conf.join(".agents")).unwrap();
        symlink("../skills", conf.join(".agents").join("skills")).unwrap();
        symlink(&literal, host.join("implement")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(
            found.iter().any(|d| d.host == real && d.guest == real),
            "the canonical target must still be bound at its own path, got: {found:?}"
        );
        assert!(
            found.iter().any(|d| d.host == real && d.guest == literal),
            "the same real directory must ALSO be bound at the literal path the \
             guest's readlink() names, got: {found:?}"
        );
    }

    #[test]
    fn discover_binds_relative_link_nested_inside_a_literal_alias() {
        // The same defect one level down: `implement` is reached through a
        // symlinked parent (so it gets an alias bind), and inside it a
        // *relative* link points out to a sibling. Entering via the alias,
        // the guest resolves `../shared` against the alias's parent — a
        // path the canonical binds never cover.
        //
        //   HOST/implement            -> $HOME/conf/.agents/skills/implement
        //   $HOME/conf/.agents/skills -> ../skills
        //   $HOME/conf/skills/implement/ref -> ../shared
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let conf = home_path.join("conf");
        let implement = conf.join("skills").join("implement");
        let shared = conf.join("skills").join("shared");
        let alias_skills = conf.join(".agents").join("skills");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&implement).unwrap();
        fs::create_dir_all(&shared).unwrap();
        fs::create_dir_all(conf.join(".agents")).unwrap();
        symlink("../skills", &alias_skills).unwrap();
        symlink(alias_skills.join("implement"), host.join("implement")).unwrap();
        symlink("../shared", implement.join("ref")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(
            found
                .iter()
                .any(|d| d.host == shared && d.guest == alias_skills.join("shared")),
            "the sibling must be bound where the guest resolves `../shared` from \
             inside the alias ({}), got: {found:?}",
            alias_skills.join("shared").display()
        );
    }

    #[test]
    fn discover_resolves_relative_links_against_a_root_whose_guest_path_differs() {
        // The shape of the user's own invocation: `--mount ~/.claude/skills`
        // where `~/.claude/skills` is itself a symlink, so
        // `parse_extra_mounts` canonicalizes the host while the guest keeps
        // the path as typed. A relative link directly under that root
        // resolves against the *guest* side, one directory level away from
        // where the host resolves it.
        //
        //   root  host = $HOME/deep/realskills   guest = $HOME/skills
        //   $HOME/deep/realskills/foo -> ../shared
        //   host resolves  -> $HOME/deep/shared
        //   guest resolves -> $HOME/shared
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let real = home_path.join("deep").join("realskills");
        let shared = home_path.join("deep").join("shared");
        fs::create_dir_all(&real).unwrap();
        fs::create_dir_all(&shared).unwrap();
        symlink("../shared", real.join("foo")).unwrap();

        let root = BindPath {
            host: real.clone(),
            guest: home_path.join("skills"),
            exclusions: Vec::new(),
        };
        let (found, warnings) = discover_followed_targets(&root, &home_path).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(
            found
                .iter()
                .any(|d| d.host == shared && d.guest == home_path.join("shared")),
            "the target must be bound where the guest resolves `../shared` from the \
             root's guest path ({}), got: {found:?}",
            home_path.join("shared").display()
        );
    }

    #[test]
    fn discover_skips_literal_path_that_disagrees_with_host_resolution() {
        // Raw target `…/p/q/../target` where `p/q` is itself a symlink:
        // the kernel resolves `q` first, so `..` climbs out of `r`, not
        // out of `p`. Folding `..` lexically would name `…/p/target`,
        // which is a different (here: nonexistent) place — so we must
        // skip it with a warning rather than bind the directory there.
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let target = home_path.join("target");
        let r = home_path.join("r");
        let p = home_path.join("p");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&r).unwrap();
        fs::create_dir_all(&p).unwrap();
        symlink("../r", p.join("q")).unwrap();
        symlink(p.join("q").join("..").join("target"), host.join("x")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert_eq!(
            hosts(&found),
            vec![target.clone()],
            "the canonical target is still discovered"
        );
        assert!(
            found.iter().all(|d| d.guest == target),
            "no bind at the lexically-folded path, got: {found:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("does not name")),
            "expected a warning that the literal path names something else, got: {warnings:?}"
        );
    }

    #[test]
    fn discover_skips_literal_path_outside_home() {
        // Canonical target is inside `$HOME` (so the hard guardrail is
        // happy), but the literal path the guest would look up is not —
        // binding there would let a link inside `$HOME` place a mount
        // anywhere in the guest.
        let root = tempfile::tempdir().unwrap();
        let root_path = canon(root.path());
        let home_path = root_path.join("h");
        let host = home_path.join("host");
        let real = home_path.join("real");
        let outside = root_path.join("outside");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&real).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink("../h/real", outside.join("skills")).unwrap();
        symlink(outside.join("skills"), host.join("x")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok");
        assert_eq!(hosts(&found), vec![real.clone()]);
        assert!(
            found.iter().all(|d| d.guest == real),
            "no bind at the outside-$HOME literal path, got: {found:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("outside your $HOME")),
            "expected an outside-$HOME warning for the literal path, got: {warnings:?}"
        );
    }

    #[test]
    fn discover_terminates_on_cycle() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let a = home_path.join("a");
        let b = home_path.join("b");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        symlink(&a, host.join("into_a")).unwrap();
        symlink(&b, a.join("x")).unwrap();
        symlink(&a, b.join("y")).unwrap();

        let (found, _warnings) = walk(&host, &home_path).expect("must terminate, not hang");
        let mut targets = hosts(&found);
        targets.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(
            targets, expected,
            "each real path discovered exactly once despite the cycle"
        );
    }

    #[test]
    fn discover_self_referential_symlink() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        fs::create_dir_all(&host).unwrap();
        symlink(&host, host.join("loop")).unwrap();

        let (found, _warnings) = walk(&host, &home_path).expect("must terminate, not hang");
        assert_eq!(hosts(&found), vec![host]);
    }

    #[test]
    fn discover_file_target_skipped() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        fs::create_dir_all(&host).unwrap();
        let file = home_path.join("some_file");
        fs::write(&file, "hi").unwrap();
        symlink(&file, host.join("f")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok, not an error");
        assert!(found.is_empty());
        assert!(
            warnings.iter().any(|w| w.contains("not a directory")),
            "expected a 'not a directory' warning, got: {warnings:?}"
        );
    }

    #[test]
    fn discover_dangling_skipped() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        fs::create_dir_all(&host).unwrap();
        symlink(home_path.join("nonexistent"), host.join("d")).unwrap();

        let (found, warnings) = walk(&host, &home_path).expect("ok, not an error");
        assert!(found.is_empty());
        assert!(
            warnings.iter().any(|w| w.contains("dangling")),
            "expected a dangling-symlink warning, got: {warnings:?}"
        );
    }

    #[test]
    fn discover_outside_home_errors() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        // `home` for the guardrail is a *subdir*, so the symlink target
        // (a sibling of that subdir) resolves outside it.
        let narrow_home = home_path.join("subhome");
        let host = home_path.join("host");
        let outside = home_path.join("outside_dir");
        fs::create_dir_all(&narrow_home).unwrap();
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, host.join("foo")).unwrap();

        let err = walk(&host, &narrow_home)
            .expect_err("target outside $HOME must be a hard error")
            .to_string();
        assert!(
            err.contains(&host.join("foo").display().to_string()),
            "got: {err}"
        );
        assert!(err.contains(&outside.display().to_string()), "got: {err}");
    }

    #[test]
    fn expand_roots_the_walk_at_the_mounts_guest_path_not_just_its_host() {
        // Wiring test for the seam above `discover_followed_targets`: an
        // `ExtraMount` whose guest path differs from its host — which is
        // what `--mount ~/.claude/skills:follow-links` produces whenever
        // that path is itself a symlink — must have BOTH sides handed to
        // the walk, or relative link text is resolved against the wrong
        // directory and the discovered bind lands where the guest never
        // looks.
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let real = home_path.join("deep").join("realskills");
        let shared = home_path.join("deep").join("shared");
        fs::create_dir_all(&real).unwrap();
        fs::create_dir_all(&shared).unwrap();
        symlink("../shared", real.join("foo")).unwrap();

        let mounts = vec![ExtraMount {
            source_spelling: String::new(),
            host: real,
            guest: home_path.join("skills"),
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: Vec::new(),
        }];
        let (expanded, warnings) = expand_follow_links(mounts, Some(&home_path)).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let want_guest = home_path.join("shared");
        assert!(
            expanded
                .iter()
                .any(|m| m.host == shared && m.guest == want_guest && m.is_readonly()),
            "expected {} bound read-only at {}, got: {:?}",
            shared.display(),
            want_guest.display(),
            expanded
                .iter()
                .map(|m| (&m.host, &m.guest))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn expand_dedups_same_realpath() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let target = home_path.join("target");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, host.join("a")).unwrap();
        symlink(&target, host.join("b")).unwrap();

        let mounts = vec![ExtraMount {
            source_spelling: String::new(),
            host: host.clone(),
            guest: host,
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: Vec::new(),
        }];
        let (expanded, warnings) = expand_follow_links(mounts, Some(&home_path)).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let target_mounts: Vec<_> = expanded.iter().filter(|m| m.host == target).collect();
        assert_eq!(
            target_mounts.len(),
            1,
            "two symlinks resolving to the same real path must dedup to one mount"
        );
    }

    #[test]
    fn expand_guest_collision_errors() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let target = home_path.join("target");
        let explicit_host = home_path.join("explicit-host");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&explicit_host).unwrap();
        symlink(&target, host.join("a")).unwrap();

        let mounts = vec![
            ExtraMount {
                source_spelling: String::new(),
                host: host.clone(),
                guest: host,
                policy: MountPolicy::BindReadOnly { follow_links: true },
                exclusions: Vec::new(),
            },
            ExtraMount {
                // An explicit mount claims the discovered target's real
                // path as its GUEST, from a different HOST.
                source_spelling: String::new(),
                host: explicit_host.clone(),
                guest: target.clone(),
                policy: MountPolicy::BindReadWrite,
                exclusions: Vec::new(),
            },
        ];
        let err = expand_follow_links(mounts, Some(&home_path))
            .expect_err("two different hosts claiming the same guest must be a hard error")
            .to_string();
        assert!(err.contains(&target.display().to_string()), "got: {err}");
        assert!(
            err.contains(&explicit_host.display().to_string()),
            "got: {err}"
        );
    }

    #[test]
    fn expand_leaves_non_follow_mounts_untouched() {
        let mounts = vec![ExtraMount {
            source_spelling: String::new(),
            host: "/".into(),
            guest: "/g".into(),
            policy: MountPolicy::BindReadWrite,
            exclusions: Vec::new(),
        }];
        let (expanded, warnings) =
            expand_follow_links(mounts, None).expect("no follow-links entries, $HOME unneeded");
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].guest, std::path::Path::new("/g"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn expand_without_home_errors_only_when_follow_links_present() {
        let mounts = vec![ExtraMount {
            source_spelling: String::new(),
            host: "/".into(),
            guest: "/".into(),
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: Vec::new(),
        }];
        let err = expand_follow_links(mounts, None)
            .expect_err("follow-links with no $HOME must be a hard error")
            .to_string();
        assert!(err.contains("HOME"), "got: {err}");
    }

    #[test]
    fn discovered_mount_builds_readonly_bind_volume() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let target = home_path.join("target");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, host.join("a")).unwrap();

        let mounts = vec![ExtraMount {
            source_spelling: String::new(),
            host: host.clone(),
            guest: host,
            policy: MountPolicy::BindReadOnly { follow_links: true },
            exclusions: Vec::new(),
        }];
        let (expanded, _warnings) = expand_follow_links(mounts, Some(&home_path)).expect("ok");
        let discovered = expanded
            .iter()
            .find(|m| m.host == target)
            .expect("discovered target present in expanded list");
        assert!(discovered.is_readonly());
        assert!(built_readonly(
            discovered.host.to_str().unwrap(),
            discovered.is_readonly()
        ));
    }
}

/// A classified source used by the launch layer.  `prepare` is the only
/// operation which turns a request into one of these instructions; launch
/// must not restat or reinterpret it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedVolumeSource {
    WritableBind(PathBuf),
    ReadOnlyBind(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedNodeKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VolumeRole {
    Explicit,
    Followed,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedVolume {
    pub(crate) guest: PathBuf,
    pub(crate) source: PreparedVolumeSource,
    pub(crate) node_kind: PreparedNodeKind,
    pub(crate) role: VolumeRole,
}

#[derive(Clone, Debug)]
pub(crate) struct RepoScanRoot {
    pub(crate) host: PathBuf,
}

#[derive(Debug)]
pub(crate) struct PreparedMountPlan {
    pub(crate) volumes: Vec<PreparedVolume>,
    pub(crate) repo_scan_roots: Vec<RepoScanRoot>,
    pub(crate) notices: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct MountContext {
    pub(crate) mount_store: PathBuf,
    pub(crate) host_home: Option<PathBuf>,
    /// Guest paths owned by agent-vm itself.  An explicit mount may not
    /// replace one: that would silently change HOME/project/state semantics.
    pub(crate) core_guest_mounts: Vec<PathBuf>,
    /// Host sources of agent-vm's own binds (guest HOME, project dir, state
    /// dir) with the role each one plays. Checked for protected-file exposure
    /// exactly like an explicit mount, because the project bind is the
    /// canonicalized cwd and is writable (`session.rs:45`): `cd ~ && agent-vm
    /// shell` would hand the guest the whole host `$HOME`.
    pub(crate) core_host_sources: Vec<CoreHostSource>,
}

/// Normalize the guest spelling before it participates in identity or
/// collision detection.  This mirrors Microsandbox's path contract rather
/// than relying on its later builder validation after host state was touched.
fn normalize_guest(raw: &str) -> Result<PathBuf> {
    use std::path::Component;
    if raw == "/" || raw.contains([':', ';', ',']) || !crate::run::guest_path_is_mountable(raw) {
        anyhow::bail!("--mount guest path {raw:?} is not mountable");
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        anyhow::bail!("--mount guest path {raw:?} must be absolute");
    }
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir | Component::Prefix(_) => {
                anyhow::bail!("--mount guest path {raw:?} must not contain `..`")
            }
        }
    }
    if out == Path::new("/") {
        anyhow::bail!("--mount guest path must not be /");
    }
    Ok(out)
}

/// Prepare a complete, closed mount plan.  This is deliberately the only
/// boundary allowed to inspect mount sources or create fork state.
pub(crate) fn prepare(
    requests: Vec<ExtraMount>,
    context: &MountContext,
) -> Result<PreparedMountPlan> {
    // Measure the protected host-file route set once, then refuse to launch a
    // core bind that would hand one over. The project bind is the
    // canonicalized cwd, so `cd ~ && agent-vm shell` is an exposure route even
    // with no `--mount` at all.
    let protected = ProtectedHostFiles::measure(context.host_home.as_deref())?;
    let mut notices = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for source in &context.core_host_sources {
        // The Pi advisories fire for one of agent-vm's *own* binds too, not
        // just for `--mount`s: `~/.pi/extensions` as the canonicalized cwd is
        // a writable live window onto host Pi state with no `--mount` at all
        // (issue #90's warning deliverable).
        for advisory in protected.core_advisories(source) {
            push_notice(&mut notices, &mut seen, advisory);
        }
        let Some(exposure) = protected.exposure(&source.path)? else {
            continue;
        };
        match exposure.severity {
            Severity::Refuse => anyhow::bail!("{}", protected.core_message(source, &exposure)),
            Severity::Advise => {
                let advisory =
                    protected.message(&source.path.display().to_string(), &exposure, None);
                push_notice(&mut notices, &mut seen, advisory);
            }
        }
    }

    let mut requests = requests;
    for request in &mut requests {
        request.guest = normalize_guest(
            request
                .guest
                .to_str()
                .context("--mount guest path must be UTF-8")?,
        )?;
    }
    // Reject/deduplicate explicit claims before touching the store/source.
    let mut unique = Vec::new();
    for request in requests {
        if context
            .core_guest_mounts
            .iter()
            .any(|core| core == &request.guest)
        {
            anyhow::bail!(
                "--mount guest path {} collides with an agent-vm core mount",
                request.guest.display()
            );
        }
        if let Some(existing) = unique
            .iter()
            .find(|m: &&ExtraMount| m.guest == request.guest)
        {
            if same_declaration(existing, &request) {
                continue;
            }
            anyhow::bail!(
                "--mount guest path {} is claimed by different declarations",
                request.guest.display()
            );
        }
        unique.push(request);
    }

    // Every fork is validated READY-first here, before any live-bind
    // discovery or state mutation. A READY entry is reused from its
    // committed `data` without reading the original source; an
    // uninitialized fork whose root is a file (or a symlink to one) is
    // rejected before discovery/transaction. A missing source is left for
    // the locked transaction, so a waiter can still reuse a fork another
    // initializer publishes while it waits.
    let known_fork_kinds = preflight_forks(&mut unique, &context.mount_store)?;

    // Live binds are the only sources that can contribute followed links, so
    // discovery runs after fork preflight and never over a fork.
    let explicit_count = unique.len();
    let (mut expanded, warnings) =
        expand_follow_links(unique.clone(), context.host_home.as_deref())?;
    sync_fork_representations(&unique, &mut expanded)?;

    let mut volumes = Vec::new();
    for (index, mount) in expanded.iter().enumerate() {
        let explicit = index < explicit_count;
        // Only a missing source remains unclassified after preflight. Its
        // provisional directory kind permits a waiter to reach the locked
        // READY recheck without requiring the original source to survive.
        let kind = if mount.is_fork() {
            known_fork_kinds
                .get(&mount.guest)
                .copied()
                // An uninitialized fork is always directory-or-rejected; the
                // locked transaction rechecks before it publishes.
                .unwrap_or(PreparedNodeKind::Directory)
        } else {
            let metadata = fs::symlink_metadata(&mount.host)
                .with_context(|| format!("validating --mount source {}", mount.host.display()))?;
            node_kind(&metadata, &mount.host)?
        };
        // A regular file cannot be a writable bind: the runtime's writable
        // file staging is intentionally unreachable from agent-vm (issue
        // #113). Reject here, after canonicalization, so a symlink-to-file
        // root is caught too.
        if kind == PreparedNodeKind::File && !mount.is_readonly() {
            anyhow::bail!(
                "--mount {}: a file can only be mounted read-only.\n\
                 Use :ro, or :fork its containing directory for a writable copy.",
                mount.source_spelling
            );
        }
        let source = if mount.is_readonly() {
            PreparedVolumeSource::ReadOnlyBind(mount.host.clone())
        } else {
            PreparedVolumeSource::WritableBind(mount.host.clone())
        };
        volumes.push(PreparedVolume {
            guest: mount.guest.clone(),
            source,
            node_kind: kind,
            role: if explicit {
                VolumeRole::Explicit
            } else {
                VolumeRole::Followed
            },
        });
    }
    // Refuse a live bind that would hand a protected host file to the guest,
    // and collect the Pi advisories. Runs after `expand_follow_links` (so a
    // followed alias is an ordinary discovered bind) and before
    // `validate_plan`/`prepare_forks` (so a refusal has no side effects).
    enforce_protected_files(&expanded, explicit_count, &protected, &mut notices)?;
    // A fork seeded by a pre-#90 build may already contain a copy of a
    // protected file, and a READY fork is reused *without* reading its source,
    // so no source-side check catches it. Report the orphaned directory that
    // the v3 identity no longer reuses.
    for mount in unique.iter().filter(|mount| mount.is_fork()) {
        if let Some(orphan) = legacy_fork_dir(mount, &context.mount_store) {
            notices.push(format!(
                "==> A fork from an earlier agent-vm build is no longer used: {}. It may \
                 contain a copy of a host credential file — remove it.",
                orphan.display()
            ));
        }
    }
    validate_plan(&mut volumes, &context.core_guest_mounts)?;

    // Only a validated complete set of core, explicit, and followed claims
    // may publish any host-managed state. The first state mutation happens
    // inside `prepare_forks`; everything above is rejection or classification.
    notices.extend(prepare_forks(
        &mut unique,
        &context.mount_store,
        &known_fork_kinds,
        &protected,
    )?);
    sync_fork_representations(&unique, &mut expanded)?;
    notices.extend(warnings.into_iter().map(|warning| format!("==> {warning}")));

    // Fork initialization changes only the explicit source path. Discovery
    // was already complete (forks do not produce live followed binds), so
    // patch the validated instruction rather than re-discovering anything.
    for mount in unique.iter().filter(|mount| mount.is_fork()) {
        let Some(volume) = volumes
            .iter_mut()
            .find(|volume| volume.role == VolumeRole::Explicit && volume.guest == mount.guest)
        else {
            anyhow::bail!(
                "prepared fork at {} lost its explicit claim",
                mount.guest.display()
            );
        };
        volume.source = PreparedVolumeSource::WritableBind(mount.host.clone());
        let metadata = fs::symlink_metadata(&mount.host)
            .with_context(|| format!("validating committed fork {}", mount.host.display()))?;
        volume.node_kind = node_kind(&metadata, &mount.host)?;
    }

    // The prepared explicit declarations in order: live binds carry their
    // canonical source (after `expand_follow_links`), and forks carry their
    // committed `data` (after `sync_fork_representations`), never the original
    // source. Followed aliases are not scanned as separate roots.
    let repo_scan_roots = expanded
        .iter()
        .take(explicit_count)
        .map(|mount| RepoScanRoot {
            host: mount.host.clone(),
        })
        .collect();
    Ok(PreparedMountPlan {
        volumes,
        repo_scan_roots,
        notices,
    })
}

/// Refuse any live bind that would hand a protected host file to the guest,
/// and collect the Pi advisories. Forks are exempt from the refusal on
/// purpose: their *content* is decided by the copy engine (`copy_opened`),
/// not by this root-level check.
///
/// Precedence is honest, not "security first": `normalize_guest`, the core
/// collision/dedup pass, `preflight_forks` and the per-mount `file`+`rw`
/// rejection all run earlier and can bail. Every one of them is read-only, so a
/// leaky-*and*-invalid plan is still refused with **no side effects** — only
/// the message the user sees is the earlier one.
fn enforce_protected_files(
    expanded: &[ExtraMount],
    explicit_count: usize,
    protected: &ProtectedHostFiles,
    notices: &mut Vec<String>,
) -> Result<()> {
    // Not at the top of `prepare`: `expand_follow_links`'s more specific
    // "$HOME is not set — required for --mount follow-links" must still win for
    // a `follow-links` mount with no `$HOME`.
    protected.require_home(expanded.len())?;
    if expanded.is_empty() {
        return Ok(());
    }
    let declarations: Vec<String> = expanded[..explicit_count]
        .iter()
        .filter(|mount| mount.follows_links() && !mount.is_fork())
        .map(|mount| mount.source_spelling.clone())
        .collect();
    let mut seen: Vec<String> = Vec::new();
    for (index, mount) in expanded.iter().enumerate() {
        // Advisories are evaluated against the *declaration*, never
        // `mount.host`: `preflight_forks` repoints a READY fork's host at
        // `<store>/forks/<id>/data`, so a notice keyed on `mount.host` would
        // silently stop firing on every launch after the first.
        let declaration = declaration_path(mount);
        if !mount.is_fork()
            && let Some(exposure) = protected.exposure(&mount.host)?
        {
            let discovered = (index >= explicit_count).then(|| discovered_by(&declarations));
            let message =
                protected.message(&mount.source_spelling, &exposure, discovered.as_deref());
            match exposure.severity {
                // A live window onto host bytes cannot be made safe by any
                // overlay: `pi auth login` on the host can create
                // `auth.json` inside a bind that is already open.
                Severity::Refuse => anyhow::bail!("{message}"),
                Severity::Advise => push_notice(notices, &mut seen, message),
            }
        }
        // A fork needs only the platform-artifact advisory: its content is the
        // copy engine's decision, and `:fork` is what it already is.
        let live_bind = !mount.is_fork();
        for advisory in protected.mount_advisories(&declaration, &mount.source_spelling, live_bind)
        {
            push_notice(notices, &mut seen, advisory);
        }
    }
    Ok(())
}

/// The provenance phrase for a `follow-links`-discovered bind, for the refusal
/// message. `expand_follow_links` does not carry the originating declaration
/// per discovered target — two `:follow-links` declarations can discover the
/// same bind — so naming every candidate would blame declarations that did not
/// contribute it. Naming the sole candidate, or naming none of them, is never
/// wrong.
fn discovered_by(declarations: &[String]) -> String {
    match declarations {
        [only] => format!("--mount {only}:follow-links"),
        _ => "one of your --mount …:follow-links declarations".to_string(),
    }
}

/// The path a declaration actually names, for advisories. A missing source (a
/// fork reused after its source was removed) falls back to the literal
/// spelling rather than failing the launch.
fn declaration_path(mount: &ExtraMount) -> PathBuf {
    Path::new(&mount.source_spelling)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&mount.source_spelling))
}

fn push_notice(notices: &mut Vec<String>, seen: &mut Vec<String>, message: String) {
    if seen.contains(&message) {
        return;
    }
    seen.push(message.clone());
    notices.push(message);
}

/// A pre-#90 fork directory that the v3 identity no longer reuses, if one
/// exists. Reported, never deleted: it may hold valuable guest state (and a
/// copy of a protected file).
fn legacy_fork_dir(mount: &ExtraMount, mount_store: &Path) -> Option<PathBuf> {
    let path = mount_store
        .join("forks")
        .join(fork_id(mount, LEGACY_IDENTITY_VERSION_V2));
    fs::symlink_metadata(&path).is_ok().then_some(path)
}

/// Validate every fork without creating its store or inspecting an
/// uninitialized source beyond its kind. READY is checked first, so a fork
/// stays reusable after its original source disappears or changes type.
fn preflight_forks(
    mounts: &mut [ExtraMount],
    mount_store: &Path,
) -> Result<std::collections::HashMap<PathBuf, PreparedNodeKind>> {
    let mut kinds = std::collections::HashMap::new();
    for mount in mounts.iter_mut().filter(|mount| mount.is_fork()) {
        let id = fork_id(mount, IDENTITY_VERSION);
        let final_dir = mount_store.join("forks").join(&id);
        if final_dir_exists(&final_dir)? {
            let kind = validate_ready(&final_dir, mount, &id)?;
            // READY wins over whatever the original source now is; the
            // committed copy is the mount source from here on.
            mount.host = final_dir.join("data");
            kinds.insert(mount.guest.clone(), kind);
            continue;
        }
        // Uninitialized: reject a file root now, before discovery or any
        // store/lock side effect. A vanished source is deliberately deferred:
        // a concurrent initializer may publish READY while this waiter blocks
        // on the per-fork lock (see the process tests).
        let Some(kind) = try_fork_source_kind(&mount.host)? else {
            continue;
        };
        require_fork_directory(kind, &mount.source_spelling)?;
        kinds.insert(mount.guest.clone(), kind);
    }
    Ok(kinds)
}

/// A `:fork` root is always a directory (issue #113). Shared between the
/// preflight classification and the locked recheck so both emit one message.
fn require_fork_directory(kind: PreparedNodeKind, source: &str) -> Result<()> {
    if kind != PreparedNodeKind::Directory {
        anyhow::bail!(
            "--mount {source}: a :fork source must be a directory.\n\
             Fork the containing directory, or bind the file read-only with :ro."
        );
    }
    Ok(())
}

fn try_fork_source_kind(source: &Path) -> Result<Option<PreparedNodeKind>> {
    match fs::symlink_metadata(source) {
        Ok(_) => fork_source_kind(source).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("validating fork root {}", source.display()))
        }
    }
}

fn fork_source_kind(source: &Path) -> Result<PreparedNodeKind> {
    let resolved = source
        .canonicalize()
        .with_context(|| format!("resolving fork root {}", source.display()))?;
    let metadata = fs::symlink_metadata(&resolved)
        .with_context(|| format!("validating fork root {}", source.display()))?;
    node_kind(&metadata, source)
}

/// Keep the follow-link-expanded representation aligned with the declaration
/// that owns fork transaction state. A READY preflight replaces only
/// `unique`; every later consumer (volumes and repository
/// scanning) must therefore use this committed path rather than the original
/// declaration source.
fn sync_fork_representations(unique: &[ExtraMount], expanded: &mut [ExtraMount]) -> Result<()> {
    for mount in expanded.iter_mut().filter(|mount| mount.is_fork()) {
        let prepared = unique
            .iter()
            .find(|candidate| {
                candidate.is_fork()
                    && candidate.guest == mount.guest
                    && candidate.source_spelling == mount.source_spelling
                    && candidate.follows_links() == mount.follows_links()
                    && candidate.exclusions == mount.exclusions
            })
            .with_context(|| {
                format!(
                    "prepared fork at {} lost its declaration representation",
                    mount.guest.display()
                )
            })?;
        mount.host = prepared.host.clone();
    }
    Ok(())
}

fn same_declaration(a: &ExtraMount, b: &ExtraMount) -> bool {
    a.source_spelling == b.source_spelling
        && a.host == b.host
        && a.is_readonly() == b.is_readonly()
        && a.follows_links() == b.follows_links()
        && a.is_fork() == b.is_fork()
        && a.exclusions == b.exclusions
}

fn node_kind(metadata: &fs::Metadata, path: &Path) -> Result<PreparedNodeKind> {
    if metadata.is_file() {
        Ok(PreparedNodeKind::File)
    } else if metadata.is_dir() {
        Ok(PreparedNodeKind::Directory)
    } else {
        anyhow::bail!("{} must be a regular file or directory", path.display())
    }
}

fn validate_plan(volumes: &mut Vec<PreparedVolume>, core: &[PathBuf]) -> Result<()> {
    // Identical claims are harmless; distinct claims at the same guest path
    // are ambiguous and must fail before builder side effects.
    let mut unique = Vec::new();
    for volume in volumes.drain(..) {
        if unique
            .iter()
            .any(|v: &PreparedVolume| same_volume(v, &volume))
        {
            continue;
        }
        if unique
            .iter()
            .any(|v: &PreparedVolume| v.guest == volume.guest)
        {
            anyhow::bail!(
                "mount plan has conflicting claims at {}",
                volume.guest.display()
            );
        }
        unique.push(volume);
    }

    for volume in &unique {
        for file in unique
            .iter()
            .filter(|candidate| candidate.node_kind == PreparedNodeKind::File)
        {
            if volume.guest != file.guest && volume.guest.starts_with(&file.guest) {
                anyhow::bail!(
                    "mount at {} is below file mount {}",
                    volume.guest.display(),
                    file.guest.display()
                );
            }
        }
        if core.iter().any(|path| path == &volume.guest) {
            anyhow::bail!(
                "mount plan collides with an agent-vm core mount at {}",
                volume.guest.display()
            );
        }
        if core.iter().any(|path| path.starts_with(&volume.guest))
            && volume.node_kind == PreparedNodeKind::File
            && core
                .iter()
                .any(|path| path != &volume.guest && path.starts_with(&volume.guest))
        {
            anyhow::bail!("core mount is below file mount {}", volume.guest.display());
        }
    }
    *volumes = unique;
    Ok(())
}

fn same_volume(a: &PreparedVolume, b: &PreparedVolume) -> bool {
    a.guest == b.guest && a.source == b.source && a.node_kind == b.node_kind && a.role == b.role
}

const MANIFEST_VERSION: u32 = 2;
/// v3 because a READY fork is reused *without* reading its source, so a fork
/// seeded by a pre-#90 build may already contain a copied protected file and no
/// source-side check could catch it. Bumping the identity makes every reusable
/// fork one that was seeded *under* protection — a structural invariant instead
/// of a runtime scan. Forks had never shipped in a release, so no released
/// user has one to orphan (ADR-0020).
const IDENTITY_VERSION: &[u8] = b"agent-vm-fork-identity-v3";
/// Only to report the orphaned directory the v3 identity leaves behind
/// ([`legacy_fork_dir`]); never used to reuse or validate a fork.
const LEGACY_IDENTITY_VERSION_V2: &[u8] = b"agent-vm-fork-identity-v2";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const FORK_MAX_LINK_DEPTH: usize = 40;

// The copy engine deliberately exposes only test-only checkpoints.  They let
// tests swap a just-classified pathname before its descriptor is opened,
// proving that O_NOFOLLOW/fstat rather than timing protects the traversal.
//
// The callback is scoped to the canonical root being copied so it can only
// fire for the copy its test armed it for. Cargo runs unit tests in parallel,
// so an unscoped process-global hook would run inside a stranger's copy and
// mutate that other test's tree.
//
// The tuple is `(scope, callback)`; the alias keeps it readable and out of
// clippy's `type_complexity` lint, which `--all-targets` now gates on.
#[cfg(test)]
type CopyCheckpoint = (PathBuf, Box<dyn Fn(&Path) + Send>);

#[cfg(test)]
static COPY_CHECKPOINT: std::sync::Mutex<Option<CopyCheckpoint>> = std::sync::Mutex::new(None);

#[cfg(test)]
thread_local! {
    // The canonical root of the copy running on this thread. The armed
    // callback's scope is compared against it, so a hook fires only for its
    // own copy even while parallel tests copy other trees.
    static COPY_CHECKPOINT_ROOT: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct CopyCheckpointScope;

#[cfg(test)]
impl CopyCheckpointScope {
    fn enter(source: &Path) -> Self {
        COPY_CHECKPOINT_ROOT.with(|root| *root.borrow_mut() = Some(source.to_path_buf()));
        Self
    }
}

#[cfg(test)]
impl Drop for CopyCheckpointScope {
    fn drop(&mut self) {
        COPY_CHECKPOINT_ROOT.with(|root| *root.borrow_mut() = None);
    }
}

// Only one callback can be armed at a time, so tests that arm/clear it
// serialize on this lock. Scoping (above) handles the other direction: a
// parallel test that copies must not fire an armed callback at all.
#[cfg(test)]
static COPY_CHECKPOINT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn set_copy_checkpoint(source: &Path, callback: Box<dyn Fn(&Path) + Send>) {
    let scope = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    *COPY_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some((scope, callback));
}

#[cfg(test)]
fn clear_copy_checkpoint() {
    *COPY_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = None;
}

#[cfg(test)]
fn copy_checkpoint(path: &Path) {
    let root = COPY_CHECKPOINT_ROOT.with(|root| root.borrow().clone());
    let guard = COPY_CHECKPOINT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let (Some(root), Some((scope, callback))) = (root.as_ref(), guard.as_ref())
        && scope == root
    {
        callback(path);
    }
    drop(guard);
    // A child-only pause lets the transaction test kill an actual
    // initializer mid-copy. This is compiled only into the test binary.
    if std::env::var_os("AGENT_VM_FORK_KILL_CHECKPOINT")
        .is_some_and(|checkpoint| path == Path::new(&checkpoint))
    {
        std::fs::write(
            std::env::var_os("AGENT_VM_FORK_KILL_READY").unwrap(),
            "ready",
        )
        .unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

#[cfg(not(test))]
fn copy_checkpoint(_: &Path) {}

#[derive(serde::Serialize, serde::Deserialize)]
struct ForkManifest {
    version: u32,
    id: String,
    source: String,
    guest: String,
    follow_links: bool,
    exclusions: Vec<String>,
    kind: String,
}

/// Initialize each fork through one lock-protected state transition. READY is
/// validated before source access, so a seeded fork is usable after removal.
///
/// `protected` is the measurement taken at the top of `prepare`; the copier
/// re-measures under the lock and unions the two (see `refreshed`), so it never
/// forgets a credential identity or route an earlier snapshot positively
/// identified.
pub(crate) fn prepare_forks(
    mounts: &mut [ExtraMount],
    mount_store: &Path,
    expected_kinds: &std::collections::HashMap<PathBuf, PreparedNodeKind>,
    protected: &ProtectedHostFiles,
) -> Result<Vec<String>> {
    let mut notices = Vec::new();
    for mount in mounts.iter_mut().filter(|mount| mount.is_fork()) {
        let id = fork_id(mount, IDENTITY_VERSION);
        let final_dir = mount_store.join("forks").join(&id);
        ensure_store(mount_store)?;
        let lock_path = mount_store.join("locks").join(format!("{id}.lock"));
        let lock = open_regular_lock(&lock_path)?;
        lock_exclusive(&lock)?;
        if final_dir_exists(&final_dir)? {
            let kind = validate_ready(&final_dir, mount, &id)?;
            mount.host = final_dir.join("data");
            notices.push(format!(
                "==> Reusing fork at {} (reset: {})",
                mount.host.display(),
                final_dir.display()
            ));
            let _ = kind;
            continue;
        }
        clean_stale_staging(&mount_store.join("staging"), &id)?;
        // The root kind is source-dependent, so resolve it only after the
        // waiter has acquired the transaction lock and rechecked READY.
        let source_kind = fork_source_kind(&mount.host)?;
        require_fork_directory(source_kind, &mount.source_spelling)?;
        if let Some(expected) = expected_kinds.get(&mount.guest)
            && *expected != source_kind
        {
            anyhow::bail!(
                "fork root kind changed while preparing {}; retry the launch",
                mount.source_spelling
            );
        }
        let staging_parent = mount_store.join("staging");
        let stage = tempfile::Builder::new()
            .prefix(&format!("{id}.stage-"))
            .tempdir_in(&staging_parent)
            .context("creating fork staging directory")?;
        let staged_data = stage.path().join("data");
        // The omission signals are re-derived from a **fresh** measurement
        // under the lock, not from the one taken at the top of `prepare`: the
        // original route set cannot see a fork root that did not exist then
        // (e.g. `--mount ~/.pi:fork` where `~/.pi` is created between `measure`
        // and this point). But the fresh snapshot is **unioned** with the
        // original, never a replacement: an atomic credential replacement can
        // make the fresh snapshot forget an inode the original positively
        // identified (a surviving hardlink still holds the old bytes), and a
        // root renamed away and recreated can make it forget a route
        // (ADR-0020). The measurement is a handful of stats, once per fork.
        let protected = protected.refreshed()?;
        let protected_relative = protected.relatives_under(&mount.host)?;
        let policy = CopyPolicy {
            exclusions: &mount.exclusions,
            follow: mount.follows_links(),
            protected_ids: protected.identities(),
            protected_relative: &protected_relative,
        };
        let mut report = CopyReport::default();
        let kind = copy_root(&mount.host, &staged_data, &policy, &mut report)
            .with_context(|| format!("initializing fork from {}", mount.source_spelling))?;
        for (relative, file) in &report.omitted {
            notices.push(format!(
                "==> Omitted {} {} from the fork of {}",
                file.description(),
                relative.display(),
                mount.source_spelling
            ));
        }
        let manifest = ForkManifest {
            version: MANIFEST_VERSION,
            id: id.clone(),
            source: mount.source_spelling.clone(),
            guest: mount.guest.display().to_string(),
            follow_links: mount.follows_links(),
            exclusions: mount
                .exclusions
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            kind: match kind {
                PreparedNodeKind::File => "file",
                PreparedNodeKind::Directory => "directory",
            }
            .into(),
        };
        write_manifest(&stage.path().join("manifest.json"), &manifest)?;
        let stage_path = stage.keep();
        match fs::rename(&stage_path, &final_dir) {
            Ok(()) => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("publishing fork {}", final_dir.display()));
            }
        }
        mount.host = final_dir.join("data");
        notices.push(format!(
            "==> Initialized fork {} -> {} (reset: {})",
            mount.source_spelling,
            mount.host.display(),
            final_dir.display()
        ));
    }
    Ok(notices)
}

fn fork_id(mount: &ExtraMount, version: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(version);
    for value in std::iter::once(mount.source_spelling.as_bytes())
        .chain(std::iter::once(mount.guest.as_os_str().as_encoded_bytes()))
        .chain(std::iter::once(if mount.follows_links() {
            b"follow".as_slice()
        } else {
            b"preserve".as_slice()
        }))
        .chain(
            mount
                .exclusions
                .iter()
                .map(|path| path.as_os_str().as_encoded_bytes()),
        )
    {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    format!("{:x}", hash.finalize())
}

fn ensure_store(store: &Path) -> Result<()> {
    let parent = store
        .parent()
        .context("mount store must have a state-root parent")?;
    // `prepare` intentionally runs before session initialization. Create
    // only the missing state-root ancestry needed by a plan that has already
    // passed every topology check; do not pull generic session setup earlier.
    ensure_private_parent_tree(parent)?;

    for path in [
        store.to_path_buf(),
        store.join("locks"),
        store.join("staging"),
        store.join("forks"),
    ] {
        ensure_private_store_directory(&path)?;
    }
    Ok(())
}

/// Materialize missing state-root ancestors without `create_dir_all`. Each
/// requested existing/created leaf is opened with `O_NOFOLLOW`, so a
/// configured state root cannot redirect host-managed fork state through a
/// final symlink. Existing user-owned ancestors retain their modes; every
/// directory created for this state root is private.
fn ensure_private_parent_tree(parent: &Path) -> Result<()> {
    match fs::symlink_metadata(parent) {
        Ok(_) => return validate_private_directory(parent, "mount store parent"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("validating mount store parent {}", parent.display()));
        }
    }

    // Recursing to the nearest existing ancestor leaves existing user-owned
    // directories untouched. Every state-root component created here is its
    // own no-follow final component, and a configured final symlink fails
    // closed.
    let ancestor = parent
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .context("missing mount store parent has no existing ancestor")?;
    ensure_private_parent_tree(ancestor)?;
    let created = match fs::create_dir(parent) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("creating mount store parent {}", parent.display()));
        }
    };
    validate_private_directory(parent, "mount store parent")?;
    if created {
        secure_directory(parent, "mount store parent")?;
    }
    Ok(())
}

fn ensure_private_store_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("creating mount store {}", path.display()));
        }
    }
    validate_private_directory(path, "mount store")?;
    // Do not let a restrictive umask make the invariant depend on the first
    // initializer. These host-managed directories remain private on reuse.
    secure_directory(path, "mount store")
}

fn validate_private_directory(path: &Path, description: &str) -> Result<()> {
    use rustix::fs::{self as rfs, FileType, Mode, OFlags};

    // Opening the entry as a directory is the validation: unlike a
    // metadata-only check, this cannot hand a later operation a symlink.
    let dir = rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("validating {description} {}", path.display()))?;
    if FileType::from_raw_mode(rfs::fstat(&dir)?.st_mode) != FileType::Directory {
        anyhow::bail!(
            "{description} entry {} must be a real directory",
            path.display()
        );
    }
    Ok(())
}

fn secure_directory(path: &Path, description: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing {description} {}", path.display()))
}
fn final_dir_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!("corrupt fork {}; remove it to reset", path.display())
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn open_regular_lock(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening fork lock {}", path.display()))?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("fork lock {} is not regular", path.display());
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("securing fork lock {}", path.display()))?;
    Ok(file)
}
fn lock_exclusive(lock: &std::fs::File) -> Result<()> {
    use rustix::fs::{FlockOperation, flock};
    loop {
        match flock(lock, FlockOperation::LockExclusive) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => {
                return Err(anyhow::anyhow!(error)).context("locking fork initialization");
            }
        }
    }
}
fn clean_stale_staging(staging: &Path, id: &str) -> Result<()> {
    for entry in fs::read_dir(staging)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(&format!("{id}.stage-")) {
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!("unsafe stale fork staging entry {}", entry.path().display());
            }
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}
fn write_manifest(path: &Path, manifest: &ForkManifest) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    serde_json::to_writer(&mut file, manifest)?;
    file.flush()?;
    Ok(())
}
fn validate_ready(dir: &Path, mount: &ExtraMount, id: &str) -> Result<PreparedNodeKind> {
    let reset = || format!("corrupt fork {}; remove it to reset", dir.display());
    let metadata = fs::symlink_metadata(dir).map_err(|_| anyhow::anyhow!(reset()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("{}", reset());
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("manifest.json"))
        .map_err(|_| anyhow::anyhow!(reset()))?;
    let metadata = file.metadata().map_err(|_| anyhow::anyhow!(reset()))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        anyhow::bail!("{}", reset());
    }
    let manifest: ForkManifest =
        serde_json::from_reader(file).map_err(|_| anyhow::anyhow!(reset()))?;
    let expected = ForkManifest {
        version: MANIFEST_VERSION,
        id: id.into(),
        source: mount.source_spelling.clone(),
        guest: mount.guest.display().to_string(),
        follow_links: mount.follows_links(),
        exclusions: mount
            .exclusions
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        kind: manifest.kind.clone(),
    };
    if manifest.version != expected.version
        || manifest.id != expected.id
        || manifest.source != expected.source
        || manifest.guest != expected.guest
        || manifest.follow_links != expected.follow_links
        || manifest.exclusions != expected.exclusions
    {
        anyhow::bail!("{}", reset());
    }
    let data = fs::symlink_metadata(dir.join("data")).map_err(|_| anyhow::anyhow!(reset()))?;
    if data.file_type().is_symlink() {
        anyhow::bail!("{}", reset());
    }
    // Only directory forks are published now (issue #113). A legacy
    // `kind: "file"` entry (or any other/unknown kind) is a hard, actionable
    // stop that names the exact final directory: never reseed, migrate,
    // truncate, rename, delete, or bypass it.
    match (manifest.kind.as_str(), data.is_file(), data.is_dir()) {
        ("directory", false, true) => Ok(PreparedNodeKind::Directory),
        ("file", true, false) => anyhow::bail!(
            "unsupported file fork {} (this build mounts directory forks only); \
             remove it to reset",
            dir.display()
        ),
        _ => anyhow::bail!("{}", reset()),
    }
}

fn is_excluded(relative: &Path, exclusions: &[PathBuf]) -> bool {
    exclusions
        .iter()
        .any(|excluded| relative == excluded || relative.starts_with(excluded))
}
/// Keep only exclusions that are reachable through a followed directory,
/// expressed relative to that directory.  The link itself remains visible;
/// its hidden children must be masked at every bind alias of its target.
fn project_exclusions(exclusions: &[PathBuf], link_relative: &Path) -> Vec<PathBuf> {
    let mut projected = exclusions
        .iter()
        .filter_map(|excluded| excluded.strip_prefix(link_relative).ok())
        .filter(|remaining| !remaining.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    projected.sort();
    projected.dedup();
    projected
}

/// Union projected exclusions when multiple logical routes produce the same
/// bind. Keep the normalized ancestor-collapse invariant from parsing: a
/// mask for `a` makes a later `a/b` mask redundant.
fn merge_exclusions(existing: &mut Vec<PathBuf>, additions: Vec<PathBuf>) {
    existing.extend(additions);
    existing.sort();
    existing.dedup();
    let mut collapsed = Vec::with_capacity(existing.len());
    for exclusion in existing.drain(..) {
        if !collapsed
            .iter()
            .any(|parent: &PathBuf| exclusion.starts_with(parent))
        {
            collapsed.push(exclusion);
        }
    }
    *existing = collapsed;
}
/// Everything the copier needs besides the two paths: the declaration's own
/// exclusions and follow policy, plus the protected-file membership and paths.
/// Bundled because these are adjacent same-typed arguments
/// (CODING_STANDARDS: do not repeat a type in a row).
struct CopyPolicy<'a> {
    exclusions: &'a [PathBuf],
    follow: bool,
    protected_ids: ProtectedIdentities<'a>,
    /// Fork-root-relative paths of protected files, **even ones that do not
    /// exist yet**. The second omission signal: identity alone cannot catch a
    /// protected file created between `measure` and the copy.
    protected_relative: &'a [(PathBuf, ProtectedFile)],
}

impl CopyPolicy<'_> {
    fn protected_file_at(&self, relative: &Path) -> Option<ProtectedFile> {
        self.protected_relative
            .iter()
            .find(|(path, _)| path == relative)
            .map(|(_, file)| *file)
    }
}

/// What the copier refused to copy, for notices.
#[derive(Default)]
struct CopyReport {
    omitted: Vec<(PathBuf, ProtectedFile)>,
}

/// A node the copier either published or deliberately did not. The enum forces
/// `copy_root` to answer the root-omitted case instead of silently publishing
/// an empty fork.
enum CopiedNode {
    Copied(PreparedNodeKind),
    Omitted,
}

/// Copy a directory root via verified descriptors. Nested links are never
/// followed in the default policy, so a swap cannot turn an untrusted leaf
/// into a read of an external target. Explicit follow mode is deliberately
/// opt-in. Nested regular files are still copied by [`copy_opened`]; only the
/// root is directory-only (issue #113).
fn copy_root(
    source: &Path,
    destination: &Path,
    policy: &CopyPolicy<'_>,
    report: &mut CopyReport,
) -> Result<PreparedNodeKind> {
    use rustix::fs::{self as rfs, FileType, Mode, OFlags};
    let source = source
        .canonicalize()
        .with_context(|| format!("resolving fork root {}", source.display()))?;
    #[cfg(test)]
    let _checkpoint_scope = CopyCheckpointScope::enter(&source);
    copy_checkpoint(&source);
    // `O_DIRECTORY` is the load-bearing enforcement: a root that was a
    // directory at preflight but is now a file or a symlink to one fails
    // here, at the descriptor actually copied from, rather than silently
    // publishing a file-root fork.
    let fd = rfs::open(
        &source,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening fork root {}", source.display()))?;
    if FileType::from_raw_mode(rfs::fstat(&fd)?.st_mode) != FileType::Directory {
        anyhow::bail!("fork root {} must be a directory", source.display());
    }
    match copy_opened(
        &fd,
        destination,
        Path::new(""),
        policy,
        0,
        &mut Vec::new(),
        report,
    )? {
        CopiedNode::Copied(kind) => Ok(kind),
        // Unreachable today: protected entries are files and a fork root is
        // `O_DIRECTORY`-enforced. Answered anyway so a future change cannot
        // publish an empty fork in place of a protected host file.
        CopiedNode::Omitted => {
            anyhow::bail!("fork root {} is a protected host file", source.display())
        }
    }
}
fn copy_opened(
    fd: &rustix::fd::OwnedFd,
    destination: &Path,
    relative: &Path,
    policy: &CopyPolicy<'_>,
    depth: usize,
    active: &mut Vec<(u64, u64)>,
    report: &mut CopyReport,
) -> Result<CopiedNode> {
    use rustix::fs::{self as rfs, FileType, Mode, OFlags};
    use std::os::unix::fs::PermissionsExt;
    // Callers skip an excluded child before they open it; this is the
    // defensive restatement of the same rule for the root itself. An excluded
    // node is not an *omitted* one: nothing is reported and nothing is written.
    if is_excluded(relative, policy.exclusions) {
        return Ok(CopiedNode::Copied(PreparedNodeKind::Directory));
    }
    let stat = rfs::fstat(fd)?;
    // Before the destination is created, so an omitted node writes nothing at
    // all — no empty file, no placeholder (an overlay would be a mask, and
    // ADR-0014 removed mask machinery).
    if let Some(file) = policy
        .protected_ids
        .matched(stat.st_dev as u64, stat.st_ino as u64)
        .or_else(|| policy.protected_file_at(relative))
    {
        report.omitted.push((relative.to_path_buf(), file));
        return Ok(CopiedNode::Omitted);
    }
    let ty = FileType::from_raw_mode(stat.st_mode);
    if ty == FileType::RegularFile {
        let mut source = std::fs::File::from(rustix::io::dup(fd)?);
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        std::io::copy(&mut source, &mut target)?;
        target.set_permissions(std::fs::Permissions::from_mode(
            stat.st_mode as u32 & 0o7777,
        ))?;
        return Ok(CopiedNode::Copied(PreparedNodeKind::File));
    }
    if ty != FileType::Directory {
        anyhow::bail!("{} is not a regular file or directory", relative.display());
    }
    let identity = (stat.st_dev as u64, stat.st_ino as u64);
    if active.contains(&identity) {
        anyhow::bail!("symlink cycle while copying {}", relative.display());
    }
    active.push(identity);
    fs::create_dir(destination)?;
    let entries = rfs::Dir::read_from(fd)?;
    for entry in entries {
        let entry = entry?;
        let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
        // libc's directory stream includes the self/parent entries on Unix.
        // They are not source children and descending into either would turn
        // a valid directory into a false active-stack cycle.
        if name == std::ffi::OsStr::new(".") || name == std::ffi::OsStr::new("..") {
            continue;
        }
        let child_relative = relative.join(name);
        if is_excluded(&child_relative, policy.exclusions) {
            continue;
        }
        let child_stat = rfs::statat(fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let child_ty = FileType::from_raw_mode(child_stat.st_mode);
        let child_dst = destination.join(name);
        copy_checkpoint(&child_relative);
        if child_ty == FileType::Symlink {
            if !policy.follow {
                let raw = rfs::readlinkat(fd, name, Vec::new())?;
                std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(raw.as_bytes()), child_dst)?;
            } else {
                if depth >= FORK_MAX_LINK_DEPTH {
                    anyhow::bail!(
                        "maximum symlink follow depth exceeded at {}",
                        child_relative.display()
                    );
                }
                // openat resolves the link relative to the already-pinned
                // parent descriptor.  Unlike synthesizing /dev/fd paths it
                // works on macOS as well as Linux and keeps relative links
                // inside the directory that contained their raw text. Without
                // `NOFOLLOW`, a followed target is classified by its own
                // `fstat`, so an omitted protected file is not materialized.
                let target = rfs::openat(
                    fd,
                    name,
                    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("following {}", child_relative.display()))?;
                copy_opened(
                    &target,
                    &child_dst,
                    &child_relative,
                    policy,
                    depth + 1,
                    active,
                    report,
                )?;
            }
        } else {
            let child = rfs::openat(
                fd,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            copy_opened(
                &child,
                &child_dst,
                &child_relative,
                policy,
                depth,
                active,
                report,
            )?;
        }
    }
    fs::set_permissions(
        destination,
        std::fs::Permissions::from_mode(stat.st_mode as u32 & 0o7777),
    )?;
    active.pop();
    Ok(CopiedNode::Copied(PreparedNodeKind::Directory))
}

#[cfg(test)]
mod prepare_tests {
    use super::*;

    /// A real, empty `$HOME` shared by every test in this binary. `measure`
    /// needs a locatable home for `require_home`; with no `~/.pi` it yields
    /// `Severity::Advise` and no exposure for a test source that is not an
    /// ancestor of the home. Held in a `OnceLock` so the directory outlives
    /// every `MountContext` without each call leaking its own.
    fn test_home() -> PathBuf {
        static HOME: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        HOME.get_or_init(|| tempfile::tempdir().unwrap())
            .path()
            .to_path_buf()
    }

    fn context(store: &Path) -> MountContext {
        context_with_home(store, test_home())
    }

    fn context_with_home(store: &Path, home: PathBuf) -> MountContext {
        MountContext {
            mount_store: store.to_path_buf(),
            host_home: Some(home),
            core_guest_mounts: Vec::new(),
            core_host_sources: Vec::new(),
        }
    }

    /// The fail-closed `$HOME`-unset case (`ProtectedHostFiles::require_home`).
    fn context_without_home(store: &Path) -> MountContext {
        MountContext {
            mount_store: store.to_path_buf(),
            host_home: None,
            core_guest_mounts: Vec::new(),
            core_host_sources: Vec::new(),
        }
    }

    fn store_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn visit(root: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
                let metadata = fs::symlink_metadata(entry.path()).unwrap();
                if metadata.is_dir() {
                    out.push((relative.clone(), b"directory".to_vec()));
                    visit(root, &entry.path(), out);
                } else if metadata.file_type().is_symlink() {
                    use std::os::unix::ffi::OsStrExt;
                    out.push((
                        relative,
                        fs::read_link(entry.path())
                            .unwrap()
                            .as_os_str()
                            .as_bytes()
                            .to_vec(),
                    ));
                } else {
                    out.push((relative, fs::read(entry.path()).unwrap()));
                }
            }
        }

        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries.sort();
        entries
    }

    #[test]
    fn prepare_normalizes_guest_before_fork_identity() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("visible"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let first = parse_extra_mounts(&[format!("{}:/guest//path:fork", source.path().display())])
            .unwrap();
        let second =
            parse_extra_mounts(&[format!("{}:/guest/./path:fork", source.path().display())])
                .unwrap();
        let first = prepare(first, &context(store.path())).unwrap();
        let second = prepare(second, &context(store.path())).unwrap();
        let first_host = match &first.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork is writable"),
        };
        let second_host = match &second.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork is writable"),
        };
        assert_eq!(first.volumes[0].guest, PathBuf::from("/guest/path"));
        assert_eq!(first_host, second_host);
    }

    #[test]
    fn ready_fork_reuses_after_source_removal() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("visible"), "seed").unwrap();
        let spelling = source.path().display().to_string();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{spelling}:/guest:fork");
        let seeded = prepare(
            parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let data = match &seeded.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            _ => panic!("fork is writable"),
        };
        fs::remove_dir_all(source.path()).unwrap();
        let reused = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let reused_data = match &reused.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork is writable"),
        };
        assert_eq!(reused_data, &data);
        assert_eq!(fs::read_to_string(data.join("visible")).unwrap(), "seed");
    }

    #[test]
    fn rejection_precedence_fork_source_then_canonicalization_then_file_rw() {
        // A bad fork root is rejected in preflight, before live-bind
        // canonicalization: the fork-source error wins over a missing live
        // source in the same argv.
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fs::write(&file, "x").unwrap();
        let missing = root.path().join("missing");
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/fork:fork", file.display()),
                format!("{}:/live:ro", missing.display()),
            ])
            .unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("a :fork source must be a directory"),
            "{error}"
        );

        // A missing live source is reported during canonicalization, before
        // the file-rw rejection in live-volume assembly.
        let file2 = root.path().join("file2");
        fs::write(&file2, "x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/file:rw", file2.display()),
                format!("{}:/missing:ro", missing.display()),
            ])
            .unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("canonicalizing --mount host"), "{error}");
    }

    #[test]
    fn legacy_ready_file_kind_fails_closed_without_mutation() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("seed"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork", source.path().display());
        let plan = prepare(
            parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let data = match &plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            _ => panic!("fork is writable"),
        };
        let final_dir = data.parent().unwrap().to_path_buf();
        let manifest_path = final_dir.join("manifest.json");

        // Negative controls: `kind: directory` paired with non-directory data,
        // and a legacy `kind: file` with a valuable regular file.
        for (kind, make_file) in [("directory", true), ("file", true), ("file", false)] {
            if make_file {
                fs::remove_dir_all(&data)
                    .or_else(|_| fs::remove_file(&data))
                    .unwrap();
                fs::write(&data, "valuable bytes").unwrap();
            }
            let mut manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
            manifest["kind"] = serde_json::Value::String(kind.into());
            fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            let before = store_tree(store.path());

            // The original source is removed to prove the failure does not
            // depend on it.
            fs::remove_dir_all(source.path()).ok();
            let error = prepare(
                parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
                &context(store.path()),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(&final_dir.display().to_string()),
                "error must name the exact final directory: {error}"
            );
            assert!(error.contains("reset"), "{error}");
            assert_eq!(
                store_tree(store.path()),
                before,
                "a legacy/bad manifest must be retained unchanged (kind={kind})"
            );
            if make_file {
                assert_eq!(fs::read_to_string(&data).unwrap(), "valuable bytes");
            }
        }
    }

    #[test]
    fn exact_core_fork_collision_is_rejected_before_fork_store_creation() {
        // An explicit fork and a core mount at the same guest path is an exact
        // collision; the fork identity is otherwise valid.
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("hidden"), "secret").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = parse_extra_mounts(&[format!(
            "{}:/guest:fork:exclude=hidden",
            source.path().display()
        )])
        .unwrap();
        let mut context = context(store.path());
        context.core_guest_mounts.push(PathBuf::from("/guest"));
        assert!(prepare(request, &context).is_err());
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());
    }

    #[test]
    fn exact_core_explicit_collision_has_no_store_side_effects() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("seed"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request =
            parse_extra_mounts(&[format!("{}:/core:fork", source.path().display())]).unwrap();
        let mut mount_context = context(store.path());
        mount_context.core_guest_mounts.push(PathBuf::from("/core"));

        let error = prepare(request, &mount_context).unwrap_err();
        assert!(error.to_string().contains("core mount"), "{error:#}");
        assert!(
            fs::read_dir(store.path()).unwrap().next().is_none(),
            "an exact explicit/core collision must not create fork state"
        );
    }

    #[test]
    fn exact_core_followed_collision_has_no_store_side_effects_in_either_order() {
        use std::os::unix::fs::symlink;

        for fork_first in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let root_path = root.path().canonicalize().unwrap();
            let home = root_path.join("home");
            let live = home.join("live");
            let target = home.join("core-target");
            let fork_source = root_path.join("fork-source");
            fs::create_dir_all(&live).unwrap();
            fs::create_dir(&target).unwrap();
            fs::create_dir(&fork_source).unwrap();
            symlink(&target, live.join("core-alias")).unwrap();
            let followed = format!("{}:/guest:ro:follow-links", live.display());
            let fork = format!("{}:/fork:fork", fork_source.display());
            let declarations = if fork_first {
                vec![fork, followed]
            } else {
                vec![followed, fork]
            };
            let store = tempfile::tempdir().unwrap();
            let mount_context = MountContext {
                mount_store: store.path().to_path_buf(),
                host_home: Some(home),
                core_guest_mounts: vec![target],
                core_host_sources: Vec::new(),
            };

            let error =
                prepare(parse_extra_mounts(&declarations).unwrap(), &mount_context).unwrap_err();
            assert!(error.to_string().contains("core mount"), "{error:#}");
            assert!(
                fs::read_dir(store.path()).unwrap().next().is_none(),
                "an exact followed/core collision must not create fork state (fork_first={fork_first})"
            );
        }
    }

    #[test]
    fn file_rw_rejection_precedes_fork_store_creation_in_either_order() {
        let fork_source = tempfile::tempdir().unwrap();
        fs::create_dir(fork_source.path().join("seed")).unwrap();
        let file_source = tempfile::tempdir().unwrap();
        let file = file_source.path().join("plain-file");
        fs::write(&file, "content").unwrap();

        for declarations in [
            vec![
                format!("{}:/fork:fork", fork_source.path().display()),
                format!("{}:/live/file", file.display()),
            ],
            vec![
                format!("{}:/live/file", file.display()),
                format!("{}:/fork:fork", fork_source.path().display()),
            ],
        ] {
            // An absent mount-store path must stay absent: the file-rw
            // rejection is a policy error, not a fork transaction.
            let store = file_source.path().join("absent-store");
            let error =
                prepare(parse_extra_mounts(&declarations).unwrap(), &context(&store)).unwrap_err();
            assert!(
                error.to_string().contains("can only be mounted read-only"),
                "{error:#}"
            );
            assert!(!store.exists(), "rejection must not create the mount store");
        }
    }

    #[test]
    fn file_ro_parent_topology_rejection_is_side_effect_free_in_either_order() {
        let fork_source = tempfile::tempdir().unwrap();
        fs::create_dir(fork_source.path().join("seed")).unwrap();
        let file_source = tempfile::tempdir().unwrap();
        let file = file_source.path().join("plain-file");
        fs::write(&file, "content").unwrap();
        let child_source = tempfile::tempdir().unwrap();

        for declarations in [
            vec![
                format!("{}:/fork:fork", fork_source.path().display()),
                format!("{}:/live/file:ro", file.display()),
                format!("{}:/live/file/child:ro", child_source.path().display()),
            ],
            vec![
                format!("{}:/live/file/child:ro", child_source.path().display()),
                format!("{}:/live/file:ro", file.display()),
                format!("{}:/fork:fork", fork_source.path().display()),
            ],
        ] {
            let store = file_source.path().join("absent-store");
            assert!(!store.exists());
            let error =
                prepare(parse_extra_mounts(&declarations).unwrap(), &context(&store)).unwrap_err();
            assert!(error.to_string().contains("below file mount"), "{error:#}");
            assert!(!store.exists(), "rejection must be side-effect free");
        }
    }

    #[test]
    fn file_fork_roots_reject_before_store_creation_and_retry_after_becoming_directory() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::write(&source, "seed").unwrap();
        let store = tempfile::tempdir().unwrap();

        // Plain, excluded, and follow-links file forks all reject before the
        // store exists; the old plain-file fork success path is gone.
        for request in [
            format!("{}:/guest:fork", source.display()),
            format!("{}:/guest:fork:exclude=hidden", source.display()),
            format!("{}:/guest:fork:follow-links", source.display()),
        ] {
            let error = prepare(
                parse_extra_mounts(&[request]).unwrap(),
                &context(store.path()),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("must be a directory"), "{error}");
            assert!(fs::read_dir(store.path()).unwrap().next().is_none());
        }

        // Turning the same spelling into a directory makes the same identity
        // resolvable on retry (the file rejection did not poison it).
        fs::remove_file(&source).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(source.join("visible"), "seed").unwrap();
        let valid = format!("{}:/guest:fork", source.display());
        assert!(
            prepare(
                parse_extra_mounts(&[valid]).unwrap(),
                &context(store.path())
            )
            .is_ok()
        );
    }

    #[test]
    fn first_use_fork_kind_validates_core_explicit_and_followed_descendants() {
        use std::os::unix::fs::symlink;

        // A directory fork keeps accepting descendant claims (explicit,
        // followed, and core) in either declaration order.
        for fork_first in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            fs::create_dir(&source).unwrap();
            let child = root.path().join("child");
            fs::create_dir(&child).unwrap();
            let live = root.path().join("live");
            fs::create_dir(&live).unwrap();
            symlink(&child, live.join("followed-child")).unwrap();
            let fork = format!("{}:{}:fork", source.display(), root.path().display());
            let explicit = format!("{}:{}:ro", child.display(), child.display());
            let followed = format!("{}:ro:follow-links", live.display());

            for child_claim in [&explicit, &followed] {
                let declarations = if fork_first {
                    vec![fork.clone(), child_claim.to_string()]
                } else {
                    vec![child_claim.to_string(), fork.clone()]
                };
                let store = tempfile::tempdir().unwrap();
                let result = prepare(
                    parse_extra_mounts(&declarations).unwrap(),
                    &MountContext {
                        mount_store: store.path().to_path_buf(),
                        host_home: Some(root.path().to_path_buf()),
                        core_guest_mounts: vec![root.path().join("core-child")],
                        core_host_sources: Vec::new(),
                    },
                );
                assert!(
                    result.is_ok(),
                    "directory fork must allow child: {result:?}"
                );
            }
        }

        // A file fork root is rejected with the directory-only diagnostic,
        // never a `below file mount` topology error, even with descendants.
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-file");
        fs::write(&source, "seed").unwrap();
        let child = root.path().join("child");
        fs::create_dir(&child).unwrap();
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/guest:fork", source.display()),
                format!("{}:/guest/child:ro", child.display()),
            ])
            .unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("a :fork source must be a directory"),
            "{error}"
        );
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());
    }

    #[test]
    fn readonly_file_bind_rejects_explicit_followed_and_core_descendants() {
        use std::os::unix::fs::symlink;

        // Explicit child below a read-only file bind, both orders.
        for file_first in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let file = root.path().join("plain-file");
            fs::write(&file, "content").unwrap();
            let child_source = root.path().join("explicit-child");
            fs::create_dir(&child_source).unwrap();
            let file_mount = format!("{}:/guest/file:ro", file.display());
            let child = format!("{}:/guest/file/child:ro", child_source.display());
            let declarations = if file_first {
                vec![file_mount.clone(), child]
            } else {
                vec![child, file_mount.clone()]
            };
            let store = tempfile::tempdir().unwrap();
            let error = prepare(
                parse_extra_mounts(&declarations).unwrap(),
                &context(store.path()),
            )
            .unwrap_err();
            assert!(error.to_string().contains("below file mount"), "{error:#}");
            assert!(fs::read_dir(store.path()).unwrap().next().is_none());
        }

        // A followed target whose discovered guest path is below the file
        // bind is rejected. The file is mounted at the guest spelling of a
        // real directory `D`; the live root is elsewhere and links into `D`.
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().canonicalize().unwrap();
        let file = home_path.join("plain-file");
        fs::write(&file, "content").unwrap();
        let live = home_path.join("live");
        let d = home_path.join("d");
        let sub = d.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir(&live).unwrap();
        symlink(&sub, live.join("link")).unwrap();
        let file_mount = format!("{}:{}:ro", file.display(), d.display());
        let followed = format!("{}:ro:follow-links", live.display());
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[file_mount, followed]).unwrap(),
            &MountContext {
                mount_store: store.path().to_path_buf(),
                host_home: Some(home_path.clone()),
                core_guest_mounts: Vec::new(),
                core_host_sources: Vec::new(),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("below file mount"), "{error:#}");
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());

        // Core child below a read-only file bind.
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("plain-file");
        fs::write(&file, "content").unwrap();
        let store = tempfile::tempdir().unwrap();
        let mut mount_context = context(store.path());
        mount_context
            .core_guest_mounts
            .push(PathBuf::from("/guest/file/core-child"));
        let error = prepare(
            parse_extra_mounts(&[format!("{}:/guest/file:ro", file.display())]).unwrap(),
            &mount_context,
        )
        .unwrap_err();
        assert!(error.to_string().contains("below file mount"), "{error:#}");
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());
    }

    #[test]
    fn ready_directory_fork_allows_explicit_child_in_either_declaration_order() {
        for fork_first in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source-directory");
            let child = root.path().join("child-directory");
            fs::create_dir(&source).unwrap();
            fs::create_dir(&child).unwrap();
            let store = tempfile::tempdir().unwrap();
            let fork = format!("{}:/guest/directory:fork", source.display());
            prepare(
                parse_extra_mounts(std::slice::from_ref(&fork)).unwrap(),
                &context(store.path()),
            )
            .expect("first launch seeds the directory fork");
            fs::remove_dir(&source).unwrap();

            let child_mount = format!("{}:/guest/directory/child:ro", child.display());
            let declarations = if fork_first {
                vec![fork, child_mount]
            } else {
                vec![child_mount, fork]
            };
            prepare(
                parse_extra_mounts(&declarations).unwrap(),
                &context(store.path()),
            )
            .expect("a READY directory fork permits a nested mount");
        }
    }

    #[test]
    fn file_ro_below_core_is_rejected_before_store_or_launch_work() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-file");
        fs::write(&source, "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let mut mount_context = context(store.path());
        mount_context
            .core_guest_mounts
            .push(PathBuf::from("/tmp/project"));

        let error = prepare(
            parse_extra_mounts(&[format!("{}:/tmp:ro", source.display())]).unwrap(),
            &mount_context,
        )
        .expect_err("a core directory below a read-only file bind cannot be mounted");
        assert!(error.to_string().contains("below file mount"), "{error:#}");
        assert!(
            fs::read_dir(store.path()).unwrap().next().is_none(),
            "topology validation must precede fork-store creation"
        );
    }

    #[test]
    fn concurrent_initializer_waits_for_ready_after_source_is_removed() {
        // Re-exec this exact unit test for the second initializer. `flock`
        // is process-scoped, so threads would incorrectly share the lock.
        if std::env::var_os("AGENT_VM_FORK_WAITER").is_some() {
            let store = PathBuf::from(std::env::var_os("AGENT_VM_FORK_STORE").unwrap());
            let request = std::env::var("AGENT_VM_FORK_REQUEST").unwrap();
            let result = prepare(parse_extra_mounts(&[request]).unwrap(), &context(&store))
                .expect("waiter must reuse READY");
            let data = match &result.volumes[0].source {
                PreparedVolumeSource::WritableBind(path) => path,
                _ => panic!("fork is writable"),
            };
            std::fs::write(
                std::env::var_os("AGENT_VM_FORK_RESULT").unwrap(),
                format!("{}\n{}", data.display(), result.notices.join("\n")),
            )
            .unwrap();
            return;
        }

        let _checkpoint_guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };

        let source_root = tempfile::tempdir().unwrap();
        let source = source_root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("waiter-stage-marker"), "initial").unwrap();
        fs::write(source.join("excluded"), "never copied").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork:exclude=excluded", source.display());
        let (staged_tx, staged_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let paused = Arc::new(AtomicBool::new(false));
        let checkpoint_paused = Arc::clone(&paused);
        set_copy_checkpoint(
            &source,
            Box::new(move |path| {
                // `waiter-stage-marker` is reached after copy_root has opened the root through
                // its pinned descriptor, so renaming the declaration path cannot
                // disrupt the first initializer's already-staged traversal.
                if path == Path::new("waiter-stage-marker")
                    && !checkpoint_paused.swap(true, Ordering::SeqCst)
                {
                    staged_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                }
            }),
        );

        let first_store = store.path().to_path_buf();
        let first_request = request.clone();
        let first = std::thread::spawn(move || {
            prepare(
                parse_extra_mounts(&[first_request]).unwrap(),
                &context(&first_store),
            )
            .unwrap()
        });
        staged_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("first initializer must stage while holding its fork lock");
        fs::rename(&source, source_root.path().join("source-moved")).unwrap();

        let waiter_result = source_root.path().join("waiter-result");
        let mut second = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mount::prepare_tests::concurrent_initializer_waits_for_ready_after_source_is_removed",
                "--nocapture",
            ])
            .env("AGENT_VM_FORK_WAITER", "1")
            .env("AGENT_VM_FORK_STORE", store.path())
            .env("AGENT_VM_FORK_REQUEST", &request)
            .env("AGENT_VM_FORK_RESULT", &waiter_result)
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            second.try_wait().unwrap().is_none(),
            "second initializer must wait for the lock instead of preflighting the removed source"
        );
        resume_tx.send(()).unwrap();
        let first_plan = first.join().unwrap();
        assert!(second.wait().unwrap().success(), "waiter must reuse READY");
        clear_copy_checkpoint();

        let fork_path = match &first_plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            _ => panic!("fork is writable"),
        };
        let waiter = fs::read_to_string(waiter_result).unwrap();
        assert!(
            waiter.starts_with(&fork_path.display().to_string()),
            "{waiter}"
        );
        assert_eq!(
            fs::read_to_string(fork_path.join("waiter-stage-marker")).unwrap(),
            "initial"
        );
        assert!(waiter.contains("Reusing fork"), "{waiter}");
    }

    #[test]
    fn killed_initializer_leaves_only_retryable_staging() {
        if std::env::var_os("AGENT_VM_FORK_KILLED_INITIALIZER").is_some() {
            let store = PathBuf::from(std::env::var_os("AGENT_VM_FORK_STORE").unwrap());
            let request = std::env::var("AGENT_VM_FORK_REQUEST").unwrap();
            prepare(parse_extra_mounts(&[request]).unwrap(), &context(&store)).unwrap();
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("kill-here"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork", source.display());
        let ready = root.path().join("copy-started");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mount::prepare_tests::killed_initializer_leaves_only_retryable_staging",
                "--nocapture",
            ])
            .env("AGENT_VM_FORK_KILLED_INITIALIZER", "1")
            .env("AGENT_VM_FORK_STORE", store.path())
            .env("AGENT_VM_FORK_REQUEST", &request)
            .env("AGENT_VM_FORK_KILL_CHECKPOINT", "kill-here")
            .env("AGENT_VM_FORK_KILL_READY", &ready)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "initializer did not reach copy"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());

        let retry = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &context(store.path()),
        )
        .expect("a killed initializer must be retryable");
        let data = match &retry.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork is writable"),
        };
        assert_eq!(fs::read_to_string(data.join("kill-here")).unwrap(), "seed");
        assert_eq!(
            fs::read_dir(store.path().join("staging")).unwrap().count(),
            0
        );
        assert_eq!(fs::read_dir(store.path().join("forks")).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_initializers_publish_one_reusable_fork() {
        use std::sync::{Arc, Barrier};

        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("seed"), "initial").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork", source.path().display());
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let store = store.path().to_path_buf();
            let request = request.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                prepare(parse_extra_mounts(&[request]).unwrap(), &context(&store)).unwrap()
            }));
        }
        let plans: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        let paths: Vec<_> = plans
            .iter()
            .map(|plan| match &plan.volumes[0].source {
                PreparedVolumeSource::WritableBind(path) => path.clone(),
                _ => panic!("fork must be writable"),
            })
            .collect();
        assert_eq!(paths[0], paths[1]);
        assert!(paths[0].is_dir());
        assert_eq!(
            fs::read_to_string(paths[0].join("seed")).unwrap(),
            "initial"
        );
        assert_eq!(
            fs::read_dir(store.path().join("forks")).unwrap().count(),
            1,
            "only one READY directory may be published"
        );
        assert_eq!(
            fs::read_dir(store.path().join("staging")).unwrap().count(),
            0,
            "a waiter must never observe or publish staging"
        );
    }

    #[test]
    fn excluded_symlink_is_not_followed_or_planned() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let target = home.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        symlink(&target, source.join("hidden-link")).unwrap();
        let (targets, _) = discover_followed_targets(
            &BindPath {
                host: source,
                guest: PathBuf::from("/guest"),
                exclusions: vec![PathBuf::from("hidden-link")],
            },
            home.path(),
        )
        .unwrap();
        assert!(targets.iter().all(|target_plan| target_plan.host != target));
    }

    #[test]
    fn descriptor_swap_at_root_nested_file_directory_and_link_fails_closed() {
        let _checkpoint_guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        use std::os::unix::fs::symlink;

        // The root case starts as a real directory and is swapped for both a
        // symlink-to-external-directory and a regular file: this is exactly
        // what `copy_root`'s `O_DIRECTORY` descriptor open must reject. Nested
        // file/directory/link swaps stay as they were.
        for (victim, root_replacement) in [
            ("root", "symlink"),
            ("root", "file"),
            ("file", "symlink"),
            ("directory", "symlink"),
            ("link", "symlink"),
        ] {
            let swapped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            let external_file = root.path().join("external-file");
            let external_dir = root.path().join("external-dir");
            fs::create_dir(&source).unwrap();
            fs::write(source.join("kept"), "inside").unwrap();
            fs::write(&external_file, "outside").unwrap();
            fs::create_dir(&external_dir).unwrap();
            fs::write(external_dir.join("outside"), "outside").unwrap();
            match victim {
                "root" => {}
                "file" => fs::write(source.join("file"), "inside").unwrap(),
                "directory" => {
                    fs::create_dir(source.join("directory")).unwrap();
                    fs::write(source.join("directory/item"), "inside").unwrap();
                }
                "link" => symlink(&external_file, source.join("link")).unwrap(),
                _ => unreachable!(),
            }
            let swap = if victim == "root" {
                source.clone()
            } else {
                source.join(victim)
            };
            let root_source = source.clone();
            let checkpoint = PathBuf::from(victim);
            let external_file_capture = external_file.clone();
            let external_dir_capture = external_dir.clone();
            let swapping_link = victim == "link";
            let root_replacement_kind = root_replacement.to_string();
            let swapped_at_checkpoint = std::sync::Arc::clone(&swapped);
            set_copy_checkpoint(
                &source,
                Box::new(move |seen| {
                    let root_checkpoint =
                        swap == root_source && seen == root_source.canonicalize().unwrap();
                    if root_checkpoint || seen == checkpoint {
                        swapped_at_checkpoint.store(true, std::sync::atomic::Ordering::SeqCst);
                        let replacement = swap.with_extension("swapped");
                        // A rename makes the check/open window deterministic.
                        fs::rename(&swap, &replacement).unwrap();
                        if swapping_link {
                            fs::hard_link(&external_file_capture, &swap).unwrap();
                        } else if root_checkpoint && root_replacement_kind == "file" {
                            fs::write(&swap, "swapped").unwrap();
                        } else if root_checkpoint {
                            symlink(&external_dir_capture, &swap).unwrap();
                        } else {
                            symlink(&external_file_capture, &swap).unwrap();
                        }
                    }
                }),
            );
            let store = tempfile::tempdir().unwrap();
            let request = format!("{}:/guest:fork", source.display());
            assert!(
                prepare(
                    parse_extra_mounts(&[request]).unwrap(),
                    &context(store.path())
                )
                .is_err(),
                "swap at {victim}/{root_replacement} was accepted"
            );
            clear_copy_checkpoint();
            assert!(
                swapped.load(std::sync::atomic::Ordering::SeqCst),
                "checkpoint at {victim}/{root_replacement} did not run"
            );
            assert!(
                fs::read_dir(store.path().join("forks"))
                    .unwrap()
                    .next()
                    .is_none()
            );
            assert_eq!(
                fs::read_to_string(external_dir.join("outside")).unwrap(),
                "outside",
                "external content must not be mutated"
            );
        }
    }

    #[test]
    fn follow_copy_rejects_cycles_and_depth_but_materializes_two_aliases() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        symlink(".", source.join("cycle")).unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork:follow-links", source.display());
        let error = prepare(
            parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ");
        assert!(error.contains("cycle"), "{error}");
        assert!(
            fs::read_dir(store.path().join("forks"))
                .unwrap()
                .next()
                .is_none()
        );

        fs::remove_file(source.join("cycle")).unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("value"), "copied").unwrap();
        symlink(&target, source.join("one")).unwrap();
        symlink(&target, source.join("two")).unwrap();
        let plan = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let data = match &plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => unreachable!(),
        };
        assert_eq!(
            fs::read_to_string(data.join("one/value")).unwrap(),
            "copied"
        );
        assert_eq!(
            fs::read_to_string(data.join("two/value")).unwrap(),
            "copied"
        );
    }

    #[test]
    fn follow_copy_accepts_deep_links_and_rejects_an_overlong_chain() {
        use std::os::unix::fs::symlink;

        fn seed_through_chain(link_count: usize) -> Result<String> {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            let target = root.path().join("target");
            fs::create_dir(&source).unwrap();
            fs::create_dir(&target).unwrap();
            fs::write(target.join("value"), "copied").unwrap();
            for index in (0..link_count).rev() {
                let destination = target.join(format!("link-{index}"));
                let raw_target = if index + 1 == link_count {
                    PathBuf::from("value")
                } else {
                    PathBuf::from(format!("link-{}", index + 1))
                };
                symlink(raw_target, destination).unwrap();
            }
            symlink(target.join("link-0"), source.join("link")).unwrap();
            let store = tempfile::tempdir().unwrap();
            let plan = prepare(
                parse_extra_mounts(&[format!("{}:/guest:fork:follow-links", source.display())])
                    .unwrap(),
                &context(store.path()),
            )?;
            let data = match &plan.volumes[0].source {
                PreparedVolumeSource::WritableBind(path) => path,
                _ => unreachable!(),
            };
            fs::read_to_string(data.join("link")).map_err(Into::into)
        }

        // Darwin rejects a chain at its lower kernel limit, before a
        // descriptor can expose every individual link. Exercise a deep chain
        // below that portable limit, then prove the declared overlong chain
        // fails cleanly rather than recursing or publishing a fork.
        let deep =
            seed_through_chain(FORK_MAX_LINK_DEPTH / 2).unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(deep, "copied");
        let error = format!("{:#}", seed_through_chain(FORK_MAX_LINK_DEPTH).unwrap_err());
        assert!(
            error.contains("maximum symlink follow depth") || error.contains("Too many levels"),
            "{error}"
        );
    }

    #[test]
    fn transaction_retries_stale_stage_and_rejects_ready_corruption() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("value"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request =
            parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap();
        let id = fork_id(&request[0], IDENTITY_VERSION);
        ensure_store(store.path()).unwrap();
        fs::create_dir(
            store
                .path()
                .join("staging")
                .join(format!("{id}.stage-crashed")),
        )
        .unwrap();
        let plan = prepare(request, &context(store.path())).unwrap();
        assert!(store.path().join("forks").join(&id).join("data").exists());
        assert!(
            store
                .path()
                .join("staging")
                .read_dir()
                .unwrap()
                .next()
                .is_none()
        );
        let data = match &plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => unreachable!(),
        };
        fs::remove_dir_all(data).unwrap();
        let error = prepare(
            parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("remove it to reset"), "{error}");
    }

    #[test]
    fn root_symlink_seeds_a_real_directory_and_reuses_after_target_changes() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("seed"), "first").unwrap();
        let declaration = root.path().join("declaration");
        symlink(&target, &declaration).unwrap();
        let store = tempfile::tempdir().unwrap();
        let request = format!("{}:/guest:fork", declaration.display());
        let seeded = prepare(
            parse_extra_mounts(std::slice::from_ref(&request)).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let data = match &seeded.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            _ => panic!("fork must be writable"),
        };
        assert!(fs::symlink_metadata(&data).unwrap().is_dir());
        fs::remove_dir_all(&target).unwrap();
        let reused = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &context(store.path()),
        )
        .unwrap();
        let reused_data = match &reused.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path,
            _ => panic!("fork must be writable"),
        };
        assert_eq!(reused_data, &data);
        assert_eq!(fs::read_to_string(data.join("seed")).unwrap(), "first");
    }

    // ── protected host files (issue #90) ─────────────────────────────

    /// A `$HOME` with a real `~/.pi`, and a context pointed at it. The
    /// `TempDir` is returned so it outlives the context.
    fn pi_home() -> (tempfile::TempDir, PathBuf) {
        let home = tempfile::tempdir().unwrap();
        let canonical = home.path().canonicalize().unwrap();
        fs::create_dir_all(canonical.join(".pi/agent")).unwrap();
        fs::write(canonical.join(".pi/agent/auth.json"), "{\"token\":\"t\"}").unwrap();
        fs::write(canonical.join(".pi/agent/models.json"), "{}").unwrap();
        fs::write(canonical.join(".pi/settings.json"), "{}").unwrap();
        (home, canonical)
    }

    fn fork_data(plan: &PreparedMountPlan) -> PathBuf {
        match &plan.volumes[0].source {
            PreparedVolumeSource::WritableBind(path) => path.clone(),
            other => panic!("fork must be writable, got {other:?}"),
        }
    }

    #[test]
    fn ro_and_rw_mounts_of_pi_home_are_refused_before_store_creation() {
        let (_home, home) = pi_home();
        for declaration in [
            format!("{}:ro", home.join(".pi").display()),
            format!("{}:rw", home.join(".pi").display()),
            format!("{}:ro", home.display()),
            format!("{}:/mnt/pi:ro", home.join(".pi").display()),
        ] {
            let store = tempfile::tempdir().unwrap();
            let error = prepare(
                parse_extra_mounts(std::slice::from_ref(&declaration)).unwrap(),
                &context_with_home(store.path(), home.clone()),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(&home.join(".pi/agent/auth.json").display().to_string()),
                "{declaration}: {error}"
            );
            assert!(error.contains(":fork"), "{declaration}: {error}");
            assert!(
                store_tree(store.path()).is_empty(),
                "a refused plan must not create fork state: {declaration}"
            );
        }
    }

    #[test]
    fn followed_symlink_alias_to_pi_home_is_refused() {
        use std::os::unix::fs::symlink;

        let (_home, home) = pi_home();
        let live = tempfile::tempdir().unwrap();
        let link = live.path().join("pi-link");
        symlink(home.join(".pi"), &link).unwrap();
        let declaration = format!("{}:ro:follow-links", live.path().display());
        let store = tempfile::tempdir().unwrap();

        let error = prepare(
            parse_extra_mounts(std::slice::from_ref(&declaration)).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();
        // The *discovered* bind is the leak; the message names the declaration
        // it came from, because the user never typed that path.
        assert!(error.contains("discovered by --mount"), "{error}");
        assert!(
            error.contains(&live.path().display().to_string()),
            "{error}"
        );
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }

    /// With two `:follow-links` declarations, `expand_follow_links` does not
    /// record which one discovered a target (and legitimately merges the two
    /// when both do), so the refusal must not blame both — let alone the one
    /// that contributed nothing.
    #[test]
    fn a_discovered_leak_with_two_follow_links_declarations_blames_neither() {
        use std::os::unix::fs::symlink;

        let (_home, home) = pi_home();
        let leak = home.join("leak");
        let innocent = home.join("innocent");
        fs::create_dir_all(&leak).unwrap();
        fs::create_dir_all(&innocent).unwrap();
        symlink(home.join(".pi"), leak.join("pi-link")).unwrap();
        let declarations = [
            format!("{}:ro:follow-links", leak.display()),
            format!("{}:ro:follow-links", innocent.display()),
        ];
        let store = tempfile::tempdir().unwrap();

        let error = prepare(
            parse_extra_mounts(&declarations).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("would expose"), "{error}");
        assert!(
            error.contains("discovered by one of your --mount"),
            "{error}"
        );
        assert!(!error.contains("discovered by --mount"), "{error}");
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }

    #[test]
    fn fork_of_pi_home_omits_both_files_and_copies_everything_else() {
        let (_home, home) = pi_home();
        fs::create_dir_all(home.join(".pi/extensions")).unwrap();
        fs::write(home.join(".pi/extensions/x.js"), "x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!("{}:/pi:fork", home.join(".pi").display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let data = fork_data(&plan);

        assert!(data.join("settings.json").is_file());
        assert!(data.join("extensions/x.js").is_file());
        // The containing directory stays; only the protected files are absent.
        assert!(data.join("agent").is_dir());
        assert!(!data.join("agent/auth.json").exists());
        assert!(!data.join("agent/models.json").exists());
        let notices = plan.notices.join("\n");
        assert!(
            notices.contains("Omitted host Pi credential file agent/auth.json"),
            "{notices}"
        );
        assert!(
            notices.contains("Omitted host Pi provider-configuration file agent/models.json"),
            "{notices}"
        );
    }

    #[test]
    fn fork_follow_links_does_not_materialize_a_protected_target() {
        use std::os::unix::fs::symlink;

        let (_home, home) = pi_home();
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("keep"), "keep").unwrap();
        symlink(home.join(".pi/agent/auth.json"), source.path().join("link")).unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!(
                "{}:/guest:fork:follow-links",
                source.path().display()
            )])
            .unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let data = fork_data(&plan);

        assert!(data.join("keep").is_file());
        // Not a symlink, and not the materialized target: nothing at all.
        assert!(!data.join("link").exists());
        assert!(
            plan.notices
                .join("\n")
                .contains("Omitted host Pi credential file link"),
            "{:?}",
            plan.notices
        );
    }

    #[test]
    fn fork_omits_a_hardlink_to_a_protected_file() {
        let (_home, home) = pi_home();
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("keep"), "keep").unwrap();
        fs::hard_link(
            home.join(".pi/agent/auth.json"),
            source.path().join("copy.json"),
        )
        .unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        let data = fork_data(&plan);

        assert!(data.join("keep").is_file());
        assert!(!data.join("copy.json").exists());
        assert!(
            plan.notices
                .join("\n")
                .contains("Omitted host Pi credential file copy.json"),
            "{:?}",
            plan.notices
        );
    }

    /// The identity signal alone fails this: the file does not exist when
    /// `measure` runs, so it has no measured inode. Only the fork-root-relative
    /// path signal catches it.
    #[test]
    fn fork_omits_a_protected_file_created_after_measurement() {
        let _checkpoint_guard = COPY_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let source = tempfile::tempdir().unwrap();
        let canonical = source.path().canonicalize().unwrap();
        fs::write(canonical.join("keep"), "keep").unwrap();
        // Arming on the *root* fires before the directory is enumerated, so
        // the new file is deterministically mid-copy rather than racing
        // readdir.
        let target = canonical.clone();
        set_copy_checkpoint(
            &canonical,
            Box::new(move |path| {
                if path == target {
                    fs::create_dir_all(target.join(".pi/agent")).unwrap();
                    fs::write(target.join(".pi/agent/auth.json"), "{\"token\":\"t\"}").unwrap();
                }
            }),
        );
        let store = tempfile::tempdir().unwrap();
        let result = prepare(
            parse_extra_mounts(&[format!("{}:/guest:fork", canonical.display())]).unwrap(),
            // No `~/.pi` at measure time: the fork root is this home.
            &context_with_home(store.path(), canonical.clone()),
        );
        clear_copy_checkpoint();
        let plan = result.unwrap();
        let data = fork_data(&plan);

        assert!(data.join("keep").is_file());
        assert!(!data.join(".pi/agent/auth.json").exists());
        assert!(
            plan.notices
                .join("\n")
                .contains("Omitted host Pi credential file .pi/agent/auth.json"),
            "{:?}",
            plan.notices
        );
        assert!(canonical.join(".pi/agent/auth.json").is_file());
    }

    #[test]
    fn protected_refusal_precedes_validate_plan_topology_errors() {
        let (_home, home) = pi_home();
        let file = tempfile::tempdir().unwrap();
        let plain = file.path().join("plain");
        fs::write(&plain, "plain").unwrap();

        // Both orders: a leaky plan that is *also* invalid still reports the
        // leak, because every pass before this one is read-only.
        for declarations in [
            vec![
                format!("{}:/leak:ro", home.join(".pi").display()),
                format!("{}:/leak/f:ro", plain.display()),
            ],
            vec![
                format!("{}:/leak/f:ro", plain.display()),
                format!("{}:/leak:ro", home.join(".pi").display()),
            ],
        ] {
            let store = tempfile::tempdir().unwrap();
            let error = prepare(
                parse_extra_mounts(&declarations).unwrap(),
                &context_with_home(store.path(), home.clone()),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("would expose"), "{error}");
            assert!(store_tree(store.path()).is_empty(), "{error}");
        }

        // The companion: an earlier-stage rejection still wins, pinning the
        // honest precedence (side-effect freedom, not "security message
        // first").
        let store = tempfile::tempdir().unwrap();
        let error = prepare(
            parse_extra_mounts(&[
                format!("{}:/fork:fork", plain.display()),
                format!("{}:/leak:ro", home.join(".pi").display()),
            ])
            .unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("a :fork source must be a directory"),
            "{error}"
        );
    }

    #[test]
    fn core_project_bind_that_is_home_is_refused() {
        let (_home, home) = pi_home();
        let store = tempfile::tempdir().unwrap();
        let mut ctx = context_with_home(store.path(), home.clone());
        ctx.core_host_sources = vec![CoreHostSource::new(CoreBind::ProjectDir, home.clone())];

        let error = prepare(Vec::new(), &ctx).unwrap_err().to_string();
        assert!(error.contains("project directory"), "{error}");
        assert!(
            error.contains(&home.join(".pi/agent/auth.json").display().to_string()),
            "{error}"
        );
        assert!(error.contains("instead of $HOME"), "{error}");
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }

    #[test]
    fn core_project_bind_inside_pi_home_is_refused() {
        let (_home, home) = pi_home();
        let store = tempfile::tempdir().unwrap();
        let mut ctx = context_with_home(store.path(), home.clone());
        ctx.core_host_sources = vec![CoreHostSource::new(CoreBind::ProjectDir, home.join(".pi"))];

        let error = prepare(Vec::new(), &ctx).unwrap_err().to_string();
        assert!(error.contains("project directory"), "{error}");
        assert!(
            error.contains(&format!("outside {}", home.join(".pi").display())),
            "{error}"
        );

        // An unrelated core source is untouched by the same check.
        ctx.core_host_sources = vec![CoreHostSource::new(
            CoreBind::ProjectDir,
            home.join("elsewhere"),
        )];
        fs::create_dir(home.join("elsewhere")).unwrap();
        assert!(prepare(Vec::new(), &ctx).is_ok());
    }

    /// A *below-`agent`* cwd inside the Pi home exposes no protected file, so
    /// it is allowed — but it is a writable live window onto host Pi state, so
    /// both advisories must fire with no `--mount` at all (issue #90's warning
    /// deliverable, which the core binds were missing).
    #[test]
    fn core_project_bind_inside_pi_home_below_agent_warns() {
        let (_home, home) = pi_home();
        fs::create_dir_all(home.join(".pi/extensions")).unwrap();
        fs::write(home.join(".pi/extensions/x.js"), "x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let mut ctx = context_with_home(store.path(), home.clone());
        ctx.core_host_sources = vec![CoreHostSource::new(
            CoreBind::ProjectDir,
            home.join(".pi/extensions"),
        )];

        let plan = prepare(Vec::new(), &ctx).unwrap();
        let notices = plan.notices.join("\n");
        assert!(
            notices.contains("is a live bind of host Pi state"),
            "{notices}"
        );
        assert!(
            notices.contains("may be built for this host's OS/arch"),
            "{notices}"
        );
        assert!(
            notices.contains("run agent-vm from a project directory outside"),
            "{notices}"
        );
    }

    #[test]
    fn pi_home_advisories_repeat_on_a_reused_fork() {
        let (_home, home) = pi_home();
        let store = tempfile::tempdir().unwrap();
        let declaration = format!("{}:/pi:fork", home.join(".pi").display());
        let declaration = parse_extra_mounts(&[declaration]).unwrap();

        let seeded = prepare(
            declaration.clone(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();
        assert!(seeded.notices.join("\n").contains("Initialized fork"));
        assert!(
            seeded
                .notices
                .join("\n")
                .contains("may not run in the Linux guest"),
            "{:?}",
            seeded.notices
        );

        // `preflight_forks` repoints the fork at its committed data, so a
        // notice keyed on `mount.host` would silently stop firing here.
        let reused = prepare(declaration, &context_with_home(store.path(), home.clone())).unwrap();
        assert!(reused.notices.join("\n").contains("Reusing fork"));
        assert!(
            reused
                .notices
                .join("\n")
                .contains("may not run in the Linux guest"),
            "{:?}",
            reused.notices
        );
    }

    #[test]
    fn pi_extensions_live_bind_warns_and_is_allowed() {
        let (_home, home) = pi_home();
        fs::create_dir_all(home.join(".pi/extensions")).unwrap();
        fs::write(home.join(".pi/extensions/x.js"), "x").unwrap();
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[format!("{}:ro", home.join(".pi/extensions").display())]).unwrap(),
            &context_with_home(store.path(), home.clone()),
        )
        .unwrap();

        let notices = plan.notices.join("\n");
        assert!(
            notices.contains("is a live bind of host Pi state"),
            "{notices}"
        );
        assert!(
            notices.contains("may be built for this host's OS/arch"),
            "{notices}"
        );
        assert!(!notices.contains("Omitted"), "{notices}");
    }

    #[test]
    fn non_pi_mounts_and_forks_are_unchanged() {
        let (_home, home) = pi_home();
        for (label, home_home) in [("pi home present", Some(home.clone())), ("no .pi", None)] {
            let home_home = home_home.unwrap_or_else(test_home);
            let source = tempfile::tempdir().unwrap();
            fs::write(source.path().join("seed"), "seed").unwrap();
            let store = tempfile::tempdir().unwrap();
            let plan = prepare(
                parse_extra_mounts(&[format!("{}:ro", source.path().display())]).unwrap(),
                &context_with_home(store.path(), home_home.clone()),
            )
            .unwrap();
            assert!(plan.notices.is_empty(), "{label}: {:?}", plan.notices);

            let store = tempfile::tempdir().unwrap();
            let fork = prepare(
                parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap(),
                &context_with_home(store.path(), home_home),
            )
            .unwrap();
            let notices = fork.notices.join("\n");
            assert!(!notices.contains("Omitted"), "{label}: {notices}");
            assert!(!notices.contains("host Pi state"), "{label}: {notices}");
        }
    }

    /// M13: the per-fork lock coordinates fork *initializers*, not host Pi
    /// writers. A host process renames the fork root away after the source kind
    /// is checked, and recreates it — credential and all — before the copy. The
    /// measured route set then has no entry for the root (its last existing
    /// ancestor was `$HOME`), so only the static path table can name the files.
    ///
    /// The omission is asserted as the outcome; the relative list is
    /// deliberately **not** asserted empty — that emptiness *is* the defect.
    #[test]
    fn fork_omission_survives_a_fork_root_recreated_after_measurement() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let source = home.join(".pi");
        fs::create_dir(&source).unwrap();
        let store = tempfile::tempdir().unwrap();
        // The lock `prepare_forks` holds while it measures; no host writer is
        // obliged to take it.
        let lock = open_regular_lock(&store.path().join("fork.lock")).unwrap();
        lock_exclusive(&lock).unwrap();
        let kind = fork_source_kind(&source).unwrap();
        require_fork_directory(kind, &source.display().to_string()).unwrap();
        // The host renames the root away after the kind check, before the
        // measurement a copier would take.
        fs::rename(&source, home.join("old-pi")).unwrap();
        let protected = ProtectedHostFiles::measure(Some(&home)).unwrap();
        // It recreates the tree, with both protected files, before the copy.
        fs::create_dir_all(source.join("agent")).unwrap();
        fs::write(source.join("agent/auth.json"), "synthetic-secret").unwrap();
        fs::write(source.join("agent/models.json"), "synthetic-models").unwrap();
        let protected_relative = protected.relatives_under(&source).unwrap();
        let policy = CopyPolicy {
            exclusions: &[],
            follow: false,
            protected_ids: protected.identities(),
            protected_relative: &protected_relative,
        };
        let data = store.path().join("data");
        let mut report = CopyReport::default();
        copy_root(&source, &data, &policy, &mut report).unwrap();
        assert!(data.join("agent").is_dir());
        assert!(
            !data.join("agent/auth.json").exists(),
            "a route set with no entry for the recreated root still copied the credential"
        );
        assert!(!data.join("agent/models.json").exists());
    }

    /// R1: an ordinary atomic credential replacement must not make the copier
    /// forget an inode the launch's first measurement positively identified.
    /// `backup-*.json` are hardlinks to the *old* credential bytes; the fresh
    /// measurement sees only the replacement, so omission has to union the
    /// preflight identities with the fresh ones rather than replace them.
    #[test]
    fn fork_omission_retains_a_preflight_credential_identity() {
        use std::os::unix::fs::MetadataExt;

        let (_home, home) = pi_home();
        let source = home.join("unrelated-fork");
        fs::create_dir(&source).unwrap();
        fs::hard_link(
            home.join(".pi/agent/auth.json"),
            source.join("backup-auth.json"),
        )
        .unwrap();
        fs::hard_link(
            home.join(".pi/agent/models.json"),
            source.join("backup-models.json"),
        )
        .unwrap();
        // The same measurement `prepare` takes before expanding/validating.
        let original = ProtectedHostFiles::measure(Some(&home)).unwrap();
        let backup = fs::metadata(source.join("backup-auth.json")).unwrap();
        assert!(
            original
                .identities()
                .matched(backup.dev(), backup.ino())
                .is_some(),
            "the preflight measurement must know the hardlink's inode"
        );

        // Ordinary atomic replacements of both protected files.
        for (path, body) in [
            (home.join(".pi/agent/auth.json"), "replacement-auth"),
            (home.join(".pi/agent/models.json"), "replacement-models"),
        ] {
            let replacement = path.with_extension("replacement");
            fs::write(&replacement, body).unwrap();
            fs::rename(&replacement, &path).unwrap();
        }

        let store = tempfile::tempdir().unwrap();
        let mut mounts = parse_extra_mounts(&[format!("{}:/fork:fork", source.display())]).unwrap();
        prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &original,
        )
        .unwrap();
        assert!(
            !mounts[0].host.join("backup-auth.json").exists(),
            "the fresh measurement discarded a known credential inode and copied it"
        );
        assert!(!mounts[0].host.join("backup-models.json").exists());
    }

    /// A fork root that did not exist at the top of `prepare` still gets the
    /// omission signals: the copier re-measures under the lock and loses no
    /// knowledge the earlier snapshot had, and the static path table names the
    /// protected files under the root even when no measurement saw it.
    #[test]
    fn fork_root_created_after_measure_is_still_omitted() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path().canonicalize().unwrap();
        let source = home.join(".pi");
        let store = tempfile::tempdir().unwrap();
        let mut mounts = parse_extra_mounts(&[format!("{}:/pi:fork", source.display())]).unwrap();

        // `prepare`'s measurement happens first, and `~/.pi` does not exist
        // yet, so its *physical* routes have no entry for the fork root. The
        // static path table still names both protected files under it (M13),
        // which is what makes the omission below independent of this snapshot.
        let stale = ProtectedHostFiles::measure(Some(&home)).unwrap();
        let stale_relatives = stale.relatives_under(&source).unwrap();
        assert!(
            stale_relatives.contains(&(PathBuf::from("agent/auth.json"), ProtectedFile::PiAuth)),
            "the static signal names the file under a root no measurement saw: {stale_relatives:?}"
        );
        assert!(
            stale_relatives
                .contains(&(PathBuf::from("agent/models.json"), ProtectedFile::PiModels)),
            "{stale_relatives:?}"
        );

        // …then `~/.pi` and its credential appear, before `prepare_forks`.
        fs::create_dir_all(source.join("agent")).unwrap();
        fs::write(source.join("agent/auth.json"), "{\"token\":\"t\"}").unwrap();
        fs::write(source.join("settings.json"), "{}").unwrap();

        prepare_forks(
            &mut mounts,
            store.path(),
            &std::collections::HashMap::new(),
            &stale,
        )
        .unwrap();
        let data = &mounts[0].host;

        assert!(data.join("settings.json").is_file());
        assert!(data.join("agent").is_dir());
        assert!(!data.join("agent/auth.json").exists());
    }

    #[test]
    fn identity_version_v3_reseeds_a_v2_fork_and_reports_the_orphan() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("seed"), "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let request =
            parse_extra_mounts(&[format!("{}:/guest:fork", source.path().display())]).unwrap();
        let legacy = store
            .path()
            .join("forks")
            .join(fork_id(&request[0], LEGACY_IDENTITY_VERSION_V2));
        fs::create_dir_all(legacy.join("data")).unwrap();
        fs::write(legacy.join("data/agent-auth.json"), "old credential copy").unwrap();

        let plan = prepare(request, &context(store.path())).unwrap();
        let data = fork_data(&plan);

        assert_ne!(data, legacy.join("data"), "a v2 fork must not be reused");
        assert_eq!(fs::read_to_string(data.join("seed")).unwrap(), "seed");
        assert!(
            legacy.join("data/agent-auth.json").is_file(),
            "the orphan is reported, never deleted"
        );
        let notices = plan.notices.join("\n");
        assert!(
            notices.contains("A fork from an earlier agent-vm build is no longer used"),
            "{notices}"
        );
        assert!(notices.contains(&legacy.display().to_string()), "{notices}");
    }

    #[test]
    fn no_home_refuses_a_declared_mount_but_not_an_empty_plan() {
        let source = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let ctx = context_without_home(store.path());
        assert!(prepare(Vec::new(), &ctx).is_ok());

        let error = prepare(
            parse_extra_mounts(&[format!("{}:ro", source.path().display())]).unwrap(),
            &ctx,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("neither $HOME nor the account record"),
            "{error}"
        );
        assert!(store_tree(store.path()).is_empty(), "{error}");
    }
}
