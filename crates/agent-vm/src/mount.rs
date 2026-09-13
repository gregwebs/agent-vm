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
    /// Normalized relative entries omitted from a fork or hidden in a bind.
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
    /// Every bind the walk discovers is read-only and retains the follow
    /// marker so mask planning knows projected exclusions may be resolved
    /// only through this safe alias. It is appended after discovery, so the
    /// marker cannot trigger another discovery pass.
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
        let parsed = parse_extra_mounts(&["/:/guest:fork:exclude=cache:exclude=cache/a".into()])
            .expect("fork syntax");
        assert!(parsed[0].is_fork());
        assert!(!parsed[0].is_readonly());
        assert_eq!(parsed[0].exclusions, vec![PathBuf::from("cache")]);
        assert!(parse_extra_mounts(&["/:fork:ro".into()]).is_err());
        assert!(parse_extra_mounts(&["/:fork:exclude=../escape".into()]).is_err());
    }

    #[test]
    fn fork_is_seeded_once_and_exclusions_are_not_copied() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("visible"), "one").unwrap();
        fs::write(source.path().join("secret"), "no").unwrap();
        let store = tempfile::tempdir().unwrap();
        let raw = format!("{}:/guest:fork:exclude=secret", source.path().display());
        let mut mounts = parse_extra_mounts(&[raw]).unwrap();
        prepare_forks(&mut mounts, store.path(), &std::collections::HashMap::new()).unwrap();
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
        prepare_forks(&mut again, store.path(), &std::collections::HashMap::new()).unwrap();
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
    /// A file mask before the complete plan is accepted. It is materialized
    /// into the shared readonly mask source only after collision validation.
    OpaqueFile,
    OpaqueDirectory,
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
    Mask,
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
    pub(crate) exclusions: Vec<PathBuf>,
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

    // Fork source access belongs exclusively to the locked transaction: a
    // concurrent waiter must be able to reuse READY after the source moves.
    // A fork whose root is still uninitialized can be a file, so reject the
    // one topology that would make a core mount pierce such a file before any
    // store/lock side effect. READY forks are validated without source I/O.
    let explicit_count = unique.len();
    let (mut expanded, warnings) =
        expand_follow_links(unique.clone(), context.host_home.as_deref())?;
    // Only topology candidates need a source-kind preflight. In particular,
    // exclusions alone must not touch the source before the per-fork lock:
    // another initializer may publish READY while this process waits.
    let known_fork_kinds = preflight_forks(
        &mut unique,
        &context.mount_store,
        &expanded,
        &context.core_guest_mounts,
    )?;
    sync_fork_representations(&unique, &mut expanded)?;

    let mut volumes = Vec::new();
    for (index, mount) in expanded.iter().enumerate() {
        let explicit = index < explicit_count;
        // An uninitialized fork deliberately has no source classification at
        // this point. `prepare_forks` performs that work after taking the
        // per-fork lock and rechecking READY. Its provisional directory kind
        // is replaced with the committed kind below before launch sees it.
        let kind = if mount.is_fork() {
            known_fork_kinds
                .get(&mount.guest)
                .copied()
                // An uninitialized fork with no topology-sensitive child can
                // remain provisional until its locked transaction resolves it.
                .unwrap_or(PreparedNodeKind::Directory)
        } else {
            let metadata = fs::symlink_metadata(&mount.host)
                .with_context(|| format!("validating --mount source {}", mount.host.display()))?;
            node_kind(&metadata, &mount.host)?
        };
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
        if !mount.is_fork() {
            add_masks(&mut volumes, mount)?;
        }
    }
    validate_plan(&mut volumes, &context.core_guest_mounts)?;

    // Only a validated complete set of core, explicit, followed, and mask
    // claims may publish any host-managed state.
    let mut notices = prepare_forks(&mut unique, &context.mount_store, &known_fork_kinds)?;
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
    // File-mask publication is deliberately last: every collision has been
    // checked, and the shared source is unnecessary for directory-only masks.
    for volume in &mut volumes {
        if volume.source == PreparedVolumeSource::OpaqueFile {
            volume.source = PreparedVolumeSource::ReadOnlyBind(mask_file(&context.mount_store)?);
        }
    }

    let repo_scan_roots = expanded
        .iter()
        .take(explicit_count)
        .enumerate()
        .map(|(index, mount)| {
            let explicit = &unique[index];
            RepoScanRoot {
                host: explicit.host.clone(),
                exclusions: if explicit.is_fork() {
                    Vec::new()
                } else {
                    mount.exclusions.clone()
                },
            }
        })
        .collect();
    Ok(PreparedMountPlan {
        volumes,
        repo_scan_roots,
        notices,
    })
}

/// Validate only committed forks without creating their store or inspecting
/// an uninitialized source. Source classification/copying happens under the
/// transaction lock in `prepare_forks`.
fn preflight_forks(
    mounts: &mut [ExtraMount],
    mount_store: &Path,
    expanded: &[ExtraMount],
    core: &[PathBuf],
) -> Result<std::collections::HashMap<PathBuf, PreparedNodeKind>> {
    let mut kinds = std::collections::HashMap::new();
    for mount in mounts.iter_mut().filter(|mount| mount.is_fork()) {
        let id = fork_id(mount);
        let final_dir = mount_store.join("forks").join(&id);
        let kind = if final_dir_exists(&final_dir)? {
            let kind = validate_ready(&final_dir, mount, &id)?;
            // `expanded` still contains the declaration spelling, so complete
            // plan validation obtains this committed kind from the preflight
            // map rather than restatting the source or using a provisional
            // directory kind. This must happen before any reuse notice or
            // other launch effect.
            kinds.insert(mount.guest.clone(), kind);
            mount.host = final_dir.join("data");
            kind
        } else {
            // A source kind affects validation only when another claim could
            // be below this fork, or an exclusion needs a directory root.
            // A vanished source is deliberately deferred: it may be a waiter
            // racing an initializer which will publish READY under the lock.
            let has_descendant = expanded
                .iter()
                .any(|claim| claim.guest != mount.guest && claim.guest.starts_with(&mount.guest))
                || core
                    .iter()
                    .any(|claim| claim != &mount.guest && claim.starts_with(&mount.guest));
            if !has_descendant && mount.exclusions.is_empty() {
                continue;
            }
            let Some(kind) = try_fork_source_kind(&mount.host)? else {
                continue;
            };
            if has_descendant {
                kinds.insert(mount.guest.clone(), kind);
            }
            kind
        };
        if !mount.exclusions.is_empty() && kind == PreparedNodeKind::File {
            anyhow::bail!(
                "--mount exclusions require a directory source: {}",
                mount.source_spelling
            );
        }
    }
    Ok(kinds)
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
/// `unique`; every later consumer (volumes, alias validation, and repository
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

fn add_masks(volumes: &mut Vec<PreparedVolume>, mount: &ExtraMount) -> Result<()> {
    if mount.exclusions.is_empty() {
        return Ok(());
    }
    if !fs::symlink_metadata(&mount.host)?.is_dir() {
        anyhow::bail!(
            "--mount exclusions require a directory source: {}",
            mount.host.display()
        );
    }
    for relative in &mount.exclusions {
        let kind = match resolve_live_exclusion(&mount.host, relative) {
            Ok(kind) => kind,
            Err(error) if mount.follows_links() && is_symlink_ancestor_error(&error) => {
                // This declaration's root bind still exposes the object at
                // its logical guest alias. Follow-link discovery adds masks
                // for canonical and literal target binds, but they do not
                // hide `/guest/alias/...` through the original root bind.
                // The final leaf remains no-follow; only the directory-link
                // ancestor is resolved, as it is for the guest alias.
                resolve_followed_alias_exclusion(&mount.host, relative)?
            }
            Err(error) => return Err(error),
        };
        let guest = mount.guest.join(relative);
        let source = match kind {
            PreparedNodeKind::Directory => PreparedVolumeSource::OpaqueDirectory,
            PreparedNodeKind::File => PreparedVolumeSource::OpaqueFile,
        };
        volumes.push(PreparedVolume {
            guest,
            source,
            node_kind: kind,
            role: VolumeRole::Mask,
        });
    }
    Ok(())
}

const SYMLINK_ANCESTOR_ERROR: &str = "excluded path has a symlink ancestor";

fn is_symlink_ancestor_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains(SYMLINK_ANCESTOR_ERROR))
}

/// Walk every ancestor without following it. The final path is opened only
/// after its parent descriptor is pinned; special leaves cannot be mounted.
fn resolve_live_exclusion(root: &Path, relative: &Path) -> Result<PreparedNodeKind> {
    use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};
    let mut dir = rfs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening mount root {}", root.display()))?;
    let parts: Vec<_> = relative.components().collect();
    for (index, component) in parts.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            anyhow::bail!("invalid exclusion {}", relative.display());
        };
        let stat = rfs::statat(&dir, *name, AtFlags::SYMLINK_NOFOLLOW).with_context(|| {
            format!("validating excluded path {}", root.join(relative).display())
        })?;
        let ty = FileType::from_raw_mode(stat.st_mode);
        if index + 1 == parts.len() {
            return match ty {
                FileType::RegularFile => Ok(PreparedNodeKind::File),
                FileType::Directory => Ok(PreparedNodeKind::Directory),
                _ => anyhow::bail!(
                    "excluded path {} must be a regular file or directory",
                    root.join(relative).display()
                ),
            };
        }
        if ty == FileType::Symlink {
            anyhow::bail!(
                "{SYMLINK_ANCESTOR_ERROR}: {}",
                root.join(relative).display()
            );
        }
        if ty != FileType::Directory {
            anyhow::bail!(
                "excluded path {} has a non-directory ancestor",
                root.join(relative).display()
            );
        }
        dir = rfs::openat(
            &dir,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
    }
    unreachable!("validated exclusion is nonempty")
}

/// Classify an exclusion reached through a directory symlink in a
/// `follow-links` root. The caller has already rejected a symlink leaf with
/// descriptor-relative resolution; this fallback is only for the logical
/// guest alias that necessarily resolves the discovered directory link.
fn resolve_followed_alias_exclusion(root: &Path, relative: &Path) -> Result<PreparedNodeKind> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("validating excluded path {}", path.display()))?;
    node_kind(&metadata, &path)
}

fn validate_plan(volumes: &mut Vec<PreparedVolume>, core: &[PathBuf]) -> Result<()> {
    // Exact duplicate generated masks are harmless. Anything else with the
    // same guest path is ambiguous and rejected before builder side effects.
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
    validate_physical_mask_aliases(&unique)?;

    for volume in &unique {
        for mask in unique
            .iter()
            .filter(|candidate| candidate.role == VolumeRole::Mask)
        {
            if volume.role != VolumeRole::Mask && volume.guest.starts_with(&mask.guest) {
                anyhow::bail!(
                    "mount at {} would pierce opaque mask {}",
                    volume.guest.display(),
                    mask.guest.display()
                );
            }
        }
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
        if core.iter().any(|path| path.starts_with(&volume.guest)) {
            if volume.role == VolumeRole::Mask {
                anyhow::bail!(
                    "core mount would pierce opaque mask {}",
                    volume.guest.display()
                );
            }
            if volume.node_kind == PreparedNodeKind::File
                && core
                    .iter()
                    .any(|path| path != &volume.guest && path.starts_with(&volume.guest))
            {
                anyhow::bail!("core mount is below file mount {}", volume.guest.display());
            }
        }
    }
    *volumes = unique;
    Ok(())
}

/// Reject an overlay that reaches an opaque mask through a symlink path in
/// an in-tree directory bind. Lexical guest paths are insufficient here:
/// `/guest/a/c/secret` and `/guest/deep/nested/secret` can name the same
/// object when `a -> b` and `b/c -> ../deep/nested`. Microsandbox applies the
/// later direct overlay after the mask, which would reveal the hidden object.
///
/// Project both guest paths through each directory bind that contains them,
/// then compare their resolved host locations. This is planning-only path
/// resolution: no mount-store, notice, builder, or source mutation occurs
/// before a collision is rejected. Repeating it for every directory anchor
/// also covers nested and transitive in-tree link chains.
fn validate_physical_mask_aliases(volumes: &[PreparedVolume]) -> Result<()> {
    validate_composed_mask_aliases(volumes)?;

    for mask in volumes
        .iter()
        .filter(|volume| volume.role == VolumeRole::Mask)
    {
        for anchor in volumes.iter().filter(|volume| {
            volume.role != VolumeRole::Mask && volume.node_kind == PreparedNodeKind::Directory
        }) {
            let Some(mask_path) = project_guest_path(anchor, &mask.guest) else {
                continue;
            };
            let mask_path = mask_path.with_context(|| {
                format!(
                    "resolving opaque mask {} through mount {}",
                    mask.guest.display(),
                    anchor.guest.display()
                )
            })?;

            for overlay in volumes
                .iter()
                .filter(|volume| volume.role != VolumeRole::Mask)
            {
                if overlay.guest == anchor.guest {
                    continue;
                }
                let Some(overlay_path) = project_guest_path(anchor, &overlay.guest) else {
                    continue;
                };
                let overlay_path = match overlay_path {
                    Ok(path) => path,
                    // The overlay mount itself can create this guest child.
                    // Until the child exists in the containing bind, it has
                    // no existing physical object that could alias a mask.
                    Err(error) if caused_by_not_found(&error) => continue,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "resolving mount {} through mount {}",
                                overlay.guest.display(),
                                anchor.guest.display()
                            )
                        });
                    }
                };
                let pierces_mask = match mask.node_kind {
                    PreparedNodeKind::File => overlay_path == mask_path,
                    PreparedNodeKind::Directory => overlay_path.starts_with(&mask_path),
                };
                if pierces_mask {
                    anyhow::bail!(
                        "mount at {} would pierce opaque mask {} through in-tree symlink aliases",
                        overlay.guest.display(),
                        mask.guest.display()
                    );
                }
            }
        }
    }
    Ok(())
}

/// Resolve each non-mask claim through the complete prepared graph, excluding
/// that claim itself. A mount can supply a child that was absent in an
/// enclosing bind, and a symlink in that child can then lead back to an
/// opaque mask. Resolving only the enclosing host root misses this composed
/// route and lets a later overlay replace the mask.
fn validate_composed_mask_aliases(volumes: &[PreparedVolume]) -> Result<()> {
    for mask in volumes
        .iter()
        .filter(|volume| volume.role == VolumeRole::Mask)
    {
        for claim in volumes
            .iter()
            .filter(|volume| volume.role != VolumeRole::Mask)
        {
            let resolved = match resolve_guest_path_through_plan(volumes, &claim.guest, claim) {
                Ok(path) => path,
                // A mount may create a child absent from every containing
                // lower bind. With no object to resolve, it cannot alias a
                // mask at preparation time.
                Err(error) if caused_by_not_found(&error) => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "resolving mount {} through the prepared mount graph",
                            claim.guest.display()
                        )
                    });
                }
            };
            let pierces_mask = match mask.node_kind {
                PreparedNodeKind::File => resolved == mask.guest,
                PreparedNodeKind::Directory => resolved.starts_with(&mask.guest),
            };
            if pierces_mask {
                anyhow::bail!(
                    "mount at {} would pierce opaque mask {} through composed mount aliases",
                    claim.guest.display(),
                    mask.guest.display()
                );
            }
        }
    }
    Ok(())
}

/// Resolve a guest pathname with the same mount selection and symlink
/// substitution order the guest uses. `ignored` is the prospective overlay:
/// it must not hide the lower alias route we are validating.
fn resolve_guest_path_through_plan(
    volumes: &[PreparedVolume],
    guest: &Path,
    ignored: &PreparedVolume,
) -> Result<PathBuf> {
    use std::collections::VecDeque;

    let mut pending = guest
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => Some(component.to_os_string()),
            _ => None,
        })
        .collect::<VecDeque<_>>();
    let mut resolved = PathBuf::from("/");
    let mut link_depth = 0;

    while let Some(component) = pending.pop_front() {
        let candidate = resolved.join(&component);
        let Some(anchor) = volumes
            .iter()
            .filter(|volume| {
                !std::ptr::eq(*volume, ignored)
                    && volume.role != VolumeRole::Mask
                    && volume.node_kind == PreparedNodeKind::Directory
                    && candidate.starts_with(&volume.guest)
            })
            .max_by_key(|volume| volume.guest.components().count())
        else {
            resolved = candidate;
            continue;
        };
        let (PreparedVolumeSource::WritableBind(host) | PreparedVolumeSource::ReadOnlyBind(host)) =
            &anchor.source
        else {
            resolved = candidate;
            continue;
        };
        let host_path = host.join(candidate.strip_prefix(&anchor.guest).unwrap());
        let metadata = fs::symlink_metadata(&host_path)?;
        if !metadata.file_type().is_symlink() {
            resolved = candidate;
            continue;
        }
        link_depth += 1;
        if link_depth > MAX_LINK_DEPTH {
            anyhow::bail!(
                "resolving mount {} exceeded maximum symlink depth",
                guest.display()
            );
        }
        let target = fs::read_link(&host_path)?;
        let replacement = if target.is_absolute() {
            target
        } else {
            candidate.parent().unwrap_or(Path::new("/")).join(target)
        };
        let replacement = normalize_guest_link_target(&replacement)?;
        pending = replacement
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(component) => Some(component.to_os_string()),
                _ => None,
            })
            .chain(pending)
            .collect();
        resolved = PathBuf::from("/");
    }
    Ok(resolved)
}

fn normalize_guest_link_target(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    anyhow::bail!("symlink target {} escapes the guest root", path.display());
                }
            }
            std::path::Component::Prefix(_) => {
                anyhow::bail!("symlink target {} is not a Unix guest path", path.display())
            }
        }
    }
    Ok(normalized)
}

/// Resolve `guest` as the guest kernel does below one directory bind.
/// `None` means the guest path is outside that bind. Callers retain a missing
/// projected child as a distinct case because a later overlay creates it.
fn caused_by_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

fn project_guest_path(anchor: &PreparedVolume, guest: &Path) -> Option<Result<PathBuf>> {
    let relative = guest.strip_prefix(&anchor.guest).ok()?;
    let (PreparedVolumeSource::WritableBind(host) | PreparedVolumeSource::ReadOnlyBind(host)) =
        &anchor.source
    else {
        return None;
    };
    Some(host.join(relative).canonicalize().map_err(Into::into))
}

fn same_volume(a: &PreparedVolume, b: &PreparedVolume) -> bool {
    a.guest == b.guest && a.source == b.source && a.node_kind == b.node_kind && a.role == b.role
}

const MANIFEST_VERSION: u32 = 2;
const IDENTITY_VERSION: &[u8] = b"agent-vm-fork-identity-v2";
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
pub(crate) fn prepare_forks(
    mounts: &mut [ExtraMount],
    mount_store: &Path,
    expected_kinds: &std::collections::HashMap<PathBuf, PreparedNodeKind>,
) -> Result<Vec<String>> {
    let mut notices = Vec::new();
    for mount in mounts.iter_mut().filter(|mount| mount.is_fork()) {
        let id = fork_id(mount);
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
        if let Some(expected) = expected_kinds.get(&mount.guest)
            && *expected != source_kind
        {
            anyhow::bail!(
                "fork root kind changed while preparing {}; retry the launch",
                mount.source_spelling
            );
        }
        if !mount.exclusions.is_empty() && source_kind == PreparedNodeKind::File {
            anyhow::bail!(
                "--mount exclusions require a directory source: {}",
                mount.source_spelling
            );
        }
        let staging_parent = mount_store.join("staging");
        let stage = tempfile::Builder::new()
            .prefix(&format!("{id}.stage-"))
            .tempdir_in(&staging_parent)
            .context("creating fork staging directory")?;
        let staged_data = stage.path().join("data");
        let kind = copy_root(
            &mount.host,
            &staged_data,
            &mount.exclusions,
            mount.follows_links(),
        )
        .with_context(|| format!("initializing fork from {}", mount.source_spelling))?;
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

fn fork_id(mount: &ExtraMount) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(IDENTITY_VERSION);
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
    match (manifest.kind.as_str(), data.is_file(), data.is_dir()) {
        ("file", true, false) => Ok(PreparedNodeKind::File),
        ("directory", false, true) => Ok(PreparedNodeKind::Directory),
        _ => anyhow::bail!("{}", reset()),
    }
}

const MASK_STAGE_PREFIX: &str = ".mask-file.stage-";

/// Remove only orphaned files created by this publisher. The staging
/// directory also holds fork transactions, so prefix lookalikes and every
/// unrelated name stay untouched. Both lookup and unlink are relative to a
/// pinned no-follow descriptor: a staged symlink is rejected rather than
/// traversed or removed.
fn clean_stale_mask_staging(staging: &Path) -> Result<()> {
    use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags};

    let staging_dir = rfs::open(
        staging,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening mask staging directory {}", staging.display()))?;
    for entry in rfs::Dir::read_from(&staging_dir)? {
        let entry = entry?;
        let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
        let Some(suffix) = name.as_bytes().strip_prefix(MASK_STAGE_PREFIX.as_bytes()) else {
            continue;
        };
        // `tempfile` appends a six-character ASCII alphanumeric suffix. A
        // reserved-prefix entry outside that grammar may not be ours.
        if suffix.len() < 6 || !suffix.iter().all(u8::is_ascii_alphanumeric) {
            anyhow::bail!(
                "unsafe stale mask staging entry {}/{}",
                staging.display(),
                name.to_string_lossy()
            );
        }
        let stat = rfs::statat(&staging_dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let mode = stat.st_mode as u32 & 0o7777;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_size != 0
            // A publisher can die before or after fchmod. No other mode is
            // produced by our exclusive tempfile publication protocol.
            || !matches!(mode, 0o600 | 0o444)
        {
            anyhow::bail!(
                "unsafe stale mask staging entry {}/{}",
                staging.display(),
                name.to_string_lossy()
            );
        }
        rfs::unlinkat(&staging_dir, name, AtFlags::empty()).with_context(|| {
            format!(
                "removing stale mask staging entry {}/{}",
                staging.display(),
                name.to_string_lossy()
            )
        })?;
    }
    Ok(())
}

/// Create the shared readonly mask exactly once. Existing entries are never
/// repaired: corruption is a stop, not an opportunity to truncate a file a
/// prior VM may still have mounted.
fn mask_file(store: &Path) -> Result<PathBuf> {
    ensure_store(store)?;
    let final_path = store.join(".mask-file");
    let lock = open_regular_lock(&store.join("locks/.mask-file.lock"))?;
    lock_exclusive(&lock)?;
    clean_stale_mask_staging(&store.join("staging"))?;
    match fs::symlink_metadata(&final_path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() != 0
                    || metadata.permissions().mode() & 0o7777 != 0o444
                {
                    anyhow::bail!(
                        "corrupt mask file {}; remove the mount store to reset",
                        final_path.display()
                    );
                }
            }
            return Ok(final_path);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let staged = tempfile::Builder::new()
        .prefix(MASK_STAGE_PREFIX)
        .tempfile_in(store.join("staging"))?;
    staged
        .as_file()
        .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o444))?;
    std::fs::hard_link(staged.path(), &final_path)
        .with_context(|| format!("publishing {}", final_path.display()))?;
    Ok(final_path)
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
/// Copy a root via verified descriptors.  Nested links are never followed in
/// the default policy, so a swap cannot turn an untrusted leaf into a read of
/// an external target. Explicit follow mode is deliberately opt-in.
fn copy_root(
    source: &Path,
    destination: &Path,
    exclusions: &[PathBuf],
    follow: bool,
) -> Result<PreparedNodeKind> {
    use rustix::fs::{self as rfs, Mode, OFlags};
    let source = source
        .canonicalize()
        .with_context(|| format!("resolving fork root {}", source.display()))?;
    #[cfg(test)]
    let _checkpoint_scope = CopyCheckpointScope::enter(&source);
    copy_checkpoint(&source);
    let fd = rfs::open(
        &source,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    copy_opened(
        &fd,
        destination,
        Path::new(""),
        exclusions,
        follow,
        0,
        &mut Vec::new(),
    )
}
fn copy_opened(
    fd: &rustix::fd::OwnedFd,
    destination: &Path,
    relative: &Path,
    exclusions: &[PathBuf],
    follow: bool,
    depth: usize,
    active: &mut Vec<(u64, u64)>,
) -> Result<PreparedNodeKind> {
    use rustix::fs::{self as rfs, FileType, Mode, OFlags};
    use std::os::unix::fs::PermissionsExt;
    if is_excluded(relative, exclusions) {
        return Ok(PreparedNodeKind::Directory);
    }
    let stat = rfs::fstat(fd)?;
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
        return Ok(PreparedNodeKind::File);
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
        if is_excluded(&child_relative, exclusions) {
            continue;
        }
        let child_stat = rfs::statat(fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let child_ty = FileType::from_raw_mode(child_stat.st_mode);
        let child_dst = destination.join(name);
        copy_checkpoint(&child_relative);
        if child_ty == FileType::Symlink {
            if !follow {
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
                // inside the directory that contained their raw text.
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
                    exclusions,
                    follow,
                    depth + 1,
                    active,
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
                exclusions,
                follow,
                depth,
                active,
            )?;
        }
    }
    fs::set_permissions(
        destination,
        std::fs::Permissions::from_mode(stat.st_mode as u32 & 0o7777),
    )?;
    active.pop();
    Ok(PreparedNodeKind::Directory)
}

#[cfg(test)]
mod prepare_tests {
    use super::*;

    fn context(store: &Path) -> MountContext {
        MountContext {
            mount_store: store.to_path_buf(),
            host_home: None,
            core_guest_mounts: Vec::new(),
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
    fn mask_collision_is_rejected_before_fork_store_creation() {
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
            "an exact explicit/core collision must not create fork or mask state"
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
            };

            let error =
                prepare(parse_extra_mounts(&declarations).unwrap(), &mount_context).unwrap_err();
            assert!(error.to_string().contains("core mount"), "{error:#}");
            assert!(
                fs::read_dir(store.path()).unwrap().next().is_none(),
                "an exact followed/core collision must not create fork or mask state (fork_first={fork_first})"
            );
        }
    }

    #[test]
    fn validation_failure_has_no_fork_or_mask_side_effects_in_either_order() {
        let fork_source = tempfile::tempdir().unwrap();
        fs::write(fork_source.path().join("seed"), "seed").unwrap();
        let live_source = tempfile::tempdir().unwrap();
        fs::write(live_source.path().join("hidden"), "hidden").unwrap();

        for declarations in [
            vec![
                format!("{}:/fork:fork", fork_source.path().display()),
                format!("{}:/live:ro:exclude=hidden", live_source.path().display()),
            ],
            vec![
                format!("{}:/live:ro:exclude=hidden", live_source.path().display()),
                format!("{}:/fork:fork", fork_source.path().display()),
            ],
        ] {
            let store = tempfile::tempdir().unwrap();
            let mut context = context(store.path());
            // This core claim would be mounted below the generated opaque
            // mask, so complete-plan validation must reject it before fork
            // state or the shared file mask can be published.
            context
                .core_guest_mounts
                .push(PathBuf::from("/live/hidden"));
            assert!(prepare(parse_extra_mounts(&declarations).unwrap(), &context).is_err());
            assert!(
                fs::read_dir(store.path()).unwrap().next().is_none(),
                "failed preparation must leave the mount store untouched"
            );
        }
    }

    #[test]
    fn fork_file_exclusions_fail_before_store_creation_and_do_not_poison_retry() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-file");
        fs::write(&source, "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let excluded = format!("{}:/guest:fork:exclude=hidden", source.display());
        let error = prepare(
            parse_extra_mounts(&[excluded]).unwrap(),
            &context(store.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("directory source"), "{error}");
        assert!(fs::read_dir(store.path()).unwrap().next().is_none());

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
    fn composed_mount_alias_overlay_cannot_pierce_opaque_mask_in_any_order() {
        use std::os::unix::fs::symlink;

        for directory in [false, true] {
            for order in [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ] {
                // The root's `z-alias` initially points into a child that
                // does not exist there. A second mount supplies that child,
                // whose link then resolves back to the root's masked leaf.
                let root = tempfile::tempdir().unwrap();
                let source = root.path().join("root");
                fs::create_dir(&source).unwrap();
                let hidden = source.join("m-hidden");
                if directory {
                    fs::create_dir(&hidden).unwrap();
                } else {
                    fs::write(&hidden, "hidden").unwrap();
                }
                symlink("a-new/secret", source.join("z-alias")).unwrap();

                let supplied_child = root.path().join("supplied-a-new");
                fs::create_dir(&supplied_child).unwrap();
                symlink("../m-hidden", supplied_child.join("secret")).unwrap();

                let declarations = [
                    format!("{}:/guest:rw:exclude=m-hidden", source.display()),
                    format!("{}:/guest/a-new:rw", supplied_child.display()),
                    format!("{}:/guest/z-alias:rw", hidden.display()),
                ];
                let declarations = order
                    .iter()
                    .map(|&index| declarations[index].clone())
                    .collect::<Vec<_>>();
                let store = tempfile::tempdir().unwrap();
                let error = prepare(
                    parse_extra_mounts(&declarations).unwrap(),
                    &context(store.path()),
                )
                .expect_err("a composed mount alias must not pierce an opaque mask")
                .to_string();
                assert!(error.contains("pierce opaque mask"), "{error}");
                assert!(
                    fs::read_dir(store.path()).unwrap().next().is_none(),
                    "rejection must precede mask publication (directory={directory}, order={order:?})"
                );
            }
        }
    }

    #[test]
    fn absent_projected_child_cannot_alias_mask_in_either_declaration_order() {
        for directory in [false, true] {
            for root_first in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let source = root.path().join("source");
                fs::create_dir(&source).unwrap();
                fs::write(source.join("hidden"), "hidden").unwrap();

                let overlay_source = root.path().join("overlay");
                if directory {
                    fs::create_dir(&overlay_source).unwrap();
                } else {
                    fs::write(&overlay_source, "overlay").unwrap();
                }

                let masked_root = format!("{}:/guest:rw:exclude=hidden", source.display());
                let overlay = format!("{}:/guest/new:rw", overlay_source.display());
                let declarations = if root_first {
                    vec![masked_root, overlay]
                } else {
                    vec![overlay, masked_root]
                };
                let store = tempfile::tempdir().unwrap();
                let plan = prepare(
                    parse_extra_mounts(&declarations).unwrap(),
                    &context(store.path()),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "an absent projected child cannot alias an existing mask (directory={directory}, root_first={root_first}): {error:#}"
                    )
                });
                assert!(
                    plan.volumes
                        .iter()
                        .any(|volume| volume.guest == Path::new("/guest/new"))
                );
            }
        }
    }

    #[test]
    fn in_tree_symlink_alias_overlay_cannot_pierce_opaque_mask_in_either_order() {
        use std::os::unix::fs::symlink;

        for directory in [false, true] {
            for root_first in [false, true] {
                // `/guest/a/c/secret` resolves through `a -> b` and
                // `b/c -> ../deep/nested` to `/guest/deep/nested/secret`.
                let home = tempfile::tempdir().unwrap();
                let source = home.path().join("source");
                let deep = source.join("deep/nested");
                fs::create_dir_all(&deep).unwrap();
                let secret = deep.join("secret");
                if directory {
                    fs::create_dir(&secret).unwrap();
                } else {
                    fs::write(&secret, "secret").unwrap();
                }
                fs::create_dir(source.join("b")).unwrap();
                symlink("b", source.join("a")).unwrap();
                symlink("../deep/nested", source.join("b/c")).unwrap();

                let root = format!(
                    "{}:/guest:ro:follow-links:exclude=a/c/secret",
                    source.display()
                );
                let overlay = format!("{}:/guest/deep/nested/secret:ro", secret.display());
                let declarations = if root_first {
                    vec![root, overlay]
                } else {
                    vec![overlay, root]
                };
                let store = tempfile::tempdir().unwrap();
                let error = prepare(
                    parse_extra_mounts(&declarations).unwrap(),
                    &MountContext {
                        mount_store: store.path().to_path_buf(),
                        host_home: Some(home.path().to_path_buf()),
                        core_guest_mounts: Vec::new(),
                    },
                )
                .expect_err("a physical alias overlay must not pierce an opaque mask")
                .to_string();
                assert!(error.contains("pierce opaque mask"), "{error}");
                assert!(
                    fs::read_dir(store.path()).unwrap().next().is_none(),
                    "rejection must not publish a mask (directory={directory}, root_first={root_first})"
                );
            }
        }
    }

    #[test]
    fn followed_aliases_receive_projected_file_and_directory_masks() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let first_target = source.join("target");
        let second_target = source.join("nested-target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&first_target).unwrap();
        fs::create_dir(&second_target).unwrap();
        fs::write(first_target.join("secret-file"), "secret").unwrap();
        fs::create_dir(first_target.join("secret-directory")).unwrap();
        fs::write(second_target.join("nested-secret"), "secret").unwrap();
        symlink("target", source.join("alias")).unwrap();
        symlink("../nested-target", first_target.join("nested-alias")).unwrap();

        let request = format!(
            "{}:/guest:ro:follow-links:exclude=alias/secret-file:exclude=alias/secret-directory:exclude=alias/nested-alias/nested-secret",
            source.display()
        );
        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[request]).unwrap(),
            &MountContext {
                mount_store: store.path().to_path_buf(),
                host_home: Some(home.path().to_path_buf()),
                core_guest_mounts: Vec::new(),
            },
        )
        .unwrap();
        let masks = plan
            .volumes
            .iter()
            .filter(|volume| volume.role == VolumeRole::Mask)
            .map(|volume| volume.guest.clone())
            .collect::<Vec<_>>();
        let first_target = first_target.canonicalize().unwrap();
        let second_target = second_target.canonicalize().unwrap();
        assert!(masks.contains(&first_target.join("secret-file")));
        assert!(masks.contains(&first_target.join("secret-directory")));
        assert!(masks.contains(&second_target.join("nested-secret")));
        // The root bind still exposes the target through its in-tree link,
        // so masking only the followed canonical/literal aliases would let
        // `/guest/alias/secret-file` pierce the exclusion.
        assert!(masks.contains(&PathBuf::from("/guest/alias/secret-file")));
        assert!(masks.contains(&PathBuf::from("/guest/alias/secret-directory")));
        assert!(masks.contains(&PathBuf::from("/guest/alias/nested-alias/nested-secret")));
    }

    #[test]
    fn exclusions_survive_deduplicated_canonical_and_literal_followed_aliases() {
        use std::os::unix::fs::symlink;

        // Make one followed target reachable through both its canonical and
        // literal guest paths, then declare those paths explicitly too. The
        // explicit declarations used to win expand_follow_links' dedup and
        // discard the exclusion projected from `implement`.
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path().canonicalize().unwrap();
        let source = home_path.join("source");
        let conf = home_path.join("conf");
        let target = conf.join("skills").join("implement");
        let literal = conf.join(".agents").join("skills").join("implement");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(conf.join(".agents")).unwrap();
        fs::write(target.join("secret"), "secret").unwrap();
        symlink("../skills", conf.join(".agents").join("skills")).unwrap();
        symlink(&literal, source.join("implement")).unwrap();

        let store = tempfile::tempdir().unwrap();
        let plan = prepare(
            parse_extra_mounts(&[
                format!(
                    "{}:ro:follow-links:exclude=implement/secret",
                    source.display()
                ),
                format!("{}:{}:ro", target.display(), target.display()),
                format!("{}:{}:ro", target.display(), literal.display()),
            ])
            .unwrap(),
            &MountContext {
                mount_store: store.path().to_path_buf(),
                host_home: Some(home_path.clone()),
                core_guest_mounts: Vec::new(),
            },
        )
        .unwrap();
        let masks = plan
            .volumes
            .iter()
            .filter(|volume| volume.role == VolumeRole::Mask)
            .map(|volume| volume.guest.clone())
            .collect::<Vec<_>>();
        assert!(masks.contains(&target.join("secret")), "{masks:?}");
        assert!(masks.contains(&literal.join("secret")), "{masks:?}");
    }

    #[test]
    fn corrupt_mask_is_never_repaired() {
        let store = tempfile::tempdir().unwrap();
        ensure_store(store.path()).unwrap();
        fs::write(store.path().join(".mask-file"), "not empty").unwrap();
        assert!(mask_file(store.path()).is_err());
        assert_eq!(
            fs::read_to_string(store.path().join(".mask-file")).unwrap(),
            "not empty"
        );
    }

    #[test]
    fn first_use_fork_kind_validates_core_explicit_and_followed_descendants() {
        use std::os::unix::fs::symlink;

        for directory in [false, true] {
            for fork_first in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let source = root.path().join("source");
                if directory {
                    fs::create_dir(&source).unwrap();
                } else {
                    fs::write(&source, "seed").unwrap();
                }
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
                        },
                    );
                    if directory {
                        assert!(
                            result.is_ok(),
                            "directory fork must allow child: {result:?}"
                        );
                    } else {
                        assert!(result.is_err(), "file fork must reject child topology");
                        assert!(fs::read_dir(store.path()).unwrap().next().is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn ready_file_fork_rejects_descendants_during_side_effect_free_complete_plan_validation() {
        use std::os::unix::fs::symlink;

        for fork_first in [false, true] {
            // First launch seeds a file fork. The second launch reuses it
            // after the declaration source is gone and adds an explicit child.
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source-file");
            fs::write(&source, "seed").unwrap();
            let store = tempfile::tempdir().unwrap();
            let guest = PathBuf::from("/guest/file");
            let fork = format!("{}:{}:fork", source.display(), guest.display());
            prepare(
                parse_extra_mounts(std::slice::from_ref(&fork)).unwrap(),
                &context(store.path()),
            )
            .expect("first launch seeds the file fork");
            fs::remove_file(&source).unwrap();

            let child = root.path().join("child");
            fs::create_dir(&child).unwrap();
            let explicit = format!("{}:{}/child:ro", child.display(), guest.display());
            let declarations = if fork_first {
                vec![fork.clone(), explicit]
            } else {
                vec![explicit, fork.clone()]
            };
            let before = store_tree(store.path());
            let error = prepare(
                parse_extra_mounts(&declarations).unwrap(),
                &context(store.path()),
            )
            .expect_err("an explicit child cannot be mounted below a READY file fork");
            assert!(error.to_string().contains("below file mount"), "{error:#}");
            assert_eq!(
                store_tree(store.path()),
                before,
                "rejected plan must not mutate READY state"
            );

            // A followed target is also a complete-plan claim. Its canonical
            // guest path is under this READY file fork's guest path.
            let followed_source = root.path().join("followed-source-file");
            fs::write(&followed_source, "seed").unwrap();
            let followed_guest = root.path().canonicalize().unwrap();
            let followed_fork = format!(
                "{}:{}:fork",
                followed_source.display(),
                followed_guest.display()
            );
            prepare(
                parse_extra_mounts(std::slice::from_ref(&followed_fork)).unwrap(),
                &context(store.path()),
            )
            .expect("first launch seeds the followed file fork");
            fs::remove_file(&followed_source).unwrap();
            let live = root.path().join("live");
            let followed_child = root.path().join("followed-child");
            fs::create_dir(&live).unwrap();
            fs::create_dir(&followed_child).unwrap();
            symlink(&followed_child, live.join("child")).unwrap();
            let followed = format!("{}:ro:follow-links", live.display());
            let declarations = if fork_first {
                vec![followed_fork.clone(), followed]
            } else {
                vec![followed, followed_fork.clone()]
            };
            let before = store_tree(store.path());
            let error = prepare(
                parse_extra_mounts(&declarations).unwrap(),
                &MountContext {
                    mount_store: store.path().to_path_buf(),
                    host_home: Some(root.path().to_path_buf()),
                    core_guest_mounts: Vec::new(),
                },
            )
            .expect_err("a followed child cannot be mounted below a READY file fork");
            assert!(error.to_string().contains("below file mount"), "{error:#}");
            assert_eq!(
                store_tree(store.path()),
                before,
                "rejected plan must not mutate READY state"
            );

            // Core claims are validated in the same side-effect-free pass.
            let before = store_tree(store.path());
            let error = prepare(
                parse_extra_mounts(&[fork]).unwrap(),
                &MountContext {
                    mount_store: store.path().to_path_buf(),
                    host_home: Some(root.path().to_path_buf()),
                    core_guest_mounts: vec![guest.join("core-child")],
                },
            )
            .expect_err("a core child cannot be mounted below a READY file fork");
            assert!(error.to_string().contains("below file mount"), "{error:#}");
            assert_eq!(
                store_tree(store.path()),
                before,
                "rejected plan must not mutate READY state"
            );
        }
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
    fn file_fork_below_core_is_rejected_before_store_or_launch_work() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source-file");
        fs::write(&source, "seed").unwrap();
        let store = tempfile::tempdir().unwrap();
        let mut mount_context = context(store.path());
        mount_context
            .core_guest_mounts
            .push(PathBuf::from("/tmp/project"));

        let error = prepare(
            parse_extra_mounts(&[format!("{}:/tmp:fork", source.display())]).unwrap(),
            &mount_context,
        )
        .expect_err("a core directory below a file fork cannot be mounted");
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

        for victim in ["root", "file", "directory", "link"] {
            let swapped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            let external = root.path().join("external");
            fs::create_dir(&source).unwrap();
            fs::write(&external, "outside").unwrap();
            match victim {
                "root" => {
                    fs::remove_dir(&source).unwrap();
                    fs::write(&source, "inside").unwrap();
                }
                "file" => fs::write(source.join("file"), "inside").unwrap(),
                "directory" => {
                    fs::create_dir(source.join("directory")).unwrap();
                    fs::write(source.join("directory/item"), "inside").unwrap();
                }
                "link" => symlink(&external, source.join("link")).unwrap(),
                _ => unreachable!(),
            }
            let swap = if victim == "root" {
                source.clone()
            } else {
                source.join(victim)
            };
            let root_source = source.clone();
            let checkpoint = PathBuf::from(victim);
            let external = external.clone();
            let swapping_link = victim == "link";
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
                            fs::hard_link(&external, &swap).unwrap();
                        } else {
                            symlink(&external, &swap).unwrap();
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
                "swap at {victim} was accepted"
            );
            clear_copy_checkpoint();
            assert!(
                swapped.load(std::sync::atomic::Ordering::SeqCst),
                "checkpoint at {victim} did not run"
            );
            assert!(
                fs::read_dir(store.path().join("forks"))
                    .unwrap()
                    .next()
                    .is_none()
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
        let id = fork_id(&request[0]);
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
    fn mask_file_rejects_every_special_permission_bit() {
        use std::os::unix::fs::PermissionsExt;

        for special_bits in 1..=0o7 {
            let store = tempfile::tempdir().unwrap();
            ensure_store(store.path()).unwrap();
            let final_path = store.path().join(".mask-file");
            fs::write(&final_path, "").unwrap();
            let mode = 0o444 | (special_bits << 9);
            fs::set_permissions(&final_path, fs::Permissions::from_mode(mode)).unwrap();

            let error = mask_file(store.path())
                .expect_err("special permission bits make a mask file corrupt")
                .to_string();
            assert!(error.contains("corrupt mask file"), "{error}");
            assert_eq!(
                fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777,
                mode,
                "corrupt mask state must never be repaired"
            );
        }
    }

    #[test]
    fn mask_file_cleans_interrupted_stages_before_reuse_and_publication() {
        use std::os::unix::fs::PermissionsExt;

        let store = tempfile::tempdir().unwrap();
        ensure_store(store.path()).unwrap();
        let staging = store.path().join("staging");
        let stale = staging.join(".mask-file.stage-crashed1");
        fs::write(&stale, "").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
        let unrelated = staging.join("unrelated-fork-stage");
        fs::write(&unrelated, "leave me alone").unwrap();

        let published = mask_file(store.path()).unwrap();
        assert_eq!(published, store.path().join(".mask-file"));
        assert!(!stale.exists(), "a process-left mask stage must be retried");
        assert!(unrelated.exists(), "unrelated staging must be preserved");

        let stale_after_ready = staging.join(".mask-file.stage-crashed2");
        fs::write(&stale_after_ready, "").unwrap();
        fs::set_permissions(&stale_after_ready, fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(mask_file(store.path()).unwrap(), published);
        assert!(
            !stale_after_ready.exists(),
            "READY reuse must also clean an interrupted publisher's stage"
        );
    }

    #[test]
    fn mask_file_retries_a_stage_left_by_an_interrupted_process() {
        if let Some(store) = std::env::var_os("AGENT_VM_INTERRUPTED_MASK_STORE") {
            let staging = PathBuf::from(store).join("staging");
            let stage = staging.join(".mask-file.stage-interrupted1");
            fs::write(&stage, "").unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(stage, fs::Permissions::from_mode(0o600)).unwrap();
            // Simulate a publisher dying after exclusive creation but before
            // fchmod/link. The parent must reclaim this exact on-disk state.
            std::process::exit(91);
        }

        let store = tempfile::tempdir().unwrap();
        ensure_store(store.path()).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mount::prepare_tests::mask_file_retries_a_stage_left_by_an_interrupted_process",
                "--nocapture",
            ])
            .env("AGENT_VM_INTERRUPTED_MASK_STORE", store.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(91));

        let published = mask_file(store.path()).unwrap();
        assert!(published.is_file());
        assert!(
            fs::read_dir(store.path().join("staging"))
                .unwrap()
                .next()
                .is_none(),
            "the next publisher must remove only its recognized stale stage"
        );
    }

    #[test]
    fn mask_file_rejects_unsafe_mask_stages_without_following_them() {
        use std::ffi::CString;
        use std::os::unix::{
            ffi::OsStrExt,
            fs::{PermissionsExt, symlink},
        };

        for kind in [
            "symlink",
            "fifo",
            "directory",
            "wrong-mode",
            "malformed-name",
        ] {
            let store = tempfile::tempdir().unwrap();
            ensure_store(store.path()).unwrap();
            let staging = store.path().join("staging");
            let stage = staging.join(match kind {
                "malformed-name" => ".mask-file.stage-",
                _ => ".mask-file.stage-unsafe1",
            });
            match kind {
                "symlink" => {
                    let target = store.path().join("target");
                    fs::write(&target, "must not be followed").unwrap();
                    symlink(&target, &stage).unwrap();
                }
                "fifo" => {
                    let stage = CString::new(stage.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(stage.as_ptr(), 0o600) }, 0);
                }
                "directory" => fs::create_dir(&stage).unwrap(),
                "wrong-mode" => {
                    fs::write(&stage, "").unwrap();
                    fs::set_permissions(&stage, fs::Permissions::from_mode(0o644)).unwrap();
                }
                "malformed-name" => fs::write(&stage, "").unwrap(),
                _ => unreachable!(),
            }

            assert!(mask_file(store.path()).is_err(), "{kind}");
            assert!(stage.exists(), "unsafe stage must not be removed: {kind}");
            assert!(
                !store.path().join(".mask-file").exists(),
                "unsafe staging must prevent publication: {kind}"
            );
        }
    }

    #[test]
    fn concurrent_mask_publishers_from_separate_processes_share_one_final() {
        if let Some(store) = std::env::var_os("AGENT_VM_MASK_PUBLISHER_STORE") {
            mask_file(Path::new(&store)).unwrap();
            return;
        }

        let store = tempfile::tempdir().unwrap();
        let children = (0..2)
            .map(|_| {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "mount::prepare_tests::concurrent_mask_publishers_from_separate_processes_share_one_final",
                        "--nocapture",
                    ])
                    .env("AGENT_VM_MASK_PUBLISHER_STORE", store.path())
                    .spawn()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        let final_path = store.path().join(".mask-file");
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&final_path).unwrap();
        assert_eq!(metadata.len(), 0);
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o444);
        assert!(
            fs::read_dir(store.path().join("staging"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn mask_publication_is_atomic_and_rejects_all_corrupt_final_kinds() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for kind in ["symlink", "directory", "nonempty", "mode"] {
            let store = tempfile::tempdir().unwrap();
            ensure_store(store.path()).unwrap();
            let final_path = store.path().join(".mask-file");
            match kind {
                "symlink" => symlink("elsewhere", &final_path).unwrap(),
                "directory" => fs::create_dir(&final_path).unwrap(),
                "nonempty" => fs::write(&final_path, "x").unwrap(),
                "mode" => {
                    fs::write(&final_path, "").unwrap();
                    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(mask_file(store.path()).is_err(), "{kind}");
        }
        let store = tempfile::tempdir().unwrap();
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = store.path().to_path_buf();
                std::thread::spawn(move || mask_file(&path).unwrap())
            })
            .collect();
        let paths: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(paths[0], paths[1]);
        let metadata = fs::metadata(&paths[0]).unwrap();
        assert_eq!(metadata.len(), 0);
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o444);
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
}
