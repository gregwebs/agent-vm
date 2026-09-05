//! `--mount HOST[:GUEST][:MODE][:MODE]...` parsing and the volume-builder
//! wiring it feeds. [`parse_extra_mounts`] and [`configure_extra_mount`] are
//! the two entry points `run.rs`'s `launch()` calls; everything else here
//! is a private implementation detail of the grammar.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use microsandbox::sandbox::MountBuilder;

use crate::run::guest_path_is_mountable;

/// A recognized `--mount` mode keyword: `ro`, `rw`, or `follow-links`
/// (issue #11 — auto-discover and bind-mount the real directories that
/// symlinks under `HOST` transitively resolve to; see
/// [`discover_followed_targets`]/[`expand_follow_links`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountMode {
    ReadOnly,
    ReadWrite,
    FollowLinks,
}

impl MountMode {
    /// Classify one trailing suffix segment as a mode keyword.
    /// `None` = not a known keyword (caller raises "unknown mode").
    fn from_keyword(kw: &str) -> Option<MountMode> {
        match kw {
            "ro" => Some(MountMode::ReadOnly),
            "rw" => Some(MountMode::ReadWrite),
            "follow-links" => Some(MountMode::FollowLinks),
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
];

/// True iff `a` and `b` may not appear on the same mount (order-independent).
fn modes_conflict(a: MountMode, b: MountMode) -> bool {
    INCOMPATIBLE_MODES
        .iter()
        .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a))
}

/// One `--mount HOST[:GUEST][:MODE][:MODE]...` argument resolved into
/// separate paths plus the mode(s) it carried.
#[derive(Debug)]
pub(crate) struct ExtraMount {
    pub(crate) host: PathBuf,
    pub(crate) guest: PathBuf,
    /// Resolved from the parsed mode set: true iff `ro` (or `follow-links`,
    /// which implies `ro`) was among them.
    pub(crate) readonly: bool,
    /// True iff `follow-links` was among the parsed modes. Consumed by
    /// [`expand_follow_links`], which walks `host` on the host side and
    /// appends one read-only `ExtraMount` per discovered symlink-target
    /// directory — plus, when a link's raw target text names that directory
    /// through a symlinked parent, a second mount of the same host
    /// directory at that *literal* path (see [`literal_guest_path`]).
    /// Mounts appended by that walk carry `follow_links: false`
    /// (the walk does not recurse into a discovered target's own targets
    /// beyond what it already resolved transitively).
    pub(crate) follow_links: bool,
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
            let mode = MountMode::from_keyword(kw).ok_or_else(|| {
                anyhow::anyhow!(
                    "--mount {entry:?}: unknown mode keyword {kw:?} \
                     (expected `ro`, `rw`, or `follow-links`)"
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

        // Canonicalize host so we follow symlinks; the bind target
        // needs to be a real path on the host.
        let host = host
            .canonicalize()
            .with_context(|| format!("canonicalizing --mount host {host_s:?}"))?;
        out.push(ExtraMount {
            host,
            guest,
            readonly,
            follow_links,
        });
    }
    Ok(out)
}

/// Configure a bind-mount `MountBuilder` for an `ExtraMount`: bind the host
/// path and apply `.readonly()` when the mount was parsed `:ro`. Factored
/// out of the `.volume(...)` closure so the readonly wiring has a boot-free
/// unit seam (see `extra_mount_ro_propagates_readonly_into_built_volume`).
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
}

impl BindPath {
    /// One host directory bound at its own real path — the ordinary case.
    fn mirrored(path: PathBuf) -> BindPath {
        BindPath {
            host: path.clone(),
            guest: path,
        }
    }

    /// Descend into `name` on both sides at once.
    fn join(&self, name: &std::ffi::OsStr) -> BindPath {
        BindPath {
            host: self.host.join(name),
            guest: self.guest.join(name),
        }
    }
}

impl From<BindPath> for ExtraMount {
    /// Every bind the walk discovers is read-only (`follow-links` implies
    /// `ro`) and carries `follow_links: false` — the walk that produced it
    /// already resolved transitively, so it must not be re-expanded.
    fn from(p: BindPath) -> ExtraMount {
        ExtraMount {
            host: p.host,
            guest: p.guest,
            readonly: true,
            follow_links: false,
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
    let mut worklist: Vec<(BindPath, usize)> = vec![(root.clone(), 0)];

    while let Some((dir, link_depth)) = worklist.pop() {
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
                    worklist.push((path, link_depth));
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
                if !out.iter().any(|d| d.guest == b.guest) {
                    out.push(b);
                }
            };
            let mirror = BindPath::mirrored(target.clone());
            push_unique_guest(mirror.clone());
            worklist.push((mirror, link_depth + 1));
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
                    };
                    push_unique_guest(alias.clone());
                    worklist.push((alias, link_depth + 1));
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
    if !mounts.iter().any(|m| m.follow_links) {
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
        if !m.follow_links {
            continue;
        }
        let root = BindPath {
            host: m.host.clone(),
            guest: m.guest.clone(),
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
    let mut host_by_guest: HashMap<PathBuf, PathBuf> = HashMap::new();
    let mut finalized = Vec::with_capacity(expanded.len());
    for m in expanded {
        match host_by_guest.get(&m.guest) {
            Some(existing_host) if *existing_host == m.host => continue,
            Some(existing_host) => anyhow::bail!(
                "--mount: guest path {} is claimed by two different host paths {} and {}",
                m.guest.display(),
                existing_host.display(),
                m.host.display()
            ),
            None => {
                host_by_guest.insert(m.guest.clone(), m.host.clone());
                finalized.push(m);
            }
        }
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
    fn parse_extra_mounts_rejects_nonexistent_host_path_at_canonicalize() {
        // canonicalize fails on missing paths → Err propagates.
        let r = parse_extra_mounts(&["/this/path/does/not/exist/anywhere".into()]);
        assert!(r.is_err());
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
        assert!(!parsed[0].readonly);
        let parsed = parse_extra_mounts(&["/:/g".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(!parsed[0].readonly);
    }

    #[test]
    fn parse_extra_mounts_ro_no_guest() {
        let parsed = parse_extra_mounts(&["/:ro".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/"));
        assert!(parsed[0].readonly);
    }

    #[test]
    fn parse_extra_mounts_rw_no_guest() {
        let parsed = parse_extra_mounts(&["/:rw".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/"));
        assert!(!parsed[0].readonly);
    }

    #[test]
    fn parse_extra_mounts_guest_and_ro() {
        let parsed = parse_extra_mounts(&["/:/g:ro".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(parsed[0].readonly);
    }

    #[test]
    fn parse_extra_mounts_guest_and_rw() {
        let parsed = parse_extra_mounts(&["/:/g:rw".into()]).expect("ok");
        assert_eq!(parsed[0].guest, std::path::Path::new("/g"));
        assert!(!parsed[0].readonly);
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
        assert!(parsed[0].readonly);

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
        assert!(em.readonly);
        assert!(built_readonly(em.host.to_str().unwrap(), em.readonly));

        let em_rw = &parse_extra_mounts(&["/:rw".into()]).unwrap()[0];
        assert!(!em_rw.readonly);
        assert!(!built_readonly(
            em_rw.host.to_str().unwrap(),
            em_rw.readonly
        ));

        let em_def = &parse_extra_mounts(&["/".into()]).unwrap()[0];
        assert!(!built_readonly(
            em_def.host.to_str().unwrap(),
            em_def.readonly
        ));
    }

    // ── follow-links: grammar/parse (issue #11) ────────────────────

    #[test]
    fn parse_follow_links_implies_readonly() {
        let parsed = parse_extra_mounts(&["/:follow-links".into()]).expect("ok");
        assert!(parsed[0].readonly);
        assert!(parsed[0].follow_links);
    }

    #[test]
    fn parse_follow_links_with_ro_ok() {
        let parsed =
            parse_extra_mounts(&["/:ro:follow-links".into()]).expect("ok, ro+follow-links coexist");
        assert!(parsed[0].readonly);
        assert!(parsed[0].follow_links);
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
        assert!(parsed[0].readonly);
        assert!(parsed[0].follow_links);
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
            host: real,
            guest: home_path.join("skills"),
            readonly: true,
            follow_links: true,
        }];
        let (expanded, warnings) = expand_follow_links(mounts, Some(&home_path)).expect("ok");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let want_guest = home_path.join("shared");
        assert!(
            expanded
                .iter()
                .any(|m| m.host == shared && m.guest == want_guest && m.readonly),
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
            host: host.clone(),
            guest: host,
            readonly: true,
            follow_links: true,
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
                host: host.clone(),
                guest: host,
                readonly: true,
                follow_links: true,
            },
            ExtraMount {
                // An explicit mount claims the discovered target's real
                // path as its GUEST, from a different HOST.
                host: explicit_host.clone(),
                guest: target.clone(),
                readonly: false,
                follow_links: false,
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
            host: "/".into(),
            guest: "/g".into(),
            readonly: false,
            follow_links: false,
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
            host: "/".into(),
            guest: "/".into(),
            readonly: false,
            follow_links: true,
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
            host: host.clone(),
            guest: host,
            readonly: true,
            follow_links: true,
        }];
        let (expanded, _warnings) = expand_follow_links(mounts, Some(&home_path)).expect("ok");
        let discovered = expanded
            .iter()
            .find(|m| m.host == target)
            .expect("discovered target present in expanded list");
        assert!(discovered.readonly);
        assert!(built_readonly(
            discovered.host.to_str().unwrap(),
            discovered.readonly
        ));
    }
}
