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
    /// directory. Mounts appended by that walk carry `follow_links: false`
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
/// increments when a symlink is followed). Termination is already
/// guaranteed by the canonicalized `visited` set (finitely many distinct
/// real paths), so this cap is belt-and-suspenders against pathological
/// symlink chains; 40 is deep enough for any real skill farm while still
/// bounding a runaway chain.
const MAX_LINK_DEPTH: usize = 40;

/// Walk `root` (already canonicalized) on the host side and return the
/// distinct canonicalized *directory* targets reachable by following the
/// symlinks it transitively contains, plus warnings for anything skipped
/// along the way (symlink-to-file, dangling symlink, unreadable
/// subdirectory, depth-cap hit).
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
fn discover_followed_targets(root: &Path, home: &Path) -> Result<(Vec<PathBuf>, Vec<String>)> {
    let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut out: Vec<PathBuf> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    // (directory to scan, symlink-follow depth so far).
    let mut worklist: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

    while let Some((dir, link_depth)) = worklist.pop() {
        // Canonicalized visited-set: two symlinks resolving to the same
        // real path (or a symlink back to an already-walked ancestor)
        // collapse to one entry here, which is what actually terminates
        // cycles — the depth cap above is a secondary bound.
        if !visited.insert(dir.clone()) {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                // A permission-denied (or otherwise unreadable) subdir must
                // not abort the whole launch — warn and move on.
                warnings.push(format!(
                    "skipping unreadable directory {}: {e}",
                    dir.display()
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
                        dir.display()
                    ));
                    continue;
                }
            };
            let path = entry.path();
            // lstat (no follow) so we can tell "is a symlink" from "is a
            // real dir/file" without resolving anything yet.
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!("skipping {}: {e}", path.display()));
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
                    path.display()
                ));
                continue;
            }
            let target = match path.canonicalize() {
                Ok(t) => t,
                Err(_) => {
                    warnings.push(format!("skipping dangling symlink {}", path.display()));
                    continue;
                }
            };
            let target_meta = match fs::metadata(&target) {
                Ok(m) => m,
                Err(e) => {
                    warnings.push(format!(
                        "skipping symlink {} -> {}: {e}",
                        path.display(),
                        target.display()
                    ));
                    continue;
                }
            };
            if !target_meta.is_dir() {
                warnings.push(format!(
                    "skipping symlink {} -> {} (not a directory)",
                    path.display(),
                    target.display()
                ));
                continue;
            }
            if !target.starts_with(home) {
                anyhow::bail!(
                    "--mount follow-links: symlink {} resolves to {}, which is outside your \
                     $HOME ({}); refusing to mount it",
                    path.display(),
                    target.display(),
                    home.display()
                );
            }
            // Dedup within this walk. Note this does not special-case a
            // target that lands *inside* `root` or another already-
            // discovered target (see `expand_follow_links` doc) — that's
            // a redundant-but-harmless extra bind at its own real path,
            // not a correctness issue.
            if !out.contains(&target) {
                out.push(target.clone());
            }
            worklist.push((target, link_depth + 1));
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
    let mut discovered_targets: Vec<PathBuf> = Vec::new();
    for m in &expanded {
        if !m.follow_links {
            continue;
        }
        let (targets, mut w) = discover_followed_targets(&m.host, &home_canon)?;
        warnings.append(&mut w);
        discovered_targets.extend(targets);
    }
    for target in discovered_targets {
        // The original follow-links mount (the HOST bind itself) stays in
        // the list unchanged; this appends one read-only mount per
        // distinct discovered real target, at its own real path.
        expanded.push(ExtraMount {
            host: target.clone(),
            guest: target,
            readonly: true,
            follow_links: false,
        });
    }

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

    #[test]
    fn discover_direct_dir_symlink() {
        let home = tempfile::tempdir().unwrap();
        let home_path = canon(home.path());
        let host = home_path.join("host");
        let outside = home_path.join("outside_dir");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, host.join("foo")).unwrap();

        let (targets, warnings) = discover_followed_targets(&host, &home_path).expect("ok");
        assert_eq!(targets, vec![outside]);
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

        let (mut targets, warnings) = discover_followed_targets(&host, &home_path).expect("ok");
        targets.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(
            targets, expected,
            "both the direct and transitive target must be discovered"
        );
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
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

        let (mut targets, _warnings) =
            discover_followed_targets(&host, &home_path).expect("must terminate, not hang");
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

        let (targets, _warnings) =
            discover_followed_targets(&host, &home_path).expect("must terminate, not hang");
        assert_eq!(targets, vec![host]);
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

        let (targets, warnings) =
            discover_followed_targets(&host, &home_path).expect("ok, not an error");
        assert!(targets.is_empty());
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

        let (targets, warnings) =
            discover_followed_targets(&host, &home_path).expect("ok, not an error");
        assert!(targets.is_empty());
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

        let err = discover_followed_targets(&host, &narrow_home)
            .expect_err("target outside $HOME must be a hard error")
            .to_string();
        assert!(
            err.contains(&host.join("foo").display().to_string()),
            "got: {err}"
        );
        assert!(err.contains(&outside.display().to_string()), "got: {err}");
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
