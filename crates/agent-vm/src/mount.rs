//! `--mount HOST[:GUEST][:MODE][:MODE]...` parsing and the volume-builder
//! wiring it feeds. [`parse_extra_mounts`] and [`configure_extra_mount`] are
//! the two entry points `run.rs`'s `launch()` calls; everything else here
//! is a private implementation detail of the grammar.

use std::path::PathBuf;

use anyhow::{Context, Result};
use microsandbox::sandbox::MountBuilder;

use crate::run::guest_path_is_mountable;

/// A recognized `--mount` mode keyword. `ro`/`rw` today. `follow-links`
/// (issue #11) slots in as another variant here plus one `from_keyword`
/// arm, one `keyword` arm, and one `INCOMPATIBLE_MODES` entry — no change to
/// the grammar or the accumulation/validation control flow (see
/// `parse_extra_mounts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountMode {
    ReadOnly,
    ReadWrite,
}

impl MountMode {
    /// Classify one trailing suffix segment as a mode keyword.
    /// `None` = not a known keyword (caller raises "unknown mode").
    fn from_keyword(kw: &str) -> Option<MountMode> {
        match kw {
            "ro" => Some(MountMode::ReadOnly),
            "rw" => Some(MountMode::ReadWrite),
            _ => None,
        }
    }

    /// The canonical keyword, for error messages that name the offending
    /// token (matches the `parse_publish_args` idiom).
    fn keyword(self) -> &'static str {
        match self {
            MountMode::ReadOnly => "ro",
            MountMode::ReadWrite => "rw",
        }
    }
}

/// Mode-keyword pairs that cannot appear together on one mount. This is the
/// single place the conflict policy lives — adding `follow-links` in issue
/// #11 means adding the variant above and one row here, e.g.
/// `(MountMode::ReadWrite, MountMode::FollowLinks)`. Note `ro`+`follow-links`
/// is intentionally NOT listed, because they coexist (follow-links implies
/// read-only) — which is precisely why a single mutually-exclusive
/// `Option<MountMode>` slot would be wrong.
const INCOMPATIBLE_MODES: &[(MountMode, MountMode)] = &[(MountMode::ReadOnly, MountMode::ReadWrite)];

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
    /// Resolved from the parsed mode set: true iff `ro` was among them.
    pub(crate) readonly: bool,
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
                    "--mount {entry:?}: unknown mode keyword {kw:?} (expected `ro` or `rw`)"
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
        let readonly = modes.contains(&MountMode::ReadOnly);

        // Canonicalize host so we follow symlinks; the bind target
        // needs to be a real path on the host.
        let host = host
            .canonicalize()
            .with_context(|| format!("canonicalizing --mount host {host_s:?}"))?;
        out.push(ExtraMount { host, guest, readonly });
    }
    Ok(out)
}

/// Configure a bind-mount `MountBuilder` for an `ExtraMount`: bind the host
/// path and apply `.readonly()` when the mount was parsed `:ro`. Factored
/// out of the `.volume(...)` closure so the readonly wiring has a boot-free
/// unit seam (see `extra_mount_ro_propagates_readonly_into_built_volume`).
pub(crate) fn configure_extra_mount(m: MountBuilder, host: PathBuf, readonly: bool) -> MountBuilder {
    let m = m.bind(host);
    if readonly { m.readonly() } else { m }
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
        assert!(
            !err.contains("unknown mode keyword \"\""),
            "got: {err}"
        );
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
        assert!(!built_readonly(em_rw.host.to_str().unwrap(), em_rw.readonly));

        let em_def = &parse_extra_mounts(&["/".into()]).unwrap()[0];
        assert!(!built_readonly(em_def.host.to_str().unwrap(), em_def.readonly));
    }
}
