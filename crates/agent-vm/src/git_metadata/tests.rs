//! Kernel tables and adapter rows for automatic Git metadata mounts (#535).
//!
//! A `verus!` body erases to ordinary Rust, so a spec function cannot be read as
//! an executable statement about a change. Every kernel here therefore carries
//! an **independently written** oracle over the erased form, plus a proptest where
//! the input space is open. The properties are stated twice on purpose
//! (ADR-0018): once as an `ensures` clause, once as a table a human can read.

use super::*;
use crate::mount::{HostSyntax, MountRequests, parse_mount_spec, same_declaration};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// U1 — the mode decision
// ---------------------------------------------------------------------------

#[test]
fn git_mount_access_matches_the_three_rows() {
    // Written out as a literal table rather than as the same expression the
    // kernel uses, so a flipped arm is visible.
    for (mode, skip, writable) in [
        (GitMountMode::ReadOnly, false, false),
        (GitMountMode::ReadWrite, false, true),
        (GitMountMode::Off, true, false),
    ] {
        let decision = git_mount_access(mode.facts());
        assert_eq!(decision == MountAccessDecision::Skip, skip, "{mode:?}");
        assert_eq!(
            decision == MountAccessDecision::ReadWrite,
            writable,
            "{mode:?}"
        );
    }
    // `off` never means writable, and no writable mode skips.
    assert_eq!(
        git_mount_access(GitMountModeFacts {
            off: true,
            writable: true
        }),
        MountAccessDecision::Skip
    );
}

// ---------------------------------------------------------------------------
// U2 — the one-line pointer
// ---------------------------------------------------------------------------

/// An independent `strip_suffix`/`iter().any` oracle for the pointer contract.
fn pointer_oracle(bytes: &[u8], prefix: &[u8]) -> Option<(usize, usize)> {
    if !bytes.starts_with(prefix) {
        return None;
    }
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b'\n' || bytes[end - 1] == b'\r') {
        end -= 1;
    }
    if end <= prefix.len() {
        return None;
    }
    if bytes[prefix.len()..end]
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f)
    {
        return None;
    }
    Some((prefix.len(), end))
}

fn pointer_actual(bytes: &[u8], prefix: &[u8]) -> Option<(usize, usize)> {
    pointer_path_span(bytes, prefix).map(|span| (span.start, span.end))
}

#[test]
fn pointer_path_span_matches_the_oracle_table() {
    let rows: Vec<(&[u8], &[u8])> = vec![
        (b"gitdir: /r/wt/.git\n", b"gitdir: "),
        (b"gitdir: /r/wt/.git", b"gitdir: "),
        (b"gitdir: /r/wt/.git\r\n", b"gitdir: "),
        (b"gitdir: /r/wt/.git\r\r\n", b"gitdir: "),
        (b"gitdir: ", b"gitdir: "),
        (b"gitdir: \n", b"gitdir: "),
        (b"", b"gitdir: "),
        (b"gitdir: \n/x\n", b"gitdir: "),
        (b"gitdir: /a\0b\n", b"gitdir: "),
        (b"gitdir: /a\x7fb\n", b"gitdir: "),
        (b"Gitdir: /a\n", b"gitdir: "),
        (b"gitdir:/a\n", b"gitdir: "),
        // Non-UTF-8 high bytes are accepted: a host path is bytes.
        (b"gitdir: /a\xc3\xa9\n", b"gitdir: "),
        // The empty prefix is how `commondir` and `gitdir` are read.
        (b"../..\n", b""),
        (b"\n", b""),
        (b"  \n", b""),
        (b"/a b\n", b""),
    ];
    for (bytes, prefix) in rows {
        assert_eq!(
            pointer_actual(bytes, prefix),
            pointer_oracle(bytes, prefix),
            "{:?} with prefix {:?}",
            String::from_utf8_lossy(bytes),
            String::from_utf8_lossy(prefix)
        );
    }
}

proptest::proptest! {
    #[test]
    fn pointer_path_span_matches_the_oracle_property(
        bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..40),
    ) {
        for prefix in [&b"gitdir: "[..], &b""[..], &b"x"[..]] {
            proptest::prop_assert_eq!(pointer_actual(&bytes, prefix), pointer_oracle(&bytes, prefix));
        }
    }
}

// ---------------------------------------------------------------------------
// U3 — the discovery state machine
// ---------------------------------------------------------------------------

/// The twelve facts, in the order they are measured.
fn facts_from(bits: u32) -> WorktreeFacts {
    let bit = |index: u32| bits & (1 << index) != 0;
    WorktreeFacts {
        dot_git_regular: bit(0),
        pointer_parsed: bit(1),
        gitdir_is_dir: bit(2),
        commondir_present: bit(3),
        linked_evidence: bit(4),
        commondir_parsed: bit(5),
        common_resolved: bit(6),
        common_is_git_dir: bit(7),
        worktree_is_git_dir: bit(8),
        registered_under_common: bit(9),
        back_pointer_matches: bit(10),
        guest_spelling_consistent: bit(11),
    }
}

/// An independent `if`-ladder, written from the state machine's own wording
/// rather than from the kernel's body.
fn verdict_oracle(f: WorktreeFacts) -> WorktreeVerdict {
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

#[test]
fn worktree_verdict_matches_the_oracle_on_all_4096_rows() {
    let mut linked = 0;
    for bits in 0u32..4096 {
        let facts = facts_from(bits);
        let verdict = worktree_verdict(facts);
        assert_eq!(verdict, verdict_oracle(facts), "facts {bits:#013b}");
        if verdict == WorktreeVerdict::Linked {
            linked += 1;
        }
    }
    // Two rows are `Linked`: every fact true with `linked_evidence` false, and
    // every fact true with it true. That fact is only consulted when `commondir`
    // is absent, so it must not be able to make a complete layout broken.
    assert_eq!(
        linked, 2,
        "linked acceptance is closed under `linked_evidence`"
    );
}

#[test]
fn a_missing_commondir_is_linked_evidence_dependent() {
    // The one fact that only matters when `commondir` is absent.
    let mut facts = facts_from(0b0011_1111_1111_1111 - 1); // all true but the last
    facts.guest_spelling_consistent = true;
    facts.back_pointer_matches = true;
    facts.registered_under_common = true;
    facts.worktree_is_git_dir = true;
    facts.common_is_git_dir = true;
    facts.common_resolved = true;
    facts.commondir_parsed = true;
    facts.pointer_parsed = true;
    facts.gitdir_is_dir = true;
    facts.dot_git_regular = true;
    for (present, evidence, expected) in [
        (false, false, WorktreeVerdict::NotLinked),
        (false, true, WorktreeVerdict::MissingCommonDirFile),
        (true, false, WorktreeVerdict::Linked),
        (true, true, WorktreeVerdict::Linked),
    ] {
        facts.commondir_present = present;
        facts.commondir_parsed = true;
        facts.linked_evidence = evidence;
        assert_eq!(worktree_verdict(facts), expected, "{present} {evidence}");
    }
}

// ---------------------------------------------------------------------------
// U4 — placement and coverage
// ---------------------------------------------------------------------------

#[test]
fn metadata_placement_matches_the_exhaustive_table() {
    for bits in 0u32..64 {
        let bit = |index: u32| bits & (1 << index) != 0;
        let facts = PlacementFacts {
            remapped: bit(0),
            guest_safe: bit(1),
            covers_core: bit(2),
            contains_checkout: bit(3),
            inside_project: bit(4),
            literal: bit(5),
        };
        // The oracle is the spec's own precedence, written as a nested `match`.
        let expected = if facts.remapped {
            Placement::Remapped
        } else if !facts.guest_safe {
            Placement::UnderTmpfs
        } else if facts.covers_core {
            Placement::CoversCoreMount
        } else if facts.contains_checkout {
            Placement::ContainsCheckout
        } else if facts.inside_project {
            if facts.literal {
                Placement::CoveredByProject
            } else {
                Placement::SymlinkInsideProject
            }
        } else {
            Placement::Bind
        };
        assert_eq!(metadata_placement(facts), expected, "facts {bits:#08b}");
    }
    // The two facts that can both hold at once, because a checkout created inside
    // the common directory also contains the project's own core bind: the reader
    // gets the remedy both share, named by the fact that says what to look at.
    assert_eq!(
        metadata_placement(PlacementFacts {
            remapped: false,
            guest_safe: true,
            covers_core: true,
            contains_checkout: true,
            inside_project: false,
            literal: true,
        }),
        Placement::CoversCoreMount
    );
}

/// U4b — the enclosing-declaration decision, over the two interesting dimensions
/// plus the one that is measured per declaration.
#[test]
fn declaration_enclosure_matches_the_exhaustive_table() {
    for bits in 0u32..8 {
        let bit = |index: u32| bits & (1 << index) != 0;
        let facts = EnclosureFacts {
            encloses: bit(0),
            same_host: bit(1),
            live: bit(2),
        };
        let expected = if !facts.encloses {
            Enclosure::Unrelated
        } else if facts.same_host && facts.live {
            Enclosure::Reachable
        } else {
            Enclosure::Shadowed
        };
        assert_eq!(declaration_enclosure(facts), expected, "facts {bits:#05b}");
    }
}

#[test]
fn worktree_coverage_matches_the_exhaustive_table() {
    for bits in 0u32..8 {
        let bit = |index: u32| bits & (1 << index) != 0;
        let facts = CoverageFacts {
            worktree_under_common: bit(0),
            common_under_worktree: bit(1),
            host_matches: bit(2),
        };
        let expected = if facts.common_under_worktree {
            Coverage::Refuse
        } else if facts.worktree_under_common {
            if facts.host_matches {
                Coverage::Covered
            } else {
                Coverage::Refuse
            }
        } else {
            Coverage::Separate
        };
        assert_eq!(worktree_coverage(facts), expected, "facts {bits:#05b}");
    }
}

/// A real `git` linked worktree in a temporary tree, built through an
/// `env_clear`-ed allow-list so a developer's Git environment cannot change the
/// fixture's shape.
struct Fixture {
    _root: tempfile::TempDir,
    /// The canonical launch directory: a linked worktree.
    worktree: PathBuf,
    /// `main/.git` — the common directory.
    common: PathBuf,
}

/// A fixture root that `discover` can accept.
///
/// The runtime tmpfs-mounts `/tmp`, `/run`, `/dev/shm` and `/var/run`, so a
/// metadata directory under one of those prefixes is refused by design. On Linux
/// `tempfile::tempdir()` lands in `/tmp`, which would make an accepted-worktree
/// fixture fail as if the product were broken; the workspace `target/` is off
/// those prefixes, and macOS canonicalizes `/tmp` to `/private/tmp` anyway.
fn fixture_root() -> tempfile::TempDir {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("CARGO_MANIFEST_DIR has two parents")
        .join("target")
        .join("git-metadata-fixtures");
    std::fs::create_dir_all(&base).expect("create fixture root");
    let dir = tempfile::tempdir_in(&base).expect("create fixture temp dir");
    assert_off_guest_tmpfs(dir.path());
    dir
}

/// Panic with an actionable message instead of a product-looking failure.
fn assert_off_guest_tmpfs(path: &std::path::Path) {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let Some(s) = path.to_str() else {
        return;
    };
    if let Some(prefix) = crate::guest_paths::TMPFS_GUEST_PREFIXES
        .iter()
        .copied()
        .find(|p| s == *p || s.starts_with(&format!("{p}/")))
    {
        panic!(
            "test fixture root {} is under the guest tmpfs prefix `{prefix}`: the runtime \
             mounts a tmpfs there, and automatic Git metadata under it is refused by design. \
             Build with an off-tmpfs target dir, e.g. `CARGO_TARGET_DIR=/build/target cargo \
             test -p agent-vm`. See CONTRIBUTING.md, \"`CARGO_TARGET_DIR` must not be on a \
             tmpfs prefix\".",
            crate::one_line::quoted_path(&path)
        );
    }
}

#[test]
#[should_panic(expected = "CARGO_TARGET_DIR")]
fn a_tmpfs_fixture_root_is_refused() {
    assert_off_guest_tmpfs(std::path::Path::new("/tmp/git-metadata-fixtures/x"));
}

fn fixture_worktree() -> Fixture {
    let root = fixture_root();
    let home = root.path().join("home");
    let main = home.join("repos/main");
    let worktree = root.path().join("wt");
    std::fs::create_dir_all(&main).unwrap();
    std::fs::create_dir(&worktree).unwrap();
    let git = |dir: &Path, args: &[&str]| {
        let out = std::process::Command::new("git")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .current_dir(dir)
            .stdin(std::process::Stdio::null())
            .args([
                "-c",
                "init.defaultBranch=main",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "fixture git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&main, &["init", "-q"]);
    git(&main, &["config", "user.name", "gm"]);
    git(&main, &["config", "user.email", "gm@example.invalid"]);
    std::fs::write(main.join("tracked.txt"), "seed\n").unwrap();
    git(&main, &["add", "tracked.txt"]);
    git(&main, &["commit", "-q", "-m", "seed"]);
    git(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            worktree.to_str().unwrap(),
            "-b",
            "wt",
        ],
    );
    Fixture {
        worktree: worktree.canonicalize().unwrap(),
        common: main.join(".git").canonicalize().unwrap(),
        _root: root,
    }
}

/// A remapped project is refused before anything else: Git's relative pointers
/// would resolve against `/workspace`, and absolute ones under a tmpfs prefix
/// would be wiped. This row needs a real linked worktree, because a remap is only
/// reachable once discovery has something to place.
#[test]
fn a_remapped_project_is_refused() {
    let fixture = fixture_worktree();
    let workspace = Path::new("/workspace");
    let error = discover(
        GitMountMode::ReadOnly,
        LaunchTopology {
            project_dir: &fixture.worktree,
            project_guest: workspace,
            core_guest_mounts: &[],
            core_host_sources: &[],
            selected: &[],
        },
    )
    .unwrap_err();
    assert!(
        format!("{error}").contains("cannot be mounted at its host paths"),
        "{error}"
    );
}

/// A real layout-A fixture driven through `discover` directly, so the
/// `MountRequests` shape (origin, order, one bind) is pinned independently of the
/// launch harness.
#[test]
fn discover_returns_one_common_request_for_a_real_worktree() {
    let fixture = fixture_worktree();
    let mounts = discover(
        GitMountMode::ReadWrite,
        LaunchTopology {
            project_dir: &fixture.worktree,
            project_guest: &fixture.worktree,
            core_guest_mounts: &[],
            core_host_sources: &[],
            selected: &[],
        },
    )
    .expect("a real worktree is discoverable");
    let (requests, report) = mounts.into_parts();
    assert_eq!(
        requests.len(),
        1,
        "the per-worktree dir is covered by the common one"
    );
    assert!(matches!(
        requests[0].origin,
        crate::mount::MountOrigin::GitMetadata {
            role: crate::mount::GitMetadataRole::Common
        }
    ));
    assert_eq!(requests[0].mount.guest, fixture.common);
    assert_eq!(requests[0].mount.host, fixture.common);
    assert!(
        matches!(
            requests[0].mount.policy,
            crate::mount::MountPolicy::BindReadWrite
        ),
        "`rw` is writable"
    );
    assert!(report.notice().unwrap().contains("writable"));

    // The request list survives `claim` unchanged: an automatic bind is an
    // ordinary declaration there.
    let claimed = crate::mount::claim(requests, &[]).expect("claim accepts it");
    assert_eq!(claimed.len(), 1);
    let _ = MountRequests::new(claimed);
}

// ---------------------------------------------------------------------------
// U5 — the component resolver
// ---------------------------------------------------------------------------

#[test]
fn resolve_components_matches_the_stack_oracle() {
    // Absolute input ignores the base entirely, so the oracle's base is the root.
    for (path, expected) in [
        // A `..` with nothing to pop escapes rather than clamping at `/`.
        ("..", None),
        ("/..", None),
        ("a/../..", None),
        ("../../x", None),
        ("../../../x", None),
        // `.` is a no-op but still occupies an index, and `..` pops the last
        // *surviving normal* component, not the last one seen.
        ("./a/./b", Some(vec![1, 2])),
        ("a/b/../c", Some(vec![0, 3])),
        ("", Some(vec![])),
    ] {
        let resolved = resolve_components(0, &components_of(path));
        let actual = (!resolved.escaped).then(|| resolved.kept.clone());
        let expected: Option<Vec<usize>> = expected;
        assert_eq!(actual, expected, "{path:?}");
    }

    // Through the adapter, with a real base.
    let base = Path::new("/a/b/c");
    for (path, expected) in [
        ("../x", Some("/a/b/x")),
        ("../../x", Some("/a/x")),
        ("../../../x", Some("/x")),
        ("../../../../x", None),
        ("/abs/./x", Some("/abs/x")),
        ("/abs/a/../x", Some("/abs/x")),
        ("//abs//x/", Some("/abs/x")),
    ] {
        assert_eq!(
            resolve_lexically(base, Path::new(path)).as_deref(),
            expected.map(Path::new),
            "{path:?} against {base:?}"
        );
    }

    // Non-UTF-8 components are carried byte for byte.
    let os = std::ffi::OsStr::from_bytes(b"caf\xc3\xa9");
    let resolved = resolve_lexically(Path::new("/a"), Path::new(os));
    assert_eq!(resolved, Some(PathBuf::from("/a").join(os)));
}

fn components_of(path: &str) -> Vec<ComponentKind> {
    Path::new(path)
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::CurDir => Some(ComponentKind::CurDir),
            Component::ParentDir => Some(ComponentKind::ParentDir),
            Component::Normal(_) => Some(ComponentKind::Normal),
            Component::Prefix(_) => None,
        })
        .collect()
}

proptest::proptest! {
    #[test]
    fn resolve_components_matches_the_stack_oracle_property(
        kinds in proptest::collection::vec(0usize..3, 0..12),
        base_depth in 0usize..4,
    ) {
        let measured: Vec<ComponentKind> = kinds
            .iter()
            .map(|kind| match kind {
                0 => ComponentKind::CurDir,
                1 => ComponentKind::ParentDir,
                _ => ComponentKind::Normal,
            })
            .collect();
        let resolved = resolve_components(base_depth, &measured);
        // The oracle is a plain stack walk over the same kinds, written as a
        // loop with explicit state rather than as a recursive specification.
        let mut stack: Vec<usize> = Vec::new();
        let mut base_kept = base_depth;
        let mut escaped = false;
        for (index, kind) in measured.iter().enumerate() {
            if escaped {
                continue;
            }
            match kind {
                ComponentKind::CurDir => {}
                ComponentKind::Normal => stack.push(index),
                ComponentKind::ParentDir => {
                    if stack.pop().is_none() {
                        if base_kept == 0 {
                            escaped = true;
                        } else {
                            base_kept -= 1;
                        }
                    }
                }
            }
        }
        proptest::prop_assert_eq!(resolved.escaped, escaped);
        proptest::prop_assert_eq!(resolved.base_kept, base_kept);
        proptest::prop_assert_eq!(&resolved.kept, &stack);
    }
}

// ---------------------------------------------------------------------------
// U6 — HEAD validity
// ---------------------------------------------------------------------------

/// An independent oracle for `headref_accepts`, written with `strip_prefix` and
/// `trim_start_matches` over the text.
fn headref_oracle(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let symbolic = text.strip_prefix("ref:").is_some_and(|rest| {
        rest.trim_start_matches([' ', '\t', '\n', '\r'])
            .starts_with("refs/")
    });
    let detached = bytes.len() >= 40 && bytes[..40].iter().all(|byte| byte.is_ascii_hexdigit());
    symbolic || detached
}

#[test]
fn headref_valid_matches_the_git_table() {
    // Every row was measured against Git 2.54.0 on a real worktree (§3 of the
    // plan): the accepted ones Git opens, the rejected ones it refuses.
    let rows: Vec<(&[u8], bool)> = vec![
        (b"ref: refs/heads/main\n", true),
        (b"ref:refs/heads/main\n", true),
        (b"ref: \t refs/heads/main\n", true),
        (b"ref: refs/heads/.invalid\n", true),
        (b"ref: refx\n", false),
        (b"refs/heads/main\n", false),
        (b"garbage\n", false),
        (b"", false),
        (b"\0", false),
        (b"0123456789abcdef0123456789abcdef01234567\n", true),
        (b"0123456789ABCDEF0123456789abcdef01234567\n", true),
        (b"0123456789abcdef0123456789abcdef0123456\n", false),
        (b"0123456789abcdef0123456789abcdef0123456g\n", false),
        (
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            true,
        ),
    ];
    for (bytes, expected) in rows {
        assert_eq!(
            headref_valid(bytes),
            expected,
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
        assert_eq!(headref_valid(bytes), headref_oracle(bytes), "differential");
    }

    // The symlink form: `refs/` at the target's first byte, nothing else.
    for (target, expected) in [
        (&b"refs/heads/main"[..], true),
        (&b"refs/x"[..], true),
        (&b"ref: refs/heads/main"[..], false),
        (&b"refs"[..], false),
        (&b""[..], false),
    ] {
        assert_eq!(headref_link_valid(target), expected, "{target:?}");
    }
}

proptest::proptest! {
    #[test]
    fn headref_valid_matches_the_git_oracle(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..80)) {
        proptest::prop_assert_eq!(headref_valid(&bytes), headref_oracle(&bytes));
    }
}

/// The differential row: a real `git` must agree about the `HEAD` *files* this
/// kernel classifies, so the kernel is not merely self-consistent. Skipped with a
/// printed reason when `git` is absent — never silently.
#[test]
fn headref_valid_agrees_with_host_git() {
    let Ok(version) = std::process::Command::new("git").arg("--version").output() else {
        eprintln!("SKIPPED headref_valid_agrees_with_host_git: no `git` on PATH");
        return;
    };
    if !version.status.success() {
        eprintln!("SKIPPED headref_valid_agrees_with_host_git: `git --version` failed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let git = |args: &[&str]| -> bool {
        std::process::Command::new("git")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    };
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    assert!(git(&["-C", repo.to_str().unwrap(), "init", "-q"]));
    let head = repo.join(".git/HEAD");
    // One row per shape this kernel accepts or refuses; `git rev-parse --git-dir`
    // is the oracle, and it fails as soon as `HEAD` is invalid.
    for (contents, expected) in [
        ("ref: refs/heads/main\n", true),
        ("ref: \t refs/heads/main\n", true),
        ("garbage\n", false),
        ("ref: refx\n", false),
        ("", false),
        ("0123456789abcdef0123456789abcdef01234567\n", true),
    ] {
        std::fs::write(&head, contents).unwrap();
        let git_accepts = git(&["-C", repo.to_str().unwrap(), "rev-parse", "--git-dir"]);
        assert_eq!(git_accepts, expected, "{contents:?}");
        assert_eq!(
            headref_valid(contents.as_bytes()),
            git_accepts,
            "kernel and host git must agree about {contents:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The declaration shape and the post-prepare race check
// ---------------------------------------------------------------------------

/// An automatic bind is the same declaration `--mount PATH:ro` parses to, so an
/// equivalent explicit declaration merges instead of conflicting (spec R10).
#[test]
fn automatic_bind_is_the_same_declaration_as_an_explicit_mount() {
    let path = Path::new("/r/main/.git");
    let automatic = ExtraMount::automatic_bind(path, BindAccess::ReadOnly).expect("UTF-8");
    let readonly = parse_mount_spec("/r/main/.git:ro", HostSyntax::AbsoluteOnly).unwrap();
    let writable = parse_mount_spec("/r/main/.git", HostSyntax::AbsoluteOnly).unwrap();
    assert!(same_declaration(&automatic, &readonly));
    assert!(!same_declaration(&automatic, &writable));
    assert_eq!(automatic.host, path);
    assert_eq!(automatic.guest, path);
    assert_eq!(automatic.source_spelling, "/r/main/.git");
    assert!(automatic.exclusions.is_empty());
    // A non-UTF-8 spelling is refused rather than stored lossily.
    let bytes = std::ffi::OsStr::from_bytes(b"/r/caf\xff/.git");
    assert!(ExtraMount::automatic_bind(Path::new(bytes), BindAccess::ReadOnly).is_none());
}

/// `verify_prepared` is a narrowing of the discovery-to-bind window, not TOCTOU
/// protection: a report whose expected canonical host differs from the prepared
/// volume is refused.
#[test]
fn verify_prepared_refuses_a_changed_host() {
    let guest = PathBuf::from("/r/main/.git");
    let report = GitMetadataReport {
        worktree: PathBuf::from("/r/wt"),
        state: MetadataState::Bound(BindAccess::ReadOnly),
        expected: vec![(guest.clone(), PathBuf::from("/r/main/.git"))],
    };
    let volume = |host: &str| crate::mount::PreparedVolume {
        guest: guest.clone(),
        source: crate::mount::PreparedVolumeSource::ReadOnlyBind(PathBuf::from(host)),
        node_kind: crate::mount::PreparedNodeKind::Directory,
        role: crate::mount::VolumeRole::Explicit,
    };
    let plan = |host: &str| crate::mount::PreparedMountPlan {
        volumes: vec![volume(host)],
        repo_scan_roots: Vec::new(),
        notices: Vec::new(),
    };
    assert!(report.verify_prepared(&plan("/r/main/.git")).is_ok());
    let error = report
        .verify_prepared(&plan("/elsewhere/.git"))
        .unwrap_err();
    let rendered = format!("{error}");
    assert!(
        rendered.contains("changed while preparing the launch"),
        "{rendered}"
    );
    assert!(rendered.contains("--git-mount=off"), "{rendered}");

    // A report with no automatic requests wraps nothing, so an ordinary launch's
    // diagnostics stay byte-identical.
    let empty = GitMetadataReport::default();
    assert!(empty.notice().is_none());
    assert_eq!(
        format!("{}", empty.annotate(anyhow::anyhow!("boom"))),
        "boom"
    );
    assert_eq!(
        report.notice().unwrap(),
        "==> Git metadata: linked worktree, read-only (--git-mount=rw|off to change)"
    );
}

/// `off` reads nothing at all: the same fixture that `ro` refuses with
/// `MalformedPointer` is `Ok` under `Off`. Observable and uid-independent (no
/// `chmod 000` oracle, which is meaningless as uid 0).
#[test]
fn off_reads_nothing() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().canonicalize().unwrap();
    std::fs::write(project.join(".git"), "not a gitdir line\n").unwrap();
    let topology = || LaunchTopology {
        project_dir: &project,
        project_guest: &project,
        core_guest_mounts: &[],
        core_host_sources: &[],
        selected: &[],
    };
    let off = discover(GitMountMode::Off, topology()).expect("off reads nothing");
    let (requests, report) = off.into_parts();
    assert!(requests.is_empty());
    assert!(report.notice().is_none());

    let error = discover(GitMountMode::ReadOnly, topology()).unwrap_err();
    assert!(format!("{error}").contains("is unusable"), "{error}");
}

// ---------------------------------------------------------------------------
// U7 — the rendered message, byte for byte
// ---------------------------------------------------------------------------

/// U7. `one_line::quoted_path` already wraps a path in quotes, and every arm used
/// to add a second pair, so the binary could not emit the line USAGE.md
/// documents. One refusal of each class is pinned whole — relationship, layout,
/// race — and the relationship row is that documented line verbatim, so the
/// documentation and the binary cannot drift apart again.
#[test]
fn refusal_messages_quote_each_path_once() {
    let render = |reason: Refusal| {
        GitMetadataError {
            worktree: PathBuf::from("/home/me/wt"),
            reason,
        }
        .to_string()
    };

    assert_eq!(
        render(Refusal::MissingCommonDirFile {
            commondir: PathBuf::from("/home/me/main/.git/worktrees/wt/commondir"),
        }),
        "linked worktree metadata for \"/home/me/wt\" is unusable: \
         \"/home/me/main/.git/worktrees/wt/commondir\" is missing. Run `git worktree repair` in \
         the main checkout or in \"/home/me/wt\", or pass --git-mount=off to launch without \
         automatic Git metadata mounts."
    );

    assert_eq!(
        render(Refusal::ContainsCheckout {
            metadata: PathBuf::from("/home/me/repos/bare"),
            checkout: PathBuf::from("/home/me/repos/bare/other"),
        }),
        "linked worktree metadata for \"/home/me/wt\" cannot be mounted at its host paths: \
         \"/home/me/repos/bare\" contains the checkout \"/home/me/repos/bare/other\", so the bind \
         would include another worktree's source. Pass --git-mount=off to launch without \
         automatic Git metadata mounts."
    );

    assert_eq!(
        render(Refusal::ChangedWhilePreparing {
            guest: PathBuf::from("/home/me/main/.git"),
            expected: PathBuf::from("/home/me/main/.git"),
            prepared: None,
        }),
        "linked worktree metadata for \"/home/me/wt\" changed while preparing the launch: the \
         prepared bind at \"/home/me/main/.git\" names no prepared volume instead of \
         \"/home/me/main/.git\". Pass --git-mount=off to launch without automatic Git metadata \
         mounts."
    );

    // The shadowed-declaration refusal names both origins and its own remedy.
    assert_eq!(
        render(Refusal::ShadowedDeclaration {
            metadata: PathBuf::from("/home/me/repos/main/.git"),
            role: crate::mount::GitMetadataRole::Common,
            declaration: crate::mount::MountOrigin::Cli,
        }),
        "linked worktree metadata for \"/home/me/wt\" cannot be mounted at its host paths: the \
         automatic Git metadata mount (common directory) at \"/home/me/repos/main/.git\" would \
         shadow --mount, which does not hand the guest that same directory. Pass \
         --git-mount=off to launch without automatic Git metadata mounts."
    );
}

/// U7b. A pointer path that carries a control byte cannot forge a second line
/// (§`pointer_accepts`), and the rendering that carries it into a message cannot
/// either.
#[test]
fn a_refusal_reason_cannot_forge_a_line() {
    let render = |reason: Refusal| {
        GitMetadataError {
            worktree: PathBuf::from("/home/me/wt"),
            reason,
        }
        .to_string()
    };
    let rendered = render(Refusal::MissingCommonDir {
        common: PathBuf::from("/home/me/x\nError: forged"),
    });
    assert!(!rendered.contains('\n'), "{rendered}");
    assert!(rendered.contains("\\x0aError: forged"), "{rendered}");
}

// ---------------------------------------------------------------------------
// U8 — the core-source measurement
// ---------------------------------------------------------------------------

/// U8. The core sources are created *after* discovery, so the containment check
/// has to canonicalize what exists and re-append what does not: otherwise a
/// symlinked ancestor — `$TMPDIR` on macOS, or a deliberately aliased state root —
/// makes the comparison miss exactly the case it exists for.
#[test]
fn canonical_host_source_resolves_the_deepest_existing_ancestor() {
    let root = tempfile::tempdir().unwrap();
    // `real` is a name the `vstd` prelude owns, so the local is `canonical_root`.
    let canonical_root = root.path().canonicalize().unwrap();
    std::fs::create_dir(canonical_root.join("target")).unwrap();
    let alias = canonical_root.join("alias");
    std::os::unix::fs::symlink(canonical_root.join("target"), &alias).unwrap();

    // An existing path is fully canonical.
    assert_eq!(canonical_host_source(&alias), canonical_root.join("target"));
    // A missing leaf under a symlinked ancestor still names the real directory.
    assert_eq!(
        canonical_host_source(&alias.join("state/hash")),
        canonical_root.join("target/state/hash")
    );
    // Nothing existable: the spelling is kept rather than guessed at.
    let absent = Path::new("/nonexistent-avm-535/x");
    assert_eq!(canonical_host_source(absent), absent);
}
