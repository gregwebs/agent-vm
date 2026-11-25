//! Writable live binds must not let a guest author a later launch's authority
//! in `~/.config/agent-vm` (ADR-0038). The walk is trusted I/O; the four
//! boundary decisions below carry contracts independently of that walk.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use vstd::prelude::*;

use crate::config;
use crate::mount::{Declaration, Spelling};
use crate::protected_host_files::{CoreBind, CoreHostSource};

verus! {
pub open spec fn authority_file_singly_linked_spec(nlink: u64) -> bool { nlink == 1u64 }

pub fn authority_file_singly_linked(nlink: u64) -> (r: bool)
    ensures r == authority_file_singly_linked_spec(nlink),
{ nlink == 1 }

pub open spec fn plain_byte(c: u8) -> bool {
    (0x30u8 <= c && c <= 0x39u8) || (0x41u8 <= c && c <= 0x5Au8)
        || (0x61u8 <= c && c <= 0x7Au8) || c == 0x2Eu8 || c == 0x2Du8 || c == 0x5Fu8
}
pub open spec fn plain(n: Seq<u8>) -> bool {
    n.len() > 0 && n[n.len() - 1] != 0x2Eu8
        && forall|i: int| 0 <= i < n.len() ==> plain_byte(n[i])
}
pub open spec fn ascii_fold(c: u8) -> u8 {
    if 0x41u8 <= c && c <= 0x5Au8 { (c + 0x20u8) as u8 } else { c }
}
pub open spec fn names_may_match(a: Seq<u8>, b: Seq<u8>) -> bool {
    !plain(a) || !plain(b) || (a.len() == b.len()
        && forall|i: int| 0 <= i < a.len() ==> ascii_fold(a[i]) == ascii_fold(b[i]))
}
#[allow(clippy::manual_range_contains, clippy::len_zero)]
fn name_is_plain(n: &[u8]) -> (r: bool)
    ensures r == plain(n@),
{
    if n.len() == 0 || n[n.len() - 1] == b'.' { return false; }
    let mut i = 0;
    while i < n.len()
        invariant i <= n.len(), n.len() > 0, n@[n@.len() - 1] != 0x2Eu8,
            forall|j: int| 0 <= j < i ==> plain_byte(n@[j]),
        decreases n.len() - i,
    {
        let c = n[i];
        if !((b'0' <= c && c <= b'9') || (b'A' <= c && c <= b'Z')
            || (b'a' <= c && c <= b'z') || c == b'.' || c == b'-' || c == b'_') {
            return false;
        }
        i += 1;
    }
    true
}
#[allow(clippy::manual_range_contains)]
fn fold_byte(c: u8) -> (r: u8)
    ensures r == ascii_fold(c),
{
    if b'A' <= c && c <= b'Z' { c + 32 } else { c }
}
/// This proves the stated conservative rule, not a filesystem's equivalence.
pub fn may_name_same_entry(a: &[u8], b: &[u8]) -> (r: bool)
    ensures r == names_may_match(a@, b@),
{
    if !name_is_plain(a) || !name_is_plain(b) { return true; }
    if a.len() != b.len() { return false; }
    let mut i = 0;
    while i < a.len()
        invariant i <= a.len(), a.len() == b.len(), plain(a@), plain(b@),
            forall|j: int| 0 <= j < i ==> ascii_fold(a@[j]) == ascii_fold(b@[j]),
        decreases a.len() - i,
    {
        if fold_byte(a[i]) != fold_byte(b[i]) { return false; }
        i += 1;
    }
    true
}
pub open spec fn may_be_prefix(src: Seq<Seq<u8>>, dst: Seq<Seq<u8>>) -> bool {
    src.len() <= dst.len() && forall|i: int| 0 <= i < src.len() ==> names_may_match(src[i], dst[i])
}
fn components_may_prefix(src: &[Vec<u8>], dst: &[Vec<u8>]) -> (r: bool)
    ensures r == may_be_prefix(src.deep_view(), dst.deep_view()),
{
    if src.len() > dst.len() { return false; }
    let mut i = 0;
    while i < src.len()
        invariant i <= src.len(), src.len() <= dst.len(),
            forall|j: int| 0 <= j < i ==> names_may_match(src.deep_view()[j], dst.deep_view()[j]),
        decreases src.len() - i,
    {
        proof {
            // The nested deep view maps bytes too; connect it to the slice contract's shallow view.
            assert(src.deep_view()[i as int] =~= src@[i as int]@);
            assert(dst.deep_view()[i as int] =~= dst@[i as int]@);
        }
        if !may_name_same_entry(&src[i], &dst[i]) { return false; }
        i += 1;
    }
    true
}
pub open spec fn same_anchor(a_id: (u64, u64), a: Seq<Seq<u8>>, b_id: (u64, u64), b: Seq<Seq<u8>>) -> bool {
    a_id == b_id || (a.len() == b.len() && may_be_prefix(a, b))
}
pub open spec fn prospectively_exposed(src_id: (u64, u64), src_anchor: Seq<Seq<u8>>, src_suffix: Seq<Seq<u8>>,
                                     id: (u64, u64), anchor: Seq<Seq<u8>>, suffix: Seq<Seq<u8>>) -> bool {
    same_anchor(src_id, src_anchor, id, anchor) && may_be_prefix(src_suffix, suffix)
}
pub fn exposing_prospective(src_id: (u64, u64), src_anchor: &[Vec<u8>], src_suffix: &[Vec<u8>],
                            ids: &[(u64, u64)], anchors: &[Vec<Vec<u8>>], suffixes: &[Vec<Vec<u8>>]) -> (r: Option<usize>)
    requires ids.len() == anchors.len(), anchors.len() == suffixes.len(),
    ensures match r {
        None => forall|j: int| 0 <= j < ids@.len() ==>
            !prospectively_exposed(src_id, src_anchor.deep_view(), src_suffix.deep_view(), ids@[j], anchors.deep_view()[j], suffixes.deep_view()[j]),
        Some(i) => i < ids@.len()
            && prospectively_exposed(src_id, src_anchor.deep_view(), src_suffix.deep_view(), ids@[i as int], anchors.deep_view()[i as int], suffixes.deep_view()[i as int])
            && forall|j: int| 0 <= j < i as int ==>
                !prospectively_exposed(src_id, src_anchor.deep_view(), src_suffix.deep_view(), ids@[j], anchors.deep_view()[j], suffixes.deep_view()[j]),
    },
{
    let mut j = 0;
    while j < ids.len()
        invariant j <= ids.len(), ids.len() == anchors.len(), anchors.len() == suffixes.len(),
            forall|k: int| 0 <= k < j ==>
                !prospectively_exposed(src_id, src_anchor.deep_view(), src_suffix.deep_view(), ids@[k], anchors.deep_view()[k], suffixes.deep_view()[k]),
        decreases ids.len() - j,
    {
        let anchor_paths_match = src_anchor.len() == anchors[j].len()
            && components_may_prefix(src_anchor, &anchors[j]);
        if (src_id == ids[j] || anchor_paths_match) && components_may_prefix(src_suffix, &suffixes[j]) {
            return Some(j);
        }
        j += 1;
    }
    None
}
pub open spec fn entry_exposed(root: Seq<u8>, root_id: Option<(u64, u64)>, id: Option<(u64, u64)>, path: Seq<u8>) -> bool {
    (root_id.is_some() && id == root_id) || root =~= path || config::is_separator_prefix(root, path)
}
pub fn exposing_entry(root: &[u8], root_id: Option<(u64, u64)>, ids: &[Option<(u64, u64)>], paths: &[&[u8]]) -> (r: Option<usize>)
    requires ids.len() == paths.len(),
    ensures match r {
        None => forall|j: int| 0 <= j < ids@.len() ==> !entry_exposed(root@, root_id, ids@[j], paths@[j]@),
        Some(i) => i < ids@.len() && entry_exposed(root@, root_id, ids@[i as int], paths@[i as int]@)
            && forall|j: int| 0 <= j < i as int ==> !entry_exposed(root@, root_id, ids@[j], paths@[j]@),
    },
{
    let mut i = 0;
    while i < ids.len()
        invariant i <= ids.len(), ids.len() == paths.len(),
            forall|j: int| 0 <= j < i ==> !entry_exposed(root@, root_id, ids@[j], paths@[j]@),
        decreases ids.len() - i,
    {
        if (root_id.is_some() && ids[i] == root_id) || config::byte_path_contains(root, paths[i]) { return Some(i); }
        i += 1;
    }
    None
}
}

/// Which host-only store a measured directory is.
///
/// The purpose decides the wording of a refusal and its remedy, and it is what
/// separates the ADR-0038 authority store (one per `$HOME`, measured with a
/// `home`) from the ADR-0064 stores that join it afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StorePurpose {
    /// `$HOME/.config/agent-vm`: the launch authority a guest must not author.
    LaunchAuthority,
    /// `<state root>/<hash>.sessions`: this project's refusal records and
    /// control sockets (ADR-0064).
    ProjectSessions,
    /// `MSB_HOME`: the runtime's own writable state, where every sandbox's
    /// `network.log` is written (ADR-0064, R1).
    RuntimeState,
    /// One non-default `trust = true` config source file and every directory
    /// along its route (ADR-0076 R2.4): the guest must not be able to rewrite a
    /// file a later launch reads as host authority.
    TrustedSource,
}

impl StorePurpose {
    /// The clause that follows "…or a directory agent-vm resolves through to
    /// reach it" in a refusal. Written so the authority store's sentence is
    /// byte-identical to the one it replaced.
    fn clause(self) -> &'static str {
        match self {
            Self::LaunchAuthority => "where agent-vm reads launch authority",
            Self::ProjectSessions => {
                "where agent-vm keeps this project's refusal records and control sockets"
            }
            Self::RuntimeState => "where the sandbox runtime writes its own state",
            Self::TrustedSource => "where a trusted config source is read",
        }
    }
    /// What a guest could plant at a store path that does not exist yet, for the
    /// prospective spelling of the same refusal.
    fn planted(self) -> &'static str {
        match self {
            Self::LaunchAuthority => "authority",
            Self::ProjectSessions => "a refusal record",
            Self::RuntimeState => "runtime state",
            Self::TrustedSource => "a trusted config source",
        }
    }
    /// What a guest that can write the store could do, as the reason a refusal
    /// gives for stopping the launch.
    fn consequence(self) -> &'static str {
        match self {
            Self::LaunchAuthority => "the guest could rewrite that authority for a later launch",
            Self::ProjectSessions => "the guest could forge or erase them",
            Self::RuntimeState => {
                "the guest could forge or erase every sandbox's refusal log, including this \
                 project's"
            }
            Self::TrustedSource => "the guest could rewrite that trusted source for a later launch",
        }
    }
}

/// One host-only store that joins the measured set.
///
/// `path` is a spelling, not a resolved path: `measure` resolves it through the
/// same walk as the authority stores, so a `:fork`/`:ro` bind of a
/// route to a store is refused exactly as a route to the authority dir is (`R1`).
#[derive(Debug, Clone)]
pub(crate) struct Store {
    purpose: StorePurpose,
    path: PathBuf,
}

impl Store {
    pub(crate) fn new(purpose: StorePurpose, path: impl Into<PathBuf>) -> Self {
        Self {
            purpose,
            path: path.into(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProtectedConfigDir {
    dirs: Vec<MeasuredDir>,
    /// `R2`: the `.sessions` directories no bind of *any* mode may name, even
    /// though `R1` exempts `:ro`/`:fork` (D3).
    sessions: Vec<SessionsDir>,
    /// Sibling snapshot scans the shared work budget cut short (D5, R18). Never
    /// fatal, and never silent: the caller prints them as launch notices.
    warnings: Vec<String>,
    cwd: PathBuf,
}
#[derive(Debug)]
struct MeasuredDir {
    spelled: PathBuf,
    /// The home this store's authority dir lives in; `None` for a store that is
    /// not the per-`$HOME` authority dir, whose remedy names the state root.
    home: Option<PathBuf>,
    purpose: StorePurpose,
    /// Every authority store file the one-link check measures, with its link
    /// count: `config.toml` and `allowances.json` (ADR-0065 P7), or a project
    /// store's `config.toml` (ADR-0073).
    authority_file_links: Vec<(PathBuf, u64)>,
    ids: Vec<Option<(u64, u64)>>,
    paths: Vec<Vec<u8>>,
    prospective_ids: Vec<(u64, u64)>,
    prospective_anchors: Vec<Vec<Vec<u8>>>,
    prospective_suffixes: Vec<Vec<Vec<u8>>>,
}

impl MeasuredDir {
    /// A measurement with no routes yet, and no authority file to check. The
    /// routes are [`apply_resolution`]'s, so every caller that resolves a route
    /// records the same ancestry.
    fn empty(spelled: PathBuf, home: Option<PathBuf>, purpose: StorePurpose) -> Self {
        Self {
            spelled,
            home,
            purpose,
            authority_file_links: Vec::new(),
            ids: Vec::new(),
            paths: Vec::new(),
            prospective_ids: Vec::new(),
            prospective_anchors: Vec::new(),
            prospective_suffixes: Vec::new(),
        }
    }
}

/// Everything one [`resolve`] walk recorded, in the three forms a bind is matched
/// against: each traversed directory's identity and resolved path, the store's own
/// spelling (which a symlinked route never equals), and each prospective route.
///
/// Shared by the authority store, every project store and a trusted source — this
/// launch's and another project's — because they must agree on ancestry: a route
/// that follows a symlink records the target, and a measurement that skipped it
/// would let a writable bind of the target rewrite a file agent-vm trusts.
fn apply_resolution(dir: &mut MeasuredDir, resolution: &Resolution) {
    for route in &resolution.routes {
        dir.ids.push(Some((route.dev, route.ino)));
        dir.paths.push(route.path.as_os_str().as_bytes().to_vec());
    }
    dir.ids.push(None);
    dir.paths.push(dir.spelled.as_os_str().as_bytes().to_vec());
    for prospective in &resolution.prospective {
        dir.prospective_ids
            .push((prospective.anchor.dev, prospective.anchor.ino));
        dir.prospective_anchors
            .push(components(&prospective.anchor.path));
        dir.prospective_suffixes
            .push(suffix_components(&prospective.suffix));
        let mut full = prospective.anchor.path.clone();
        for component in &prospective.suffix {
            full.push(component);
        }
        dir.ids.push(None);
        dir.paths.push(full.as_os_str().as_bytes().to_vec());
    }
}

/// A `.sessions` directory, in the three spellings `R2` needs: the resolved
/// path, the directory's own identity, and the anchored lexical path for a
/// root that does not exist yet.
#[derive(Debug)]
struct SessionsDir {
    identity: Option<(u64, u64)>,
    anchored: PathBuf,
}
#[derive(Clone, Debug)]
struct WriteRoute {
    dev: u64,
    ino: u64,
    path: PathBuf,
}
#[derive(Debug)]
struct ProspectiveDir {
    anchor: WriteRoute,
    suffix: Vec<OsString>,
}
struct Resolution {
    routes: Vec<WriteRoute>,
    prospective: Vec<ProspectiveDir>,
    end: (WriteRoute, Vec<OsString>),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Walk {
    Authority,
    ProvisionedSource,
}

fn anchored(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}
fn uncertain(path: &Path) -> String {
    format!(
        "cannot determine whether a mount would expose \"{}\"",
        crate::one_line::path(path)
    )
}
fn route(path: &Path) -> Result<WriteRoute> {
    let m = fs::symlink_metadata(path).with_context(|| uncertain(path))?;
    Ok(WriteRoute {
        dev: m.dev(),
        ino: m.ino(),
        path: path.to_path_buf(),
    })
}
fn record_with_ancestors(routes: &mut Vec<WriteRoute>, path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if !routes.iter().any(|r| r.path == ancestor) {
            routes.push(route(ancestor)?);
        }
    }
    Ok(())
}
/// Owned components let link text be prepended without losing non-UTF-8 names.
fn pending(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::CurDir => Some(OsString::from(".")),
            _ => None,
        })
        .collect()
}
fn resolve(target: &Path, walk: Walk) -> Result<Resolution> {
    if !target.is_absolute() {
        bail!("{}", uncertain(target));
    }
    let mut queue = pending(target);
    let mut cursor = PathBuf::from("/");
    let mut ghost = Vec::new();
    let mut routes = Vec::new();
    let mut prospective = Vec::new();
    let mut hops = 0;
    record_with_ancestors(&mut routes, &cursor)?;
    while let Some(c) = queue.pop_front() {
        if c == "." {
            continue;
        }
        if c == ".." {
            if !ghost.is_empty() {
                if walk == Walk::ProvisionedSource {
                    bail!("{}", uncertain(target));
                }
                ghost.pop();
            } else {
                cursor.pop();
            }
            continue;
        }
        if !ghost.is_empty() {
            prospective.push(ProspectiveDir {
                anchor: route(&cursor)?,
                suffix: ghost.clone(),
            });
            ghost.push(c);
            continue;
        }
        record_with_ancestors(&mut routes, &cursor)?;
        let candidate = cursor.join(&c);
        match fs::symlink_metadata(&candidate) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ghost.push(c),
            Err(e) => return Err(e).with_context(|| uncertain(target)),
            Ok(m) if m.file_type().is_symlink() => {
                hops += 1;
                if hops > 40 {
                    bail!("{}", uncertain(target));
                }
                let text = fs::read_link(&candidate).with_context(|| uncertain(target))?;
                if text.is_absolute() {
                    cursor = PathBuf::from("/");
                }
                let mut front = pending(&text);
                front.append(&mut queue);
                queue = front;
            }
            Ok(m) if m.is_dir() || queue.is_empty() => cursor = candidate,
            Ok(_) => bail!("{}", uncertain(target)),
        }
    }
    if ghost.is_empty() {
        record_with_ancestors(&mut routes, &cursor)?;
    } else {
        prospective.push(ProspectiveDir {
            anchor: route(&cursor)?,
            suffix: ghost.clone(),
        });
    }
    Ok(Resolution {
        routes,
        prospective,
        end: (route(&cursor)?, ghost),
    })
}
fn components(path: &Path) -> Vec<Vec<u8>> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.as_bytes().to_vec()),
            _ => None,
        })
        .collect()
}
fn suffix_components(suffix: &[OsString]) -> Vec<Vec<u8>> {
    suffix.iter().map(|s| s.as_bytes().to_vec()).collect()
}
/// The walk's answer as one path: the deepest existing ancestor it reached,
/// followed by the components that do not exist yet.
///
/// An error rather than a fallback: `resolve` bails on an unreadable or
/// non-absolute root, and the lexical spelling is then an *unverified* answer —
/// returning it would let the caller decide a bind is outside `.sessions` on the
/// strength of a path nothing could check. R1 fails closed the same way
/// (`measure_store` propagates `resolve`), and R2 guards the same boundary.
fn anchored_resolved(cwd: &Path, path: &Path) -> Result<PathBuf> {
    let spelled = anchored(cwd, path);
    let resolution = resolve(&spelled, Walk::Authority)?;
    let mut end = resolution.end.0.path;
    for component in resolution.end.1 {
        end.push(component);
    }
    Ok(end)
}

/// Whether any directory on the way to `path` — `path` itself included — has
/// `identity`, the `(dev, ino)` of this project's `.sessions` directory.
///
/// This is the spelling a canonical prefix cannot see: a bind of
/// `alias/refusals.json` where `alias` *is* `.sessions` under another name. A
/// component that does not exist yet simply contributes no identity, and one that
/// cannot be stated contributes none either — the prefix rule is the one that has
/// to catch that case, and `resolve` has already failed closed on it.
fn under_identity(path: &Path, identity: Option<(u64, u64)>) -> bool {
    let Some(identity) = identity else {
        return false;
    };
    path.ancestors().any(|ancestor| {
        fs::symlink_metadata(ancestor)
            .ok()
            .filter(|metadata| metadata.is_dir())
            .is_some_and(|metadata| (metadata.dev(), metadata.ino()) == identity)
    })
}

/// The ADR-0038 authority directory of one `$HOME`: the one store measured
/// with a `home`, because its remedy names running from a narrower project
/// directory rather than pointing `AGENT_VM_STATE_DIR` elsewhere.
fn measure_authority_store(home: &Path) -> Result<MeasuredDir> {
    let spelled = home.join(config::USER_CONFIG_DIR_RELATIVE);
    let resolution = resolve(&spelled, Walk::Authority)?;
    let authority_file_links = authority_file_links(&spelled, |path| fs::symlink_metadata(path))?;
    // A home may itself be missing; its walk still locates prospective authority.
    let resolved_home = resolve(home, Walk::Authority)?;
    let mut home = resolved_home.end.0.path;
    for c in resolved_home.end.1 {
        home.push(c);
    }
    let mut dir = MeasuredDir::empty(spelled, Some(home), StorePurpose::LaunchAuthority);
    dir.authority_file_links = authority_file_links;
    apply_resolution(&mut dir, &resolution);
    Ok(dir)
}

/// ADR-0038 Decision 2's one-link check, over every authority file that can
/// grant something: `config.toml` and, since ADR-0065, `allowances.json`.
///
/// Both are measured identically because both decide authority, and a second
/// name for either one is a file a guest could write and then unlink before the
/// next launch read it.
fn authority_file_links(
    spelled: &Path,
    lstat: impl Fn(&Path) -> std::io::Result<std::fs::Metadata>,
) -> Result<Vec<(PathBuf, u64)>> {
    file_links(
        spelled,
        &[crate::project_config::CONFIG_FILE, crate::allowances::FILE],
        lstat,
    )
}

/// The one-link measurement over `names` in `dir`, shared by the authority
/// store's two files and a project store's `config.toml` (ADR-0073).
///
/// Three outcomes per file, and the middle one is this function's whole point:
/// a regular file records its link count; a missing file and a non-file are
/// ignored — the *reader* classifies those, as `Damaged` or `Untrusted`; and any
/// other error refuses the launch (ADR-0065 E2). Deferring the uninspectable
/// case to the reader would be wrong for the reason the check exists: not
/// applying the file now does not stop laundering into the *next* launch.
fn file_links(
    dir: &Path,
    names: &[&str],
    lstat: impl Fn(&Path) -> std::io::Result<std::fs::Metadata>,
) -> Result<Vec<(PathBuf, u64)>> {
    let mut links = Vec::new();
    for name in names {
        let file = dir.join(name);
        match lstat(&file) {
            Ok(m) if m.is_file() => links.push((file, m.nlink())),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| uncertain(&file)),
        }
    }
    Ok(links)
}

/// One project store's authority files, measured like the authority store's
/// files (ADR-0073, ADR-0038).
///
/// `config.toml` and `pins.json` are measured by exact name, needing no
/// `read_dir`, so a store whose snapshot scan the budget cut short still has
/// both of them checked. The store's snapshots join them under the names the
/// pin store writes ([`crate::config_pins::is_snapshot_name`], matched
/// case-insensitively so an APFS case variant cannot evade the check) and under
/// the same admittance rules: a regular file, owned by this user, not group- or
/// other-writable, and — via [`ProtectedConfigDir::check_authority_links`] — a
/// single link. A snapshot name occupied by anything else is a file the guard
/// cannot vouch for, so it refuses rather than being skipped.
///
/// `lstat(<entry>/config.toml)` answers `NotADirectory` when the entry itself is
/// not a directory — a regular file, or a symlink to one — and the generic
/// "cannot determine" context then names only the file under it, which no user
/// can act on. The refusal stays: an entry the guard cannot classify is exactly
/// what it must not skip, so the message names the entry and the one remedy.
fn project_store_file_links(entry: &Path, scan: StoreScan<'_>) -> Result<StoreFileLinks> {
    let measured = (|| -> Result<StoreFileLinks> {
        let mut links = file_links(
            entry,
            &[
                crate::project_config::CONFIG_FILE,
                crate::config_pins::PINS_FILE,
            ],
            |path| fs::symlink_metadata(path),
        )?;
        let (snapshots, warning) = snapshot_file_links(entry, scan)?;
        links.extend(snapshots);
        Ok((links, warning))
    })();
    measured.map_err(|error| match error.downcast_ref::<std::io::Error>() {
        Some(e) if e.kind() == std::io::ErrorKind::NotADirectory => anyhow::anyhow!(
            "cannot determine whether a mount would expose {file}: {entry} is not a directory, \
             and every entry of the project store is measured; remove it",
            file = crate::one_line::quoted_path(&entry.join(crate::project_config::CONFIG_FILE)),
            entry = crate::one_line::quoted_path(entry),
        ),
        _ => error,
    })
}

/// One store's measured authority files: the link counts the one-name check
/// consumes, and the bounded-scan warning when this was a sibling's store.
type StoreFileLinks = (Vec<(PathBuf, u64)>, Option<String>);

/// Which store's snapshot scan this is.
///
/// The current launch's own store gets a reservation of its own, taken before
/// any sibling costs anything, and crossing it refuses the launch (D5). Every
/// other store is charged against one cross-home budget, and a scan the budget
/// cut short warns instead of wedging an unrelated project.
enum StoreScan<'a> {
    Current,
    Sibling(&'a mut SiblingWork),
}

/// The one work budget behind [`StoreScan::Sibling`], spanning every home
/// [`ProtectedConfigDir::measure`] visits rather than restarting per home (D5).
///
/// Enumeration and a matched snapshot's `lstat` each cost one unit, because a
/// store packed with junk entries costs the same scan as one packed with
/// snapshots, and a second `$HOME` must not buy another 8192 units.
struct SiblingWork {
    remaining: usize,
}

impl SiblingWork {
    fn new() -> Self {
        Self {
            remaining: MAX_SIBLING_SNAPSHOT_WORK,
        }
    }

    /// Take one unit; `false` means the budget is spent and the scan must stop.
    fn charge(&mut self) -> bool {
        match self.remaining.checked_sub(1) {
            Some(left) => {
                self.remaining = left;
                true
            }
            None => false,
        }
    }
}

/// The one-link counts of every pin snapshot a project store holds, plus the
/// warning when a sibling's scan was bounded (D5, R18).
///
/// Only the entry *name* decides what is a snapshot, so `pins.lock`,
/// `.agent-vm-pin-tmp-*` and a malformed `pin-XYZ.toml` cost enumeration work
/// and are otherwise ignored. A matching name that is not a regular file, or is
/// someone else's or writable by others, refuses: those are exactly the files
/// the pin store itself will not read.
fn snapshot_file_links(entry: &Path, mut scan: StoreScan<'_>) -> Result<StoreFileLinks> {
    let entries = match fs::read_dir(entry) {
        Ok(entries) => entries,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok((Vec::new(), None));
        }
        Err(e) => return Err(e).with_context(|| uncertain(entry)),
    };
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    let mut bounded = false;
    for entry_result in entries {
        let entry_result = entry_result.with_context(|| uncertain(entry))?;
        match &mut scan {
            StoreScan::Current if names.len() >= MAX_PROJECT_STORE_ENTRIES => bail!(
                "{projects}: more than {MAX_PROJECT_STORE_ENTRIES} entries, and this launch \
                 measures every pin snapshot in its own project store; quiesce every agent-vm \
                 process for this project, then remove the confirmed orphan pin-*.toml snapshots \
                 and abandoned .agent-vm-pin-tmp-* files under {store}, and keep pins.json and \
                 pins.lock",
                projects = uncertain(entry),
                store = crate::one_line::quoted_path(entry),
            ),
            StoreScan::Current => {}
            StoreScan::Sibling(work) => {
                if names.len() >= MAX_PROJECT_STORE_ENTRIES || !work.charge() {
                    bounded = true;
                    break;
                }
            }
        }
        names.push(entry_result.file_name());
    }
    // Deterministic across filesystems, so a first-match refusal does not depend
    // on directory hash order.
    names.sort();
    let mut links = Vec::new();
    for name in names {
        if !crate::config_pins::is_snapshot_name(&name) {
            continue;
        }
        match &mut scan {
            StoreScan::Current => {}
            StoreScan::Sibling(work) => {
                if !work.charge() {
                    bounded = true;
                    break;
                }
            }
        }
        let file = entry.join(&name);
        match fs::symlink_metadata(&file) {
            Ok(metadata) if metadata.is_file() => {
                check_snapshot_file(&file, &metadata)?;
                links.push((file, metadata.nlink()));
            }
            // Nothing is there to vouch for: a cleanup unlinked it between the
            // enumeration and the stat.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!(
                "{file}: a source pin snapshot name is not a regular file, and agent-vm will not \
                 launch while a file it cannot vouch for sits where it reads a snapshot; remove it",
                file = crate::one_line::quoted_path(&file),
            ),
            Err(e) => return Err(e).with_context(|| uncertain(&file)),
        }
    }
    let warning = bounded.then(|| {
        format!(
            "==> warning: {store}: the pin snapshot scan was bounded by this launch's limits \
             ({MAX_PROJECT_STORE_ENTRIES} entries per store, {MAX_SIBLING_SNAPSHOT_WORK} units \
             across every other project store), so this store's remaining snapshots were not \
             measured; each snapshot is verified by its own SHA-256 when read",
            store = crate::one_line::quoted_path(entry),
        )
    });
    Ok((links, warning))
}

/// ADR-0040's file admittance rules for a pin snapshot: this user's file, not
/// group- or other-writable. The link count is checked with every other
/// authority file, so all of them answer with one sentence.
fn check_snapshot_file(file: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.uid() != crate::host_paths::current_euid() {
        bail!(
            "{file}: a source pin snapshot is not owned by you, and agent-vm will not launch \
             while it could read someone else's snapshot; remove it",
            file = crate::one_line::quoted_path(file),
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "{file}: a source pin snapshot is group- or other-writable, and agent-vm will not \
             launch while another user could rewrite the baseline it reviews against; make it \
             writable by you only",
            file = crate::one_line::quoted_path(file),
        );
    }
    Ok(())
}

/// One additional host-only store (ADR-0064) measured exactly like the
/// authority directory, so every `R1` predicate applies unchanged.
fn measure_store(spelled: PathBuf, purpose: StorePurpose) -> Result<MeasuredDir> {
    let resolution = resolve(&spelled, Walk::Authority)?;
    let mut dir = MeasuredDir::empty(spelled, None, purpose);
    apply_resolution(&mut dir, &resolution);
    Ok(dir)
}

/// ADR-0076 R2.4: one non-default `trust = true` source, measured like a store so
/// an overlapping writable bind is refused.
///
/// The parent's route walk records every traversed (and prospective) directory,
/// and the file's own `(dev, ino)` is appended so a bind naming the file itself
/// — or a hard link to it — matches too. Its link count joins
/// [`ProtectedConfigDir::check_authority_links`], so a multi-link trusted source
/// is refused at mount-planning time as well as at load time.
fn measure_trusted_source(spelled_file: PathBuf) -> Result<MeasuredDir> {
    let parent = spelled_file
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{}", uncertain(&spelled_file)))?;
    let mut dir = measure_store(parent.to_path_buf(), StorePurpose::TrustedSource)?;
    match fs::symlink_metadata(&spelled_file) {
        Ok(m) => {
            dir.ids.push(Some((m.dev(), m.ino())));
            dir.paths.push(spelled_file.as_os_str().as_bytes().to_vec());
            dir.authority_file_links
                .push((spelled_file.clone(), m.nlink()));
        }
        // Absent is measured by its parent's walk: a `trust = true` source that
        // does not exist is a load error in `config::load`, not a mount error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| uncertain(&spelled_file)),
    }
    dir.spelled = spelled_file;
    Ok(dir)
}

/// Best-effort measurement of a `trust = true` source **another** project
/// declared (ADR-0076 R2.4).
///
/// The sibling's own read resolves its route through every symlinked ancestor
/// (`project_config::open_trusted_source_route`), so this measurement must record
/// what that walk will reach, not what the `[[sources]]` line spells: the parent
/// goes through the same bounded [`resolve`] as this launch's own trusted
/// sources, and every directory it traverses — the target of an owner-controlled
/// symlink included — joins the routes a writable bind is matched against.
/// Recording only the lexical spelling would leave the target's directories
/// unmeasured, which is exactly the bind a guest needs in order to rewrite the
/// file that project's next launch reads as host authority.
///
/// A sibling project's route may be broken or looping, and that must never loop or
/// block this launch: when the walk refuses, the lexical prefix it could stat is
/// recorded plus a prospective entry at the first component it could not, so a
/// writable bind overlapping the prefix is still refused while a disjoint launch
/// proceeds. Launching the broken project itself still fails in its own
/// `config::load`, naming that project's `config.toml`.
fn measure_cross_project_trusted_source(spelled_file: PathBuf) -> MeasuredDir {
    let parent = spelled_file
        .parent()
        .unwrap_or(Path::new("/"))
        .to_path_buf();
    let mut dir = match resolve(&parent, Walk::Authority) {
        Ok(resolution) => {
            let mut dir = MeasuredDir::empty(parent, None, StorePurpose::TrustedSource);
            apply_resolution(&mut dir, &resolution);
            dir
        }
        Err(_) => lexical_ancestors(&spelled_file),
    };
    // The file's own `(dev, ino)`, so a bind naming the file — or a hard link to
    // it — matches. `symlink_metadata`, exactly as `measure_trusted_source`: a
    // `trust = true` read never follows a final symlink, so the link is what a
    // bind of this spelling would reach.
    if let Ok(metadata) = fs::symlink_metadata(&spelled_file) {
        dir.ids.push(Some((metadata.dev(), metadata.ino())));
        dir.paths.push(spelled_file.as_os_str().as_bytes().to_vec());
    }
    dir.spelled = spelled_file;
    dir
}

/// The lexical fallback for a sibling route [`resolve`] refuses: whatever
/// ancestors exist, stat'd by spelling, then one prospective route from the
/// deepest existing ancestor.
///
/// Never an error. An unrelated project's broken, looping or unreadable route is
/// its own load's refusal; this launch only has to stay out of the way while
/// still refusing a writable bind of the prefix it could see.
fn lexical_ancestors(spelled_file: &Path) -> MeasuredDir {
    let mut ids = Vec::new();
    let mut paths = Vec::new();
    let mut prospective_ids = Vec::new();
    let mut prospective_anchors = Vec::new();
    let mut prospective_suffixes = Vec::new();

    let names: Vec<OsString> = spelled_file
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect();
    let mut cursor = PathBuf::from("/");
    if let Ok(m) = fs::symlink_metadata(&cursor) {
        ids.push(Some((m.dev(), m.ino())));
        paths.push(cursor.as_os_str().as_bytes().to_vec());
    }
    let mut failed_at = None;
    for (index, name) in names.iter().enumerate() {
        cursor.push(name);
        match fs::symlink_metadata(&cursor) {
            Ok(m) => {
                ids.push(Some((m.dev(), m.ino())));
                paths.push(cursor.as_os_str().as_bytes().to_vec());
            }
            Err(_) => {
                failed_at = Some(index);
                break;
            }
        }
    }
    if let Some(index) = failed_at {
        let anchor = cursor.parent().unwrap_or(Path::new("/")).to_path_buf();
        if let Some(m) = fs::symlink_metadata(&anchor).ok().filter(|m| m.is_dir()) {
            prospective_ids.push((m.dev(), m.ino()));
            prospective_anchors.push(components(&anchor));
            prospective_suffixes.push(suffix_components(&names[index..]));
        }
        ids.push(None);
        paths.push(spelled_file.as_os_str().as_bytes().to_vec());
    }

    MeasuredDir {
        spelled: spelled_file.to_path_buf(),
        home: None,
        purpose: StorePurpose::TrustedSource,
        authority_file_links: Vec::new(),
        ids,
        paths,
        prospective_ids,
        prospective_anchors,
        prospective_suffixes,
    }
}

/// A fail-closed bound on the entries of one `projects/` directory.
///
/// The guard measures **every** entry, not only this launch's project (ADR-0038's
/// cross-project threat), so its cost grows with the directory: 10,000 empty
/// entries already cost 8 s per launch on a developer laptop. agent-vm creates
/// one directory per project, so a directory this size is not its own doing, and
/// there is no safe way to measure part of it: skipping entries is what
/// launderers a project store into a later launch. Refusing is therefore the same
/// choice ADR-0065 makes for an uninspectable file, with a message that names the
/// directory, the bound and the remedy.
const MAX_PROJECT_STORES: usize = 1024;

/// One project store's bounded directory scan (R18).
///
/// The current launch's own store gets this reservation in full, before any
/// sibling is scanned, and crossing it refuses the launch: this store's pins are
/// its own launch's authority, so a file it cannot measure must not be skipped.
const MAX_PROJECT_STORE_ENTRIES: usize = 2048;

/// The work one launch may spend on **sibling** stores' snapshot scans, one
/// budget for every `$HOME` it measures (D5, R18).
const MAX_SIBLING_SNAPSHOT_WORK: usize = 8192;

/// Stores measured so far, in first-match order, plus the spellings already in
/// them.
///
/// The `BTreeSet` is what keeps the cost of a launch near-linear in the number of
/// stores: every entry of every `projects/` directory is a candidate, and
/// rescanning the `Vec` for each one made the guard quadratic in the entry count.
/// Order stays the `Vec`'s, so a first-match refusal still names the same
/// directory on every filesystem.
#[derive(Default)]
struct MeasuredDirs {
    dirs: Vec<MeasuredDir>,
    spelled: std::collections::BTreeSet<PathBuf>,
}

impl MeasuredDirs {
    /// Keep `dir` unless its spelling was already measured; reports whether it
    /// was kept.
    fn push(&mut self, dir: MeasuredDir) -> bool {
        if !self.spelled.insert(dir.spelled.clone()) {
            return false;
        }
        self.dirs.push(dir);
        true
    }
}

/// The identity of the current launch's project store, and of its `pins.json`.
///
/// A sibling is matched by what a file *is*, never by how its directory is
/// spelled (B4/D5): an APFS case variant of the project digest, or an uppercase
/// spelling of it, is the same store and must not be scanned twice or spend the
/// sibling budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StoreIdentity {
    dir: Option<(u64, u64)>,
    pins: Option<(u64, u64)>,
}

impl StoreIdentity {
    fn of(store: &Path) -> Self {
        Self {
            dir: identity_of(store),
            pins: identity_of(&store.join(crate::config_pins::PINS_FILE)),
        }
    }

    /// Whether `other` is this store: the same directory, or the same
    /// `pins.json`. A hard-linked manifest matches here too, and that can only
    /// save work: the current store's own one-link check refuses it either way.
    fn is(&self, other: &Self) -> bool {
        (self.dir.is_some() && self.dir == other.dir)
            || (self.pins.is_some() && self.pins == other.pins)
    }
}

fn identity_of(path: &Path) -> Option<(u64, u64)> {
    fs::symlink_metadata(path)
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

/// The current launch's project store, measured **first** and by identity
/// (D5/B4).
///
/// Its path comes from the captured project plus the authority HOME, so it is
/// not discovered among `projects/`' entries at all: a case-variant spelling of
/// the entry cannot make it a sibling. Its snapshot scan takes the full 2048-entry
/// reservation before any sibling costs a unit, and its files are checked whether
/// or not the sibling budget is later spent.
fn measure_current_project_store(store: &Path) -> Result<(MeasuredDir, StoreIdentity)> {
    let mut dir = measure_store(store.to_path_buf(), StorePurpose::LaunchAuthority)?;
    let (links, _warning) = project_store_file_links(&dir.spelled, StoreScan::Current)?;
    dir.authority_file_links = links;
    let identity = StoreIdentity::of(&dir.spelled);
    Ok((dir, identity))
}

/// ADR-0073: project configs sit strictly inside the authority directory, where
/// "is or contains a route" alone allows a writable bind of `projects/` or of one
/// project's directory (ADR-0038: a bind strictly inside is allowed). Each is
/// therefore its own measured store: the walk records its routes — through a
/// symlinked entry, to wherever it points — so such a bind is refused, and its
/// `config.toml`, `pins.json` and pin snapshots join the one-name check.
///
/// **Every** existing entry, not only this launch's project: the guard exists so
/// P1's guest cannot plant P2's authority (ADR-0038's cross-project threat). The
/// consequence is deliberate and fails closed: even an unrelated project's
/// uninspectable route or multi-link `config.toml` refuses every launch, because
/// leaving it unmeasured would launder it into a later one.
///
/// The current store — when `current` names it — was already measured, so it is
/// skipped by identity. Every other store's exact `config.toml` and `pins.json`
/// checks and its directory route are measured unconditionally; only its
/// snapshot scan draws on `work`, and one it cannot finish yields a warning
/// rather than refusing an unrelated project.
///
/// A missing entry needs no prospective record: provisioning names are 12-hex
/// state names or fixed words, which the name rule never equates with a 64-hex
/// project id, so no core bind can create one.
fn measure_project_stores(
    home: &Path,
    current: Option<&StoreIdentity>,
    work: &mut SiblingWork,
    warnings: &mut Vec<String>,
) -> Result<Vec<MeasuredDir>> {
    let projects = crate::project_config::projects_dir(home);
    let mut dirs = vec![measure_store(
        projects.clone(),
        StorePurpose::LaunchAuthority,
    )?];
    let entries = match fs::read_dir(&projects) {
        Ok(entries) => entries,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(dirs);
        }
        Err(e) => return Err(e).with_context(|| uncertain(&projects)),
    };
    let mut sorted = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| uncertain(&projects))?;
        if sorted.len() >= MAX_PROJECT_STORES {
            bail!(
                "{}: more than {MAX_PROJECT_STORES} entries, and a launch measures every one; \
                 remove the project directories under it that agent-vm does not use",
                uncertain(&projects),
            );
        }
        sorted.push(entry);
    }
    // Deterministic scan order across filesystems, so a first-match refusal and
    // a link-count error do not depend on directory hash order.
    sorted.sort_by_key(|entry| entry.file_name());
    for entry in sorted {
        let kind = entry
            .file_type()
            .with_context(|| uncertain(&entry.path()))?;
        if !(kind.is_dir() || kind.is_symlink()) {
            continue;
        }
        let spelled = entry.path();
        if current.is_some_and(|current| current.is(&StoreIdentity::of(&spelled))) {
            continue;
        }
        let mut dir = measure_store(spelled, StorePurpose::LaunchAuthority)?;
        let (links, warning) = project_store_file_links(&dir.spelled, StoreScan::Sibling(work))?;
        dir.authority_file_links = links;
        if let Some(warning) = warning {
            warnings.push(warning);
        }
        dirs.push(dir);
    }
    if !dirs.is_empty() {
        dirs.extend(measure_project_trusted_sources(&projects)?);
    }
    Ok(dirs)
}

/// A fail-closed bound on the distinct `trust = true` sources every other project
/// may declare. A host with more is a host this guard will not vouch for.
const MAX_TRUSTED_SOURCES: usize = 256;

/// Every `trust = true` host-anchored source declared by **any** project under
/// `projects/` (ADR-0076 R2.4), so project P1's guest cannot rewrite the trusted
/// source P2 will read on its next launch.
///
/// Paths are extracted syntactically from each `projects/<id>/config.toml`
/// (`config_sources::extract_trusted_non_relative_paths`), so a sibling's broken
/// syntax extracts nothing and a sibling's broken route never loops or blocks this
/// launch: [`measure_cross_project_trusted_source`] is bounded and best-effort.
fn measure_project_trusted_sources(projects: &Path) -> Result<Vec<MeasuredDir>> {
    let Ok(entries) = fs::read_dir(projects) else {
        return Ok(Vec::new());
    };
    let mut sorted: Vec<_> = entries
        .filter_map(|entry| entry.ok())
        .take(MAX_PROJECT_STORES)
        .collect();
    sorted.sort_by_key(|entry| entry.file_name());
    let mut seen = std::collections::BTreeSet::new();
    let mut measured = Vec::new();
    for entry in sorted {
        let config = entry.path().join(crate::project_config::CONFIG_FILE);
        let Ok((bytes, _)) = crate::host_paths::read_bounded_regular_file_no_follow(
            &config,
            crate::config::MAX_CONFIG_FILE_BYTES,
        ) else {
            // An absent, symlinked or unreadable sibling `config.toml` is already
            // measured as a store, and its own load reports the problem.
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        // `projects` is `<home>/.config/agent-vm/projects`.
        let home = projects
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .unwrap_or(Path::new("/"));
        for path in crate::config_sources::extract_trusted_non_relative_paths(text, home) {
            if !seen.insert(path.clone()) {
                continue;
            }
            if seen.len() > MAX_TRUSTED_SOURCES {
                bail!(
                    "{}: more than {MAX_TRUSTED_SOURCES} distinct trust = true config sources, and a \
                     launch measures every one; remove the trust = true declarations agent-vm does \
                     not use under {}",
                    uncertain(projects),
                    crate::one_line::quoted_path(projects),
                );
            }
            measured.push(measure_cross_project_trusted_source(path));
        }
    }
    Ok(measured)
}

impl ProtectedConfigDir {
    /// Measure the authority stores (one per `$HOME`), this launch's own project
    /// store, the other project stores under each home (ADR-0073), every
    /// `trust = true` source this launch reads (ADR-0076 R2.4), and the extra
    /// host-only stores this launcher writes refusal artefacts into (ADR-0064).
    ///
    /// Two passes over `homes` on purpose: every home's top-level
    /// `~/.config/agent-vm` is measured before *any* project store, so a
    /// project-store route in a raw `$HOME` cannot outrank the account home's
    /// authority store in [`Self::decide`]'s first-match scan. The current
    /// launch's own project store is measured between the two, before any sibling
    /// is scanned, so its 2048-entry reservation is spent first (D5).
    ///
    /// `project_store` is the current launch's store, carried from the captured
    /// project and the authority HOME (D5/B4). It is measured directly rather
    /// than found among `projects/`' entries, and the sibling scan recognises it
    /// by identity, so a case-variant spelling cannot make it a sibling.
    pub(crate) fn measure(
        homes: &[PathBuf],
        stores: &[Store],
        trusted_sources: &[PathBuf],
        project_store: Option<&Path>,
        cwd: &Path,
    ) -> Result<Self> {
        let mut dirs = MeasuredDirs::default();
        let mut unique_homes: Vec<PathBuf> = Vec::new();
        for home in homes {
            let home = anchored(cwd, home);
            let dir = measure_authority_store(&home)?;
            if dirs.push(dir) {
                unique_homes.push(home);
            }
        }
        let mut work = SiblingWork::new();
        let mut warnings = Vec::new();
        let current = match project_store {
            Some(store) => {
                let (dir, identity) = measure_current_project_store(&anchored(cwd, store))?;
                dirs.push(dir);
                Some(identity)
            }
            None => None,
        };
        for home in &unique_homes {
            for project_store in
                measure_project_stores(home, current.as_ref(), &mut work, &mut warnings)?
            {
                dirs.push(project_store);
            }
        }
        // A source inside `~/.config/agent-vm` is already covered by that store's
        // own measurement, and measuring it twice would only change which
        // refusal answers first.
        let covered: Vec<PathBuf> = unique_homes
            .iter()
            .map(|home| home.join(crate::config::USER_CONFIG_DIR_RELATIVE))
            .collect();
        for source in trusted_sources {
            let spelled = anchored(cwd, source);
            if covered.iter().any(|dir| spelled.starts_with(dir)) {
                continue;
            }
            dirs.push(measure_trusted_source(spelled)?);
        }
        let mut sessions: Vec<SessionsDir> = Vec::new();
        for store in stores {
            let dir = measure_store(anchored(cwd, &store.path), store.purpose)?;
            let spelled = dir.spelled.clone();
            if !dirs.push(dir) {
                continue;
            }
            if store.purpose == StorePurpose::ProjectSessions {
                sessions.push(SessionsDir {
                    identity: fs::symlink_metadata(&spelled)
                        .ok()
                        .filter(|m| m.is_dir())
                        .map(|m| (m.dev(), m.ino())),
                    anchored: anchored_resolved(cwd, &spelled)?,
                });
            }
        }
        Ok(Self {
            dirs: dirs.dirs,
            sessions,
            warnings,
            cwd: cwd.to_path_buf(),
        })
    }

    /// The sibling snapshot scans the shared budget cut short (D5, R18), each as
    /// a complete notice line. A launch prints them; a test asserts on them.
    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
    pub(crate) fn check_authority_links(&self) -> Result<()> {
        for d in &self.dirs {
            for (file, n) in &d.authority_file_links {
                if !authority_file_singly_linked(*n) {
                    bail!(
                        "\"{}\" has {n} hard links; agent-vm will not launch while another name for it could be written from a guest and then removed; review the file's launch-authorizing contents, then remove its other names before launching.",
                        crate::one_line::path(file)
                    );
                }
            }
        }
        Ok(())
    }
    fn decide(
        &self,
        spelled: Option<&Path>,
        root: &Path,
        root_id: Option<(u64, u64)>,
    ) -> Option<&MeasuredDir> {
        self.dirs.iter().find(|d| {
            let paths: Vec<&[u8]> = d.paths.iter().map(Vec::as_slice).collect();
            exposing_entry(root.as_os_str().as_bytes(), root_id, &d.ids, &paths).is_some()
                || spelled
                    .filter(|s| !s.components().any(|c| c == Component::ParentDir))
                    .is_some_and(|s| {
                        exposing_entry(s.as_os_str().as_bytes(), None, &d.ids, &paths).is_some()
                    })
        })
    }
    fn decide_prospective(&self, anchor: &WriteRoute, suffix: &[OsString]) -> Option<&MeasuredDir> {
        let a = components(&anchor.path);
        let s = suffix_components(suffix);
        self.dirs.iter().find(|d| {
            exposing_prospective(
                (anchor.dev, anchor.ino),
                &a,
                &s,
                &d.prospective_ids,
                &d.prospective_anchors,
                &d.prospective_suffixes,
            )
            .is_some()
        })
    }
    pub(crate) fn check_core_bind(&self, source: &CoreHostSource) -> Result<()> {
        let root = anchored(&self.cwd, &source.path);
        match fs::metadata(&root) {
            Ok(m) => {
                let canonical = fs::canonicalize(&root).with_context(|| uncertain(&root))?;
                if let Some(d) = self.decide(Some(&root), &canonical, Some((m.dev(), m.ino()))) {
                    bail!(
                        "agent-vm's {} \"{}\" is, or contains, \"{}\" or a directory agent-vm resolves through to reach it, {}; {}. {}",
                        source.bind.description(),
                        crate::one_line::path(&root),
                        crate::one_line::path(&d.spelled),
                        d.purpose.clause(),
                        d.purpose.consequence(),
                        remedy(source.bind, &canonical, d.purpose, d.home.as_deref())
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (anchor, suffix) = resolve(&root, Walk::ProvisionedSource)?.end;
                if suffix.is_empty() {
                    bail!("{}", uncertain(&root));
                }
                if let Some(d) = self.decide_prospective(&anchor, &suffix) {
                    bail!(
                        "agent-vm's {} \"{}\" does not exist yet; once created it could be, or contain, a directory in which agent-vm looks up names on the way to \"{}\", {}, so the guest could plant {} there for a later launch. (Names that do not exist yet are compared ignoring letter case, and a name ending in '.' or containing characters other than ASCII letters, digits, '.', '-' or '_' is assumed to match any name.) {}",
                        source.bind.description(),
                        crate::one_line::path(&root),
                        crate::one_line::path(&d.spelled),
                        d.purpose.clause(),
                        d.purpose.planted(),
                        remedy(source.bind, &root, d.purpose, d.home.as_deref())
                    );
                }
            }
            Err(e) => return Err(e).with_context(|| uncertain(&root)),
        }
        Ok(())
    }
    /// Refuse a writable live bind that could change, or change what something
    /// resolves to, where agent-vm reads its launch authority. `subject` names
    /// the declaration: `--mount` for argv, the config entry's own
    /// `mounts[N] in "<file>"` for a verified user entry.
    ///
    /// `declaration` decides how the spelling is quoted: an argv `--mount` keeps
    /// its byte-pinned `{:?}` rendering and a config entry its byte-escaped
    /// `mounts[N] in "<file>"` attribution ([`Spelling::render_quoted`]), so one
    /// declaration cannot print two ways depending on which refusal fires.
    pub(crate) fn check_writable_mount(
        &self,
        declaration: Declaration<'_>,
        spelling: &Spelling,
        spelled_host: &Path,
        host: &Path,
    ) -> Result<()> {
        let subject = declaration.subject();
        match fs::metadata(host) {
            Ok(m) => {
                let canonical = fs::canonicalize(host).with_context(|| uncertain(host))?;
                if let Some(d) =
                    self.decide(Some(spelled_host), &canonical, Some((m.dev(), m.ino())))
                {
                    // `render_quoted` escapes, so these bytes are never printed raw.
                    let declared = spelling.render_quoted(declaration);
                    bail!(
                        "{subject} {declared} would let the guest change what {} contains or resolves to, {}. Mount it read-only (:ro), or mount a narrower path that does not contain it.",
                        crate::one_line::quoted_path(&d.spelled),
                        d.purpose.clause()
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| uncertain(host)),
        }
        Ok(())
    }

    /// The `.sessions` directory a bind root names or lies inside, if any.
    ///
    /// `R2` (ADR-0064) is deliberately separate from `R1`: `exposing_entry`
    /// decides *is or contains* for a **writable** bind only, and D3 keeps
    /// `:ro`/`:fork` ancestors exempt. A bind *at or inside* `.sessions` can
    /// name one `refusals.json`, `refusals.lock` or socket whatever its mode, so
    /// it is refused in every mode. Three spellings of "inside", because the
    /// directory may not exist yet:
    ///
    /// - the resolved path is `.sessions` or a separator-prefixed descendant;
    /// - the root *is* the directory, by `(dev, ino)` even under another name;
    /// - an ancestor of the root has that `(dev, ino)`, so the root is inside
    ///   `.sessions` reached through an alias;
    /// - for a root that does not exist, the anchored lexical path is inside.
    ///
    /// The two resolved spellings need `resolve`, which fails closed: a path it
    /// cannot read is an error here, not a bind allowed on an unverified spelling.
    pub(crate) fn sessions_dir_named_by(&self, host: &Path) -> Result<Option<&Path>> {
        let anchored_host = anchored_resolved(&self.cwd, host)?;
        let host_bytes = anchored_host.as_os_str().as_bytes();
        let identity = fs::symlink_metadata(&anchored_host)
            .ok()
            .filter(|m| m.is_dir())
            .map(|m| (m.dev(), m.ino()));
        Ok(self
            .sessions
            .iter()
            .find(|sessions| {
                let named_by_identity = identity.is_some() && identity == sessions.identity;
                let inside = config::byte_path_contains(
                    sessions.anchored.as_os_str().as_bytes(),
                    host_bytes,
                );
                named_by_identity || inside || under_identity(&anchored_host, sessions.identity)
            })
            .map(|sessions| sessions.anchored.as_path()))
    }

    /// Refuse a core bind, in any mode, that names this project's `.sessions`
    /// directory or anything in it (`R2`, ADR-0064).
    pub(crate) fn check_core_bind_names_sessions(&self, source: &CoreHostSource) -> Result<()> {
        let root = anchored(&self.cwd, &source.path);
        if let Some(sessions) = self.sessions_dir_named_by(&root)? {
            bail!(
                "agent-vm's {} \"{}\" is, or lies inside, \"{}\", where agent-vm keeps this \
                 project's refusal records and control socket; the guest could forge or erase \
                 them. {}",
                source.bind.description(),
                crate::one_line::path(&root),
                crate::one_line::path(sessions),
                remedy(source.bind, &root, StorePurpose::ProjectSessions, None)
            );
        }
        Ok(())
    }

    /// Refuse a mount declaration, in any mode, that names this project's
    /// `.sessions` directory or anything in it (`R2`, ADR-0064).
    pub(crate) fn check_mount_names_sessions(
        &self,
        declaration: Declaration<'_>,
        spelling: &Spelling,
        host: &Path,
    ) -> Result<()> {
        let Some(sessions) = self.sessions_dir_named_by(host)? else {
            return Ok(());
        };
        // `render_quoted` escapes, so these bytes are never printed raw.
        let declared = spelling.render_quoted(declaration);
        bail!(
            "{} {declared} is, or lies inside, \"{}\", where agent-vm keeps this project's \
             refusal records and control socket, so the guest could forge or erase them. Mount \
             a path that does not include it.",
            declaration.subject(),
            crate::one_line::quoted_path(sessions)
        );
    }
}
fn remedy(bind: CoreBind, root: &Path, purpose: StorePurpose, home: Option<&Path>) -> &'static str {
    // A store that is not the per-`$HOME` authority dir is agent-vm's own state
    // (ADR-0064). There is no narrower project directory to offer when the
    // state root itself sits inside the project, so the remedy is the documented
    // move (USAGE, "Moving the state root").
    if purpose != StorePurpose::LaunchAuthority && bind == CoreBind::ProjectDir {
        return "Move agent-vm's state root outside the project (see \"Moving the state root\" in USAGE.md), or run agent-vm from a directory that does not contain it.";
    }
    match bind {
        CoreBind::ProjectDir if Some(root) == home => {
            "Run agent-vm from a project directory instead of $HOME."
        }
        CoreBind::ProjectDir => "Run agent-vm from a directory that does not contain it.",
        CoreBind::StateDir | CoreBind::GuestHome => {
            "Point AGENT_VM_STATE_DIR at a directory that does not contain it."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn plain_oracle(n: &[u8]) -> bool {
        !n.is_empty()
            && !n.ends_with(b".")
            && n.iter()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
    }
    fn name_oracle(a: &[u8], b: &[u8]) -> bool {
        !plain_oracle(a) || !plain_oracle(b) || a.eq_ignore_ascii_case(b)
    }
    fn prefix_oracle(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
        a.len() <= b.len() && a.iter().zip(b).all(|(a, b)| name_oracle(a, b))
    }
    fn cs(parts: &[&str]) -> Vec<Vec<u8>> {
        parts.iter().map(|p| p.as_bytes().to_vec()).collect()
    }
    /// One snapshot file name in the store's canonical shape, so a test names a
    /// file the guard must measure rather than one it may ignore.
    fn snapshot_for_tests() -> String {
        crate::config_pins::snapshot_name(
            crate::config_pins::StoreId::parse_hex(&"b".repeat(32)).unwrap(),
            &crate::config_pins::ContentHash::of(b"snapshot"),
        )
    }
    #[test]
    fn name_equivalence_table() {
        for (a, b) in [
            ("ab12", "ab12"),
            ("ab12", "AB12"),
            ("home", "HOME"),
            (".config", ".CONFIG"),
            ("ﬀ12", "ff12"),
            ("é", "e\u{301}"),
            ("Kx", "kx"),
            ("a b", "zz"),
            ("ab~1", "zz"),
            ("ab.", "ab"),
            ("a:b", "zz"),
            ("", "zz"),
        ] {
            assert!(may_name_same_entry(a.as_bytes(), b.as_bytes()), "{a}/{b}");
        }
        assert!(may_name_same_entry(&[255], b"zz"));
        for (a, b) in [("ab12", "ab13"), ("agent-vm", "agent_vm"), ("ab", "abc")] {
            assert!(!may_name_same_entry(a.as_bytes(), b.as_bytes()));
        }
        for n in [0, 1, 2, 3, u64::MAX] {
            assert_eq!(authority_file_singly_linked(n), n == 1);
        }
    }
    /// ADR-0065 E1/E2: both authority files are measured, an uninspectable one
    /// refuses, and a missing or non-file one is left to the reader.
    ///
    /// The injected `lstat` is the whole point: the ordinary read error (EACCES
    /// on an unreadable file) must *not* be what this asserts, so the cases
    /// below separate a failing `lstat` from a present-but-unreadable file.
    #[test]
    fn authority_file_links_measures_both_files_and_refuses_an_uninspectable_one() {
        use std::io::{Error, ErrorKind};
        let dir = Path::new("/authority");
        let exists = |name: &str, nlink: u64| {
            let name = name.to_owned();
            move |path: &Path| {
                if path == dir.join(&name) {
                    // A real regular file, then a hard link to it, so the mode
                    // and link count come from the kernel rather than a stub.
                    let root = tempfile::tempdir().unwrap();
                    let file = root.path().join("f");
                    std::fs::write(&file, b"").unwrap();
                    let alias = root.path().join("alias");
                    for _ in 1..nlink {
                        std::fs::hard_link(&file, &alias).unwrap();
                    }
                    std::fs::symlink_metadata(&file)
                } else {
                    Err(Error::from(ErrorKind::NotFound))
                }
            }
        };
        // Neither file: nothing measured, no error.
        assert!(
            authority_file_links(dir, |_| Err(Error::from(ErrorKind::NotFound)))
                .unwrap()
                .is_empty()
        );
        // `config.toml` alone, singly named: measured, and the guard passes.
        assert_eq!(
            authority_file_links(dir, exists("config.toml", 1)).unwrap(),
            vec![(dir.join("config.toml"), 1)]
        );
        // The store's own name, from the one place it is spelled: the ADR-0065
        // addition. The guard measures `allowances::FILE`, so a rename cannot
        // leave it looking at a path the reader never opens.
        assert_eq!(
            authority_file_links(dir, exists(crate::allowances::FILE, 1)).unwrap(),
            vec![(dir.join(crate::allowances::FILE), 1)]
        );
        // A second name for it is recorded, and the guard refuses.
        let links = authority_file_links(dir, exists(crate::allowances::FILE, 2)).unwrap();
        assert_eq!(links, vec![(dir.join(crate::allowances::FILE), 2)]);
        let guard = ProtectedConfigDir {
            dirs: vec![MeasuredDir {
                spelled: dir.to_path_buf(),
                home: None,
                purpose: StorePurpose::LaunchAuthority,
                authority_file_links: links,
                ids: Vec::new(),
                paths: Vec::new(),
                prospective_ids: Vec::new(),
                prospective_anchors: Vec::new(),
                prospective_suffixes: Vec::new(),
            }],
            sessions: Vec::new(),
            warnings: Vec::new(),
            cwd: "/".into(),
        };
        let error = guard.check_authority_links().unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "\"{}\" has 2 hard links; agent-vm will not launch while another name for it could be written from a guest and then removed; review the file's launch-authorizing contents, then remove its other names before launching.",
                crate::one_line::path(&dir.join(crate::allowances::FILE))
            )
        );
        // An uninspectable file refuses, naming it (E2).
        let error = authority_file_links(dir, |path| {
            if path == dir.join("config.toml") {
                std::fs::symlink_metadata(tempfile::tempdir().unwrap().path())
            } else {
                Err(Error::from(ErrorKind::PermissionDenied))
            }
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains(crate::allowances::FILE), "{error}");
        assert!(
            error.contains("cannot determine whether a mount would expose"),
            "{error}"
        );
        // A non-file is not this check's business: the reader classifies it.
        let links = authority_file_links(dir, |path| {
            if path == dir.join(crate::allowances::FILE) {
                std::fs::symlink_metadata(tempfile::tempdir().unwrap().path())
            } else {
                Err(Error::from(ErrorKind::NotFound))
            }
        })
        .unwrap();
        assert!(links.is_empty(), "{links:?}");
    }

    #[test]
    fn existing_entry_table() {
        let ids = [Some((1, 2)), None, Some((3, 4))];
        let paths: [&[u8]; 3] = [b"/else", b"/home/config", b"/home/config/sub"];
        assert_eq!(
            exposing_entry(b"/disjoint", Some((1, 2)), &ids, &paths),
            Some(0)
        );
        assert_eq!(
            exposing_entry(b"/home", Some((9, 9)), &ids, &paths),
            Some(1)
        );
        assert_eq!(exposing_entry(b"/disjoint", None, &ids, &paths), None);
        assert_eq!(exposing_entry(b"/homex", Some((9, 9)), &ids, &paths), None);
        assert_eq!(exposing_entry(b"/home/config", None, &ids, &paths), Some(1));
    }
    #[test]
    fn prospective_table_and_adapter() {
        let ids = [(1, 2), (1, 2)];
        let anchors = vec![cs(&["other"]), cs(&["else"])];
        let suffixes = vec![cs(&["ab12", "home", ".config"]), cs(&["ab12", "home"])];
        for suffix in [
            cs(&["ab12", "home"]),
            cs(&["AB12", "HOME"]),
            cs(&["ﬀ12", "home"]),
        ] {
            assert_eq!(
                exposing_prospective((1, 2), &cs(&["alias"]), &suffix, &ids, &anchors, &suffixes),
                Some(0)
            );
        }
        for suffix in [
            cs(&["ab13"]),
            cs(&["ab"]),
            cs(&["ab12", "home", ".config", "more"]),
        ] {
            assert_eq!(
                exposing_prospective((1, 2), &cs(&["alias"]), &suffix, &ids, &anchors, &suffixes),
                None
            );
        }
        assert_eq!(
            exposing_prospective(
                (9, 9),
                &cs(&["OTHER"]),
                &cs(&["ab12"]),
                &ids,
                &anchors,
                &suffixes
            ),
            Some(0)
        );
        assert_eq!(
            exposing_prospective(
                (9, 9),
                &cs(&["different"]),
                &cs(&["ab12"]),
                &ids,
                &anchors,
                &suffixes
            ),
            None
        );
        let d = MeasuredDir {
            spelled: "/authority".into(),
            home: Some("/home".into()),
            purpose: StorePurpose::LaunchAuthority,
            authority_file_links: Vec::new(),
            ids: vec![],
            paths: vec![],
            prospective_ids: ids.to_vec(),
            prospective_anchors: anchors,
            prospective_suffixes: suffixes,
        };
        let guard = ProtectedConfigDir {
            dirs: vec![d],
            sessions: Vec::new(),
            warnings: Vec::new(),
            cwd: "/".into(),
        };
        let anchor = WriteRoute {
            dev: 1,
            ino: 2,
            path: "/alias".into(),
        };
        assert!(
            guard
                .decide_prospective(&anchor, &["AB12".into(), "home".into()])
                .is_some()
        );
    }
    proptest! {
        #[test]
        fn name_matches_oracle(a in prop::collection::vec(any::<u8>(),0..20), b in prop::collection::vec(any::<u8>(),0..20)) {
            prop_assert_eq!(may_name_same_entry(&a,&b), name_oracle(&a,&b));
        }
        #[test]
        fn plain_names_match_oracle(a in "[a-zA-Z0-9._-]{0,20}", b in "[a-zA-Z0-9._-]{0,20}") {
            prop_assert_eq!(may_name_same_entry(a.as_bytes(),b.as_bytes()), name_oracle(a.as_bytes(),b.as_bytes()));
        }
        #[test]
        fn existing_matches_oracle(root in "/[a-z]{1,4}", paths in prop::collection::vec("/[a-z]{1,4}(/[a-z]{1,4})?",0..10), id in 0u64..4) {
            let ids: Vec<_> = (0..paths.len()).map(|i| Some((0,i as u64 % 4))).collect();
            let slices: Vec<_> = paths.iter().map(|p| p.as_bytes()).collect();
            let expected = paths.iter().enumerate().position(|(i,p)| ids[i] == Some((0,id)) || p == &root || p.starts_with(&(root.clone()+"/")));
            prop_assert_eq!(exposing_entry(root.as_bytes(),Some((0,id)),&ids,&slices),expected);
        }
        #[test]
        fn prospective_matches_oracle(parts in prop::collection::vec("[a-zA-Z0-9._-]{1,8}",1..5), shared in any::<bool>(), case_prefix in any::<bool>()) {
            let dst: Vec<Vec<u8>> = parts.iter().map(|p| p.as_bytes().to_vec()).collect();
            let src: Vec<Vec<u8>> = if case_prefix { parts[..1].iter().map(|p| p.to_ascii_uppercase().into_bytes()).collect() } else { cs(&["miss"]) };
            let a = cs(&["anchor"]); let b = if shared { a.clone() } else { cs(&["other"]) };
            let src_id = (1,2); let id = if shared { src_id } else { (3,4) };
            let expected = ((src_id == id || (a.len()==b.len() && prefix_oracle(&a,&b))) && prefix_oracle(&src,&dst)).then_some(0);
            prop_assert_eq!(exposing_prospective(src_id,&a,&src,&[id],&[b],&[dst]),expected);
        }
    }
    struct Tree {
        _root: tempfile::TempDir,
        home: PathBuf,
        cwd: PathBuf,
        state: PathBuf,
        trusted_sources: Vec<PathBuf>,
    }
    impl Tree {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let base = root.path().canonicalize().unwrap();
            let home = base.join("home");
            let cwd = base.join("project");
            let state = base.join("state");
            for p in [&home, &cwd, &state] {
                fs::create_dir(p).unwrap();
            }
            Self {
                _root: root,
                home,
                cwd,
                state,
                trusted_sources: Vec::new(),
            }
        }
        fn guard(&self) -> ProtectedConfigDir {
            self.guard_with(&[])
        }
        fn check(&self, path: &Path) -> Result<()> {
            self.guard()
                .check_core_bind(&CoreHostSource::new(CoreBind::StateDir, path.into()))
        }
    }
    #[test]
    fn plain_present_and_missing_routes() {
        let t = Tree::new();
        let cfg = t.home.join(".config/agent-vm");
        fs::create_dir_all(cfg.join("sub")).unwrap();
        for p in t.home.ancestors().chain(
            [t.home.join(".config"), cfg.clone()]
                .iter()
                .map(PathBuf::as_path),
        ) {
            assert!(t.check(p).is_err(), "{}", p.display());
        }
        for p in [
            t.home.join(".config/other"),
            t.home.join("proj"),
            cfg.join("sub"),
            t.home.join(".configx"),
        ] {
            fs::create_dir_all(&p).unwrap();
            assert!(t.check(&p).is_ok(), "{}", p.display());
        }
        fs::remove_dir_all(t.home.join(".config")).unwrap();
        assert!(t.check(&t.home).is_err());
        assert!(t.check(&t.home.join("x")).is_ok());
        fs::create_dir(t.home.join(".config")).unwrap();
        assert!(t.check(&t.home.join(".config")).is_err());
    }
    /// ADR-0073: `projects/` and each project's directory are routes the guard
    /// measures, while a bind strictly inside one stays allowed — the same rule
    /// ADR-0038 applies to `~/.config/agent-vm/sub`.
    #[test]
    fn project_stores_are_routes_and_their_insides_are_not() {
        let t = Tree::new();
        let cfg = t.home.join(".config/agent-vm");
        let projects = cfg.join("projects");
        let id = "a".repeat(64);
        let store = projects.join(&id);
        fs::create_dir_all(store.join("sub")).unwrap();
        fs::create_dir_all(cfg.join("sub")).unwrap();

        for refused in [&cfg, &t.home, &projects, &store] {
            let msg = t.check(refused).unwrap_err().to_string();
            assert!(
                msg.contains("is, or contains,"),
                "{}: {msg}",
                refused.display()
            );
        }
        // Strictly inside a project's directory: no route is contained.
        assert!(t.check(&store.join("sub")).is_ok());
        assert!(t.check(&cfg.join("sub")).is_ok());

        // A symlinked entry records its target, so a bind of that target is
        // refused however the entry is named.
        let ext = t.cwd.join("ext");
        fs::create_dir_all(&ext).unwrap();
        symlink(&ext, projects.join("b".repeat(64))).unwrap();
        assert!(t.check(&ext).is_err());

        // A regular file and a dangling symlink under `projects/` are not
        // stores: they cannot hold a `config.toml`, so they are skipped
        // deterministically rather than panicking.
        fs::write(projects.join("c".repeat(64)), "").unwrap();
        symlink(t.cwd.join("missing"), projects.join("d".repeat(64))).unwrap();
        assert!(t.guard().check_authority_links().is_ok());
    }

    /// ADR-0073 R6: only `NotFound` is silence, so an entry under `projects/`
    /// that is a symlink to a regular file refuses the launch — `lstat` of
    /// `<entry>/config.toml` answers `NotADirectory`, not `NotFound`.
    ///
    /// The refusal must be actionable: the generic "cannot determine" context
    /// names the unmeasurable `config.toml` path, which no user can act on, so
    /// the message names the entry itself and the remedy.
    #[test]
    fn a_project_store_entry_that_is_not_a_directory_is_refused_by_name() {
        let t = Tree::new();
        let projects = t.home.join(".config/agent-vm/projects");
        fs::create_dir_all(&projects).unwrap();
        let file = t.cwd.join("not-a-store");
        fs::write(&file, "").unwrap();
        let entry = projects.join("e".repeat(64));
        symlink(&file, &entry).unwrap();
        let error =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .expect_err("a store entry that cannot be measured refuses the launch");
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!("\"{}\"", entry.display())),
            "the offending entry must be named: {message}"
        );
        assert!(
            message.contains("not a directory") && message.contains("remove it"),
            "the refusal must state the fact and the remedy: {message}"
        );
    }

    /// The entry bound is fail-closed (see [`MAX_PROJECT_STORES`]): a directory
    /// too large to measure every entry of refuses the launch, names the bound,
    /// and names the directory to clean up.
    #[test]
    fn too_many_project_store_entries_refuse_the_launch() {
        let t = Tree::new();
        let projects = t.home.join(".config/agent-vm/projects");
        fs::create_dir_all(&projects).unwrap();
        for n in 0..=MAX_PROJECT_STORES {
            fs::create_dir(projects.join(format!("{n:064x}"))).unwrap();
        }
        let error =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .expect_err("an unbounded project store refuses the launch");
        let message = format!("{error:#}");
        assert!(
            message.contains(&MAX_PROJECT_STORES.to_string())
                && message.contains(&format!("\"{}\"", projects.display())),
            "the bound and the directory must be named: {message}"
        );
    }

    /// Measuring needs no `projects/` at all, and with only the account home
    /// known (no raw `$HOME`) the project subtree is still measured.
    #[test]
    fn project_stores_measure_without_the_directory_or_a_raw_home() {
        let t = Tree::new();
        assert!(t.guard().check_authority_links().is_ok());
        let cfg = t.home.join(".config/agent-vm");
        fs::create_dir_all(cfg.join("projects").join("a".repeat(64))).unwrap();
        let guard =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .unwrap();
        assert!(
            guard
                .check_core_bind(&CoreHostSource::new(
                    CoreBind::StateDir,
                    cfg.join("projects")
                ))
                .is_err()
        );
    }

    /// Two-pass precedence: a project store reached from a *raw* `$HOME` must
    /// not answer for the account home's own authority directory, or the refusal
    /// would name the wrong directory.
    #[test]
    fn an_account_home_authority_store_outranks_a_raw_home_project_store() {
        let t = Tree::new();
        let cfg = t.home.join(".config/agent-vm");
        fs::create_dir_all(&cfg).unwrap();
        let raw = t.cwd.join("raw-home");
        let raw_projects = raw.join(".config/agent-vm/projects");
        fs::create_dir_all(&raw_projects).unwrap();
        // The raw home's project store resolves into the account home's
        // authority directory, so both stores match a bind of it.
        symlink(&cfg, raw_projects.join("a".repeat(64))).unwrap();
        let guard =
            ProtectedConfigDir::measure(&[raw.clone(), t.home.clone()], &[], &[], None, &t.cwd)
                .unwrap();
        let msg = guard
            .check_core_bind(&CoreHostSource::new(CoreBind::StateDir, cfg.clone()))
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains(&format!("\"{}\"", cfg.display())),
            "the account home's authority store must answer first: {msg}"
        );
    }

    /// The pin manifest is authority under the same one-name rule as
    /// `config.toml`: another name for it could be rewritten from a guest and
    /// then removed.
    #[test]
    fn a_project_pins_manifest_with_two_links_refuses_every_launch() {
        let t = Tree::new();
        let projects = t.home.join(".config/agent-vm/projects");
        let store = projects.join("c".repeat(64));
        fs::create_dir_all(&store).unwrap();
        let pins = store.join(crate::config_pins::PINS_FILE);
        fs::write(&pins, "{\"v\":1}").unwrap();
        let alias = t.cwd.join("pins-alias");
        fs::hard_link(&pins, &alias).unwrap();
        let msg = t.guard().check_authority_links().unwrap_err().to_string();
        assert!(
            msg.contains(&format!("\"{}\" has 2 hard links", pins.display())),
            "{msg}"
        );
        fs::remove_file(&alias).unwrap();
        assert!(t.guard().check_authority_links().is_ok());
    }

    /// V33: a snapshot is authority under the same one-name rule as the manifest
    /// it belongs to, matched case-insensitively so an APFS case variant of a
    /// live snapshot cannot evade the check.
    #[test]
    fn a_project_snapshot_with_two_links_refuses_every_launch() {
        let t = Tree::new();
        let store = t
            .home
            .join(".config/agent-vm/projects")
            .join("d".repeat(64));
        fs::create_dir_all(&store).unwrap();
        for name in [snapshot_for_tests(), snapshot_for_tests().to_uppercase()] {
            let snapshot = store.join(&name);
            fs::write(&snapshot, "snapshot").unwrap();
            let alias = t.cwd.join("snapshot-alias");
            fs::hard_link(&snapshot, &alias).unwrap();
            let msg = t.guard().check_authority_links().unwrap_err().to_string();
            assert!(
                msg.contains(&format!("\"{}\" has 2 hard links", snapshot.display())),
                "{name}: {msg}"
            );
            fs::remove_file(&alias).unwrap();
            assert!(t.guard().check_authority_links().is_ok());
            fs::remove_file(&snapshot).unwrap();
        }
    }

    /// V33: a name the pin store reserves for a snapshot, occupied by anything
    /// else, is a file the guard cannot vouch for, so the launch is refused
    /// rather than the file being skipped. A snapshot another user could rewrite
    /// is refused for the same reason. Names the store writes that are not
    /// snapshots stay ignored.
    #[test]
    fn a_snapshot_name_that_is_not_a_snapshot_file_refuses_the_launch() {
        let t = Tree::new();
        let store = t
            .home
            .join(".config/agent-vm/projects")
            .join("e".repeat(64));
        fs::create_dir_all(store.join(snapshot_for_tests())).unwrap();
        let msg =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .unwrap_err()
                .to_string();
        assert!(
            msg.contains("not a regular file") && msg.contains("remove it"),
            "{msg}"
        );

        // The pin store's own junk names are not snapshots: they cost
        // enumeration work and are otherwise ignored.
        fs::remove_dir(store.join(snapshot_for_tests())).unwrap();
        for name in [
            crate::config_pins::LOCK_FILE.to_owned(),
            format!("{}{}", crate::config_pins::PIN_TMP_PREFIX, "x"),
            "pin-XYZ.toml".to_owned(),
            "unrelated".to_owned(),
        ] {
            fs::write(store.join(name), "").unwrap();
        }
        assert!(t.guard().check_authority_links().is_ok());

        use std::os::unix::fs::PermissionsExt as _;
        let snapshot = store.join(snapshot_for_tests());
        fs::write(&snapshot, "snapshot").unwrap();
        fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o666)).unwrap();
        let msg =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .unwrap_err()
                .to_string();
        assert!(
            msg.contains("group- or other-writable") && msg.contains("writable by you only"),
            "{msg}"
        );
        fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(t.guard().check_authority_links().is_ok());
    }

    /// V33/D5: this launch's own store is measured first, with its own
    /// 2048-entry reservation, so it is fully checked even when every sibling
    /// unit is already spent. One `MAX_SIBLING_SNAPSHOT_WORK` budget spans both
    /// homes: exhaustion in the first home bounds the second, and the bounded
    /// scan is reported against the store it cut short rather than skipped
    /// silently.
    #[test]
    fn one_sibling_budget_spans_every_home_after_the_current_store() {
        let t = Tree::new();
        let second_home = t.cwd.join("second-home");
        let first_projects = t.home.join(".config/agent-vm/projects");
        let second_projects = second_home.join(".config/agent-vm/projects");
        // Four full sibling scans of junk entries spend all 8192 units: the
        // per-store 2048-entry cap means no fewer stores can exhaust it.
        for store in 0..4 {
            let dir = first_projects.join(format!("{store:064x}"));
            fs::create_dir_all(&dir).unwrap();
            for entry in 0..MAX_PROJECT_STORE_ENTRIES {
                fs::write(dir.join(format!("junk-{entry:05}")), "").unwrap();
            }
        }
        let current = second_projects.join("a".repeat(64));
        let sibling = second_projects.join("b".repeat(64));
        fs::create_dir_all(&current).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        let current_snapshot = current.join(snapshot_for_tests());
        fs::write(&current_snapshot, "snapshot").unwrap();
        fs::hard_link(&current_snapshot, t.cwd.join("current-alias")).unwrap();
        let sibling_snapshot = sibling.join(snapshot_for_tests());
        fs::write(&sibling_snapshot, "snapshot").unwrap();
        fs::hard_link(&sibling_snapshot, t.cwd.join("sibling-alias")).unwrap();

        let guard = ProtectedConfigDir::measure(
            &[t.home.clone(), second_home.clone()],
            &[],
            &[],
            Some(&current),
            &t.cwd,
        )
        .unwrap();
        // Exactly one bounded scan, and it names the second home's sibling: the
        // current store was not scanned again as a sibling, and the first home's
        // stores each fit their own cap.
        assert_eq!(guard.warnings().len(), 1, "{:?}", guard.warnings());
        let warning = &guard.warnings()[0];
        assert!(
            warning.contains(&format!("{}", sibling.display())),
            "{warning}"
        );
        assert!(
            warning.contains("was bounded") && warning.contains("snapshots were not measured"),
            "{warning}"
        );
        // The current store's reservation was taken first: its snapshot is
        // still checked, and refused, at zero remaining sibling budget.
        let msg = guard.check_authority_links().unwrap_err().to_string();
        assert!(
            msg.contains(&format!(
                "\"{}\" has 2 hard links",
                current_snapshot.display()
            )),
            "{msg}"
        );
    }

    /// V33: the current store's own 2048-entry bound fails closed, with a
    /// remedy naming the store, however small the sibling scan was.
    #[test]
    fn too_many_entries_in_the_current_store_refuse_the_launch() {
        let t = Tree::new();
        let store = t
            .home
            .join(".config/agent-vm/projects")
            .join("f".repeat(64));
        fs::create_dir_all(&store).unwrap();
        for entry in 0..=MAX_PROJECT_STORE_ENTRIES {
            fs::write(store.join(format!("pin-XYZ-{entry:05}.toml")), "").unwrap();
        }
        let error = ProtectedConfigDir::measure(
            std::slice::from_ref(&t.home),
            &[],
            &[],
            Some(&store),
            &t.cwd,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(&MAX_PROJECT_STORE_ENTRIES.to_string())
                && error.contains(&format!("{}", crate::one_line::quoted_path(&store))),
            "{error}"
        );
        // The remedy must not tell anyone to remove `pins.lock`: it is the
        // store's permanent coordination inode (ADR-0077), so only confirmed
        // orphans and abandoned temporaries are removable.
        assert!(error.contains("quiesce"), "{error}");
        assert!(error.contains("confirmed orphan pin-*.toml"), "{error}");
        assert!(error.contains("keep pins.json and pins.lock"), "{error}");
        assert!(!error.contains("remove the orphan"), "{error}");
    }

    /// V33/B4: the current store is recognised by identity, never by spelling. A
    /// case-folded APFS spelling and a symlink alias both name the same store, so
    /// neither makes it a sibling — and its snapshots are still checked.
    #[test]
    fn the_current_store_is_recognised_by_identity_not_by_spelling() {
        let t = Tree::new();
        let store = t
            .home
            .join(".config/agent-vm/projects")
            .join("a".repeat(64));
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join(crate::config_pins::PINS_FILE), "{\"v\":1}").unwrap();

        let spelling = if identity_of(&store) == identity_of(&store.with_file_name("A".repeat(64)))
        {
            // APFS: the uppercase spelling is the same directory.
            store.with_file_name("A".repeat(64))
        } else {
            let alias = t.cwd.join("store-alias");
            symlink(&store, &alias).unwrap();
            alias
        };
        assert!(
            StoreIdentity::of(&store).is(&StoreIdentity::of(&spelling)),
            "{} names the same store",
            spelling.display()
        );
        let other = t
            .home
            .join(".config/agent-vm/projects")
            .join("b".repeat(64));
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join(crate::config_pins::PINS_FILE), "{\"v\":1}").unwrap();
        assert!(!StoreIdentity::of(&store).is(&StoreIdentity::of(&other)));

        // Measured through the other spelling it is still this launch's store:
        // its snapshot is checked, and its second name refused.
        let snapshot = store.join(snapshot_for_tests());
        fs::write(&snapshot, "snapshot").unwrap();
        fs::hard_link(&snapshot, t.cwd.join("snapshot-alias")).unwrap();
        let guard = ProtectedConfigDir::measure(
            std::slice::from_ref(&t.home),
            &[],
            &[],
            Some(&spelling),
            &t.cwd,
        )
        .unwrap();
        assert!(guard.warnings().is_empty(), "{:?}", guard.warnings());
        let msg = guard.check_authority_links().unwrap_err().to_string();
        assert!(msg.contains("has 2 hard links"), "{msg}");
    }

    /// ADR-0038 Decision 2 over every project's `config.toml`, in sorted entry
    /// order, so the refusal names the same file on every filesystem.
    #[test]
    fn a_project_config_with_two_links_refuses_every_launch() {
        let t = Tree::new();
        let projects = t.home.join(".config/agent-vm/projects");
        let first = projects.join("a".repeat(64));
        let second = projects.join("b".repeat(64));
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        let config = first.join("config.toml");
        fs::write(&config, "").unwrap();
        let alias = t.cwd.join("alias");
        fs::hard_link(&config, &alias).unwrap();
        let msg = t.guard().check_authority_links().unwrap_err().to_string();
        assert!(
            msg.contains(&format!("\"{}\" has 2 hard links", config.display())),
            "{msg}"
        );
        fs::remove_file(&alias).unwrap();
        assert!(t.guard().check_authority_links().is_ok());

        // Another project's file is measured too: the guard exists so P1's guest
        // cannot plant P2's authority.
        let other = second.join("config.toml");
        fs::write(&other, "").unwrap();
        fs::hard_link(&other, &alias).unwrap();
        let msg = t.guard().check_authority_links().unwrap_err().to_string();
        assert!(msg.contains(&format!("\"{}\"", other.display())), "{msg}");
        fs::remove_file(&alias).unwrap();
        assert!(t.guard().check_authority_links().is_ok());

        // An uninspectable file fails closed: the reader never gets to classify
        // it, because not applying it now would launder it into the next launch.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIPPED EACCES: running as root");
            return;
        }
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&second, fs::Permissions::from_mode(0o000)).unwrap();
        let err =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .unwrap_err()
                .to_string();
        fs::set_permissions(&second, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.contains("cannot determine"), "{err}");
    }

    #[test]
    fn an_unreadable_projects_dir_fails_closed() {
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIPPED EACCES: running as root");
            return;
        }
        let t = Tree::new();
        let projects = t.home.join(".config/agent-vm/projects");
        fs::create_dir_all(&projects).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&projects, fs::Permissions::from_mode(0o000)).unwrap();
        let err =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .unwrap_err()
                .to_string();
        fs::set_permissions(&projects, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.contains("cannot determine"), "{err}");
        assert!(err.contains("projects"), "{err}");
    }

    #[test]
    fn departing_and_dangling_symlinks() {
        let t = Tree::new();
        let ext = t.cwd.join("ext");
        fs::create_dir_all(ext.join("config")).unwrap();
        symlink(ext.join("config"), t.home.join(".config")).unwrap();
        assert!(t.check(&t.home).is_err());
        assert!(t.check(&ext).is_err());
        fs::remove_file(t.home.join(".config")).unwrap();
        fs::create_dir(t.home.join(".config")).unwrap();
        symlink(ext.join("agent-vm"), t.home.join(".config/agent-vm")).unwrap();
        assert!(t.check(&ext).is_err());
    }
    #[test]
    fn relative_link_loop_and_non_directory_fail_closed() {
        let t = Tree::new();
        symlink("../state/config", t.home.join(".config")).unwrap();
        assert!(t.check(&t.state).is_err());
        fs::remove_file(t.home.join(".config")).unwrap();
        symlink(".config", t.home.join(".config")).unwrap();
        assert!(
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .unwrap_err()
                .to_string()
                .contains("cannot determine")
        );
        fs::remove_file(t.home.join(".config")).unwrap();
        fs::write(t.home.join(".config"), "file").unwrap();
        assert!(
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .is_err()
        );
    }
    #[test]
    fn both_homes_and_messages() {
        let t = Tree::new();
        let other = t.cwd.join("other");
        fs::create_dir(&other).unwrap();
        let guard =
            ProtectedConfigDir::measure(&[t.home.clone(), other.clone()], &[], &[], None, &t.cwd)
                .unwrap();
        for home in [&t.home, &other] {
            assert!(
                guard
                    .check_core_bind(&CoreHostSource::new(CoreBind::ProjectDir, home.clone()))
                    .unwrap_err()
                    .to_string()
                    .contains("instead of $HOME")
            );
        }
        for bind in [
            CoreBind::ProjectDir,
            CoreBind::StateDir,
            CoreBind::GuestHome,
        ] {
            let msg = guard
                .check_core_bind(&CoreHostSource::new(bind, t.home.clone()))
                .unwrap_err()
                .to_string();
            assert!(msg.contains(bind.description()));
            assert!(msg.contains("is, or contains,"));
            assert!(msg.contains(if bind == CoreBind::ProjectDir {
                "instead of $HOME"
            } else {
                "AGENT_VM_STATE_DIR"
            }));
        }
        let msg = guard
            .check_writable_mount(Declaration::Argv, &Spelling::new("/decl"), &t.home, &t.home)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("contains or resolves to"));
        assert!(msg.contains(":ro"));
        assert!(!msg.contains(":fork"));
    }
    /// `d.spelled` is `<measured home>/.config/agent-vm`, so every sentence that
    /// names it has a measured path in it — the classification that decides the
    /// policy here. A non-ASCII `$HOME` must read as itself in each of them.
    #[test]
    fn a_non_ascii_home_prints_as_itself_in_every_refusal() {
        let t = Tree::new();
        let home = t.cwd.join("дом");
        fs::create_dir(&home).unwrap();
        fs::create_dir_all(home.join(".config/agent-vm")).unwrap();
        let guard =
            ProtectedConfigDir::measure(std::slice::from_ref(&home), &[], &[], None, &t.cwd)
                .unwrap();
        for message in [
            guard
                .check_core_bind(&CoreHostSource::new(CoreBind::StateDir, home.clone()))
                .unwrap_err()
                .to_string(),
            guard
                .check_writable_mount(Declaration::Argv, &Spelling::new("/decl"), &home, &home)
                .unwrap_err()
                .to_string(),
        ] {
            assert!(message.contains("дом/.config/agent-vm"), "{message}");
            assert!(!message.contains("\\xd0"), "byte-escaped: {message}");
        }
    }
    /// The declared spelling is *not* measured: an argv `--mount` keeps the
    /// `{:?}` rendering every other argv diagnostic pins, and a config entry keeps
    /// the byte-escaped, attributed `mounts[N] in "<file>"` form, so a spelling
    /// cannot print one way in this refusal and another in `mount`'s own.
    #[test]
    fn a_declared_spelling_is_rendered_by_its_declaration() {
        let t = Tree::new();
        fs::create_dir_all(t.home.join(".config/agent-vm")).unwrap();
        let guard = t.guard();
        let file = t.cwd.join(".config/agent-vm/config.toml");
        let spelling = Spelling::new("/декларация");
        let argv = guard
            .check_writable_mount(Declaration::Argv, &spelling, &t.home, &t.home)
            .unwrap_err()
            .to_string();
        assert!(argv.starts_with("--mount \"/декларация\""), "{argv}");
        let user = guard
            .check_writable_mount(
                Declaration::UserConfig {
                    file: &file,
                    index: 0,
                },
                &spelling,
                &t.home,
                &t.home,
            )
            .unwrap_err()
            .to_string();
        assert!(user.starts_with("mounts[0] in"), "{user}");
        assert!(!user.contains("декларация"), "{user}");
        assert!(user.contains("\\xd0\\xb4"), "byte-escaped: {user}");
    }
    #[test]
    fn prospective_basic_and_dotdot() {
        let t = Tree::new();
        let msg = t.check(&t.home.join(".config")).unwrap_err().to_string();
        assert!(msg.contains("does not exist yet; once created it could be, or contain,"));
        assert!(!msg.contains("would contain"));
        assert!(t.check(&t.state.join("ab12")).is_ok());
        assert!(t.check(&t.home.join(".local/state/agent-vm/ab12")).is_ok());
        assert!(
            t.check(&t.state.join("missing/../ab12"))
                .unwrap_err()
                .to_string()
                .contains("cannot determine")
        );
        for missing_anchor in [false, true] {
            let state = if missing_anchor {
                t.state.join("missing")
            } else {
                t.state.clone()
            };
            symlink(state.join("ab12/home/.config"), t.home.join(".config")).unwrap();
            assert!(t.check(&state.join("ab12/home")).is_err());
            fs::remove_file(t.home.join(".config")).unwrap();
        }
        symlink(
            t.state.join("ab12/../other/.config"),
            t.home.join(".config"),
        )
        .unwrap();
        assert!(t.check(&t.state.join("ab12")).is_ok());
        assert!(t.check(&t.state.join("ab12/home")).is_ok());
        fs::remove_file(t.home.join(".config")).unwrap();
        symlink(t.state.join("ab12/../cd34/.config"), t.home.join(".config")).unwrap();
        assert!(t.check(&t.state.join("cd34")).is_err());
    }
    #[test]
    fn relative_first_and_later_sources() {
        let t = Tree::new();
        let source = Path::new("state/ab12/home");
        assert!(t.check(source).is_ok());
        symlink(t.cwd.join(source).join(".config"), t.home.join(".config")).unwrap();
        let msg = t.check(source).unwrap_err().to_string();
        assert!(msg.contains(&t.cwd.join(source).display().to_string()));
        fs::create_dir_all(t.cwd.join(source)).unwrap();
        assert!(t.check(source).is_err());
        fs::remove_file(t.home.join(".config")).unwrap();
        assert!(t.check(source).is_ok());
        assert!(t.check(Path::new("../state/ab12")).is_ok());
    }
    #[test]
    fn launch_links_unconditional_and_symlink_exemption() {
        let t = Tree::new();
        let file = t.home.join(".config/agent-vm/config.toml");
        assert!(t.guard().check_authority_links().is_ok());
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "# no network; private content").unwrap();
        let link = t.cwd.join("alias");
        fs::hard_link(&file, &link).unwrap();
        let msg = t.guard().check_authority_links().unwrap_err().to_string();
        assert!(msg.contains("has 2 hard links"));
        assert!(!msg.contains("private content"));
        fs::remove_file(&link).unwrap();
        assert!(t.guard().check_authority_links().is_ok());
        fs::rename(&file, &link).unwrap();
        symlink(&link, &file).unwrap();
        assert!(t.guard().check_authority_links().is_ok());
    }
    #[test]
    fn permission_errors_fail_closed() {
        // Root can traverse 000 directories, so it cannot exercise this failure.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIPPED EACCES: running as root");
            return;
        }
        let t = Tree::new();
        let cfg = t.home.join(".config");
        fs::create_dir(&cfg).unwrap();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o000)).unwrap();
        let err =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .unwrap_err();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(err.to_string().contains("cannot determine"));

        // The authority directory itself can be measured, but looking up its
        // config file must fail closed independently of the route walk.
        let t = Tree::new();
        let cfg = t.home.join(".config/agent-vm");
        fs::create_dir_all(&cfg).unwrap();
        fs::write(cfg.join("config.toml"), "# no network\n").unwrap();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o000)).unwrap();
        let err =
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &[], &[], None, &t.cwd)
                .unwrap_err();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(err.to_string().contains("cannot determine"));
        assert!(err.to_string().contains("config.toml"));
    }
    #[test]
    fn spelled_arm_wiring_and_dotdot_skip() {
        let t = Tree::new();
        let g = t.guard();
        assert!(
            g.decide(Some(&t.home), Path::new("/disjoint"), Some((0, 0)))
                .is_some()
        );
        assert!(
            g.decide(
                Some(&t.home.join("../home")),
                Path::new("/disjoint"),
                Some((0, 0))
            )
            .is_none()
        );
    }
    #[test]
    fn case_variant_first_and_later() {
        let t = Tree::new();
        fs::create_dir(t.cwd.join("abc")).unwrap();
        let first = fs::metadata(t.cwd.join("abc")).unwrap();
        if !fs::metadata(t.cwd.join("ABC"))
            .is_ok_and(|m| (m.dev(), m.ino()) == (first.dev(), first.ino()))
        {
            eprintln!("SKIPPED case variant: filesystem is case-sensitive");
            return;
        }
        symlink(t.state.join("AB12/home/.config"), t.home.join(".config")).unwrap();
        let source = t.state.join("ab12/home");
        assert!(t.check(&source).is_err());
        fs::create_dir_all(&source).unwrap();
        assert!(t.check(&source).is_err());
        fs::remove_file(t.home.join(".config")).unwrap();
        symlink(t.state.join("AB13/home/.config"), t.home.join(".config")).unwrap();
        assert!(t.check(&source).is_ok());
    }
    #[test]
    fn firmlink_anchor() {
        if !cfg!(target_os = "macos") {
            eprintln!(
                "SKIPPED firmlink: Linux needs root bind mounts; pure alias row supplies evidence"
            );
            return;
        }
        let t = Tree::new();
        let alias = PathBuf::from(format!("/System/Volumes/Data{}", t.state.display()));
        let a = fs::metadata(&t.state).unwrap();
        if !fs::metadata(&alias).is_ok_and(|b| (a.dev(), a.ino()) == (b.dev(), b.ino()))
            || fs::canonicalize(&alias).ok() == fs::canonicalize(&t.state).ok()
        {
            eprintln!("SKIPPED firmlink: no distinct canonical spellings sharing identity");
            return;
        }
        symlink(t.state.join("ab12/home/.config"), t.home.join(".config")).unwrap();
        assert!(t.check(&alias.join("ab12/home")).is_err());
    }
    #[test]
    fn filesystem_name_rule_adequacy_probe() {
        if !cfg!(target_os = "macos") {
            eprintln!("SKIPPED adequacy probe: macOS only");
            return;
        }
        let t = Tree::new();
        for (i, (a, b)) in [
            ("f854122c3070", "F854122C3070"),
            ("é", "e\u{301}"),
            ("k", "K"),
            ("ff", "ﬀ"),
        ]
        .iter()
        .enumerate()
        {
            let p = t.cwd.join(i.to_string());
            fs::create_dir(&p).unwrap();
            fs::create_dir(p.join(a)).unwrap();
            let am = fs::metadata(p.join(a)).unwrap();
            if !fs::metadata(p.join(b)).is_ok_and(|bm| (am.dev(), am.ino()) == (bm.dev(), bm.ino()))
            {
                eprintln!("SKIPPED pair {a}/{b}: not equivalent here");
                continue;
            }
            assert!(may_name_same_entry(a.as_bytes(), b.as_bytes()));
        }
    }

    // -- R1/R2: the ADR-0064 stores -----------------------------------------

    /// The same tree, plus the two stores a launch writes besides the authority
    /// directory: this project's `.sessions` directory under the state root and
    /// `MSB_HOME` beside it.
    impl Tree {
        fn sessions(&self) -> PathBuf {
            self.state.join("ab12cd34ef56.sessions")
        }
        fn msb_home(&self) -> PathBuf {
            self.state.join("msb-home")
        }
        fn guard_with(&self, stores: &[Store]) -> ProtectedConfigDir {
            ProtectedConfigDir::measure(
                std::slice::from_ref(&self.home),
                stores,
                &self.trusted_sources,
                None,
                &self.cwd,
            )
            .unwrap()
        }
        fn launch_stores(&self) -> Vec<Store> {
            vec![
                Store::new(StorePurpose::ProjectSessions, self.sessions()),
                Store::new(StorePurpose::RuntimeState, self.msb_home()),
            ]
        }
        /// A `--mount` declaration of `path`, in whichever mode `access` names.
        fn mount(&self, guard: &ProtectedConfigDir, path: &Path, read_only: bool) -> Result<()> {
            if !read_only {
                guard.check_writable_mount(
                    Declaration::Argv,
                    &Spelling::new("/decl"),
                    path,
                    path,
                )?;
            }
            guard.check_mount_names_sessions(Declaration::Argv, &Spelling::new("/decl"), path)
        }
    }

    /// ADR-0076 R2.4: a writable bind over a `trust = true` source, or over any
    /// directory along its route, is refused; `:ro` and unrelated writable mounts
    /// stay allowed.
    #[test]
    fn a_writable_bind_over_a_trusted_source_route_is_refused() {
        let mut t = Tree::new();
        let team = t.home.join("team");
        fs::create_dir_all(team.join("sub")).unwrap();
        let source = team.join("sub/agent-vm.toml");
        fs::write(&source, "[[tools]]\nname = \"x\"\ncommand = \"true\"\n").unwrap();
        t.trusted_sources = vec![source.clone()];
        let guard = t.guard();
        for path in [
            source.clone(),
            source.parent().unwrap().to_path_buf(),
            team.clone(),
        ] {
            let message = guard
                .check_writable_mount(Declaration::Argv, &Spelling::new("/decl"), &path, &path)
                .unwrap_err()
                .to_string();
            assert!(
                message.contains("trusted config source"),
                "{}: {message}",
                path.display()
            );
            assert!(message.contains("read-only (:ro)"), "{message}");
        }
        // A bind of `$HOME` is refused too — by the authority store's own
        // measurement, which answers first.
        assert!(
            guard
                .check_writable_mount(Declaration::Argv, &Spelling::new("/decl"), &t.home, &t.home)
                .is_err()
        );
        // Positive controls: the same route read-only, and an unrelated writable
        // directory.
        assert!(
            t.mount(&guard, &team, true).is_ok(),
            "a read-only bind cannot rewrite the source"
        );
        let unrelated = t.cwd.join("other");
        fs::create_dir(&unrelated).unwrap();
        assert!(t.mount(&guard, &unrelated, false).is_ok());
    }

    /// A multi-link trusted source is refused at mount-planning time too, so a
    /// hard link cannot launder the file into a guest-writable path.
    #[test]
    fn a_trusted_source_with_two_links_refuses_every_launch() {
        let mut t = Tree::new();
        let team = t.home.join("team");
        fs::create_dir_all(&team).unwrap();
        let source = team.join("agent-vm.toml");
        fs::write(&source, "").unwrap();
        fs::hard_link(&source, team.join("laundered.toml")).unwrap();
        t.trusted_sources = vec![source.clone()];
        let message = t.guard().check_authority_links().unwrap_err().to_string();
        assert!(message.contains("agent-vm.toml"), "{message}");
    }

    /// ADR-0076 R2.4 for another project's `trust = true` source, spelled
    /// directly: the guard refuses a writable bind of the file or of any directory
    /// on its route.
    #[test]
    fn a_writable_bind_over_another_projects_trusted_source_is_refused() {
        let t = Tree::new();
        let team = t.state.join("team");
        fs::create_dir_all(team.join("sub")).unwrap();
        let source = team.join("sub/agent-vm.toml");
        fs::write(&source, "# another project's trusted source\n").unwrap();
        write_sibling_project(
            &t,
            &format!(
                "[[sources]]\nname = \"team\"\npath = {:?}\ntrust = true\n",
                source.display().to_string()
            ),
        );
        let guard = t.guard();
        for path in [source.clone(), source.parent().unwrap().to_path_buf(), team] {
            let message = guard
                .check_writable_mount(Declaration::Argv, &Spelling::new("/decl"), &path, &path)
                .unwrap_err()
                .to_string();
            assert!(
                message.contains("trusted config source"),
                "{}: {message}",
                path.display()
            );
            assert!(message.contains("read-only (:ro)"), "{message}");
        }
    }

    /// ADR-0076 R2.4 through a symlinked ancestor: another project trusts a file
    /// it reaches through an owner-controlled link, and this launch binds the
    /// link's **target** writable. That project's read resolves the link
    /// (`project_config::open_trusted_source_route`), so the measurement must
    /// resolve it too: a lexical walk records the link and misses the target,
    /// which is exactly the bind a guest needs in order to rewrite the file the
    /// other project's next launch reads as host authority.
    #[test]
    fn a_writable_bind_over_another_projects_symlinked_trusted_source_is_refused() {
        let t = Tree::new();
        let target = t.state.join("team");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("agent-vm.toml"), "# trusted\n").unwrap();
        let link = t.home.join("safe/link");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&target, &link).unwrap();
        write_sibling_project(
            &t,
            &format!(
                "[[sources]]\nname = \"team\"\npath = {:?}\ntrust = true\n",
                link.join("agent-vm.toml").display().to_string()
            ),
        );

        let guard = t.guard();
        // The target, the target's parent, and the link's own spelling are all
        // routes to the file that project's next launch would read.
        for path in [target.clone(), t.state.clone(), link.clone()] {
            let message = guard
                .check_writable_mount(Declaration::Argv, &Spelling::new("/decl"), &path, &path)
                .unwrap_err()
                .to_string();
            assert!(
                message.contains("trusted config source"),
                "{}: {message}",
                path.display()
            );
            assert!(message.contains("read-only (:ro)"), "{message}");
        }
        // Positive controls: the same target read-only, and an unrelated writable
        // directory.
        assert!(t.mount(&guard, &target, true).is_ok());
        let unrelated = t.cwd.join("unrelated");
        fs::create_dir(&unrelated).unwrap();
        assert!(t.mount(&guard, &unrelated, false).is_ok());
    }

    /// The second project's own `config.toml`, declaring `sources` text as the
    /// **reader** wrote it, so the guard must extract the trusted paths itself.
    fn write_sibling_project(t: &Tree, body: &str) {
        let store = t
            .home
            .join(".config/agent-vm/projects")
            .join("b".repeat(64));
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join(crate::project_config::CONFIG_FILE), body).unwrap();
    }

    /// R1 for the state root: a writable live bind of the directory that holds
    /// `.sessions` would let the guest write this project's refusal log.
    #[test]
    fn a_writable_state_root_bind_exposes_the_sessions_dir() {
        let t = Tree::new();
        fs::create_dir_all(t.sessions()).unwrap();
        let guard = t.guard_with(&t.launch_stores());
        let message = guard
            .check_writable_mount(
                Declaration::Argv,
                &Spelling::new("/decl"),
                &t.state,
                &t.state,
            )
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("refusal records and control sockets"),
            "{message}"
        );
        assert!(
            message.contains(&t.sessions().display().to_string()),
            "{message}"
        );
        assert!(message.contains(":ro"), "{message}");
    }

    /// R1 for `MSB_HOME`: every sandbox's `network.log` lives inside it.
    #[test]
    fn a_writable_bind_of_msb_home_is_refused() {
        let t = Tree::new();
        fs::create_dir_all(t.msb_home().join("sandboxes/agent-vm-x/logs")).unwrap();
        let guard = t.guard_with(&t.launch_stores());
        let message = guard
            .check_writable_mount(
                Declaration::Argv,
                &Spelling::new("/decl"),
                &t.msb_home(),
                &t.msb_home(),
            )
            .unwrap_err()
            .to_string();
        assert!(message.contains("sandbox runtime"), "{message}");
        // A sibling of it is untouched: the store is the directory, not the root.
        fs::create_dir_all(t.state.join("msb-home-next")).unwrap();
        assert!(
            guard
                .check_writable_mount(
                    Declaration::Argv,
                    &Spelling::new("/decl"),
                    &t.state.join("msb-home-next"),
                    &t.state.join("msb-home-next"),
                )
                .is_ok()
        );
    }

    /// The two core binds beside the store stay allowed: the state bind is
    /// `<state>/<hash>`, a *sibling* of `<state>/<hash>.sessions`, and the guest
    /// home is below it.
    #[test]
    fn the_core_state_bind_beside_it_is_allowed() {
        let t = Tree::new();
        fs::create_dir_all(t.sessions()).unwrap();
        fs::create_dir_all(t.state.join("ab12cd34ef56/home")).unwrap();
        let guard = t.guard_with(&t.launch_stores());
        for (bind, path) in [
            (CoreBind::StateDir, t.state.join("ab12cd34ef56")),
            (CoreBind::GuestHome, t.state.join("ab12cd34ef56/home")),
            (CoreBind::ProjectDir, t.cwd.clone()),
        ] {
            guard
                .check_core_bind(&CoreHostSource::new(bind, path.clone()))
                .unwrap_or_else(|e| panic!("{} refused: {e:#}", path.display()));
            guard
                .check_core_bind_names_sessions(&CoreHostSource::new(bind, path))
                .unwrap();
        }
    }

    /// A project that has never launched has no `.sessions` directory yet, so
    /// the store has to be refused while it does not exist: `measure` records
    /// the path its walk would reach, and a writable bind of the state root is
    /// refused against that path rather than against a directory on disk.
    ///
    /// The `.sessions` store is a *sibling* of the state directory, so the
    /// prospective spelling of a missing root cannot reach it: a core bind of
    /// `<state>/<hash>` never names `<state>/<hash>.sessions`.
    #[test]
    fn a_missing_sessions_dir_is_protected_prospectively() {
        let t = Tree::new();
        assert!(!t.sessions().exists());
        let guard = t.guard_with(&t.launch_stores());
        let message = guard
            .check_writable_mount(
                Declaration::Argv,
                &Spelling::new("/decl"),
                &t.state,
                &t.state,
            )
            .unwrap_err()
            .to_string();
        assert!(
            message.contains(t.sessions().to_str().unwrap()),
            "{message}"
        );
        assert!(message.contains("refusal records"), "{message}");
        // Nor does a missing core bind reach it.
        assert!(
            guard
                .check_core_bind(&CoreHostSource::new(
                    CoreBind::StateDir,
                    t.state.join("ab12cd34ef56"),
                ))
                .is_ok()
        );
    }

    /// R2 for the files themselves: whatever a bind's mode says, a bind of
    /// `refusals.json` or `refusals.lock` names one refusal artefact.
    #[test]
    fn ro_and_fork_binds_of_refusals_json_and_the_lock_are_refused() {
        let t = Tree::new();
        fs::create_dir_all(t.sessions()).unwrap();
        for name in ["refusals.json", "refusals.lock", "ab12cd34.sock"] {
            fs::write(t.sessions().join(name), "x").unwrap();
            for read_only in [false, true] {
                let message = t
                    .mount(
                        &t.guard_with(&t.launch_stores()),
                        &t.sessions().join(name),
                        read_only,
                    )
                    .unwrap_err()
                    .to_string();
                assert!(message.contains("lies inside"), "{message}");
                assert!(message.contains("refusal records"), "{message}");
            }
        }
    }

    /// A bind *inside* a `.sessions` directory that does not exist yet: the
    /// lexical spelling is the only evidence there is.
    #[test]
    fn a_bind_spelled_inside_a_missing_sessions_dir_is_refused() {
        let t = Tree::new();
        let guard = t.guard_with(&t.launch_stores());
        for inside in [t.sessions(), t.sessions().join("nothing-here.json")] {
            assert!(
                t.mount(&guard, &inside, true).is_err(),
                "{}",
                inside.display()
            );
        }
        // A directory whose *name* merely starts with the store's does not.
        let beside = t.state.join("ab12cd34ef56.sessions-backup");
        fs::create_dir_all(&beside).unwrap();
        assert!(t.mount(&guard, &beside, true).is_ok());
    }

    /// R2's three spellings that a plain canonical prefix cannot all see: `..`
    /// (the resolved path leaves the component behind), a symlink under another
    /// name (the resolved path is the same entry), and a different letter case
    /// (the same entry under a name whose bytes differ — only the filesystem knows,
    /// so the case spelling is asserted only where the platform says it is the same
    /// directory).
    #[test]
    fn r2_catches_dot_dot_symlink_and_case_spellings() {
        let t = Tree::new();
        fs::create_dir_all(t.sessions()).unwrap();
        fs::write(t.sessions().join("refusals.json"), "x").unwrap();
        fs::create_dir_all(t.msb_home()).unwrap();
        let guard = t.guard_with(&t.launch_stores());

        // `..`: spelled through a sibling of the store, resolved back into it.
        let via_dot_dot = t
            .msb_home()
            .join("..")
            .join("ab12cd34ef56.sessions")
            .join("refusals.json");
        let message = t
            .mount(&guard, &via_dot_dot, true)
            .expect_err("`..` does not leave the store")
            .to_string();
        assert!(message.contains("lies inside"), "{message}");

        // A symlink to the store under a name of the guest's choosing.
        let alias = t.state.join("innocent");
        std::os::unix::fs::symlink(t.sessions(), &alias).unwrap();
        let message = t
            .mount(&guard, &alias.join("refusals.json"), true)
            .expect_err("an alias of the store is the store")
            .to_string();
        assert!(message.contains("lies inside"), "{message}");

        // A different letter case. Both spellings are compared byte-wise by the
        // prefix rule, so this only fails closed where the platform resolves the
        // two to one entry — which is exactly the case that must be refused.
        let cased = t.state.join("AB12CD34EF56.SESSIONS").join("refusals.json");
        let identity = |path: &Path| fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
        if identity(&cased) == identity(&t.sessions().join("refusals.json"))
            && identity(&cased).is_some()
        {
            let message = t
                .mount(&guard, &cased, true)
                .expect_err("the same entry under another spelling")
                .to_string();
            assert!(message.contains("lies inside"), "{message}");
        } else {
            eprintln!("SKIPPED the case spelling: this filesystem is case-sensitive");
        }

        // A neighbouring directory that is *not* the store stays allowed, so the
        // three spellings above are not the rule refusing everything.
        let elsewhere = t.state.join("innocent-2");
        fs::create_dir_all(&elsewhere).unwrap();
        assert!(t.mount(&guard, &elsewhere, true).is_ok());
    }

    /// R2 fails closed. The resolved spelling used to fall back to the lexical one
    /// when the walk could not answer, which decided "outside `.sessions`" on a
    /// path nothing had checked; R1 fails closed on the same input, and R2 guards
    /// the same boundary.
    #[test]
    fn r2_fails_closed_when_the_path_cannot_be_resolved() {
        let t = Tree::new();
        fs::create_dir_all(t.sessions()).unwrap();
        let guard = t.guard_with(&t.launch_stores());
        // A regular file where a directory would have to be: the walk cannot say
        // what the path resolves to.
        fs::write(t.state.join("a-file"), "x").unwrap();
        let unresolvable = t.state.join("a-file").join("refusals.json");
        let message = t
            .mount(&guard, &unresolvable, true)
            .expect_err("an unanswerable path is refused, not allowed")
            .to_string();
        assert!(message.contains("cannot determine"), "{message}");
    }

    /// D3: a `:ro`/`:fork` bind of a strict ancestor stays exempt from R1, so it
    /// must stay exempt from R2 too — the state root itself contains `.sessions`
    /// and is not *inside* it.
    #[test]
    fn a_ro_bind_of_an_ancestor_is_allowed() {
        let t = Tree::new();
        fs::create_dir_all(t.sessions()).unwrap();
        let guard = t.guard_with(&t.launch_stores());
        for ancestor in [t.state.clone(), t.cwd.clone(), t.home.clone()] {
            assert!(
                t.mount(&guard, &ancestor, true).is_ok(),
                "{}",
                ancestor.display()
            );
        }
        // The writable spelling of the same ancestor is still R1's refusal...
        assert!(t.mount(&guard, &t.state, false).is_err());
        // ...and readability of the strict ancestor D3 is about is unchanged.
        fs::create_dir_all(t.home.join(".config/agent-vm")).unwrap();
        assert!(
            t.mount(&t.guard_with(&t.launch_stores()), &t.home, true)
                .is_ok()
        );
    }
}
