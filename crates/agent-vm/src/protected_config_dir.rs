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
use crate::protected_host_files::{CoreBind, CoreHostSource};

verus! {
pub fn authority_file_singly_linked(nlink: u64) -> (r: bool)
    ensures r == (nlink == 1u64),
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

#[derive(Debug)]
pub(crate) struct ProtectedConfigDir {
    dirs: Vec<MeasuredDir>,
    cwd: PathBuf,
}
#[derive(Debug)]
struct MeasuredDir {
    spelled: PathBuf,
    home: PathBuf,
    config_file_links: Option<(PathBuf, u64)>,
    ids: Vec<Option<(u64, u64)>>,
    paths: Vec<Vec<u8>>,
    prospective_ids: Vec<(u64, u64)>,
    prospective_anchors: Vec<Vec<Vec<u8>>>,
    prospective_suffixes: Vec<Vec<Vec<u8>>>,
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
        config::escape_path(path)
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

impl ProtectedConfigDir {
    pub(crate) fn measure(homes: &[PathBuf], cwd: &Path) -> Result<Self> {
        let mut dirs: Vec<MeasuredDir> = Vec::new();
        for home in homes {
            let home = anchored(cwd, home);
            let spelled = home.join(config::USER_CONFIG_DIR_RELATIVE);
            if dirs.iter().any(|d| d.spelled == spelled) {
                continue;
            }
            let resolution = resolve(&spelled, Walk::Authority)?;
            let file = spelled.join("config.toml");
            let config_file_links = match fs::symlink_metadata(&file) {
                Ok(m) if m.is_file() => Some((file.clone(), m.nlink())),
                Ok(_) => None,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e).with_context(|| uncertain(&file)),
            };
            let mut ids = Vec::new();
            let mut paths = Vec::new();
            for r in &resolution.routes {
                ids.push(Some((r.dev, r.ino)));
                paths.push(r.path.as_os_str().as_bytes().to_vec());
            }
            ids.push(None);
            paths.push(spelled.as_os_str().as_bytes().to_vec());
            let mut prospective_ids = Vec::new();
            let mut prospective_anchors = Vec::new();
            let mut prospective_suffixes = Vec::new();
            for p in resolution.prospective {
                prospective_ids.push((p.anchor.dev, p.anchor.ino));
                prospective_anchors.push(components(&p.anchor.path));
                prospective_suffixes.push(suffix_components(&p.suffix));
                let mut full = p.anchor.path;
                for c in p.suffix {
                    full.push(c);
                }
                ids.push(None);
                paths.push(full.as_os_str().as_bytes().to_vec());
            }
            // A home may itself be missing; its walk still locates prospective authority.
            let resolved_home = resolve(&home, Walk::Authority)?;
            let mut home = resolved_home.end.0.path;
            for c in resolved_home.end.1 {
                home.push(c);
            }
            dirs.push(MeasuredDir {
                spelled,
                home,
                config_file_links,
                ids,
                paths,
                prospective_ids,
                prospective_anchors,
                prospective_suffixes,
            });
        }
        Ok(Self {
            dirs,
            cwd: cwd.to_path_buf(),
        })
    }
    pub(crate) fn check_authority_links(&self) -> Result<()> {
        for d in &self.dirs {
            if let Some((file, n)) = &d.config_file_links
                && !authority_file_singly_linked(*n)
            {
                bail!(
                    "\"{}\" has {n} hard links; agent-vm will not launch while another name for it could be written from a guest and then removed. Remove the other links, or replace the file with a copy.",
                    config::escape_path(file)
                );
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
                        "agent-vm's {} \"{}\" is, or contains, \"{}\" or a directory agent-vm resolves through to reach it, where agent-vm reads launch authority; the guest could rewrite that authority for a later launch. {}",
                        source.bind.description(),
                        config::escape_path(&root),
                        config::escape_path(&d.spelled),
                        remedy(source.bind, &canonical, d)
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
                        "agent-vm's {} \"{}\" does not exist yet; once created it could be, or contain, a directory in which agent-vm looks up names on the way to \"{}\", where agent-vm reads launch authority, so the guest could plant authority there for a later launch. (Names that do not exist yet are compared ignoring letter case, and a name ending in '.' or containing characters other than ASCII letters, digits, '.', '-' or '_' is assumed to match any name.) {}",
                        source.bind.description(),
                        config::escape_path(&root),
                        config::escape_path(&d.spelled),
                        remedy(source.bind, &root, d)
                    );
                }
            }
            Err(e) => return Err(e).with_context(|| uncertain(&root)),
        }
        Ok(())
    }
    pub(crate) fn check_writable_mount(
        &self,
        spelling: &str,
        spelled_host: &Path,
        host: &Path,
    ) -> Result<()> {
        match fs::metadata(host) {
            Ok(m) => {
                let canonical = fs::canonicalize(host).with_context(|| uncertain(host))?;
                if let Some(d) =
                    self.decide(Some(spelled_host), &canonical, Some((m.dev(), m.ino())))
                {
                    bail!(
                        "--mount \"{}\" would let the guest change what \"{}\" contains or resolves to, where agent-vm reads launch authority. Mount it read-only (:ro), or mount a narrower path that does not contain it.",
                        config::escape_path(Path::new(spelling)),
                        config::escape_path(&d.spelled)
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| uncertain(host)),
        }
        Ok(())
    }
}
fn remedy(bind: CoreBind, root: &Path, dir: &MeasuredDir) -> &'static str {
    match bind {
        CoreBind::ProjectDir if root == dir.home => {
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
            home: "/home".into(),
            config_file_links: None,
            ids: vec![],
            paths: vec![],
            prospective_ids: ids.to_vec(),
            prospective_anchors: anchors,
            prospective_suffixes: suffixes,
        };
        let guard = ProtectedConfigDir {
            dirs: vec![d],
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
            }
        }
        fn guard(&self) -> ProtectedConfigDir {
            ProtectedConfigDir::measure(std::slice::from_ref(&self.home), &self.cwd).unwrap()
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
            ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &t.cwd)
                .unwrap_err()
                .to_string()
                .contains("cannot determine")
        );
        fs::remove_file(t.home.join(".config")).unwrap();
        fs::write(t.home.join(".config"), "file").unwrap();
        assert!(ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &t.cwd).is_err());
    }
    #[test]
    fn both_homes_and_messages() {
        let t = Tree::new();
        let other = t.cwd.join("other");
        fs::create_dir(&other).unwrap();
        let guard = ProtectedConfigDir::measure(&[t.home.clone(), other.clone()], &t.cwd).unwrap();
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
            .check_writable_mount("/decl", &t.home, &t.home)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("contains or resolves to"));
        assert!(msg.contains(":ro"));
        assert!(!msg.contains(":fork"));
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
        let err = ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &t.cwd).unwrap_err();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(err.to_string().contains("cannot determine"));

        // The authority directory itself can be measured, but looking up its
        // config file must fail closed independently of the route walk.
        let t = Tree::new();
        let cfg = t.home.join(".config/agent-vm");
        fs::create_dir_all(&cfg).unwrap();
        fs::write(cfg.join("config.toml"), "# no network\n").unwrap();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o000)).unwrap();
        let err = ProtectedConfigDir::measure(std::slice::from_ref(&t.home), &t.cwd).unwrap_err();
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
}
