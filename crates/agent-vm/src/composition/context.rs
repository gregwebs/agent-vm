//! The normalized build-context enumeration shared by the frozen v1 chain
//! encoder and the v2 identity encoder.
//!
//! Both encoders must hash the *same* normalization of a layer's build
//! context: the walk's lstat-not-follow rule, symlink-by-target-string,
//! directory lines with no mode, and the git-mode fold. Sharing one
//! enumeration is what keeps those rules from silently diverging; the two
//! encoders differ only in the tag and header they wrap these bytes in.
//!
//! [`NormalizedContext::read`] is the crate's caller-side filesystem adapter,
//! not a pure planner operation: it is the existing context-enumeration code
//! moved here verbatim, so the v1 hash it feeds stays bit-identical. The
//! identity/dag/plan modules above it do no I/O.

use std::{fs, io::Read, os::unix::ffi::OsStrExt, path::Path};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::hex;

/// Entry kinds. `Other` covers fifos, sockets and devices, which contribute
/// a line and are never opened: reading a fifo blocks forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
    Symlink,
    Other,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Dir => "dir",
            Kind::File => "file",
            Kind::Symlink => "symlink",
            Kind::Other => "other",
        }
    }
}

/// One enumerated path's contribution to the canonical stream.
///
/// `rel` (and, transitively, `content` for a symlink) are raw bytes, not
/// guaranteed UTF-8 — a relative path or symlink target on a Unix
/// filesystem can be any byte sequence except NUL and `/`. Hashing via
/// `OsStrExt::as_bytes()` rather than `to_string_lossy()` keeps the byte
/// stream exact instead of silently mangling non-UTF-8 names into `\u{FFFD}`
/// (which would make two different directory trees hash identically).
struct Entry {
    rel: Vec<u8>,
    kind: Kind,
    mode: &'static str,
    size: String,
    content: String,
}

/// A build context enumerated once, with every normalization rule already
/// applied, ready for a `.write_entries()` call by either encoder.
pub(crate) struct NormalizedContext {
    entries: Vec<Entry>,
    hashed_bytes: u64,
}

impl NormalizedContext {
    /// Enumerates `dir` and flat-sorts it. Enumeration errors are fatal.
    pub(crate) fn read(dir: &Path) -> Result<Self> {
        let (mut entries, hashed_bytes) = enumerate(dir)?;

        // Flat sort of the collected relative paths, not walk order. A
        // per-directory (hierarchical) sort disagrees with a flat sort whenever
        // a name containing '.' sorts differently against a sibling directory
        // than their full paths would — "a.txt" before "a/b" flatly ('.' is
        // 0x2E, '/' is 0x2F), after it hierarchically. A flat sort is the
        // property that can be stated, tested, and reproduced regardless of
        // readdir order.
        entries.sort_by(|a, b| a.rel.cmp(&b.rel));

        Ok(Self {
            entries,
            hashed_bytes,
        })
    }

    /// Every enumerated kind, not only regular files — the count a caller
    /// reports as the context's size.
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Total bytes read while hashing file contents (not directory/symlink
    /// entries, which don't stream file bytes).
    pub(crate) fn hashed_bytes(&self) -> u64 {
        self.hashed_bytes
    }

    /// Appends one NUL-delimited line per entry, in flat sorted order. Every
    /// field is present on every entry; the ones a kind has no answer for are
    /// empty, which is what makes the stream unambiguous.
    pub(crate) fn write_entries(&self, buf: &mut Vec<u8>) {
        for e in &self.entries {
            buf.extend_from_slice(&e.rel);
            buf.push(0);
            buf.extend_from_slice(e.kind.as_str().as_bytes());
            buf.push(0);
            buf.extend_from_slice(e.mode.as_bytes());
            buf.push(0);
            buf.extend_from_slice(e.size.as_bytes());
            buf.push(0);
            buf.extend_from_slice(e.content.as_bytes());
            buf.push(0);
        }
    }
}

/// Streams a file's contents through SHA-256 rather than reading it whole: a
/// layer may legitimately vendor a large tarball, and the size guard below
/// is informational (`file_count`/`hashed_bytes`) rather than a refusal, so
/// this must stay bounded in memory.
///
/// Nothing here interprets `.dockerignore`. Implementing dockerignore
/// matching (`!` negation, `**`, and the two runtimes' possibly-differing
/// implementations) here would put build-context semantics in the launcher,
/// where they could disagree with the runtime that applies them.
/// Over-hashing's failure mode is a spurious rebuild, which is safe;
/// under-hashing's is running a stale toolchain. A `.dockerignore` in the
/// layer directory is therefore hashed like any other file.
fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut f = fs::File::open(path)
        .with_context(|| format!("reading tooling layer context {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut n: u64 = 0;
    loop {
        let read = f
            .read(&mut buf)
            .with_context(|| format!("reading tooling layer context {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        n += read as u64;
    }
    Ok((hex::encode(hasher.finalize()), n))
}

/// Normalizes a file's permissions to the one bit git tracks: `0755` when
/// any execute bit is set, `0644` otherwise.
///
/// This is the least obvious line in the module and the reason it exists is
/// portability, not tidiness. File permissions vary with the umask of
/// whoever checked the repository out, so hashing the raw mode would give
/// two developers on the same commit two different tags — and therefore two
/// multi-minute builds of an identical image. Git tracks exactly one bit, so
/// a checked-out layer hashes identically on every machine that checked it
/// out, while `chmod +x build-helper.sh` still invalidates.
///
/// The accepted cost, worth stating because it narrows "a changed layer
/// always rebuilds": a `chmod 0640` genuinely changes what a `COPY` puts in
/// the image and does *not* change the tag.
fn git_mode(mode: u32) -> &'static str {
    if mode & 0o111 != 0 { "0755" } else { "0644" }
}

/// Recursively walks `dir` (never following symlinks), collecting one
/// [`Entry`] per path below `dir` (`dir` itself is skipped — its own line
/// would be a constant, and its relative path is empty, which would sort
/// ahead of everything and say nothing).
///
/// Enumeration errors are fatal: over-hashing fails by rebuilding something
/// that did not need it, which costs time; under-hashing fails by running a
/// stale toolchain, which is the bug this module must not have.
fn enumerate(dir: &Path) -> Result<(Vec<Entry>, u64)> {
    let mut entries = Vec::new();
    let mut hashed_bytes: u64 = 0;
    enumerate_into(dir, dir, &mut entries, &mut hashed_bytes)?;
    Ok((entries, hashed_bytes))
}

fn enumerate_into(
    root: &Path,
    dir: &Path,
    entries: &mut Vec<Entry>,
    hashed_bytes: &mut u64,
) -> Result<()> {
    let read_dir = fs::read_dir(dir)
        .with_context(|| format!("reading tooling layer context {}", dir.display()))?;
    for item in read_dir {
        let item =
            item.with_context(|| format!("reading tooling layer context {}", dir.display()))?;
        let path = item.path();

        // symlink_metadata (Lstat), never metadata/Stat: symlinks are not
        // followed. Following them would let the declared context reach
        // files outside itself, so the hash would depend on state the user
        // never put in the layer; a symlink loop would hang the walk; and
        // neither container runtime's symlink handling in a build context
        // is something the launcher should pretend to model.
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("reading tooling layer context {}", path.display()))?;

        let rel = relative_bytes(root, &path)
            .with_context(|| format!("reading tooling layer context {}", path.display()))?;
        let file_type = meta.file_type();

        if file_type.is_symlink() {
            // Hashed by its target *string*, not the target's contents. A
            // dangling symlink is therefore hashable and is not an error.
            let target = fs::read_link(&path)
                .with_context(|| format!("reading tooling layer context {}", path.display()))?;
            let target_bytes = target.as_os_str().as_bytes();
            let sum = Sha256::digest(target_bytes);
            entries.push(Entry {
                rel,
                kind: Kind::Symlink,
                mode: "",
                size: target_bytes.len().to_string(),
                content: hex::encode(sum),
            });
        } else if file_type.is_dir() {
            // Directories contribute a line so that adding an empty
            // directory changes the hash: a `COPY . .` makes an empty
            // directory observable in the image. Their modes are
            // deliberately *not* hashed — mkdir applies the process umask,
            // so hashing them would give two developers on the same commit
            // two different tags.
            entries.push(Entry {
                rel: rel.clone(),
                kind: Kind::Dir,
                mode: "",
                size: String::new(),
                content: String::new(),
            });
            enumerate_into(root, &path, entries, hashed_bytes)?;
        } else if file_type.is_file() {
            let (content, n) = hash_file(&path)?;
            *hashed_bytes += n;
            entries.push(Entry {
                rel,
                kind: Kind::File,
                mode: git_mode(
                    std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777,
                ),
                size: meta.len().to_string(),
                content,
            });
        } else {
            // fifos, sockets, devices: contribute a line, never opened.
            // Reading a fifo blocks forever.
            entries.push(Entry {
                rel,
                kind: Kind::Other,
                mode: "",
                size: String::new(),
                content: String::new(),
            });
        }
    }
    Ok(())
}

/// `path`'s slash-separated position relative to `root`, as raw bytes.
///
/// Hand-rolled rather than `Path::strip_prefix` + `to_string_lossy` so a
/// non-UTF-8 relative path is carried through exactly (see [`Entry`]'s doc
/// comment) instead of being lossily mangled. The platform separator (always
/// `/` on the Unix targets this module runs on) needs no conversion, so this
/// is a straight byte-slice copy after stripping the root prefix and any
/// leading separator.
fn relative_bytes(root: &Path, path: &Path) -> Result<Vec<u8>> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| anyhow::anyhow!("{} is not under {}", path.display(), root.display()))?;
    let bytes = rel.as_os_str().as_bytes();
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::{git_mode, relative_bytes};

    /// The fold must honor *any* execute bit, not one named bit.
    ///
    /// Git only ever checks out `100644`/`100755`, so on a real checkout all
    /// three execute bits agree and a rule that looks at only the owner bit
    /// (`0o100`) or only the group/other bits (`0o011`) is indistinguishable
    /// by the end-to-end hash tests. A context materialized outside git can
    /// carry `0010` or `0001` on its own, and the v1 contract is that *any*
    /// execute bit folds to `0755`. Pinning each bit alone is what tells the
    /// any-bit rule apart from a single-bit mask in either direction.
    #[test]
    fn git_mode_folds_any_execute_bit_not_just_one_named_bit() {
        assert_eq!(git_mode(0o644), "0644");
        assert_eq!(git_mode(0o600), "0644");
        assert_eq!(git_mode(0o755), "0755");

        // Each execute bit on its own, owner included: a mask that honors
        // only the owner bit misses the last two; a mask that honors only
        // group/other misses the first.
        assert_eq!(git_mode(0o100), "0755", "owner execute alone counts");
        assert_eq!(git_mode(0o010), "0755", "group execute alone counts");
        assert_eq!(git_mode(0o001), "0755", "other execute alone counts");
    }

    /// [`relative_bytes`] must carry a relative path's raw bytes, not a lossy
    /// string. The v1 encoder hashes paths byte-for-byte, so a
    /// `to_string_lossy` refactor would map every non-UTF-8 byte to U+FFFD and
    /// make two different directory trees hash identically. APFS (macOS)
    /// refuses non-UTF-8 names, so this uses a synthetic path that never
    /// touches the filesystem and pins the behavior on every platform; the
    /// end-to-end `layer::tests::v1_hash_context_golden_non_utf8_path` golden
    /// covers the same rule where the filesystem allows it.
    #[test]
    fn relative_bytes_preserves_non_utf8_bytes() {
        let root = Path::new("/root");
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/root/caf\xE9.txt"));
        assert_eq!(relative_bytes(root, path).unwrap(), b"caf\xE9.txt".to_vec());
    }
}
