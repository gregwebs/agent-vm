//! Turn a project's tooling layer directory into the identity of the derived
//! image the launcher must (eventually) run.
//!
//! Identity is a content hash rather than a recorded state file: the tag
//! itself is the staleness check, so there is nothing to forget to write and
//! nothing that can disagree with the image store. (ADR for the full
//! tooling-layer design lands with the build/boot ticket that consumes this
//! module.)
//!
//! Ported from `claude-contained`'s `internal/layer/{hash,layer}.go` and
//! `internal/host/sanitize.go` — see those files for the original Go
//! implementation this mirrors. This module only builds the identity; no
//! image is built or booted here (that is the next ticket).

use std::{
    fs,
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// The derived images' repository name, separate from the base image's so a
/// listing (`docker image ls` equivalent) stays a readable per-project
/// cleanup handle.
const REPO: &str = "agent-vm-layer";

/// Version tag for these enumeration rules. Exists so a future change to
/// them deliberately invalidates every derived image instead of silently
/// colliding with images hashed under the old rules — a collision there
/// means running a toolchain that is not the one the layer describes, which
/// is the single failure this module exists to prevent.
const SCHEME_TAG: &[u8] = b"agent-vm-layer\x00v1\x00";

/// How much of the SHA-256 the tag carries, in hex characters. Truncating a
/// digest at all follows the precedent elsewhere in this codebase of
/// shortening a hash for a human-facing name; this one decides whether to
/// skip a build, so 32 hex chars (128 bits) is used rather than something
/// shorter — a collision here means silently running the wrong toolchain.
const HASH_LEN: usize = 32;

/// Default tooling-layer directory, relative to the project root.
const DEFAULT_LAYER_SUBDIR: &str = ".agent-vm/layer";

/// Env var carrying an explicit layer directory override. Read by clap
/// (`env = "AGENT_VM_LAYER"` on the `--layer` flag in `run.rs`), not by this
/// module directly — see [`resolve_layer_dir`].
#[allow(dead_code)] // documents the wiring; the literal lives in run.rs's clap attribute
const LAYER_ENV: &str = "AGENT_VM_LAYER";

/// Mirrors `claude-contained`'s `maxFolderNameLen` (`cut -c1-20` in the
/// original bash `sanitize_foldername`).
const MAX_SLUG_LEN: usize = 20;

/// Everything a caller needs about a resolved, hashed layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerIdentity {
    /// The layer directory, which is also the build context.
    pub dir: PathBuf,
    /// The build recipe inside `dir`.
    pub dockerfile: PathBuf,
    /// `REPO:<slug>-<hash>`.
    pub tag: String,
    /// The truncated content digest, [`HASH_LEN`] hex characters.
    pub hash: String,
    /// Lets a caller warn about an oversized context without this module
    /// owning a size policy. Nothing here refuses anything.
    pub file_count: usize,
    /// Total bytes read while hashing file contents (not directory/symlink
    /// entries, which don't stream file bytes).
    pub hashed_bytes: u64,
}

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

/// Renders `(base_image_id, the directory tree under `dir`)` as one
/// canonical, domain-separated, length-unambiguous byte stream:
///
/// ```text
/// "agent-vm-layer\x00v1\x00"
/// "base\x00" <baseImageID> "\x00"
/// per entry, in flat sorted relative-path (byte-lexicographic) order:
///     <relPath> "\x00" <kind> "\x00" <mode> "\x00" <size> "\x00" <contentHash> "\x00"
/// ```
///
/// Every field is present on every entry; the ones a kind has no answer for
/// are empty. That is what makes the stream unambiguous: no reading of it
/// can be confused about where one entry ends.
///
/// This is a separate function from [`hash_context`], and named, so the
/// golden test in this module's `tests` submodule can pin the format against
/// a literal expected byte string a human can read and argue with. An
/// expected *digest* could be neither written nor reviewed by hand — and it
/// is precisely because the stream is pinned this legibly that a future
/// format change only needs [`SCHEME_TAG`] bumped.
///
/// The Dockerfile is not hashed separately from the rest. The layer
/// directory *is* the build context, so `Dockerfile` is enumerated like
/// every other file; hashing it twice would add nothing and invite a bug
/// where the two copies disagree about which bytes count.
///
/// Nothing is refused. Size policy is the caller's: over-hashing only costs
/// a slower run, so a hard limit here would refuse a project's own
/// legitimate layer for no reachable benefit — "a container that looks
/// healthy while missing its toolchain" is the exact outcome this design
/// exists to prevent.
fn canonical_stream(dir: &Path, base_image_id: &str) -> Result<(Vec<u8>, usize, u64)> {
    let (mut entries, hashed_bytes) = enumerate(dir)?;

    // Flat sort of the collected relative paths, not walk order. A
    // per-directory (hierarchical) sort disagrees with a flat sort whenever
    // a name containing '.' sorts differently against a sibling directory
    // than their full paths would — "a.txt" before "a/b" flatly ('.' is
    // 0x2E, '/' is 0x2F), after it hierarchically. A flat sort is the
    // property that can be stated, tested, and reproduced regardless of
    // readdir order.
    entries.sort_by(|a, b| a.rel.cmp(&b.rel));

    let count = entries.len();
    let mut buf = Vec::new();
    buf.extend_from_slice(SCHEME_TAG);
    buf.extend_from_slice(b"base\x00");
    buf.extend_from_slice(base_image_id.as_bytes());
    buf.push(0);
    for e in &entries {
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
    Ok((buf, count, hashed_bytes))
}

/// The SHA-256 of [`canonical_stream`], hex-encoded in full. [`resolve`]
/// truncates it for the tag.
fn hash_context(dir: &Path, base_image_id: &str) -> Result<(String, usize, u64)> {
    let (stream, count, hashed_bytes) = canonical_stream(dir, base_image_id)?;
    Ok((hex::encode(Sha256::digest(&stream)), count, hashed_bytes))
}

/// Hashes `dir` against `base_image_id` and names the derived image.
///
/// The *hash* covers exactly the base image's resolved digest, the
/// Dockerfile, and the rest of the build-context files. The *tag* is that
/// hash plus a readable project prefix, which is decorative and
/// deliberately not part of the hash. The consequence — two projects with
/// byte-identical layers on the same base build twice — buys per-project
/// cleanup: `docker image ls agent-vm-layer` stays a readable handle instead
/// of a bare content address.
pub fn resolve(dir: &Path, project_dir: &Path, base_image_id: &str) -> Result<LayerIdentity> {
    let (digest, count, hashed_bytes) = hash_context(dir, base_image_id)?;
    let hash = digest[..HASH_LEN].to_string();

    // project_dir is passed whole, not through a basename helper first —
    // slug() applies its own basename extraction, and wrapping it here would
    // risk a second, disagreeing truncation. slug() truncates at
    // MAX_SLUG_LEN on its own, so there is no second truncation here, and
    // its output can legally end in a dash (trimming happens before
    // truncation), which makes `slug--hash` a tag every consumer must
    // tolerate.
    let slug = slug(project_dir);

    Ok(LayerIdentity {
        dir: dir.to_path_buf(),
        dockerfile: dir.join("Dockerfile"),
        tag: format!("{REPO}:{slug}-{hash}"),
        hash,
        file_count: count,
        hashed_bytes,
    })
}

/// Sanitizes `project_dir`'s basename into a tag-safe slug: `[a-z0-9-]`,
/// truncated to [`MAX_SLUG_LEN`].
///
/// Ported from `claude-contained`'s `host.SanitizeFolderName`
/// (`internal/host/sanitize.go`), which is itself a byte-for-byte port of a
/// bash `sanitize_foldername` helper. Steps: Unicode-lowercase the basename,
/// replace every non-`[a-z0-9]` byte with a dash, collapse dash runs, trim
/// leading/trailing dashes, truncate to [`MAX_SLUG_LEN`], and fall back to
/// `"root"` if that leaves nothing.
///
/// Unicode `str::to_lowercase` (not `to_ascii_lowercase`) is deliberate: the
/// Go original uses `strings.ToLower`, whose Unicode-aware casing (e.g.
/// 'İ' → 'i') is the behavior verified against the reference bash tool under
/// the UTF-8 locales it actually runs in — an ASCII-only lowercasing would
/// be the divergence here, not the fidelity.
///
/// The detail that is easiest to get wrong: dash trimming happens *before*
/// truncation, so truncating at 20 can legitimately leave a trailing dash
/// (`"abcdefghijklmnopqrs-tuv"` → `"abcdefghijklmnopqrs-"`).
///
/// Divergence from the Go port, accepted rather than reproduced: Go's
/// `baseName` special-cases a leading-dash path to the empty string,
/// emulating how `basename(1)` (which the original bash tool shelled out to)
/// treats a leading dash as an option flag and errors out. agent-vm has no
/// parity requirement with `claude-contained`, and reproducing a
/// `basename(1)` option-parsing quirk in a path-sanitizing helper would be
/// surprising on its own terms — a straight `Path::file_name()`-based
/// basename is used here instead, so a project directory literally named
/// `-foo` slugs to `"foo"` rather than `"root"`.
fn slug(project_dir: &Path) -> String {
    let name = basename(project_dir).to_lowercase();

    let mut dashed: Vec<u8> = name
        .bytes()
        .map(|b| {
            if b.is_ascii_lowercase() || b.is_ascii_digit() {
                b
            } else {
                b'-'
            }
        })
        .collect();

    // Collapse runs of '-'.
    let mut collapsed: Vec<u8> = Vec::with_capacity(dashed.len());
    let mut prev_dash = false;
    for &b in &dashed {
        if b == b'-' {
            if prev_dash {
                continue;
            }
            prev_dash = true;
        } else {
            prev_dash = false;
        }
        collapsed.push(b);
    }
    dashed = collapsed;

    // Trim leading/trailing dash.
    let mut start = 0;
    let mut end = dashed.len();
    if start < end && dashed[start] == b'-' {
        start += 1;
    }
    if end > start && dashed[end - 1] == b'-' {
        end -= 1;
    }
    let mut trimmed = dashed[start..end].to_vec();

    if trimmed.len() > MAX_SLUG_LEN {
        trimmed.truncate(MAX_SLUG_LEN);
    }

    if trimmed.is_empty() {
        return "root".to_string();
    }
    // Safe: every byte in `trimmed` is ASCII ('a'-'z', '0'-'9', or '-').
    String::from_utf8(trimmed).expect("slug bytes are ASCII by construction")
}

/// `basename(path)` for the purpose of [`slug`]: the final path component,
/// with a trailing `/` (or an all-slash / empty path) treated as nameless.
/// Unlike [`Path::file_name`], this never returns `None` — a nameless input
/// yields the empty string, which [`slug`] then falls back to `"root"` for.
fn basename(path: &Path) -> String {
    let trimmed = path.as_os_str().as_bytes();
    let trimmed = {
        let mut end = trimmed.len();
        while end > 0 && trimmed[end - 1] == b'/' {
            end -= 1;
        }
        &trimmed[..end]
    };
    if trimmed.is_empty() {
        return String::new();
    }
    let start = trimmed
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&trimmed[start..]).into_owned()
}

/// Resolves the project's tooling-layer directory, applying precedence and
/// the fail-closed missing-`Dockerfile` rule.
///
/// `flag` is the *pre-resolved* explicit source: the caller (`run.rs`) folds
/// `$AGENT_VM_LAYER` into the clap flag's value via `env = "AGENT_VM_LAYER"`
/// before calling this, and filters an explicitly-set-but-empty value to
/// `None` first (`AGENT_VM_LAYER=""` must resolve as "unset", not as an
/// explicit empty-path layer dir) — so this function does not read the
/// environment itself and an env-sourced value is indistinguishable from a
/// `--layer`-sourced one, which is the desired behavior.
///
/// Precedence, once resolved to a single optional path by the caller:
///
/// - `flag` explicit (whether from `--layer` or `$AGENT_VM_LAYER`): the
///   directory must exist and contain a `Dockerfile`, or this is a hard
///   error naming which one is missing.
/// - otherwise, the default `project_dir/.agent-vm/layer`: absent means "no
///   layer" (`Ok(None)`); present without a `Dockerfile` is still a hard
///   error — a present default layer dir is a declared layer, and a missing
///   Dockerfile in it is a mistake, not "no layer".
pub fn resolve_layer_dir(flag: Option<&Path>, project_dir: &Path) -> Result<Option<PathBuf>> {
    match flag {
        Some(dir) => {
            if !dir.is_dir() {
                bail!(
                    "--layer {} does not exist or is not a directory",
                    dir.display()
                );
            }
            let dockerfile = dir.join("Dockerfile");
            if !dockerfile.is_file() {
                bail!(
                    "--layer {} has no Dockerfile (expected {})",
                    dir.display(),
                    dockerfile.display()
                );
            }
            Ok(Some(dir.to_path_buf()))
        }
        None => {
            let dir = project_dir.join(DEFAULT_LAYER_SUBDIR);
            if !dir.exists() {
                return Ok(None);
            }
            if !dir.is_dir() {
                bail!(
                    "default tooling-layer path {} exists but is not a directory",
                    dir.display()
                );
            }
            let dockerfile = dir.join("Dockerfile");
            if !dockerfile.is_file() {
                bail!(
                    "tooling-layer directory {} has no Dockerfile (expected {})",
                    dir.display(),
                    dockerfile.display()
                );
            }
            Ok(Some(dir))
        }
    }
}

// hex encode/decode without a new dependency: sha2 already gives us
// GenericArray output, and the hex alphabet is trivial to hand-roll. Kept
// tiny and private to this module rather than pulling in the `hex` crate for
// two functions.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const TEST_BASE_ID: &str = "sha256:base00";

    /// Writes one file and chmods it explicitly. The chmod matters:
    /// `fs::write`'s mode is masked by the process umask, and several cases
    /// are *about* what the mode contributes to the hash, so the bits have
    /// to be the ones the case names rather than the ones the developer's
    /// umask allows.
    fn write_layer_file(dir: &Path, rel: &str, content: &str, mode: u32) {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn digest_of(s: &str) -> String {
        hex::encode(Sha256::digest(s.as_bytes()))
    }

    fn must_hash(dir: &Path) -> String {
        hash_context(dir, TEST_BASE_ID).unwrap().0
    }

    fn must_stream(dir: &Path) -> String {
        String::from_utf8(canonical_stream(dir, TEST_BASE_ID).unwrap().0).unwrap()
    }

    // The specification. A small fixed tree, and the exact bytes it must
    // produce, with every NUL spelled out. Everything else in this module is
    // downstream of this format; if this test and the code disagree, this
    // test is right.
    #[test]
    fn canonical_stream_is_exactly_the_documented_format() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_layer_file(dir, "Dockerfile", "FROM scratch\n", 0o644);
        write_layer_file(dir, "scripts/a.sh", "echo hi\n", 0o755);
        fs::create_dir(dir.join("empty")).unwrap();
        std::os::unix::fs::symlink("target-does-not-exist", dir.join("link")).unwrap();

        let want = format!(
            "agent-vm-layer\x00v1\x00base\x00{TEST_BASE_ID}\x00\
             Dockerfile\x00file\x000644\x0013\x00{}\x00\
             empty\x00dir\x00\x00\x00\x00\
             link\x00symlink\x00\x0021\x00{}\x00\
             scripts\x00dir\x00\x00\x00\x00\
             scripts/a.sh\x00file\x000755\x008\x00{}\x00",
            digest_of("FROM scratch\n"),
            digest_of("target-does-not-exist"),
            digest_of("echo hi\n"),
        );

        assert_eq!(must_stream(dir), want);
    }

    #[test]
    fn hash_is_stable_across_repeated_calls() {
        let tmp = tempfile::tempdir().unwrap();
        write_layer_file(tmp.path(), "Dockerfile", "FROM scratch\n", 0o644);
        assert_eq!(must_hash(tmp.path()), must_hash(tmp.path()));
    }

    #[test]
    fn base_image_id_participates_in_the_hash() {
        let tmp = tempfile::tempdir().unwrap();
        write_layer_file(tmp.path(), "Dockerfile", "FROM scratch\n", 0o644);

        let before = hash_context(tmp.path(), "sha256:aaaa").unwrap().0;
        let after = hash_context(tmp.path(), "sha256:bbbb").unwrap().0;
        assert_ne!(before, after, "changing only the base image ID must change the hash");
    }

    #[test]
    fn adding_an_empty_directory_changes_the_hash() {
        let tmp = tempfile::tempdir().unwrap();
        write_layer_file(tmp.path(), "Dockerfile", "FROM scratch\n", 0o644);
        let before = must_hash(tmp.path());
        fs::create_dir(tmp.path().join("sub")).unwrap();
        let after = must_hash(tmp.path());
        assert_ne!(before, after);
    }

    #[test]
    fn setting_the_execute_bit_changes_the_hash() {
        let tmp = tempfile::tempdir().unwrap();
        write_layer_file(tmp.path(), "Dockerfile", "FROM scratch\n", 0o644);
        write_layer_file(tmp.path(), "a.txt", "content\n", 0o644);
        let before = must_hash(tmp.path());
        fs::set_permissions(tmp.path().join("a.txt"), fs::Permissions::from_mode(0o755)).unwrap();
        let after = must_hash(tmp.path());
        assert_ne!(before, after);
    }

    // The counterpart to the execute-bit case, and the reason git_mode
    // exists: permissions vary with the checkout's umask, so anything but
    // the execute bit must be invisible or two developers on the same
    // commit get two tags.
    #[test]
    fn non_executable_mode_bits_do_not_change_the_hash() {
        let tmp = tempfile::tempdir().unwrap();
        write_layer_file(tmp.path(), "Dockerfile", "FROM scratch\n", 0o644);
        write_layer_file(tmp.path(), "a.txt", "content\n", 0o644);
        let before = must_hash(tmp.path());
        fs::set_permissions(tmp.path().join("a.txt"), fs::Permissions::from_mode(0o640)).unwrap();
        let after = must_hash(tmp.path());
        assert_eq!(before, after, "chmod 0640 must not change the hash; only the execute bit is tracked");
    }

    #[test]
    fn hash_is_stable_across_different_umasks() {
        // Simulate two checkouts under different umasks by writing the
        // "same" file at two different raw modes that agree on the
        // execute bit (git only ever tracks 0644 or 0755).
        let a = tempfile::tempdir().unwrap();
        write_layer_file(a.path(), "Dockerfile", "FROM scratch\n", 0o644);
        write_layer_file(a.path(), "run.sh", "echo hi\n", 0o755);

        let b = tempfile::tempdir().unwrap();
        write_layer_file(b.path(), "Dockerfile", "FROM scratch\n", 0o664);
        write_layer_file(b.path(), "run.sh", "echo hi\n", 0o775);

        assert_eq!(
            must_hash(a.path()),
            must_hash(b.path()),
            "umask-driven mode differences that agree on the execute bit must hash identically"
        );
    }

    #[test]
    fn symlinks_are_hashed_by_target_string_and_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_layer_file(dir, "Dockerfile", "FROM scratch\n", 0o644);
        write_layer_file(dir, "real.txt", "one\n", 0o644);
        std::os::unix::fs::symlink("real.txt", dir.join("link")).unwrap();

        let before = must_hash(dir);

        // Changing the *target's* contents to the same bytes must not move
        // the hash — proving the symlink is not followed.
        write_layer_file(dir, "real.txt", "one\n", 0o644);
        assert_eq!(must_hash(dir), before);

        // Retargeting does change it: the target string is the hashed
        // content.
        fs::remove_file(dir.join("link")).unwrap();
        std::os::unix::fs::symlink("elsewhere.txt", dir.join("link")).unwrap();
        assert_ne!(must_hash(dir), before);
    }

    #[test]
    fn dangling_symlink_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        write_layer_file(tmp.path(), "Dockerfile", "FROM scratch\n", 0o644);
        std::os::unix::fs::symlink("nothing-is-here", tmp.path().join("broken")).unwrap();

        hash_context(tmp.path(), TEST_BASE_ID).expect("a dangling symlink must be hashable");
    }

    #[test]
    fn flat_sort_orders_dotted_names_before_sibling_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_layer_file(dir, "Dockerfile", "FROM scratch\n", 0o644);
        write_layer_file(dir, "a.txt", "flat\n", 0o644);
        write_layer_file(dir, "a/b", "nested\n", 0o644);

        let stream = must_stream(dir);
        let dotted = stream.find("a.txt\x00").unwrap();
        let nested = stream.find("a/b\x00").unwrap();
        assert!(
            dotted < nested,
            "a.txt must precede a/b: the enumeration sorts full relative paths flatly, not per directory"
        );
    }

    #[test]
    fn creation_order_does_not_change_the_hash() {
        let forward = tempfile::tempdir().unwrap();
        write_layer_file(forward.path(), "Dockerfile", "FROM scratch\n", 0o644);
        write_layer_file(forward.path(), "a.txt", "a\n", 0o644);
        write_layer_file(forward.path(), "z/deep.txt", "z\n", 0o644);

        let backward = tempfile::tempdir().unwrap();
        write_layer_file(backward.path(), "z/deep.txt", "z\n", 0o644);
        write_layer_file(backward.path(), "a.txt", "a\n", 0o644);
        write_layer_file(backward.path(), "Dockerfile", "FROM scratch\n", 0o644);

        assert_eq!(must_hash(forward.path()), must_hash(backward.path()));
    }

    // --- resolve() / tag derivation ---

    fn layer_dir_fixture() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        write_layer_file(tmp.path(), "Dockerfile", "FROM scratch\n", 0o644);
        tmp
    }

    #[test]
    fn resolve_names_the_derived_image() {
        let dir = layer_dir_fixture();
        let id = resolve(dir.path(), Path::new("/work/my-app"), TEST_BASE_ID).unwrap();

        assert_eq!(id.hash.len(), HASH_LEN);
        assert_eq!(id.tag, format!("{REPO}:my-app-{}", id.hash));
        assert_eq!(id.dir, dir.path());
        assert_eq!(id.dockerfile, dir.path().join("Dockerfile"));
        assert_eq!(id.file_count, 1);
        assert_eq!(id.hashed_bytes, "FROM scratch\n".len() as u64);
    }

    #[test]
    fn resolve_slug_shapes() {
        let dir = layer_dir_fixture();
        let cases: &[(&str, &str)] = &[
            ("/work/My Project!", "my-project"),
            (
                "/work/abcdefghijklmnopqrstuvwxyz",
                "abcdefghijklmnopqrst",
            ),
            (
                "/work/abcdefghijklmnopqrs-tuv",
                "abcdefghijklmnopqrs-",
            ),
            ("/", "root"),
        ];
        for (project_dir, want_slug) in cases {
            let id = resolve(dir.path(), Path::new(project_dir), TEST_BASE_ID).unwrap();
            assert_eq!(
                id.tag,
                format!("{REPO}:{want_slug}-{}", id.hash),
                "project_dir = {project_dir}"
            );
        }
    }

    #[test]
    fn resolve_passes_the_project_path_whole() {
        let dir = layer_dir_fixture();
        let with_slash = resolve(dir.path(), Path::new("/work/my-app/"), TEST_BASE_ID).unwrap();
        let without_slash = resolve(dir.path(), Path::new("/work/my-app"), TEST_BASE_ID).unwrap();
        assert_eq!(with_slash.tag, without_slash.tag);
    }

    #[test]
    fn resolve_hash_ignores_the_project_directory() {
        let dir = layer_dir_fixture();
        let a = resolve(dir.path(), Path::new("/work/alpha"), TEST_BASE_ID).unwrap();
        let b = resolve(dir.path(), Path::new("/work/beta"), TEST_BASE_ID).unwrap();
        assert_eq!(a.hash, b.hash);
    }

    // --- slug() sanitization ---

    #[test]
    fn slug_sanitizes_mixed_case_and_punctuation() {
        assert_eq!(slug(Path::new("/work/My Project!")), "my-project");
    }

    #[test]
    fn slug_collapses_non_alnum_runs_to_one_dash() {
        assert_eq!(slug(Path::new("/work/a---b___c")), "a-b-c");
    }

    #[test]
    fn slug_trims_leading_and_trailing_dashes() {
        assert_eq!(slug(Path::new("/work/-abc-")), "abc");
    }

    #[test]
    fn slug_truncates_at_twenty() {
        assert_eq!(
            slug(Path::new("/work/abcdefghijklmnopqrstuvwxyz")),
            "abcdefghijklmnopqrst"
        );
    }

    #[test]
    fn slug_empty_or_slash_falls_back_to_root() {
        assert_eq!(slug(Path::new("/")), "root");
        assert_eq!(slug(Path::new("")), "root");
    }

    // --- resolve_layer_dir() precedence & errors ---

    #[test]
    fn explicit_dir_with_dockerfile_resolves() {
        let dir = layer_dir_fixture();
        let project = tempfile::tempdir().unwrap();
        let got = resolve_layer_dir(Some(dir.path()), project.path()).unwrap();
        assert_eq!(got, Some(dir.path().to_path_buf()));
    }

    #[test]
    fn explicit_dir_without_dockerfile_errors() {
        let dir = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let err = resolve_layer_dir(Some(dir.path()), project.path()).unwrap_err();
        assert!(format!("{err:?}").contains("Dockerfile"));
    }

    #[test]
    fn default_dir_absent_resolves_to_none() {
        let project = tempfile::tempdir().unwrap();
        let got = resolve_layer_dir(None, project.path()).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn default_dir_present_without_dockerfile_errors() {
        let project = tempfile::tempdir().unwrap();
        fs::create_dir_all(project.path().join(DEFAULT_LAYER_SUBDIR)).unwrap();
        let err = resolve_layer_dir(None, project.path()).unwrap_err();
        assert!(format!("{err:?}").contains("Dockerfile"));
    }

    #[test]
    fn default_dir_present_with_dockerfile_resolves() {
        let project = tempfile::tempdir().unwrap();
        let layer_dir = project.path().join(DEFAULT_LAYER_SUBDIR);
        fs::create_dir_all(&layer_dir).unwrap();
        fs::write(layer_dir.join("Dockerfile"), "FROM scratch\n").unwrap();
        let got = resolve_layer_dir(None, project.path()).unwrap();
        assert_eq!(got, Some(layer_dir));
    }
}
