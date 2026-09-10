//! Compose a project's ordered chain of tooling layers into the identity of
//! the final derived image, then build, registry-lessly load, and report on
//! that derived image.
//!
//! A project declares its chain under `.agent-vm/layers/`; each immediate
//! subdirectory is one step, built `FROM` the previous step (the base image
//! for step 0). A repeatable `--layer DIR` flag appends more steps after
//! those, in command-line order — never prepends, and never overrides them
//! — so a project's own steps keep their tags whether or not any flag is
//! passed. Only the final step is registry-lessly ingested — the
//! intermediates live in docker's own local image store and are pinned for
//! the next step by their tag.
//!
//! Identity is a content hash rather than a recorded state file: each step's
//! hash covers the previous step's hash (a Merkle chain anchored on the base
//! image's manifest digest), so the tag itself is the staleness check — there
//! is nothing to forget to write and nothing that can disagree with the image
//! store. See `docs/adr/0003-project-tooling-layers.md` for the full design,
//! including the amendment recording this chain and why it hashes against the
//! previous step's content hash rather than its docker image id.
//!
//! Ported from `claude-contained`'s `internal/layer/{hash,layer}.go` and
//! `internal/host/sanitize.go` — see those files for the original Go
//! implementation this mirrors (single-layer only; the chain is native to
//! this port).
//!
//! The module splits into three sections: identity (pure, no I/O beyond
//! reading a layer directory to hash it), chain composition (pure planning
//! plus the effectful [`ChainRuntime`] seam), and build & load (the only
//! I/O/process-spawning code here — `docker buildx build` plus a
//! registry-less `microsandbox_image::load_archive` ingest). `run.rs`
//! orchestrates calling into all three from `launch()`.

use std::{
    fs,
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
// `microsandbox_image::Digest` (a content digest) and `sha2::Digest` (the
// hasher trait) share a name; the sha2 one is used pervasively below via
// unqualified `Digest`/`Sha256`, so the image crate's type is referenced
// fully-qualified at its two call sites instead of importing it here.
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

/// The tooling-layer chain directory, relative to the project root. Its
/// immediate subdirectories are the chain, in lexicographic order — this is
/// the only place a *project* declares its chain. `--layer` steps
/// (repeatable, flag-only) are appended after these (see
/// [`resolve_layer_chain`]); there is no environment-variable override.
const LAYERS_SUBDIR: &str = ".agent-vm/layers";

/// The removed single-layer path. Retained solely to detect an un-migrated
/// checkout and fail with a useful message (see [`resolve_layer_chain`]);
/// nothing reads a layer from here.
const LEGACY_LAYER_SUBDIR: &str = ".agent-vm/layer";

/// Mirrors `claude-contained`'s `maxFolderNameLen` (`cut -c1-20` in the
/// original bash `sanitize_foldername`).
const MAX_SLUG_LEN: usize = 20;

/// A step's place in the chain. Display/orchestration metadata only — it is
/// deliberately not part of the hash (see [`resolve`]'s doc comment): the
/// chain's transitivity already comes from feeding each step's content hash
/// in as the next step's `base_image_id`, so hashing the position too would
/// only fragment the cache (step 0 of a one-step chain and step 0 of a
/// two-step chain, over identical inputs, must share a tag) and would break
/// the free-migration property (a bare directory's tag must match what a
/// one-step chain produces for the same contents).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPosition {
    pub index: usize,
    pub total: usize,
}

impl ChainPosition {
    /// 1-based, for humans: "step 2/3".
    pub fn human(self) -> String {
        format!("{}/{}", self.index + 1, self.total)
    }
}

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
    /// This step's place in the chain. Not hashed — see [`ChainPosition`].
    pub position: ChainPosition,
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
pub fn resolve(
    dir: &Path,
    project_dir: &Path,
    base_image_id: &str,
    position: ChainPosition,
) -> Result<LayerIdentity> {
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
        position,
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

/// Where a chain step was declared. Display/orchestration metadata only —
/// deliberately NOT hashed, exactly like [`ChainPosition`]: `resolve`'s
/// hash covers a step's build context and its predecessor, never how the
/// step was named on the command line. That is also what makes
/// try-then-adopt free (see `docs/adr/0003-project-tooling-layers.md`'s
/// amendment): `--layer examples/layers/x` and a copy of the same contents
/// at `.agent-vm/layers/10-x` must hash identically at the same position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerOrigin {
    Project,
    Flag,
}

/// One resolved chain-step directory, before hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainDir {
    /// Absolute path used as the build context. For a project step this is
    /// `project_dir/.agent-vm/layers/<name>`, not canonicalised, so a
    /// symlinked step still displays under its own name; for a `--layer`
    /// step it is the canonicalised absolute path (symlinks resolved, so
    /// dedup can see through them).
    pub dir: PathBuf,
    pub origin: LayerOrigin,
    /// What humans see in the prompt, notices and errors: `.agent-vm/layers/10-a`
    /// for a project step, or `--layer examples/layers/chrome-devtools` (the
    /// flag value exactly as typed) for a flag step.
    pub label: String,
}

/// The project's tooling-layer chain, in build order: its own
/// `.agent-vm/layers/*` steps, then any `--layer DIR` values, in
/// command-line order. Empty means "no layer declared", which the caller
/// turns into "boot the base unchanged".
///
/// There is no *precedence* — nothing overrides anything — but there is
/// *composition*: `--layer` steps are always appended after the project's
/// own, never prepended, so a project's steps keep the same tags (and stay
/// cache hits) whether or not any `--layer` is passed. `$AGENT_VM_LAYER` was
/// removed with this change (issue #79) and is rejected elsewhere
/// (`run.rs`'s `reject_removed_layer_env`); this function never reads the
/// environment.
///
/// Resolution, checked in this order:
///
/// 0. `project_dir` is canonicalised once and used for every comparison
///    below (the ancestor check, dedup keys, resolving relative `--layer`
///    values). Production already passes a canonical `project_dir`
///    (`ProjectSession::for_cwd`), but this still matters under test, where
///    a `TempDir` root can canonicalise to a different path (`/var/…` vs
///    `/private/var/…` on macOS) than the one handed in.
/// 1. [`LEGACY_LAYER_SUBDIR`] (`.agent-vm/layer/`, singular) exists in any
///    form — checked first, unconditionally, whether or not
///    [`LAYERS_SUBDIR`] also exists and regardless of `flag_dirs` — is a
///    hard error naming the path and the migration to run. This is a
///    migration guardrail, not backwards compatibility: nothing about the
///    old layout still works, including reaching it through `--layer`. The
///    alternative (silently ignoring it) would let an un-migrated checkout
///    boot looking healthy while missing the toolchain the user believes
///    they declared — exactly the failure this module exists to prevent.
///    The suggested `git mv` is safe to run without invalidating anything
///    already built: the hash covers the directory's *contents*, not its
///    path (see `canonical_stream`), so migrating is a pure rename.
/// 2. Project steps, independent of `flag_dirs`:
///    - [`LAYERS_SUBDIR`] absent ⇒ no project steps.
///    - present as a file (the predictable rename-without-nesting mistake)
///      ⇒ a hard error pointing at a numbered subdirectory, distinct from
///      the legacy-directory error above.
///    - present as a directory with no subdirectories ⇒ a hard error
///      ("declares no layer steps") **even when `flag_dirs` supplies
///      layers** — the project declared a chain location with no steps, and
///      booting base + flag layers would still boot without the project's
///      own toolchain, the same looks-healthy-but-missing-it failure.
///    - otherwise, its immediate subdirectories, byte-lexicographically
///      sorted by file name (`fs::read_dir` order is arbitrary, so this sort
///      is mandatory — `10-a` < `20-b` < `30-c` falls out of byte order).
///      Each must hold a `Dockerfile` ([`require_step_dir`]). Non-directory
///      entries (`README.md`, `.gitkeep`) are ignored — they are not steps.
/// 3. Flag steps, in command-line order. For each, checks run in this fixed
///    order — the ancestor check must precede the `Dockerfile` check, or
///    `--layer ..` would report "no Dockerfile" instead of the real problem:
///    non-empty; exists and is a directory (resolved against the canonical
///    project dir if relative, then canonicalised); is not the project
///    directory or an ancestor of it; holds a `Dockerfile` (with a hint when
///    the directory instead holds subdirectories that are themselves
///    layers).
/// 4. Duplicate detection across the combined chain, keyed by canonical
///    path — covers a flag repeated, a flag naming a project step, and
///    symlink aliasing.
pub fn resolve_layer_chain(project_dir: &Path, flag_dirs: &[PathBuf]) -> Result<Vec<ChainDir>> {
    let legacy = project_dir.join(LEGACY_LAYER_SUBDIR);
    if legacy.exists() {
        bail!(
            "{} is no longer supported (agent-vm now composes an ordered chain \
             of layers). Move it under {}/ as a numbered step, e.g.\n  \
             git mv {} {}/10-tools\n\
             Your already-built image is not invalidated by the move: the layer \
             hash covers the directory's contents, not its path.",
            legacy.display(),
            project_dir.join(LAYERS_SUBDIR).display(),
            legacy.display(),
            project_dir.join(LAYERS_SUBDIR).display(),
        );
    }

    // Phase 0 (see the doc comment above): canonicalise once, use
    // everywhere below that compares against the project root.
    let canonical_project = project_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing project directory {}", project_dir.display()))?;

    let mut chain = resolve_project_steps(project_dir)?;
    chain.extend(resolve_flag_steps(&canonical_project, flag_dirs)?);
    reject_duplicate_steps(&chain)?;
    Ok(chain)
}

/// Phase 2 of [`resolve_layer_chain`]: the project's own `.agent-vm/layers/*`
/// steps, independent of any `--layer` flag.
fn resolve_project_steps(project_dir: &Path) -> Result<Vec<ChainDir>> {
    let layers_dir = project_dir.join(LAYERS_SUBDIR);
    if !layers_dir.exists() {
        return Ok(vec![]);
    }
    if !layers_dir.is_dir() {
        bail!(
            "{} exists but is not a directory; each layer step belongs in its own \
             numbered subdirectory, e.g. {}/10-tools/Dockerfile",
            layers_dir.display(),
            layers_dir.display(),
        );
    }

    let mut names: Vec<std::ffi::OsString> = Vec::new();
    for entry in fs::read_dir(&layers_dir).with_context(|| {
        format!(
            "reading tooling-layer chain directory {}",
            layers_dir.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "reading tooling-layer chain directory {}",
                layers_dir.display()
            )
        })?;
        if entry
            .file_type()
            .with_context(|| format!("reading {}", entry.path().display()))?
            .is_dir()
        {
            names.push(entry.file_name());
        } else if entry.file_name() == "Dockerfile" {
            bail!(
                "{} has a Dockerfile directly inside it; each layer step needs its own \
                 numbered subdirectory, e.g. {}/10-tools/Dockerfile",
                layers_dir.display(),
                layers_dir.display(),
            );
        }
    }
    if names.is_empty() {
        bail!(
            "{} declares no layer steps (no subdirectories found)",
            layers_dir.display()
        );
    }
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut steps = Vec::with_capacity(names.len());
    for name in names {
        let dir = layers_dir.join(&name);
        require_step_dir(&dir, &format!("tooling-layer step {}", dir.display()))?;
        steps.push(ChainDir {
            dir,
            origin: LayerOrigin::Project,
            label: format!("{LAYERS_SUBDIR}/{}", name.to_string_lossy()),
        });
    }
    Ok(steps)
}

/// Phase 3 of [`resolve_layer_chain`]: `--layer` values, in command-line
/// order, resolved against `canonical_project` and validated per the fixed
/// check order documented there.
fn resolve_flag_steps(canonical_project: &Path, flag_dirs: &[PathBuf]) -> Result<Vec<ChainDir>> {
    let mut steps = Vec::with_capacity(flag_dirs.len());
    for flag in flag_dirs {
        let as_typed = flag.display().to_string();
        if flag.as_os_str().is_empty() {
            bail!("--layer requires a non-empty directory");
        }

        // Relative paths resolve against the project directory — the shell
        // user's cwd, since `project_dir` *is* the canonicalised cwd
        // (`ProjectSession::for_cwd`) — deliberately diverging from
        // `--mount`, which requires absolute paths: the approved workflow is
        // trying a checked-in example by relative path.
        let resolved = if flag.is_relative() {
            canonical_project.join(flag)
        } else {
            flag.clone()
        };
        if !resolved.is_dir() {
            bail!("--layer {as_typed} does not exist or is not a directory");
        }
        let canonical_flag = resolved
            .canonicalize()
            .with_context(|| format!("canonicalizing --layer {as_typed}"))?;

        // Ancestor check before the Dockerfile check (see the doc comment
        // above): `plan_chain` hashes every step's whole tree on every
        // launch to detect a cache hit, streaming every file's bytes, and
        // buildx would upload the same as build context — a project root
        // (or above) drags in the VCS directory, `target/`, `node_modules/`,
        // gigabytes per launch, for what was never a sensible layer anyway.
        if canonical_project.starts_with(&canonical_flag) {
            bail!(
                "--layer {as_typed} is the project directory or an ancestor of it; agent-vm \
                 hashes and uploads a layer's whole directory tree on every launch, which would \
                 mean the entire project checkout. Put the layer in its own subdirectory instead."
            );
        }

        require_step_dir(&canonical_flag, &format!("--layer {as_typed}")).map_err(|err| {
            match directory_of_layers_hint(&canonical_flag) {
                Some(hint) => err.context(hint),
                None => err,
            }
        })?;

        steps.push(ChainDir {
            dir: canonical_flag,
            origin: LayerOrigin::Flag,
            label: format!("--layer {as_typed}"),
        });
    }
    Ok(steps)
}

/// Best-effort hint for the predictable `--layer` mistake of naming a
/// directory *of* layer directories (e.g. `--layer examples/layers`) rather
/// than one layer: `dir` itself has no `Dockerfile`, but one of its
/// immediate subdirectories does. Only ever attached to the Dockerfile-
/// missing error, so a read failure here just means no hint, not a lost
/// error.
fn directory_of_layers_hint(dir: &Path) -> Option<String> {
    let has_layer_child = fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .any(|e| e.path().join("Dockerfile").is_file());
    has_layer_child
        .then(|| "each --layer names one layer directory, not a directory of layers".to_string())
}

/// Phase 4 of [`resolve_layer_chain`]: the same directory twice in the
/// combined chain — a flag repeated, a flag naming an existing project step,
/// or two paths that alias through a symlink — is never intentional (it
/// would build a layer on top of itself) and is a hard error naming both
/// labels, keyed by canonical path so aliasing can't slip through.
fn reject_duplicate_steps(chain: &[ChainDir]) -> Result<()> {
    let mut seen: std::collections::HashMap<PathBuf, &str> = std::collections::HashMap::new();
    for step in chain {
        let canonical = step
            .dir
            .canonicalize()
            .with_context(|| format!("canonicalizing tooling-layer step {}", step.dir.display()))?;
        if let Some(&first_label) = seen.get(&canonical) {
            bail!(
                "{first_label} and {} name the same layer directory ({}); each chain step must \
                 be distinct",
                step.label,
                canonical.display(),
            );
        }
        seen.insert(canonical, &step.label);
    }
    Ok(())
}

/// A step directory must be a directory and hold a `Dockerfile`. `what`
/// names the step in the error text — `tooling-layer step <path>` for a
/// project step, `--layer <as typed>` for a flag step — so the same check
/// serves both without either caller building its own error text by hand.
fn require_step_dir(dir: &Path, what: &str) -> Result<()> {
    let dockerfile = dir.join("Dockerfile");
    if !dockerfile.is_file() {
        bail!(
            "{what} has no Dockerfile (expected {})",
            dockerfile.display()
        );
    }
    Ok(())
}

// --- chain composition ---
//
// `plan_chain` is pure: no process spawned, no network, no cache read — just
// the layer directories and the base digest. Every step's tag is therefore
// known before anything is built, which is what lets the cache check, the
// prompt, and the build set all be decided up front. `ChainRuntime` is the
// narrow effectful seam `execute_chain` drives; `run.rs` implements it
// against real docker + the msb cache, and tests implement it with a
// recording fake — following the `ExecEventSource` precedent elsewhere in
// this crate (private AFIT trait, `&mut self`, no `async-trait`).

/// The whole chain's identities, in build order.
///
/// Step 0 is anchored on the base image's *manifest* digest; every later
/// step on its predecessor's *content hash* — never a docker-assigned image
/// id. Both are content addresses that move whenever what they name moves,
/// which is all the hash needs, and keeping it a pure hash is what makes the
/// whole chain computable without spawning a process.
///
/// Chaining on the previous step's content hash rather than its resolved
/// docker image id (as an earlier draft of this design, and the originating
/// issue, proposed) is a deliberate choice, not an oversight: image-id
/// chaining would put `docker image inspect` on the cache-hit path of every
/// launch (the final tag would not otherwise be computable), and `docker
/// image inspect` exits non-zero both when an image is absent *and* when the
/// daemon is unreachable — so an already-ingested chain would read as "not
/// cached" and hard-fail whenever docker simply wasn't running. Image ids are
/// also not stable across `docker image prune` or reproducible across
/// machines, while a content hash is both. See
/// `docs/adr/0003-project-tooling-layers.md`'s chain amendment for the full
/// writeup.
///
/// `origin` and `label` (see [`ChainDir`]) never reach [`resolve`] and never
/// enter the hash, by construction: `resolve` and [`LayerIdentity`] are
/// untouched by this amendment, and this function only attaches provenance
/// to the identity it already computed. That is what keeps try-then-adopt
/// free — a `--layer` step and a project step over the same directory
/// contents at the same chain position hash identically.
pub fn plan_chain(
    chain: &[ChainDir],
    project_dir: &Path,
    base_manifest_digest: &str,
) -> Result<Vec<ChainStep>> {
    let total = chain.len();
    if total == 0 {
        bail!("plan_chain called with an empty chain");
    }
    let mut plan = Vec::with_capacity(total);
    let mut base_id = base_manifest_digest.to_string();
    for (index, step) in chain.iter().enumerate() {
        let id = resolve(
            &step.dir,
            project_dir,
            &base_id,
            ChainPosition { index, total },
        )?;
        base_id = id.hash.clone();
        plan.push(ChainStep {
            id,
            origin: step.origin,
            label: step.label.clone(),
        });
    }
    Ok(plan)
}

/// A hashed chain step: the identity [`resolve`] computed, plus where it
/// came from. Kept separate from [`LayerIdentity`] rather than folded into
/// it — see [`plan_chain`]'s doc comment — so provenance cannot reach the
/// hash by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStep {
    pub id: LayerIdentity,
    pub origin: LayerOrigin,
    pub label: String,
}

/// One row of the confirmation prompt.
pub struct PlannedStep {
    pub position: ChainPosition,
    /// Kept for symmetry with `ChainDir`/`ChainStep`'s provenance and for a
    /// future per-origin consumer; today `layer_chain_build_question`
    /// distinguishes origins through `label`'s text alone (a `--layer`
    /// label always carries that literal prefix), so nothing in production
    /// reads this field yet. Exercised directly by
    /// `layer_chain_build_question_marks_flag_layers`.
    #[allow(dead_code)]
    pub origin: LayerOrigin,
    /// `.agent-vm/layers/10-a`, or `--layer <as typed>` — see [`ChainDir::label`].
    pub label: String,
    /// Always known — the chain is pure, so every tag is computed before
    /// anything is built.
    pub tag: String,
    /// `false` means already cached — shown to the user as "(cached)".
    pub pending: bool,
}

/// Every effect executing a chain performs. `run.rs` implements it against
/// real docker + the msb cache; tests implement it with a recording fake.
pub trait ChainRuntime {
    fn notice(&mut self, message: &str) -> Result<()>;

    /// Ask once for the whole chain. The implementation runs the
    /// `docker buildx` preflight *before* asking, so a broken docker
    /// install surfaces as one clear error instead of wasting the user's
    /// answer — that ordering is today's single-layer behavior and the
    /// reason this is one method rather than two.
    fn confirm_build(&mut self, plan: &[PlannedStep]) -> Result<()>;

    /// `docker image inspect <tag> --format '{{.Id}}'`; `Ok(None)` means
    /// absent.
    async fn intermediate_image_id(&mut self, tag: &str) -> Result<Option<String>>;

    /// `layer::derived_is_cached` against the msb cache.
    async fn final_is_cached(&mut self, tag: &str) -> Result<bool>;

    /// buildx `--output type=docker`, into docker's own image store.
    async fn build_intermediate(&mut self, id: &LayerIdentity, from_ref: &str) -> Result<()>;

    /// buildx `--output type=oci` + `load_archive` into the msb cache.
    async fn build_and_load_final(&mut self, id: &LayerIdentity, from_ref: &str) -> Result<()>;
}

/// Executes `plan`, returning the final derived tag to boot.
///
/// Traced for `total ∈ {1,2,3}` while writing this: with `total == 1` the
/// backward walk below never runs (its range is empty), so a one-step chain
/// takes exactly one `build_and_load_final` off `pinned_base_ref` — byte-
/// identical to the pre-chain single-layer behavior. With `total == 2` and
/// step 0 already in docker's store, the walk finds it, `build_from` becomes
/// 1, and only the final step builds `FROM` `plan[0].tag`. With `total == 3`
/// and nothing cached, both intermediates build in order before the final.
pub async fn execute_chain<R: ChainRuntime>(
    plan: &[ChainStep],
    pinned_base_ref: &str,
    rt: &mut R,
) -> Result<String> {
    let total = plan.len();
    let final_step = plan
        .last()
        .context("execute_chain called with an empty chain")?;

    // 1. The common case, and the only path a cache-hit launch takes: the
    //    final tag is already ingested. No prompt, no docker process at all
    //    — not even an `inspect` (see plan_chain's doc comment).
    if rt.final_is_cached(&final_step.id.tag).await? {
        rt.notice(&format!(
            "==> Reusing cached tooling layer {}",
            final_step.id.tag
        ))?;
        return Ok(final_step.id.tag.clone());
    }

    // 2. Decide where to start building. Walk *backwards* from the last
    //    intermediate: the first one already in docker's store is a usable
    //    FROM for the step above it, so nothing below it needs rebuilding.
    //    Presence of `tag_i` is sufficient — the tag embeds H_i, which
    //    covers every step beneath it, so an image under that tag was
    //    necessarily built from the right predecessor. (When the chain grew
    //    a `--layer` step after a project chain whose final step was
    //    ingested, that step's image is not in docker's store — it was built
    //    with `--output type=oci` — so the walk lands on it as `build_from`
    //    and it is re-exported once; see the ADR amendment's A6.)
    let mut build_from = 0;
    for i in (0..total.saturating_sub(1)).rev() {
        if rt.intermediate_image_id(&plan[i].id.tag).await?.is_some() {
            build_from = i + 1;
            break;
        }
    }

    // 3. One prompt for the whole chain, listing every step with its real
    //    tag and whether it will be built.
    let steps: Vec<PlannedStep> = plan
        .iter()
        .enumerate()
        .map(|(i, step)| PlannedStep {
            position: step.id.position,
            origin: step.origin,
            label: step.label.clone(),
            tag: step.id.tag.clone(),
            pending: i >= build_from,
        })
        .collect();
    rt.confirm_build(&steps)?;

    // 4. Build forward. Any failure propagates and aborts the launch; the
    //    msb cache is untouched until the final step succeeds, so a
    //    partially-composed chain can never boot (ADR-0003's hard-fail
    //    rule).
    let mut from_ref = if build_from == 0 {
        pinned_base_ref.to_string()
    } else {
        plan[build_from - 1].id.tag.clone()
    };
    for step in &plan[build_from..] {
        rt.notice(&format!(
            "==> Building tooling layer step {} ({}) …",
            step.id.position.human(),
            step.label,
        ))?;
        if step.id.position.index + 1 == total {
            rt.build_and_load_final(&step.id, &from_ref).await?; // ONLY here
        } else {
            rt.build_intermediate(&step.id, &from_ref).await?;
            from_ref = step.id.tag.clone();
        }
    }
    rt.notice(&format!("==> Tooling layer {} ready", final_step.id.tag))?;
    Ok(final_step.id.tag.clone())
}

// --- build & load ---
//
// Everything below is I/O and process-spawning: `docker buildx build` to
// produce the derived image as an OCI archive, and a registry-less
// `microsandbox_image::load_archive` ingest of that archive into the msb
// cache. Nothing above this line touches the network, spawns a process, or
// writes anything other than reading the layer directory to hash it.

/// True iff the derived image `tag` is already ingested in `cache_dir`: its
/// metadata is cached by a prior [`load_derived_image`] call AND its VMDK is
/// materialized.
///
/// The VMDK check (not just metadata presence) matters: `load_archive`
/// writes image metadata *after* materializing per-layer EROFS plus fsmeta
/// and VMDK (verified in the vendored `microsandbox_image` crate — see
/// `docs/adr/0003-project-tooling-layers.md`'s F5), so on a clean ingest
/// metadata implies VMDK. The only gap is a raw-cache eviction of the VMDK
/// while the metadata record survives; without this extra check that state
/// would read as "cached", and a boot would fall through to a registry pull
/// of a tag that has no registry — a hard failure instead of a rebuild.
pub async fn derived_is_cached(cache_dir: &Path, tag: &str) -> Result<bool> {
    let reference: microsandbox_image::Reference = tag
        .parse()
        .with_context(|| format!("parsing derived image tag {tag}"))?;
    let cache = microsandbox_image::GlobalCache::new_async(cache_dir)
        .await
        .with_context(|| format!("opening image cache at {}", cache_dir.display()))?;
    let Some(metadata) = cache
        .read_image_metadata_async(&reference)
        .await
        .with_context(|| format!("reading cached image metadata for {tag}"))?
    else {
        return Ok(false);
    };
    let manifest_digest: microsandbox_image::Digest = metadata
        .manifest_digest
        .parse()
        .with_context(|| format!("parsing cached manifest digest for {tag}"))?;
    Ok(cache.is_vmdk_materialized(&manifest_digest))
}

/// Preflight: confirms `docker buildx` actually works before a launch
/// prompts to build a tooling layer, so a missing/broken docker install
/// surfaces as one clear, actionable error instead of a confusing failure
/// partway through a build the user just confirmed.
pub fn ensure_docker_buildx() -> Result<()> {
    let status = std::process::Command::new("docker")
        .args(["buildx", "version"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("running `docker buildx version` failed; is docker installed and on PATH?")?;
    if !status.success() {
        bail!(
            "`docker buildx version` exited non-zero; install Docker Buildx \
             (https://docs.docker.com/build/architecture/#buildx) to build project tooling layers"
        );
    }
    Ok(())
}

/// Pins the base reference to `<registry>/<repository>@<manifest_digest>` so
/// docker's own `FROM` pull resolves to exactly the base image msb already
/// cached & hashed (see `docs/adr/0003-project-tooling-layers.md`'s
/// "Digest-pinned BASE_IMAGE" decision) — without this, docker independently
/// re-resolves `FROM ghcr.io/.../agent-vm-template:latest` against the
/// registry, which can race a moving `:latest` tag and silently build FROM a
/// different image than the one the layer hash covers.
///
/// Any existing tag or digest on `base_ref` is discarded — `manifest_digest`
/// always wins, so a caller can't accidentally pin the *previous* digest
/// alongside a now-stale tag.
///
/// Parses `base_ref` through the same `Reference` type
/// `image_config_path_and_digest` (`run.rs`) already uses for the booted
/// image, so a `host:port/repo:tag`-shaped ref is never misparsed into
/// stripping the registry-port colon instead of the tag colon. Falls back to
/// hand-rolled string surgery only when `Reference`'s stricter grammar
/// (lowercase-only repository segments) rejects the ref outright — the
/// surgery has to make the same port-vs-tag-colon distinction by hand, which
/// is the one subtle bug surface in this function and the reason it is
/// unit-tested directly (`digest_pin_by_string_surgery_*` below).
pub fn digest_pinned_base(base_ref: &str, manifest_digest: &str) -> Result<String> {
    if let Ok(reference) = base_ref.parse::<microsandbox_image::Reference>() {
        return Ok(reference
            .clone_with_digest(manifest_digest.to_string())
            .whole());
    }
    Ok(digest_pin_by_string_surgery(base_ref, manifest_digest))
}

/// Fallback for [`digest_pinned_base`] when `Reference` can't parse
/// `base_ref`. Strips any existing `@digest`, then any trailing `:tag` —
/// guarding the registry-port colon by only treating a colon *after* the
/// last `/` as a tag separator — and appends `@manifest_digest`.
fn digest_pin_by_string_surgery(base_ref: &str, manifest_digest: &str) -> String {
    let base_ref = base_ref.split_once('@').map_or(base_ref, |(repo, _)| repo);
    let last_slash = base_ref.rfind('/').map_or(0, |i| i + 1);
    let repo = match base_ref[last_slash..].rfind(':') {
        Some(i) => &base_ref[..last_slash + i],
        None => base_ref,
    };
    format!("{repo}@{manifest_digest}")
}

/// Runs `docker buildx build` producing an OCI archive at `out_tar`
/// containing exactly one image (`--provenance=false --sbom=false`
/// suppresses the attestation manifests that would otherwise turn the
/// archive into a multi-image index — see F7 in
/// `docs/adr/0003-project-tooling-layers.md`).
///
/// Tries `compression=zstd` first (dedups against blobs the msb cache
/// already holds for the base image, per ADR-0003); on any build failure it
/// retries once with `compression=gzip` (F6: some older buildx/registries
/// lack zstd) before giving up. Because stdout/stderr are inherited so the
/// user sees live build progress, the failure text isn't captured to detect
/// "specifically a zstd problem" — so this retries unconditionally on any
/// non-zero exit. The accepted cost: a genuinely broken Dockerfile (bad
/// syntax, unreachable FROM) fails, then fails again identically with gzip,
/// doubling the wait for that case. That's judged acceptable because a
/// build is confirmed (never automatic) and the error text a user sees is
/// the same either way, just repeated.
pub async fn build_derived_oci(
    id: &LayerIdentity,
    pinned_base: &str,
    out_tar: &Path,
) -> Result<()> {
    let oci = |compression: &'static str| BuildxOutput::Oci {
        out_tar,
        compression,
    };
    match run_buildx(id, pinned_base, oci("zstd")).await {
        Ok(()) => Ok(()),
        Err(zstd_err) => {
            eprintln!(
                "==> docker buildx build (zstd output) failed for {}; retrying with gzip output: {zstd_err}",
                id.tag
            );
            run_buildx(id, pinned_base, oci("gzip")).await.with_context(|| {
                format!(
                    "building tooling layer {} (gzip retry also failed; zstd attempt failed with: {zstd_err})",
                    id.tag
                )
            })
        }
    }
}

/// Builds an *intermediate* chain step with `--output type=docker`, landing
/// it in docker's own local image store (equivalent to `--load -t <tag>`) so
/// the next step's `FROM <tag>` can find it there — never registry-pulled,
/// see `docs/adr/0003-project-tooling-layers.md`'s chain amendment. Unlike
/// [`build_derived_oci`], this takes no `compression=` (the docker exporter
/// has no such option) and so has no zstd/gzip retry.
///
/// After the build, asserts `docker image inspect id.tag` actually resolves.
/// Its absence overwhelmingly means the active buildx builder uses the
/// `docker-container` driver rather than `docker` — that driver's isolated
/// buildkit container cannot see a previous build's `--load` output, so a
/// later `FROM <tag>` falls through to a Docker Hub pull of a tag that does
/// not exist there. `.github/workflows/chrome-layer-contract.yml` already
/// pins `driver: docker` for exactly this reason. Checked as a post-build
/// assertion (not by parsing `docker buildx inspect` up front) because that
/// is a second output format to track, can false-positive on multi-node
/// builders, and the post-hoc check cannot be wrong.
pub async fn build_derived_docker(id: &LayerIdentity, from_ref: &str) -> Result<()> {
    run_buildx(id, from_ref, BuildxOutput::Docker)
        .await
        .with_context(|| format!("building intermediate tooling layer {}", id.tag))?;
    if docker_image_id(&id.tag).await?.is_none() {
        let driver = buildx_driver().unwrap_or_else(|| "<unknown>".to_string());
        bail!(
            "tooling layer step {} ({}) built, but its image did not appear in docker's \
             local image store. agent-vm chains layer steps through that store, which \
             requires the default `docker` buildx driver (this host's builder uses driver \
             `{driver}`). Run `docker buildx use default`, or create a builder with \
             `docker buildx create --driver docker --use`.",
            id.position.human(),
            id.dir.display(),
        );
    }
    Ok(())
}

/// Only on the [`build_derived_docker`] failure path: the current builder's
/// driver, best-effort, for the error message. Never fails a build on its
/// own — a `None` just means the error message says "<unknown>" instead of
/// naming the driver.
fn buildx_driver() -> Option<String> {
    let output = std::process::Command::new("docker")
        .args(["buildx", "inspect"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Driver:"))
        .map(|driver| driver.trim().to_string())
}

/// Trims and validates `docker image inspect --format '{{.Id}}'` output.
/// Split out from the process call so the trailing-newline and empty-output
/// cases are unit-testable without docker.
fn parse_image_id(stdout: &str) -> Result<String> {
    let id = stdout.trim();
    if id.is_empty() {
        bail!("`docker image inspect` produced empty output");
    }
    Ok(id.to_string())
}

/// The resolved image id of `tag` in docker's local image store, or `None`
/// when absent (`docker image inspect` exits 1). A *spawn* failure is an
/// error, not `None` — "docker is broken" must not read as "not cached",
/// which would make [`execute_chain`]'s cache-hit path indistinguishable
/// from a genuinely broken docker install.
pub async fn docker_image_id(tag: &str) -> Result<Option<String>> {
    let output = tokio::process::Command::new("docker")
        .args(["image", "inspect", tag, "--format", "{{.Id}}"])
        .output()
        .await
        .with_context(|| format!("spawning `docker image inspect {tag}`"))?;
    if !output.status.success() {
        // Exit 1 covers both "no such image" and "daemon unreachable" —
        // indistinguishable from the exit code alone. That ambiguity is
        // exactly why content-hash chaining keeps this call off the
        // cache-hit path entirely (see plan_chain's doc comment): a stopped
        // daemon must never read as "chain not cached".
        return Ok(None);
    }
    let id = parse_image_id(&String::from_utf8_lossy(&output.stdout))
        .with_context(|| format!("parsing `docker image inspect {tag}` output"))?;
    Ok(Some(id))
}

/// The `docker buildx --platform` value for the host we are running on.
///
/// This MUST track `microsandbox_image::load_archive`'s own platform
/// selection: `load_archive` materializes the archive's manifest matching
/// `Platform::host_linux()` (`vendor/microsandbox/crates/image/lib/platform.rs`),
/// which maps `std::env::consts::ARCH` (`x86_64` -> `amd64`, `aarch64` ->
/// `arm64`, anything else passed through) — the *running host's*
/// architecture, not a fixed value. A hardcoded `linux/amd64` built on an
/// Apple-Silicon (`aarch64`) host produces an OCI archive that `load_archive`
/// then rejects with "OCI layout contains no image manifests for the host
/// platform", because it looks for the `arm64` manifest the build never
/// emitted. Deriving the flag here with the identical mapping keeps the built
/// image and the load/boot platform in lockstep on every supported host
/// (see ADR-0003 and README "Requirements": Linux/KVM x86_64 and Apple
/// Silicon are both first-class). The host arch is also exactly the platform
/// msb resolved and cached for the base image, so docker's digest-pinned
/// `FROM` pull selects the same base manifest the layer hash covers.
fn host_oci_platform() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("linux/{arch}")
}

/// Which exporter [`run_buildx`] targets. The two variants differ in three
/// deliberate ways, each commented at its point of asymmetry below:
/// whether a `-t` tag is passed (docker's local store needs one to be
/// addressable by the next step; an OCI archive does not), whether
/// `--provenance=false --sbom=false` apply, and the shape of the `--output`
/// value itself.
enum BuildxOutput<'a> {
    /// `--output type=oci,dest=<out_tar>,compression=<compression>`. Final
    /// step only.
    Oci {
        out_tar: &'a Path,
        compression: &'a str,
    },
    /// `-t <tag> --output type=docker`, into docker's local image store.
    /// Intermediate steps only.
    Docker,
}

async fn run_buildx(id: &LayerIdentity, from_ref: &str, output: BuildxOutput<'_>) -> Result<()> {
    let dockerfile_str = id
        .dockerfile
        .to_str()
        .context("Dockerfile path is not valid UTF-8")?;
    let dir_str = id
        .dir
        .to_str()
        .context("tooling-layer directory path is not valid UTF-8")?;

    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("buildx")
        .arg("build")
        .arg("--build-arg")
        .arg(format!("BASE_IMAGE={from_ref}"))
        .arg("-f")
        .arg(dockerfile_str)
        .arg("--platform")
        .arg(host_oci_platform());

    let output_desc = match output {
        BuildxOutput::Oci {
            out_tar,
            compression,
        } => {
            let out_tar_str = out_tar
                .to_str()
                .context("tooling-layer OCI archive path is not valid UTF-8")?;
            // `--provenance=false --sbom=false` is OCI-only: it suppresses
            // the attestation manifests that would otherwise turn the
            // archive into a multi-image index — see F7 in
            // `docs/adr/0003-project-tooling-layers.md`. The docker exporter
            // carries no attestations, so the flags would be meaningless
            // there and buildx may warn about them.
            cmd.arg("--provenance=false").arg("--sbom=false");
            cmd.arg("--output").arg(format!(
                "type=oci,dest={out_tar_str},compression={compression}"
            ));
            format!("{compression} output")
        }
        BuildxOutput::Docker => {
            // `-t` is what makes the image addressable by tag in docker's
            // own store for the next step's `FROM`; an OCI archive has no
            // such addressability need. No `compression=` here — the
            // docker exporter takes no such argument, so intermediates get
            // no zstd/gzip retry (that retry exists only for the OCI
            // archive path; see build_derived_oci).
            cmd.arg("-t")
                .arg(&id.tag)
                .arg("--output")
                .arg("type=docker");
            "docker output".to_string()
        }
    };
    cmd.arg(dir_str);

    let status = cmd.status().await.with_context(|| {
        format!(
            "spawning `docker buildx build` for tooling layer {}",
            id.tag
        )
    })?;
    if !status.success() {
        bail!(
            "`docker buildx build` failed for tooling layer {} ({output_desc}, exit {})",
            id.tag,
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "terminated by signal".to_string())
        );
    }
    Ok(())
}

/// Ingests `tar` registry-lessly into `cache_dir`, tagging the archive's
/// image `tag`. This is the step that materializes the per-layer EROFS plus
/// fsmeta and VMDK (see [`derived_is_cached`] and
/// `docs/adr/0003-project-tooling-layers.md`) — after this returns
/// successfully, a boot of `tag` with `PullPolicy::IfMissing` resolves
/// entirely from cache, with no registry contact.
pub async fn load_derived_image(cache_dir: &Path, tar: &Path, tag: &str) -> Result<()> {
    microsandbox_image::load_archive(
        cache_dir,
        tar,
        microsandbox_image::ImageLoadOptions {
            tags: vec![tag.to_string()],
            ..Default::default()
        },
    )
    .await
    .with_context(|| format!("loading tooling layer {tag} into the msb cache"))?;
    Ok(())
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
        assert_ne!(
            before, after,
            "changing only the base image ID must change the hash"
        );
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
        assert_eq!(
            before, after,
            "chmod 0640 must not change the hash; only the execute bit is tracked"
        );
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

    /// The position a single-step (non-chain) caller uses. Test-only: the
    /// only production caller of `resolve` is `plan_chain`, which always has
    /// a real `{index, total}` to hand it, so a production
    /// `ChainPosition::single()` would sit unused behind a `dead_code`
    /// allow. Kept in test code instead.
    fn first_of_one() -> ChainPosition {
        ChainPosition { index: 0, total: 1 }
    }

    #[test]
    fn resolve_names_the_derived_image() {
        let dir = layer_dir_fixture();
        let id = resolve(
            dir.path(),
            Path::new("/work/my-app"),
            TEST_BASE_ID,
            first_of_one(),
        )
        .unwrap();

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
            ("/work/abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrst"),
            ("/work/abcdefghijklmnopqrs-tuv", "abcdefghijklmnopqrs-"),
            ("/", "root"),
        ];
        for (project_dir, want_slug) in cases {
            let id = resolve(
                dir.path(),
                Path::new(project_dir),
                TEST_BASE_ID,
                first_of_one(),
            )
            .unwrap();
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
        let with_slash = resolve(
            dir.path(),
            Path::new("/work/my-app/"),
            TEST_BASE_ID,
            first_of_one(),
        )
        .unwrap();
        let without_slash = resolve(
            dir.path(),
            Path::new("/work/my-app"),
            TEST_BASE_ID,
            first_of_one(),
        )
        .unwrap();
        assert_eq!(with_slash.tag, without_slash.tag);
    }

    #[test]
    fn resolve_hash_ignores_the_project_directory() {
        let dir = layer_dir_fixture();
        let a = resolve(
            dir.path(),
            Path::new("/work/alpha"),
            TEST_BASE_ID,
            first_of_one(),
        )
        .unwrap();
        let b = resolve(
            dir.path(),
            Path::new("/work/beta"),
            TEST_BASE_ID,
            first_of_one(),
        )
        .unwrap();
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn chain_position_does_not_change_the_hash() {
        let dir = layer_dir_fixture();
        let at_0_of_1 = resolve(
            dir.path(),
            Path::new("/work/my-app"),
            TEST_BASE_ID,
            first_of_one(),
        )
        .unwrap();
        let at_1_of_3 = resolve(
            dir.path(),
            Path::new("/work/my-app"),
            TEST_BASE_ID,
            ChainPosition { index: 1, total: 3 },
        )
        .unwrap();
        assert_eq!(
            at_0_of_1.tag, at_1_of_3.tag,
            "the chain position must not participate in the hash (D3)"
        );
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

    // --- resolve_layer_dirs() ---

    /// Creates `<project>/.agent-vm/layers/<name>/Dockerfile`.
    fn write_step(project: &Path, name: &str, dockerfile: &str) -> PathBuf {
        let dir = project.join(LAYERS_SUBDIR).join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Dockerfile"), dockerfile).unwrap();
        dir
    }

    /// `resolve_layer_chain` returns `ChainDir`s; most resolution tests only
    /// care about the resolved directories, not the labels/origins.
    fn dirs_of(chain: &[ChainDir]) -> Vec<PathBuf> {
        chain.iter().map(|c| c.dir.clone()).collect()
    }

    #[test]
    fn resolve_layer_dirs_orders_steps_lexicographically() {
        let project = tempfile::tempdir().unwrap();
        // Created out of order: readdir order is arbitrary, so this is the
        // real guard on the sort.
        write_step(project.path(), "20-b", "FROM scratch\n");
        write_step(project.path(), "05-z", "FROM scratch\n");
        write_step(project.path(), "10-a", "FROM scratch\n");

        let got = dirs_of(&resolve_layer_chain(project.path(), &[]).unwrap());
        assert_eq!(
            got,
            vec![
                project.path().join(LAYERS_SUBDIR).join("05-z"),
                project.path().join(LAYERS_SUBDIR).join("10-a"),
                project.path().join(LAYERS_SUBDIR).join("20-b"),
            ]
        );
    }

    #[test]
    fn resolve_layer_dirs_absent_resolves_to_an_empty_chain() {
        let project = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_layer_chain(project.path(), &[]).unwrap(),
            Vec::<ChainDir>::new()
        );
    }

    #[test]
    fn resolve_layer_dirs_legacy_singular_dir_is_a_migration_error() {
        let project = tempfile::tempdir().unwrap();
        let legacy = project.path().join(LEGACY_LAYER_SUBDIR);
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("Dockerfile"), "FROM scratch\n").unwrap();

        let err = resolve_layer_chain(project.path(), &[]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains(&legacy.display().to_string()), "{msg}");
        assert!(msg.contains(LAYERS_SUBDIR), "{msg}");
    }

    #[test]
    fn resolve_layer_dirs_legacy_dir_errors_even_when_layers_also_exists() {
        let project = tempfile::tempdir().unwrap();
        let legacy = project.path().join(LEGACY_LAYER_SUBDIR);
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("Dockerfile"), "FROM scratch\n").unwrap();
        write_step(project.path(), "10-a", "FROM scratch\n");

        let err = resolve_layer_chain(project.path(), &[]).unwrap_err();
        assert!(
            format!("{err:?}").contains(&legacy.display().to_string()),
            "the legacy check must run first and unconditionally"
        );
    }

    #[test]
    fn resolve_layer_dirs_step_without_dockerfile_errors() {
        let project = tempfile::tempdir().unwrap();
        let dir = project.path().join(LAYERS_SUBDIR).join("10-a");
        fs::create_dir_all(&dir).unwrap();

        let err = resolve_layer_chain(project.path(), &[]).unwrap_err();
        assert!(format!("{err:?}").contains(&dir.display().to_string()));
    }

    #[test]
    fn resolve_layer_dirs_empty_layers_dir_errors() {
        let project = tempfile::tempdir().unwrap();
        fs::create_dir_all(project.path().join(LAYERS_SUBDIR)).unwrap();

        let err = resolve_layer_chain(project.path(), &[]).unwrap_err();
        assert!(format!("{err:?}").contains("no layer steps"));
    }

    #[test]
    fn resolve_layer_dirs_dockerfile_directly_in_layers_dir_errors() {
        let project = tempfile::tempdir().unwrap();
        let layers_dir = project.path().join(LAYERS_SUBDIR);
        fs::create_dir_all(&layers_dir).unwrap();
        fs::write(layers_dir.join("Dockerfile"), "FROM scratch\n").unwrap();

        let err = resolve_layer_chain(project.path(), &[]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("numbered subdirectory"), "{msg}");
        assert!(
            !msg.contains("no longer supported"),
            "must be a distinct message from the legacy-directory error: {msg}"
        );
    }

    #[test]
    fn resolve_layer_dirs_ignores_non_directory_entries() {
        let project = tempfile::tempdir().unwrap();
        write_step(project.path(), "10-a", "FROM scratch\n");
        fs::write(project.path().join(LAYERS_SUBDIR).join("README.md"), "hi").unwrap();

        let got = dirs_of(&resolve_layer_chain(project.path(), &[]).unwrap());
        assert_eq!(got, vec![project.path().join(LAYERS_SUBDIR).join("10-a")]);
    }

    #[test]
    fn resolve_layer_dirs_single_step_chain_resolves() {
        let project = tempfile::tempdir().unwrap();
        let dir = write_step(project.path(), "10-a", "FROM scratch\n");
        assert_eq!(
            dirs_of(&resolve_layer_chain(project.path(), &[]).unwrap()),
            vec![dir]
        );
    }

    // --- resolve_layer_chain() over both sources (amendment A1) ---

    #[test]
    fn resolve_layer_chain_appends_flag_layers_after_project_steps_in_order() {
        let project = tempfile::tempdir().unwrap();
        // Project steps intentionally created/named out of the flags' order,
        // so the assertion below is a real guard on "project first, sorted;
        // flags after, in command-line order, unsorted".
        write_step(project.path(), "20-b", "FROM scratch\n");
        write_step(project.path(), "10-a", "FROM scratch\n");
        let flag_y = tempfile::tempdir().unwrap();
        fs::write(flag_y.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let flag_x = tempfile::tempdir().unwrap();
        fs::write(flag_x.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let got = dirs_of(
            &resolve_layer_chain(
                project.path(),
                &[flag_y.path().to_path_buf(), flag_x.path().to_path_buf()],
            )
            .unwrap(),
        );
        assert_eq!(
            got,
            vec![
                project.path().join(LAYERS_SUBDIR).join("10-a"),
                project.path().join(LAYERS_SUBDIR).join("20-b"),
                flag_y.path().canonicalize().unwrap(),
                flag_x.path().canonicalize().unwrap(),
            ],
            "project steps sorted; flags after, in command-line order (not sorted)"
        );
    }

    #[test]
    fn resolve_layer_chain_flags_alone_form_the_chain() {
        let project = tempfile::tempdir().unwrap();
        let flag = tempfile::tempdir().unwrap();
        fs::write(flag.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let chain = resolve_layer_chain(project.path(), &[flag.path().to_path_buf()]).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].origin, LayerOrigin::Flag);
        assert_eq!(chain[0].dir, flag.path().canonicalize().unwrap());
    }

    #[test]
    fn resolve_layer_chain_resolves_relative_flags_against_the_project_dir() {
        let project = tempfile::tempdir().unwrap();
        let dir = project.path().join("tools/l");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Dockerfile"), "FROM scratch\n").unwrap();

        let chain = resolve_layer_chain(project.path(), &[PathBuf::from("tools/l")]).unwrap();
        assert_eq!(
            chain[0].dir,
            project.path().canonicalize().unwrap().join("tools/l")
        );
    }

    #[test]
    fn resolve_layer_chain_accepts_absolute_flags_outside_the_project() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let chain = resolve_layer_chain(project.path(), &[outside.path().to_path_buf()]).unwrap();
        assert_eq!(chain[0].dir, outside.path().canonicalize().unwrap());
    }

    #[test]
    fn resolve_layer_chain_rejects_an_empty_flag() {
        let project = tempfile::tempdir().unwrap();
        // The case that makes this check necessary: an empty flag value must
        // not silently resolve to the project root just because it happens
        // to hold a Dockerfile.
        fs::write(project.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let err = resolve_layer_chain(project.path(), &[PathBuf::new()]).unwrap_err();
        assert!(format!("{err}").contains("non-empty"));
    }

    #[test]
    fn resolve_layer_chain_flag_missing_dir_errors_as_typed() {
        let project = tempfile::tempdir().unwrap();
        let err = resolve_layer_chain(project.path(), &[PathBuf::from("./nope")]).unwrap_err();
        assert!(format!("{err}").contains("./nope"));
    }

    #[test]
    fn resolve_layer_chain_flag_without_dockerfile_errors() {
        let project = tempfile::tempdir().unwrap();
        let flag = tempfile::tempdir().unwrap();

        let err = resolve_layer_chain(project.path(), &[flag.path().to_path_buf()]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Dockerfile"), "{msg}");
        assert!(
            msg.contains(
                &flag
                    .path()
                    .canonicalize()
                    .unwrap()
                    .join("Dockerfile")
                    .display()
                    .to_string()
            ),
            "{msg}"
        );
    }

    #[test]
    fn resolve_layer_chain_hints_when_given_a_directory_of_layers() {
        let project = tempfile::tempdir().unwrap();
        let of_layers = tempfile::tempdir().unwrap();
        let sub = of_layers.path().join("10-a");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("Dockerfile"), "FROM scratch\n").unwrap();

        let err =
            resolve_layer_chain(project.path(), &[of_layers.path().to_path_buf()]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("directory of layers"), "{msg}");
    }

    #[test]
    fn resolve_layer_chain_rejects_the_project_dir_and_its_ancestors() {
        // A nested `<tmp>/outer/project` layout, both holding a Dockerfile,
        // so a passing per-flag check order would otherwise mask the real
        // (ancestor) problem behind "no Dockerfile" for `..` — and exercises
        // the macOS `/var` -> `/private/var` canonicalisation phase 0 exists
        // for, since `tempfile::tempdir()` roots there.
        let outer = tempfile::tempdir().unwrap();
        fs::write(outer.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let project = outer.path().join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("Dockerfile"), "FROM scratch\n").unwrap();

        let err_dot = resolve_layer_chain(&project, &[PathBuf::from(".")]).unwrap_err();
        assert!(format!("{err_dot}").contains("ancestor"), "{err_dot}");

        let err_dotdot = resolve_layer_chain(&project, &[PathBuf::from("..")]).unwrap_err();
        assert!(format!("{err_dotdot}").contains("ancestor"), "{err_dotdot}");
    }

    #[test]
    fn resolve_layer_chain_rejects_the_same_flag_twice() {
        let project = tempfile::tempdir().unwrap();
        let flag = tempfile::tempdir().unwrap();
        fs::write(flag.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let dotted = flag.path().join(".");

        let err =
            resolve_layer_chain(project.path(), &[flag.path().to_path_buf(), dotted]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains(&flag.path().display().to_string()), "{msg}");
    }

    #[test]
    fn resolve_layer_chain_rejects_a_flag_naming_a_project_step() {
        let project = tempfile::tempdir().unwrap();
        write_step(project.path(), "10-a", "FROM scratch\n");

        let err = resolve_layer_chain(project.path(), &[PathBuf::from(".agent-vm/layers/10-a")])
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("same layer directory"), "{msg}");
    }

    #[test]
    fn resolve_layer_chain_sees_duplicates_through_symlinks() {
        let project = tempfile::tempdir().unwrap();
        let real = tempfile::tempdir().unwrap();
        fs::write(real.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let link = project.path().join("link-to-real");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();

        let err =
            resolve_layer_chain(project.path(), &[real.path().to_path_buf(), link]).unwrap_err();
        assert!(format!("{err}").contains("same layer directory"));
    }

    #[test]
    fn resolve_layer_chain_allows_a_subdirectory_of_a_project_step() {
        let project = tempfile::tempdir().unwrap();
        write_step(project.path(), "10-a", "FROM scratch\n");
        let sub = project.path().join(LAYERS_SUBDIR).join("10-a").join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("Dockerfile"), "FROM scratch\n").unwrap();

        let chain = resolve_layer_chain(
            project.path(),
            &[PathBuf::from(".agent-vm/layers/10-a/sub")],
        )
        .unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn resolve_layer_chain_legacy_dir_errors_even_with_flags() {
        let project = tempfile::tempdir().unwrap();
        let legacy = project.path().join(LEGACY_LAYER_SUBDIR);
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("Dockerfile"), "FROM scratch\n").unwrap();
        let flag = tempfile::tempdir().unwrap();
        fs::write(flag.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let err = resolve_layer_chain(project.path(), &[flag.path().to_path_buf()]).unwrap_err();
        assert!(format!("{err:?}").contains(&legacy.display().to_string()));
    }

    #[test]
    fn resolve_layer_chain_empty_layers_dir_errors_even_with_flags() {
        let project = tempfile::tempdir().unwrap();
        fs::create_dir_all(project.path().join(LAYERS_SUBDIR)).unwrap();
        let flag = tempfile::tempdir().unwrap();
        fs::write(flag.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let err = resolve_layer_chain(project.path(), &[flag.path().to_path_buf()]).unwrap_err();
        assert!(format!("{err:?}").contains("no layer steps"));
    }

    #[test]
    fn resolve_layer_chain_labels_steps() {
        let project = tempfile::tempdir().unwrap();
        write_step(project.path(), "10-a", "FROM scratch\n");
        let flag = tempfile::tempdir().unwrap();
        fs::write(flag.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let chain = resolve_layer_chain(project.path(), &[flag.path().to_path_buf()]).unwrap();
        assert_eq!(chain[0].label, format!("{LAYERS_SUBDIR}/10-a"));
        assert_eq!(chain[1].label, format!("--layer {}", flag.path().display()));
    }

    // --- plan_chain() ---

    /// A `ChainDir` for a bare project-step path, for tests that build a
    /// chain directly rather than going through `resolve_layer_chain`.
    fn project_chain_dir(dir: PathBuf) -> ChainDir {
        let label = dir.file_name().unwrap().to_string_lossy().into_owned();
        ChainDir {
            dir,
            origin: LayerOrigin::Project,
            label,
        }
    }

    #[test]
    fn plan_chain_orders_identities_and_positions() {
        let project = tempfile::tempdir().unwrap();
        let a = write_step(project.path(), "10-a", "FROM scratch\nRUN true\n");
        let b = write_step(project.path(), "20-b", "FROM scratch\nRUN false\n");
        let dirs = vec![project_chain_dir(a.clone()), project_chain_dir(b.clone())];

        let plan = plan_chain(&dirs, project.path(), TEST_BASE_ID).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].id.dir, a);
        assert_eq!(plan[0].id.position, ChainPosition { index: 0, total: 2 });
        assert_eq!(plan[1].id.dir, b);
        assert_eq!(plan[1].id.position, ChainPosition { index: 1, total: 2 });
    }

    #[test]
    fn plan_chain_hashes_each_step_against_its_predecessors_hash() {
        let project = tempfile::tempdir().unwrap();
        let a = write_step(project.path(), "10-a", "FROM scratch\nRUN true\n");
        let b = write_step(project.path(), "20-b", "FROM scratch\nRUN false\n");
        let dirs = vec![project_chain_dir(a.clone()), project_chain_dir(b.clone())];

        let plan = plan_chain(&dirs, project.path(), TEST_BASE_ID).unwrap();
        let step1_alone = resolve(
            &b,
            project.path(),
            &plan[0].id.hash,
            ChainPosition { index: 1, total: 2 },
        )
        .unwrap();
        assert_eq!(plan[1].id.tag, step1_alone.tag);
    }

    #[test]
    fn editing_an_early_step_changes_every_later_tag() {
        let project = tempfile::tempdir().unwrap();
        let a = write_step(project.path(), "10-a", "FROM scratch\nRUN a\n");
        let b = write_step(project.path(), "20-b", "FROM scratch\nRUN b\n");
        let c = write_step(project.path(), "30-c", "FROM scratch\nRUN c\n");
        let dirs = vec![
            project_chain_dir(a.clone()),
            project_chain_dir(b),
            project_chain_dir(c),
        ];

        let before = plan_chain(&dirs, project.path(), TEST_BASE_ID).unwrap();
        fs::write(a.join("Dockerfile"), "FROM scratch\nRUN a-edited\n").unwrap();
        let after = plan_chain(&dirs, project.path(), TEST_BASE_ID).unwrap();

        for i in 0..3 {
            assert_ne!(
                before[i].id.tag, after[i].id.tag,
                "step {i} tag must change"
            );
        }
    }

    #[test]
    fn editing_the_last_step_changes_only_its_own_tag() {
        let project = tempfile::tempdir().unwrap();
        let a = write_step(project.path(), "10-a", "FROM scratch\nRUN a\n");
        let b = write_step(project.path(), "20-b", "FROM scratch\nRUN b\n");
        let c = write_step(project.path(), "30-c", "FROM scratch\nRUN c\n");
        let dirs = vec![
            project_chain_dir(a),
            project_chain_dir(b),
            project_chain_dir(c.clone()),
        ];

        let before = plan_chain(&dirs, project.path(), TEST_BASE_ID).unwrap();
        fs::write(c.join("Dockerfile"), "FROM scratch\nRUN c-edited\n").unwrap();
        let after = plan_chain(&dirs, project.path(), TEST_BASE_ID).unwrap();

        assert_eq!(before[0].id.tag, after[0].id.tag);
        assert_eq!(before[1].id.tag, after[1].id.tag);
        assert_ne!(before[2].id.tag, after[2].id.tag);
    }

    #[test]
    fn plan_chain_is_stable_across_repeated_calls() {
        let project = tempfile::tempdir().unwrap();
        let a = write_step(project.path(), "10-a", "FROM scratch\n");
        let b = write_step(project.path(), "20-b", "FROM scratch\n");
        let dirs = vec![project_chain_dir(a), project_chain_dir(b)];

        let first = plan_chain(&dirs, project.path(), TEST_BASE_ID).unwrap();
        let second = plan_chain(&dirs, project.path(), TEST_BASE_ID).unwrap();
        assert_eq!(
            first.iter().map(|i| &i.id.tag).collect::<Vec<_>>(),
            second.iter().map(|i| &i.id.tag).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn plan_chain_of_one_matches_a_bare_resolve() {
        // The migration-is-free guard: a one-step chain's tag must be
        // exactly what the pre-chain implementation produced for the same
        // directory contents, so moving `.agent-vm/layer/` under
        // `.agent-vm/layers/` invalidates nobody's already-built image.
        let project = tempfile::tempdir().unwrap();
        let dir = write_step(project.path(), "10-a", "FROM scratch\n");

        let via_chain = plan_chain(
            &[project_chain_dir(dir.clone())],
            project.path(),
            TEST_BASE_ID,
        )
        .unwrap();
        let via_bare_resolve = resolve(&dir, project.path(), TEST_BASE_ID, first_of_one()).unwrap();
        assert_eq!(via_chain[0].id.tag, via_bare_resolve.tag);
    }

    #[test]
    fn appending_a_flag_layer_leaves_every_project_tag_unchanged() {
        // The design's core claim (ADR amendment "why append, not prepend"):
        // H_i depends only on steps 0..i, so appending a flag layer after
        // the project's own chain must not move any project step's tag.
        let project = tempfile::tempdir().unwrap();
        let a = write_step(project.path(), "10-a", "FROM scratch\n");
        let b = write_step(project.path(), "20-b", "FROM scratch\n");
        let flag = tempfile::tempdir().unwrap();
        fs::write(flag.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let without_flag = plan_chain(
            &[project_chain_dir(a.clone()), project_chain_dir(b.clone())],
            project.path(),
            TEST_BASE_ID,
        )
        .unwrap();
        let with_flag = plan_chain(
            &resolve_layer_chain(project.path(), &[flag.path().to_path_buf()]).unwrap(),
            project.path(),
            TEST_BASE_ID,
        )
        .unwrap();

        assert_eq!(without_flag[0].id.tag, with_flag[0].id.tag);
        assert_eq!(without_flag[1].id.tag, with_flag[1].id.tag);
        assert_eq!(with_flag.len(), 3);
    }

    #[test]
    fn try_then_adopt_yields_the_same_tag() {
        // origin/label must never reach the hash: trying an example via
        // `--layer` and then adopting it as a project step must be a cache
        // hit, not a rebuild. Same project directory throughout — the tag's
        // slug comes from `project_dir`, so a different project would
        // legitimately produce a different tag (resolve's own documented
        // trade-off) and would defeat the point of this test.
        let project = tempfile::tempdir().unwrap();
        let example = tempfile::tempdir().unwrap();
        fs::write(example.path().join("Dockerfile"), "FROM scratch\nRUN x\n").unwrap();
        let via_flag = plan_chain(
            &resolve_layer_chain(project.path(), &[example.path().to_path_buf()]).unwrap(),
            project.path(),
            TEST_BASE_ID,
        )
        .unwrap();

        write_step(project.path(), "10-x", "FROM scratch\nRUN x\n");
        let via_project = plan_chain(
            &resolve_layer_chain(project.path(), &[]).unwrap(),
            project.path(),
            TEST_BASE_ID,
        )
        .unwrap();

        assert_eq!(via_flag[0].id.tag, via_project[0].id.tag);
    }

    #[test]
    fn origin_and_label_reach_the_chain_step() {
        let project = tempfile::tempdir().unwrap();
        write_step(project.path(), "10-a", "FROM scratch\n");
        let flag = tempfile::tempdir().unwrap();
        fs::write(flag.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let chain = resolve_layer_chain(project.path(), &[flag.path().to_path_buf()]).unwrap();
        let plan = plan_chain(&chain, project.path(), TEST_BASE_ID).unwrap();

        assert_eq!(plan[0].origin, LayerOrigin::Project);
        assert_eq!(plan[0].label, chain[0].label);
        assert_eq!(plan[1].origin, LayerOrigin::Flag);
        assert_eq!(plan[1].label, chain[1].label);

        let bare = resolve(
            &chain[1].dir,
            project.path(),
            &plan[0].id.hash,
            ChainPosition { index: 1, total: 2 },
        )
        .unwrap();
        assert_eq!(plan[1].id, bare);
    }

    // --- parse_image_id() ---

    #[test]
    fn parse_image_id_trims_the_trailing_newline() {
        assert_eq!(parse_image_id("sha256:abc123\n").unwrap(), "sha256:abc123");
    }

    #[test]
    fn parse_image_id_rejects_empty_output() {
        assert!(parse_image_id("").is_err());
        assert!(parse_image_id("\n").is_err());
    }

    // --- execute_chain() against a recording fake ---

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Notice(String),
        ConfirmBuild(Vec<(String, bool)>), // (tag, pending) per step
        InspectIntermediate(String),
        CheckFinal(String),
        BuildIntermediate { tag: String, from: String },
        BuildAndLoadFinal { tag: String, from: String },
    }

    struct FakeRuntime {
        log: Vec<Event>,
        docker_store: std::collections::HashSet<String>, // intermediate tags "already built"
        msb_cache: std::collections::HashSet<String>,    // final tags "already ingested"
        fail_at: Option<usize>,                          // step index whose build returns Err
        declined: bool,
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self {
                log: Vec::new(),
                docker_store: std::collections::HashSet::new(),
                msb_cache: std::collections::HashSet::new(),
                fail_at: None,
                declined: false,
            }
        }
    }

    impl ChainRuntime for FakeRuntime {
        fn notice(&mut self, message: &str) -> Result<()> {
            self.log.push(Event::Notice(message.to_string()));
            Ok(())
        }

        fn confirm_build(&mut self, plan: &[PlannedStep]) -> Result<()> {
            self.log.push(Event::ConfirmBuild(
                plan.iter().map(|s| (s.tag.clone(), s.pending)).collect(),
            ));
            if self.declined {
                bail!("declined");
            }
            Ok(())
        }

        async fn intermediate_image_id(&mut self, tag: &str) -> Result<Option<String>> {
            self.log.push(Event::InspectIntermediate(tag.to_string()));
            Ok(self
                .docker_store
                .contains(tag)
                .then(|| format!("sha256:{tag}")))
        }

        async fn final_is_cached(&mut self, tag: &str) -> Result<bool> {
            self.log.push(Event::CheckFinal(tag.to_string()));
            Ok(self.msb_cache.contains(tag))
        }

        async fn build_intermediate(&mut self, id: &LayerIdentity, from_ref: &str) -> Result<()> {
            self.log.push(Event::BuildIntermediate {
                tag: id.tag.clone(),
                from: from_ref.to_string(),
            });
            if self.fail_at == Some(id.position.index) {
                bail!("build failed at step {}", id.position.index);
            }
            self.docker_store.insert(id.tag.clone());
            Ok(())
        }

        async fn build_and_load_final(&mut self, id: &LayerIdentity, from_ref: &str) -> Result<()> {
            self.log.push(Event::BuildAndLoadFinal {
                tag: id.tag.clone(),
                from: from_ref.to_string(),
            });
            if self.fail_at == Some(id.position.index) {
                bail!("build failed at step {}", id.position.index);
            }
            self.msb_cache.insert(id.tag.clone());
            Ok(())
        }
    }

    /// A 3-step chain plan with distinct tags, cheap to build repeatedly per
    /// test without touching disk — `execute_chain` never reads the
    /// filesystem itself, only the already-resolved `ChainStep`s.
    fn fake_plan(n: usize) -> Vec<ChainStep> {
        (0..n)
            .map(|i| ChainStep {
                id: LayerIdentity {
                    dir: PathBuf::from(format!("/proj/.agent-vm/layers/{i}")),
                    dockerfile: PathBuf::from(format!("/proj/.agent-vm/layers/{i}/Dockerfile")),
                    tag: format!("agent-vm-layer:proj-tag{i}"),
                    hash: format!("hash{i}"),
                    file_count: 1,
                    hashed_bytes: 1,
                    position: ChainPosition { index: i, total: n },
                },
                origin: LayerOrigin::Project,
                label: format!(".agent-vm/layers/{i}"),
            })
            .collect()
    }

    const PINNED_BASE: &str = "ghcr.io/example/base@sha256:base";

    #[tokio::test]
    async fn chain_builds_every_step_in_order_and_loads_only_the_last() {
        let plan = fake_plan(3);
        let mut rt = FakeRuntime::new();
        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        let intermediates: Vec<&str> = rt
            .log
            .iter()
            .filter_map(|e| match e {
                Event::BuildIntermediate { tag, .. } => Some(tag.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            intermediates,
            vec!["agent-vm-layer:proj-tag0", "agent-vm-layer:proj-tag1"]
        );

        let finals: Vec<&str> = rt
            .log
            .iter()
            .filter_map(|e| match e {
                Event::BuildAndLoadFinal { tag, .. } => Some(tag.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(finals, vec!["agent-vm-layer:proj-tag2"]);
    }

    #[tokio::test]
    async fn chain_from_ref_is_the_pinned_base_then_the_previous_tag() {
        let plan = fake_plan(3);
        let mut rt = FakeRuntime::new();
        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        let froms: Vec<&str> = rt
            .log
            .iter()
            .filter_map(|e| match e {
                Event::BuildIntermediate { from, .. } => Some(from.as_str()),
                Event::BuildAndLoadFinal { from, .. } => Some(from.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            froms,
            vec![
                PINNED_BASE,
                "agent-vm-layer:proj-tag0",
                "agent-vm-layer:proj-tag1"
            ]
        );
    }

    #[tokio::test]
    async fn fully_cached_chain_spawns_nothing_and_never_confirms() {
        let plan = fake_plan(2);
        let mut rt = FakeRuntime::new();
        rt.msb_cache.insert(plan[1].id.tag.clone());

        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        assert_eq!(
            rt.log,
            vec![
                Event::CheckFinal(plan[1].id.tag.clone()),
                Event::Notice(format!(
                    "==> Reusing cached tooling layer {}",
                    plan[1].id.tag
                )),
            ],
            "a cache-hit launch must touch nothing else — no inspect, no confirm, no build"
        );
    }

    #[tokio::test]
    async fn a_cached_prefix_is_not_rebuilt() {
        let plan = fake_plan(2);
        let mut rt = FakeRuntime::new();
        rt.docker_store.insert(plan[0].id.tag.clone());

        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        assert!(
            !rt.log
                .iter()
                .any(|e| matches!(e, Event::BuildIntermediate { .. })),
            "step 0 must not rebuild: {:?}",
            rt.log
        );
        let final_build = rt
            .log
            .iter()
            .find_map(|e| match e {
                Event::BuildAndLoadFinal { from, .. } => Some(from.clone()),
                _ => None,
            })
            .expect("final step must build");
        assert_eq!(final_build, plan[0].id.tag);
    }

    #[tokio::test]
    async fn the_backward_walk_stops_at_the_highest_cached_intermediate() {
        let plan = fake_plan(4);
        let mut rt = FakeRuntime::new();
        rt.docker_store.insert(plan[2].id.tag.clone());

        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        let inspected: Vec<&str> = rt
            .log
            .iter()
            .filter_map(|e| match e {
                Event::InspectIntermediate(tag) => Some(tag.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            inspected,
            vec![plan[2].id.tag.as_str()],
            "the walk must stop at the first (highest-index) cached intermediate it finds \
             and never inspect below it"
        );
        assert!(rt.log.iter().any(
            |e| matches!(e, Event::BuildAndLoadFinal { from, .. } if from == &plan[2].id.tag)
        ));
    }

    #[tokio::test]
    async fn a_failing_step_aborts_the_chain_and_never_loads() {
        for fail_at in [0usize, 1, 2] {
            let plan = fake_plan(3);
            let mut rt = FakeRuntime::new();
            rt.fail_at = Some(fail_at);

            let result = execute_chain(&plan, PINNED_BASE, &mut rt).await;
            assert!(result.is_err(), "fail_at={fail_at}");
            assert!(
                !rt.log
                    .iter()
                    .any(|e| matches!(e, Event::BuildAndLoadFinal { .. })
                        && rt.msb_cache.contains(&plan[2].id.tag)),
                "fail_at={fail_at}: a failed final build must not leave the msb cache populated"
            );
            assert!(
                rt.msb_cache.is_empty(),
                "fail_at={fail_at}: nothing may be ingested when any step fails"
            );
        }
    }

    #[tokio::test]
    async fn the_whole_chain_is_confirmed_by_a_single_prompt() {
        let plan = fake_plan(3);
        let mut rt = FakeRuntime::new();
        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        let confirms: Vec<&Vec<(String, bool)>> = rt
            .log
            .iter()
            .filter_map(|e| match e {
                Event::ConfirmBuild(steps) => Some(steps),
                _ => None,
            })
            .collect();
        assert_eq!(confirms.len(), 1, "exactly one prompt for the whole chain");
        assert_eq!(
            confirms[0],
            &vec![
                (plan[0].id.tag.clone(), true),
                (plan[1].id.tag.clone(), true),
                (plan[2].id.tag.clone(), true),
            ]
        );
    }

    #[tokio::test]
    async fn confirm_precedes_every_build() {
        let plan = fake_plan(3);
        let mut rt = FakeRuntime::new();
        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        let confirm_idx = rt
            .log
            .iter()
            .position(|e| matches!(e, Event::ConfirmBuild(_)))
            .unwrap();
        for (i, event) in rt.log.iter().enumerate() {
            if matches!(
                event,
                Event::BuildIntermediate { .. } | Event::BuildAndLoadFinal { .. }
            ) {
                assert!(
                    i > confirm_idx,
                    "build at index {i} precedes confirm at {confirm_idx}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_declined_chain_builds_nothing() {
        let plan = fake_plan(2);
        let mut rt = FakeRuntime::new();
        rt.declined = true;

        assert!(execute_chain(&plan, PINNED_BASE, &mut rt).await.is_err());
        assert!(!rt.log.iter().any(|e| matches!(
            e,
            Event::BuildIntermediate { .. } | Event::BuildAndLoadFinal { .. }
        )));
    }

    #[tokio::test]
    async fn a_single_step_chain_uses_the_pinned_base_and_never_inspects() {
        let plan = fake_plan(1);
        let mut rt = FakeRuntime::new();
        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        assert!(!rt.log.iter().any(|e| matches!(
            e,
            Event::InspectIntermediate(_) | Event::BuildIntermediate { .. }
        )));
        assert_eq!(
            rt.log
                .iter()
                .filter(|e| matches!(e, Event::BuildAndLoadFinal { .. }))
                .count(),
            1
        );
        assert!(
            rt.log
                .iter()
                .any(|e| matches!(e, Event::BuildAndLoadFinal { from, .. } if from == PINNED_BASE))
        );
    }

    /// Like [`fake_plan`], but the caller picks each step's origin — for the
    /// amendment's A6 tests, where whether a step is a project step or a
    /// `--layer` step is the point.
    fn fake_plan_with_origins(origins: &[LayerOrigin]) -> Vec<ChainStep> {
        let n = origins.len();
        origins
            .iter()
            .enumerate()
            .map(|(i, &origin)| {
                let label = match origin {
                    LayerOrigin::Project => format!(".agent-vm/layers/{i}"),
                    LayerOrigin::Flag => format!("--layer flag-{i}"),
                };
                ChainStep {
                    id: LayerIdentity {
                        dir: PathBuf::from(format!("/proj/{i}")),
                        dockerfile: PathBuf::from(format!("/proj/{i}/Dockerfile")),
                        tag: format!("agent-vm-layer:proj-tag{i}"),
                        hash: format!("hash{i}"),
                        file_count: 1,
                        hashed_bytes: 1,
                        position: ChainPosition { index: i, total: n },
                    },
                    origin,
                    label,
                }
            })
            .collect()
    }

    #[tokio::test]
    async fn adding_a_flag_layer_reexports_only_the_last_project_step() {
        // Amendment A6: the project's own last step was only ever ingested
        // as an OCI archive (never landed in docker's local image store), so
        // appending a --layer after it must re-export that step once — the
        // backward walk sees it as "not cached" from docker's point of view
        // and the confirmation prompt must show it as pending, not cached.
        use LayerOrigin::{Flag, Project};
        let plan = fake_plan_with_origins(&[Project, Project, Flag]);
        let mut rt = FakeRuntime::new();
        rt.docker_store.insert(plan[0].id.tag.clone());
        // plan[1] (the project's last step) is deliberately absent from
        // docker_store: it was built with --output type=oci and only lives
        // in the msb cache, which this fake never populates for it.

        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        let confirm = rt
            .log
            .iter()
            .find_map(|e| match e {
                Event::ConfirmBuild(steps) => Some(steps),
                _ => None,
            })
            .expect("one confirmation");
        assert_eq!(
            confirm,
            &vec![
                (plan[0].id.tag.clone(), false),
                (plan[1].id.tag.clone(), true),
                (plan[2].id.tag.clone(), true),
            ],
            "step 0 cached; the project's last step and the flag step both pending"
        );

        let built: Vec<&str> = rt
            .log
            .iter()
            .filter_map(|e| match e {
                Event::BuildIntermediate { tag, .. } => Some(tag.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(built, vec![plan[1].id.tag.as_str()]);
        assert!(
            rt.log.iter().any(
                |e| matches!(e, Event::BuildAndLoadFinal { tag, .. } if tag == &plan[2].id.tag)
            )
        );
    }

    #[tokio::test]
    async fn dropping_the_flag_again_is_a_pure_cache_hit() {
        // Once the project's own chain (without any --layer) has its final
        // tag ingested, launching without the flag again touches nothing —
        // the project's tag never left the msb cache regardless of what was
        // appended to it on some other launch.
        use LayerOrigin::Project;
        let plan = fake_plan_with_origins(&[Project, Project]);
        let mut rt = FakeRuntime::new();
        rt.msb_cache.insert(plan[1].id.tag.clone());

        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        assert_eq!(
            rt.log,
            vec![
                Event::CheckFinal(plan[1].id.tag.clone()),
                Event::Notice(format!(
                    "==> Reusing cached tooling layer {}",
                    plan[1].id.tag
                )),
            ]
        );
    }

    #[tokio::test]
    async fn a_failing_flag_layer_aborts_and_never_loads() {
        use LayerOrigin::{Flag, Project};
        let plan = fake_plan_with_origins(&[Project, Flag]);
        let mut rt = FakeRuntime::new();
        rt.fail_at = Some(1); // the flag step

        let result = execute_chain(&plan, PINNED_BASE, &mut rt).await;
        assert!(result.is_err());
        assert!(rt.msb_cache.is_empty(), "nothing may be ingested");
    }

    #[tokio::test]
    async fn notices_use_step_labels() {
        use LayerOrigin::{Flag, Project};
        let plan = fake_plan_with_origins(&[Project, Flag]);
        let mut rt = FakeRuntime::new();

        execute_chain(&plan, PINNED_BASE, &mut rt).await.unwrap();

        let building_final = rt
            .log
            .iter()
            .find_map(|e| match e {
                Event::Notice(msg) if msg.contains("Building") && msg.contains("2/2") => {
                    Some(msg.clone())
                }
                _ => None,
            })
            .expect("a building notice for the flag step");
        assert!(
            building_final.contains("--layer flag-1"),
            "{building_final}"
        );
    }

    // --- digest_pinned_base() ---

    #[test]
    fn digest_pinned_base_pins_tagged_ref() {
        let pinned =
            digest_pinned_base("ghcr.io/wirenboard/agent-vm-template:latest", "sha256:abc")
                .unwrap();
        assert_eq!(pinned, "ghcr.io/wirenboard/agent-vm-template@sha256:abc");
    }

    #[test]
    fn digest_pinned_base_handles_registry_port() {
        // The tricky colon case: `localhost:5000` must stay intact as the
        // registry host:port, and only the *tag* colon (after the `/`) gets
        // replaced by the digest.
        let pinned = digest_pinned_base("localhost:5000/x:latest", "sha256:def").unwrap();
        assert_eq!(pinned, "localhost:5000/x@sha256:def");
    }

    #[test]
    fn digest_pinned_base_handles_untagged_ref() {
        // `Reference` normalizes a bare "nginx" to the fully-qualified
        // docker.io/library/nginx form (the same normalization docker
        // itself would apply to `FROM nginx`), so the plan's "or normalized
        // form" allowance is exercised here: assert the digest is appended
        // exactly once and the repository name survives, rather than
        // pinning the literal input string.
        let pinned = digest_pinned_base("nginx", "sha256:aaa").unwrap();
        assert_eq!(pinned.matches('@').count(), 1, "pinned = {pinned}");
        assert!(pinned.ends_with("@sha256:aaa"), "pinned = {pinned}");
        assert!(pinned.contains("nginx"), "pinned = {pinned}");
    }

    #[test]
    fn digest_pinned_base_normalizes_ref_that_already_has_a_digest() {
        // A full 64-hex-char digest so `Reference::parse` accepts it as a
        // valid existing digest (short/fake digests fail its length check
        // and would instead exercise the string-surgery fallback below).
        let old_digest = format!("sha256:{}", "a".repeat(64));
        let base_ref = format!("ghcr.io/wirenboard/agent-vm-template@{old_digest}");
        let pinned = digest_pinned_base(&base_ref, "sha256:newnew").unwrap();
        // Defines the behavior: the caller's manifest_digest always wins,
        // completely replacing any digest already embedded in base_ref.
        assert_eq!(pinned, "ghcr.io/wirenboard/agent-vm-template@sha256:newnew");
    }

    // --- digest_pin_by_string_surgery() — the Reference-parse-failure fallback ---

    #[test]
    fn digest_pin_by_string_surgery_guards_registry_port_colon() {
        // Uppercase in the repository segment makes `Reference::parse`
        // reject the whole ref (its grammar requires lowercase repository
        // components), forcing the fallback path — this is the case that
        // must not confuse the `localhost:5000` port colon for a tag colon.
        let base_ref = "localhost:5000/MyRepo:latest";
        assert!(base_ref.parse::<microsandbox_image::Reference>().is_err());
        assert_eq!(
            digest_pin_by_string_surgery(base_ref, "sha256:ccc"),
            "localhost:5000/MyRepo@sha256:ccc"
        );
    }

    #[test]
    fn digest_pin_by_string_surgery_untagged_ref_appends_digest() {
        assert_eq!(
            digest_pin_by_string_surgery("MyRepo", "sha256:ddd"),
            "MyRepo@sha256:ddd"
        );
    }

    #[test]
    fn digest_pin_by_string_surgery_strips_existing_digest_first() {
        assert_eq!(
            digest_pin_by_string_surgery("host/MyRepo@sha256:old", "sha256:new"),
            "host/MyRepo@sha256:new"
        );
    }

    // --- host_oci_platform() ---

    #[test]
    fn host_oci_platform_matches_the_running_host_and_load_archive_mapping() {
        // Must mirror microsandbox_image's Platform::host_linux() arch
        // mapping exactly, so the image we build is the manifest
        // load_archive materializes for this host (see the fn's doc and
        // ADR-0003's platform note). Asserting against the same
        // std::env::consts::ARCH the vendored crate reads keeps the two in
        // lockstep regardless of which arch the test itself runs on.
        let expected = match std::env::consts::ARCH {
            "x86_64" => "linux/amd64".to_string(),
            "aarch64" => "linux/arm64".to_string(),
            other => format!("linux/{other}"),
        };
        assert_eq!(host_oci_platform(), expected);
        // Never the bare, host-agnostic literal the plan originally
        // hardcoded — that is precisely the bug this replaces on aarch64.
        assert!(host_oci_platform().starts_with("linux/"));
    }

    // --- derived_is_cached() ---

    #[tokio::test]
    async fn derived_is_cached_is_false_when_nothing_was_ever_loaded() {
        let cache_dir = tempfile::tempdir().unwrap();
        let cached = derived_is_cached(cache_dir.path(), "agent-vm-layer:my-app-deadbeef")
            .await
            .unwrap();
        assert!(!cached);
    }

    #[tokio::test]
    async fn derived_is_cached_rejects_an_unparseable_tag() {
        let cache_dir = tempfile::tempdir().unwrap();
        let err = derived_is_cached(cache_dir.path(), "NOT A VALID TAG")
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("parsing derived image tag"));
    }

    // --- e2e: real docker buildx build + registry-less load ---
    //
    // `#[ignore]`d: needs a working `docker buildx` on PATH, plus a base
    // image resolvable without a registry-less launcher of its own —
    // either already present in docker's local image store, or pullable
    // over the network. Defaults to `alpine:latest` (small, public,
    // portable to any dev host with normal internet access); override with
    // `AGENT_VM_E2E_BASE_IMAGE=<ref>` to point at a locally cached image
    // instead (e.g. the real `agent-vm-template:latest`) on a host where
    // outbound registry access is restricted. Run explicitly:
    // `cargo test -p agent-vm --bin agent-vm layer::tests::e2e -- --ignored`
    // (there is no `--lib` target: `crates/agent-vm/Cargo.toml` declares only
    // `[[bin]]`).
    //
    // This exercises the novel, riskiest part of this ticket for real —
    // `docker buildx build --output type=oci` with a digest-pinned
    // `BASE_IMAGE` (mirrors [`digest_pinned_base`]) producing an archive
    // that `microsandbox_image::load_archive` then ingests registry-lessly,
    // with no `registry:2` sidecar involved — without needing the full
    // `agent-vm` CLI/session/mount machinery or an actual VM boot (which
    // this test deliberately does not attempt; see
    // `docs/adr/0003-project-tooling-layers.md` and the plan's note that a
    // live VM boot needs Hypervisor.framework/KVM this dev sandbox may not
    // have).

    /// Resolves the e2e base image's local content digest (pulling it once
    /// if it isn't already present and the pull succeeds), and pins it via
    /// the same [`digest_pinned_base`] production code path `run.rs` uses.
    /// Returns `None` — skip, don't fail — when neither a local copy nor a
    /// network pull can produce one, so this e2e module degrades to a
    /// no-op on a host with no docker at all rather than a false failure.
    ///
    /// The returned "digest" is actually `docker image inspect`'s resolved
    /// image id, not a registry manifest digest — a pre-existing
    /// simplification of this e2e harness (there is no registry in play
    /// here to ask for a manifest digest), reused as-is for the chain e2e
    /// test below rather than fixed as part of this ticket.
    fn e2e_pinned_base() -> Option<(String, String, String)> {
        let base = std::env::var("AGENT_VM_E2E_BASE_IMAGE")
            .unwrap_or_else(|_| "alpine:latest".to_string());
        let inspect = |base: &str| {
            std::process::Command::new("docker")
                .args(["image", "inspect", base, "--format", "{{.Id}}"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        };
        let digest = inspect(&base).or_else(|| {
            let pulled = std::process::Command::new("docker")
                .args(["pull", "-q", &base])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            pulled.then(|| inspect(&base)).flatten()
        })?;
        let pinned = digest_pinned_base(&base, &digest).ok()?;
        Some((base, digest, pinned))
    }

    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_build_and_load_round_trip_through_derived_is_cached() {
        if ensure_docker_buildx().is_err() {
            eprintln!("skipping: `docker buildx` not available on PATH");
            return;
        }
        let Some((base, _digest, pinned_base)) = e2e_pinned_base() else {
            eprintln!("skipping: no base image available locally or via network pull");
            return;
        };
        eprintln!("e2e base: {base} pinned to {pinned_base}");

        let layer_dir = tempfile::tempdir().unwrap();
        write_layer_file(
            layer_dir.path(),
            "Dockerfile",
            &format!(
                "ARG BASE_IMAGE={base}\n\
                 FROM ${{BASE_IMAGE}}\n\
                 RUN ln -s /bin/true /usr/local/bin/marker-tool\n\
                 ENV PATH=/usr/local/bin:$PATH\n"
            ),
            0o644,
        );
        let id = resolve(
            layer_dir.path(),
            Path::new("/tmp/e2e-project"),
            "sha256:e2e0000000000000000000000000000000000000000000000000000000000",
            first_of_one(),
        )
        .unwrap();

        let cache_dir = tempfile::tempdir().unwrap();
        assert!(
            !derived_is_cached(cache_dir.path(), &id.tag).await.unwrap(),
            "must start uncached"
        );

        let tar = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
        build_derived_oci(&id, &pinned_base, tar.path())
            .await
            .expect("docker buildx build");
        load_derived_image(cache_dir.path(), tar.path(), &id.tag)
            .await
            .expect("load_archive");

        assert!(
            derived_is_cached(cache_dir.path(), &id.tag).await.unwrap(),
            "must be cached after load — this is the invariant boot's \
             PullPolicy::IfMissing relies on to resolve from cache with no \
             registry contact"
        );

        // PATH propagation: read the ingested image's config directly
        // (mirrors run.rs's `image_config_path_and_digest`, inlined here so
        // this crate-internal test doesn't reach across into `run.rs`).
        let reference: microsandbox_image::Reference = id.tag.parse().unwrap();
        let cache = microsandbox_image::GlobalCache::new_async(cache_dir.path())
            .await
            .unwrap();
        let metadata = cache
            .read_image_metadata_async(&reference)
            .await
            .unwrap()
            .expect("metadata must be present after load_archive");
        let path_entry = metadata
            .config
            .env
            .iter()
            .rev()
            .find_map(|e| e.strip_prefix("PATH="));
        let path_entry = path_entry.expect("derived image config must declare a PATH");
        assert!(
            path_entry.starts_with("/usr/local/bin:"),
            "the layer's ENV PATH=/usr/local/bin:$PATH must merge into the \
             derived image's config, prefixed ahead of the base's own PATH; got {path_entry:?}"
        );

        // No registry:2 sidecar: this whole test never started one, and
        // load_archive/derived_is_cached never touch the network — the
        // absence of network calls (not a `docker ps` grep) is the actual
        // proof for the in-process ingest path this test exercises.
    }

    /// Companion to the round-trip test above: editing the layer (a second
    /// symlink) changes [`resolve`]'s hash, so the *new* identity's tag is
    /// correctly a fresh cache miss even though the *old* tag was already
    /// ingested — pins the "edit invalidates the cache" behavior the ticket
    /// calls "rebuild on edit" without needing to literally invoke
    /// `docker buildx build` twice (that invariant belongs to `resolve`,
    /// already covered by the hash tests above; this only confirms
    /// `derived_is_cached` sees the two tags as unrelated cache entries).
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_editing_the_layer_is_a_fresh_cache_miss() {
        if ensure_docker_buildx().is_err() {
            eprintln!("skipping: `docker buildx` not available on PATH");
            return;
        }
        let Some((base, _digest, pinned_base)) = e2e_pinned_base() else {
            eprintln!("skipping: no base image available locally or via network pull");
            return;
        };

        let layer_dir = tempfile::tempdir().unwrap();
        write_layer_file(
            layer_dir.path(),
            "Dockerfile",
            &format!("ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\n"),
            0o644,
        );
        let base_id = "sha256:e2e0000000000000000000000000000000000000000000000000000000000";
        let before = resolve(
            layer_dir.path(),
            Path::new("/tmp/e2e-project"),
            base_id,
            first_of_one(),
        )
        .unwrap();

        let cache_dir = tempfile::tempdir().unwrap();
        let tar = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
        build_derived_oci(&before, &pinned_base, tar.path())
            .await
            .expect("docker buildx build");
        load_derived_image(cache_dir.path(), tar.path(), &before.tag)
            .await
            .expect("load_archive");
        assert!(
            derived_is_cached(cache_dir.path(), &before.tag)
                .await
                .unwrap()
        );

        write_layer_file(
            layer_dir.path(),
            "Dockerfile",
            &format!(
                "ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\nRUN ln -s /bin/true /usr/local/bin/marker-tool\n"
            ),
            0o644,
        );
        let after = resolve(
            layer_dir.path(),
            Path::new("/tmp/e2e-project"),
            base_id,
            first_of_one(),
        )
        .unwrap();

        assert_ne!(
            before.tag, after.tag,
            "editing the Dockerfile must change the tag"
        );
        assert!(
            !derived_is_cached(cache_dir.path(), &after.tag)
                .await
                .unwrap(),
            "the edited layer's tag must be a fresh cache miss, triggering a rebuild"
        );
        // The old tag is untouched — still resolves from cache. Confirms
        // the hash-as-staleness-check design (no state file to go stale):
        // both identities coexist in the cache independently.
        assert!(
            derived_is_cached(cache_dir.path(), &before.tag)
                .await
                .unwrap()
        );
    }

    // --- e2e: the chain, and ADR-0003's fsmeta/VMDK guard ---

    /// A minimal, real [`ChainRuntime`]: notices go to stderr, confirmation
    /// always proceeds (there is no interactive prompt to script in a
    /// test), and every other method is the real production function
    /// against real docker + the msb cache. `run.rs`'s `LaunchChainRuntime`
    /// is the production wiring; this is its crate-internal twin so
    /// `plan_chain` + `execute_chain` can be exercised end-to-end here
    /// without dragging in `run.rs`'s launch machinery.
    struct E2eChainRuntime {
        cache_dir: PathBuf,
    }

    impl ChainRuntime for E2eChainRuntime {
        fn notice(&mut self, message: &str) -> Result<()> {
            eprintln!("{message}");
            Ok(())
        }

        fn confirm_build(&mut self, _plan: &[PlannedStep]) -> Result<()> {
            Ok(())
        }

        async fn intermediate_image_id(&mut self, tag: &str) -> Result<Option<String>> {
            docker_image_id(tag).await
        }

        async fn final_is_cached(&mut self, tag: &str) -> Result<bool> {
            derived_is_cached(&self.cache_dir, tag).await
        }

        async fn build_intermediate(&mut self, id: &LayerIdentity, from_ref: &str) -> Result<()> {
            build_derived_docker(id, from_ref).await
        }

        async fn build_and_load_final(&mut self, id: &LayerIdentity, from_ref: &str) -> Result<()> {
            let tar = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
            build_derived_oci(id, from_ref, tar.path()).await?;
            load_derived_image(&self.cache_dir, tar.path(), &id.tag).await?;
            Ok(())
        }
    }

    /// Issue AC 1: `.agent-vm/layers/{10-a,20-b}/` builds both layers in
    /// order and loads only the final image. (Booting it is out of scope
    /// for this crate-internal module — see the file-level e2e note above —
    /// but everything up to "ready to boot" runs for real here: two live
    /// `docker buildx build`s chained through docker's own image store, then
    /// a real `load_archive` ingest.)
    ///
    /// Each step's marker is an `ENV`, not a `RUN ln -s` file, specifically
    /// so this test can prove both steps composed by reading the *ingested
    /// image's config* (mirroring the PATH-merge assertion in the round-trip
    /// test above) without needing a VM boot to `ls` a symlink.
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_two_step_chain_builds_in_order_and_ingests_only_the_final_image() {
        if ensure_docker_buildx().is_err() {
            eprintln!("skipping: `docker buildx` not available on PATH");
            return;
        }
        let Some((base, digest, _pinned)) = e2e_pinned_base() else {
            eprintln!("skipping: no base image available locally or via network pull");
            return;
        };

        let project = tempfile::tempdir().unwrap();
        write_step(
            project.path(),
            "10-a",
            &format!("ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\nENV MARKER_A=present\n"),
        );
        write_step(
            project.path(),
            "20-b",
            // FROM the *previous step's tag*, per D5/D4: this step's build
            // context never names the base image directly.
            "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\nENV MARKER_B=present\n",
        );
        let dirs = resolve_layer_chain(project.path(), &[]).unwrap();
        assert_eq!(dirs.len(), 2);

        let plan = plan_chain(&dirs, project.path(), &digest).unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let mut rt = E2eChainRuntime {
            cache_dir: cache_dir.path().to_path_buf(),
        };
        let pinned_base = digest_pinned_base(&base, &digest).unwrap();
        let final_tag = execute_chain(&plan, &pinned_base, &mut rt)
            .await
            .expect("chain execution");

        assert_eq!(final_tag, plan[1].id.tag);
        assert!(
            derived_is_cached(cache_dir.path(), &plan[1].id.tag)
                .await
                .unwrap(),
            "the final step must be ingested into the msb cache"
        );
        assert!(
            !derived_is_cached(cache_dir.path(), &plan[0].id.tag)
                .await
                .unwrap(),
            "an intermediate step must never be ingested — only docker's own image store"
        );
        assert!(
            docker_image_id(&plan[0].id.tag).await.unwrap().is_some(),
            "the intermediate step must land in docker's local image store"
        );

        let reference: microsandbox_image::Reference = plan[1].id.tag.parse().unwrap();
        let cache = microsandbox_image::GlobalCache::new_async(cache_dir.path())
            .await
            .unwrap();
        let metadata = cache
            .read_image_metadata_async(&reference)
            .await
            .unwrap()
            .expect("metadata must be present after the chain ingests the final image");
        assert!(
            metadata.config.env.iter().any(|e| e == "MARKER_A=present"),
            "step 0's ENV must survive into the final image — proof step 1 was built \
             FROM step 0's tag, not straight from the base"
        );
        assert!(
            metadata.config.env.iter().any(|e| e == "MARKER_B=present"),
            "step 1's own ENV must also be present"
        );
    }

    /// Amendment A1/A6's one genuinely new real-docker behavior: a project
    /// step that was already built and ingested as a **final** step (OCI
    /// archive, never landed in docker's local image store) must be
    /// rebuildable as an **intermediate** (`--output type=docker`) under
    /// the exact same tag once a `--layer` is appended after it — content-
    /// hash chaining is prefix-stable, so the tag doesn't move even though
    /// the *kind* of build that produces it does.
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_a_final_step_can_be_rebuilt_as_an_intermediate_under_the_same_tag() {
        if ensure_docker_buildx().is_err() {
            eprintln!("skipping: `docker buildx` not available on PATH");
            return;
        }
        let Some((base, digest, _pinned)) = e2e_pinned_base() else {
            eprintln!("skipping: no base image available locally or via network pull");
            return;
        };

        let project = tempfile::tempdir().unwrap();
        write_step(
            project.path(),
            "10-a",
            &format!("ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\nENV MARKER_A=present\n"),
        );
        let flag_dir = tempfile::tempdir().unwrap();
        write_layer_file(
            flag_dir.path(),
            "Dockerfile",
            "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\nENV MARKER_X=present\n",
            0o644,
        );

        let cache_dir = tempfile::tempdir().unwrap();
        let pinned_base = digest_pinned_base(&base, &digest).unwrap();

        // First launch: just the project's one-step chain. Built and
        // ingested as a final step (OCI archive) — never lands in docker's
        // local image store.
        let solo_dirs = resolve_layer_chain(project.path(), &[]).unwrap();
        let solo_plan = plan_chain(&solo_dirs, project.path(), &digest).unwrap();
        let solo_tag = solo_plan[0].id.tag.clone();
        let mut rt = E2eChainRuntime {
            cache_dir: cache_dir.path().to_path_buf(),
        };
        execute_chain(&solo_plan, &pinned_base, &mut rt)
            .await
            .expect("first chain execution");
        assert!(
            derived_is_cached(cache_dir.path(), &solo_tag)
                .await
                .unwrap(),
            "the solo project step must be ingested as a final step"
        );
        assert!(
            docker_image_id(&solo_tag).await.unwrap().is_none(),
            "a step ingested only as a final (OCI) build must not be in docker's own store"
        );

        // Second launch: append a --layer after it. execute_chain's
        // backward walk must not find `solo_tag` in docker's store, so it
        // rebuilds step 0 as an intermediate under the *same* tag before
        // building the flag step as the new final.
        let chain_with_flag =
            resolve_layer_chain(project.path(), &[flag_dir.path().to_path_buf()]).unwrap();
        let plan_with_flag = plan_chain(&chain_with_flag, project.path(), &digest).unwrap();
        assert_eq!(
            plan_with_flag[0].id.tag, solo_tag,
            "prefix-stability: the project's step must keep the exact same tag"
        );
        let mut rt2 = E2eChainRuntime {
            cache_dir: cache_dir.path().to_path_buf(),
        };
        let final_tag = execute_chain(&plan_with_flag, &pinned_base, &mut rt2)
            .await
            .expect("second chain execution");

        assert_eq!(final_tag, plan_with_flag[1].id.tag);
        assert!(
            docker_image_id(&solo_tag).await.unwrap().is_some(),
            "step 0 must now also exist in docker's local image store, re-built as an \
             intermediate under its unchanged tag"
        );

        let reference: microsandbox_image::Reference = final_tag.parse().unwrap();
        let cache = microsandbox_image::GlobalCache::new_async(cache_dir.path())
            .await
            .unwrap();
        let metadata = cache
            .read_image_metadata_async(&reference)
            .await
            .unwrap()
            .expect("metadata must be present after the second chain's ingest");
        assert!(metadata.config.env.iter().any(|e| e == "MARKER_A=present"));
        assert!(metadata.config.env.iter().any(|e| e == "MARKER_X=present"));
    }

    /// The named ADR-0003 guard (issue AC 9). `derived_is_cached`'s own
    /// check (exercised by the round-trip test above, via
    /// `is_vmdk_materialized`) says nothing about the fsmeta EROFS image —
    /// the metadata-only merged view `load_archive` also materializes and
    /// ADR-0003's Consequences section calls out by name ("stages blobs
    /// AND materializes per-layer EROFS + fsmeta + VMDK offline"). Without
    /// fsmeta, a boot would fail even though `derived_is_cached` still read
    /// "cached". `GlobalCache::is_fsmeta_materialized` is the public
    /// accessor the vendored `microsandbox_image` crate exposes for this
    /// (`vendor/microsandbox/crates/image/lib/cache/store.rs`).
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_load_archive_materializes_fsmeta_and_vmdk() {
        if ensure_docker_buildx().is_err() {
            eprintln!("skipping: `docker buildx` not available on PATH");
            return;
        }
        let Some((base, _digest, pinned_base)) = e2e_pinned_base() else {
            eprintln!("skipping: no base image available locally or via network pull");
            return;
        };

        let layer_dir = tempfile::tempdir().unwrap();
        write_layer_file(
            layer_dir.path(),
            "Dockerfile",
            &format!("ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\n"),
            0o644,
        );
        let id = resolve(
            layer_dir.path(),
            Path::new("/tmp/e2e-fsmeta-project"),
            "sha256:e2efsmeta000000000000000000000000000000000000000000000000000",
            first_of_one(),
        )
        .unwrap();

        let cache_dir = tempfile::tempdir().unwrap();
        let tar = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
        build_derived_oci(&id, &pinned_base, tar.path())
            .await
            .expect("docker buildx build");
        load_derived_image(cache_dir.path(), tar.path(), &id.tag)
            .await
            .expect("load_archive");

        let reference: microsandbox_image::Reference = id.tag.parse().unwrap();
        let cache = microsandbox_image::GlobalCache::new_async(cache_dir.path())
            .await
            .unwrap();
        let metadata = cache
            .read_image_metadata_async(&reference)
            .await
            .unwrap()
            .expect("metadata must be present after load_archive");
        let manifest_digest: microsandbox_image::Digest = metadata.manifest_digest.parse().unwrap();

        assert!(
            cache.is_fsmeta_materialized(&manifest_digest),
            "load_archive must materialize the fsmeta EROFS image, not just the VMDK \
             (ADR-0003 Consequences)"
        );
        assert!(
            cache.is_vmdk_materialized(&manifest_digest),
            "companion assertion, so this one test names both halves of ADR-0003's \
             invariant together"
        );
    }
}
