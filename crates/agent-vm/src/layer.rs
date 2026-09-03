//! Turn a project's tooling layer directory into the identity of the derived
//! image, then build, registry-lessly load, and report on that derived
//! image.
//!
//! Identity is a content hash rather than a recorded state file: the tag
//! itself is the staleness check, so there is nothing to forget to write and
//! nothing that can disagree with the image store. See
//! `docs/adr/0003-project-tooling-layers.md` for the full design.
//!
//! Ported from `claude-contained`'s `internal/layer/{hash,layer}.go` and
//! `internal/host/sanitize.go` — see those files for the original Go
//! implementation this mirrors.
//!
//! The module splits into two sections: identity (pure, no I/O beyond
//! reading the layer directory to hash it) and build & load (the only
//! I/O/process-spawning code here — `docker buildx build` plus a
//! registry-less `microsandbox_image::load_archive` ingest). `run.rs`
//! orchestrates calling both from `launch()`.

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
    match run_buildx(id, pinned_base, out_tar, "zstd").await {
        Ok(()) => Ok(()),
        Err(zstd_err) => {
            eprintln!(
                "==> docker buildx build (zstd output) failed for {}; retrying with gzip output: {zstd_err}",
                id.tag
            );
            run_buildx(id, pinned_base, out_tar, "gzip").await.with_context(|| {
                format!(
                    "building tooling layer {} (gzip retry also failed; zstd attempt failed with: {zstd_err})",
                    id.tag
                )
            })
        }
    }
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

async fn run_buildx(
    id: &LayerIdentity,
    pinned_base: &str,
    out_tar: &Path,
    compression: &str,
) -> Result<()> {
    let out_tar_str = out_tar
        .to_str()
        .context("tooling-layer OCI archive path is not valid UTF-8")?;
    let dockerfile_str = id
        .dockerfile
        .to_str()
        .context("Dockerfile path is not valid UTF-8")?;
    let dir_str = id
        .dir
        .to_str()
        .context("tooling-layer directory path is not valid UTF-8")?;
    let status = tokio::process::Command::new("docker")
        .arg("buildx")
        .arg("build")
        .arg("--build-arg")
        .arg(format!("BASE_IMAGE={pinned_base}"))
        .arg("-f")
        .arg(dockerfile_str)
        .arg("--platform")
        .arg(host_oci_platform())
        .arg("--provenance=false")
        .arg("--sbom=false")
        .arg("--output")
        .arg(format!(
            "type=oci,dest={out_tar_str},compression={compression}"
        ))
        .arg(dir_str)
        .status()
        .await
        .with_context(|| {
            format!(
                "spawning `docker buildx build` for tooling layer {}",
                id.tag
            )
        })?;
    if !status.success() {
        bail!(
            "`docker buildx build` failed for tooling layer {} ({compression} output, exit {})",
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
            ("/work/abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrst"),
            ("/work/abcdefghijklmnopqrs-tuv", "abcdefghijklmnopqrs-"),
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
    // `cargo test -p agent-vm --lib layer::tests::e2e -- --ignored`.
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
    fn e2e_pinned_base() -> Option<(String, String)> {
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
        Some((base, pinned))
    }

    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_build_and_load_round_trip_through_derived_is_cached() {
        if ensure_docker_buildx().is_err() {
            eprintln!("skipping: `docker buildx` not available on PATH");
            return;
        }
        let Some((base, pinned_base)) = e2e_pinned_base() else {
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
        let Some((base, pinned_base)) = e2e_pinned_base() else {
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
        let before = resolve(layer_dir.path(), Path::new("/tmp/e2e-project"), base_id).unwrap();

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
        let after = resolve(layer_dir.path(), Path::new("/tmp/e2e-project"), base_id).unwrap();

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
}
