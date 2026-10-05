//! The user-scoped record of which immutable boot image this host retains as
//! its default (issue #261).
//!
//! # A bookmark, not a cache
//!
//! The record stores one OCI reference pinned by digest. It names exact image
//! content; microsandbox separately downloads and caches that content. Losing
//! the msb cache, changing `AGENT_VM_STATE_DIR`, enabling a shared cache or
//! working in another project must not change which image a default launch
//! boots, so the record lives beside the other user-scoped agent-vm settings
//! (`$HOME/.config/agent-vm/`) and **never** inside project state, the msb home
//! or `config.toml`. Writing a top-level `image =` into `config.toml` would make
//! the user tier outrank the project tier, which is a precedence change, not a
//! retention.
//!
//! # Write-once, after acquisition
//!
//! [`load`] is read-only and never repairs: a genuinely absent file is
//! `Ok(None)`, and anything else that cannot be turned into a validated
//! immutable reference is an error naming a recovery. [`adopt`] is the only
//! mutator, is called only after the image content was actually acquired, and
//! is first-writer-wins under an exclusive `flock`: a concurrent second adopter
//! (or a launcher upgrade) cannot replace a record already on disk. Replacing a
//! *working* retained default is deliberately not implemented here (#262).
//!
//! [`adopt`] checks for an existing valid record **before** it creates the
//! config directory, the lock file or any temporary file: a steady-state
//! default launch neither needs nor is blocked by a writable config directory.
//! The check is repeated under the lock so a peer that won the race is honoured
//! (first writer wins).
//!
//! # Failure and atomicity contract
//!
//! Reads are bounded and no-follow: a symlink, FIFO, directory, oversize file
//! or permission error is a hard error, never a silent reset. Writes go through
//! [`host_paths::atomic_write`], so a process killed mid-adopt leaves either no
//! file or a complete one — never an empty "already selected" file. That
//! primitive does not `fsync`, so this module promises the repository's existing
//! trusted-host interruption atomicity, not power-loss durability.
//!
//! # Diagnostic safety
//!
//! The record is untrusted input (a user-writable file whose reference may name
//! a private registry). Every failure this module reports is therefore a
//! **closed, fixed reason** plus the escaped record/lock path — never a
//! formatted source error, and never a source chain. Filesystem, lock, reader,
//! serde, UTF-8, digest-parser and save errors are all mapped to one of the
//! reasons below; the original error is discarded (it can embed a raw
//! `path.display()` and, for the reader, the path is the one carrying a
//! control-character `$HOME`). Callers may format the returned error freely:
//! its `Display` and its debug chain are the same safe text.

use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use rustix::fs::{FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};

use crate::boot_image::ImmutableImageRef;
use crate::config;
use crate::host_paths;

/// The record's file name inside the user config directory. A sibling lock file
/// keeps the write-once check and the save from interleaving.
const SELECTION_FILE: &str = "default-image.json";
const LOCK_FILE: &str = "default-image.lock";

/// One OCI reference plus a schema tag fits in a few hundred bytes; 16 KiB is
/// bounded and generous, so an oversized file is refused before it is parsed.
const MAX_SELECTION_FILE_BYTES: u64 = 16 * 1024;

const SELECTION_FILE_MODE: u32 = 0o600;
const SELECTION_VERSION: u32 = 1;

/// The on-disk schema. `deny_unknown_fields` plus serde's duplicate/missing
/// field rejection means an unknown schema is an error, never a lenient read:
/// a record written by a future launcher must not be silently reinterpreted.
/// No launcher version, timestamp, tool name or platform guess is stored —
/// those would make the record a cache index rather than a bookmark.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionFile {
    version: u32,
    image: String,
}

/// The user config directory and the two files the record uses. A named value
/// (rather than ambient `$HOME` reads at each call) keeps path construction in
/// one place and lets tests exercise the same code against a temp directory.
struct SelectionPaths {
    directory: PathBuf,
}

impl SelectionPaths {
    fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn record(&self) -> PathBuf {
        self.directory.join(SELECTION_FILE)
    }

    fn lock(&self) -> PathBuf {
        self.directory.join(LOCK_FILE)
    }
}

/// `$HOME/.config/agent-vm`, through the shared `$HOME` discipline. Deliberately
/// ignores `XDG_CONFIG_HOME`, matching the user config and credential inventory.
fn selection_paths() -> Result<SelectionPaths> {
    let home = match config::host_home_dir() {
        Ok(Some(home)) => home,
        Ok(None) => {
            return Err(anyhow!(
                "$HOME is not set; cannot locate {}",
                config::quoted_str(config::USER_CONFIG_DIR_RELATIVE)
            ));
        }
        Err(error) => {
            return Err(anyhow!(
                "{error}; cannot locate {}",
                config::quoted_str(config::USER_CONFIG_DIR_RELATIVE)
            ));
        }
    };
    Ok(SelectionPaths::new(
        home.join(config::USER_CONFIG_DIR_RELATIVE),
    ))
}

/// The resolved record path, for diagnostics that must name where the retained
/// selection lives.
pub(super) fn record_path() -> Result<PathBuf> {
    Ok(selection_paths()?.record())
}

/// The retained default, or `None` when no record exists yet.
///
/// Only a *missing* file is `None`. A record that exists but cannot be read,
/// parsed or validated is an error: auto-resetting it would silently discard
/// the user's choice (and, on a shared host, could pick a different image than
/// a concurrent session).
pub(super) fn load() -> Result<Option<ImmutableImageRef>> {
    load_from(&selection_paths()?)
}

/// The image this launcher offers when no record exists. Not persisted here;
/// [`adopt`] records it only after the content is acquired.
pub(super) fn initial_recommendation() -> Result<ImmutableImageRef> {
    #[cfg(debug_assertions)]
    if let Some(raw) = std::env::var_os("AGENT_VM_TEST_DEFAULT_IMAGE") {
        // A boot-free CLI test that falls through to the default would
        // otherwise start a real multi-GB pull, so the seam exists — but it is
        // an *initial recommendation*, not an override of a saved record, and
        // it is held to the same immutable-reference rule as production. A
        // non-Unicode or unpinned value fails; it is never lossily converted or
        // silently replaced by the production recommendation. The value is
        // never echoed: the seam may itself be sensitive.
        let raw = raw.to_str().ok_or_else(|| {
            anyhow!("AGENT_VM_TEST_DEFAULT_IMAGE is set but is not valid Unicode")
        })?;
        return ImmutableImageRef::parse(raw).map_err(|reason| {
            anyhow!(
                "AGENT_VM_TEST_DEFAULT_IMAGE is not usable as an initial recommendation: {reason}"
            )
        });
    }
    ImmutableImageRef::parse(crate::defaults::INITIAL_DEFAULT_IMAGE_REF)
        .map_err(|reason| anyhow!("the compiled-in initial recommendation is unusable: {reason}"))
}

/// Retain `reference` as the user's default. Write-once: a valid record that
/// already exists is left byte-for-byte untouched, so a second concurrent
/// adopter (or a launcher whose recommendation changed) cannot overwrite it.
pub(super) fn adopt(reference: &ImmutableImageRef) -> Result<()> {
    adopt_to(&selection_paths()?, reference)
}

fn adopt_to(paths: &SelectionPaths, reference: &ImmutableImageRef) -> Result<()> {
    adopt_to_with_checkpoint(paths, reference, || {}).map(|_wrote| ())
}

/// [`adopt_to`] with a test-only checkpoint between the under-lock recheck and
/// the save. The checkpoint holds the exclusive lock, so it is the deterministic
/// point at which a competing adopter must be blocked by `flock`; it exists so
/// the concurrency test can tell `flock` from its absence without a sleep, a
/// process-wide pause env, or a timing assumption.
fn adopt_to_with_checkpoint(
    paths: &SelectionPaths,
    reference: &ImmutableImageRef,
    after_recheck: impl FnOnce(),
) -> Result<bool> {
    // Fast path: a valid record already exists, so do no work — not even a
    // directory or lock. A damaged record still fails closed here.
    if load_from(paths)?.is_some() {
        return Ok(false);
    }
    std::fs::create_dir_all(&paths.directory)
        .map_err(|_| selection_error(&paths.directory, "could not be created"))?;
    let lock = open_lock(&paths.lock())?;
    host_paths::flock_exclusive(&lock)
        .map_err(|_| selection_error(&paths.lock(), "could not be locked"))?;
    // First writer wins, even a different reference: the peer that wrote while
    // this process waited for the lock is the retained default.
    if load_from(paths)?.is_some() {
        return Ok(false);
    }
    after_recheck();
    let bytes = serialize_v1(reference)
        .map_err(|_| selection_error(&paths.record(), "could not be encoded for saving"))?;
    host_paths::atomic_write(&paths.record(), &bytes, SELECTION_FILE_MODE)
        .map_err(|_| selection_error(&paths.record(), "could not be saved"))?;
    Ok(true)
}

/// Open (creating if needed) the sibling lock file as a regular file, refusing
/// to follow a final-component symlink. `O_NOFOLLOW` turns the symlink into an
/// error rather than a stat-then-open race. Every failure is a fixed reason
/// naming only the escaped lock path.
fn open_lock(path: &Path) -> Result<File> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| selection_error(path, "could not be opened for locking"))?;
    let stat =
        rustix::fs::fstat(&fd).map_err(|_| selection_error(path, "could not be examined"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(selection_error(path, "is not a regular file"));
    }
    Ok(File::from(fd))
}

fn load_from(paths: &SelectionPaths) -> Result<Option<ImmutableImageRef>> {
    load_from_with_checkpoint(paths, || {})
}

/// [`load_from`] with a test-only checkpoint between the stat-first validation
/// and the bounded read. The checkpoint deterministically reproduces the
/// stat-then-open race a concurrent symlink swap creates, without a sleep.
fn load_from_with_checkpoint(
    paths: &SelectionPaths,
    after_stat: impl FnOnce(),
) -> Result<Option<ImmutableImageRef>> {
    let path = paths.record();
    // Stat first so "absent" is a fact, not an inference from a failed open,
    // and so a symlink/FIFO/directory/oversize file gets a reason rather than a
    // generic read error.
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(selection_error(&path, "could not be examined")),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(selection_error(&path, "is a symbolic link"));
            }
            if !metadata.file_type().is_file() {
                return Err(selection_error(&path, "is not a regular file"));
            }
            if metadata.len() > MAX_SELECTION_FILE_BYTES {
                return Err(selection_error(
                    &path,
                    &format!("is larger than {MAX_SELECTION_FILE_BYTES} bytes"),
                ));
            }
        }
    }
    after_stat();
    // The reader's own error text embeds the path (and its chain embeds it
    // again, raw), so it is discarded in favour of one fixed reason. The race
    // here is exactly how a symlink swap can otherwise leak a control-character
    // `$HOME` into the diagnostic.
    let (bytes, _facts) =
        host_paths::read_bounded_regular_file_no_follow(&path, MAX_SELECTION_FILE_BYTES)
            .map_err(|_| selection_error(&path, "could not be read"))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| selection_error(&path, "is not valid UTF-8"))?;
    // serde's error Display is value-bearing for a wrong JSON type, so it is
    // never formatted into the diagnostic.
    let file: SelectionFile = serde_json::from_str(text)
        .map_err(|_| selection_error(&path, "is not the expected JSON schema"))?;
    if file.version != SELECTION_VERSION {
        return Err(selection_error(
            &path,
            &format!("has an unsupported version, expected {SELECTION_VERSION}"),
        ));
    }
    ImmutableImageRef::parse(&file.image)
        .map(Some)
        .map_err(|reason| selection_error(&path, reason))
}

fn serialize_v1(reference: &ImmutableImageRef) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&SelectionFile {
        version: SELECTION_VERSION,
        image: reference.as_str().to_string(),
    })
    .map_err(|_| anyhow!("serializing the retained default failed"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// The one diagnostic shape for record, lock and save failures: the escaped
/// path, a fixed reason, and the same two recovery options. Recovery is
/// deliberately manual: silently deleting or repairing the record would erase a
/// choice the user made. `reason` is always a fixed literal (or a fixed literal
/// with a compile-time constant); it never carries a source error or a value
/// read from the record.
fn selection_error(path: &Path, reason: &str) -> anyhow::Error {
    anyhow!(
        "boot-image selection {} {reason}; restore the intended digest record from backup, or \
         deliberately move it aside to reinitialize from the current recommendation",
        config::escape_path(path)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str =
        "localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str =
        "localhost:1/b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str =
        "localhost:1/c@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    fn temp_paths() -> (tempfile::TempDir, SelectionPaths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = SelectionPaths::new(dir.path().to_path_buf());
        (dir, paths)
    }

    fn parsed(reference: &str) -> ImmutableImageRef {
        ImmutableImageRef::parse(reference).unwrap()
    }

    /// No diagnostic may carry an unsafe source chain: `{error:#}` must equal
    /// the top-level `{error}` (there is no source), and the raw path bytes must
    /// not appear (only the escaped form).
    fn assert_safe(error: &anyhow::Error, path: &Path) {
        let display = format!("{error}");
        assert_eq!(
            format!("{error:#}"),
            display,
            "the diagnostic must not chain a source error"
        );
        let raw = path.display().to_string();
        if raw != config::escape_path(path) {
            assert!(
                !display.contains(&raw),
                "the diagnostic leaked the raw path: {display}"
            );
        }
    }

    #[test]
    fn absent_record_is_none_and_creates_nothing() {
        let (_dir, paths) = temp_paths();
        assert!(load_from(&paths).unwrap().is_none());
        assert!(!paths.record().exists());
        assert!(!paths.lock().exists());
    }

    #[test]
    fn adopt_round_trips_and_writes_a_complete_v1_record() {
        let (_dir, paths) = temp_paths();
        adopt_to(&paths, &parsed(A)).unwrap();
        assert_eq!(load_from(&paths).unwrap().unwrap().as_str(), A);
        let bytes = std::fs::read(paths.record()).unwrap();
        assert_eq!(
            serde_json::from_slice::<SelectionFile>(&bytes)
                .unwrap()
                .version,
            1
        );
        assert!(bytes.ends_with(b"\n"));
    }

    /// A retained record is immutable: a different recommendation must never
    /// overwrite it, whether the peer adopts before, after or concurrently.
    #[test]
    fn adopt_is_first_writer_wins() {
        let (_dir, paths) = temp_paths();
        adopt_to(&paths, &parsed(A)).unwrap();
        let before = std::fs::read(paths.record()).unwrap();
        adopt_to(&paths, &parsed(B)).unwrap();
        assert_eq!(std::fs::read(paths.record()).unwrap(), before);
        assert_eq!(load_from(&paths).unwrap().unwrap().as_str(), A);
    }

    /// An existing valid record is a no-op *before* any directory/lock work:
    /// with the record stored read-only (and with no writable config directory
    /// needed), adoption must still succeed and must not create the lock.
    #[test]
    fn adopt_with_an_existing_record_does_no_work() {
        let (dir, paths) = temp_paths();
        std::fs::create_dir_all(&paths.directory).unwrap();
        std::fs::write(
            paths.record(),
            format!("{{\"version\":1,\"image\":\"{A}\"}}\n"),
        )
        .unwrap();
        std::fs::remove_file(paths.lock()).ok();
        adopt_to(&paths, &parsed(B)).unwrap();
        assert!(
            !paths.lock().exists(),
            "an existing valid record must not require or create the lock"
        );
        assert_eq!(load_from(&paths).unwrap().unwrap().as_str(), A);
        drop(dir);
    }

    /// Deterministic proof that the adopter holds the exclusive `flock` across
    /// the under-lock recheck: thread A pauses at the checkpoint (inside the
    /// critical section); an **independently opened descriptor** on the same
    /// lock file must fail a non-blocking exclusive lock with `WOULDBLOCK`.
    /// Removing `flock` makes the probe succeed, so the test fails without any
    /// timing window. A always releases in bounded time.
    #[test]
    fn adopt_holds_the_exclusive_lock_across_the_recheck() {
        use std::sync::mpsc;

        let (_dir, paths) = temp_paths();
        let paths = std::sync::Arc::new(paths);
        let (at_checkpoint_tx, at_checkpoint_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let a = {
            let paths = std::sync::Arc::clone(&paths);
            std::thread::spawn(move || {
                adopt_to_with_checkpoint(&paths, &parsed(A), || {
                    at_checkpoint_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
            })
        };
        at_checkpoint_rx.recv().unwrap();

        // The independent descriptor must not be able to take the lock A holds.
        let probe = std::fs::File::open(paths.lock()).unwrap();
        let probe_result =
            rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive);
        // Always release A before asserting/joining, so a failing assertion
        // cannot leave the helper thread blocked.
        release_tx.send(()).unwrap();
        let a_wrote = a.join().unwrap().unwrap();

        assert_eq!(
            probe_result,
            Err(rustix::io::Errno::WOULDBLOCK),
            "the adopter held no exclusive lock across the recheck"
        );
        assert!(a_wrote, "the first writer must save");
        assert_eq!(load_from(&paths).unwrap().unwrap().as_str(), A);
    }

    /// The under-lock recheck's first-writer property: concurrent first adopters
    /// serialize on the lock, so exactly one of them saves and the surviving
    /// record is that writer's. (Missing-`flock` discrimination is the job of
    /// `adopt_holds_the_exclusive_lock_across_the_recheck`, which has no timing
    /// assumption.)
    #[test]
    fn concurrent_first_adoption_keeps_exactly_one_record() {
        use std::sync::{Arc, Barrier};

        let (_dir, paths) = temp_paths();
        let paths = Arc::new(paths);
        let start = Arc::new(Barrier::new(3));
        let handles: Vec<_> = [A, B, C]
            .into_iter()
            .map(|reference| {
                let paths = Arc::clone(&paths);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    adopt_to_with_checkpoint(&paths, &parsed(reference), || {})
                })
            })
            .collect();
        let writes: Vec<bool> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect();
        assert_eq!(
            writes.iter().filter(|wrote| **wrote).count(),
            1,
            "exactly one adopter must save: {writes:?}"
        );
        let retained = load_from(&paths)
            .unwrap()
            .expect("exactly one adopter must have written");
        assert!(
            [A, B, C].contains(&retained.as_str()),
            "the surviving record must be the writer's: {}",
            retained.as_str()
        );
    }

    /// Every rejection is a hard error, and the original bytes are untouched.
    #[test]
    fn invalid_records_fail_closed_without_repair() {
        let cases: [(&str, &str); 11] = [
            ("", "empty"),
            ("not json", "not JSON"),
            ("[]", "wrong top-level type"),
            ("{}", "missing fields"),
            (
                r#"{"version":2,"image":"localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
                "unknown version",
            ),
            (
                r#"{"version":1,"image":"localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":1}"#,
                "unknown field",
            ),
            (
                r#"{"version":"1","image":"localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
                "wrong field type",
            ),
            (
                r#"{"version":1,"image":"localhost:1/a@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","image":"localhost:1/b@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
                "duplicate field",
            ),
            (
                r#"{"version":1,"image":"localhost:1/a:latest"}"#,
                "tag only",
            ),
            (r#"{"version":1,"image":"/rootfs"}"#, "local path"),
            (
                r#"{"version":1,"image":"localhost:1/a@sha256:00ff"}"#,
                "short digest",
            ),
        ];
        for (contents, label) in cases {
            let (_dir, paths) = temp_paths();
            std::fs::write(paths.record(), contents).unwrap();
            let error = load_from(&paths).expect_err(label);
            assert!(
                !format!("{error:#}").contains(contents) || contents.is_empty(),
                "{label}: the diagnostic echoed the record bytes"
            );
            assert_safe(&error, &paths.record());
            assert_eq!(std::fs::read(paths.record()).unwrap(), contents.as_bytes());
        }
    }

    #[test]
    fn non_utf8_short_digest_and_oversize_are_rejected() {
        let (_dir, paths) = temp_paths();
        std::fs::write(paths.record(), b"\xff\xfe").unwrap();
        assert!(load_from(&paths).is_err());

        let (_dir, paths) = temp_paths();
        std::fs::write(
            paths.record(),
            r#"{"version":1,"image":"localhost:1/a@sha256:00ff"}"#,
        )
        .unwrap();
        assert!(load_from(&paths).is_err());

        let (_dir, paths) = temp_paths();
        std::fs::write(
            paths.record(),
            vec![b' '; MAX_SELECTION_FILE_BYTES as usize + 1],
        )
        .unwrap();
        assert!(load_from(&paths).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_directory_records_are_rejected() {
        let (dir, paths) = temp_paths();
        let target = dir.path().join("target.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, paths.record()).unwrap();
        assert!(load_from(&paths).is_err());

        let (dir, paths) = temp_paths();
        std::fs::create_dir(paths.record()).unwrap();
        assert!(load_from(&paths).is_err());
        drop(dir);
    }

    /// A valid, hand-formatted record must not be rewritten just to normalize
    /// it: formatting is the user's, not the launcher's.
    #[test]
    fn a_valid_record_is_never_rewritten_by_adoption() {
        let (_dir, paths) = temp_paths();
        let hand = format!("{{ \"version\" : 1 , \"image\" : \"{A}\" }}\n");
        std::fs::write(paths.record(), &hand).unwrap();
        adopt_to(&paths, &parsed(B)).unwrap();
        assert_eq!(std::fs::read_to_string(paths.record()).unwrap(), hand);
    }

    /// A save that fails after the under-lock recheck (the record path becomes a
    /// directory between the check and the rename) must fail loudly with a safe
    /// reason, not pretend to retain and not leak the raw path or a source chain.
    #[test]
    fn adoption_save_failure_is_a_safe_fixed_reason() {
        let (_dir, paths) = temp_paths();
        let record = paths.record();
        let error = adopt_to_with_checkpoint(&paths, &parsed(A), || {
            std::fs::create_dir(&record).unwrap();
        })
        .expect_err("a save that cannot replace the record must fail");
        let message = format!("{error}");
        assert!(
            message.contains("could not be saved"),
            "the reason must be fixed and closed: {message}"
        );
        assert_safe(&error, &record);
    }

    /// A control-character `$HOME` (hence record path) must never reach the
    /// diagnostic raw. The record is a symlink here, exercising the stat-first
    /// branch; the ESC in the path must be escaped.
    #[cfg(unix)]
    #[test]
    fn a_control_character_path_is_escaped_not_raw() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home-\u{1b}[31m");
        let paths = SelectionPaths::new(home.join(".config/agent-vm"));
        std::fs::create_dir_all(&paths.directory).unwrap();
        let target = dir.path().join("target.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, paths.record()).unwrap();

        let error = load_from(&paths).expect_err("a symlink record must fail");
        let display = format!("{error}");
        assert!(
            !display.contains('\u{1b}'),
            "the raw ESC reached the diagnostic: {display:?}"
        );
        assert!(
            display.contains("\\x1b"),
            "the path must be escaped, not dropped: {display:?}"
        );
        assert_safe(&error, &paths.record());
    }

    /// A symlink swapped in *after* the stat-first validation reaches the
    /// no-follow reader, whose `ELOOP` guard embeds `path.display()` raw. With a
    /// control-character `$HOME`, that must still be a fixed reason — never the
    /// raw ESC of the record path or a source chain.
    #[cfg(unix)]
    #[test]
    fn a_symlink_swapped_after_the_stat_is_a_safe_fixed_reason() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home-\u{1b}[31m");
        let paths = SelectionPaths::new(home.join(".config/agent-vm"));
        std::fs::create_dir_all(&paths.directory).unwrap();
        std::fs::write(paths.record(), "{}").unwrap();
        let target = dir.path().join("target.json");
        std::fs::write(&target, "{}").unwrap();

        let error = load_from_with_checkpoint(&paths, || {
            std::fs::remove_file(paths.record()).unwrap();
            std::os::unix::fs::symlink(&target, paths.record()).unwrap();
        })
        .expect_err("a symlink swapped in after the stat must be refused");
        let display = format!("{error}");
        assert!(
            !display.contains('\u{1b}'),
            "the raw ESC reached the diagnostic: {display:?}"
        );
        assert!(
            display.contains("could not be read"),
            "the reason must be fixed: {display:?}"
        );
        assert_safe(&error, &paths.record());
    }

    #[test]
    fn a_final_component_symlink_lock_is_refused() {
        let (dir, paths) = temp_paths();
        std::fs::create_dir_all(&paths.directory).unwrap();
        let elsewhere = dir.path().join("elsewhere.lock");
        std::fs::write(&elsewhere, b"").unwrap();
        std::os::unix::fs::symlink(&elsewhere, paths.lock()).unwrap();
        let error = open_lock(&paths.lock()).expect_err("a symlink lock must be refused");
        assert_safe(&error, &paths.lock());
    }
}
