//! Host and descriptor-relative guest-state path helpers.

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{Read, Write},
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use rustix::{
    fs::{self as rfs, AtFlags, FileType, Mode, OFlags},
    io::{self as rio, Errno},
};

pub(crate) const MAX_GUEST_STATE_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_HOST_CREDENTIAL_FILE_BYTES: u64 = 1024 * 1024;
const ATOMIC_WRITE_RETRIES: usize = 16;

/// `$AGENT_VM_STATE_DIR` → `$XDG_STATE_HOME/agent-vm` → `$HOME/.local/state/agent-vm`.
pub fn state_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("AGENT_VM_STATE_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
        return Some(PathBuf::from(dir).join("agent-vm"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/state/agent-vm"))
}

pub fn host_claude_creds_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("HOME")?).join(".claude/.credentials.json"))
}

pub fn host_codex_auth_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("HOME")?).join(".codex/auth.json"))
}

pub fn host_opencode_auth_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("HOME")?).join(".local/share/opencode/auth.json"))
}

pub fn host_copilot_token_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("HOME")?).join(".cache/claude-vm/copilot-token.json"))
}

/// Reads a regular host credential file without allowing a FIFO or oversized
/// file to consume a launcher or validated interception request.
pub(crate) fn read_bounded_regular_file(path: &Path, max: u64) -> Result<Vec<u8>> {
    let fd = rfs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {}", path.display()))?;
    read_regular_fd(fd, max, path.display().to_string())
}

/// Writes trusted-host files atomically. The initial parent open intentionally
/// follows trusted-host symlinks; guest-relative no-follow rules belong to
/// `GuestStateDir` only.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?;
    let parent_fd = rfs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening parent {}", parent.display()))?;
    atomic_write_at(&parent_fd, name, data, mode, path.display().to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreateOutcome {
    Created,
    AlreadyExists,
}

pub(crate) struct GuestStateDir {
    root: OwnedFd,
    display_root: PathBuf,
}

impl GuestStateDir {
    pub(crate) fn open(root: &Path) -> Result<Self> {
        let fd = rfs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening guest state root {}", root.display()))?;
        Ok(Self {
            root: fd,
            display_root: root.to_path_buf(),
        })
    }

    pub(crate) fn read(&self, relative: &Path) -> Result<Option<Vec<u8>>> {
        self.read_with_checkpoints(relative, || {}, || {})
    }

    /// `after_parent_open` fires once the parent directory descriptor is
    /// held (before the final component is opened); `after_final_open`
    /// fires once the final entry has been opened, `fstat`-validated as
    /// a regular file within the size limit, but before its bytes are
    /// read. [`Self::read`] passes no-ops for both; tests use this
    /// directly to prove operations stay anchored to the originally
    /// opened descriptors even if a guest-controlled entry is swapped
    /// out from under the path in between.
    pub(crate) fn read_with_checkpoints(
        &self,
        relative: &Path,
        after_parent_open: impl FnOnce(),
        after_final_open: impl FnOnce(),
    ) -> Result<Option<Vec<u8>>> {
        let parts = validated_components(relative)?;
        let Some((parent, name)) = self.parent_for(&parts, false)? else {
            return Ok(None);
        };
        after_parent_open();
        let fd = match rfs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(anyhow!(error))
                    .with_context(|| self.operation_path("opening", relative));
            }
        };
        read_regular_fd_checkpointed(
            fd,
            MAX_GUEST_STATE_FILE_BYTES,
            self.display_path(relative),
            after_final_open,
        )
        .map(Some)
    }

    /// Test-only seam mirroring [`Self::read_with_checkpoints`] for the
    /// write path: `after_parent_open` fires once the parent directory
    /// descriptor is held (and any missing directories created), before
    /// the atomic replace of `relative` begins.
    #[cfg(test)]
    pub(crate) fn atomic_write_with_checkpoint(
        &self,
        relative: &Path,
        data: &[u8],
        mode: u32,
        after_parent_open: impl FnOnce(),
    ) -> Result<()> {
        let parts = validated_components(relative)?;
        let (parent, name) = self
            .parent_for(&parts, true)?
            .expect("writer creates missing parent directories");
        after_parent_open();
        atomic_write_at(&parent, name, data, mode, self.display_path(relative))
    }

    pub(crate) fn create(&self, relative: &Path, data: &[u8], mode: u32) -> Result<CreateOutcome> {
        let parts = validated_components(relative)?;
        let (parent, name) = self
            .parent_for(&parts, true)?
            .expect("writer creates missing parent directories");
        let fd = match rfs::openat(
            &parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            unix_mode(mode),
        ) {
            Ok(fd) => fd,
            Err(Errno::EXIST) => return Ok(CreateOutcome::AlreadyExists),
            Err(error) => {
                return Err(anyhow!(error))
                    .with_context(|| self.operation_path("creating", relative));
            }
        };
        let result = write_and_chmod(fd, data, mode, self.display_path(relative));
        if result.is_err() {
            let _ = rfs::unlinkat(&parent, name, AtFlags::empty());
        }
        result.map(|()| CreateOutcome::Created)
    }

    pub(crate) fn atomic_write(&self, relative: &Path, data: &[u8], mode: u32) -> Result<()> {
        let parts = validated_components(relative)?;
        let (parent, name) = self
            .parent_for(&parts, true)?
            .expect("writer creates missing parent directories");
        atomic_write_at(&parent, name, data, mode, self.display_path(relative))
    }

    pub(crate) fn remove_file(&self, relative: &Path) -> Result<bool> {
        let parts = validated_components(relative)?;
        let Some((parent, name)) = self.parent_for(&parts, false)? else {
            return Ok(false);
        };
        match rfs::unlinkat(&parent, name, AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => {
                Err(anyhow!(error)).with_context(|| self.operation_path("removing", relative))
            }
        }
    }

    pub(crate) fn remove_empty_dir(&self, relative: &Path) -> Result<bool> {
        let parts = validated_components(relative)?;
        let Some((parent, name)) = self.parent_for(&parts, false)? else {
            return Ok(false);
        };
        match rfs::unlinkat(&parent, name, AtFlags::REMOVEDIR) {
            Ok(()) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(anyhow!(error))
                .with_context(|| self.operation_path("removing directory", relative)),
        }
    }

    fn parent_for<'a>(
        &self,
        parts: &'a [OsString],
        create: bool,
    ) -> Result<Option<(OwnedFd, &'a OsStr)>> {
        let final_name = parts.last().expect("validated path has a final component");
        let mut parent = rio::dup(&self.root).context("duplicating guest state root")?;
        for component in &parts[..parts.len() - 1] {
            parent = match rfs::openat(
                &parent,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(next) => next,
                Err(Errno::NOENT) if create => {
                    match rfs::mkdirat(&parent, component, Mode::from_raw_mode(0o700)) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(error) => {
                            return Err(anyhow!(error)).with_context(|| {
                                self.operation_path("creating directory", Path::new(component))
                            });
                        }
                    }
                    rfs::openat(
                        &parent,
                        component,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|error| anyhow!(error))
                    .with_context(|| {
                        self.operation_path("opening directory", Path::new(component))
                    })?
                }
                Err(Errno::NOENT) => return Ok(None),
                Err(error) => {
                    return Err(anyhow!(error)).with_context(|| {
                        self.operation_path("opening directory", Path::new(component))
                    });
                }
            };
        }
        Ok(Some((parent, final_name)))
    }

    fn display_path(&self, relative: &Path) -> String {
        self.display_root.join(relative).display().to_string()
    }

    fn operation_path(&self, operation: &str, relative: &Path) -> String {
        format!("{operation} guest state {}", self.display_path(relative))
    }
}

fn validated_components(relative: &Path) -> Result<Vec<OsString>> {
    if relative.as_os_str().is_empty() {
        return Err(anyhow!("guest state path is empty"));
    }
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(anyhow!(
                "guest state path must contain only normal relative components"
            ));
        };
        if name.as_bytes().contains(&0) {
            return Err(anyhow!("guest state path contains NUL"));
        }
        parts.push(name.to_os_string());
    }
    if parts.is_empty() {
        return Err(anyhow!("guest state path is empty"));
    }
    Ok(parts)
}

fn read_regular_fd(fd: OwnedFd, max: u64, display: String) -> Result<Vec<u8>> {
    read_regular_fd_checkpointed(fd, max, display, || {})
}

/// `after_fstat` fires after the opened descriptor has been validated
/// (regular file, within `max`) but before its bytes are read — the
/// exact TOCTOU-relevant window a guest-controlled path could try to
/// exploit if these operations were not descriptor-anchored. Only
/// [`GuestStateDir::read_with_checkpoints`] passes a non-trivial
/// closure; every other caller behaves exactly as before.
fn read_regular_fd_checkpointed(
    fd: OwnedFd,
    max: u64,
    display: String,
    after_fstat: impl FnOnce(),
) -> Result<Vec<u8>> {
    let stat = rfs::fstat(&fd)
        .map_err(|error| anyhow!(error))
        .with_context(|| format!("stating {display}"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(anyhow!("{display} is not a regular file"));
    }
    if stat.st_size < 0 || stat.st_size as u64 > max {
        return Err(anyhow!("{display} exceeds its size limit"));
    }
    after_fstat();
    let mut data = Vec::with_capacity((stat.st_size as u64).min(max) as usize);
    let file = fs::File::from(fd);
    file.take(max + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("reading {display}"))?;
    if data.len() as u64 > max {
        return Err(anyhow!("{display} exceeds its size limit"));
    }
    Ok(data)
}

fn unix_mode(mode: u32) -> Mode {
    Mode::from_raw_mode((mode & 0o7777) as _)
}

fn write_and_chmod(fd: OwnedFd, data: &[u8], mode: u32, display: String) -> Result<()> {
    let mut file = fs::File::from(fd);
    file.write_all(data)
        .with_context(|| format!("writing {display}"))?;
    rfs::fchmod(&file, unix_mode(mode))
        .map_err(|error| anyhow!(error))
        .with_context(|| format!("chmodding {display}"))?;
    file.flush().with_context(|| format!("flushing {display}"))
}

struct TempEntry<'a> {
    parent: BorrowedFd<'a>,
    name: OsString,
    armed: bool,
}

impl Drop for TempEntry<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = rfs::unlinkat(self.parent, &self.name, AtFlags::empty());
        }
    }
}

fn atomic_write_at(
    parent: &OwnedFd,
    final_name: &OsStr,
    data: &[u8],
    mode: u32,
    display: String,
) -> Result<()> {
    atomic_write_with_random(parent, final_name, data, mode, display, random_temp_name)
}

/// Fault points production never fails at, injected between the
/// exclusively-created temporary's write/chmod/rename steps. Each
/// closure returning `Err` simulates that operation failing; production
/// always passes [`WriteFaults::none`] (three calls that inline to
/// nothing), so this exists purely so `host_paths.rs` tests can prove
/// [`TempEntry`]'s `Drop` cleans up the temporary at every stage, per
/// the plan's "private operations adapter ... fault injection only
/// inside host_paths.rs tests" seam. Bundled into one struct (rather
/// than three more function parameters) to stay under the arity lint.
struct WriteFaults<W, C, R>
where
    W: FnMut() -> Result<()>,
    C: FnMut() -> Result<()>,
    R: FnMut() -> Result<()>,
{
    before_write: W,
    before_chmod: C,
    before_rename: R,
}

impl WriteFaults<fn() -> Result<()>, fn() -> Result<()>, fn() -> Result<()>> {
    fn none() -> Self {
        Self {
            before_write: || Ok(()),
            before_chmod: || Ok(()),
            before_rename: || Ok(()),
        }
    }
}

fn atomic_write_with_random(
    parent: &OwnedFd,
    final_name: &OsStr,
    data: &[u8],
    mode: u32,
    display: String,
    random_name: impl FnMut() -> Result<OsString>,
) -> Result<()> {
    atomic_write_with_random_and_faults(
        parent,
        final_name,
        data,
        mode,
        display,
        random_name,
        WriteFaults::none(),
    )
}

/// Same replacement algorithm as [`atomic_write_with_random`], with the
/// [`WriteFaults`] injection points described there.
fn atomic_write_with_random_and_faults<W, C, R>(
    parent: &OwnedFd,
    final_name: &OsStr,
    data: &[u8],
    mode: u32,
    display: String,
    mut random_name: impl FnMut() -> Result<OsString>,
    mut faults: WriteFaults<W, C, R>,
) -> Result<()>
where
    W: FnMut() -> Result<()>,
    C: FnMut() -> Result<()>,
    R: FnMut() -> Result<()>,
{
    for _ in 0..ATOMIC_WRITE_RETRIES {
        let temp_name = random_name()?;
        let fd = match rfs::openat(
            parent,
            &temp_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            unix_mode(mode),
        ) {
            Ok(fd) => fd,
            Err(Errno::EXIST) => continue,
            Err(error) => {
                return Err(anyhow!(error))
                    .with_context(|| format!("creating temporary file for {display}"));
            }
        };
        let mut cleanup = TempEntry {
            parent: parent.as_fd(),
            name: temp_name,
            armed: true,
        };
        let mut file = fs::File::from(fd);
        (faults.before_write)()?;
        file.write_all(data)
            .with_context(|| format!("writing {display}"))?;
        (faults.before_chmod)()?;
        rfs::fchmod(&file, unix_mode(mode))
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("chmodding {display}"))?;
        file.flush()
            .with_context(|| format!("flushing {display}"))?;
        (faults.before_rename)()?;
        rfs::renameat(parent, &cleanup.name, parent, final_name)
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("replacing {display}"))?;
        cleanup.armed = false;
        return Ok(());
    }
    Err(anyhow!("exhausted random temporary names for {display}"))
}

fn random_temp_name() -> Result<OsString> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).context("getting random temporary-file name")?;
    let mut name = String::from(".agent-vm-tmp-");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("writing into String cannot fail");
    }
    Ok(name.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn guest_state_dir_rejects_unsafe_relative_paths_before_effects() {
        let root = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(root.path()).unwrap();
        for path in ["", "/absolute", ".", "..", "nested/../file"] {
            assert!(
                guest
                    .atomic_write(Path::new(path), b"secret", 0o600)
                    .is_err()
            );
        }
        assert!(fs::read_dir(root.path()).unwrap().next().is_none());
    }

    #[test]
    fn guest_state_dir_treats_missing_parent_as_missing() {
        let root = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(root.path()).unwrap();
        assert_eq!(guest.read(Path::new("missing/auth.json")).unwrap(), None);
        assert!(!guest.remove_file(Path::new("missing/auth.json")).unwrap());
        assert!(!guest.remove_empty_dir(Path::new("missing/dir")).unwrap());
    }

    #[test]
    fn guest_state_dir_refuses_final_symlink_without_reading_canary() {
        let root = tempfile::tempdir().unwrap();
        let canary = root.path().join("canary");
        fs::write(&canary, b"outside").unwrap();
        std::os::unix::fs::symlink(&canary, root.path().join("auth.json")).unwrap();

        let guest = GuestStateDir::open(root.path()).unwrap();
        assert!(guest.read(Path::new("auth.json")).is_err());
        assert_eq!(fs::read(&canary).unwrap(), b"outside");
    }

    #[test]
    fn guest_state_dir_rejects_parent_links_special_files_and_oversized_files() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("canary"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("parent")).unwrap();
        let guest = GuestStateDir::open(root.path()).unwrap();
        assert!(
            guest
                .atomic_write(Path::new("parent/canary"), b"changed", 0o600)
                .is_err()
        );
        assert_eq!(fs::read(outside.path().join("canary")).unwrap(), b"outside");
        let fifo = root.path().join("fifo");
        assert_eq!(
            unsafe {
                libc::mkfifo(
                    std::ffi::CString::new(fifo.as_os_str().as_bytes())
                        .unwrap()
                        .as_ptr(),
                    0o600,
                )
            },
            0
        );
        assert!(guest.read(Path::new("fifo")).is_err());
        fs::write(
            root.path().join("large"),
            vec![0_u8; MAX_GUEST_STATE_FILE_BYTES as usize + 1],
        )
        .unwrap();
        assert!(guest.read(Path::new("large")).is_err());
    }

    #[test]
    fn host_atomic_write_uses_complete_random_replacements() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("credential");
        atomic_write(&target, b"first", 0o600).unwrap();
        let inode = fs::metadata(&target).unwrap().ino();
        atomic_write(&target, b"second", 0o600).unwrap();
        let metadata = fs::metadata(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        assert_ne!(metadata.ino(), inode);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".agent-vm-tmp-")
        }));
    }

    #[test]
    fn random_exclusive_temp_retry_never_follows_a_collision_symlink() {
        let root = tempfile::tempdir().unwrap();
        let parent = rfs::open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let canary = root.path().join("canary");
        fs::write(&canary, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&canary, root.path().join(".agent-vm-tmp-collision")).unwrap();
        let names = std::cell::RefCell::new(vec![
            OsString::from(".agent-vm-tmp-free"),
            OsString::from(".agent-vm-tmp-collision"),
        ]);
        atomic_write_with_random(
            &parent,
            OsStr::new("target"),
            b"replacement",
            0o600,
            "target".into(),
            || Ok(names.borrow_mut().pop().unwrap()),
        )
        .unwrap();
        assert_eq!(fs::read(&canary).unwrap(), b"unchanged");
        assert_eq!(
            fs::read(root.path().join("target")).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn random_name_exhaustion_leaves_no_temporary_file() {
        let root = tempfile::tempdir().unwrap();
        let parent = rfs::open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let collision = OsStr::new(".agent-vm-tmp-collision");
        fs::write(root.path().join(collision), b"occupied").unwrap();
        assert!(
            atomic_write_with_random(
                &parent,
                OsStr::new("target"),
                b"replacement",
                0o600,
                "target".into(),
                || Ok(collision.to_os_string()),
            )
            .is_err()
        );
        assert_eq!(fs::read(root.path().join(collision)).unwrap(), b"occupied");
        assert!(!root.path().join("target").exists());
    }

    #[test]
    fn read_stays_anchored_to_the_originally_opened_parent_after_it_is_renamed_away() {
        // Regression test for the architecture invariant: "if an
        // attacker swaps or renames a parent after it is opened,
        // operations stay in the directory represented by the held
        // fd." Rename the whole guest-state directory out from under
        // an already-open `GuestStateDir` and replace it with a fresh
        // directory containing a symlink at the same relative name
        // pointing at an external canary — the held root fd must keep
        // resolving inside the original (now unlinked-by-name)
        // directory, never through the new symlink.
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::write(state.join("auth.json"), b"original").unwrap();
        let guest = GuestStateDir::open(&state).unwrap();

        let moved = root.path().join("state-moved-by-attacker");
        fs::rename(&state, &moved).unwrap();
        let canary = root.path().join("canary");
        fs::write(&canary, b"outside").unwrap();
        fs::create_dir(&state).unwrap();
        std::os::unix::fs::symlink(&canary, state.join("auth.json")).unwrap();

        // Read: must still see the original content via the held fd,
        // never the new symlink's target.
        let data = guest.read(Path::new("auth.json")).unwrap().unwrap();
        assert_eq!(data, b"original");
        assert_eq!(fs::read(&canary).unwrap(), b"outside");

        // Write: must replace the entry inside the original directory
        // (now reachable only via the held fd), never through the new
        // symlink at the "current" path.
        guest
            .atomic_write(Path::new("auth.json"), b"replaced", 0o600)
            .unwrap();
        assert_eq!(fs::read(moved.join("auth.json")).unwrap(), b"replaced");
        assert_eq!(
            fs::read(&canary).unwrap(),
            b"outside",
            "write must never follow the attacker's symlink onto the canary"
        );
    }

    #[test]
    fn read_checkpoint_after_fstat_uses_only_the_already_validated_inode() {
        // Checkpoint deterministically between fstat-validation and the
        // byte read: swap the final directory entry for a symlink to an
        // external canary in that window, and prove the already-opened
        // (and already-validated-regular) descriptor is what gets read
        // — never the swapped-in symlink target.
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("auth.json"), b"original").unwrap();
        let canary = root.path().join("canary");
        fs::write(&canary, b"outside").unwrap();
        let guest = GuestStateDir::open(root.path()).unwrap();

        let target = root.path().join("auth.json");
        let data = guest
            .read_with_checkpoints(
                Path::new("auth.json"),
                || {},
                || {
                    fs::remove_file(&target).unwrap();
                    std::os::unix::fs::symlink(&canary, &target).unwrap();
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(data, b"original");
        assert_eq!(fs::read(&canary).unwrap(), b"outside");
    }

    #[test]
    fn write_checkpoint_after_parent_open_replaces_inside_original_directory() {
        // Same TOCTOU shape as the read checkpoint above, but for the
        // write path: swap the whole state directory for an
        // attacker-controlled one (containing a symlink at the same
        // relative name) in the window between the parent descriptor
        // being opened and the atomic replace beginning.
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        let guest = GuestStateDir::open(&state).unwrap();
        let moved = root.path().join("state-moved");
        let canary = root.path().join("canary");
        fs::write(&canary, b"outside").unwrap();

        guest
            .atomic_write_with_checkpoint(Path::new("auth.json"), b"replaced", 0o600, || {
                fs::rename(&state, &moved).unwrap();
                fs::create_dir(&state).unwrap();
                std::os::unix::fs::symlink(&canary, state.join("auth.json")).unwrap();
            })
            .unwrap();

        assert_eq!(fs::read(moved.join("auth.json")).unwrap(), b"replaced");
        assert_eq!(fs::read(&canary).unwrap(), b"outside");
    }

    #[test]
    fn atomic_write_fault_before_write_leaves_no_temp_and_preserves_target() {
        let root = tempfile::tempdir().unwrap();
        let parent = rfs::open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        fs::write(root.path().join("target"), b"original").unwrap();
        let names = std::cell::RefCell::new(vec![OsString::from(".agent-vm-tmp-fault")]);
        let err = atomic_write_with_random_and_faults(
            &parent,
            OsStr::new("target"),
            b"new",
            0o600,
            "target".into(),
            || Ok(names.borrow_mut().pop().unwrap()),
            WriteFaults {
                before_write: || Err(anyhow!("injected write fault")),
                before_chmod: || Ok(()),
                before_rename: || Ok(()),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("injected write fault"));
        assert_eq!(fs::read(root.path().join("target")).unwrap(), b"original");
        assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".agent-vm-tmp-")
        }));
    }

    #[test]
    fn atomic_write_fault_before_chmod_leaves_no_temp_and_preserves_target() {
        let root = tempfile::tempdir().unwrap();
        let parent = rfs::open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        fs::write(root.path().join("target"), b"original").unwrap();
        let names = std::cell::RefCell::new(vec![OsString::from(".agent-vm-tmp-fault")]);
        let err = atomic_write_with_random_and_faults(
            &parent,
            OsStr::new("target"),
            b"new",
            0o600,
            "target".into(),
            || Ok(names.borrow_mut().pop().unwrap()),
            WriteFaults {
                before_write: || Ok(()),
                before_chmod: || Err(anyhow!("injected chmod fault")),
                before_rename: || Ok(()),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("injected chmod fault"));
        assert_eq!(fs::read(root.path().join("target")).unwrap(), b"original");
        assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".agent-vm-tmp-")
        }));
    }

    #[test]
    fn atomic_write_fault_before_rename_leaves_no_temp_and_preserves_target() {
        let root = tempfile::tempdir().unwrap();
        let parent = rfs::open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        fs::write(root.path().join("target"), b"original").unwrap();
        let names = std::cell::RefCell::new(vec![OsString::from(".agent-vm-tmp-fault")]);
        let err = atomic_write_with_random_and_faults(
            &parent,
            OsStr::new("target"),
            b"new",
            0o600,
            "target".into(),
            || Ok(names.borrow_mut().pop().unwrap()),
            WriteFaults {
                before_write: || Ok(()),
                before_chmod: || Ok(()),
                before_rename: || Err(anyhow!("injected rename fault")),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("injected rename fault"));
        assert_eq!(
            fs::read(root.path().join("target")).unwrap(),
            b"original",
            "a rename fault must never leave the target replaced or truncated"
        );
        assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".agent-vm-tmp-")
        }));
    }

    #[test]
    fn concurrent_atomic_writes_never_interleave_or_leave_temp_siblings() {
        use std::sync::Arc;
        let root = tempfile::tempdir().unwrap();
        let target = Arc::new(root.path().join("credential"));
        atomic_write(&target, b"seed", 0o600).unwrap();
        const THREADS: usize = 8;
        const ITERATIONS: usize = 25;
        let handles: Vec<_> = (0..THREADS)
            .map(|thread_index| {
                let target = Arc::clone(&target);
                std::thread::spawn(move || {
                    for iteration in 0..ITERATIONS {
                        let value = format!("thread-{thread_index}-iter-{iteration}");
                        atomic_write(&target, value.as_bytes(), 0o600).unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        use std::os::unix::fs::PermissionsExt as _;
        let final_bytes = fs::read(&*target).unwrap();
        let final_value = String::from_utf8(final_bytes).unwrap();
        assert!(
            final_value == "seed"
                || final_value
                    .strip_prefix("thread-")
                    .and_then(|rest| rest.split("-iter-").next())
                    .is_some(),
            "final content must be one complete write, got {final_value:?}"
        );
        assert_eq!(
            fs::metadata(&*target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".agent-vm-tmp-")
        }));
    }

    #[test]
    fn guest_state_dir_creates_and_replaces_regular_files_with_requested_mode() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let guest = GuestStateDir::open(root.path()).unwrap();
        assert_eq!(
            guest
                .create(Path::new("nested/auth.json"), b"one", 0o600)
                .unwrap(),
            CreateOutcome::Created
        );
        let before = fs::metadata(root.path().join("nested/auth.json"))
            .unwrap()
            .ino();
        guest
            .atomic_write(Path::new("nested/auth.json"), b"two", 0o600)
            .unwrap();
        let metadata = fs::metadata(root.path().join("nested/auth.json")).unwrap();
        assert_eq!(
            fs::read(root.path().join("nested/auth.json")).unwrap(),
            b"two"
        );
        assert_ne!(metadata.ino(), before);
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }
}
