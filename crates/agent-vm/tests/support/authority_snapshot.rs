//! ADR-0065 §8.3's snapshot: everything a read path must leave exactly as it
//! was.
//!
//! One rendering per entry — name, type, inode, mode, size, mtime, and either
//! the bytes (regular files) or the target text (symlinks, read without
//! following) — so two snapshots compare with `assert_eq!` and a mismatch prints
//! both sides. A FIFO or a socket is recorded by type and inode only and is never
//! opened, because opening one is exactly the mutation a wrong reader would
//! perform.
//!
//! The guarantee is only as good as *when* it is taken: before the operation,
//! never around a fixture the test just wrote.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
};

pub type Snapshot = BTreeMap<OsString, String>;

/// Snapshot `dir` and every entry in it. The directory itself is recorded under
/// the empty name, so a chmod or a replacement of the directory is caught too.
pub fn take(dir: &Path) -> Snapshot {
    let mut snapshot = Snapshot::new();
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) => {
            snapshot.insert(OsString::new(), render(&metadata, None));
        }
        Err(error) => {
            snapshot.insert(OsString::new(), format!("unstatable: {:?}", error.kind()));
            return snapshot;
        }
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            snapshot.insert(
                OsString::from("<unreadable>"),
                format!("{:?}", error.kind()),
            );
            return snapshot;
        }
    };
    for entry in entries {
        let entry = entry.expect("a directory entry");
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).expect("lstat");
        // Only a symlink has a target to record; a regular file's *bytes* are
        // appended below, and everything else is recorded by its facts alone.
        let content = metadata
            .file_type()
            .is_symlink()
            .then(|| std::fs::read_link(&path).expect("readlink"));
        let rendered = render(&metadata, content.as_deref());
        // Only a regular file is ever opened, and its bytes are part of the
        // evidence: a rewritten file with the same size must still differ.
        let rendered = if metadata.file_type().is_file() {
            match std::fs::read(&path) {
                Ok(bytes) => format!("{rendered} bytes={bytes:02x?}"),
                Err(error) => format!("{rendered} unreadable={:?}", error.kind()),
            }
        } else {
            rendered
        };
        snapshot.insert(entry.file_name(), rendered);
    }
    snapshot
}

fn render(metadata: &std::fs::Metadata, target: Option<&Path>) -> String {
    let kind = metadata.file_type();
    let kind = if kind.is_dir() {
        "dir"
    } else if kind.is_file() {
        "file"
    } else if kind.is_symlink() {
        "symlink"
    } else if kind.is_fifo() {
        "fifo"
    } else if kind.is_socket() {
        "socket"
    } else {
        "other"
    };
    let target = target
        .map(|target| {
            format!(
                " -> {}",
                String::from_utf8_lossy(target.as_os_str().as_bytes())
            )
        })
        .unwrap_or_default();
    format!(
        "{kind} ino={} mode={:04o} size={} mtime={}.{}{target}",
        metadata.ino(),
        metadata.permissions().mode() & 0o7777,
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

/// A directory that holds nothing yet: the shape `$HOME/.config/agent-vm` has on
/// a host that has never recorded an allowance.
pub fn empty_authority_dir(home: &Path) -> PathBuf {
    let dir = home.join(".config/agent-vm");
    std::fs::create_dir_all(&dir).unwrap();
    for path in [dir.parent().unwrap(), dir.as_path()] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}
