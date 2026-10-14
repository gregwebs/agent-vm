//! Verbatim runtime unpacking (ADR-0041). Only fully hashed stages are published;
//! reuse deliberately checks lengths, not hashes, to avoid per-invocation hashing.
use microsandbox_utils::{libkrunfw_filename, msb_binary_filename};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(crate) struct PayloadFile<'a> {
    pub(crate) compressed: &'a [u8],
    pub(crate) len: u64,
    pub(crate) sha256: [u8; 32],
}
pub(crate) struct Payload<'a> {
    pub(crate) msb: PayloadFile<'a>,
    pub(crate) libkrunfw: PayloadFile<'a>,
}
#[cfg(feature = "embedded-runtime")]
pub(crate) static EMBEDDED: Option<Payload<'static>> = Some(include!(concat!(
    env!("OUT_DIR"),
    "/embedded-runtime/payload.rs"
)));
#[cfg(not(feature = "embedded-runtime"))]
pub(crate) static EMBEDDED: Option<Payload<'static>> = None;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnpackedRuntime {
    pub(crate) msb: PathBuf,
    pub(crate) libkrunfw: PathBuf,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeFile {
    Msb,
    Libkrunfw,
}
impl fmt::Display for RuntimeFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Msb => f.write_str("msb"),
            Self::Libkrunfw => f.write_str(&libkrunfw_filename(std::env::consts::OS)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum UnpackError {
    Io { root: PathBuf, source: io::Error },
    Mismatch { dir: PathBuf, file: RuntimeFile },
    CorruptPayload { file: RuntimeFile },
}
impl fmt::Display for UnpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { root, source } => write!(
                f,
                "agent-vm could not unpack its embedded `msb` runtime into {}: {source}\nMake that directory writable, or set XDG_CACHE_HOME to a writable directory.",
                root.display()
            ),
            Self::Mismatch { dir, file } => {
                write!(
                    f,
                    "agent-vm could not use its unpacked runtime at {}: {file} does not match the runtime embedded in this binary.",
                    dir.display()
                )?;
                match removal_hint(dir) {
                    Some(command) => write!(f, "\nRemove that directory and retry: {command}"),
                    None => f.write_str(
                        "\nRemove that cache directory yourself (its path cannot be shown safely here) and retry.",
                    ),
                }
            }
            Self::CorruptPayload { file } => write!(
                f,
                "agent-vm could not unpack its embedded `msb` runtime: the embedded {file} does not match the digest recorded when this binary was built, so the binary is damaged.\nCopy or rebuild agent-vm again (`./script/build/macos.sh --single-binary`)."
            ),
        }
    }
}
impl std::error::Error for UnpackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
fn io_error(root: &Path, source: io::Error) -> UnpackError {
    UnpackError::Io {
        root: root.to_owned(),
        source,
    }
}

/// A paste-ready `rm -rf` for the mismatch hint, or `None` when the path cannot
/// be printed faithfully. `Path::display` is lossy, so a command built from it
/// could name a *different*, valid directory; non-UTF-8 or control bytes
/// therefore get advice without a command. Apostrophes are single-quoted out.
fn removal_hint(dir: &Path) -> Option<String> {
    let text = dir.to_str()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    Some(format!("rm -rf '{}'", text.replace('\'', "'\\''")))
}
struct RuntimeId(String);
impl RuntimeId {
    fn of(payload: &Payload<'_>) -> Self {
        let mut hash = Sha256::new();
        hash.update(payload.msb.sha256);
        hash.update(payload.libkrunfw.sha256);
        Self(
            hash.finalize()[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }
}
pub(crate) fn unpacked_dir(root: &Path, payload: &Payload<'_>) -> PathBuf {
    root.join(RuntimeId::of(payload).0)
}
fn layout(dir: &Path) -> UnpackedRuntime {
    UnpackedRuntime {
        msb: dir
            .join("bin")
            .join(msb_binary_filename(std::env::consts::OS)),
        libkrunfw: dir
            .join("lib")
            .join(libkrunfw_filename(std::env::consts::OS)),
    }
}
fn check_published(dir: &Path, payload: &Payload<'_>) -> Result<UnpackedRuntime, UnpackError> {
    let rt = layout(dir);
    for (path, data, file) in [
        (&rt.msb, &payload.msb, RuntimeFile::Msb),
        (&rt.libkrunfw, &payload.libkrunfw, RuntimeFile::Libkrunfw),
    ] {
        if !fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.len() == data.len) {
            return Err(UnpackError::Mismatch {
                dir: dir.to_owned(),
                file,
            });
        }
    }
    Ok(rt)
}
fn write_verified(
    dst: &Path,
    file: &PayloadFile<'_>,
    mode: u32,
    which: RuntimeFile,
    root: &Path,
) -> Result<(), UnpackError> {
    let corrupt = || UnpackError::CorruptPayload { file: which };
    let mut decoder = zstd::stream::read::Decoder::with_buffer(file.compressed)
        .map_err(|_| corrupt())?
        .take(file.len.saturating_add(1));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(dst)
        .map_err(|e| io_error(root, e))?;
    output
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|e| io_error(root, e))?;
    let mut hash = Sha256::new();
    let mut len = 0;
    let mut buf = [0; 64 * 1024];
    loop {
        let n = decoder.read(&mut buf).map_err(|_| corrupt())?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n]).map_err(|e| io_error(root, e))?;
        hash.update(&buf[..n]);
        len += n as u64;
    }
    if len != file.len || <[u8; 32]>::from(hash.finalize()) != file.sha256 {
        return Err(corrupt());
    }
    output.sync_all().map_err(|e| io_error(root, e))
}
#[derive(Debug, PartialEq, Eq)]
enum Publish {
    Published,
    PeerWon,
}
fn fsync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
fn publish(stage: tempfile::TempDir, dest: &Path, root: &Path) -> Result<Publish, UnpackError> {
    match fs::rename(stage.path(), dest) {
        Ok(()) => {
            // Keep immediately: the old stage name may be reused by another process.
            let _ = stage.keep();
            fsync_dir(root).map_err(|e| io_error(root, e))?;
            Ok(Publish::Published)
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::AlreadyExists
            ) =>
        {
            Ok(Publish::PeerWon)
        }
        Err(e) => Err(io_error(root, e)),
    }
}
pub(crate) fn unpack(root: &Path, payload: &Payload<'_>) -> Result<UnpackedRuntime, UnpackError> {
    let dest = unpacked_dir(root, payload);
    match fs::symlink_metadata(&dest) {
        Ok(_) => return check_published(&dest, payload),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(root, e)),
    }
    fs::create_dir_all(root).map_err(|e| io_error(root, e))?;
    let stage = tempfile::Builder::new()
        .prefix(".stage-")
        // Private from creation: tempfile defaults to 0o777 filtered by umask,
        // which would briefly expose the stage under a permissive umask. The
        // reset below still forces exactly 0o700 whatever the umask.
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(root)
        .map_err(|e| io_error(root, e))?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| io_error(root, e))?;
    let rt = layout(stage.path());
    for dir in ["bin", "lib"] {
        fs::create_dir(stage.path().join(dir)).map_err(|e| io_error(root, e))?;
    }
    write_verified(&rt.msb, &payload.msb, 0o755, RuntimeFile::Msb, root)?;
    write_verified(
        &rt.libkrunfw,
        &payload.libkrunfw,
        0o644,
        RuntimeFile::Libkrunfw,
        root,
    )?;
    for dir in [
        stage.path().join("bin"),
        stage.path().join("lib"),
        stage.path().to_owned(),
    ] {
        fsync_dir(&dir).map_err(|e| io_error(root, e))?;
    }
    match publish(stage, &dest, root)? {
        Publish::Published => Ok(layout(&dest)),
        Publish::PeerWon => check_published(&dest, payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    struct Fixture {
        msb: Vec<u8>,
        lib: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                msb: zstd::encode_all(&b"signed msb bytes"[..], 1).unwrap(),
                lib: zstd::encode_all(&b"firmware bytes"[..], 1).unwrap(),
            }
        }
        fn payload(&self) -> Payload<'_> {
            Payload {
                msb: PayloadFile {
                    compressed: &self.msb,
                    len: 16,
                    sha256: Sha256::digest(b"signed msb bytes").into(),
                },
                libkrunfw: PayloadFile {
                    compressed: &self.lib,
                    len: 14,
                    sha256: Sha256::digest(b"firmware bytes").into(),
                },
            }
        }
    }
    fn assert_empty(root: &Path) {
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
    }

    #[test]
    fn unpack_writes_bundle_layout_with_modes() {
        let root = tempfile::tempdir().unwrap();
        let f = Fixture::new();
        let rt = unpack(root.path(), &f.payload()).unwrap();
        assert_eq!(fs::read(&rt.msb).unwrap(), b"signed msb bytes");
        assert_eq!(fs::read(&rt.libkrunfw).unwrap(), b"firmware bytes");
        assert_eq!(fs::metadata(&rt.msb).unwrap().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(&rt.libkrunfw).unwrap().mode() & 0o777, 0o644);
        assert_eq!(
            fs::metadata(unpacked_dir(root.path(), &f.payload()))
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(rt.msb.parent().unwrap().file_name().unwrap(), "bin");
        assert_eq!(rt.libkrunfw.parent().unwrap().file_name().unwrap(), "lib");
    }
    #[test]
    fn unpack_reuses_published_runtime_without_rewriting() {
        let root = tempfile::tempdir().unwrap();
        let f = Fixture::new();
        let rt = unpack(root.path(), &f.payload()).unwrap();
        let before: Vec<_> = [&rt.msb, &rt.libkrunfw]
            .map(|p| {
                let m = fs::metadata(p).unwrap();
                (m.ino(), m.modified().unwrap())
            })
            .into();
        assert_eq!(unpack(root.path(), &f.payload()).unwrap(), rt);
        let after: Vec<_> = [&rt.msb, &rt.libkrunfw]
            .map(|p| {
                let m = fs::metadata(p).unwrap();
                (m.ino(), m.modified().unwrap())
            })
            .into();
        assert_eq!(before, after);
    }
    #[test]
    fn unpack_rejects_length_changed_runtime_with_rm_hint() {
        for which in [RuntimeFile::Msb, RuntimeFile::Libkrunfw] {
            let root = tempfile::tempdir().unwrap();
            let f = Fixture::new();
            let rt = unpack(root.path(), &f.payload()).unwrap();
            let path = if which == RuntimeFile::Msb {
                rt.msb
            } else {
                rt.libkrunfw
            };
            OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(b"x")
                .unwrap();
            let err = unpack(root.path(), &f.payload()).unwrap_err();
            assert!(matches!(err, UnpackError::Mismatch { file, .. } if file == which));
            let msg = err.to_string();
            assert!(msg.contains("rm -rf '"));
            assert!(msg.contains(&which.to_string()));
        }
        let err = UnpackError::Mismatch {
            dir: PathBuf::from("/cache/it's"),
            file: RuntimeFile::Msb,
        };
        assert!(err.to_string().contains("'/cache/it'\\''s'"));
    }
    #[test]
    fn unpack_rejects_missing_or_non_regular_runtime_file() {
        for kind in ["missing", "directory", "symlink"] {
            let root = tempfile::tempdir().unwrap();
            let f = Fixture::new();
            let rt = unpack(root.path(), &f.payload()).unwrap();
            fs::remove_file(&rt.msb).unwrap();
            match kind {
                "directory" => fs::create_dir(&rt.msb).unwrap(),
                "symlink" => std::os::unix::fs::symlink(&rt.libkrunfw, &rt.msb).unwrap(),
                _ => {}
            }
            assert!(matches!(
                unpack(root.path(), &f.payload()),
                Err(UnpackError::Mismatch {
                    file: RuntimeFile::Msb,
                    ..
                })
            ));
        }
    }
    #[test]
    fn unpack_reuse_accepts_same_length_edit() {
        let root = tempfile::tempdir().unwrap();
        let f = Fixture::new();
        let rt = unpack(root.path(), &f.payload()).unwrap();
        fs::write(&rt.msb, b"edited msb bytes").unwrap();
        assert_eq!(unpack(root.path(), &f.payload()).unwrap(), rt);
        assert_eq!(fs::read(&rt.msb).unwrap(), b"edited msb bytes");
    }
    #[test]
    fn unpack_reuse_accepts_symlinked_bin_ancestor() {
        // Pins the ADR-0041 reuse gap by its other route: only the final
        // component is type- and length-checked, so replacing `bin/` with a
        // symlink to a directory holding a same-length file is accepted.
        // Closing this needs hash-on-reuse (rejected on per-invocation cost)
        // or a mount guard; a writable mount can replace the bundle instead.
        let root = tempfile::tempdir().unwrap();
        let f = Fixture::new();
        let rt = unpack(root.path(), &f.payload()).unwrap();
        let outside = root.path().join("outside");
        fs::rename(rt.msb.parent().unwrap(), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, rt.msb.parent().unwrap()).unwrap();
        fs::write(outside.join("msb"), b"replaced msb byt").unwrap();
        assert_eq!(unpack(root.path(), &f.payload()).unwrap(), rt);
        assert_eq!(fs::read(&rt.msb).unwrap(), b"replaced msb byt");
    }
    #[test]
    fn mismatch_hint_quotes_ordinary_paths_and_refuses_hostile_bytes() {
        let ordinary = UnpackError::Mismatch {
            dir: PathBuf::from("/cache/it's"),
            file: RuntimeFile::Msb,
        };
        assert!(ordinary.to_string().contains("rm -rf '/cache/it'\\''s'"));

        use std::os::unix::ffi::OsStrExt;
        let non_utf8 = UnpackError::Mismatch {
            dir: PathBuf::from(std::ffi::OsStr::from_bytes(b"/cache/a\xffb")),
            file: RuntimeFile::Msb,
        };
        let text = non_utf8.to_string();
        assert!(!text.contains("rm -rf"), "{text}");
        assert!(text.contains("cannot be shown safely"), "{text}");

        let control = UnpackError::Mismatch {
            dir: PathBuf::from("/cache/a\nb"),
            file: RuntimeFile::Msb,
        };
        assert!(!control.to_string().contains("rm -rf"));
    }
    #[test]
    fn unpack_rejects_payload_digest_mismatch_and_publishes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let f = Fixture::new();
        let mut p = f.payload();
        p.msb.sha256[0] ^= 1;
        assert!(matches!(
            unpack(root.path(), &p),
            Err(UnpackError::CorruptPayload {
                file: RuntimeFile::Msb
            })
        ));
        assert_empty(root.path());
    }
    #[test]
    fn unpack_rejects_payload_length_mismatch() {
        for len in [1, 17] {
            let root = tempfile::tempdir().unwrap();
            let f = Fixture::new();
            let mut p = f.payload();
            p.msb.len = len;
            assert!(matches!(
                unpack(root.path(), &p),
                Err(UnpackError::CorruptPayload { .. })
            ));
            assert_empty(root.path());
        }
    }
    #[test]
    fn unpack_rejects_damaged_compressed_payload() {
        for truncated in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let mut f = Fixture::new();
            if truncated {
                f.msb.truncate(f.msb.len() / 2);
            } else {
                let last = f.msb.len() - 1;
                f.msb[last] ^= 1;
            }
            assert!(matches!(
                unpack(root.path(), &f.payload()),
                Err(UnpackError::CorruptPayload { .. })
            ));
            assert_empty(root.path());
        }
    }
    #[test]
    fn unpack_reports_root_occupied_by_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("occupied");
        fs::write(&root, b"x").unwrap();
        assert!(matches!(
            unpack(&root, &Fixture::new().payload()),
            Err(UnpackError::Io { .. })
        ));
    }
    #[test]
    fn unpack_reports_unwritable_root() {
        if crate::host_paths::current_euid() == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let result = unpack(root.path(), &Fixture::new().payload());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(result, Err(UnpackError::Io { .. })));
    }
    #[test]
    fn unpack_follows_a_symlinked_root_to_a_directory() {
        // E1: the cache root (or an ancestor) is a symlink to a real directory;
        // create_dir_all + tempdir_in must follow it, not fail or detach.
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let f = Fixture::new();
        let rt = unpack(&link, &f.payload()).unwrap();
        assert_eq!(fs::read(&rt.msb).unwrap(), b"signed msb bytes");
        assert!(rt.msb.starts_with(&link));
        assert!(
            rt.msb
                .canonicalize()
                .unwrap()
                .starts_with(real.canonicalize().unwrap())
        );
    }
    #[test]
    fn unpack_recovers_with_a_stale_stage_directory_present() {
        // E4: an interrupted publish leaves `.stage-*` behind. A later run must
        // still publish (no wedge). The stale stage is deliberately not
        // removed: there is no self-healing (ADR-0041).
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".stage-stale")).unwrap();
        let f = Fixture::new();
        let rt = unpack(root.path(), &f.payload()).unwrap();
        assert_eq!(fs::read(&rt.msb).unwrap(), b"signed msb bytes");
        assert!(root.path().join(".stage-stale").is_dir());
        assert_eq!(unpack(root.path(), &f.payload()).unwrap(), rt);
    }
    #[test]
    fn publish_adopts_peer_runtime_when_dest_exists() {
        let root = tempfile::tempdir().unwrap();
        let f = Fixture::new();
        let rt = unpack(root.path(), &f.payload()).unwrap();
        let stage = tempfile::Builder::new()
            .prefix(".stage-")
            .tempdir_in(root.path())
            .unwrap();
        fs::write(stage.path().join("complete"), b"x").unwrap();
        assert_eq!(
            publish(stage, &unpacked_dir(root.path(), &f.payload()), root.path()).unwrap(),
            Publish::PeerWon
        );
        assert_eq!(
            check_published(&unpacked_dir(root.path(), &f.payload()), &f.payload()).unwrap(),
            rt
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
    #[test]
    fn concurrent_unpack_publishes_once() {
        let root = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        let f = Fixture::new();
                        barrier.wait();
                        unpack(root.path(), &f.payload()).unwrap()
                    })
                })
                .collect();
            let runtimes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(runtimes.iter().all(|r| r == &runtimes[0]));
        });
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
    #[test]
    fn runtime_id_is_content_derived_16_hex() {
        let f = Fixture::new();
        let p = f.payload();
        let id = RuntimeId::of(&p).0;
        let expected = Sha256::digest([p.msb.sha256, p.libkrunfw.sha256].concat());
        assert_eq!(
            id,
            expected[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(id.len(), 16);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let mut changed = f.payload();
        changed.libkrunfw.sha256[0] ^= 1;
        assert_ne!(id, RuntimeId::of(&changed).0);
    }
}
