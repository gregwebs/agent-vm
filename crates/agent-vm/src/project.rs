//! What a **project** is (CONTEXT.md → Project): the canonical working
//! directory of an agent-vm command, captured once at its entry point.
//!
//! # Why this is a capture and not an ambient read
//!
//! An external `rename` changes what `getcwd` returns without any `chdir` in
//! this process, so reading the cwd twice can name two different projects
//! within one command. Session state and approval authority must agree on one
//! identity for the whole command, so the entry point captures it once and
//! every consumer borrows that capture.
//!
//! # Why capture resolves and then verifies identity
//!
//! `current_dir` and `canonicalize` are two separate system calls, so a rename
//! between them can leave the captured spelling pointing at a *different*
//! directory — one another user can prepare. Canonicalizing alone would then
//! name (and let a build or import approve content for) a project the command
//! never ran in. The capture therefore compares the resolved directory's
//! identity with the working directory's own identity and fails when they
//! differ: a wrong answer here is authority in the wrong project, so the one
//! safe outcome is a hard error, never a retry or a silent continue.
//!
//! # The invariant: the resolved path must itself be the working directory
//!
//! Resolving and measuring are also separate system calls, so agreement on
//! identity is not enough on its own: the resolved *name* can be replaced by a
//! symlink in between, including one that points back at the process's own
//! working directory. Both measurements then agree while the resolved path is a
//! substitution. The check is therefore made against `lstat` of the resolved
//! path — never `stat` — and requires a real directory: a canonical path's
//! final component is a directory on disk, so a symlink there means someone
//! re-pointed the name after it was resolved, and capture refuses.
//!
//! # Why a digest and not the path
//!
//! Approval authority lives in `$HOME/.config/agent-vm/`, independent of
//! `AGENT_VM_STATE_DIR` (ADR-0047), so a pin record cannot hold the state
//! directory. The identifier is therefore the lowercase hex SHA-256 of the
//! canonical path's bytes: the full digest, because approval authority must not
//! depend on a truncated hash, while session's 12-hex state-directory name is
//! that digest's prefix — the same hash over the same bytes, so existing state
//! directories stay reachable.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};

/// One capture per command is enforced by lint and review, not by the type:
/// [`ProjectDir::capture`] is a clippy `disallowed-methods` entry with
/// statement-level allowances at the command entry points. Not `Clone`, so
/// consumers borrow the capture rather than copying it.
pub(crate) struct ProjectDir(PathBuf);

impl ProjectDir {
    /// The command's project: `current_dir()` canonicalized.
    ///
    /// Every command entry point calls this exactly once; the error contexts
    /// are the ones a launch printed before this module existed.
    pub(crate) fn capture() -> Result<Self> {
        let cwd = std::env::current_dir().context("reading current directory")?;
        // `.` resolves from the working directory itself, not from the name the
        // cwd was read as, so it identifies the directory this command runs in
        // even after that name moved.
        resolve(cwd, Path::new("."))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// The full lowercase hex SHA-256 of the canonical path's bytes (64 chars).
    pub(crate) fn digest_hex(&self) -> String {
        digest_hex_of(&self.0)
    }

    /// Canonicalizes `path`; the unit tests' seam for alias/subdirectory rows.
    #[cfg(test)]
    pub(crate) fn from_path_for_tests(path: &Path) -> Result<Self> {
        canonical(path.to_owned())
    }
}

/// [`ProjectDir::digest_hex`] for a path that is not a capture: a store record's
/// `path` column must hash to its `project` column, and that check has only the
/// stored bytes (ADR-0065 D2).
pub(crate) fn digest_hex_of(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

fn canonical(path: PathBuf) -> Result<ProjectDir> {
    path.canonicalize()
        .map(ProjectDir)
        .context("canonicalizing current directory")
}

/// Canonicalize `spelling` and require the result to denote the same directory
/// as `working`.
fn resolve(spelling: PathBuf, working: &Path) -> Result<ProjectDir> {
    let captured = canonical(spelling)?;
    bind(&captured, working)?;
    Ok(captured)
}

/// Require `captured` to *be* `working`: the same `(device, inode)`, measured
/// without following a final symlink.
///
/// Identity, not spelling: `(device, inode)` survives a rename, and a directory
/// cannot be substituted without a different inode. Anything else — a symlink
/// planted at the old name, a rename followed by a fresh directory at that
/// name — resolves to a directory the process is not in, which this refuses.
///
/// [`identity`] reads `lstat`, so a link planted at the resolved name *after*
/// canonicalization reports the link rather than a target that agrees with the
/// working directory: following it would make both measurements agree while the
/// captured path named someone else's directory.
fn bind(captured: &ProjectDir, working: &Path) -> Result<()> {
    let working = identity(working).context("reading the identity of the current directory")?;
    let resolved =
        identity(captured.path()).context("reading the identity of the resolved project")?;
    if working != resolved {
        return Err(anyhow!(
            "the current directory moved while its path was being resolved: {} is device {} \
             inode {}, which is not the process's working directory (device {} inode {}); \
             re-run the command from the project's current path",
            crate::one_line::path(captured.path()),
            resolved.device,
            resolved.inode,
            working.device,
            working.inode,
        ));
    }
    Ok(())
}

/// What a directory *is*, rather than what it is called.
#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

/// Measure `path` as the directory entry itself (`lstat`): a symlink is a link,
/// not its target, and anything that is not a directory is refused.
fn identity(path: &Path) -> Result<Identity> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading the identity of {}", crate::one_line::path(path)))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "{} is a symlink, not the resolved project directory; someone re-pointed the name \
             after it was resolved, so re-run the command from the project's current path",
            crate::one_line::path(path),
        ));
    }
    if !metadata.is_dir() {
        return Err(anyhow!(
            "{} is not a directory, so it cannot be this command's project",
            crate::one_line::path(path),
        ));
    }
    Ok(Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn symlink_alias_is_one_project_and_subdirectory_is_not() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("app");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(project.join("sub")).unwrap();
        let link = root.path().join("alias");
        symlink(&project, &link).unwrap();

        let direct = ProjectDir::from_path_for_tests(&project).unwrap();
        let alias = ProjectDir::from_path_for_tests(&link).unwrap();
        let sub = ProjectDir::from_path_for_tests(&project.join("sub")).unwrap();
        assert_eq!(direct.digest_hex(), alias.digest_hex());
        assert_eq!(direct.path(), alias.path());
        assert_ne!(direct.digest_hex(), sub.digest_hex());
    }

    /// The free-function form hashes the same bytes the capture does, which is
    /// what lets a store record's `path` column be checked against its `project`
    /// column without a capture (ADR-0065 D2).
    #[test]
    fn digest_of_a_path_equals_the_captures_digest() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("app");
        std::fs::create_dir(&dir).unwrap();
        let project = ProjectDir::from_path_for_tests(&dir).unwrap();
        assert_eq!(digest_hex_of(project.path()), project.digest_hex());
        // And it is a hash of exactly the bytes it was handed, not a canonical
        // spelling: an unavailable path still has a digest.
        assert_eq!(digest_hex_of(Path::new("/no/such/place")).len(), 64);
    }

    /// The rename race is refused, deterministically: `resolve` is the seam
    /// where the spelling and the working directory can disagree, and this
    /// proves the check fires rather than trusting a racy loop to hit it.
    #[test]
    fn a_resolved_path_that_is_not_the_working_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let working = root.path().join("working");
        let other = root.path().join("other");
        std::fs::create_dir(&working).unwrap();
        std::fs::create_dir(&other).unwrap();

        // `working` is the process's directory; its old name now resolves to
        // `other`. Capturing `other` would approve content for the wrong
        // project, so this must be an error that names the mismatch.
        let error = match resolve(other.clone(), &working) {
            Ok(captured) => panic!(
                "captured {} instead of refusing the swap",
                captured.path().display()
            ),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            error.contains("moved while its path was being resolved"),
            "{error}"
        );
        assert!(
            error.contains(&format!("device {}", identity(&other).unwrap().device)),
            "{error}"
        );

        // The ordinary case still captures, so the check is not a refusal of
        // every path.
        let captured = resolve(working.clone(), &working).unwrap();
        assert_eq!(captured.path(), working.canonicalize().unwrap());
    }

    /// The reviewer's two-swap probe, replayed in syscall order instead of by
    /// racing: rename the working directory aside, point its old name at another
    /// directory (so canonicalization captures *that* one), then move that
    /// directory aside and point its name at the working directory. Both
    /// identity measurements now agree while the captured path names a
    /// substitution, so identity alone cannot refuse it — the `lstat` in
    /// [`identity`] must.
    #[test]
    fn a_resolved_path_replaced_by_a_symlink_to_the_working_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let working = root.path().join("working");
        let captured_name = root.path().join("b");
        std::fs::create_dir(&working).unwrap();
        std::fs::create_dir(&captured_name).unwrap();

        // Swap 1: the name the cwd was read as now resolves to `b`, so the
        // capture's canonicalization lands on `b`.
        let a = root.path().join("a");
        symlink(&captured_name, &a).unwrap();
        let project = ProjectDir::from_path_for_tests(&a).unwrap();
        assert_eq!(project.path(), captured_name.canonicalize().unwrap());

        // Swap 2: `b` itself moves aside and its name becomes a link to the
        // working directory.
        std::fs::rename(&captured_name, root.path().join("b-aside")).unwrap();
        symlink(&working, &captured_name).unwrap();

        let followed = std::fs::metadata(&captured_name).unwrap();
        let after = std::fs::metadata(&working).unwrap();
        assert_eq!(
            (followed.dev(), followed.ino()),
            (after.dev(), after.ino()),
            "the two measurements agree, which is why identity alone cannot see this swap"
        );

        let error = match bind(&project, &working) {
            Ok(()) => panic!(
                "captured {} although it is a link to the working directory",
                project.path().display()
            ),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains("is a symlink"), "{error}");

        // The ordinary case still binds, so the refusal is about the link.
        let ordinary = ProjectDir::from_path_for_tests(&working).unwrap();
        bind(&ordinary, &working).unwrap();
    }

    /// The state-directory name is a prefix of the pin scope, and both are one
    /// hash of the same bytes: an existing `<state>/<hash>` stays reachable and
    /// the two consumers cannot disagree about which project they mean.
    #[test]
    fn state_directory_name_is_a_stable_digest_prefix() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("app");
        std::fs::create_dir(&dir).unwrap();
        let project = ProjectDir::from_path_for_tests(&dir).unwrap();
        let digest = project.digest_hex();
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        );
        // The pre-#532 `session::hash_path`, kept here as the independent
        // expectation: changing how the 12-hex state name is derived would make
        // every existing project's state directory unreachable.
        let mut hasher = Sha256::new();
        hasher.update(project.path().as_os_str().as_encoded_bytes());
        let old: String = hasher.finalize()[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(&digest[..12], old);
        assert_eq!(
            digest,
            ProjectDir::from_path_for_tests(&dir).unwrap().digest_hex()
        );
        let other = root.path().join("other");
        std::fs::create_dir(&other).unwrap();
        assert_ne!(
            digest,
            ProjectDir::from_path_for_tests(&other)
                .unwrap()
                .digest_hex()
        );
    }

    /// Spec R2 and the recipe USAGE hands the operator: the identifier is the
    /// SHA-256 of the **canonical** path's bytes, i.e. what
    /// `printf %s "$(pwd -P)" | shasum -a 256` prints from inside the project.
    /// Hashing the spelling the user typed (or the path before
    /// `canonicalize`) hashes a different string, and the operator then looks
    /// for records under an identifier no command writes.
    #[test]
    fn the_documented_pwd_recipe_names_the_same_project() {
        let sha256_of = |path: &Path| {
            let mut hasher = Sha256::new();
            hasher.update(path.as_os_str().as_encoded_bytes());
            let digest = hasher.finalize();
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("app");
        std::fs::create_dir(&project).unwrap();
        let link = root.path().join("alias");
        symlink(&project, &link).unwrap();

        // A symlink alias is the same project, and the identifier is the
        // canonical spelling's: the alias's own bytes hash to something else.
        let captured = ProjectDir::from_path_for_tests(&link).unwrap();
        assert_eq!(captured.path(), project.canonicalize().unwrap());
        assert_eq!(captured.digest_hex(), sha256_of(captured.path()));
        assert_ne!(
            captured.digest_hex(),
            sha256_of(&link),
            "the identifier must not be the spelling the user typed"
        );

        // macOS resolves `/tmp` to `/private/tmp`, so a user who typed
        // `cd /tmp/x` gets the resolved spelling from `pwd -P` while the
        // capture saw `/tmp/x`. Both must name one project.
        let spelled = tempfile::Builder::new()
            .prefix("avproject-")
            .tempdir_in("/tmp")
            .unwrap();
        let captured = ProjectDir::from_path_for_tests(spelled.path()).unwrap();
        assert_eq!(captured.digest_hex(), sha256_of(captured.path()));
        if captured.path() != spelled.path() {
            assert_ne!(
                captured.digest_hex(),
                sha256_of(spelled.path()),
                "an unresolved spelling must not be the identifier"
            );
        }
    }
}
