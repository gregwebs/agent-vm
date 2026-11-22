//! The host-managed project config path (ADR-0073), computed independently of
//! `agent-vm`.
//!
//! `e2e.sh` and `e2e-released-image.sh` used to write `<project>/.agent-vm/
//! config.toml`. The product now reads
//! `$HOME/.config/agent-vm/projects/<64-hex>/config.toml`, where the id is the
//! SHA-256 of the canonical project path's raw bytes — the same id
//! `image-pins.json` and `allowances.json` use.
//!
//! Hashing belongs in Rust, not a shell pipeline (ADR-0072,
//! `CODING_STANDARDS.md` "Shell or Rust"), and it must not be a copy of the
//! product's code: this crate is an independent oracle, so a wrong id in
//! `agent-vm` fails here rather than agreeing with itself. The unit test below
//! pins whole vectors computed outside this crate.

use std::{
    fmt::Write as _,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use clap::Args;
use sha2::{Digest as _, Sha256};

#[derive(Debug, Args)]
pub struct ProjectConfigPathArgs {
    /// The `$HOME` the launch will see.
    #[arg(long, value_name = "HOME")]
    home: PathBuf,

    /// The project directory, as the process will name it.
    #[arg(long, value_name = "PATH")]
    project: PathBuf,
}

pub fn run(args: ProjectConfigPathArgs) -> Result<String, String> {
    project_config_path(&args.home, &args.project).map(|path| path.to_string_lossy().into_owned())
}

/// Where `agent-vm` reads `project`'s config under `home`.
///
/// `home` is used as given: the product joins the literal `$HOME` spelling and
/// never canonicalizes it, so a caller that passes a symlinked home must pass the
/// same spelling the child will see.
pub fn project_config_path(home: &Path, project: &Path) -> Result<PathBuf, String> {
    let canonical = project
        .canonicalize()
        .map_err(|error| format!("usage: cannot canonicalize {}: {error}", project.display()))?;
    Ok(home
        .join(".config/agent-vm/projects")
        .join(digest_hex(&canonical))
        .join("config.toml"))
}

/// The lowercase hex SHA-256 of the path's raw bytes (64 characters).
fn digest_hex(path: &Path) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(path.as_os_str().as_bytes()) {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// Both vectors were computed by `shasum -a 256` outside this crate, so a
    /// changed hash input (lossy UTF-8, a truncated id, the 12-hex state name)
    /// fails here.
    #[test]
    fn the_digest_is_the_full_sha256_of_the_raw_path_bytes() {
        assert_eq!(
            digest_hex(Path::new("/a/b")),
            "662b7b62a798bb2d53e67cad9778e12e48297c79eae98d3aae7197be825d768f"
        );
        assert_eq!(
            digest_hex(Path::new(OsStr::from_bytes(b"/a/\xff"))),
            "7c83ed9afbe4f45264a1bae418eaec47444a63fbcb68b96818bb0f6bd1b4b608"
        );
    }

    #[test]
    fn the_path_is_home_projects_digest_config_toml() {
        let root = std::env::temp_dir().join(format!(
            "harness-project-config-path-{}",
            crate::egress_fixtures::monotonic_nanos()
        ));
        let project = root.join("proj");
        std::fs::create_dir_all(&project).expect("create the project");
        let canonical = project.canonicalize().expect("canonicalize the project");
        let path = project_config_path(Path::new("/home/someone"), &project).expect("a path");
        assert_eq!(
            path,
            Path::new("/home/someone")
                .join(".config/agent-vm/projects")
                .join(digest_hex(&canonical))
                .join("config.toml")
        );
        let id = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .expect("a hex id");
        assert_eq!(id.len(), 64, "{id}");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{id}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_project_is_misuse() {
        let error = project_config_path(Path::new("/home/someone"), Path::new("/nonexistent/x"))
            .expect_err("a missing project cannot be hashed");
        assert!(error.starts_with("usage: "), "{error}");
    }
}
