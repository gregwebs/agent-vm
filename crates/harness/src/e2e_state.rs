//! `e2e.sh`'s two state-root observations (#700).
//!
//! Both come from the direct-launch rows, which reason about the launcher's
//! private state root after a launch:
//!
//! * `--absent` is the "nothing was provisioned" assertion. It is a *decision*,
//!   not a `[ ! -e ]`: only `ENOENT` is evidence. "I could not look" (a parent
//!   that is not a directory, a permission error) is a failure, because an
//!   observation that did not happen must never certify absence.
//! * `--home-links` is the guest-HOME furniture assertion: the exact
//!   `name<TAB>target` set of symlinks under `<state>/home`. The caller compares
//!   the whole set against the expected furniture, so an unexpected link (a
//!   catalog `persist` declaration, a provider link) fails instead of passing as
//!   "some path under the state root".

use std::{
    fs, io,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

use clap::Args;

#[derive(Debug, Args)]
pub struct E2eStateArgs {
    /// The state root to observe.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    state: Option<PathBuf>,

    /// Entries, relative to --state, that must not exist.
    #[arg(long, value_name = "RELATIVE", num_args = 1.., requires = "state")]
    absent: Vec<String>,

    /// The description the failures name.
    #[arg(long, value_name = "TEXT", requires = "absent")]
    desc: Option<String>,

    /// Print `relative<TAB>target` for every symlink under `<state>/home`.
    #[arg(long, conflicts_with = "absent", requires = "state")]
    home_links: bool,

    /// Run the boot-free controls for both observations.
    #[arg(long)]
    self_test: bool,
}

pub fn run(args: E2eStateArgs) -> Result<String, String> {
    if args.self_test {
        self_test()?;
        return Ok("e2e state controls passed".to_owned());
    }
    let state = args
        .state
        .ok_or("choose --state PATH with an observation")?;
    if args.home_links {
        return home_links(&state);
    }
    if args.absent.is_empty() {
        return Err("choose --absent RELATIVE…, --home-links or --self-test".to_owned());
    }
    let desc = args.desc.unwrap_or_else(|| state.display().to_string());
    entries_absent(&desc, &state, &args.absent)
}

/// One failure line per entry that exists or could not be observed. `ENOENT` is
/// the only outcome that passes; every other error is reported as the failed
/// observation it is.
fn entries_absent(desc: &str, state: &Path, entries: &[String]) -> Result<String, String> {
    let mut failures = Vec::new();
    for entry in entries {
        let path = state.join(entry);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => failures.push(format!(
                "FAIL: {desc}: could not observe {}: {error}",
                path.display()
            )),
            Ok(_) => failures.push(format!("FAIL: {desc}: {} must not exist", path.display())),
        }
    }
    if failures.is_empty() {
        return Ok(format!("state: {} entries absent", entries.len()));
    }
    Err(failures.join("\n"))
}

/// Every symlink under `<state>/home`, as `relative-to-home<TAB>target`.
/// A symlinked directory is reported and not descended, which is what the
/// expected furniture describes.
fn home_links(state: &Path) -> Result<String, String> {
    let root = state.join("home");
    let mut rows = Vec::new();
    walk(&root, &root, &mut rows)
        .map_err(|error| format!("FAIL: could not walk {}: {error}", root.display()))?;
    rows.sort();
    Ok(rows.join("\n"))
}

fn walk(root: &Path, directory: &Path, rows: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            let target = fs::read_link(&path)?;
            rows.push(format!("{}\t{}", relative.display(), target.display()));
        } else if kind.is_dir() {
            walk(root, &path, rows)?;
        }
    }
    Ok(())
}

fn self_test() -> Result<(), String> {
    let scratch = crate::scratch::Scratch::new("e2e-state")
        .map_err(|error| format!("cannot create the control directory: {error}"))?;
    let state = scratch.path().join("state");
    fs::create_dir_all(state.join("home/.config")).map_err(describe)?;
    fs::write(state.join("provisioned"), b"").map_err(describe)?;

    let ok = entries_absent("probe", &state, &["missing".to_owned()])
        .map_err(|error| format!("the absence oracle rejected a missing entry: {error}"))?;
    if !ok.contains("1 entries absent") {
        return Err(format!("the absence oracle reported {ok:?}"));
    }
    let error = entries_absent("probe", &state, &["provisioned".to_owned()])
        .err()
        .ok_or("the absence oracle accepted an existing entry")?;
    if !error.contains("must not exist") {
        return Err(format!(
            "an existing entry failed without its message: {error}"
        ));
    }
    // A parent that is a regular file is ENOTDIR: "could not observe", not
    // absence. This is the distinction `[ ! -e ]` cannot make.
    let error = entries_absent("probe", &state, &["provisioned/child".to_owned()])
        .err()
        .ok_or("the absence oracle called an unobservable path absent")?;
    if !error.contains("could not observe") {
        return Err(format!(
            "an unobservable entry failed without the observation message: {error}"
        ));
    }

    symlink(
        "/agent-vm-state/bash_history",
        state.join("home/.bash_history"),
    )
    .map_err(describe)?;
    symlink("/agent-vm-state/gh-config", state.join("home/.config/gh")).map_err(describe)?;
    fs::write(state.join("home/.config/plain"), b"").map_err(describe)?;
    symlink("..", state.join("home/.config/loop")).map_err(describe)?;
    let links = home_links(&state)?;
    let expected = ".bash_history\t/agent-vm-state/bash_history\n\
                    .config/gh\t/agent-vm-state/gh-config\n\
                    .config/loop\t..";
    if links != expected {
        return Err(format!(
            "the HOME-link walk reported {links:?}, want {expected:?}"
        ));
    }
    let empty = scratch.path().join("empty");
    fs::create_dir(&empty).map_err(describe)?;
    let error = home_links(&empty)
        .err()
        .ok_or("the HOME-link walk accepted a state root with no home")?;
    if !error.contains("could not walk") {
        return Err(format!(
            "a missing home failed without the walk message: {error}"
        ));
    }
    Ok(())
}

fn describe(error: io::Error) -> String {
    format!("control setup failed: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_controls_hold() {
        self_test().expect("e2e state controls pass");
    }
}
