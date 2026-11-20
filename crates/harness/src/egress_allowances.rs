//! The project allowance store the ADR-0065 boot cases launch under (#692).
//!
//! Ported from `script/test/lib/egress-fixtures.py` (`allowance_store`,
//! `allowance_lock`, `allowance_present`, `seed_allowances`,
//! `check_allowance_seed`, `remove_allowances`, `cleanup_pa2`,
//! `prepare_allowance`).
//!
//! This release has no writer for the store, so the harness writes the record
//! `PA1`/`PA1x` launch under. Two things make the cases mean something, and both
//! live here:
//!
//! * The digest is the launcher's own identity for the case's project, computed
//!   over the canonical path (the work directory may sit under `/tmp`, a symlink
//!   to `/private/tmp` on macOS, so the path is realpath'ed as the launcher does).
//! * A record already at the store is reported and refused, not overwritten: a
//!   leak from an earlier case must be visible, and `PA1x` expects default deny,
//!   so a seed it never received would make it pass while proving no isolation.
//!
//! PA2's live half — `prepare_live_allowance`, `check_live_allowance` and the
//! `snapshot_validation` a validation-only row is compared against — lives in
//! `egress_witness` with the two witness threads, because it reads and writes the
//! same evidence the witness does.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const PA2_SIGNALS: [&str; 2] = ["PA2-granted", "PA2-revoked"];

/// `work/home/.config/agent-vm/allowances.json`.
pub fn allowance_store(work: &Path) -> PathBuf {
    work.join("home/.config/agent-vm/allowances.json")
}

/// The writer's lock, created beside the record and never unlinked.
pub fn allowance_lock(work: &Path) -> PathBuf {
    work.join("home/.config/agent-vm/allowances.lock")
}

/// Whether anything carries the store's name, a dangling symlink included.
///
/// `Path::exists` follows the link, so a leftover record that was replaced by a
/// symlink would read as absent and the case would overwrite the link.
pub fn allowance_present(work: &Path) -> bool {
    let store = allowance_store(work);
    store.exists() || store.symlink_metadata().is_ok()
}

/// A containment check that tolerates a path which is not there yet.
///
/// The Python's `Path.resolve()` is non-strict: a missing tail, or a dangling
/// link, resolves to where it points. Canonicalising the parent and re-joining
/// the name is that same reading, and it keeps "the record is absent" apart from
/// "the record escaped the work directory".
fn within(path: &Path, root: &Path) -> Result<PathBuf, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("{root:?}: {error}"))?;
    let resolved = match path.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => {
            let parent = path
                .parent()
                .ok_or_else(|| format!("{} has no parent", path.display()))?;
            match parent.canonicalize() {
                Ok(parent) => parent.join(path.file_name().unwrap_or_default()),
                // The authority directory does not exist either: nothing is
                // there, so nothing can have escaped.
                Err(_) => return Ok(path.to_path_buf()),
            }
        }
    };
    if !resolved.starts_with(&root) {
        return Err(format!("path outside owned root: {}", resolved.display()));
    }
    Ok(resolved)
}

/// The launcher's project identity: the SHA-256 of the canonical path's bytes.
pub fn project_digest(project: &Path) -> Result<String, String> {
    let canonical = project
        .canonicalize()
        .map_err(|error| format!("{project:?}: {error}"))?;
    Ok(hex(canonical.as_os_str().as_encoded_bytes()))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn mode(path: &Path) -> Result<u32, String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .map_err(|error| format!("{path:?}: {error}"))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("{path:?}: {error}"))
}

/// The case whose record the seed writes: `PA1` is this launch's own project,
/// `PA1x` a different project that is never launched from, so the only
/// difference between the two cases is the record's identity.
fn seeded_project(work: &Path, case: &str) -> PathBuf {
    work.join(if case == "PA1" { "proj" } else { "other" })
}

/// The record the seed writes, as the launcher reads it.
fn expected_record(work: &Path, case: &str, lan: &str) -> Result<Value, String> {
    let project = seeded_project(work, case)
        .canonicalize()
        .map_err(|error| format!("{work:?}: {error}"))?;
    Ok(json!({
        "v": 1,
        "records": [{
            "project": hex(project.as_os_str().as_encoded_bytes()),
            "path": project.to_string_lossy(),
            "destination": format!("tcp://{lan}:18080"),
            "recorded_ms": 1762680120000u64,
        }],
    }))
}

/// Write the one record each ADR-0065 case launches under.
pub fn seed_allowances(work: &Path, case: &str, lan: &str) -> Result<(), String> {
    if !matches!(case, "PA1" | "PA1x") {
        return Err(format!("{case} has no allowance record"));
    }
    if allowance_present(work) {
        return Err(format!(
            "a store is already present: {}",
            allowance_store(work).display()
        ));
    }
    let store = allowance_store(work);
    let directory = store.parent().expect("the store has a parent");
    std::fs::create_dir_all(directory).map_err(|error| format!("{directory:?}: {error}"))?;
    set_mode(directory, 0o700)?;
    if case == "PA1x" {
        let project = seeded_project(work, case);
        std::fs::create_dir_all(&project).map_err(|error| format!("{project:?}: {error}"))?;
    }
    let record = expected_record(work, case, lan)?;
    std::fs::write(&store, record.to_string()).map_err(|error| format!("{store:?}: {error}"))?;
    set_mode(&store, 0o600)
}

/// The seed, read back and checked against an independent identity.
///
/// The boot cases rest on two things a launch cannot re-derive for itself: that
/// the file is *there*, and that its digest is the launcher's own identity for
/// the case's project. A missing or malformed seed makes PA1x pass while proving
/// no isolation at all, so this runs before the launch and a failure stops it.
pub fn check_allowance_seed(work: &Path, case: &str, lan: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let store = allowance_store(work);
    if let Err(error) = within(&store, work) {
        return vec![format!("the allowance seed is unreadable: {error}")];
    }
    if store
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_symlink())
    {
        return vec![format!(
            "the allowance seed is a symlink: {}",
            store.display()
        )];
    }
    let record: Value = match std::fs::read(&store)
        .map_err(|error| error.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
    {
        Ok(record) => record,
        Err(error) => return vec![format!("the allowance seed is unreadable: {error}")],
    };
    match expected_record(work, case, lan) {
        Ok(expected) if record == expected => {}
        Ok(_) => failures.push(format!(
            "the allowance seed is not the case's record: {record}"
        )),
        Err(error) => failures.push(format!("the allowance seed is unreadable: {error}")),
    }
    if let Ok(mode) = mode(&store)
        && mode != 0o600
    {
        failures.push(format!("the allowance seed is mode {mode:04o}, not 0600"));
    }
    if let Ok(mode) = mode(store.parent().expect("the store has a parent"))
        && mode != 0o700
    {
        failures.push(format!(
            "the authority directory is mode {mode:04o}, not 0700"
        ));
    }
    failures
}

/// Everything a PA case must do before it launches.
///
/// A leftover store is reported *and* removed rather than overwritten, and the
/// seed is then checked against an independent identity: those two steps are the
/// difference between PA1x proving isolation and PA1x passing because it never
/// had a record.
pub fn prepare_allowance(work: &Path, case: &str, lan: &str) -> Vec<String> {
    let mut failures = Vec::new();
    if allowance_present(work) {
        failures.push(
            "a project allowance record was left from an earlier case; \
             removing it before this case's record"
                .to_owned(),
        );
        if let Err(error) = std::fs::remove_file(allowance_store(work)) {
            failures.push(format!("the leftover record could not be removed: {error}"));
        }
    }
    match seed_allowances(work, case, lan) {
        Ok(()) => failures.extend(check_allowance_seed(work, case, lan)),
        Err(error) => failures.push(format!("the allowance seed failed: {error}")),
    }
    failures
}

/// Remove the case's record, and report anything of the store's own left.
///
/// Only `allowances.*` names are checked: a launch writes its image pin into the
/// same directory, so "anything else" there is not this case's evidence. A lock
/// or a set-aside sibling would be, because this release writes neither.
pub fn remove_allowances(work: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    let store = allowance_store(work);
    // A symlink is refused before the containment check: a dangling one has no
    // canonical form, and "replaced by a link" is the finding worth reporting.
    if store
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_symlink())
    {
        return vec![format!(
            "allowance record symlink refused: {}",
            store.display()
        )];
    }
    if let Err(error) = within(&store, work) {
        return vec![error];
    }
    if let Err(error) = std::fs::remove_file(&store)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        failures.push(format!("{store:?}: {error}"));
    }
    if allowance_present(work) {
        failures.push(format!("allowance record remains: {}", store.display()));
    }
    for sibling in allowance_siblings(&store) {
        failures.push(format!(
            "the store left {} behind; this release writes no lock",
            sibling.to_string_lossy()
        ));
    }
    failures
}

/// The `allowances.*` names beside the store, sorted as the Python's `glob` was.
fn allowance_siblings(store: &Path) -> Vec<OsString> {
    let Some(directory) = store.parent() else {
        return Vec::new();
    };
    let mut names: Vec<OsString> = std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name())
                .filter(|name| name.to_string_lossy().starts_with("allowances."))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Remove what PA2's own writer leaves: the record and its lock.
///
/// The writer creates `allowances.lock` beside the record and never unlinks it
/// (ADR-0065 constraint 1), so this is the one place a lock is *cleanup* rather
/// than a finding. It stays narrow on purpose: a `.damaged` or other
/// `allowances.*` sibling means the store was refused rather than written, which
/// is a failure and is still reported.
pub fn cleanup_pa2(work: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    for path in [allowance_store(work), allowance_lock(work)] {
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_symlink())
        {
            failures.push(format!(
                "allowance {} symlink refused",
                path.file_name().unwrap_or_default().to_string_lossy()
            ));
            continue;
        }
        match within(&path, work) {
            Ok(path) => {
                if let Err(error) = std::fs::remove_file(&path)
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    failures.push(format!("{path:?}: {error}"));
                }
                if path.exists() {
                    failures.push(format!(
                        "allowance material remains: {}",
                        Path::new(path.file_name().unwrap_or_default()).display()
                    ));
                }
            }
            Err(error) => failures.push(error),
        }
    }
    let store = allowance_store(work);
    if store.parent().is_some_and(Path::exists) {
        for sibling in allowance_siblings(&store) {
            failures.push(format!(
                "the live-allowance case left {} behind",
                sibling.to_string_lossy()
            ));
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "harness-allowance-{label}-{}",
            crate::egress_fixtures::monotonic_nanos()
        ));
        std::fs::create_dir_all(path.join("proj")).expect("a scratch project");
        std::fs::create_dir_all(path.join("home")).expect("a scratch home");
        path
    }

    #[test]
    fn the_seed_is_the_case_record_and_removal_leaves_nothing() {
        let work = scratch("seed");
        for case in ["PA1", "PA1x"] {
            seed_allowances(&work, case, "192.168.1.2").expect("the record is written");
            assert!(allowance_present(&work));
            assert!(
                check_allowance_seed(&work, case, "192.168.1.2").is_empty(),
                "{case}: the seed must read back as its own record"
            );
            // The two cases differ only in the record's identity: PA1's is the
            // launch project, PA1x's is a project nothing launches from.
            let record: Value =
                serde_json::from_slice(&std::fs::read(allowance_store(&work)).unwrap()).unwrap();
            let project = record["records"][0]["path"]
                .as_str()
                .expect("a project path")
                .to_owned();
            assert!(
                project.ends_with(if case == "PA1" { "proj" } else { "other" }),
                "{case}: {project}"
            );
            assert_eq!(mode(&allowance_store(&work)).unwrap(), 0o600);
            assert_eq!(
                mode(allowance_store(&work).parent().unwrap()).unwrap(),
                0o700
            );
            assert!(remove_allowances(&work).is_empty());
            assert!(!allowance_present(&work));
        }
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn a_leftover_store_is_reported_not_replaced() {
        let work = scratch("leftover");
        seed_allowances(&work, "PA1", "192.168.1.2").expect("the record is written");
        let refused = seed_allowances(&work, "PA1x", "192.168.1.2")
            .expect_err("a second seed must not overwrite the first");
        assert!(refused.contains("a store is already present"), "{refused}");
        // `prepare_allowance` reports the leak and then writes its own case's
        // record, so a leak costs a reported failure and not the case.
        let failures = prepare_allowance(&work, "PA1x", "192.168.1.2");
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("left from an earlier case"));
        assert!(check_allowance_seed(&work, "PA1x", "192.168.1.2").is_empty());
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn a_symlink_and_a_lock_are_both_refused() {
        let work = scratch("symlink");
        let directory = allowance_store(&work).parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&directory).expect("the authority directory");
        std::os::unix::fs::symlink(work.join("elsewhere"), allowance_store(&work))
            .expect("a symlinked store");
        // A dangling link still reads as present: that is the whole point.
        assert!(allowance_present(&work));
        assert!(
            remove_allowances(&work)
                .iter()
                .any(|failure| failure.contains("symlink refused"))
        );
        std::fs::remove_file(allowance_store(&work)).expect("the link is removed");
        std::fs::write(allowance_lock(&work), "").expect("a lock beside the record");
        let reported = remove_allowances(&work);
        assert!(
            reported
                .iter()
                .any(|failure| failure.contains("allowances.lock")),
            "{reported:?}"
        );
        // PA2's writer leaves the lock on purpose: for that case it is cleanup.
        assert!(cleanup_pa2(&work).is_empty(), "the lock is the case's own");
        assert!(!allowance_lock(&work).exists());
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn a_seed_outside_the_case_tables_is_refused() {
        let work = scratch("refuse");
        let refused = seed_allowances(&work, "PA2", "192.168.1.2")
            .expect_err("only the seeded cases have a record");
        assert!(refused.contains("no allowance record"), "{refused}");
        assert!(!allowance_present(&work));
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn the_digest_is_the_launcher_identity_for_the_canonical_path() {
        let work = scratch("digest");
        // The digest is over the canonical path, so a path spelled through a
        // symlink has the same identity as the real one.
        let linked = work.join("linked");
        std::os::unix::fs::symlink(work.join("proj"), &linked).expect("a symlinked project");
        assert_eq!(
            project_digest(&linked).expect("the project resolves"),
            project_digest(&work.join("proj")).expect("the project resolves")
        );
        assert_eq!(
            project_digest(&work.join("proj")).unwrap().len(),
            64,
            "a SHA-256 digest is 32 bytes of hex"
        );
        let _ = std::fs::remove_dir_all(&work);
    }
}
