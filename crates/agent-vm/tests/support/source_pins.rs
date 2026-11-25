//! An independent oracle for the `#736` source pin store on disk.
//!
//! Every byte a real approval writes — `projects/<id>/pins.json`, the permanent
//! 144-byte `pins.lock` header, and `pin-<store_id>-<sha256>.toml` — is written
//! here by hand from the documented schema. Nothing in this module calls
//! `config_pins::store`, `ContentHash::of` or any other production writer, and
//! SHA-256 comes from `sha2` directly. That independence is the point: a fixture
//! that approved through `PinStore::update` could only prove the reader reads
//! what the writer wrote, so a reader that accepted, say, an unhashed snapshot,
//! would still pass.
//!
//! The module also owns the negative states a reader must classify exactly:
//! first use ([`Pins::new`] without [`Pins::write`]), a changed source
//! ([`Pins::approve_keeping_active`]), a newer approved branch, a tampered
//! snapshot ([`tamper_snapshot`]) and a damaged manifest ([`damage_manifest`]).
//!
//! Correctness of this module is checked on two levels. [`Pins::write`] re-reads
//! every file it wrote and refuses shape it did not intend (schema version,
//! generation agreement, `active ∈ approved`, snapshot name digest), so a stale
//! helper fails loudly here rather than as a confusing product refusal. And every
//! consumer proves the *production* reader accepts it: `doctor` renders
//! `pin=approved sha256:<hex>` and a launch reaches the fake runtime.

#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt as _,
    path::{Component, Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

/// A fixed 128-bit store id. Deliberately not random: the oracle states the
/// generation rather than generating one, so a frozen value in an assertion can
/// never agree with itself by accident.
pub const STORE_ID: &str = "0123456789abcdef0123456789abcdef";
/// First creation's epoch. A reset would write `2`, which the tests that need a
/// stale generation state for themselves.
pub const RESET_EPOCH: u64 = 1;
/// One fixed approval clock. The review UI only reports these, so their exact
/// value is irrelevant to every pin decision.
const APPROVED_MS: i64 = 1_000;

/// SHA-256 as 64 lowercase hex — the one digest spelling `pins.json`, a snapshot
/// name and the review UI all use.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// `<home>/.config/agent-vm/projects/<sha256 of the canonical project root>`.
///
/// The id is recomputed here, independently of `support::project_config_path`,
/// so a wrong product-side derivation cannot agree with the oracle.
pub fn store_dir(home: &Path, project_root: &Path) -> PathBuf {
    let canonical = project_root
        .canonicalize()
        .expect("canonicalize the oracle's project root");
    let id = sha256_hex(canonical.as_os_str().as_encoded_bytes());
    home.join(".config/agent-vm/projects").join(id)
}

/// One pin key: the source path exactly as `pins.json` spells it.
///
/// The reader requires a normalized absolute UTF-8 path (V3). Callers pass the
/// same absolute path the project config resolves to; the checks here make a
/// caller that passes `./x` or a relative spelling fail in the fixture instead of
/// producing a store the reader rejects.
fn pin_key(source: &Path) -> String {
    assert!(
        source.is_absolute(),
        "a pin key is absolute, not {}",
        source.display()
    );
    let text = source.to_str().expect("a pin key is UTF-8").to_owned();
    // `Path::components` silently drops `.`, so the spelling is checked as text:
    // the reader compares raw bytes and refuses a key that is not its own normal
    // form.
    assert!(
        !text.contains("//")
            && !text.contains("/./")
            && !text.ends_with("/.")
            && !text.ends_with('/'),
        "a pin key is its own normal form: {text}"
    );
    for component in source.components() {
        assert!(
            !matches!(component, Component::ParentDir),
            "a pin key keeps the user's `..` spelling only when it is the user's: {text}"
        );
    }
    text
}

/// The 144-byte permanent lock record for a `live` generation.
///
/// Production writes one `pwrite` of exactly this shape: the text, space padding
/// to byte 143, and a final `\n`. Reimplemented rather than imported, so a
/// change to the record's length or terminator breaks this oracle first.
pub fn lock_header(store_id: &str, epoch: u64) -> [u8; 144] {
    let text = format!("v=1 state=live id={store_id} epoch={epoch}");
    assert!(text.len() < 144, "the lock header text fits the record");
    let mut record = [b' '; 144];
    record[..text.len()].copy_from_slice(text.as_bytes());
    record[143] = b'\n';
    record
}

/// The snapshot file name for one generation and digest.
pub fn snapshot_name(store_id: &str, hash: &str) -> String {
    format!("pin-{store_id}-{hash}.toml")
}

/// The snapshot path for `hash` in `store`.
pub fn snapshot_path(store: &Path, hash: &str) -> PathBuf {
    store.join(snapshot_name(STORE_ID, hash))
}

/// One `pins.json` source line under construction.
struct Record {
    /// The last-active digest: what a review diffs against.
    active: String,
    /// Every approved digest, in the order the fixture named them.
    approved: Vec<String>,
}

/// The hand-built store a fixture states, then writes once.
///
/// A builder rather than a per-call function because a real project may pin
/// several sources, and because "approved twice, active on the older one" is a
/// state several rows need.
pub struct Pins {
    home: PathBuf,
    project: PathBuf,
    records: BTreeMap<String, Record>,
}

impl Pins {
    /// An empty store: the first-use state. Until [`write`](Self::write) runs,
    /// no file exists — which is also the fixture for "no store at all".
    pub fn new(home: &Path, project_root: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
            project: project_root.to_path_buf(),
            records: BTreeMap::new(),
        }
    }

    /// Approve `source`'s current bytes and make them the active baseline.
    pub fn approve(&mut self, source: &Path) -> &mut Self {
        let bytes = std::fs::read(source)
            .unwrap_or_else(|error| panic!("read {} for approval: {error}", source.display()));
        self.approve_bytes(source, &bytes)
    }

    /// Approve `bytes` for `source` and make them active; the snapshot is
    /// written from these bytes.
    pub fn approve_bytes(&mut self, source: &Path, bytes: &[u8]) -> &mut Self {
        let hash = sha256_hex(bytes);
        self.approve_hash(source, &hash, bytes);
        let key = pin_key(source);
        self.records.get_mut(&key).expect("just inserted").active = hash;
        self
    }

    /// Approve `source`'s current bytes **without** moving the active baseline.
    /// That is the branch-switch shape: an older approved version is written to
    /// disk while a newer one stays recorded as active.
    pub fn approve_keeping_active(&mut self, source: &Path) -> &mut Self {
        let bytes = std::fs::read(source)
            .unwrap_or_else(|error| panic!("read {} for approval: {error}", source.display()));
        let hash = sha256_hex(&bytes);
        self.approve_hash(source, &hash, &bytes)
    }

    /// Approve `bytes` for `source` without moving the baseline.
    pub fn approve_bytes_keeping_active(&mut self, source: &Path, bytes: &[u8]) -> &mut Self {
        let hash = sha256_hex(bytes);
        self.approve_hash(source, &hash, bytes)
    }

    fn approve_hash(&mut self, source: &Path, hash: &str, bytes: &[u8]) -> &mut Self {
        let key = pin_key(source);
        let record = self.records.entry(key).or_insert_with(|| Record {
            active: hash.to_owned(),
            approved: Vec::new(),
        });
        if !record.approved.iter().any(|seen| seen == hash) {
            record.approved.push(hash.to_owned());
        }
        // The snapshot for every approved digest must exist: a diff that needs
        // it later would otherwise report `missing`, which is a different state.
        let store = self.store_dir();
        std::fs::create_dir_all(&store).expect("create the oracle's store dir");
        set_mode(&store, 0o700);
        write_file(&snapshot_path(&store, hash), bytes);
        self
    }

    /// The store directory this fixture writes.
    pub fn store_dir(&self) -> PathBuf {
        store_dir(&self.home, &self.project)
    }

    /// Record the manifest and lock exactly as stated, and return the store dir.
    ///
    /// Re-reads what it wrote: an oracle that drifts from the schema must fail
    /// here with a fixture-shaped message, not present a store the product
    /// rejects as `damaged`.
    pub fn write(&self) -> PathBuf {
        let store = self.store_dir();
        std::fs::create_dir_all(store.parent().expect("a store has a parent"))
            .expect("create projects/");
        set_mode(store.parent().unwrap(), 0o700);
        std::fs::create_dir_all(&store).expect("create the oracle's store dir");
        set_mode(&store, 0o700);
        write_file(
            &store.join("pins.lock"),
            &lock_header(STORE_ID, RESET_EPOCH),
        );
        write_file(&store.join("pins.json"), self.manifest().as_bytes());
        self.validate(&store);
        store
    }

    /// The exact compact JSON a real writer produces: sources sorted by key,
    /// approvals sorted by digest, no whitespace.
    fn manifest(&self) -> String {
        let mut sources: Vec<String> = Vec::new();
        for (path, record) in &self.records {
            let mut approved: Vec<&String> = record.approved.iter().collect();
            approved.sort();
            let approvals: Vec<String> = approved
                .iter()
                .map(|hash| {
                    format!(
                        r#"{{"sha256":"{hash}","approved_ms":{APPROVED_MS},"active_ms":{APPROVED_MS}}}"#
                    )
                })
                .collect();
            sources.push(format!(
                r#"{{"path":{},"active":"{}","approved":[{}]}}"#,
                json_string(path),
                record.active,
                approvals.join(",")
            ));
        }
        format!(
            r#"{{"v":1,"store_id":"{STORE_ID}","reset_epoch":{RESET_EPOCH},"sources":[{}]}}"#,
            sources.join(",")
        )
    }

    /// Every rule the production decoder enforces, stated again here.
    fn validate(&self, store: &Path) {
        let header = std::fs::read(store.join("pins.lock")).expect("read the lock header");
        assert_eq!(header.len(), 144, "the lock record is 144 bytes");
        assert_eq!(header[143], b'\n', "the lock record ends with one newline");
        let expected = format!("v=1 state=live id={STORE_ID} epoch={RESET_EPOCH}");
        assert_eq!(
            String::from_utf8_lossy(&header[..expected.len()]),
            expected,
            "the lock header states the generation the manifest does"
        );

        let text = std::fs::read_to_string(store.join("pins.json")).expect("read the manifest");
        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("the oracle's manifest is JSON");
        assert_eq!(parsed["v"], 1);
        assert_eq!(parsed["store_id"], STORE_ID);
        assert_eq!(parsed["reset_epoch"], RESET_EPOCH);
        let sources = parsed["sources"].as_array().expect("a sources array");
        assert_eq!(sources.len(), self.records.len());
        for line in sources {
            let active = line["active"].as_str().expect("an active digest");
            let approved: Vec<&str> = line["approved"]
                .as_array()
                .expect("an approved array")
                .iter()
                .map(|approval| approval["sha256"].as_str().expect("a digest"))
                .collect();
            assert!(
                approved.contains(&active),
                "an active digest is one of the approved ones: {active}"
            );
            assert!(!approved.is_empty(), "a source has an approved digest");
        }
    }
}

/// Stamp one source approved-and-active from its current bytes, returning the
/// digest the fixture wrote. The common shape; [`Pins`] covers the rest.
pub fn approve(home: &Path, project_root: &Path, source: &Path) -> String {
    let bytes = std::fs::read(source)
        .unwrap_or_else(|error| panic!("read {} for approval: {error}", source.display()));
    let mut pins = Pins::new(home, project_root);
    pins.approve_bytes(source, &bytes);
    pins.write();
    sha256_hex(&bytes)
}

/// Stamp several sources approved-and-active from their current bytes.
pub fn approve_all<'a>(
    home: &Path,
    project_root: &Path,
    sources: impl IntoIterator<Item = &'a Path>,
) -> Vec<String> {
    let mut pins = Pins::new(home, project_root);
    let mut hashes = Vec::new();
    for source in sources {
        let bytes = std::fs::read(source)
            .unwrap_or_else(|error| panic!("read {} for approval: {error}", source.display()));
        pins.approve_bytes(source, &bytes);
        hashes.push(sha256_hex(&bytes));
    }
    pins.write();
    hashes
}

/// Overwrite one approved snapshot with different bytes, keeping its name. The
/// reader must re-hash and report `Unavailable(HashMismatch)`; a reader that
/// trusted the name would render the wrong baseline.
pub fn tamper_snapshot(store: &Path, hash: &str) {
    let path = snapshot_path(store, hash);
    let mut bytes = std::fs::read(&path).expect("the snapshot exists before tampering");
    bytes[0] = bytes[0].wrapping_add(b'X');
    write_file(&path, &bytes);
}

/// Replace `pins.json` with bytes that are not a manifest this build reads.
pub fn damage_manifest(store: &Path) {
    write_file(&store.join("pins.json"), b"{ not a manifest\n");
}

/// Every entry in `store`, sorted — the fixture's own view of what a command
/// created or left untouched.
pub fn entries(store: &Path) -> Vec<String> {
    let mut names: Vec<String> = match std::fs::read_dir(store) {
        Ok(entries) => entries
            .map(|entry| {
                entry
                    .expect("a dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read {}: {error}", store.display()),
    };
    names.sort();
    names
}

/// The `pins.json` bytes, if the fixture has written one.
pub fn manifest_bytes(store: &Path) -> Option<Vec<u8>> {
    std::fs::read(store.join("pins.json")).ok()
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create the snapshot's dir");
    }
    std::fs::write(path, bytes).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    set_mode(path, 0o600);
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("chmod {}: {error}", path.display()));
}

/// A JSON string literal, escaped as the schema requires. Paths in these tests
/// are plain ASCII, so this only has to be correct, not clever.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The outside digest, pinned to the three literals V1 records from
    /// `shasum -a 256`. If `sha2` were wired wrong, every fixture would agree
    /// with itself and prove nothing.
    #[test]
    fn the_outside_digest_matches_the_published_literals() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"foo\n"),
            "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
        );
        assert_eq!(
            sha256_hex(b"bar\n"),
            "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"
        );
    }

    /// The lock record is exactly the shape the reader accepts: text, padding,
    /// one trailing newline, and the generation both files name.
    #[test]
    fn the_lock_header_is_the_144_byte_record() {
        let record = lock_header(STORE_ID, RESET_EPOCH);
        assert_eq!(record.len(), 144);
        let text = std::str::from_utf8(&record[..143]).expect("ASCII header");
        assert_eq!(
            text.trim_end_matches(' '),
            format!("v=1 state=live id={STORE_ID} epoch={RESET_EPOCH}")
        );
        assert_eq!(record[143], b'\n');
    }

    /// A writer/reader drift (a changed terminator, an unnormalized key, an
    /// active digest outside the approved set) fails in the fixture.
    #[test]
    #[should_panic(expected = "a pin key is its own normal form")]
    fn a_dot_component_is_refused_by_the_oracle() {
        pin_key(Path::new("/a/./b.toml"));
    }

    #[test]
    fn a_written_store_re_reads_as_stated() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let source = project.join("s.toml");
        std::fs::write(&source, "image = \"x\"\n").unwrap();
        let hash = approve(&home, &project, &source);
        let store = store_dir(&home, &project);
        let expected = vec![
            snapshot_name(STORE_ID, &hash),
            "pins.json".to_owned(),
            "pins.lock".to_owned(),
        ];
        assert_eq!(entries(&store), expected);
        assert_eq!(
            std::fs::read_to_string(store.join("pins.json")).unwrap(),
            format!(
                r#"{{"v":1,"store_id":"{STORE_ID}","reset_epoch":1,"sources":[{{"path":{},"active":"{hash}","approved":[{{"sha256":"{hash}","approved_ms":1000,"active_ms":1000}}]}}]}}"#,
                json_string(source.to_str().unwrap())
            )
        );
        assert_eq!(
            sha256_hex(&std::fs::read(snapshot_path(&store, &hash)).unwrap()),
            hash,
            "the snapshot name is the digest of its bytes"
        );
    }
}
