//! The pin store's own tests: schema, keys, the pure state machine, and the
//! descriptor-anchored store's classification, commit and recovery behaviour.
//!
//! Every fixture lives under `tempfile`; nothing here reads `$HOME`, the real
//! `~/.config/agent-vm`, or `AGENT_VM_STATE_DIR`.

use std::{
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
};

use super::*;
use crate::config_authority::AuthorityRefusal;
use crate::config_pins::store::*;

fn key(path: &str) -> PinKey {
    PinKey::for_source(Path::new(path)).unwrap()
}

fn hash(bytes: &[u8]) -> ContentHash {
    ContentHash::of(bytes)
}

struct Fixture {
    base: tempfile::TempDir,
    home: PathBuf,
    project: crate::project::ProjectDir,
}

impl Fixture {
    fn new() -> Self {
        let base = tempfile::tempdir().unwrap();
        let base_path = base.path().canonicalize().unwrap();
        let home = base_path.join("home");
        std::fs::create_dir(&home).unwrap();
        let root = base_path.join("project");
        std::fs::create_dir(&root).unwrap();
        let project = crate::project::ProjectDir::from_path_for_tests(&root).unwrap();
        Self {
            base,
            home,
            project,
        }
    }

    fn base_path(&self) -> &Path {
        self.base.path()
    }

    fn store(&self) -> PinStore {
        PinStore::at_for_tests(&self.home, &self.project)
    }

    fn store_dir(&self) -> PathBuf {
        crate::project_config::project_dir(&self.home, &self.project)
    }

    fn create_store_dir(&self) -> PathBuf {
        let dir = self.store_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn observe(&self) -> ObservedStore {
        self.store().observe().unwrap()
    }

    fn commit(&self, path: &str, body: &[u8], now_ms: i64) -> CommitOutcome {
        let observed = self.observe();
        self.commit_observed(&observed, path, body, now_ms)
    }

    fn commit_observed(
        &self,
        observed: &ObservedStore,
        path: &str,
        body: &[u8],
        now_ms: i64,
    ) -> CommitOutcome {
        let batch = CommitBatch {
            approve: vec![ApprovalCandidate {
                key: key(path),
                hash: hash(body),
                bytes: body.to_vec(),
                activate: true,
            }],
            activate: Vec::new(),
            retained_keys: vec![key(path)],
        };
        self.store().update(observed, &batch, now_ms).unwrap()
    }

    fn pins_path(&self) -> PathBuf {
        self.store_dir().join(PINS_FILE)
    }

    fn lock_path(&self) -> PathBuf {
        self.store_dir().join(LOCK_FILE)
    }

    fn snapshot_path(&self, generation: LiveGeneration, bytes: &[u8]) -> PathBuf {
        self.store_dir()
            .join(snapshot_name(generation.store_id, &hash(bytes)))
    }

    fn write_lock_record(&self, header: &LockHeader) {
        std::fs::write(self.lock_path(), encode_lock_header(header)).unwrap();
        std::fs::set_permissions(self.lock_path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

// ---- V1/V2: digests ----

#[test]
fn content_hashes_match_independent_shasum_literals() {
    // `printf %s "" | shasum -a 256`, and the same for "foo\n"/"bar\n".
    assert_eq!(
        hash(b"").hex(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hash(b"foo\n").hex(),
        "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
    );
    assert_eq!(
        hash(b"bar\n").hex(),
        "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"
    );
    assert_eq!(
        hash(b"foo\n").to_string(),
        "sha256:b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
    );
}

#[test]
fn digest_and_store_id_spellings_are_exact() {
    let good = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c";
    assert_eq!(ContentHash::parse_hex(good), Some(hash(b"foo\n")));
    assert_eq!(
        ContentHash::parse_prefixed(&format!("sha256:{good}")),
        Some(hash(b"foo\n"))
    );
    for bad in [
        "B5BB9D8014A0F9B1D61E21E796D78DCCDF1352F23CD32812F4850B878AE4944C".to_owned(),
        good[..63].to_owned(),
        format!("{good}0"),
        good.replace('b', "g"),
        String::new(),
    ] {
        assert_eq!(ContentHash::parse_hex(&bad), None, "{bad}");
    }
    assert_eq!(ContentHash::parse_prefixed(&format!("SHA256:{good}")), None);

    let id = "0123456789abcdef0123456789abcdef";
    assert!(StoreId::parse_hex(id).is_some());
    assert_eq!(StoreId::parse_hex(&id.to_ascii_uppercase()), None);
    assert_eq!(StoreId::parse_hex(&id[..31]), None);
    assert_eq!(StoreId::parse_hex(&format!("{id}0")), None);
}

// ---- V3: keys ----

#[test]
fn pin_keys_normalize_once_and_compare_raw_spellings() {
    let normalized = PinKey::for_source(Path::new("/a//b/./c.toml")).unwrap();
    assert_eq!(normalized.as_str(), "/a/b/c.toml");
    assert_eq!(normalized.as_path(), Path::new("/a/b/c.toml"));
    // `..` is kept: the OS resolves it through the symlink the user named.
    assert_eq!(
        PinKey::for_source(Path::new("/a/b/../c.toml"))
            .unwrap()
            .as_str(),
        "/a/b/../c.toml"
    );
    for refused in ["a/b.toml", "/a/b/", "/a/b/.", "/a/b/..", "/", ""] {
        assert!(PinKey::for_source(Path::new(refused)).is_err(), "{refused}");
    }
    // Non-UTF-8 is refused before any path comparison can happen.
    assert_eq!(
        PinKey::for_source(Path::new(std::ffi::OsStr::from_bytes(b"/a/\xff"))).unwrap_err(),
        KeyRefusal::NotUtf8
    );
    assert_eq!(
        PinKey::for_source(Path::new(&format!("/{}", "a".repeat(4096)))).unwrap_err(),
        KeyRefusal::TooLong
    );
    assert_eq!(
        PinKey::for_source(Path::new("/a/\u{7}b")).unwrap_err(),
        KeyRefusal::Control
    );

    // A stored spelling must already be its own normal form: `Path` equality
    // would hide `//` and `/./`, so the raw string is what is compared.
    assert!(PinKey::from_stored("/a/b").is_ok());
    assert!(PinKey::from_stored("/a//b").is_err());
    assert!(PinKey::from_stored("/a/./b").is_err());
    assert!(PinKey::from_stored("/a/b/").is_err());
}

#[test]
fn snapshot_names_are_case_insensitive_and_generation_bound() {
    let id = StoreId::parse_hex("0123456789abcdef0123456789abcdef").unwrap();
    let digest = hash(b"foo\n");
    let name = snapshot_name(id, &digest);
    assert_eq!(
        name,
        "pin-0123456789abcdef0123456789abcdef-b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c.toml"
    );
    assert!(is_snapshot_name(std::ffi::OsStr::new(&name)));
    assert!(is_snapshot_name(std::ffi::OsStr::new(
        &name.to_ascii_uppercase()
    )));
    for not in [
        "pins.json".to_owned(),
        "pins.lock".to_owned(),
        "pin-XYZ.toml".to_owned(),
        "pin-0123-b5bb.toml".to_owned(),
        format!("{name}.extra"),
        format!(".{name}"),
    ] {
        assert!(!is_snapshot_name(std::ffi::OsStr::new(&not)), "{not}");
    }
}

// ---- V4: manifest decoding ----

fn valid_manifest_json(id: &str, epoch: u64, sources: &str) -> String {
    format!(r#"{{"v":1,"store_id":"{id}","reset_epoch":{epoch},"sources":[{sources}]}}"#)
}

const ID: &str = "0123456789abcdef0123456789abcdef";
const H1: &str = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c";
const H2: &str = "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730";

fn one_source(path: &str, active: &str, approved: &str) -> String {
    format!(r#"{{"path":"{path}","active":"{active}","approved":[{approved}]}}"#)
}

fn approval(digest: &str, approved_ms: i64, active_ms: i64) -> String {
    format!(r#"{{"sha256":"{digest}","approved_ms":{approved_ms},"active_ms":{active_ms}}}"#)
}

fn decode_error(text: &str) -> DecodeFailure {
    Current::decode(text.as_bytes()).unwrap_err()
}

#[test]
fn manifest_decode_enforces_the_schema_and_the_store_bound() {
    let good = valid_manifest_json(ID, 1, &one_source("/w/a.toml", H1, &approval(H1, 1, 2)));
    let current = Current::decode(good.as_bytes()).unwrap();
    assert_eq!(current.generation().reset_epoch, 1);
    assert!(current.is_approved(&key("/w/a.toml"), &hash(b"foo\n")));

    assert_eq!(
        decode_error(
            &valid_manifest_json(ID, 1, &one_source("/w/a.toml", H1, &approval(H1, 1, 2)))
                .replace("\"v\":1", "\"v\":2")
        ),
        DecodeFailure::Newer { v: 2 }
    );
    assert_eq!(
        decode_error(
            &valid_manifest_json(ID, 1, &one_source("/w/a.toml", H1, &approval(H1, 1, 2)))
                .replace("\"v\":1", "\"v\":0")
        ),
        DecodeFailure::OlderVersion(0)
    );
    assert_eq!(
        decode_error(&valid_manifest_json("nothex", 1, "")),
        DecodeFailure::Invalid("store_id is not 32 lowercase hex")
    );
    assert_eq!(
        decode_error(&valid_manifest_json(ID, 0, "")),
        DecodeFailure::Invalid("reset_epoch is zero")
    );
    assert_eq!(decode_error("{\"v\":1,"), DecodeFailure::Undecodable);
    assert_eq!(
        decode_error(
            &valid_manifest_json(ID, 1, &one_source("/w/a.toml", H1, &approval(H1, 1, 2)))
                .replace("\"v\":1", "\"v\":1,\"extra\":true")
        ),
        DecodeFailure::Undecodable
    );
    assert_eq!(
        decode_error(&format!(
            "{}{}",
            &valid_manifest_json(ID, 1, &one_source("/w/a.toml", H1, &approval(H1, 1, 2)))[..20],
            ""
        )),
        DecodeFailure::Undecodable
    );
    // Duplicate and unnormalized paths.
    assert_eq!(
        decode_error(&valid_manifest_json(
            ID,
            1,
            &format!(
                "{},{}",
                one_source("/w/a.toml", H1, &approval(H1, 1, 1)),
                one_source("/w/a.toml", H2, &approval(H2, 1, 1))
            )
        )),
        DecodeFailure::Invalid("a duplicate source path")
    );
    assert_eq!(
        decode_error(&valid_manifest_json(
            ID,
            1,
            &one_source("/w//a.toml", H1, &approval(H1, 1, 1))
        )),
        DecodeFailure::Invalid("a source path is not normalized absolute UTF-8")
    );
    // Duplicate hash, active not approved, empty approved, negative clocks.
    assert_eq!(
        decode_error(&valid_manifest_json(
            ID,
            1,
            &one_source(
                "/w/a.toml",
                H1,
                &format!("{},{}", approval(H1, 1, 1), approval(H1, 2, 2))
            )
        )),
        DecodeFailure::Invalid("a source repeats an approved digest")
    );
    assert_eq!(
        decode_error(&valid_manifest_json(
            ID,
            1,
            &one_source("/w/a.toml", H2, &approval(H1, 1, 1))
        )),
        DecodeFailure::Invalid("a source's active hash is not one of its approved digests")
    );
    assert_eq!(
        decode_error(&valid_manifest_json(
            ID,
            1,
            &one_source("/w/a.toml", H1, "")
        )),
        DecodeFailure::Invalid("a source has no approved digests")
    );
    assert_eq!(
        decode_error(&valid_manifest_json(
            ID,
            1,
            &one_source("/w/a.toml", H1, &approval(H1, -1, 1))
        )),
        DecodeFailure::Invalid("an approval clock is negative")
    );
    let seventeen = (0..17)
        .map(|index| approval(&format!("{index:064x}"), 1, 1))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        decode_error(&valid_manifest_json(
            ID,
            1,
            &one_source("/w/a.toml", &format!("{:064x}", 0), &seventeen)
        )),
        DecodeFailure::Invalid("a source has more than 16 approved digests")
    );

    // The store bound is its own number, distinct from the declaration bound.
    assert_eq!(MAX_PINNED_KEYS, 64);
    assert_eq!(crate::config_sources::MAX_DECLARED_SOURCES, 32);
    assert_ne!(MAX_PINNED_KEYS, crate::config_sources::MAX_DECLARED_SOURCES);
    let sixty_five = (0..65)
        .map(|index| one_source(&format!("/w/{index}.toml"), H1, &approval(H1, 1, 1)))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        decode_error(&valid_manifest_json(ID, 1, &sixty_five)),
        DecodeFailure::Invalid("more than 64 pinned source keys")
    );
    // Exactly 64 is accepted, so the refusal is the bound and not something else.
    let sixty_four = (0..64)
        .map(|index| one_source(&format!("/w/{index}.toml"), H1, &approval(H1, 1, 1)))
        .collect::<Vec<_>>()
        .join(",");
    let current = Current::decode(valid_manifest_json(ID, 1, &sixty_four).as_bytes()).unwrap();
    assert_eq!(current.sources().len(), 64);
}

// ---- V7: the pure state machine ----

fn state_with(approvals: Vec<Approval>, active: ContentHash) -> KeyState {
    KeyState {
        active,
        approved: approvals,
    }
}

#[test]
fn the_pure_state_machine_approves_switches_and_never_resurrects() {
    let generation = LiveGeneration {
        store_id: StoreId::parse_hex(ID).unwrap(),
        reset_epoch: 1,
    };
    let mut current = Current::empty(generation);
    let k = key("/w/a.toml");
    let digest = hash(b"foo\n");
    let batch = CommitBatch {
        approve: vec![ApprovalCandidate {
            key: k.clone(),
            hash: digest,
            bytes: b"foo\n".to_vec(),
            activate: true,
        }],
        activate: Vec::new(),
        retained_keys: vec![k.clone()],
    };
    let receipts = current.apply_batch(&batch, 10).unwrap();
    assert_eq!(receipts[0].kind, ReceiptKind::Approved);
    assert_eq!(
        current.lookup(&k, &digest),
        Lookup::Approved { active: true }
    );
    assert_eq!(
        current.lookup(&k, &hash(b"bar\n")),
        Lookup::Unapproved(PendingReason::Changed {
            last_active: digest
        })
    );
    assert_eq!(
        current.lookup(&key("/w/b.toml"), &digest),
        Lookup::Unapproved(PendingReason::NeverApproved)
    );

    // Idempotent re-approval: no clock moves, no state change.
    let before = current.clone();
    let receipts = current.apply_batch(&batch, 99).unwrap();
    assert_eq!(receipts[0].kind, ReceiptKind::AlreadyApproved);
    assert_eq!(current, before);

    // A missing key or an unapproved digest is never recreated by activation.
    assert!(!current.mark_active(&key("/w/missing.toml"), &digest, 100));
    assert!(!current.mark_active(&k, &hash(b"bar\n"), 100));
}

#[test]
fn eviction_chooses_the_least_recently_active_and_protects_the_batch() {
    let mut approvals = Vec::new();
    for index in 0..16_u8 {
        approvals.push(Approval {
            hash: ContentHash::of(&[index]),
            approved_ms: 100 + i64::from(index),
            active_ms: if index == 0 {
                1
            } else {
                200 + i64::from(index)
            },
        });
    }
    let active = approvals[0].hash;
    let mut state = state_with(approvals, active);
    let mut current = Current {
        generation: LiveGeneration {
            store_id: StoreId::parse_hex(ID).unwrap(),
            reset_epoch: 1,
        },
        sources: std::collections::BTreeMap::new(),
    };
    current.sources.insert(key("/w/a.toml"), state.clone());
    let new_digest = ContentHash::of(&[99]);
    let batch = CommitBatch {
        approve: vec![ApprovalCandidate {
            key: key("/w/a.toml"),
            hash: new_digest,
            bytes: vec![99],
            activate: true,
        }],
        activate: Vec::new(),
        retained_keys: vec![key("/w/a.toml")],
    };
    current.apply_batch(&batch, 1000).unwrap();
    state = current.key_state(&key("/w/a.toml")).unwrap().clone();
    assert_eq!(state.approved.len(), 16);
    assert!(state.is_approved(&new_digest));
    assert_eq!(state.active, new_digest, "the batch digest activates");
    // Eviction protects the digest that is active *now* and the batch: the old
    // active digest (active_ms 1) is the least recently active and is gone;
    // its better-used peers survive.
    assert!(!state.is_approved(&active));
    assert!(state.is_approved(&ContentHash::of(&[1])));
    assert!(state.is_approved(&ContentHash::of(&[2])));
}

#[test]
fn a_full_store_evicts_only_a_non_retained_historical_key() {
    let generation = LiveGeneration {
        store_id: StoreId::parse_hex(ID).unwrap(),
        reset_epoch: 1,
    };
    let mut current = Current::empty(generation);
    for index in 0..64_u64 {
        let digest = ContentHash::of(&index.to_le_bytes());
        current.sources.insert(
            key(&format!("/w/{index}.toml")),
            KeyState {
                active: digest,
                approved: vec![Approval {
                    hash: digest,
                    approved_ms: index as i64,
                    active_ms: index as i64,
                }],
            },
        );
    }
    let new_key = key("/w/new.toml");
    let retained: Vec<PinKey> = (1..64)
        .map(|index| key(&format!("/w/{index}.toml")))
        .collect();
    let batch = CommitBatch {
        approve: vec![ApprovalCandidate {
            key: new_key.clone(),
            hash: ContentHash::of(b"new"),
            bytes: b"new".to_vec(),
            activate: true,
        }],
        activate: Vec::new(),
        retained_keys: retained.clone(),
    };
    current.apply_batch(&batch, 1000).unwrap();
    assert_eq!(current.sources().len(), 64);
    assert!(current.key_state(&new_key).is_some());
    assert!(current.key_state(&key("/w/0.toml")).is_none());
    for retained_key in retained {
        assert!(current.key_state(&retained_key).is_some());
    }
}

// ---- V5/V10: directory and file trust ----

#[test]
fn an_absent_store_is_absent_and_a_writable_store_directory_is_refused() {
    let f = Fixture::new();
    // No store directory at all: no project config could have named a source.
    assert_eq!(f.observe().store_dir_id, None);
    assert!(matches!(
        f.observe().state,
        ObservedStoreState::Absent { lock: None }
    ));

    let dir = f.create_store_dir();
    assert!(matches!(
        f.observe().state,
        ObservedStoreState::Absent { lock: None }
    ));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Untrusted(AuthorityRefusal::DirWritable)
    ));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    // A symlinked store directory is not a directory this module descends into.
    let moved = f.base_path().join("moved-store");
    std::fs::rename(&dir, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &dir).unwrap();
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Untrusted(AuthorityRefusal::DirNotDirectory)
    ));
}

#[test]
fn pins_json_is_verified_directory_first_and_never_through_a_link() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    let pins = dir.join(PINS_FILE);

    std::fs::write(&pins, b"{").unwrap();
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Damaged(Damage::Undecodable)
    ));

    std::fs::remove_file(&pins).unwrap();
    std::fs::create_dir(&pins).unwrap();
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Damaged(Damage::NotAFile(kind)) if kind.is_dir()
    ));
    std::fs::remove_dir(&pins).unwrap();

    let target = f.base_path().join("pins-target.json");
    std::fs::write(&target, b"{}").unwrap();
    std::os::unix::fs::symlink(&target, &pins).unwrap();
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Untrusted(AuthorityRefusal::ThroughSymlink)
    ));
    std::fs::remove_file(&pins).unwrap();

    std::fs::write(&pins, b"{}").unwrap();
    let alias = f.base_path().join("pins-alias.json");
    std::fs::hard_link(&pins, &alias).unwrap();
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Untrusted(AuthorityRefusal::FileLinks(2))
    ));
    std::fs::remove_file(&alias).unwrap();
    // 0644 is admitted (mode 0600 is not required); 0620 is not.
    std::fs::set_permissions(&pins, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Damaged(Damage::Undecodable)
    ));
    std::fs::set_permissions(&pins, std::fs::Permissions::from_mode(0o620)).unwrap();
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Untrusted(AuthorityRefusal::FileWritable)
    ));
}

#[test]
fn read_only_manifests_are_admitted_and_an_untrusted_directory_creates_no_lock() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    let pins = dir.join(PINS_FILE);
    std::fs::write(
        &pins,
        valid_manifest_json(ID, 1, &one_source("/w/a.toml", H1, &approval(H1, 1, 1))),
    )
    .unwrap();
    std::fs::set_permissions(&pins, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(matches!(
        f.observe().state,
        ObservedStoreState::Existing { .. }
    ));

    // A writer refuses an untrusted store directory before creating its lock.
    let observed = ObservedStore {
        store_dir_id: Some(identity_of(&dir)),
        state: ObservedStoreState::Absent { lock: None },
    };
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let error = f
        .store()
        .update(&observed, &CommitBatch::default(), 1)
        .unwrap_err();
    assert!(matches!(
        error,
        WriteError::Untrusted(AuthorityRefusal::DirWritable)
    ));
    assert!(!f.lock_path().exists(), "no lock was created");
}

#[test]
fn a_damaged_manifest_leaves_bytes_inode_and_mtime_untouched() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    let pins = dir.join(PINS_FILE);
    std::fs::write(&pins, b"{\"v\":1,\"truncated\":").unwrap();
    std::fs::set_permissions(&pins, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::metadata(&pins).unwrap();
    let observed = ObservedStore {
        store_dir_id: Some(identity_of(&dir)),
        state: ObservedStoreState::Absent { lock: None },
    };
    let error = f
        .store()
        .update(&observed, &CommitBatch::default(), 1)
        .unwrap_err();
    assert!(matches!(error, WriteError::Damaged(Damage::Undecodable)));
    let after = std::fs::metadata(&pins).unwrap();
    assert_eq!(
        (
            before.ino(),
            before.mtime(),
            before.mtime_nsec(),
            before.size()
        ),
        (after.ino(), after.mtime(), after.mtime_nsec(), after.size())
    );
    assert_eq!(std::fs::read(&pins).unwrap(), b"{\"v\":1,\"truncated\":");
}

fn identity_of(path: &Path) -> crate::host_paths::FileIdentity {
    let metadata = std::fs::metadata(path).unwrap();
    crate::host_paths::FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

// ---- V8: commit, recovery table, and post-publish finalization ----

#[test]
fn a_first_commit_writes_the_hand_written_manifest_snapshot_and_live_header() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    let outcome = f.commit("/w/a.toml", b"foo\n", 1000);
    assert_eq!(outcome.receipts[0].kind, ReceiptKind::Approved);
    let generation = outcome.generation;
    assert_eq!(generation.reset_epoch, 1);

    let expected = format!(
        concat!(
            r#"{{"v":1,"store_id":"{}","reset_epoch":1,"sources":["#,
            r#"{{"path":"/w/a.toml","active":"{}","approved":["#,
            r#"{{"sha256":"{}","approved_ms":1000,"active_ms":1000}}"#,
            r#"]}}]}}"#
        ),
        generation.store_id.hex(),
        H1,
        H1
    );
    assert_eq!(std::fs::read_to_string(f.pins_path()).unwrap(), expected);
    assert_eq!(
        std::fs::read(f.snapshot_path(generation, b"foo\n")).unwrap(),
        b"foo\n"
    );
    assert_eq!(
        std::fs::read(f.lock_path()).unwrap(),
        encode_lock_header(&LockHeader::Live(generation))
    );

    let observed = f.observe();
    assert_eq!(observed.store_dir_id, Some(identity_of(&dir)));
    assert_eq!(
        observed.state,
        ObservedStoreState::Existing {
            generation,
            lock_id: Some(identity_of(&f.lock_path()))
        }
    );
}

#[test]
fn a_never_created_store_diffs_against_an_empty_baseline() {
    let f = Fixture::new();
    f.create_store_dir();
    let observed = f.observe();
    let diff = f
        .store()
        .read_for_diff(
            &observed,
            &[DiffRequest {
                key: &key("/w/a.toml"),
                candidate: b"foo\n",
            }],
        )
        .unwrap();
    assert!(diff.current.sources().is_empty());
    assert!(diff.snapshots.is_empty());
    assert!(diff.unavailable.is_empty());
}

#[test]
fn a_rotating_header_with_an_absent_manifest_is_interrupted_not_absent() {
    let f = Fixture::new();
    f.create_store_dir();
    let next = LiveGeneration {
        store_id: StoreId::parse_hex("11111111111111111111111111111111").unwrap(),
        reset_epoch: 2,
    };
    f.write_lock_record(&LockHeader::Rotating { prev: None, next });
    assert!(matches!(
        f.store().observe().unwrap_err(),
        Problem::Damaged(Damage::InterruptedRotation)
    ));
    // The read-only diff path refuses too, and creates no manifest.
    assert!(!f.pins_path().exists());
}

#[test]
fn a_corrupt_lock_header_fails_closed() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    for body in [
        b"garbage\n".to_vec(),
        vec![b'x'; MAX_LOCK_HEADER_BYTES + 1],
        b"v=1 state=rotating\n".to_vec(),
        b"v=1 state=live id=short epoch=1\n".to_vec(),
    ] {
        std::fs::write(dir.join(LOCK_FILE), &body).unwrap();
        std::fs::set_permissions(dir.join(LOCK_FILE), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(
            matches!(
                f.store().observe().unwrap_err(),
                Problem::Damaged(Damage::CorruptLockHeader)
            ),
            "{body:?}"
        );
    }
}

#[test]
fn a_crashed_post_rename_finalization_is_committed_with_a_warning() {
    let f = Fixture::new();
    f.create_store_dir();
    let observed = f.observe();
    let mut store = f.store();
    store.faults.fail_finalize = true;
    let key = key("/w/a.toml");
    let batch = CommitBatch {
        approve: vec![ApprovalCandidate {
            key: key.clone(),
            hash: hash(b"foo\n"),
            bytes: b"foo\n".to_vec(),
            activate: true,
        }],
        activate: Vec::new(),
        retained_keys: vec![key],
    };
    let outcome = store.update(&observed, &batch, 1000).unwrap();
    assert!(f.pins_path().exists(), "the manifest is committed");
    assert_eq!(outcome.receipts.len(), 1);
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("approvals were recorded")),
        "{:?}",
        outcome.warnings
    );
    // The stored approvals are real: a load sees them even before recovery.
    assert!(matches!(
        f.observe().state,
        ObservedStoreState::Existing { .. }
    ));
    // A later writer rolls the header forward, and an idempotent commit still
    // performs that recovery.
    f.commit("/w/a.toml", b"foo\n", 2000);
    let Observation::Live = Observation::of(f.store().observe().unwrap().state) else {
        panic!("the header was finalized");
    };
}

enum Observation {
    Live,
    Other,
}

impl Observation {
    fn of(state: ObservedStoreState) -> Self {
        match state {
            ObservedStoreState::Existing { .. } => Self::Live,
            _ => Self::Other,
        }
    }
}

#[test]
fn a_post_rename_rotation_header_is_rolled_forward_by_the_next_writer() {
    let f = Fixture::new();
    f.create_store_dir();
    let outcome = f.commit("/w/a.toml", b"foo\n", 1000);
    let generation = outcome.generation;
    let other = LiveGeneration {
        store_id: StoreId::parse_hex("22222222222222222222222222222222").unwrap(),
        reset_epoch: 2,
    };
    // Staged, then the manifest rename happened: committed as the next
    // generation, and the next writer rolls the header forward.
    f.write_lock_record(&LockHeader::Rotating {
        prev: Some(other),
        next: generation,
    });
    assert!(matches!(
        f.observe().state,
        ObservedStoreState::Existing {
            generation: observed,
            ..
        } if observed == generation
    ));
    assert!(f.store().read_for_diff(&f.observe(), &[]).is_ok());
    let observed = f.observe();
    let batch = CommitBatch {
        approve: Vec::new(),
        activate: vec![(key("/w/a.toml"), hash(b"foo\n"))],
        retained_keys: vec![key("/w/a.toml")],
    };
    f.store().update(&observed, &batch, 2000).unwrap();
    assert_eq!(
        f.store().observe().unwrap().state,
        ObservedStoreState::Existing {
            generation,
            lock_id: Some(identity_of(&f.lock_path())),
        }
    );
    // The other interruption: staged, rename did not happen. A writer refuses.
    f.write_lock_record(&LockHeader::Rotating {
        prev: Some(generation),
        next: other,
    });
    let error = f
        .store()
        .update(&f.observe(), &CommitBatch::default(), 3000)
        .unwrap_err();
    assert!(
        matches!(error, WriteError::InterruptedRotation),
        "{error:?}"
    );
}

#[test]
fn reset_rotates_the_generation_keeps_the_lock_inode_and_fences_stale_reviews() {
    let f = Fixture::new();
    f.create_store_dir();
    let outcome = f.commit("/w/a.toml", b"foo\n", 1000);
    let before = std::fs::metadata(f.lock_path()).unwrap();
    let observed = f.observe();
    let reset = f.store().reset(ResetMode::Normal).unwrap();
    assert!(reset.generation.reset_epoch >= 2);
    assert!(reset.warnings.is_empty());
    assert!(reset.cleanup_complete);
    assert_ne!(reset.generation.store_id, outcome.generation.store_id);
    let after = std::fs::metadata(f.lock_path()).unwrap();
    assert_eq!(before.ino(), after.ino(), "pins.lock keeps its inode");
    assert_eq!(
        std::fs::read(f.lock_path()).unwrap(),
        encode_lock_header(&LockHeader::Live(reset.generation))
    );

    // Stale review: a commit from the pre-reset observation cannot land.
    let error = f
        .store()
        .update(&observed, &CommitBatch::default(), 2000)
        .unwrap_err();
    assert!(
        matches!(
            error,
            WriteError::ResetConflict | WriteError::IncarnationChanged
        ),
        "{error:?}"
    );
    // Old snapshots never match the new generation.
    assert_eq!(
        f.store()
            .read_snapshot(outcome.generation.store_id, &hash(b"foo\n"))
            .unwrap_err(),
        Unavailable::Missing
    );
    // Historical keys are gone from the manifest; the reset is empty.
    assert!(
        f.store()
            .observe()
            .and_then(|observed| match observed.state {
                ObservedStoreState::Existing { generation, .. } => Ok(generation),
                _ => Err(Problem::Displaced),
            })
            .unwrap()
            == reset.generation
    );
}

#[test]
fn reset_force_repairs_a_corrupt_header_and_bumps_past_u64_max() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    std::fs::write(dir.join(LOCK_FILE), b"not a header\n").unwrap();
    std::fs::set_permissions(dir.join(LOCK_FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
    let reset = f.store().reset(ResetMode::Force).unwrap();
    assert!(reset.generation.reset_epoch >= 2);
    assert!(matches!(
        f.store().observe().unwrap().state,
        ObservedStoreState::Existing { .. }
    ));

    // `u64::MAX` cannot be incremented: reset fails closed and leaves bytes.
    let max = LiveGeneration {
        store_id: StoreId::parse_hex(ID).unwrap(),
        reset_epoch: u64::MAX,
    };
    let manifest = Current::empty(max).encode().unwrap();
    std::fs::write(f.pins_path(), &manifest).unwrap();
    f.write_lock_record(&LockHeader::Live(max));
    let error = f.store().reset(ResetMode::Normal).unwrap_err();
    assert!(matches!(error, WriteError::EpochExhausted), "{error:?}");
    assert_eq!(std::fs::read(f.pins_path()).unwrap(), manifest);
}

// ---- V9/V12: idempotence and snapshot integrity ----

#[test]
fn reapproving_the_active_digest_leaves_the_manifest_inode_and_mtime_alone() {
    let f = Fixture::new();
    f.create_store_dir();
    f.commit("/w/a.toml", b"foo\n", 1000);
    let before = std::fs::metadata(f.pins_path()).unwrap();
    let outcome = f.commit("/w/a.toml", b"foo\n", 2000);
    assert_eq!(outcome.receipts[0].kind, ReceiptKind::AlreadyApproved);
    let after = std::fs::metadata(f.pins_path()).unwrap();
    assert_eq!(
        (
            before.ino(),
            before.mtime(),
            before.mtime_nsec(),
            before.size()
        ),
        (after.ino(), after.mtime(), after.mtime_nsec(), after.size())
    );
}

#[test]
fn a_tampered_snapshot_is_unavailable_and_never_authorization() {
    let f = Fixture::new();
    f.create_store_dir();
    let outcome = f.commit("/w/a.toml", b"foo\n", 1000);
    let snapshot = f.snapshot_path(outcome.generation, b"foo\n");
    std::fs::write(&snapshot, b"bar\n").unwrap();
    assert_eq!(
        f.store()
            .read_snapshot(outcome.generation.store_id, &hash(b"foo\n"))
            .unwrap_err(),
        Unavailable::HashMismatch
    );
    let observed = f.observe();
    // The review asks about an unapproved candidate, so its baseline (the
    // approved `foo`) is the tampered snapshot.
    let diff = f
        .store()
        .read_for_diff(
            &observed,
            &[DiffRequest {
                key: &key("/w/a.toml"),
                candidate: b"bar\n",
            }],
        )
        .unwrap();
    assert_eq!(diff.generation, outcome.generation);
    assert!(diff.snapshots.is_empty());
    assert_eq!(
        diff.unavailable.get(&hash(b"foo\n")),
        Some(&Unavailable::HashMismatch)
    );
    // The manifest still says the digest is approved: the snapshot is a review
    // baseline, not the approval.
    assert_eq!(
        diff.current.lookup(&key("/w/a.toml"), &hash(b"foo\n")),
        Lookup::Approved { active: true }
    );
}

#[test]
fn a_non_replaceable_snapshot_target_fails_before_the_manifest_rename() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    let observed = f.observe();
    // A directory occupies the content-addressed name the first commit needs.
    let store_id = LiveGeneration {
        store_id: StoreId::parse_hex(ID).unwrap(),
        reset_epoch: 1,
    };
    let _ = store_id;
    let outcome = f.commit_observed(&observed, "/w/a.toml", b"foo\n", 1000);
    let generation = outcome.generation;
    // A new digest needs a new snapshot; its name is occupied.
    std::fs::create_dir(f.snapshot_path(generation, b"bar\n")).unwrap();
    let before = std::fs::read(f.pins_path()).unwrap();
    let batch = CommitBatch {
        approve: vec![ApprovalCandidate {
            key: key("/w/a.toml"),
            hash: hash(b"bar\n"),
            bytes: b"bar\n".to_vec(),
            activate: true,
        }],
        activate: Vec::new(),
        retained_keys: vec![key("/w/a.toml")],
    };
    let observed = f.observe();
    let error = f.store().update(&observed, &batch, 2000).unwrap_err();
    assert!(
        matches!(error, WriteError::SnapshotUnwritable(_)),
        "{error:?}"
    );
    assert_eq!(std::fs::read(f.pins_path()).unwrap(), before);
    let _ = dir;
}

// ---- Serialization: two commits against one store ----

#[test]
fn two_commits_against_one_store_serialize_on_the_lock() {
    let f = Fixture::new();
    f.create_store_dir();
    let observed = f.observe();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = f.store();
        let barrier = Arc::clone(&barrier);
        let key = key("/w/a.toml");
        handles.push(std::thread::spawn(move || {
            let batch = CommitBatch {
                approve: vec![ApprovalCandidate {
                    key: key.clone(),
                    hash: hash(b"foo\n"),
                    bytes: b"foo\n".to_vec(),
                    activate: true,
                }],
                activate: Vec::new(),
                retained_keys: vec![key],
            };
            barrier.wait();
            store.update(&observed, &batch, 1000).map(|outcome| {
                outcome
                    .receipts
                    .into_iter()
                    .map(|receipt| receipt.kind)
                    .collect::<Vec<_>>()
            })
        }));
    }
    let mut kinds: Vec<ReceiptKind> = handles
        .into_iter()
        .flat_map(|handle| handle.join().unwrap().unwrap())
        .collect();
    kinds.sort_by_key(|kind| *kind as u8);
    assert_eq!(
        kinds,
        vec![ReceiptKind::Approved, ReceiptKind::AlreadyApproved]
    );
    let manifest = f.store().observe().unwrap();
    assert!(matches!(
        manifest.state,
        ObservedStoreState::Existing { .. }
    ));
    // One key, one approval: the second writer read the first's commit.
    let diff = f
        .store()
        .read_for_diff(
            &manifest,
            &[DiffRequest {
                key: &key("/w/a.toml"),
                candidate: b"foo\n",
            }],
        )
        .unwrap();
    assert_eq!(diff.current.sources().len(), 1);
    assert_eq!(
        diff.current
            .key_state(&key("/w/a.toml"))
            .unwrap()
            .approved
            .len(),
        1
    );
}

// ---- Bounded sweep ----

#[test]
fn the_sweep_removes_unreferenced_snapshots_and_abandoned_temporaries_only() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    let outcome = f.commit("/w/a.toml", b"foo\n", 1000);
    let generation = outcome.generation;
    // A referenced snapshot and an unreferenced one, a temporary, and a file a
    // reset or another writer would never own.
    let live = f.snapshot_path(generation, b"foo\n");
    let orphan = dir.join(snapshot_name(
        StoreId::parse_hex(ID).unwrap(),
        &hash(b"bar\n"),
    ));
    std::fs::write(&orphan, b"bar\n").unwrap();
    let temp = dir.join(format!("{PIN_TMP_PREFIX}deadbeef"));
    std::fs::write(&temp, b"partial").unwrap();
    let keep = dir.join("notes.txt");
    std::fs::write(&keep, b"keep").unwrap();

    f.commit("/w/b.toml", b"baz\n", 2000);
    assert!(live.exists());
    assert!(!orphan.exists(), "an unreferenced snapshot is swept");
    assert!(!temp.exists(), "an abandoned pin temporary is swept");
    assert!(keep.exists(), "unrelated entries are never touched");
}

// ---- Diagnostics read every field without ever echoing bytes ----

#[test]
fn diagnostics_are_one_line_and_never_echo_stored_bytes() {
    for refusal in [
        KeyRefusal::NotUtf8,
        KeyRefusal::NotNormalized,
        KeyRefusal::TooLong,
        KeyRefusal::Control,
    ] {
        assert!(refusal.clause().contains("cannot pin it"), "{refusal:?}");
    }
    for reason in [
        Unavailable::Missing,
        Unavailable::NotTrusted(AuthorityRefusal::ThroughSymlink),
        Unavailable::NotAFile,
        Unavailable::TooLarge,
        Unavailable::NotUtf8,
        Unavailable::HashMismatch,
        Unavailable::Unreadable("EIO".to_owned()),
    ] {
        let text = reason.reason();
        assert!(!text.contains('\n'), "{text}");
    }
    for problem in [
        Problem::Untrusted(AuthorityRefusal::FileWritable),
        Problem::Damaged(Damage::TooLarge),
        Problem::Damaged(Damage::CorruptLockHeader),
        Problem::Newer { v: 2 },
        Problem::Unreadable("EIO".to_owned()),
        Problem::Unsettled,
        Problem::Displaced,
    ] {
        let text = problem.line();
        assert!(!text.is_empty() && !text.contains('\n'), "{text}");
    }
    for error in [
        WriteError::NoStore,
        WriteError::Untrusted(AuthorityRefusal::DirWritable),
        WriteError::Damaged(Damage::Undecodable),
        WriteError::Newer { v: 2 },
        WriteError::Unreadable("EIO".to_owned()),
        WriteError::Unsettled,
        WriteError::Displaced,
        WriteError::LockBusy("busy".to_owned()),
        WriteError::IncarnationChanged,
        WriteError::ResetConflict,
        WriteError::InterruptedRotation,
        WriteError::EpochExhausted,
        WriteError::BatchStale,
        WriteError::Full,
        WriteError::SnapshotUnwritable("dir".to_owned()),
        WriteError::SnapshotMismatch,
    ] {
        let text = error.line();
        assert!(!text.is_empty() && !text.contains('\n'), "{text}");
    }
}

// ---- Schema encode bounds ----

#[test]
fn encoding_enforces_the_key_and_approval_caps() {
    let generation = LiveGeneration {
        store_id: StoreId::parse_hex(ID).unwrap(),
        reset_epoch: 1,
    };
    let mut current = Current::empty(generation);
    for index in 0..65_u64 {
        let digest = ContentHash::of(&index.to_le_bytes());
        current.sources.insert(
            key(&format!("/w/{index}.toml")),
            KeyState {
                active: digest,
                approved: vec![Approval {
                    hash: digest,
                    approved_ms: 1,
                    active_ms: 1,
                }],
            },
        );
    }
    assert_eq!(current.encode().unwrap_err(), EncodeFailure::TooManyKeys);
}

// ---- V13/B7: the review's baseline, decided at the store boundary ----
//
// The renderer itself is tested in `diff::tests` without a store. What these two
// rows pin down is which *hash* the renderer is handed: the `active` one in the
// manifest read under the diff's `LOCK_SH`, never the pre-lock inspection's
// reason and never the newest snapshot.

fn review(state: &DiffState, path: &str, candidate: &[u8]) -> String {
    let key = key(path);
    let source = super::PendingSource::for_tests(key, candidate.to_vec());
    let pending = diff::PendingReview::of(&source, state);
    diff::render_review(std::slice::from_ref(&pending)).expect("the fixture is within every cap")
}

fn set_mtime(path: &Path, seconds: u64) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds))
        .unwrap();
}

#[test]
fn a_branch_switch_reviews_against_the_recorded_active_version_not_the_newest_snapshot() {
    let f = Fixture::new();
    f.create_store_dir();
    let (a, b, c) = (b"v = \"a\"\n", b"v = \"b\"\n", b"v = \"c\"\n");
    f.commit("/w/a.toml", a, 1_000);
    let generation = f.commit("/w/a.toml", b, 2_000).generation;
    // A -> B -> A: A is active again, while B's snapshot is physically newer.
    f.commit("/w/a.toml", a, 3_000);
    let (snapshot_a, snapshot_b) = (
        f.snapshot_path(generation, a),
        f.snapshot_path(generation, b),
    );
    set_mtime(&snapshot_a, 1_000_000);
    set_mtime(&snapshot_b, 2_000_000);
    assert!(
        std::fs::metadata(&snapshot_b).unwrap().mtime()
            > std::fs::metadata(&snapshot_a).unwrap().mtime()
    );

    let observed = f.observe();
    let state = f
        .store()
        .read_for_diff(
            &observed,
            &[DiffRequest {
                key: &key("/w/a.toml"),
                candidate: c,
            }],
        )
        .unwrap();
    assert_eq!(
        state.current.key_state(&key("/w/a.toml")).unwrap().active,
        hash(a)
    );
    let rendered = review(&state, "/w/a.toml", c);
    assert!(
        rendered.contains(&format!("--- /w/a.toml\t(last approved {})\n", hash(a))),
        "{rendered}"
    );
    assert!(rendered.contains("-v = \"a\"\n"), "{rendered}");
    assert!(!rendered.contains("-v = \"b\"\n"), "{rendered}");
    assert!(rendered.contains("+v = \"c\"\n"), "{rendered}");
}

/// The store boundary's half of B7: the locked read reports the refreshed
/// active digest. That a *production* review fetches that digest is pinned by
/// `pins_cmd::tests::a_peer_update_before_the_locked_read_reviews_against_the_new_active_digest`:
/// this row hands the read its request directly, so it cannot see a caller that
/// passes the wrong keys.
#[test]
fn a_peer_that_changes_the_active_digest_between_inspection_and_the_locked_read_sets_the_baseline()
{
    let f = Fixture::new();
    f.create_store_dir();
    let (a, b, c) = (b"v = 1\n", b"v = 2\n", b"v = 3\n");
    f.commit("/w/a.toml", a, 1_000);

    // Inspection: A is active, so C is pending "changed since A".
    let inspected = f.observe();
    let stale = f
        .store()
        .read_for_diff(
            &inspected,
            &[DiffRequest {
                key: &key("/w/a.toml"),
                candidate: c,
            }],
        )
        .unwrap()
        .current
        .lookup(&key("/w/a.toml"), &hash(c));
    assert_eq!(
        stale,
        Lookup::Unapproved(PendingReason::Changed {
            last_active: hash(a)
        })
    );

    // A peer approves B and makes it active, without resetting the store: the
    // observation taken before the commit still names the same generation.
    f.commit_observed(&inspected, "/w/a.toml", b, 2_000);

    // The review's own locked read sees the refreshed active digest, and the
    // diff describes B even though the inspection said A.
    let state = f
        .store()
        .read_for_diff(
            &inspected,
            &[DiffRequest {
                key: &key("/w/a.toml"),
                candidate: c,
            }],
        )
        .unwrap();
    assert_eq!(
        state.current.key_state(&key("/w/a.toml")).unwrap().active,
        hash(b)
    );
    let rendered = review(&state, "/w/a.toml", c);
    assert!(
        rendered.contains(&format!("--- /w/a.toml\t(last approved {})\n", hash(b))),
        "{rendered}"
    );
    assert!(rendered.contains("-v = 2\n"), "{rendered}");
    assert!(!rendered.contains("-v = 1\n"), "{rendered}");
    assert!(rendered.contains("+v = 3\n"), "{rendered}");
}

// ---- The observation's lock identity is the fence ----
//
// `pins.lock` is a permanent inode *and* the thing two writers serialize on.
// Verifying only that an opened descriptor is still the live name proves
// nothing about *which* inode was reviewed: a replaced lock is accepted, and a
// writer that got its lock first can be joined by a second writer holding the
// replacement. Both come back here.

/// The replacement interleaving: the observation recorded one `pins.lock`
/// inode and a different, perfectly valid one now carries the name.
#[test]
fn a_replaced_lock_inode_is_not_the_observed_lock() {
    let f = Fixture::new();
    f.create_store_dir();
    let generation = f.commit("/w/a.toml", b"foo\n", 1000).generation;
    let observed = f.observe();
    let ObservedStoreState::Existing {
        lock_id: Some(observed_lock),
        ..
    } = observed.state
    else {
        panic!("the observation recorded the lock inode");
    };
    // A valid replacement: same live header, same mode, a new inode.
    std::fs::rename(f.lock_path(), f.base_path().join("pins.lock.replaced")).unwrap();
    f.write_lock_record(&LockHeader::Live(generation));
    assert_ne!(identity_of(&f.lock_path()), observed_lock);
    let before = std::fs::read(f.pins_path()).unwrap();

    // The diff's baseline must not come from a lock the review never saw.
    let error = f
        .store()
        .read_for_diff(
            &observed,
            &[DiffRequest {
                key: &key("/w/a.toml"),
                candidate: b"foo\n",
            }],
        )
        .unwrap_err();
    assert!(matches!(error, Problem::Displaced), "{error:?}");

    // Nor may the commit land in it.
    let batch = CommitBatch {
        approve: vec![ApprovalCandidate {
            key: key("/w/a.toml"),
            hash: hash(b"bar\n"),
            bytes: b"bar\n".to_vec(),
            activate: true,
        }],
        activate: Vec::new(),
        retained_keys: vec![key("/w/a.toml")],
    };
    let error = f.store().update(&observed, &batch, 2000).unwrap_err();
    assert!(matches!(error, WriteError::IncarnationChanged), "{error:?}");
    assert_eq!(
        std::fs::read(f.pins_path()).unwrap(),
        before,
        "nothing was published"
    );
}

/// The split-lock interleaving: this writer holds the old inode; the name is
/// replaced, so a second writer locks the replacement concurrently, reads the
/// same manifest and publishes its own next one. The writer that no longer owns
/// the live lock must refuse rather than publish a second next manifest.
#[test]
fn a_lock_replaced_while_committing_cannot_publish_a_second_manifest() {
    let f = Fixture::new();
    let dir = f.create_store_dir();
    let generation = f.commit("/w/a.toml", b"foo\n", 1000).generation;
    let observed = f.observe();
    let reviewer_key = key("/w/a.toml");
    let batch = CommitBatch {
        approve: vec![ApprovalCandidate {
            key: reviewer_key.clone(),
            hash: hash(b"reviewed\n"),
            bytes: b"reviewed\n".to_vec(),
            activate: true,
        }],
        activate: Vec::new(),
        retained_keys: vec![reviewer_key.clone()],
    };
    let mut peer_published = false;
    let error = f
        .store()
        .update_checkpointed(&observed, &batch, 2000, |store_dir| {
            // The peer takes the permanent name while this writer still holds
            // the inode it locked, then locks its own inode and commits.
            std::fs::rename(
                store_dir.join(LOCK_FILE),
                f.base_path().join("pins.lock.lost"),
            )
            .unwrap();
            f.write_lock_record(&LockHeader::Live(generation));
            let peer = key("/w/b.toml");
            let peer_observed = f.observe();
            let peer_batch = CommitBatch {
                approve: vec![ApprovalCandidate {
                    key: peer.clone(),
                    hash: hash(b"peer\n"),
                    bytes: b"peer\n".to_vec(),
                    activate: true,
                }],
                activate: Vec::new(),
                retained_keys: vec![peer],
            };
            f.store().update(&peer_observed, &peer_batch, 2500).unwrap();
            peer_published = true;
        })
        .unwrap_err();
    assert!(peer_published, "the peer's commit is the interleaving");
    assert!(
        matches!(
            error,
            WriteError::Displaced | WriteError::IncarnationChanged
        ),
        "{error:?}"
    );
    let after = f.store().observe().unwrap();
    let state = f.store().read_for_diff(&after, &[]).unwrap();
    let reviewed = state
        .current
        .key_state(&reviewer_key)
        .expect("the first commit's key is still there");
    assert_eq!(
        reviewed.approved.len(),
        1,
        "the loser published no approval"
    );
    assert_eq!(reviewed.approved[0].hash, hash(b"foo\n"));
    assert!(
        state
            .current
            .key_state(&key("/w/b.toml"))
            .is_some_and(|state| state.approved.len() == 1),
        "the peer's next manifest is the one that landed"
    );
    let _ = dir;
}

// ---- A failed move-aside recreation must not wedge the store ----
//
// `live(G) + absent pins.json` is a supported, readable state (the manifest was
// moved aside). Recreating it stages `Rotating` before the snapshots, so a
// crash cannot publish a snapshot for an unpublished generation — but an
// ordinary error after that staging must return to `live(G)`, or every later
// reader reports `InterruptedRotation` and only a force reset can recover.

#[test]
fn a_failed_move_aside_recreation_leaves_a_readable_store() {
    /// Which ordinary failure the commit meets after staging the header.
    enum Failure {
        /// The target snapshot's name is occupied (injected: the recreation
        /// generates its store id inside the commit, so the real name cannot be
        /// predicted and a directory placed there).
        SnapshotNameOccupied,
        /// The manifest rename fails as it does on a full disk.
        NoSpace,
    }

    impl Failure {
        fn applied(&self, store: &mut PinStore) {
            match self {
                Self::SnapshotNameOccupied => store.faults.fail_snapshot = true,
                Self::NoSpace => store.faults.fail_publish = true,
            }
        }

        fn reported(&self, error: &WriteError) -> bool {
            match self {
                Self::SnapshotNameOccupied => {
                    matches!(error, WriteError::SnapshotUnwritable(_))
                }
                Self::NoSpace => matches!(error, WriteError::Unreadable(_)),
            }
        }
    }

    let f = Fixture::new();
    let dir = f.create_store_dir();
    let (a, b, c) = (b"v = 1\n", b"v = 2\n", b"v = 3\n");
    f.commit("/w/a.toml", a, 1_000);
    let generation = f.commit("/w/b.toml", b, 2_000).generation;
    let snapshots = [
        (f.snapshot_path(generation, a), a),
        (f.snapshot_path(generation, b), b),
    ];
    // The user moved the manifest aside; the store is readable and remembers
    // its generation.
    std::fs::rename(f.pins_path(), dir.join("pins.json.moved")).unwrap();
    let before = f.observe();
    assert!(
        matches!(
            before.state,
            ObservedStoreState::Absent {
                lock: Some(LockObservation {
                    header: LockHeader::Live(live),
                    ..
                })
            } if live == generation
        ),
        "{:?}",
        before.state
    );

    for failure in [Failure::SnapshotNameOccupied, Failure::NoSpace] {
        let mut store = f.store();
        failure.applied(&mut store);
        let batch = CommitBatch {
            approve: vec![ApprovalCandidate {
                key: key("/w/a.toml"),
                hash: hash(c),
                bytes: c.to_vec(),
                activate: true,
            }],
            activate: Vec::new(),
            retained_keys: vec![key("/w/a.toml")],
        };
        let observed = f.observe();
        let error = store.update(&observed, &batch, 3_000).unwrap_err();
        assert!(failure.reported(&error), "{error:?}");

        // The store a returned error leaves behind is readable, at the same
        // generation, with the manifest still absent and both snapshots whole.
        let after = f
            .store()
            .observe()
            .expect("a returned error leaves a readable store");
        assert_eq!(after.state, before.state, "the header was restored");
        assert!(!f.pins_path().exists(), "nothing was published");
        for (path, bytes) in &snapshots {
            assert_eq!(&std::fs::read(path).unwrap(), bytes);
        }
    }

    // A no-op commit in the same state returns without publishing; it must not
    // leave the staged record behind either.
    let noop = f
        .store()
        .update(&f.observe(), &CommitBatch::default(), 4_000)
        .unwrap();
    assert!(noop.receipts.is_empty());
    assert!(!f.pins_path().exists());
    assert_eq!(
        f.store().observe().unwrap().state,
        before.state,
        "a no-op commit unwinds its staged record too"
    );

    // Restoring the user's moved-aside manifest lands back in the store it was:
    // the header names the prior generation, so the pair is compatible and the
    // pre-existing approvals are intact and usable.
    std::fs::rename(dir.join("pins.json.moved"), f.pins_path()).unwrap();
    let restored = f.observe();
    let state = f
        .store()
        .read_for_diff(
            &restored,
            &[
                DiffRequest {
                    key: &key("/w/a.toml"),
                    candidate: c,
                },
                DiffRequest {
                    key: &key("/w/b.toml"),
                    candidate: b"v = 4\n",
                },
            ],
        )
        .unwrap();
    assert_eq!(state.generation, generation);
    assert_eq!(state.current.sources().len(), 2);
    assert!(state.snapshots.contains_key(&hash(a)));
    assert!(state.snapshots.contains_key(&hash(b)));
}

// ---- A batch that assumes an evicted approval must refuse ----
//
// `batch.activate` is the digest a load already used. The review assumed the
// manifest still approves it; a peer can evict it as the oldest inactive digest
// while the review is open. Committing the rest would report and persist success
// for a launch whose assumed approval is gone — the one reload then refuses.

#[test]
fn an_activation_that_assumes_an_unapproved_digest_is_stale() {
    let generation = LiveGeneration {
        store_id: StoreId::parse_hex(ID).unwrap(),
        reset_epoch: 1,
    };
    let mut current = Current::empty(generation);
    let batch = |activate: Vec<(PinKey, ContentHash)>| CommitBatch {
        approve: Vec::new(),
        activate,
        retained_keys: Vec::new(),
    };
    let assumed = hash(b"foo\n");
    assert!(matches!(
        current
            .apply_batch(&batch(vec![(key("/w/a.toml"), assumed)]), 1_000)
            .unwrap_err(),
        WriteError::BatchStale
    ));
    // Approved, so the same activation is not stale.
    current
        .apply_batch(
            &CommitBatch {
                approve: vec![ApprovalCandidate {
                    key: key("/w/a.toml"),
                    hash: assumed,
                    bytes: b"foo\n".to_vec(),
                    activate: true,
                }],
                activate: Vec::new(),
                retained_keys: vec![key("/w/a.toml")],
            },
            1_000,
        )
        .unwrap();
    current
        .apply_batch(&batch(vec![(key("/w/a.toml"), assumed)]), 2_000)
        .unwrap();
}

#[test]
fn a_concurrently_evicted_assumed_approval_refuses_the_whole_batch() {
    let f = Fixture::new();
    f.create_store_dir();
    let source_key = key("/w/a.toml");
    let bodies: Vec<Vec<u8>> = (0..=MAX_APPROVED_PER_SOURCE)
        .map(|index| format!("v = {index}\n").into_bytes())
        .collect();
    // H1 active, H2..H16 approved and inactive: the review's baseline is H1 and
    // every other digest is a candidate for eviction.
    for (index, body) in bodies[..MAX_APPROVED_PER_SOURCE].iter().enumerate() {
        let observed = f.observe();
        let batch = CommitBatch {
            approve: vec![ApprovalCandidate {
                key: source_key.clone(),
                hash: hash(body),
                bytes: body.clone(),
                activate: index == 0,
            }],
            activate: Vec::new(),
            retained_keys: vec![source_key.clone()],
        };
        f.store()
            .update(&observed, &batch, 1_000 + index as i64)
            .unwrap();
    }
    let reviewed = f.observe();
    let assumed = hash(&bodies[1]);
    assert_eq!(
        f.store()
            .read_for_diff(&reviewed, &[])
            .unwrap()
            .current
            .lookup(&source_key, &assumed),
        Lookup::Approved { active: false }
    );

    // The peer approves one more digest, which evicts the least recently active
    // one — the digest this review assumed.
    {
        let observed = f.observe();
        let batch = CommitBatch {
            approve: vec![ApprovalCandidate {
                key: source_key.clone(),
                hash: hash(&bodies[MAX_APPROVED_PER_SOURCE]),
                bytes: bodies[MAX_APPROVED_PER_SOURCE].clone(),
                activate: false,
            }],
            activate: Vec::new(),
            retained_keys: vec![source_key.clone()],
        };
        f.store().update(&observed, &batch, 2_000).unwrap();
    }
    let after_peer = f.observe();
    assert_eq!(
        f.store()
            .read_for_diff(&after_peer, &[])
            .unwrap()
            .current
            .lookup(&source_key, &assumed),
        Lookup::Unapproved(PendingReason::Changed {
            last_active: hash(&bodies[0])
        }),
        "the peer evicted the assumed digest"
    );
    let manifest_before = std::fs::read(f.pins_path()).unwrap();

    // The review commits a second source and activates the assumed digest.
    let second = key("/w/b.toml");
    let second_body = b"y = 1\n";
    let batch = CommitBatch {
        approve: vec![ApprovalCandidate {
            key: second.clone(),
            hash: hash(second_body),
            bytes: second_body.to_vec(),
            activate: true,
        }],
        activate: vec![(source_key.clone(), assumed)],
        retained_keys: vec![source_key.clone(), second.clone()],
    };
    let error = f.store().update(&reviewed, &batch, 3_000).unwrap_err();
    assert!(matches!(error, WriteError::BatchStale), "{error:?}");

    // Nothing from the batch survived: not the new approval, not the activation.
    assert_eq!(
        std::fs::read(f.pins_path()).unwrap(),
        manifest_before,
        "a stale batch publishes nothing"
    );
    let state = f.store().read_for_diff(&f.observe(), &[]).unwrap().current;
    assert!(state.key_state(&second).is_none());
    assert_eq!(
        state.key_state(&source_key).unwrap().active,
        hash(&bodies[0])
    );
    assert_eq!(
        state.key_state(&source_key).unwrap().approved.len(),
        MAX_APPROVED_PER_SOURCE
    );
}

// ---- The recovery advice preserves the store's invariants ----
//
// Two invariants the advice must not contradict: `pins.lock` is a permanent
// inode this build never unlinks, and this release ships no reset command. Every
// recovery line therefore names the manifest for a supported quiesced move-aside
// (or the backup-restore path) and says the lock is kept.

#[test]
fn recovery_advice_keeps_the_lock_and_names_no_missing_command() {
    let lines = [
        (
            "damaged manifest",
            Problem::Damaged(Damage::Undecodable).line(),
        ),
        (
            "interrupted rotation",
            Problem::Damaged(Damage::InterruptedRotation).line(),
        ),
        (
            "corrupt lock header",
            Problem::Damaged(Damage::CorruptLockHeader).line(),
        ),
        (
            "write refusal",
            WriteError::Damaged(Damage::Undecodable).line(),
        ),
        (
            "unfinished rotation",
            WriteError::InterruptedRotation.line(),
        ),
        ("exhausted epoch", WriteError::EpochExhausted.line()),
    ];
    for (name, line) in &lines {
        assert!(line.contains("quiesce"), "{name}: {line}");
        assert!(
            line.contains("pins.json"),
            "{name} names the manifest: {line}"
        );
        assert!(
            line.contains("keep `pins.lock`"),
            "{name} preserves the lock: {line}"
        );
        for forbidden in [
            "run a pin store reset",
            "delete pins.json",
            "reset this project's approvals",
            "remove `pins.lock`",
        ] {
            assert!(
                !line.contains(forbidden),
                "{name} must not say {forbidden:?}: {line}"
            );
        }
    }

    // The two classes keep their own supported remedy.
    assert!(
        lines[0].1.contains("move `pins.json` aside"),
        "a damaged manifest is moved aside: {}",
        lines[0].1
    );
    assert!(
        lines[1].1.contains("restore") && lines[1].1.contains("backup"),
        "an unfinished rotation is restored from backup: {}",
        lines[1].1
    );
}

// ---- B6/B2: pending and snapshot bytes never reach a debug or error path ----
//
// The review deliberately prints exact configuration text and the store
// deliberately keeps it in a snapshot (B6). Everything else must be byte-free:
// `Debug` output lands in backtraces, test output and crashes, and an error's
// `Debug` is what a panic prints. These rows put a sentinel in every carrier and
// prove that neither the ordinary nor the alternate form can carry it, while the
// deliberate review and the stored snapshot still do.

const SENTINEL: &str = "SENTINEL-736-PENDING-BYTES";

/// A pending source whose candidate is the sentinel.
fn sentinel_pending() -> PendingSource {
    let candidate = SENTINEL.as_bytes().to_vec();
    PendingSource {
        alias: SourceAlias::for_test("repo"),
        declared: Declaration::Entry(0),
        scope: SourceScope::External,
        allow: true,
        hash: ContentHash::of(&candidate),
        key: key("/w/sentinel.toml"),
        reason: PendingReason::NeverApproved,
        candidate,
    }
}

/// A pending source for the same key whose candidate is not the sentinel, so a
/// review renders the sentinel as its removed baseline.
fn sentinel_candidate() -> PendingSource {
    let mut pending = sentinel_pending();
    pending.key = key("/w/sentinel.toml");
    pending.candidate = b"a different candidate\n".to_vec();
    pending.hash = ContentHash::of(&pending.candidate);
    pending
}

/// Both `Debug` forms, so a `derive` that forwards to the alternate form cannot
/// hide a leak.
fn debug_forms(value: &impl std::fmt::Debug) -> String {
    format!("{value:?}\n{value:#?}")
}

/// The sentinel in the two spellings a byte-carrying `Debug` could use: the
/// literal text, and `Vec<u8>`'s decimal list. Whitespace is removed so the
/// alternate (multi-line) form cannot hide the list from this check.
fn sentinel_spellings() -> [String; 2] {
    let compact = |text: &str| {
        text.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
    };
    [
        compact(SENTINEL),
        SENTINEL
            .bytes()
            .map(|byte| format!("{byte},"))
            .collect::<String>(),
    ]
}

/// Assert that a carrier renders neither spelling of the sentinel.
fn assert_byte_free(carrier: &str) {
    let compact: String = carrier.chars().filter(|c| !c.is_whitespace()).collect();
    for spelling in sentinel_spellings() {
        assert!(!compact.contains(&spelling), "{carrier}");
    }
}

#[test]
fn no_debug_form_of_a_pending_source_carries_its_bytes() {
    let pending = sentinel_pending();
    let carrier = debug_forms(&pending);
    assert_byte_free(&carrier);
    // Redaction keeps the diagnostic: the identity is still there.
    assert!(carrier.contains("sentinel.toml"), "{carrier}");
    assert!(
        carrier.contains(&ContentHash::of(SENTINEL.as_bytes()).hex()),
        "{carrier}"
    );
    assert!(carrier.contains("redacted"), "{carrier}");
}

#[test]
fn no_debug_or_error_form_of_the_typed_refusal_carries_pending_bytes() {
    let pending = sentinel_pending();
    let key = pending.key.clone();
    let unapproved = UnapprovedSources::new(
        PathBuf::from("/w/config.toml"),
        PathBuf::from("/w/store"),
        None,
        Vec::new(),
        vec![pending],
        std::collections::BTreeSet::from([key]),
        std::collections::BTreeSet::new(),
    );
    let carrier = debug_forms(&unapproved);
    assert_byte_free(&carrier);
    // The refusal's `Display` is the deliberate diagnostic, and it is byte-free
    // too: it names the path and the digest, never the text.
    let rendered = format!("{unapproved}\n{unapproved:#}");
    assert_byte_free(&rendered);
    assert!(rendered.contains("sentinel.toml"), "{rendered}");

    // The same through `anyhow`, which is how a load or a gate reports it: a
    // panic prints the chain's `Debug`, not just its `Display`.
    let error = anyhow::anyhow!(unapproved);
    let carrier = format!("{error:?}\n{error:#?}\n{error}\n{error:#}");
    assert_byte_free(&carrier);
}

#[test]
fn no_debug_form_of_a_commit_batch_carries_approved_bytes() {
    let candidate = ApprovalCandidate {
        key: key("/w/sentinel.toml"),
        hash: hash(SENTINEL.as_bytes()),
        bytes: SENTINEL.as_bytes().to_vec(),
        activate: true,
    };
    let batch = CommitBatch {
        approve: vec![candidate],
        activate: Vec::new(),
        retained_keys: vec![key("/w/sentinel.toml")],
    };
    let carrier = debug_forms(&batch);
    assert_byte_free(&carrier);
    assert!(carrier.contains("sentinel.toml"), "{carrier}");
    assert!(carrier.contains("redacted"), "{carrier}");
}

#[test]
fn no_debug_form_of_a_diff_state_carries_snapshot_bytes() {
    let f = Fixture::new();
    f.create_store_dir();
    let outcome = f.commit("/w/sentinel.toml", SENTINEL.as_bytes(), 1_000);
    let state = f
        .store()
        .read_for_diff(
            &f.observe(),
            &[DiffRequest {
                key: &key("/w/sentinel.toml"),
                candidate: b"a different candidate\n",
            }],
        )
        .unwrap();
    assert!(
        state.snapshots.contains_key(&hash(SENTINEL.as_bytes())),
        "the fixture's baseline snapshot is the sentinel"
    );
    let carrier = debug_forms(&state);
    assert_byte_free(&carrier);
    // The digest is what a diagnostic may name.
    assert!(
        carrier.contains(&hash(SENTINEL.as_bytes()).hex()),
        "{carrier}"
    );

    // The deliberate places keep the literal text: the stored snapshot on disk
    // and the review transcript.
    let snapshot = f.snapshot_path(outcome.generation, SENTINEL.as_bytes());
    assert_eq!(std::fs::read(&snapshot).unwrap(), SENTINEL.as_bytes());
    let review = diff::render_review(&[diff::PendingReview::of(&sentinel_candidate(), &state)])
        .expect("the fixture is within every cap");
    assert!(
        review.contains(&format!("-{SENTINEL}")),
        "the review is the one place the snapshot's bytes are shown: {review}"
    );
}
