//! The v2 layer-identity encoders (issue #228): pure, no I/O, no launch use.
//!
//! An identity is a cache key computed **before** anything is built. The v1
//! chain's key covered a step's *position*; v2 covers a layer's declared
//! parent, its normalized build context, and every build argument passed
//! except `BASE_IMAGE`. Over-hashing only costs a spurious rebuild;
//! under-hashing silently boots a stale toolchain, so every uncertainty here
//! resolves toward hashing more.
//!
//! # The stream format (canonical, stated once)
//!
//! Each kind is hashed as `SCHEME_TAG` + a kind word + NUL-delimited fields.
//! The kind word and the parent tag make the domains distinct — they do not
//! prove SHA-256 collision freedom, they stop one kind's bytes from being
//! read as another's. Counts and trailing NULs make the variable-length
//! sections unambiguous under the validated name/value grammar:
//!
//! ```text
//! context     = SCHEME_TAG "context\0" <normalized entries>
//! accounts    = SCHEME_TAG "accounts\0" <caller canonical rendered union bytes>
//! root        = SCHEME_TAG "root\0" "base\0" <sha256:hex> "\0"
//!               ( "accounts\0none\0" | "accounts\0union\0" <accounts hex> "\0" )
//! artifact    = SCHEME_TAG "artifact\0"
//!               ( "parent\0root\0" <root hex> "\0"
//!               | "parent\0layer\0" <artifact hex> "\0" )
//!               "context\0" <context hex> "\0"
//!               "args\0" <decimal count> "\0" { <name> "=" <value> "\0" }
//! composition = SCHEME_TAG "composition\0" "root\0" <root hex> "\0"
//!               "artifacts\0" <decimal count> "\0" { <artifact hex> "\0" }
//! ```
//!
//! Argument pairs are emitted in `BuildArgName` order (name bytes, not the
//! rendered `name=value` string: `A` sorts before `A1`, but `A1=…` sorts
//! before `A=…` as strings). The context is a separate digest because a
//! base-only change must not move it; it anchors v2 artifact keys and, later,
//! CP5 context annotation, CP6 selection invalidation and CP7 retained
//! provenance.
//!
//! `BASE_IMAGE` is refused rather than filtered: the builder supplies it from
//! the parent as a `target:`/`oci-layout://` reference that varies with cache
//! state, and the parent identity already names what it stands for. Filtering
//! at encode time would let a caller believe an override was honored.
//!
//! # Not type-level
//!
//! The distinct digest types and the absence of position/project/name inputs
//! are structural. The correspondence between the context/args *hashed* and
//! the context/args the builder actually uses is **not**: CP2/CP5 must render
//! non-`BASE_IMAGE` args from [`ArtifactInputs::build_args`] and build the
//! same materialized context CP9 hashed.

use std::collections::{BTreeMap, btree_map::Entry as BTreeMapEntry};

use sha2::{Digest, Sha256 as Sha256Hasher};

use super::context::NormalizedContext;
use super::hex;

/// The v2 scheme tag. Distinct from the frozen v1 `CHAIN_SCHEME_TAG_V1` in
/// `layer.rs`; nothing on the launch path reads it until CP10.
pub(crate) const SCHEME_TAG: &[u8] = b"agent-vm-layer\x00v2\x00";

/// The one build argument agent-vm owns: it names the parent and is added by
/// the builder, never passed as a user input.
const BASE_IMAGE_ARG: &str = "BASE_IMAGE";

/// The accepted build-argument name length, in bytes. Every name agent-vm
/// passes (`AGENT_VERSION_*`, `AGENT_INSTALL_SOFT_FAIL`) fits well inside it;
/// the bound keeps the `name=value` encoding's name half finite.
const MAX_BUILD_ARG_NAME_BYTES: usize = 128;

/// A SHA-256 digest, private to this module; callers reach it only through a
/// kind's `compute`/`of`, never as raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Sha256([u8; 32]);

impl Sha256 {
    fn of(bytes: &[u8]) -> Self {
        let digest = Sha256Hasher::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// Generates one digest newtype per hash domain. There are no `From`
/// conversions between kinds — a root cannot be passed where an artifact is
/// expected — because the difference is a different hash domain, not a runtime
/// check.
macro_rules! digest_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub(crate) struct $name(Sha256);

        impl $name {
            fn to_hex(self) -> String {
                self.0.to_hex()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }
    };
}

digest_newtype!(
    /// A layer's normalized build context, independent of its parent or args.
    ContextDigest
);
digest_newtype!(
    /// One built layer artifact: parent identity + context + passed args.
    ArtifactIdentity
);
digest_newtype!(
    /// The composition root: selected base manifest digest plus the generated
    /// union account layer, when present. Never covers catalog layers.
    RootIdentity
);
digest_newtype!(
    /// The derived image: root + ordered unique participating artifacts.
    CompositionIdentity
);
digest_newtype!(
    /// CP4's canonical rendered accounts union, hashed by CP1.
    AccountLayerIdentity
);

/// A selected per-platform base manifest digest (`sha256:` + 64 lowercase
/// hex), the same form msb records. Platform is implied by the per-platform
/// digest, so it is not a separate root input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ManifestDigest(String);

impl ManifestDigest {
    pub(crate) fn parse(raw: &str) -> Result<Self, IdentityInputError> {
        let malformed = || IdentityInputError::MalformedManifestDigest {
            raw: raw.to_string(),
        };
        let hex = raw.strip_prefix("sha256:").ok_or_else(malformed)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(malformed());
        }
        Ok(Self(raw.to_string()))
    }
}

/// A validated build-argument name. Case-sensitive (Docker's own ARG names
/// are); `BASE_IMAGE` is reserved in this exact spelling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct BuildArgName(String);

impl BuildArgName {
    pub(crate) fn parse(raw: &str) -> Result<Self, IdentityInputError> {
        let invalid = || IdentityInputError::InvalidBuildArgName {
            raw: raw.to_string(),
        };
        if raw.is_empty() || raw.len() > MAX_BUILD_ARG_NAME_BYTES {
            return Err(invalid());
        }
        let mut bytes = raw.bytes();
        let first = bytes.next().expect("non-empty above");
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return Err(invalid());
        }
        if !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(invalid());
        }
        if raw == BASE_IMAGE_ARG {
            return Err(IdentityInputError::ReservedBuildArg);
        }
        Ok(Self(raw.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated build-argument value: any text without NUL, including empty
/// and text containing `=`. NUL-free is what argv already requires, and it is
/// what keeps the stream unambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuildArgValue(String);

impl BuildArgValue {
    pub(crate) fn parse(raw: &str) -> Result<Self, IdentityInputError> {
        if raw.contains('\0') {
            return Err(IdentityInputError::BuildArgValueContainsNul);
        }
        Ok(Self(raw.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The passed build arguments, name-sorted so insertion order cannot leak
/// into an identity. A `BTreeMap` rather than a `HashMap`: the order is
/// load-bearing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BuildArgs(BTreeMap<BuildArgName, BuildArgValue>);

impl BuildArgs {
    /// Inserts one argument, refusing a duplicate without replacing the
    /// original value — a silent overwrite would hide which value was hashed.
    pub(crate) fn insert(
        &mut self,
        name: BuildArgName,
        value: BuildArgValue,
    ) -> Result<(), IdentityInputError> {
        match self.0.entry(name.clone()) {
            BTreeMapEntry::Occupied(_) => Err(IdentityInputError::DuplicateBuildArg { name }),
            BTreeMapEntry::Vacant(slot) => {
                slot.insert(value);
                Ok(())
            }
        }
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = (&BuildArgName, &BuildArgValue)> {
        self.0.iter()
    }
}

/// Everything besides the parent that an artifact's identity covers. Passing
/// parent and inputs separately means the interface cannot accept a position,
/// project, name or declaration provenance: there is no parameter for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArtifactInputs {
    pub(crate) context: ContextDigest,
    pub(crate) build_args: BuildArgs,
}

/// What an artifact builds `FROM`. Root means the composition root; Layer
/// means a named catalog layer's artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParentIdentity {
    Root(RootIdentity),
    Layer(ArtifactIdentity),
}

/// The root's inputs. No catalog layer can appear here — the type has no
/// slot for one.
pub(crate) struct RootInputs<'a> {
    pub(crate) base: &'a ManifestDigest,
    pub(crate) accounts: Option<AccountLayerIdentity>,
}

impl ContextDigest {
    pub(crate) fn of(context: &NormalizedContext) -> Self {
        Self(Sha256::of(&context_stream(context)))
    }
}

impl AccountLayerIdentity {
    /// Caller (CP4) supplies the canonical rendered union bytes, not
    /// declaration provenance. Declaration serialization is a separate,
    /// retained-data representation in [`super::account_data`].
    pub(crate) fn of_canonical_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::of(&accounts_stream(bytes)))
    }
}

impl ArtifactIdentity {
    pub(crate) fn compute(parent: ParentIdentity, inputs: &ArtifactInputs) -> Self {
        Self(Sha256::of(&artifact_stream(parent, inputs)))
    }
}

impl RootIdentity {
    pub(crate) fn compute(inputs: &RootInputs<'_>) -> Self {
        Self(Sha256::of(&root_stream(inputs)))
    }
}

impl CompositionIdentity {
    /// The artifacts are hashed in the order given (derived stitch order) —
    /// reordering them changes the key. Accepting them independently of the
    /// root is what lets #229 pair a destination root with existing artifact
    /// identities; CP1's normal `identify` always uses the actual parent.
    pub(crate) fn compute(root: RootIdentity, artifacts: &[ArtifactIdentity]) -> Self {
        Self(Sha256::of(&composition_stream(root, artifacts)))
    }
}

// The private stream writers below are what the golden tests pin: they return
// the exact bytes each `compute` hashes, so a test can read the format.

fn context_stream(context: &NormalizedContext) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(SCHEME_TAG);
    buf.extend_from_slice(b"context\x00");
    context.write_entries(&mut buf);
    buf
}

fn accounts_stream(canonical: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(SCHEME_TAG);
    buf.extend_from_slice(b"accounts\x00");
    buf.extend_from_slice(canonical);
    buf
}

fn root_stream(inputs: &RootInputs<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(SCHEME_TAG);
    buf.extend_from_slice(b"root\x00");
    buf.extend_from_slice(b"base\x00");
    buf.extend_from_slice(inputs.base.0.as_bytes());
    buf.push(0);
    match &inputs.accounts {
        None => buf.extend_from_slice(b"accounts\x00none\x00"),
        Some(accounts) => {
            buf.extend_from_slice(b"accounts\x00union\x00");
            buf.extend_from_slice(accounts.to_hex().as_bytes());
            buf.push(0);
        }
    }
    buf
}

fn artifact_stream(parent: ParentIdentity, inputs: &ArtifactInputs) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(SCHEME_TAG);
    buf.extend_from_slice(b"artifact\x00");
    match parent {
        ParentIdentity::Root(identity) => {
            buf.extend_from_slice(b"parent\x00root\x00");
            buf.extend_from_slice(identity.to_hex().as_bytes());
            buf.push(0);
        }
        ParentIdentity::Layer(identity) => {
            buf.extend_from_slice(b"parent\x00layer\x00");
            buf.extend_from_slice(identity.to_hex().as_bytes());
            buf.push(0);
        }
    }
    buf.extend_from_slice(b"context\x00");
    buf.extend_from_slice(inputs.context.to_hex().as_bytes());
    buf.push(0);
    buf.extend_from_slice(b"args\x00");
    buf.extend_from_slice(inputs.build_args.0.len().to_string().as_bytes());
    buf.push(0);
    for (name, value) in inputs.build_args.iter() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(value.as_str().as_bytes());
        buf.push(0);
    }
    buf
}

fn composition_stream(root: RootIdentity, artifacts: &[ArtifactIdentity]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(SCHEME_TAG);
    buf.extend_from_slice(b"composition\x00");
    buf.extend_from_slice(b"root\x00");
    buf.extend_from_slice(root.to_hex().as_bytes());
    buf.push(0);
    buf.extend_from_slice(b"artifacts\x00");
    buf.extend_from_slice(artifacts.len().to_string().as_bytes());
    buf.push(0);
    for identity in artifacts {
        buf.extend_from_slice(identity.to_hex().as_bytes());
        buf.push(0);
    }
    buf
}

/// A rejected identity input. Every variant implements `Display`; argument
/// *values* are never printed, so a secret-looking value cannot leak through
/// an error chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentityInputError {
    MalformedManifestDigest { raw: String },
    ReservedBuildArg,
    InvalidBuildArgName { raw: String },
    BuildArgValueContainsNul,
    DuplicateBuildArg { name: BuildArgName },
}

impl std::fmt::Display for IdentityInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedManifestDigest { raw } => write!(
                f,
                "{raw:?} is not a manifest digest: expected \"sha256:\" followed by 64 lowercase hex characters"
            ),
            Self::ReservedBuildArg => write!(
                f,
                "build argument {BASE_IMAGE_ARG:?} is reserved for the parent and is not an identity input"
            ),
            Self::InvalidBuildArgName { raw } => write!(
                f,
                "build argument name {raw:?} is not valid: expected [A-Za-z_][A-Za-z0-9_]* of 1..=128 bytes"
            ),
            Self::BuildArgValueContainsNul => {
                write!(f, "build argument values must not contain NUL")
            }
            Self::DuplicateBuildArg { name } => write!(
                f,
                "build argument {:?} was passed more than once",
                name.as_str()
            ),
        }
    }
}

impl std::error::Error for IdentityInputError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;
    use crate::composition::test_support::{
        arg_name, arg_value, args, base_digest, context_digest, digest_of, root,
        two_context_digests,
    };

    // --- H1–H6: the exact stream format, pinned by literal bytes ---

    // The stream is the specification: a small fixed tree and the exact bytes
    // it must produce, with every NUL spelled out. The tag is v2, so this
    // cannot be satisfied by the frozen v1 encoder.
    #[test]
    fn context_stream_is_v1_entries_under_the_v2_tag() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        for (rel, content, mode) in [
            ("Dockerfile", "FROM scratch\n", 0o644),
            ("scripts/a.sh", "echo hi\n", 0o755),
        ] {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let context = NormalizedContext::read(dir.path()).unwrap();

        let stream = String::from_utf8(context_stream(&context)).unwrap();
        let want = format!(
            "agent-vm-layer\x00v2\x00context\x00\
             Dockerfile\x00file\x000644\x0013\x00{}\x00\
             scripts\x00dir\x00\x00\x00\x00\
             scripts/a.sh\x00file\x000755\x008\x00{}\x00",
            digest_of(b"FROM scratch\n"),
            digest_of(b"echo hi\n"),
        );
        assert_eq!(stream, want);
        assert_eq!(
            ContextDigest::of(&context).to_hex(),
            digest_of(stream.as_bytes())
        );
    }

    #[test]
    fn accounts_stream_is_exactly_the_documented_format() {
        let canonical = b"root:x:0:0:root:/root:/bin/sh\n";
        let stream = accounts_stream(canonical);
        let want = b"agent-vm-layer\x00v2\x00accounts\x00root:x:0:0:root:/root:/bin/sh\n";
        assert_eq!(stream, want);
        assert_eq!(
            AccountLayerIdentity::of_canonical_bytes(canonical).to_hex(),
            digest_of(want)
        );
    }

    #[test]
    fn artifact_stream_is_exactly_the_documented_format() {
        let context = context_digest("FROM scratch\n");
        let root = root(None);
        // Inserted out of order on purpose. The `A`/`A1` pair is what
        // separates name-byte sorting from rendered `name=value` sorting:
        // `A1=…` sorts before `A=…` as a string, but `A` sorts before `A1`.
        let inputs = ArtifactInputs {
            context,
            build_args: args(&[("A1", "y"), ("AGENT_INSTALL_SOFT_FAIL", ""), ("A", "x")]),
        };

        let stream =
            String::from_utf8(artifact_stream(ParentIdentity::Root(root), &inputs)).unwrap();
        let want = format!(
            "agent-vm-layer\x00v2\x00artifact\x00parent\x00root\x00{}\x00\
             context\x00{}\x00args\x003\x00A=x\x00A1=y\x00AGENT_INSTALL_SOFT_FAIL=\x00",
            root.to_hex(),
            context.to_hex(),
        );
        assert_eq!(stream, want);
        assert_eq!(
            ArtifactIdentity::compute(ParentIdentity::Root(root), &inputs).to_hex(),
            digest_of(stream.as_bytes())
        );
    }

    #[test]
    fn artifact_stream_with_layer_parent_is_exactly_the_documented_format() {
        let root = root(None);
        let parent = ArtifactIdentity::compute(
            ParentIdentity::Root(root),
            &ArtifactInputs {
                context: context_digest("FROM scratch\n"),
                build_args: args(&[("AGENT_VERSION_CLAUDE", "1")]),
            },
        );
        let inputs = ArtifactInputs {
            context: context_digest("FROM busybox\n"),
            build_args: BuildArgs::default(),
        };

        let stream =
            String::from_utf8(artifact_stream(ParentIdentity::Layer(parent), &inputs)).unwrap();
        let want = format!(
            "agent-vm-layer\x00v2\x00artifact\x00parent\x00layer\x00{}\x00\
             context\x00{}\x00args\x000\x00",
            parent.to_hex(),
            inputs.context.to_hex(),
        );
        assert_eq!(stream, want);
    }

    #[test]
    fn root_stream_is_exactly_the_documented_format() {
        let base = base_digest();
        let base_hex = format!("sha256:{}", "1".repeat(64));

        let none = String::from_utf8(root_stream(&RootInputs {
            base: &base,
            accounts: None,
        }))
        .unwrap();
        let want_none =
            format!("agent-vm-layer\x00v2\x00root\x00base\x00{base_hex}\x00accounts\x00none\x00");
        assert_eq!(none, want_none);
        assert_eq!(
            RootIdentity::compute(&RootInputs {
                base: &base,
                accounts: None
            })
            .to_hex(),
            digest_of(none.as_bytes())
        );

        let accounts = AccountLayerIdentity::of_canonical_bytes(b"root:x:0:0\n");
        let union = String::from_utf8(root_stream(&RootInputs {
            base: &base,
            accounts: Some(accounts),
        }))
        .unwrap();
        let want_union = format!(
            "agent-vm-layer\x00v2\x00root\x00base\x00{base_hex}\x00accounts\x00union\x00{}\x00",
            accounts.to_hex(),
        );
        assert_eq!(union, want_union);
    }

    #[test]
    fn composition_stream_is_exactly_the_documented_format() {
        let root = root(None);
        let context = context_digest("FROM scratch\n");
        let codex = ArtifactIdentity::compute(
            ParentIdentity::Root(root),
            &ArtifactInputs {
                context,
                build_args: args(&[("AGENT_VERSION_CODEX", "1")]),
            },
        );
        let claude = ArtifactIdentity::compute(
            ParentIdentity::Root(root),
            &ArtifactInputs {
                context,
                build_args: args(&[("AGENT_VERSION_CLAUDE", "2")]),
            },
        );
        let plugin = ArtifactIdentity::compute(
            ParentIdentity::Layer(claude),
            &ArtifactInputs {
                context,
                build_args: BuildArgs::default(),
            },
        );
        let artifacts = [codex, claude, plugin];

        let stream = String::from_utf8(composition_stream(root, &artifacts)).unwrap();
        let want = format!(
            "agent-vm-layer\x00v2\x00composition\x00root\x00{}\x00artifacts\x003\x00{}\x00{}\x00{}\x00",
            root.to_hex(),
            codex.to_hex(),
            claude.to_hex(),
            plugin.to_hex(),
        );
        assert_eq!(stream, want);
        assert_eq!(
            CompositionIdentity::compute(root, &artifacts).to_hex(),
            digest_of(stream.as_bytes())
        );
    }

    // --- H7–H12: parsing and the small input distinctions ---

    #[test]
    fn build_arg_name_shapes_and_reserved_base_image() {
        for valid in [
            "A",
            "_x",
            "AGENT_VERSION_PI_CLAUDE_BRIDGE",
            "base_image",
            &"A".repeat(128),
            "AGENT_INSTALL_SOFT_FAIL",
        ] {
            assert!(
                BuildArgName::parse(valid).is_ok(),
                "{valid:?} must be accepted"
            );
        }

        for invalid in ["", "1A", "A-B", "A=B", "A B", "A\0", "é", &"A".repeat(129)] {
            let err = BuildArgName::parse(invalid).unwrap_err();
            assert_eq!(
                err,
                IdentityInputError::InvalidBuildArgName {
                    raw: invalid.to_string()
                },
                "{invalid:?} must be rejected as an invalid name"
            );
        }

        assert_eq!(
            BuildArgName::parse("BASE_IMAGE").unwrap_err(),
            IdentityInputError::ReservedBuildArg,
            "only the exact uppercase spelling is reserved"
        );

        let message = BuildArgName::parse("A-B").unwrap_err().to_string();
        assert!(
            message.contains("[A-Za-z_][A-Za-z0-9_]*"),
            "the error must name the accepted shape: {message}"
        );
    }

    #[test]
    fn build_arg_value_rejects_nul() {
        let err = BuildArgValue::parse("a\0b").unwrap_err();
        assert_eq!(err, IdentityInputError::BuildArgValueContainsNul);
        assert!(
            !err.to_string().contains('\0'),
            "the error must not echo the value"
        );

        for valid in ["", "=", "a=b", "x=y=z"] {
            assert!(BuildArgValue::parse(valid).is_ok(), "{valid:?} accepted");
        }
    }

    #[test]
    fn build_args_reject_a_duplicate_name() {
        let mut build_args = args(&[("A", "first")]);
        let err = build_args
            .insert(arg_name("A"), arg_value("second"))
            .unwrap_err();
        assert_eq!(
            err,
            IdentityInputError::DuplicateBuildArg {
                name: arg_name("A")
            }
        );

        let (name, value) = build_args.iter().next().unwrap();
        assert_eq!(name.as_str(), "A");
        assert_eq!(
            value.as_str(),
            "first",
            "a failed insert must not replace the original value"
        );
        assert_eq!(build_args.iter().len(), 1);
    }

    #[test]
    fn manifest_digest_shapes() {
        let valid = format!("sha256:{}", "a1".repeat(32));
        assert!(ManifestDigest::parse(&valid).is_ok());

        for invalid in [
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("md5:{}", "a".repeat(64)),
            "sha256:".to_string(),
            format!("sha512:{}", "a".repeat(64)),
        ] {
            let err = ManifestDigest::parse(&invalid).unwrap_err();
            assert_eq!(
                err,
                IdentityInputError::MalformedManifestDigest {
                    raw: invalid.clone()
                }
            );
        }

        let message = ManifestDigest::parse("nonsense").unwrap_err().to_string();
        assert!(
            message.contains("sha256:"),
            "the error must state the accepted form: {message}"
        );
    }

    #[test]
    fn passing_an_empty_value_differs_from_not_passing() {
        // The Dockerfile default is empty, so `X=` and passing nothing build the
        // same image; only the *passed* set differs, and that difference must
        // show up in the identity because the identity covers what is passed.
        let context = context_digest("FROM scratch\nARG AGENT_INSTALL_SOFT_FAIL=\n");
        let root = root(None);
        let identity = |build_args: BuildArgs| {
            ArtifactIdentity::compute(
                ParentIdentity::Root(root),
                &ArtifactInputs {
                    context,
                    build_args,
                },
            )
        };

        let absent = identity(BuildArgs::default());
        let empty = identity(args(&[("AGENT_INSTALL_SOFT_FAIL", "")]));

        assert_ne!(absent, empty, "an empty passed value is still passed");
        assert_ne!(
            identity(args(&[("AGENT_INSTALL_SOFT_FAIL", "1")])),
            absent,
            "a passed value differs from not passing it"
        );
    }

    #[test]
    fn passing_a_value_equal_to_a_nonempty_default_is_still_passed() {
        // The Dockerfile default is `1`, so passing nothing and passing `1`
        // build the same image; their identities must still differ, because
        // the identity covers the *passed* set, not the effective value.
        let context = context_digest("FROM scratch\nARG AGENT_VERSION_X=1\n");
        let root = root(None);
        let identity = |build_args: BuildArgs| {
            ArtifactIdentity::compute(
                ParentIdentity::Root(root),
                &ArtifactInputs {
                    context,
                    build_args,
                },
            )
        };

        let absent = identity(BuildArgs::default());
        let pinned = identity(args(&[("AGENT_VERSION_X", "1")]));

        assert_ne!(
            absent, pinned,
            "a passed value equal to the default is still passed"
        );
    }

    #[test]
    fn no_accounts_differs_from_an_empty_union() {
        let base = base_digest();
        let none = RootIdentity::compute(&RootInputs {
            base: &base,
            accounts: None,
        });
        let empty_union = RootIdentity::compute(&RootInputs {
            base: &base,
            accounts: Some(AccountLayerIdentity::of_canonical_bytes(&[])),
        });
        assert_ne!(none, empty_union);
    }

    // --- P1–P3: argument-encoding properties ---

    fn any_name() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("A".to_string()),
            Just("A1".to_string()),
            "AGENT_VERSION_[A-Z0-9]{0,6}",
            "[A-Za-z_][A-Za-z0-9_]{0,7}",
        ]
    }

    fn any_value() -> impl Strategy<Value = String> {
        "[a-z0-9=]{0,6}"
    }

    fn pairs() -> impl Strategy<Value = Vec<(String, String)>> {
        prop::collection::vec((any_name(), any_value()), 0..=5)
    }

    /// Deduplicated argument pairs that do not depend on input order: for a
    /// repeated name the lexicographically smallest value wins. Kept as pairs
    /// (not a `BuildArgs`) so a caller can feed them to `BuildArgs::insert` in
    /// whatever order it wants to exercise.
    fn unique_pairs(pairs: &[(String, String)]) -> Vec<(String, String)> {
        let mut by_name: BTreeMap<String, String> = BTreeMap::new();
        for (name, value) in pairs {
            by_name
                .entry(name.clone())
                .and_modify(|current| {
                    if value < current {
                        *current = value.clone();
                    }
                })
                .or_insert_with(|| value.clone());
        }
        by_name.into_iter().collect()
    }

    /// [`unique_pairs`] inserted into the production container.
    fn unique_args(pairs: &[(String, String)]) -> BuildArgs {
        let mut build_args = BuildArgs::default();
        for (name, value) in unique_pairs(pairs) {
            build_args
                .insert(arg_name(&name), arg_value(&value))
                .unwrap();
        }
        build_args
    }

    fn artifact(
        root: RootIdentity,
        context: ContextDigest,
        build_args: &BuildArgs,
    ) -> ArtifactIdentity {
        ArtifactIdentity::compute(
            ParentIdentity::Root(root),
            &ArtifactInputs {
                context,
                build_args: build_args.clone(),
            },
        )
    }

    fn stream(context: ContextDigest, build_args: &BuildArgs) -> Vec<u8> {
        artifact_stream(
            ParentIdentity::Root(root(None)),
            &ArtifactInputs {
                context,
                build_args: build_args.clone(),
            },
        )
    }

    fn replace_value(build_args: &BuildArgs, name: &BuildArgName, value: &str) -> BuildArgs {
        let mut out = BuildArgs::default();
        for (existing_name, existing_value) in build_args.iter() {
            let new_value = if existing_name == name {
                arg_value(value)
            } else {
                existing_value.clone()
            };
            out.insert(existing_name.clone(), new_value).unwrap();
        }
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn every_passed_build_arg_changes_identity(
            pairs in pairs(),
            probe in any_name(),
            probe_value in any_value(),
        ) {
            let context = two_context_digests().0;
            let root = root(None);
            let initial = unique_args(&pairs);
            let baseline = artifact(root, context, &initial);

            // Adding a name that is not already present changes the key, even
            // when the value is empty.
            if !initial.iter().any(|(name, _)| name.as_str() == probe) {
                let mut added = initial.clone();
                added.insert(arg_name(&probe), arg_value(&probe_value)).unwrap();
                prop_assert_ne!(artifact(root, context, &added), baseline);
            }

            // Changing an existing value changes the key; `Z`-suffixing can
            // never reproduce the original bytes.
            if let Some((name, value)) = initial.iter().next() {
                let changed = replace_value(&initial, name, &format!("{}Z", value.as_str()));
                prop_assert_ne!(artifact(root, context, &changed), baseline);
            }
        }

        #[test]
        fn build_arg_insertion_order_is_irrelevant(pairs in pairs()) {
            // Deduplicate the generated pairs once, then insert that same
            // unique set forward and reversed *directly* through
            // `BuildArgs::insert`. The fixture must not re-sort first: sorting
            // the reversed pairs before insertion would hand the production
            // container the same insertion sequence twice and make this
            // property confirm itself.
            let unique = unique_pairs(&pairs);
            let mut forward = BuildArgs::default();
            for (name, value) in &unique {
                forward.insert(arg_name(name), arg_value(value)).unwrap();
            }
            let mut backward = BuildArgs::default();
            for (name, value) in unique.iter().rev() {
                backward.insert(arg_name(name), arg_value(value)).unwrap();
            }

            let context = two_context_digests().0;
            let root = root(None);
            prop_assert_eq!(stream(context, &forward), stream(context, &backward));
            prop_assert_eq!(
                artifact(root, context, &forward),
                artifact(root, context, &backward)
            );
        }

        #[test]
        fn distinct_arg_sets_never_share_a_stream(a in pairs(), b in pairs()) {
            let context = two_context_digests().0;
            let args_a = unique_args(&a);
            let mut args_b = unique_args(&b);
            if args_a == args_b {
                // Perturb rather than assert on a vacuous equal-input case.
                let mut n = 0;
                loop {
                    let candidate = format!("PERTURB{n}");
                    if args_b.insert(arg_name(&candidate), arg_value("1")).is_ok() {
                        break;
                    }
                    n += 1;
                }
            }
            prop_assert_ne!(&args_a, &args_b);
            prop_assert_ne!(stream(context, &args_a), stream(context, &args_b));
        }
    }
}
