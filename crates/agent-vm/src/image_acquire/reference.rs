//! The single canonical form of an OCI acquisition target.
//!
//! The native `Reference` parser keeps a user's spelling: `DOCKER.IO/alpine`,
//! `registry-1.docker.io/alpine` and `docker.io/library/alpine:latest` parse to
//! three different `Reference` values. Native cache keys hash
//! `Reference::to_string()`, so those three spellings become three cache
//! entries. Worse, `registry-1.docker.io/alpine` parses with repository
//! `alpine` (no `library/` prefix, because only `docker.io` gets the Hub
//! rewrite), so a canonicalizer that only lowercased the host would still key
//! it differently from the equivalent Hub reference.
//!
//! Acquisition, cache metadata, derived `repo@child` references and every
//! future pin key use [`OciTarget::reference`]'s output. The original text is
//! kept only as provenance/display: it is never a second cache key.
//!
//! This module deliberately owns the *only* canonicalizer. A second
//! key-only normalizer would drift from what acquisition actually requests;
//! the round-trip assertion in [`canonicalize`] is the guard against that.

use std::fmt;

use microsandbox_image::Reference;
use vstd::prelude::*;

use crate::boot_image::ImageRef;

/// Why a target was refused. The two are different user mistakes and get
/// different fixed advice: a local rootfs/disk path is a supported launch
/// target that simply cannot be acquired, while malformed reference text is not
/// a local path at all and must not be told to launch itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OciTargetError {
    LocalPath,
    InvalidReference,
}

/// Classify a refused target from its text alone: no stat, no filesystem read.
fn refuse(raw: &str) -> OciTargetError {
    if microsandbox_utils::looks_like_local_path_text(raw) {
        OciTargetError::LocalPath
    } else {
        OciTargetError::InvalidReference
    }
}

/// One OCI reference whose components are in canonical form.
///
/// Opaque by construction: the only ways to obtain one are
/// [`CanonicalOciReference::parse`] and [`CanonicalOciReference::with_digest`],
/// both of which reparse their result and require identical components.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CanonicalOciReference {
    reference: Reference,
    /// The stated digest, already measured strict, so no consumer re-parses it
    /// or unwraps an `Option` it cannot act on.
    digest: Option<ValidatedDigest>,
}

/// A canonical `repo@digest` reference.
///
/// Only [`CanonicalOciReference::with_digest`] constructs one, so a receipt, a
/// cache key or an approved identity can never be handed a tag by mistake.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PinnedReference {
    canonical: CanonicalOciReference,
    digest: ValidatedDigest,
}

impl PinnedReference {
    /// The immutable identity this reference names.
    pub(crate) fn digest(&self) -> &ValidatedDigest {
        &self.digest
    }

    /// The canonical text: `repo@digest`, what a cache key or a receipt stores.
    pub(crate) fn whole(&self) -> String {
        self.canonical.whole()
    }

    pub(crate) fn reference(&self) -> &Reference {
        self.canonical.reference()
    }
}

impl CanonicalOciReference {
    /// Canonicalize `raw`. The acceptance policy is config-file acceptance
    /// (OCI, not an SDK local path, no whitespace/control) plus native parsing,
    /// so a reference accepted by one acquisition caller is accepted by all.
    pub(crate) fn parse(raw: &str) -> Result<Self, OciTargetError> {
        let parsed: Reference = raw.parse().map_err(|_| refuse(raw))?;
        ImageRef::from_config(raw).map_err(|_| refuse(raw))?;
        canonicalize(parsed)
    }

    /// Canonicalize `repo@digest` for this reference's registry/repository.
    ///
    /// Every derived child (the host-platform manifest behind an index, an
    /// approved digest) goes through this function, never through a raw
    /// `with_digest`, so the acquisition key and the stored identity agree.
    pub(crate) fn with_digest(
        &self,
        digest: &ValidatedDigest,
    ) -> Result<PinnedReference, OciTargetError> {
        let reference = Reference::with_digest(
            self.reference.registry().to_owned(),
            self.reference.repository().to_owned(),
            digest.as_str().to_owned(),
        );
        let canonical = round_trip(reference, Some(digest.clone()))?;
        Ok(PinnedReference {
            canonical,
            digest: digest.clone(),
        })
    }

    pub(crate) fn reference(&self) -> &Reference {
        &self.reference
    }

    /// The canonical text: what native acquisition and the cache key see.
    pub(crate) fn whole(&self) -> String {
        self.reference.whole()
    }

    /// The stated immutable digest, canonical lowercase, when the reference
    /// names one. This is the *source binding*, not necessarily the digest the
    /// registry resolves it to (an index resolves to its host child).
    pub(crate) fn digest(&self) -> Option<&ValidatedDigest> {
        self.digest.as_ref()
    }
}

/// An acquisition target: the canonical reference plus the user's original
/// text as provenance.
///
/// `source_text` is for display and source identity only. It never keys a
/// cache lookup, a native request or a registry credential decision.
pub(crate) struct OciTarget {
    source_text: String,
    precanonical: Reference,
    canonical: CanonicalOciReference,
}

impl OciTarget {
    pub(crate) fn parse(raw: &str) -> Result<Self, OciTargetError> {
        let precanonical: Reference = raw.parse().map_err(|_| refuse(raw))?;
        Ok(Self {
            source_text: raw.to_owned(),
            canonical: CanonicalOciReference::parse(raw)?,
            precanonical,
        })
    }

    /// The originally parsed native reference, before canonicalization.
    ///
    /// Only a bounded compatibility read of an old cache spelling may use this;
    /// it is never requested from a registry or used as a new cache key.
    pub(crate) fn precanonical(&self) -> &Reference {
        &self.precanonical
    }

    /// The canonical reference every acquisition/cache operation uses.
    pub(crate) fn reference(&self) -> &Reference {
        self.canonical.reference()
    }

    pub(crate) fn canonical(&self) -> &CanonicalOciReference {
        &self.canonical
    }

    /// The user's original spelling, for provenance and rendered notices.
    pub(crate) fn source_text(&self) -> &str {
        &self.source_text
    }

    /// The source's stated immutable digest, when it named one. A derived child
    /// is always immutable; a mutable tag states none.
    pub(crate) fn stated_digest(&self) -> Option<&ValidatedDigest> {
        self.canonical.digest()
    }
}

impl fmt::Debug for OciTarget {
    /// Never renders the reference: acquisition targets can name a private
    /// registry, and a debug-printed target is still record data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OciTarget(<redacted reference>)")
    }
}

/// Canonicalize parsed native components.
///
/// Order matters: fold the Hub endpoint first, then apply the `library/`
/// rewrite. `registry-1.docker.io/alpine` parses with repository `alpine`, so
/// rewriting before the fold would leave it unprefixed and key it apart from
/// `docker.io/library/alpine`.
fn canonicalize(parsed: Reference) -> Result<CanonicalOciReference, OciTargetError> {
    let (host, port) = split_host_port(parsed.registry());
    let host = host.to_ascii_lowercase();
    let registry = fold_registry(&host, port);
    let repository = fold_repository(&registry, parsed.repository());
    let (reference, digest) = match parsed.digest() {
        // A digest fixes identity, so a redundant tag is dropped rather than
        // retained as decoration that a later comparison might trust.
        Some(digest) => {
            let digest = ValidatedDigest::parse(digest)?;
            (
                Reference::with_digest(registry, repository, digest.as_str().to_owned()),
                Some(digest),
            )
        }
        None => (
            Reference::with_tag(
                registry,
                repository,
                parsed.tag().unwrap_or("latest").to_string(),
            ),
            None,
        ),
    };
    round_trip(reference, digest)
}

/// Reparse the constructed reference and require identical components *and*
/// text. A canonicalizer whose output reparses differently is not idempotent,
/// which would silently split cache keys again.
fn round_trip(
    reference: Reference,
    digest: Option<ValidatedDigest>,
) -> Result<CanonicalOciReference, OciTargetError> {
    let text = reference.whole();
    let reparsed: Reference = text.parse().map_err(|_| OciTargetError::InvalidReference)?;
    if reparsed != reference
        || reparsed.whole() != text
        || reparsed.digest() != digest.as_ref().map(ValidatedDigest::as_str)
    {
        return Err(OciTargetError::InvalidReference);
    }
    Ok(CanonicalOciReference {
        reference: reparsed,
        digest,
    })
}

/// Split a native registry component into host and explicit port.
///
/// The native grammar admits only `host[:digits]` — no IPv6 brackets — so the
/// last colon is unambiguous. The port is preserved exactly; only the host is
/// lowercased.
fn split_host_port(registry: &str) -> (&str, Option<&str>) {
    match registry.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (registry, None),
    }
}

fn fold_registry(host: &str, port: Option<&str>) -> String {
    let folds = folds_to_docker_io(HubHostFacts {
        is_docker_io: host == "docker.io",
        is_index_docker_io: host == "index.docker.io",
        is_registry_1_docker_io: host == "registry-1.docker.io",
        has_port: port.is_some(),
    });
    match port {
        Some(port) => format!("{host}:{port}"),
        None if folds => "docker.io".to_string(),
        None => host.to_string(),
    }
}

fn fold_repository(registry: &str, repository: &str) -> String {
    if library_prefix_applies(LibraryPrefixFacts {
        registry_is_docker_io: registry == "docker.io",
        repository_has_slash: repository.contains('/'),
    }) {
        format!("library/{repository}")
    } else {
        repository.to_string()
    }
}

/// One measured strict immutable digest: lowercase algorithm plus exactly that
/// algorithm's lowercase hex.
///
/// Opaque by construction: [`ValidatedDigest::parse`] is the only way in, so a
/// receipt, a derived child or an approved identity can never carry a digest
/// that was not grammar-checked exactly once.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ValidatedDigest(String);

impl ValidatedDigest {
    pub(crate) fn parse(raw: &str) -> Result<Self, OciTargetError> {
        canonical_digest(raw).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ValidatedDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The canonical strict digest, or a refusal.
///
/// Deliberately narrower than native `Digest::from_str` (which accepts
/// `sha256:abc123`): the algorithm spelling must be one of the three supported
/// lowercase OCI algorithms, the hex must be exactly that algorithm's length,
/// and the output hex is lowercase. Uppercase *hex* is accepted and folded;
/// uppercase *algorithm* spellings are refused rather than aliased.
fn canonical_digest(digest: &str) -> Result<String, OciTargetError> {
    let (algorithm, hex) = digest
        .split_once(':')
        .ok_or(OciTargetError::InvalidReference)?;
    let expected = match algorithm {
        "sha256" => Some(64),
        "sha384" => Some(96),
        "sha512" => Some(128),
        _ => None,
    };
    let facts = DigestFacts {
        algorithm_supported: expected.is_some(),
        hex_length_matches: expected == Some(hex.len()),
        hex_is_hexadecimal: hex.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte.to_ascii_lowercase())
        }),
    };
    if !digest_is_acceptable(facts) {
        return Err(OciTargetError::InvalidReference);
    }
    Ok(format!("{algorithm}:{}", hex.to_ascii_lowercase()))
}

verus! {

/// The already-measured Hub-endpoint facts the fold reads. Named fields rather
/// than adjacent booleans, so an argument swap cannot invert the decision.
pub(crate) struct HubHostFacts {
    pub(crate) is_docker_io: bool,
    pub(crate) is_index_docker_io: bool,
    pub(crate) is_registry_1_docker_io: bool,
    pub(crate) has_port: bool,
}

/// Fold a Hub endpoint spelling to `docker.io` iff it names a Hub hostname and
/// carries no explicit port. An explicit port names a distinct endpoint (a
/// mirror or dev registry) and is never folded.
pub(crate) fn folds_to_docker_io(facts: HubHostFacts) -> (folds: bool)
    ensures folds == (!facts.has_port
        && (facts.is_docker_io || facts.is_index_docker_io || facts.is_registry_1_docker_io))
{
    !facts.has_port && (facts.is_docker_io || facts.is_index_docker_io || facts.is_registry_1_docker_io)
}

pub(crate) struct LibraryPrefixFacts {
    pub(crate) registry_is_docker_io: bool,
    pub(crate) repository_has_slash: bool,
}

/// Insert the Hub `library/` namespace iff the folded registry is `docker.io`
/// and the repository is a bare name. Team namespaces and every other registry
/// keep their repository spelling.
pub(crate) fn library_prefix_applies(facts: LibraryPrefixFacts) -> (applies: bool)
    ensures applies == (facts.registry_is_docker_io && !facts.repository_has_slash)
{
    facts.registry_is_docker_io && !facts.repository_has_slash
}

pub(crate) struct DigestFacts {
    pub(crate) algorithm_supported: bool,
    pub(crate) hex_length_matches: bool,
    pub(crate) hex_is_hexadecimal: bool,
}

/// The strict digest acceptance decision: supported algorithm, exact hex length
/// and hexadecimal content. Total over all eight combinations, so acceptance
/// never bypasses a check.
pub(crate) fn digest_is_acceptable(facts: DigestFacts) -> (accepted: bool)
    ensures accepted == (facts.algorithm_supported && facts.hex_length_matches && facts.hex_is_hexadecimal)
{
    facts.algorithm_supported && facts.hex_length_matches && facts.hex_is_hexadecimal
}

} // verus!

impl fmt::Debug for CanonicalOciReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CanonicalOciReference(<redacted>)")
    }
}
impl fmt::Debug for PinnedReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedReference(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(raw: &str) -> String {
        OciTarget::parse(raw).unwrap().canonical().whole()
    }

    fn cache_path(cache: &microsandbox_image::GlobalCache, text: &str) -> std::path::PathBuf {
        cache.image_metadata_path(&text.parse().unwrap())
    }

    /// The full independent A1 table. Every accepted row also proves the
    /// idempotence property `C(C(x)) == C(x)` and that the actual native cache
    /// metadata path is the canonical key's path.
    #[test]
    fn canonical_table_is_ordered_and_idempotent() {
        let h256 = "a".repeat(64);
        let h384 = "b".repeat(96);
        let h512 = "c".repeat(128);
        let u256 = h256.to_ascii_uppercase();
        let rows: &[(&str, &str)] = &[
            // Hub short forms and endpoint aliases.
            ("alpine", "docker.io/library/alpine:latest"),
            ("alpine:latest", "docker.io/library/alpine:latest"),
            ("docker.io/alpine", "docker.io/library/alpine:latest"),
            (
                "docker.io/library/alpine:latest",
                "docker.io/library/alpine:latest",
            ),
            ("index.docker.io/alpine", "docker.io/library/alpine:latest"),
            (
                "registry-1.docker.io/alpine",
                "docker.io/library/alpine:latest",
            ),
            ("DOCKER.IO/alpine", "docker.io/library/alpine:latest"),
            ("INDEX.DOCKER.IO/alpine", "docker.io/library/alpine:latest"),
            (
                "REGISTRY-1.DOCKER.IO/alpine",
                "docker.io/library/alpine:latest",
            ),
            // Team namespaces keep their spelling; no library/ injection.
            ("index.docker.io/team/alpine:X", "docker.io/team/alpine:X"),
            (
                "registry-1.docker.io/team/alpine:X",
                "docker.io/team/alpine:X",
            ),
            ("DOCKER.IO/library/alpine:X", "docker.io/library/alpine:X"),
            ("docker.io/library/alpine:X", "docker.io/library/alpine:X"),
            // Explicit ports are distinct endpoints and are never folded.
            (
                "registry-1.docker.io:443/alpine",
                "registry-1.docker.io:443/alpine:latest",
            ),
            ("docker.io:443/alpine", "docker.io:443/alpine:latest"),
            ("EXAMPLE.COM:5000/team/a:T", "example.com:5000/team/a:T"),
            ("example.com:5000/team/a:T", "example.com:5000/team/a:T"),
            ("example.com:5001/team/a:T", "example.com:5001/team/a:T"),
            ("localhost:5000/a", "localhost:5000/a:latest"),
            ("mirror.example/alpine", "mirror.example/alpine:latest"),
        ];
        for (input, expected) in rows {
            let once = canonical(input);
            assert_eq!(&once, expected, "canonical form of {input:?}");
            assert_eq!(canonical(&once), once, "C(C({input:?})) == C({input:?})");
        }
        // Digest rows drop a redundant tag and canonicalize the hex.
        for (input, expected) in [
            (
                format!("alpine@sha256:{u256}"),
                format!("docker.io/library/alpine@sha256:{h256}"),
            ),
            (
                format!("alpine:SomeTag@sha256:{h256}"),
                format!("docker.io/library/alpine@sha256:{h256}"),
            ),
            (
                format!("alpine@sha384:{h384}"),
                format!("docker.io/library/alpine@sha384:{h384}"),
            ),
            (
                format!("alpine@sha512:{h512}"),
                format!("docker.io/library/alpine@sha512:{h512}"),
            ),
        ] {
            let once = canonical(&input);
            assert_eq!(once, expected);
            assert_eq!(canonical(&once), once);
        }
    }

    /// Inequality rows must have distinct canonical texts *and* distinct
    /// native cache metadata paths: B keys these identities, and a collision
    /// would silently merge two approvals.
    #[test]
    fn distinct_identities_have_distinct_cache_paths() {
        let directory = tempfile::tempdir().unwrap();
        let cache = microsandbox_image::GlobalCache::new(directory.path()).unwrap();
        let groups: &[&[&str]] = &[
            &["docker.io/library/alpine:X", "docker.io/library/alpine:x"],
            &[
                "docker.io/library/alpine:X",
                "docker.io/library/alpine:latest",
            ],
            &[
                "docker.io/library/alpine:latest",
                "docker.io/team/alpine:latest",
                "docker.io/library/beta:latest",
            ],
            &[
                "registry-1.docker.io:443/alpine",
                "docker.io:443/alpine",
                "docker.io/library/alpine",
            ],
            &[
                "example.com:5000/team/a:T",
                "example.com:5001/team/a:T",
                "example.com/team/a:T",
            ],
        ];
        for group in groups {
            let mut seen = std::collections::BTreeMap::new();
            for raw in *group {
                let text = canonical(raw);
                if let Some(previous) = seen.insert(cache_path(&cache, &text), (text.clone(), *raw))
                {
                    panic!(
                        "{raw:?} and {:?} share canonical text/path {:?}",
                        previous.1, previous.0
                    );
                }
            }
        }
        // Sha384 and sha512 of the same digest value are different identities.
        assert_ne!(
            cache_path(
                &cache,
                &canonical(&format!("alpine@sha384:{}", "b".repeat(96)))
            ),
            cache_path(
                &cache,
                &canonical(&format!("alpine@sha512:{}", "b".repeat(128)))
            )
        );
    }

    #[test]
    fn malformed_and_local_targets_are_typed_refusals() {
        for raw in [
            "",
            "Foo/Bar:tag",
            "repo:bad tag",
            "repo@sha256:short",
            "repo\nsecret",
            "repo\u{1b}",
            &format!("repo@SHA256:{}", "a".repeat(64)),
            &format!("repo@sha256:{}", "g".repeat(64)),
            &format!("repo@sha256:{}", "a".repeat(96)),
            &format!("repo@md5:{}", "a".repeat(32)),
        ] {
            assert_eq!(
                OciTarget::parse(raw).err(),
                Some(OciTargetError::InvalidReference),
                "{raw:?} is malformed, not a local path"
            );
        }
        for raw in ["/private/path", "./rootfs", "../rootfs", ".", ".."] {
            assert_eq!(
                OciTarget::parse(raw).err(),
                Some(OciTargetError::LocalPath),
                "{raw:?} is a local launch target"
            );
        }
    }

    #[test]
    fn derived_children_are_canonical_and_bind_one_strict_digest() {
        let target = OciTarget::parse("index.docker.io/team/a:tag").unwrap();
        let child = format!("sha256:{}", "d".repeat(64));
        let pinned = target
            .canonical()
            .with_digest(&ValidatedDigest::parse(&child).unwrap())
            .unwrap();
        assert_eq!(pinned.whole(), format!("docker.io/team/a@{child}"));
        assert_eq!(pinned.digest().as_str(), child);
        assert_eq!(target.stated_digest().map(ValidatedDigest::as_str), None);
        // A derived digest must be strict; the permissive native spelling is
        // not accepted here.
        assert_eq!(
            ValidatedDigest::parse("sha256:abc").err(),
            Some(OciTargetError::InvalidReference)
        );
    }

    /// Old loader/launcher spellings are recognized for a bounded compatibility
    /// read, but they are never the canonical key.
    #[test]
    fn old_cache_spellings_are_distinct_from_the_canonical_key() {
        for (input, canonical, precanonical) in [
            (
                "registry-1.docker.io/alpine",
                "docker.io/library/alpine:latest",
                "registry-1.docker.io/alpine:latest",
            ),
            (
                "DOCKER.IO/alpine",
                "docker.io/library/alpine:latest",
                "DOCKER.IO/alpine:latest",
            ),
            (
                "alpine:latest",
                "docker.io/library/alpine:latest",
                "docker.io/library/alpine:latest",
            ),
        ] {
            let target = OciTarget::parse(input).unwrap();
            assert_eq!(target.canonical().whole(), canonical, "{input}");
            assert_eq!(target.precanonical().whole(), precanonical, "{input}");
        }
    }

    #[test]
    fn debug_rendering_carries_no_reference() {
        let target = OciTarget::parse("registry.example/private:tag").unwrap();
        let rendered = format!("{target:?}");
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("registry.example"));
    }

    #[test]
    fn every_decision_is_total_over_its_measured_facts() {
        for bits in 0..16 {
            let facts = HubHostFacts {
                is_docker_io: bits & 1 != 0,
                is_index_docker_io: bits & 2 != 0,
                is_registry_1_docker_io: bits & 4 != 0,
                has_port: bits & 8 != 0,
            };
            assert_eq!(folds_to_docker_io(facts), bits & 8 == 0 && bits & 7 != 0);
        }
        for bits in 0..4 {
            assert_eq!(
                library_prefix_applies(LibraryPrefixFacts {
                    registry_is_docker_io: bits & 1 != 0,
                    repository_has_slash: bits & 2 != 0,
                }),
                bits == 1
            );
        }
        for bits in 0..8 {
            assert_eq!(
                digest_is_acceptable(DigestFacts {
                    algorithm_supported: bits & 1 != 0,
                    hex_length_matches: bits & 2 != 0,
                    hex_is_hexadecimal: bits & 4 != 0,
                }),
                bits == 7
            );
        }
    }

    /// The strict digest grammar accepts exactly the three supported
    /// algorithms at their exact lengths and folds upper-case hex.
    #[test]
    fn strict_digest_grammar() {
        for (algorithm, length) in [("sha256", 64), ("sha384", 96), ("sha512", 128)] {
            assert!(canonical_digest(&format!("{algorithm}:{}", "f".repeat(length))).is_ok());
            assert!(canonical_digest(&format!("{algorithm}:{}", "F".repeat(length))).is_ok());
            assert!(canonical_digest(&format!("{algorithm}:{}", "f".repeat(length - 1))).is_err());
            assert!(canonical_digest(&format!("{algorithm}:{}", "f".repeat(length + 1))).is_err());
        }
        for rejected in [
            "SHA256:".to_string() + &"a".repeat(64),
            "sha1:".to_string() + &"a".repeat(40),
            "sha256:".to_string() + &"z".repeat(64),
            "sha256".to_string(),
            String::new(),
        ] {
            assert!(canonical_digest(&rejected).is_err(), "{rejected:?}");
        }
    }
}
