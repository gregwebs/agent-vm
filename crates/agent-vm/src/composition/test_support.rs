//! Shared fixtures for the composition test suites: fixed base/root values,
//! validated argument construction, real context digests and — from the plan
//! checkpoint — graph and plan helpers. Test-only: it exists so the suites
//! state inputs rather than to widen any production seam.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::context::NormalizedContext;
use super::hex;
use super::identity::{
    AccountLayerIdentity, BuildArgName, BuildArgValue, BuildArgs, ContextDigest, ManifestDigest,
    RootIdentity, RootInputs,
};

/// A validated fixture layer name, through config's authoritative validator.
pub(crate) fn layer_name(raw: &str) -> super::dag::LayerName {
    super::dag::LayerName::for_test(raw)
}

/// Full lowercase hex of the SHA-256 of `bytes`.
pub(crate) fn digest_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The one fictional base manifest digest the pure fixtures share.
pub(crate) fn base_digest() -> ManifestDigest {
    ManifestDigest::parse(&format!("sha256:{}", "1".repeat(64))).expect("valid fixture digest")
}

pub(crate) fn arg_name(raw: &str) -> BuildArgName {
    BuildArgName::parse(raw).expect("fixture argument name is valid")
}

pub(crate) fn arg_value(raw: &str) -> BuildArgValue {
    BuildArgValue::parse(raw).expect("fixture argument value has no NUL")
}

pub(crate) fn args(pairs: &[(&str, &str)]) -> BuildArgs {
    let mut args = BuildArgs::default();
    for (name, value) in pairs {
        args.insert(arg_name(name), arg_value(value))
            .expect("fixture arguments are unique");
    }
    args
}

pub(crate) fn root(accounts: Option<AccountLayerIdentity>) -> RootIdentity {
    RootIdentity::compute(&RootInputs {
        base: &base_digest(),
        accounts,
    })
}

/// A real `ContextDigest` over a tiny on-disk fixture whose only file is a
/// `Dockerfile` with `dockerfile` as its bytes. The temporary directory is
/// dropped normally: `ContextDigest` owns its bytes and borrows nothing from
/// the directory, so RAII cleanup is correct here.
pub(crate) fn context_digest(dockerfile: &str) -> ContextDigest {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("Dockerfile"), dockerfile).expect("write Dockerfile");
    ContextDigest::of(&NormalizedContext::read(dir.path()).expect("read context"))
}

/// A pair of distinct real context digests, cached once per process so
/// property runners need not create a tempdir per case.
pub(crate) fn two_context_digests() -> &'static (ContextDigest, ContextDigest) {
    static CACHE: OnceLock<(ContextDigest, ContextDigest)> = OnceLock::new();
    CACHE.get_or_init(|| {
        (
            context_digest("FROM scratch\n"),
            context_digest("FROM busybox\n"),
        )
    })
}
