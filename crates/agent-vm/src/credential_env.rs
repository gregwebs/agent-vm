//! `source: env` (agent-vm #163): host environment values a launch selected,
//! captured before the launch spawns any child and removed from agent-vm's own
//! environment so no child of that launch inherits them. Capture runs only on
//! the launch path; verbs that select no credentials (`agent-vm msb <verb>`,
//! `agent-vm setup`) remove nothing.
//!
//! Why here and why then: `main` spawns `msb --version` (`point_at_msb`) and
//! `run::launch` spawns `git`/`gh` long before phase-1 resolution, and every
//! child inherits the environment. `remove_var` is also only sound while the
//! process is single-threaded, i.e. before Tokio. So capture is `main`'s
//! prologue, not part of resolution.
//!
//! What is not claimed: the parent shell keeps its variable; Linux
//! `/proc/<pid>/environ` still shows agent-vm's *initial* environment block to
//! same-uid processes (unsetenv edits the pointer array, not the strings); and
//! `Zeroizing` wipes only the copies this module owns (ADR-0025's list).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::OsStringExt as _;

use vstd::prelude::*;
use zeroize::Zeroizing;

use crate::credential_resolver::CredentialSource;
use crate::credential_yaml::{AuthorizationSet, GuestEnvName, SourceKind};
use crate::secret_store::{Resolved, SecretValue, ServiceName};

verus! {

/// The Boolean selection decision for one credential: capture (and remove)
/// its host variable iff the name is requested, it is authorized, and that
/// authorization selects `source: env`. Anything less leaves the variable
/// untouched, which is what keeps an unrequested authorization inert.
///
/// Only this Boolean kernel is proved. The loop that feeds it, the lookup, and
/// the read/removal are the trusted adapter [`EnvCapture::take_with`] /
/// [`EnvCapture::take_from_process`], checked by E1/E5 and the subprocess
/// controls, not by this contract (ADR-0018 scope; same shape as
/// `provider_replaced`).
pub(crate) fn env_source_selected(requested: bool, authorized: bool, env_source: bool) -> (selected: bool)
    ensures
        selected == (requested && authorized && env_source),
{
    requested && authorized && env_source
}

} // verus!

/// One selected variable, as captured.
enum Captured {
    /// Unset, or set to the empty string (treated alike; see USAGE.md).
    Unset,
    /// The raw bytes, validated on every read by `SecretValue::try_parse`.
    Present(Zeroizing<Vec<u8>>),
}

/// The selected host values of one launch. Holds no value it was not asked
/// for: every key is a requested, authorized, `source: env` service.
pub(crate) struct EnvCapture {
    selected: BTreeMap<ServiceName, Captured>,
}

impl fmt::Debug for EnvCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.selected.iter().map(|(name, value)| {
                (
                    name,
                    match value {
                        Captured::Unset => "unset",
                        Captured::Present(_) => "set",
                    },
                )
            }))
            .finish()
    }
}

impl EnvCapture {
    pub(crate) fn none() -> Self {
        Self {
            selected: BTreeMap::new(),
        }
    }

    /// Take every selected variable out of this process's environment.
    ///
    /// Contract: call only while the process is single-threaded and has spawned
    /// no child, i.e. from `main` before `point_at_msb` and before Tokio.
    pub(crate) fn take_from_process(
        requested: &BTreeSet<ServiceName>,
        authorizations: &AuthorizationSet,
    ) -> Self {
        Self::take_with(requested, authorizations, |name| {
            let value = std::env::var_os(name.as_str());
            // SAFETY: see the contract above — `main` runs this before any
            // thread or child exists, the same invariant as `point_at_msb`'s
            // `set_var`. The variable is removed whether or not it was set, so
            // "unset" is also what every child observes.
            unsafe { std::env::remove_var(name.as_str()) };
            value
        })
    }

    /// The pure decision with the environment injected: unit tests (here and in
    /// `credential_resolver`) drive this without touching the process
    /// environment. Safe to expose: it reads nothing itself.
    pub(crate) fn take_with(
        requested: &BTreeSet<ServiceName>,
        authorizations: &AuthorizationSet,
        mut take: impl FnMut(&GuestEnvName) -> Option<OsString>,
    ) -> Self {
        let mut selected = BTreeMap::new();
        for service in requested {
            let Some(credential) = authorizations.get(service) else {
                continue;
            };
            // `requested` and `authorized` are true by construction here.
            if !env_source_selected(true, true, credential.source() == SourceKind::Environment) {
                continue;
            }
            let captured = match take(credential.env_name()) {
                Some(value) if !value.is_empty() => {
                    Captured::Present(Zeroizing::new(value.into_vec()))
                }
                _ => Captured::Unset,
            };
            selected.insert(service.clone(), captured);
        }
        Self { selected }
    }

    /// Whether this launch reads `service` from the environment. True for every
    /// selected service, set or not, so the router never falls through to the
    /// keychain for one (AC1). Records the trusted adapter's selection; only the
    /// Boolean kernel [`env_source_selected`] is proved.
    pub(crate) fn selects(&self, service: &ServiceName) -> bool {
        self.selected.contains_key(service)
    }
}

impl CredentialSource for EnvCapture {
    fn resolve(&self, service: &ServiceName) -> Resolved {
        match self.selected.get(service) {
            Some(Captured::Present(bytes)) => match SecretValue::try_parse(bytes.to_vec()) {
                Ok(value) => Resolved::Value(value),
                Err(rejection) => Resolved::InvalidValue(rejection),
            },
            Some(Captured::Unset) | None => Resolved::Missing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::{MAX_SECRET_VALUE_LEN, ValueRejection};

    fn service() -> ServiceName {
        ServiceName::parse("alpha").unwrap()
    }
    fn names() -> BTreeSet<ServiceName> {
        [service()].into()
    }
    fn authorization(environment: bool) -> AuthorizationSet {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".config/agent-vm");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("credentials.yaml"), format!(
            "credentials:\n  - service: alpha\n{}    apiKey:\n      name: CREDENTIAL_ENV_TEST_SELECTED\n      inject: [{{domain: api.example.com, scheme: bearer}}]\n",
            if environment { "    source: env\n" } else { "" }
        )).unwrap();
        crate::credential_yaml::load(home.path()).unwrap()
    }

    /// The direct launch (#398) requests no service, so it must read and remove
    /// no host variable even when an authorization for the *same* name exists:
    /// the variable therefore stays set for the process that launched it.
    #[test]
    fn an_empty_request_set_reads_and_removes_nothing() {
        let set = authorization(true);
        let capture = EnvCapture::take_with(&BTreeSet::new(), &set, |name| {
            panic!("a direct launch must not read {}", name.as_str());
        });
        assert!(!capture.selects(&service()));
        assert!(matches!(capture.resolve(&service()), Resolved::Missing));
        // Positive control for the same name: a requesting launch does select
        // it, so the empty-set result above is not vacuous.
        let selected = EnvCapture::take_with(&names(), &set, |_| Some("sk-value".into()));
        assert!(selected.selects(&service()));
    }

    #[test]
    fn selection_is_exactly_requested_authorized_and_env() {
        for requested in [false, true] {
            for authorized in [false, true] {
                for env in [false, true] {
                    let set = if authorized {
                        authorization(env)
                    } else {
                        AuthorizationSet::empty()
                    };
                    let mut calls = Vec::new();
                    let capture = EnvCapture::take_with(
                        &if requested { names() } else { BTreeSet::new() },
                        &set,
                        |name| {
                            calls.push(name.as_str().to_owned());
                            Some("sk-ok".into())
                        },
                    );
                    let expected = requested && authorized && env;
                    assert_eq!(capture.selects(&service()), expected);
                    assert_eq!(
                        calls,
                        if expected {
                            vec!["CREDENTIAL_ENV_TEST_SELECTED"]
                        } else {
                            vec![]
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn capture_outcomes() {
        let set = authorization(true);
        let cases = [
            (None, None),
            (Some(vec![]), None),
            (Some(b"sk-ok".to_vec()), None),
            (Some(b" sk".to_vec()), Some(ValueRejection::EdgeSpace)),
            (Some(vec![0xff]), Some(ValueRejection::NonPrintable)),
            (
                Some(vec![b'x'; MAX_SECRET_VALUE_LEN + 1]),
                Some(ValueRejection::TooLong),
            ),
        ];
        for (bytes, rejection) in cases {
            let present = bytes.as_ref().is_some_and(|v| !v.is_empty());
            let capture =
                EnvCapture::take_with(&names(), &set, |_| bytes.clone().map(OsString::from_vec));
            match (capture.resolve(&service()), rejection) {
                (Resolved::Missing, None) => assert!(!present),
                (Resolved::Value(value), None) => assert_eq!(value.expose_for_test(), "sk-ok"),
                (Resolved::InvalidValue(actual), Some(expected)) => assert_eq!(actual, expected),
                _ => panic!("unexpected capture outcome"),
            }
        }
    }

    #[test]
    fn resolve_is_repeatable() {
        let capture =
            EnvCapture::take_with(&names(), &authorization(true), |_| Some("sk-repeat".into()));
        for _ in 0..2 {
            let Resolved::Value(value) = capture.resolve(&service()) else {
                panic!("expected value")
            };
            assert_eq!(value.expose_for_test(), "sk-repeat");
        }
    }

    #[test]
    fn debug_never_renders_a_value() {
        let capture = EnvCapture::take_with(&names(), &authorization(true), |_| {
            Some("sk-CANARY-debug".into())
        });
        let debug = format!("{capture:?}");
        assert!(debug.contains("alpha"));
        assert!(!debug.contains("sk-CANARY-debug"));
    }

    #[test]
    fn take_from_process_removes_only_selected_variables() {
        let mut guard = crate::test_env::guard();
        guard.set_var("CREDENTIAL_ENV_TEST_SELECTED", "sk-selected");
        guard.set_var("CREDENTIAL_ENV_TEST_INERT", "visible");
        let capture = EnvCapture::take_from_process(&names(), &authorization(true));
        assert!(std::env::var_os("CREDENTIAL_ENV_TEST_SELECTED").is_none());
        assert_eq!(
            std::env::var("CREDENTIAL_ENV_TEST_INERT").unwrap(),
            "visible"
        );
        let Resolved::Value(value) = capture.resolve(&service()) else {
            panic!("expected value")
        };
        assert_eq!(value.expose_for_test(), "sk-selected");
    }
}
