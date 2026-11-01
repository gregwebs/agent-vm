//! Launch resolution: turning a tool's `credentials = [...]` **request** into
//! the credentials this one launch may actually use (agent-vm #161).
//!
//! Two authorities meet here and neither may grow:
//!
//! - The tool configuration *requests* names. It cannot define an
//!   authorization, and it cannot widen one: the set of services whose value
//!   may leave the keychain is exactly `ready`, built from the user's
//!   `credentials.yaml` (AC8).
//! - The authorization file *authorizes*. It does not force a launch to use
//!   anything: an authorized service that no launch requests changes nothing.
//!
//! # Precedence: the authorization wins (#162)
//!
//! For a requested name, the YAML authorization is resolved **first**. When one
//! exists it *completely replaces* the same-named built-in provider's
//! credential handling — source acquisition, the guest placeholder, proxy
//! injection, and OAuth capture/refresh — and there is deliberately **no
//! fallback**: an unavailable authorized value must never re-enable the
//! built-in, because that would silently downgrade a shielded credential to a
//! guest-visible placeholder the user never asked for. The providers this
//! launch replaced are recorded in [`LaunchCredentials::replaced`] and every
//! built-in *credential* facet is gated on their complement; the built-in's
//! guest *configuration* and persistence (onboarding bypass files, `$HOME`
//! links, state dirs, Copilot's `trusted_folders`) are untouched — a credential
//! authorization does not speak for them ([`crate::secrets`],
//! `docs/adr/0025-yaml-credential-shielding.md`).
//!
//! # Availability is negotiable; configuration is not
//!
//! [`MissingCredentialPolicy`] moves the availability of a *YAML* credential
//! only. A malformed authorization file, an unsupported field, a rejected
//! stored value, any guest-env ownership conflict, and a *built-in* provider's
//! own missing-credential bail stay hard errors under both variants.
//!
//! # Two phases, and why
//!
//! Resolution runs twice per launch. Phase 1 (this module, before any sandbox
//! record is written) proves the source is *available* and drops the value
//! immediately: it decides between a warning, a withheld credential, and a
//! hard error before boot. Phase 2 is
//! [`LaunchCredentialResolver`], called by the runtime immediately before
//! `fork` on a value it never keeps. Splitting them means a locked or missing
//! keychain fails *before* a sandbox is created, rather than producing a
//! booted-but-uncredentialed sandbox.
//!
//! A SecretSpec source reads through a `secretspec serve --read-only` session
//! started by the first phase-1 read and reused by phase 2; `CredentialSessions`
//! ends it when `create` returns (#202).
//!
//! A keychain source reads once per requested authorized service in phase 1,
//! then once per durable reference occurrence in phase 2 (several per service
//! when it has several rules). `LaunchSource` routes env sources to immutable
//! bytes captured in `main`, never rereading the environment. Rotation is
//! launch-scoped: `agent-vm secret set` does not reach a running sandbox.
//!
//! [`LaunchCredentials::assemble_guest_env`] is the one ownership-aware guest
//! environment decision. Every writer whose contribution *could* carry a name a
//! credential owns is settled there: a tool-declared `env` key is refused, and
//! provider-forwarded pairs are dropped (AC2). The launcher's
//! own contributions (`PATH`, the guest-identity triple, `GUEST_ALWAYS_ENV`) are
//! emitted unfiltered because their names are refused as credential-owned names
//! at load time (see [`LaunchCredentials::assemble_guest_env`] for the precise
//! boundary).
//!
//! # The `Send + Sync` seam
//!
//! [`microsandbox::CredentialResolver`] is `Send + Sync`, and the SDK create
//! call takes an `Arc<dyn CredentialResolver>`. `SecretStore` is **not**
//! `Sync` in a `#[cfg(test)]` build: it carries a `Cell` for inventory-write
//! fault injection, and `fake::FakeKeychain` uses `RefCell` behind an `Rc`.
//! Implementing the SDK trait on a type that *holds* a store would therefore
//! fail to compile for `cargo test`, not just be awkward to fake.
//!
//! [`CredentialSource`] is that seam: a minimal `Send + Sync` read that the
//! resolver holds behind a `dyn`, with the production implementation wrapping
//! the store in a `Mutex` (which is `Sync` whenever the store is `Send`). A
//! unit test supplies a plain pre-seeded source, and `SecretStore::resolve`
//! is tested separately where no `Sync` bound applies.
//!
//! # No plaintext anywhere durable
//!
//! Phase 1 drops the value; phase 2 hands it to the runtime's private fd. The
//! built `SandboxConfig` carries only the reference (`credential_injection`).
//! Nothing here writes a file, and no resolved value is formatted into an
//! error, a warning or a notice: the messages name a service and a closed
//! failure class only.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use vstd::prelude::*;
use zeroize::Zeroizing;

use crate::config::USER_CONFIG_DIR_RELATIVE;
use crate::credential_env::EnvCapture;
use crate::credential_provider::{CredentialProvider, ProviderSet};
use crate::credential_yaml::{self, AuthorizationSet, GuestEnvName, SourceKind, SourceSelection};
use crate::secret_store::{
    BoundedKeychainReads, KeychainFailure, Resolved, SecretStore, ServiceName, SystemKeychain,
    system_store,
};
// Named only by the debug-only seam below and by the tests, so a release build
// (which compiles neither) would report it as an unused import.
#[cfg(debug_assertions)]
use crate::secret_store::SecretValue;

/// The minimal read the resolver needs, and the `Send + Sync` boundary that
/// keeps the SDK's trait bound away from the store's test-only `!Sync` fields.
pub(crate) trait CredentialSource: Send + Sync {
    fn resolve(&self, service: &ServiceName) -> Resolved;
}

/// The production source: the host keychain, read under the store's own lock.
///
/// The `Mutex` is not for mutual exclusion (a resolve already takes the store's
/// file lock) but for the trait bound: it makes the source `Sync` from the
/// store being `Send`, independent of whether the test-only `Cell` field is
/// compiled in.
///
/// The backend is [`BoundedKeychainReads`] because a phase-1 resolve is exactly
/// where an unbounded platform read used to park the launcher forever while
/// holding the secret inventory's lock (#251). The store's lock wait is bounded
/// the same way, so a peer holding it cannot park a launch either (#291).
pub(crate) struct KeychainCredentialSource {
    store: Mutex<SecretStore<BoundedKeychainReads<SystemKeychain>>>,
}

impl KeychainCredentialSource {
    pub(crate) fn system() -> Result<Arc<dyn CredentialSource>> {
        #[cfg(debug_assertions)]
        if let Some(source) = test_credential_override() {
            return Ok(source);
        }
        Ok(Arc::new(Self {
            store: Mutex::new(system_store()?),
        }))
    }
}

/// Debug-only launch-credential seam for the subprocess tests (agent-vm #161).
///
/// When `AGENT_VM_TEST_CREDENTIAL` is set to `<service>=<value>`, that one
/// service resolves to the synthetic value and every other service is
/// [`Resolved::Missing`].
///
/// It exists so `tests/config_launch_driven.rs` can reach a *genuinely
/// credential-bearing* create - a durable `header_credentials` entry and
/// therefore the runtime's `__capabilities` probe - without an OS keychain
/// (Linux CI has no Secret Service, so a real key would read as `Unavailable`
/// and withhold). It is **not** a value oracle: it never reads the user's store
/// or any value an `agent-vm secret set` wrote, and it returns only the bytes
/// the test process itself supplied in its own environment. Like
/// `RecordingKeychain`, it is compiled out of release builds, so a shipped
/// binary cannot be pointed at it.
#[cfg(debug_assertions)]
fn test_credential_override() -> Option<Arc<dyn CredentialSource>> {
    let spec = std::env::var("AGENT_VM_TEST_CREDENTIAL").ok()?;
    let (service, value) = spec.split_once('=')?;
    let service = ServiceName::parse(service).ok()?;
    Some(Arc::new(TestCredentialSource {
        service,
        value: value.to_owned(),
    }))
}

#[cfg(debug_assertions)]
struct TestCredentialSource {
    service: ServiceName,
    value: String,
}

#[cfg(debug_assertions)]
impl CredentialSource for TestCredentialSource {
    fn resolve(&self, service: &ServiceName) -> Resolved {
        if *service != self.service {
            return Resolved::Missing;
        }
        match SecretValue::try_parse(self.value.as_bytes().to_vec()) {
            Ok(value) => Resolved::Value(value),
            Err(rejection) => Resolved::InvalidValue(rejection),
        }
    }
}

impl CredentialSource for KeychainCredentialSource {
    fn resolve(&self, service: &ServiceName) -> Resolved {
        match self.store.lock() {
            Ok(store) => store.resolve(service),
            // A poisoned lock is a panic in another thread, not a keychain
            // failure; from the launch's point of view the source could not be
            // read, which is the `Unavailable` class.
            Err(_) => Resolved::Unavailable(KeychainFailure::Unknown),
        }
    }
}

/// The one source a launch reads (#163): each requested service is routed to
/// the single source its authorization selects. An env-sourced service whose
/// variable was unset resolves `Missing`; it is never retried against the
/// keychain, and a keychain-sourced service never reads the environment.
///
/// `keychain` is `None` when no requested authorization is keychain-sourced, so
/// a built-in-only or env-only launch constructs no keychain at all (an unset
/// `$HOME` or a missing Secret Service changes nothing for it).
pub(crate) struct LaunchSource {
    keychain: Option<Arc<dyn CredentialSource>>,
    environment: EnvCapture,
    /// `None` when no requested authorization selects SecretSpec, so a launch
    /// without one builds no session pool and spawns nothing.
    secretspec: Option<Arc<crate::credential_secretspec::SecretspecSource>>,
}

impl LaunchSource {
    /// Test-only: build the router from its three parts, for the cross-source
    /// routing test (#202 R1), which must see one backend per service.
    #[cfg(test)]
    pub(crate) fn for_test(
        keychain: Option<Arc<dyn CredentialSource>>,
        environment: EnvCapture,
        secretspec: Option<Arc<crate::credential_secretspec::SecretspecSource>>,
    ) -> Self {
        Self {
            keychain,
            environment,
            secretspec,
        }
    }

    /// Test-only: whether the SecretSpec source owns this service. The routing
    /// test asserts one backend per service without reaching into the pool.
    #[cfg(test)]
    pub(crate) fn secretspec_selects(&self, service: &ServiceName) -> bool {
        self.secretspec
            .as_ref()
            .is_some_and(|secretspec| secretspec.selects(service))
    }
}

impl CredentialSource for LaunchSource {
    fn resolve(&self, service: &ServiceName) -> Resolved {
        if self.environment.selects(service) {
            return self.environment.resolve(service);
        }
        if let Some(secretspec) = &self.secretspec
            && secretspec.selects(service)
        {
            return secretspec.resolve(service);
        }
        match &self.keychain {
            Some(keychain) => keychain.resolve(service),
            None => Resolved::Missing,
        }
    }
}

/// Phase 1's three products: the resolved credentials, the source phase 2 reads
/// through, and the guard that ends this launch's host-side sessions.
pub(crate) type ResolvedLaunch = (
    LaunchCredentials,
    Option<Arc<dyn CredentialSource>>,
    CredentialSessions,
);

/// Ends the host-side credential sessions this launch opened (today: one
/// `secretspec serve` per pinned session key).
///
/// `run::launch` closes it the moment `create` returns, and dropping it closes
/// too, so every early return ends them as well. Closing makes later reads fail
/// without spawning, so a resolver `Arc` the SDK holds longer cannot revive a
/// session. It proves only that **no later read spawns or reads**: dropping a
/// `JoinHandle` detaches its task, so this cannot withdraw a value the create
/// task already acquired (ADR-0055).
#[must_use]
pub(crate) struct CredentialSessions(Option<Arc<crate::credential_secretspec::SecretspecSource>>);

impl CredentialSessions {
    pub(crate) fn none() -> Self {
        Self(None)
    }

    /// Explicit close, at the one point the launch knows phase 2 has ended.
    pub(crate) fn close(self) {}

    /// Test-only: a guard over an already-built source, so the close path is
    /// exercised through the type the launch actually holds.
    #[cfg(test)]
    pub(crate) fn for_test(
        source: Option<Arc<crate::credential_secretspec::SecretspecSource>>,
    ) -> Self {
        Self(source)
    }
}

impl Drop for CredentialSessions {
    fn drop(&mut self) {
        if let Some(source) = self.0.take() {
            source.close();
        }
    }
}

/// A launch's credential inputs, gathered in `main` before the first child
/// process and before Tokio (#163): the authorization file, loaded exactly
/// once, and the host values its `source: env` entries select.
///
/// A load error is carried, not raised, so `run::launch` reports it at the same
/// point (and after the same notices) as before #163.
pub(crate) struct CredentialPreflight {
    requested: BTreeSet<ServiceName>,
    authorizations: Result<AuthorizationSet>,
    environment: EnvCapture,
}

#[cfg(test)]
thread_local! {
    /// How many keychain backends **this thread** has constructed.
    ///
    /// R2 constrains construction, and construction has no other observable: a
    /// keychain built and never read looks exactly like one never built, which
    /// is why the routing test alone cannot prove R2. A thread-local (not a
    /// global) so parallel tests cannot see each other's counts; `resolve` is
    /// synchronous, so a launch's construction always lands on its own test's
    /// thread.
    static KEYCHAIN_BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many keychain backends this thread has constructed so far.
#[cfg(test)]
fn keychain_built() -> usize {
    KEYCHAIN_BUILT.with(std::cell::Cell::get)
}

impl CredentialPreflight {
    /// `main`'s prologue only (see `EnvCapture::take_from_process`).
    pub(crate) fn capture(requested: &BTreeSet<ServiceName>) -> Self {
        let requested = requested.clone();
        if requested.is_empty() {
            // A launch that requests nothing never reads the file (#161).
            return Self {
                requested,
                authorizations: Ok(AuthorizationSet::empty()),
                environment: EnvCapture::none(),
            };
        }
        match load_authorizations() {
            Ok(set) => {
                let environment = EnvCapture::take_from_process(&requested, &set);
                Self {
                    requested,
                    authorizations: Ok(set),
                    environment,
                }
            }
            // Nothing is selected without a valid file, so nothing is captured.
            Err(error) => Self {
                requested,
                authorizations: Err(error),
                environment: EnvCapture::none(),
            },
        }
    }

    /// For built-in commands and tests: no request, nothing captured.
    pub(crate) fn none() -> Self {
        Self {
            requested: BTreeSet::new(),
            authorizations: Ok(AuthorizationSet::empty()),
            environment: EnvCapture::none(),
        }
    }

    /// Phase 1, plus the source phase 2 will use and the guard that ends this
    /// launch's host-side sessions. `None` source when nothing was requested
    /// (the create path then takes the resolver-free branch).
    ///
    /// A keychain backend is built only when some requested authorization is
    /// keychain-sourced, and a SecretSpec pool only when one selects
    /// `source: secretspec`, so a launch that names neither constructs neither.
    pub(crate) fn resolve(self, policy: MissingCredentialPolicy) -> Result<ResolvedLaunch> {
        if self.requested.is_empty() {
            return Ok((
                LaunchCredentials::default(),
                None,
                CredentialSessions::none(),
            ));
        }
        let authorizations = self.authorizations?;
        let needs_keychain = self.requested.iter().any(|name| {
            authorizations
                .get(name)
                .is_some_and(|credential| credential.source() == SourceKind::Keychain)
        });
        let keychain = if needs_keychain {
            #[cfg(test)]
            KEYCHAIN_BUILT.with(|count| count.set(count.get() + 1));
            Some(KeychainCredentialSource::system()?)
        } else {
            None
        };
        let secretspec = crate::credential_secretspec::SecretspecSource::select(
            &self.requested,
            &authorizations,
        )
        .map(Arc::new);
        // Cloned before phase 1 runs, so a `?` below drops the guard and closes
        // whatever phase 1 already started.
        let sessions = CredentialSessions(secretspec.clone());
        let source: Arc<dyn CredentialSource> = Arc::new(LaunchSource {
            keychain,
            environment: self.environment,
            secretspec,
        });
        let launch = resolve_launch(&self.requested, &authorizations, source.as_ref(), policy)?;
        Ok((launch, Some(source), sessions))
    }
}

/// Phase 2: the value the runtime's spawn path asks for, immediately before
/// `fork`, reading the launch's routed source.
///
/// `allowed` is exactly the services this launch authorized **and** requested.
/// The check is load-bearing (AC8): a durable config tampered with between
/// build and spawn cannot widen what is read, because a reference outside the
/// set is refused rather than resolved.
pub(crate) struct LaunchCredentialResolver {
    source: Arc<dyn CredentialSource>,
    allowed: BTreeSet<ServiceName>,
}

impl microsandbox::CredentialResolver for LaunchCredentialResolver {
    fn resolve(
        &self,
        reference: &str,
    ) -> std::result::Result<Zeroizing<String>, microsandbox::CredentialResolveError> {
        // The reference is the folded service name. A reference that is not a
        // valid service name cannot have been authorized, so it is refused
        // without being echoed anywhere.
        let Ok(service) = ServiceName::parse(reference) else {
            return Err(microsandbox::CredentialResolveError::not_authorized());
        };
        if !self.allowed.contains(&service) {
            return Err(microsandbox::CredentialResolveError::not_authorized());
        }
        match self.source.resolve(&service) {
            Resolved::Value(value) => Ok(value.into_zeroizing()),
            Resolved::Missing => Err(microsandbox::CredentialResolveError::not_found()),
            // "Locked", "no Secret Service" and "the stored bytes are not an
            // acceptable value" are one closed kind here: the SDK's own error
            // is index-and-label only, and a richer category would have to
            // carry text that could contain secret material.
            Resolved::Unavailable(_)
            | Resolved::SecretspecUnavailable(_)
            | Resolved::InvalidValue(_) => Err(microsandbox::CredentialResolveError::failed()),
        }
    }
}

/// One credential this launch may use: a service name and the origins it is
/// authorized for. **No value.**
#[derive(Debug, Clone)]
pub(crate) struct ReadyCredential {
    service: ServiceName,
    inject: Vec<credential_yaml::InjectionRule>,
}

impl ReadyCredential {
    pub(crate) fn service(&self) -> &ServiceName {
        &self.service
    }

    pub(crate) fn inject(&self) -> &[credential_yaml::InjectionRule] {
        &self.inject
    }
}

/// Whether this launch may continue past a credential it asked for but cannot
/// get. The host-only `--allow-missing-credentials` flag selects `Warn`.
///
/// It is deliberately *not* a `bool`: `resolve_launch` already takes three
/// reference arguments, and this is the one that changes the outcome class of
/// the whole function (CODING_STANDARDS, "strong typing").
///
/// It moves **availability of a YAML credential** only. A malformed
/// authorization file, an unsupported field, a rejected stored value, any
/// guest-env ownership conflict, and a *built-in* provider's own
/// missing-credential bail all stay hard errors under both variants: the
/// override cannot relax configuration, destination or value-handling rules
/// (docs/specs/credential-shielding.md, Availability and failure behavior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingCredentialPolicy {
    /// Default: a missing authorization, or an unavailable `required: true`
    /// value, refuses the launch.
    Fail,
    /// `--allow-missing-credentials`: warn, withhold, and launch.
    Warn,
}

/// What the guest variable named by `apiKey.name` must end up as.
///
/// "Publish nothing" is not "leave it unset": the name is *owned* by this
/// authorization, so agent-vm must actively suppress every other writer (a tool-declared
/// `env` key, a provider-forwarded pair) rather than merely declining to add
/// one (AC2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvDisposition {
    /// Publish the non-secret sentinel, last of every emission point.
    Sentinel,
    /// Publish nothing, and suppress every other writer of this name.
    Unset,
}

/// Every writer that contributes a guest environment variable, in the order the
/// final environment is built (guest env is last-wins).
///
/// The writers feeding [`LaunchCredentials::assemble_guest_env`]. Filtering
/// happens centrally there rather than at each emission site, so the
/// credential-relevant writers (`tool_env`, `provider`) can only
/// be settled in one place (agent-vm #161 review, M1). The launcher-owned
/// writers (`path`, `identity`, `always`) are emitted unfiltered; their names
/// are already refused as credential-owned names at load time, so filtering
/// them here would be unreachable code.
pub(crate) struct GuestEnvSources<'a> {
    /// The launched tool's own config-declared `env` pairs.
    pub tool_env: &'a BTreeMap<String, String>,
    /// The booted image's own `PATH`, or `None` to leave `PATH` entirely
    /// unset so the acquired OCI config supplies it. `None` never means "fall
    /// back to a literal": the exec layer resolves the effective PATH from the
    /// sandbox config after create (#258).
    pub path: Option<String>,
    /// The launcher-owned guest identity triple (`HOME`/`USER`/`LOGNAME`):
    /// `user::guest_identity_env` in default mode, `user::root_identity_env`
    /// under `--root`, never empty (#258).
    pub identity: &'a [(&'static str, String)],
    /// The launcher's always-env pairs.
    pub always: &'a [(&'static str, &'static str)],
    /// Provider-owned pairs (e.g. `COPILOT_GITHUB_TOKEN`).
    pub provider: &'a [(&'static str, &'static str)],
}

/// The resolved credential state of one launch.
#[derive(Debug, Default)]
pub(crate) struct LaunchCredentials {
    ready: Vec<ReadyCredential>,
    withheld: Vec<Withheld>,
    owned_env: BTreeMap<GuestEnvName, EnvDisposition>,
    /// Non-fatal notices that are *not* about a withheld credential (the
    /// authorization file's mode, the `proxyManaged` alias).
    notes: Vec<String>,
    /// Built-in providers a same-named authorization took over for this launch
    /// (#162). Every built-in *credential* facet is gated on the complement of
    /// this set; the built-in's configuration and persistence facets are not.
    replaced: ProviderSet,
}

/// Why a requested service could not be used. A closed enum, not a string, so
/// the message is composed at render time from the service name and a fixed
/// label - never from anything a source returned.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WithheldCause {
    Missing,
    EnvironmentUnset(GuestEnvName),
    Unavailable(KeychainFailure),
    /// SecretSpec answered `missing` **or** `undeclared` for this secret
    /// (#202). One cause for both, because the issue maps both to
    /// `Resolved::Missing`; the reason covers both readings plus the
    /// out-of-scope case, so the remedy stays actionable without inventing an
    /// outcome class.
    SecretspecMissing(crate::credential_secretspec::config::SecretspecName),
    SecretspecUnavailable(crate::credential_secretspec::SecretspecFailure),
    /// The launch requested a name that is neither a built-in provider nor
    /// authorized. Only reachable under `MissingCredentialPolicy::Warn`;
    /// under `Fail` this is the hard error it has always been.
    NotAuthorized,
}

/// A requested service whose source could not be read. Carries no value; the
/// reason is built from the closed cause above.
#[derive(Debug)]
pub(crate) struct Withheld {
    service: ServiceName,
    cause: WithheldCause,
    /// True when only `--allow-missing-credentials` kept this launch alive, so
    /// a warning that would otherwise have been fatal says so. Computed from
    /// the policy at construction, never from `required` alone, so the field is
    /// true for exactly the values it describes.
    via_override: bool,
}

/// The `secret set` command a message tells the user to run, quoted by
/// [`crate::shell`]. `ServiceName`'s charset keeps it plain today, so no note is
/// ever needed; taking the encoder means widening that charset cannot print an
/// unreadable command with no way to know.
fn secret_set_command(service: &ServiceName) -> String {
    let word = crate::shell::PastedWord::new(service.as_str().as_bytes());
    let note = crate::shell::note_parenthetical(&[&word]);
    format!("agent-vm secret set {word}{note}")
}

impl Withheld {
    /// The full, renderable reason. Names the service (user-controlled
    /// metadata, already shown by `secret ls`) and, for `Unavailable`, the
    /// closed failure message, so "locked" never reads as "not stored".
    pub(crate) fn reason(&self) -> String {
        match &self.cause {
            WithheldCause::Missing => format!(
                "no value is stored in the system keychain for `{}`; store it with `{}`",
                self.service,
                secret_set_command(&self.service)
            ),
            WithheldCause::Unavailable(failure) => format!(
                "the system keychain could not be read for `{}`: {}",
                self.service,
                failure.message()
            ),
            WithheldCause::EnvironmentUnset(name) => format!(
                "the host environment variable `{name}` selected by `{}` (`source: env`) was unset or empty when agent-vm started; export it before launching",
                self.service
            ),
            WithheldCause::SecretspecMissing(name) => format!(
                "SecretSpec has no value for `{name}`, which `{}` reads (`source: secretspec`): it \
                 is either not declared in the manifest for this profile/scope (a name outside \
                 the session scope answers the same way) or declared but unset. Declare it and \
                 set it with SecretSpec - agent-vm only reads SecretSpec-managed values; \
                 `agent-vm doctor` shows the configured manifest, profile and scope",
                self.service
            ),
            WithheldCause::SecretspecUnavailable(failure) => format!(
                "SecretSpec could not resolve `{}` (`source: secretspec`): {}",
                self.service,
                failure.message()
            ),
            WithheldCause::NotAuthorized => format!(
                "`{}` is neither a built-in credential provider nor authorized in {}/{}",
                self.service,
                USER_CONFIG_DIR_RELATIVE,
                credential_yaml::CREDENTIALS_FILE_NAME
            ),
        }
    }

    /// The complete launch warning line, so the module that knows *why* also
    /// knows how it reads. `run.rs` emits `warning: {notice}`.
    pub(crate) fn notice(&self) -> String {
        let reason = self.reason();
        if self.via_override {
            format!(
                "{reason}; continuing without it because --allow-missing-credentials was passed"
            )
        } else {
            format!("{reason}; continuing without it")
        }
    }
}

impl LaunchCredentials {
    pub(crate) fn ready(&self) -> &[ReadyCredential] {
        &self.ready
    }

    /// The built-ins whose credential handling a same-named authorization
    /// replaced. Empty for a launch with no same-named authorization, which is
    /// why every pre-#162 launch is bit-for-bit unchanged.
    pub(crate) fn replaced(&self) -> ProviderSet {
        self.replaced
    }

    /// The owned-variable dispositions. Test-only: production code reads them
    /// through `assemble_guest_env` and `owns_env`, which are the whole
    /// decision.
    #[cfg(test)]
    pub(crate) fn owned_env(&self) -> &BTreeMap<GuestEnvName, EnvDisposition> {
        &self.owned_env
    }

    /// Whether `raw` is a variable some authorization owns. Used to suppress
    /// other writers *by name*, before validating it as a guest env name, so a
    /// name that is owned is suppressed even if it could not itself be
    /// declared.
    pub(crate) fn owns_env(&self, raw: &str) -> bool {
        self.owned_env.keys().any(|name| name.as_str() == raw)
    }

    /// Whether some owned variable must end up *unset*, i.e. whether the launch
    /// needs the boot image's own `env` to answer "can it actually be unset?".
    pub(crate) fn needs_image_env_check(&self) -> bool {
        self.owned_env
            .values()
            .any(|disposition| *disposition == EnvDisposition::Unset)
    }

    /// The services this launch requested and was authorized for, but could not
    /// read. Each is emitted as a warning; this accessor is what makes the
    /// *set* available rather than only the prose.
    pub(crate) fn withheld(&self) -> &[Withheld] {
        &self.withheld
    }

    /// Non-fatal notices that are not about one withheld credential.
    pub(crate) fn notes(&self) -> &[String] {
        &self.notes
    }

    /// The phase-2 resolver, scoped to exactly the ready services.
    pub(crate) fn resolver(
        &self,
        source: Arc<dyn CredentialSource>,
    ) -> Arc<dyn microsandbox::CredentialResolver> {
        Arc::new(LaunchCredentialResolver {
            source,
            allowed: self.ready.iter().map(|c| c.service.clone()).collect(),
        })
    }

    /// Names owned with `sentinelEnv: false`: those must not collide with an
    /// environment variable the boot image itself ships, because the SDK
    /// builder cannot *remove* an image `ENV` — only override it (guest env is
    /// last-wins). Checked against the composed image's OCI config `env` at the
    /// one point the launch reads it; see `run.rs`.
    ///
    /// Ownership comes from the authorization, not from resolution success, so
    /// a *withheld* `sentinelEnv: false` credential owns its name here too: the
    /// image value would otherwise survive the launch un-suppressed.
    pub(crate) fn unset_names_in_image_env(
        &self,
        image_env: &BTreeSet<String>,
    ) -> Vec<GuestEnvName> {
        self.owned_env
            .iter()
            .filter(|(_, disposition)| **disposition == EnvDisposition::Unset)
            .filter(|(name, _)| {
                image_env.iter().any(|entry| {
                    entry
                        .split_once('=')
                        .is_some_and(|(key, _)| key == name.as_str())
                })
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Assemble the **final** guest environment, applying credential ownership
    /// exactly once (#161, AC2).
    ///
    /// This is the whole decision, computed apart from `SandboxBuilder` so it
    /// can be unit-tested: the caller emits the returned pairs in order and
    /// nothing else in this path consults ownership. The writers that can name
    /// a credential-owned variable are settled here rather than at their own
    /// emission sites:
    ///
    /// - `tool_env` — an owned name is **refused**;
    /// - `provider` — an owned name is **dropped**.
    ///
    /// The launcher-owned writers are emitted unfiltered on purpose (`path`,
    /// the guest-identity triple in `identity`, and `always`): every one of
    /// their names is refused as a credential-owned name at load time
    /// (`PATH`/`IS_SANDBOX`/`LANG` via `LAUNCHER_OWNED_ENV_NAMES`, the identity
    /// triple and the `MSB_` prefix via `GuestEnvName::parse`), so a credential
    /// can never own one and a filter would be dead code. The legacy wire-slot
    /// variables are a *separate* guest-env route (`network.secret(..).env(..)`)
    /// that is safe for the same `MSB_`-prefix reason; `credential_injection`
    /// asserts that invariant.
    ///
    /// The tool's own `env` declaring an owned name is refused here rather than
    /// in `config::check_env_key`, which is config-time and has no launch
    /// context. A provider variable an authorization owns is
    /// suppressed, including while the credential is withheld — "publish
    /// nothing" is not "leave it unset". The sentinel is appended **last** of
    /// every emission point so no other writer can displace it. Injection is
    /// deliberately not here: the header credential is registered from `ready`,
    /// so `sentinelEnv` cannot affect it (AC2).
    pub(crate) fn assemble_guest_env(
        &self,
        sources: GuestEnvSources<'_>,
    ) -> Result<Vec<(String, String)>> {
        for name in self.owned_env.keys() {
            if sources.tool_env.contains_key(name.as_str()) {
                anyhow::bail!(
                    "the tool's own `env` declares `{name}`, which is owned by an authorized \
                     credential in {}/{}; the credential decides that variable (see `sentinelEnv`)",
                    USER_CONFIG_DIR_RELATIVE,
                    authorization_file_name()
                );
            }
        }
        let mut env: Vec<(String, String)> = Vec::new();
        for (key, value) in sources.tool_env {
            // PATH is launcher/image-owned: a tool's own `env` never publishes
            // it, so with `path: None` no writer can leak a PATH override and
            // the acquired OCI default stands (#258). Previously the launcher
            // always published PATH last and shadowed this anyway.
            if key == "PATH" {
                continue;
            }
            env.push((key.clone(), value.clone()));
        }
        if let Some(path) = &sources.path {
            env.push(("PATH".to_owned(), path.clone()));
        }
        for (name, value) in sources.identity {
            env.push(((*name).to_owned(), value.clone()));
        }
        for (name, value) in sources.always {
            env.push(((*name).to_owned(), (*value).to_owned()));
        }
        for (name, value) in sources.provider {
            if !self.owns_env(name) {
                env.push(((*name).to_owned(), (*value).to_owned()));
            }
        }
        for (name, disposition) in &self.owned_env {
            if *disposition == EnvDisposition::Sentinel {
                env.push((
                    name.as_str().to_owned(),
                    credential_yaml::SENTINEL_ENV_VALUE.to_owned(),
                ));
            }
        }
        Ok(env)
    }
}

/// Phase 1: decide, before anything is created, which requested credentials
/// this launch may use and what each guest variable must end up as.
pub(crate) fn resolve_launch(
    requested: &BTreeSet<ServiceName>,
    authorization: &AuthorizationSet,
    source: &dyn CredentialSource,
    policy: MissingCredentialPolicy,
) -> Result<LaunchCredentials> {
    let mut launch = LaunchCredentials::default();
    for note in authorization.warnings() {
        launch.notes.push(note.clone());
    }
    launch.replaced = replaced_providers(requested, authorization);

    for service in requested {
        let built_in = CredentialProvider::from_config_name(service.as_str());
        match (built_in, authorization.get(service)) {
            // AC1: the authorization wins outright. The built-in's credential
            // facets are suppressed through `replaced` (see `secrets.rs`); its
            // configuration and persistence facets are untouched (AC2). There
            // is deliberately no fallback arm: an unavailable authorized value
            // does not re-enable the built-in, because that would silently
            // downgrade a shielded credential to a guest-visible placeholder.
            (_, Some(credential)) => {
                resolve_authorized(&mut launch, service, credential, source, policy)?;
            }
            (Some(_), None) => {}
            (None, None) => match policy {
                MissingCredentialPolicy::Fail => {
                    return Err(anyhow!(
                        "`{service}` is neither a built-in credential provider nor authorized in \
                         {}/{}; add an entry for it there (see USAGE.md), or remove it from the \
                         tool's `credentials` list",
                        USER_CONFIG_DIR_RELATIVE,
                        credential_yaml::CREDENTIALS_FILE_NAME
                    ));
                }
                MissingCredentialPolicy::Warn => launch.withheld.push(Withheld {
                    service: service.clone(),
                    cause: WithheldCause::NotAuthorized,
                    via_override: true,
                }),
            },
        }
    }
    Ok(launch)
}

verus! {

/// The per-name replacement decision (#162/#178), stated as bools so the proof
/// is about the decision rather than the bitset. A built-in provider's
/// credential handling is replaced for this launch iff all three hold: the
/// launch requests the name, the name is a built-in provider, and the user
/// authorized that exact name.
///
/// Stated plainly, as ADR-0018's *verified surface* does for its
/// restated-comparison rows: the exec body restates this spec, so what is proved
/// is that the decision **is** that conjunction — **not** that the facets
/// downstream of `replaced` are wired correctly. The three measurements
/// (`requested` by set iteration, `built_in` by `CredentialProvider::from_config_name`,
/// `authorized` by `AuthorizationSet::get`) are the trusted adapter
/// [`replaced_providers`].
fn provider_replaced(requested: bool, built_in: bool, authorized: bool) -> (replaced: bool)
    ensures
        replaced == (requested && built_in && authorized),
        replaced ==> requested && built_in && authorized,
        !(requested && built_in && authorized) ==> !replaced,
{
    requested && built_in && authorized
}

} // verus!

/// The built-ins a launch with these `requested` names replaces, given the
/// authorizations. Pure — it reads no source — so `doctor` can report which
/// host credential files a launch will never read without constructing a
/// keychain (#178), while `resolve_launch` remains the launch's single
/// authority for the same fact.
///
/// A replacement needs three things at once: the name is requested, it names a
/// built-in provider, and the user authorized that exact name. Any one missing
/// leaves the built-in's credential handling in place. The per-name decision is
/// the machine-checked [`provider_replaced`]; this is its trusted adapter.
pub(crate) fn replaced_providers(
    requested: &BTreeSet<ServiceName>,
    authorization: &AuthorizationSet,
) -> ProviderSet {
    let mut replaced = ProviderSet::default();
    for service in requested {
        let built_in = CredentialProvider::from_config_name(service.as_str());
        let authorized = authorization.get(service).is_some();
        // `requested` is true by construction: `service` comes from the set.
        if provider_replaced(true, built_in.is_some(), authorized)
            && let Some(provider) = built_in
        {
            replaced = replaced.union(ProviderSet::new([provider]));
        }
    }
    replaced
}

/// The YAML path: record the owned variable, prove the source is available, and
/// either publish the credential or apply the availability policy. Extracted so
/// the two `Some(credential)` match arms share exactly one copy.
fn resolve_authorized(
    launch: &mut LaunchCredentials,
    service: &ServiceName,
    credential: &credential_yaml::AuthorizedCredential,
    source: &dyn CredentialSource,
    policy: MissingCredentialPolicy,
) -> Result<()> {
    // Ownership comes from the authorization, not from resolution success: a
    // withheld credential must still suppress every other writer of its
    // variable.
    let env_name = credential.env_name().clone();
    launch
        .owned_env
        .insert(env_name.clone(), EnvDisposition::Unset);

    let resolved = source.resolve(service);
    match &resolved {
        Resolved::Value(_) => {
            // The value is dropped here. Phase 1 proves availability; it
            // does not carry the value forward.
            if credential.sentinel_env() {
                launch
                    .owned_env
                    .insert(env_name.clone(), EnvDisposition::Sentinel);
            }
            launch.ready.push(ReadyCredential {
                service: service.clone(),
                inject: credential.inject().to_vec(),
            });
        }
        Resolved::Missing | Resolved::Unavailable(_) | Resolved::SecretspecUnavailable(_) => {
            // The cause is chosen from the outcome *and* the selection: a
            // `Missing` from a SecretSpec-sourced entry is not a missing
            // keychain item, and saying so would send the user to
            // `agent-vm secret set` for a value only SecretSpec can supply.
            let cause = match (&resolved, credential.selection()) {
                (Resolved::Unavailable(failure), _) => WithheldCause::Unavailable(*failure),
                (Resolved::SecretspecUnavailable(failure), _) => {
                    WithheldCause::SecretspecUnavailable(*failure)
                }
                (_, SourceSelection::Environment) => {
                    WithheldCause::EnvironmentUnset(env_name.clone())
                }
                (_, SourceSelection::Secretspec(selection)) => {
                    WithheldCause::SecretspecMissing(selection.name().clone())
                }
                (_, SourceSelection::Keychain) => WithheldCause::Missing,
            };
            // A `required: true` value that cannot be read is the one
            // availability failure the host may override. `InvalidValue` below
            // is NOT: the bytes are present and were rejected, which is a
            // configuration error, not an unavailable source.
            //
            // `(required, policy)` is two bits, so the decision is stated once
            // and the match is exhaustive: a future policy variant that reaches
            // the `required: true` row is a compile error here rather than a
            // silently-unsatisfied pair of complements. `via_override` is true
            // only for a value the flag actually rescued — an *optional*
            // credential is withheld with or without the flag, so its warning
            // must not claim the flag did anything, and on the `fatal` row it
            // would describe a value that was never kept.
            let (fatal, via_override) = match (credential.required(), policy) {
                (true, MissingCredentialPolicy::Fail) => (true, false),
                (true, MissingCredentialPolicy::Warn) => (false, true),
                (false, _) => (false, false),
            };
            let withheld = Withheld {
                service: service.clone(),
                cause,
                via_override,
            };
            if fatal {
                return Err(anyhow!("{}", withheld.reason()));
            }
            launch.withheld.push(withheld);
        }
        Resolved::InvalidValue(rejection) => {
            match credential.selection() {
                SourceSelection::Environment => {
                    return Err(anyhow!(
                        "the host environment variable `{env_name}` selected by `{service}` cannot be used: {}. Fix or unset it on the host",
                        host_value_rule(*rejection)
                    ));
                }
                SourceSelection::Secretspec(selection) => {
                    return Err(anyhow!(
                        "the value SecretSpec resolved for `{service}` (secret `{}`) cannot be used: {}. Fix it in SecretSpec",
                        selection.name(),
                        host_value_rule(*rejection)
                    ));
                }
                // A hard error regardless of `required` and regardless of the
                // policy: the stored bytes are not a value this release will
                // inject, and treating that as merely withheld would hide a
                // real problem behind a warning.
                SourceSelection::Keychain => {
                    return Err(anyhow!(
                        "the stored value for `{service}` cannot be used: {}. Remove and \
                         re-store it with `{}`",
                        rejection.message(),
                        secret_set_command(service)
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The value-free rule that rejected a *host* value, shared by the two host
/// sources (`source: env`, `source: secretspec`).
///
/// Storage-specific advice ("it was not stored", "re-store it") is wrong for a
/// value this process just read, so only the rule itself is reused and each
/// source adds its own remedy.
fn host_value_rule(rejection: crate::secret_store::ValueRejection) -> String {
    match rejection {
        crate::secret_store::ValueRejection::Empty
        | crate::secret_store::ValueRejection::TooLong => rejection.message(),
        crate::secret_store::ValueRejection::EdgeSpace => "a leading or trailing space".to_owned(),
        crate::secret_store::ValueRejection::NonPrintable => {
            "characters that are not printable ASCII".to_owned()
        }
    }
}

/// The authorization file's name, for messages that name the location.
pub(crate) fn authorization_file_name() -> &'static str {
    credential_yaml::CREDENTIALS_FILE_NAME
}

/// `$HOME`'s authorization file, or an empty set when `$HOME` is unset (a
/// request for a YAML name then fails with the both-lookup-locations message).
pub(crate) fn load_authorizations() -> Result<AuthorizationSet> {
    match crate::config::host_home_dir() {
        Ok(Some(home)) => credential_yaml::load(&home),
        Ok(None) => Ok(AuthorizationSet::empty()),
        Err(error) => Err(anyhow!(
            "{error}; cannot locate {}/{}",
            USER_CONFIG_DIR_RELATIVE,
            credential_yaml::CREDENTIALS_FILE_NAME
        )),
    }
}

/// Test-only constructors for the resolved launch state, so a sibling unit test
/// (the proxy plan) can exercise registration without a keychain or a file.
#[cfg(test)]
impl LaunchCredentials {
    pub(crate) fn for_test(
        ready: Vec<(&str, Vec<credential_yaml::InjectionRule>)>,
        owned_env: Vec<(&str, EnvDisposition)>,
    ) -> Self {
        Self {
            ready: ready
                .into_iter()
                .map(|(service, inject)| ReadyCredential {
                    service: ServiceName::parse(service).expect("test service name"),
                    inject,
                })
                .collect(),
            withheld: Vec::new(),
            owned_env: owned_env
                .into_iter()
                .map(|(name, disposition)| {
                    (
                        GuestEnvName::parse(name).expect("test env name"),
                        disposition,
                    )
                })
                .collect(),
            notes: Vec::new(),
            replaced: ProviderSet::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use microsandbox::CredentialResolver as _;

    use super::*;
    use crate::credential_yaml::{self, AuthorizationSet};
    use crate::secret_store::{SecretValue, ValueRejection};

    /// What the scripted source should do for one service.
    #[derive(Clone)]
    enum Scripted {
        Value(String),
        Missing,
        Unavailable(KeychainFailure),
        SecretspecUnavailable(crate::credential_secretspec::SecretspecFailure),
        Invalid,
        /// A value on the first read, `Missing` afterwards: the phase-1 → phase-2
        /// transition a live SecretSpec store can have.
        ValueThenMissing(String),
        /// A value on the first read, a SecretSpec failure afterwards.
        ValueThenSecretspecUnavailable(String, crate::credential_secretspec::SecretspecFailure),
    }

    /// A plain `Send + Sync` source: a pre-seeded map behind a `Mutex`. The
    /// point of `CredentialSource` is that this never has to be the `!Sync`
    /// `FakeKeychain`.
    struct TestSource {
        scripted: Mutex<BTreeMap<String, Scripted>>,
        lookups: Mutex<Vec<String>>,
        /// Per-source read counts, for [`Scripted::ValueThenMissing`]: the
        /// phase-1 → phase-2 transition, which is a property of one launch.
        counts: Mutex<BTreeMap<String, usize>>,
    }

    impl TestSource {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                scripted: Mutex::new(BTreeMap::new()),
                lookups: Mutex::new(Vec::new()),
                counts: Mutex::new(BTreeMap::new()),
            })
        }

        fn script(self: &Arc<Self>, service: &str, outcome: Scripted) -> Arc<Self> {
            self.scripted
                .lock()
                .unwrap()
                .insert(service.to_owned(), outcome);
            Arc::clone(self)
        }

        fn lookups(&self) -> Vec<String> {
            self.lookups.lock().unwrap().clone()
        }
    }

    /// Unsized coercion at the call site; a plain `source.clone()` would stay
    /// an `Arc<TestSource>`.
    fn dyn_source(source: &Arc<TestSource>) -> Arc<dyn CredentialSource> {
        source.clone()
    }

    impl CredentialSource for TestSource {
        fn resolve(&self, service: &ServiceName) -> Resolved {
            self.lookups
                .lock()
                .unwrap()
                .push(service.as_str().to_owned());
            let seen = {
                let mut counts = self.counts.lock().unwrap();
                let count = counts.entry(service.as_str().to_owned()).or_insert(0);
                *count += 1;
                *count
            };
            match self.scripted.lock().unwrap().get(service.as_str()).cloned() {
                Some(Scripted::ValueThenSecretspecUnavailable(raw, failure)) => {
                    if seen == 1 {
                        Resolved::Value(SecretValue::parse(raw.into_bytes()).expect("acceptable"))
                    } else {
                        Resolved::SecretspecUnavailable(failure)
                    }
                }
                Some(Scripted::ValueThenMissing(raw)) => {
                    if seen == 1 {
                        Resolved::Value(SecretValue::parse(raw.into_bytes()).expect("acceptable"))
                    } else {
                        Resolved::Missing
                    }
                }
                Some(Scripted::Value(raw)) => {
                    Resolved::Value(SecretValue::parse(raw.into_bytes()).expect("acceptable"))
                }
                Some(Scripted::Unavailable(failure)) => Resolved::Unavailable(failure),
                Some(Scripted::SecretspecUnavailable(failure)) => {
                    Resolved::SecretspecUnavailable(failure)
                }
                Some(Scripted::Invalid) => Resolved::InvalidValue(ValueRejection::NonPrintable),
                Some(Scripted::Missing) | None => Resolved::Missing,
            }
        }
    }

    /// Write a `credentials.yaml` for `body` in a fresh `$HOME` and load it.
    fn authorizations(body: &str) -> (tempfile::TempDir, AuthorizationSet) {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(USER_CONFIG_DIR_RELATIVE);
        fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join(credential_yaml::CREDENTIALS_FILE_NAME);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let set = credential_yaml::load(home.path()).expect("the fixture loads");
        (home, set)
    }

    fn names(list: &[&str]) -> BTreeSet<ServiceName> {
        list.iter()
            .map(|raw| ServiceName::parse(raw).unwrap())
            .collect()
    }

    /// The full writer set a real launch contributes, so a test asserts the
    /// **final assembled environment** rather than a decision in isolation.
    fn assemble(
        launch: &LaunchCredentials,
        tool_env: &BTreeMap<String, String>,
    ) -> Vec<(String, String)> {
        launch
            .assemble_guest_env(GuestEnvSources {
                tool_env,
                path: Some("/image/bin".to_owned()),
                identity: &[
                    ("HOME", "/host/home".to_owned()),
                    ("USER", "hostuser".to_owned()),
                    ("LOGNAME", "hostuser".to_owned()),
                ],
                always: &[("IS_SANDBOX", "1"), ("LANG", "C.UTF-8")],
                provider: &[("COPILOT_GITHUB_TOKEN", "msb-copilot-placeholder-v2")],
            })
            .expect("ownership-assembled environment")
    }

    /// `(key, value)` lookups in the assembled vector, last-wins.
    fn value_of<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    fn contains_key(env: &[(String, String)], key: &str) -> bool {
        value_of(env, key).is_some()
    }

    fn one(
        body: &str,
        requested: &[&str],
        source: &dyn CredentialSource,
    ) -> Result<LaunchCredentials> {
        one_with_policy(body, requested, source, MissingCredentialPolicy::Fail)
    }

    /// [`one`] with an explicit availability policy. The default keeps the
    /// ~20 existing call sites at `Fail` untouched (#162); the availability
    /// matrix is the only caller that needs `Warn`.
    fn one_with_policy(
        body: &str,
        requested: &[&str],
        source: &dyn CredentialSource,
        policy: MissingCredentialPolicy,
    ) -> Result<LaunchCredentials> {
        let (home, set) = authorizations(body);
        let result = resolve_launch(&names(requested), &set, source, policy);
        drop(home);
        result
    }

    const ALPHA: &str = "\
credentials:
  - service: alpha
    apiKey:
      name: ALPHA_KEY
      sentinelEnv: true
      inject:
        - domain: api.alpha.example
          scheme: bearer
";

    const BETA_REQUIRED: &str = "\
credentials:
  - service: beta
    required: true
    apiKey:
      name: BETA_KEY
      inject:
        - domain: api.beta.example
          header: x-beta
          format: \"%s\"
";

    #[test]
    fn required_credential_fails_before_build() {
        let source = TestSource::new();
        let error = one(BETA_REQUIRED, &["beta"], &*source).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("beta"), "{text}");
        assert!(text.contains("agent-vm secret set beta"), "{text}");
        assert!(text.contains("no value is stored"), "{text}");
    }

    #[test]
    fn a_busy_inventory_lock_names_the_lock_in_the_launch_message() {
        let source = TestSource::new().script(
            "beta",
            Scripted::Unavailable(KeychainFailure::InventoryBusy),
        );
        let error = one(BETA_REQUIRED, &["beta"], &*source).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("could not be read for `beta`"), "{text}");
        assert!(text.contains("secret inventory lock"), "{text}");
        let optional = TestSource::new().script(
            "alpha",
            Scripted::Unavailable(KeychainFailure::InventoryBusy),
        );
        let launch = one(ALPHA, &["alpha"], &*optional).unwrap();
        let notice = launch.withheld()[0].notice();
        assert!(notice.contains("secret inventory lock"), "{notice}");
        assert!(notice.contains("continuing without it"), "{notice}");
        let launch = one_with_policy(
            BETA_REQUIRED,
            &["beta"],
            &*source,
            MissingCredentialPolicy::Warn,
        )
        .unwrap();
        assert!(launch.ready().is_empty());
        assert_eq!(launch.withheld().len(), 1);
        let notice = launch.withheld()[0].notice();
        assert!(notice.contains("secret inventory lock"), "{notice}");
        assert!(notice.contains("--allow-missing-credentials"), "{notice}");
    }

    #[test]
    fn optional_credential_warns_and_withholds() {
        let source = TestSource::new().script("alpha", Scripted::Missing);
        let launch = one(ALPHA, &["alpha"], &*source).expect("optional is not fatal");
        assert!(launch.ready().is_empty());
        assert_eq!(launch.withheld().len(), 1);
        assert!(
            launch.withheld()[0]
                .reason()
                .contains("agent-vm secret set alpha"),
            "{}",
            launch.withheld()[0].reason()
        );
        // The name is still *owned*: a withheld credential must suppress every
        // other writer of its variable.
        let owned: Vec<&str> = launch
            .owned_env()
            .keys()
            .map(|name| name.as_str())
            .collect();
        assert_eq!(owned, vec!["ALPHA_KEY"]);
        assert_eq!(
            launch.owned_env().values().next(),
            Some(&EnvDisposition::Unset)
        );
    }

    #[test]
    fn invalid_stored_value_is_a_hard_error_even_when_optional() {
        let source = TestSource::new().script("alpha", Scripted::Invalid);
        let error = one(ALPHA, &["alpha"], &*source).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("cannot be used"), "{text}");
        assert!(text.contains("alpha"), "{text}");
    }

    #[test]
    fn unrequested_same_named_definition_does_not_disturb_a_launch() {
        // The file authorizes BOTH the YAML-only `alpha` and a same-named
        // `anthropic`; this launch requests only `alpha`, so the same-named
        // definition is inert. #162 makes an authorization *requested* by name
        // precedence-setting; an authorization nobody requests still changes
        // nothing (CONTEXT.md → "Authorized credential").
        let anthropic = "  - service: anthropic\n    apiKey:\n      name: ANTHROPIC_API_KEY\n      inject:\n        - domain: api.anthropic.example\n          header: x-api-key\n          format: \"%s\"\n";
        let body = format!(
            "credentials:\n{anthropic}{}",
            ALPHA.strip_prefix("credentials:\n").unwrap()
        );
        let source = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
        let launch = one(&body, &["alpha"], &*source).expect("unrequested is inert");
        assert_eq!(launch.ready().len(), 1);
        assert_eq!(launch.replaced(), ProviderSet::default());
        assert_eq!(source.lookups(), vec!["alpha"]);
    }

    #[test]
    fn requested_name_with_no_authorization_names_both_lookup_locations() {
        let source = TestSource::new();
        let error = one(ALPHA, &["gamma"], &*source).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("gamma"), "{text}");
        assert!(text.contains("built-in credential provider"), "{text}");
        assert!(text.contains("credentials.yaml"), "{text}");
    }

    // -- #162: the availability matrix, driven by `MissingCredentialPolicy` --

    /// A same-named authorization for the built-in `anthropic` provider.
    const ANTHROPIC_AUTHORIZED: &str = "\
credentials:
  - service: anthropic
    apiKey:
      name: ANTHROPIC_API_KEY
      sentinelEnv: true
      inject: [{domain: api.anthropic.example, header: x-api-key, format: \"%s\"}]
";

    #[test]
    fn a_same_named_authorization_wins_and_records_the_replacement() {
        let source = TestSource::new().script("anthropic", Scripted::Value("sk-REAL".into()));
        let launch = one(ANTHROPIC_AUTHORIZED, &["anthropic"], &*source).unwrap();
        assert_eq!(launch.ready().len(), 1);
        assert_eq!(launch.ready()[0].service().as_str(), "anthropic");
        assert_eq!(
            launch.replaced(),
            ProviderSet::new([CredentialProvider::Anthropic])
        );
        // One read, no double-resolve: the YAML path was taken exactly once.
        assert_eq!(source.lookups(), vec!["anthropic"]);
    }

    #[test]
    fn a_built_in_without_an_authorization_is_not_replaced() {
        let source = TestSource::new();
        let launch = one(ALPHA, &["anthropic"], &*source).unwrap();
        assert!(launch.ready().is_empty());
        assert_eq!(launch.replaced(), ProviderSet::default());
        assert!(source.lookups().is_empty());
    }

    /// The pure predicate `doctor` reads (#178) is the same fact `resolve_launch`
    /// records for a launch, over every combination of requested and authorized.
    /// A drift here would make `doctor` annotate a host file a launch does read.
    #[test]
    fn replaced_providers_and_the_launch_agree_with_an_independent_oracle() {
        let (_home, set) = authorizations(ANTHROPIC_AUTHORIZED);
        // `(requested, expected)`, the expected set written from the rule
        // "requested ∩ built-in ∩ authorized" rather than from the
        // implementation, so a shared bug in `replaced_providers` cannot make
        // both sides agree.
        let cases: &[(&[&str], &[CredentialProvider])] = &[
            (&["anthropic"], &[CredentialProvider::Anthropic]),
            (&["anthropic", "openai"], &[CredentialProvider::Anthropic]),
            (&["openai"], &[]),
            (&["alpha"], &[]),
            (&["copilot", "opencode-static"], &[]),
        ];
        for (requested, expected) in cases {
            let requested = names(requested);
            let expected = ProviderSet::new(expected.iter().copied());
            assert_eq!(
                replaced_providers(&requested, &set),
                expected,
                "predicate for {requested:?}"
            );
            let source = TestSource::new().script("anthropic", Scripted::Value("sk-x".into()));
            let launch = resolve_launch(&requested, &set, &*source, MissingCredentialPolicy::Warn)
                .expect("warn never bails");
            assert_eq!(launch.replaced(), expected, "launch for {requested:?}");
        }
    }

    #[test]
    fn an_unavailable_replacement_does_not_fall_back_to_the_built_in() {
        // The authorization is set *before* resolution is attempted, so an
        // unavailable value still records the replacement. Falling back would
        // silently downgrade a shielded credential to the built-in's
        // guest-visible placeholder.
        let source = TestSource::new(); // Missing
        let launch = one(ANTHROPIC_AUTHORIZED, &["anthropic"], &*source).unwrap();
        assert!(launch.ready().is_empty());
        assert_eq!(
            launch.replaced(),
            ProviderSet::new([CredentialProvider::Anthropic])
        );
        assert_eq!(launch.withheld().len(), 1);
    }

    #[test]
    fn a_required_replacement_fails_the_launch_by_default() {
        let body = ANTHROPIC_AUTHORIZED.replace("    apiKey:", "    required: true\n    apiKey:");
        let source = TestSource::new(); // Missing
        let error = one(&body, &["anthropic"], &*source).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("anthropic"), "{text}");
        assert!(text.contains("agent-vm secret set anthropic"), "{text}");
    }

    #[test]
    fn a_required_replacement_is_skipped_under_the_override() {
        let body = ANTHROPIC_AUTHORIZED.replace("    apiKey:", "    required: true\n    apiKey:");
        let source = TestSource::new(); // Missing
        let launch = one_with_policy(
            &body,
            &["anthropic"],
            &*source,
            MissingCredentialPolicy::Warn,
        )
        .expect("the override keeps the launch alive");
        assert_eq!(launch.withheld().len(), 1);
        let notice = launch.withheld()[0].notice();
        assert!(notice.contains("--allow-missing-credentials"), "{notice}");
        assert!(notice.contains("agent-vm secret set anthropic"), "{notice}");
    }

    #[test]
    fn an_optional_withheld_credential_does_not_claim_the_override() {
        // `alpha` is optional, so it is withheld with or without the flag. Its
        // warning must not claim the flag rescued it (D9).
        let source = TestSource::new(); // Missing
        let launch =
            one_with_policy(ALPHA, &["alpha"], &*source, MissingCredentialPolicy::Warn).unwrap();
        assert_eq!(launch.withheld().len(), 1);
        let notice = launch.withheld()[0].notice();
        assert!(notice.ends_with("; continuing without it"), "{notice}");
        assert!(!notice.contains("--allow-missing-credentials"), "{notice}");
    }

    #[test]
    fn an_unauthorized_name_is_skipped_under_the_override() {
        let source = TestSource::new();
        let launch =
            one_with_policy(ALPHA, &["gamma"], &*source, MissingCredentialPolicy::Warn).unwrap();
        assert!(launch.ready().is_empty());
        assert!(launch.owned_env().is_empty());
        assert_eq!(launch.withheld().len(), 1);
        let notice = launch.withheld()[0].notice();
        assert!(notice.contains("gamma"), "{notice}");
        assert!(
            notice.contains("neither a built-in credential provider"),
            "{notice}"
        );
        assert!(notice.contains("--allow-missing-credentials"), "{notice}");
    }

    #[test]
    fn an_invalid_stored_value_is_a_hard_error_under_the_override() {
        // Present-but-invalid is a configuration error, not an unavailable
        // source, so the flag cannot swallow it (D5).
        let source = TestSource::new().script("alpha", Scripted::Invalid);
        let error = one_with_policy(ALPHA, &["alpha"], &*source, MissingCredentialPolicy::Warn)
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("cannot be used"), "{text}");
    }

    #[test]
    fn a_withheld_replacement_still_owns_its_guest_variable() {
        // Ownership comes from the authorization, not resolution success: a
        // `sentinelEnv: true` name that could not be read stays *owned* with
        // `Unset` (never `Sentinel`, which would claim a value is proxied).
        let source = TestSource::new(); // Missing
        let launch = one_with_policy(
            ANTHROPIC_AUTHORIZED,
            &["anthropic"],
            &*source,
            MissingCredentialPolicy::Warn,
        )
        .unwrap();
        assert_eq!(
            launch
                .owned_env()
                .get(&GuestEnvName::parse("ANTHROPIC_API_KEY").unwrap()),
            Some(&EnvDisposition::Unset)
        );
    }

    #[test]
    fn ready_credential_carries_rules_and_a_sentinel_disposition() {
        let source = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
        let launch = one(ALPHA, &["alpha"], &*source).unwrap();
        assert_eq!(launch.ready().len(), 1);
        assert_eq!(launch.ready()[0].service().as_str(), "alpha");
        assert_eq!(launch.ready()[0].inject()[0].host(), "api.alpha.example");
        assert_eq!(
            launch
                .owned_env()
                .get(&GuestEnvName::parse("ALPHA_KEY").unwrap()),
            Some(&EnvDisposition::Sentinel)
        );
    }

    #[test]
    fn resolver_refuses_a_reference_outside_the_allowed_set() {
        let source = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
        let launch = one(ALPHA, &["alpha"], &*source).unwrap();
        let resolver = launch.resolver(dyn_source(&source));
        // Inside the set: the value comes back, and the folded spelling of the
        // reference selects the same credential (names are case-folded).
        assert_eq!(&*resolver.resolve("alpha").unwrap(), "sk-REAL");
        assert_eq!(&*resolver.resolve("ALPHA").unwrap(), "sk-REAL");
        // Outside it: refused, and the reference is not echoed into the error.
        for reference in ["beta", "not a name", ""] {
            let error = resolver
                .resolve(reference)
                .expect_err("an unauthorized reference is refused");
            assert_eq!(error, microsandbox::CredentialResolveError::NotAuthorized);
            let rendered = format!("{error:?} {error}");
            assert!(
                reference.is_empty() || !rendered.contains(reference),
                "{rendered}"
            );
        }
        // The refused references were never looked up and never reached the
        // source: `allowed` is the authority, not the store.
        // One lookup for phase 1, one per successful phase-2 resolve.
        assert_eq!(source.lookups(), vec!["alpha", "alpha", "alpha"]);
    }

    #[test]
    fn resolver_maps_keychain_outcomes_to_closed_error_kinds() {
        let source = TestSource::new()
            .script("alpha", Scripted::Value("sk-REAL".into()))
            .script("beta", Scripted::Missing)
            .script(
                "gamma",
                Scripted::Unavailable(KeychainFailure::AccessDenied),
            )
            .script("delta", Scripted::Invalid);
        let body = "\
credentials:
  - service: alpha
    apiKey:
      name: ALPHA_KEY
      inject: [{domain: a.example, header: x-a, format: \"%s\"}]
  - service: beta
    apiKey:
      name: BETA_KEY
      inject: [{domain: b.example, header: x-b, format: \"%s\"}]
  - service: gamma
    apiKey:
      name: GAMMA_KEY
      inject: [{domain: c.example, header: x-c, format: \"%s\"}]
  - service: delta
    apiKey:
      name: DELTA_KEY
      inject: [{domain: d.example, header: x-d, format: \"%s\"}]
";
        // gamma is scripted `Unavailable`, so phase 1 withholds it (optional)
        // and it never becomes ready; delta is Invalid, which phase 1 refuses.
        let (home, set) = authorizations(body);
        let error = resolve_launch(
            &names(&["delta"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("cannot be used"));
        let launch = resolve_launch(
            &names(&["alpha", "beta", "gamma"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .expect("all optional");
        let resolver = launch.resolver(dyn_source(&source));
        assert_eq!(
            resolver.resolve("alpha").map(|v| v.to_string()),
            Ok("sk-REAL".to_owned())
        );
        // beta was withheld, so it is not in `allowed` at all.
        assert_eq!(
            resolver.resolve("beta").unwrap_err(),
            microsandbox::CredentialResolveError::NotAuthorized
        );
        assert_eq!(
            resolver.resolve("gamma").unwrap_err(),
            microsandbox::CredentialResolveError::NotAuthorized
        );
        // Rendered failures carry no service name and no keychain text.
        let rendered = format!(
            "{:?} {}",
            resolver.resolve("beta").unwrap_err(),
            resolver.resolve("gamma").unwrap_err()
        );
        assert!(
            !rendered.contains("beta") && !rendered.contains("gamma"),
            "{rendered}"
        );
        assert!(!rendered.contains("keychain"), "{rendered}");
        drop(home);

        // A ready service whose store is missing maps to NotFound; a ready
        // service whose store is unavailable maps to Failed.
        for failure in [
            KeychainFailure::AccessDenied,
            KeychainFailure::InventoryBusy,
        ] {
            let source = TestSource::new()
                .script("alpha", Scripted::Missing)
                .script("beta", Scripted::Unavailable(failure));
            // Phase 1 refuses Missing/Unavailable for required, so build the
            // resolver through the type's own constructor instead.
            let resolver = LaunchCredentialResolver {
                source: dyn_source(&source),
                allowed: names(&["alpha", "beta"]),
            };
            assert_eq!(
                resolver.resolve("alpha").unwrap_err(),
                microsandbox::CredentialResolveError::NotFound
            );
            assert_eq!(
                resolver.resolve("beta").unwrap_err(),
                microsandbox::CredentialResolveError::Failed
            );
        }
    }

    /// Build the *actual* durable network config a launch would register, from
    /// resolved credentials, through the path `run::launch` uses
    /// (`apply_to_network`).
    fn durable_config(
        launch: &LaunchCredentials,
        state_dir: &std::path::Path,
    ) -> microsandbox_network::config::NetworkConfig {
        let creds = crate::secrets::CredsState::default();
        let plan = crate::credential_injection::Plan::new(
            PathBuf::from("/agent-vm"),
            crate::credential_injection::Inputs {
                creds: &creds,
                state_dir,
                allowed_repos: &[],
                provisioned: crate::credential_provider::ProviderSet::default(),
                launch,
            },
        )
        .expect("a proxy plan");
        plan.apply_to_network(microsandbox_network::builder::NetworkBuilder::new())
            .expect("a valid base network")
            .build()
            .expect("a durable network config")
    }

    /// The Decision-2 application-level guarantee, proved by seeding a canary
    /// through the in-process source and rendering the **actual** durable
    /// config the launch builds - not by asserting that a constant is absent
    /// from a plan that never carried a value (agent-vm #161 review, M4).
    #[test]
    fn durable_config_carries_the_reference_and_never_a_value() {
        let canary = "sk-CANARY-7a1b2c3d4e5f60718293a4b5c6d7e8f9";
        let source = TestSource::new().script("alpha", Scripted::Value(canary.into()));
        let (home, set) = authorizations(ALPHA);
        let state = tempfile::tempdir().unwrap();
        let launch = resolve_launch(
            &names(&["alpha"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .unwrap();
        // Prove the canary is live: the phase-2 resolver hands it over, so if
        // the durable config carried a value it would be this one.
        let resolver = launch.resolver(dyn_source(&source));
        assert_eq!(&*resolver.resolve("alpha").unwrap(), canary);
        let config = durable_config(&launch, state.path());
        let rendered = serde_json::to_string(&config).unwrap();
        // The reference is present; the value is nowhere in the durable shape
        // or its Debug.
        assert!(rendered.contains("alpha"), "{rendered}");
        assert_eq!(config.secrets.header_credentials.len(), 1);
        assert_eq!(config.secrets.header_credentials[0].reference, "alpha");
        assert!(
            !rendered.contains(canary),
            "the value reached the durable config: {rendered}"
        );
        assert!(!format!("{config:?}").contains(canary));
        drop(home);
    }

    #[test]
    fn a_full_resolve_writes_no_file_and_leaks_no_value() {
        let canary = "sk-CANARY-4f7a1b2c3d4e5f60718293a4b5c6d7e8";
        let source = TestSource::new().script("alpha", Scripted::Value(canary.into()));
        let (home, set) = authorizations(ALPHA);
        let state = tempfile::tempdir().unwrap();
        let before_home = directory_contents(home.path());
        let before_state = directory_contents(state.path());
        let launch = resolve_launch(
            &names(&["alpha"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .unwrap();
        let resolver = launch.resolver(dyn_source(&source));
        let value = resolver.resolve("alpha").unwrap();
        assert_eq!(&*value, canary);
        // Build the durable config too: it is the other artifact a launch would
        // produce, and it must not carry the value either.
        let _config = durable_config(&launch, state.path());
        // Contents, not paths and lengths: a same-length overwrite must fail.
        for (root, before) in [(home.path(), before_home), (state.path(), before_state)] {
            let after = directory_contents(root);
            assert_eq!(
                before,
                after,
                "resolution created or changed a file under {}",
                root.display()
            );
            for (path, bytes) in after {
                assert!(
                    !bytes.windows(canary.len()).any(|w| w == canary.as_bytes()),
                    "the value was written to {}",
                    path.display()
                );
            }
        }
        // Nothing in the launch state renders the value.
        let rendered = format!(
            "{:?}\n{:?}\n{}",
            launch,
            launch.ready(),
            launch.notes().join("\n")
        );
        assert!(!rendered.contains(canary), "the value leaked: {rendered}");
        drop(value);
        drop(home);
    }

    /// Every regular file under `root` with its **contents**, recursively. A
    /// read error is a test failure (`.unwrap()`), not a silent skip: a file
    /// that cannot be read is itself a resolution side effect worth catching.
    fn directory_contents(root: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(dir: &std::path::Path, into: &mut Vec<(PathBuf, Vec<u8>)>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let meta = entry.metadata().unwrap();
                if meta.is_dir() {
                    walk(&path, into);
                } else {
                    let bytes = fs::read(&path).unwrap();
                    into.push((path, bytes));
                }
            }
        }
        let mut found = Vec::new();
        walk(root, &mut found);
        found.sort();
        found
    }

    #[test]
    fn sentinel_env_true_puts_only_the_non_secret_sentinel_in_the_owned_variable() {
        // AC2: `sentinelEnv: true` publishes the sentinel and *only* it, last of
        // every writer. Injection is independent (covered in
        // `credential_injection`).
        let source = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
        let launch = one(ALPHA, &["alpha"], &*source).unwrap();
        let env = assemble(&launch, &BTreeMap::new());
        assert_eq!(value_of(&env, "ALPHA_KEY"), Some("proxy-managed"));
        // The sentinel is the final writer, so nothing can displace it, and no
        // host or provider value for the owned name is present at all.
        assert_eq!(env.iter().filter(|(k, _)| k == "ALPHA_KEY").count(), 1);
        assert!(!format!("{env:?}").contains("sk-REAL"));
    }

    #[test]
    fn sentinel_env_defaults_to_false_and_leaves_the_name_unset() {
        // AC2: absent `sentinelEnv`/`proxyManaged` means the guest variable is
        // left unset, so no sentinel is published for it and every other writer
        // of the name is suppressed.
        let body = "\
credentials:
  - service: alpha
    apiKey:
      name: OPENAI_API_KEY
      inject: [{domain: a.example, header: x-a, format: \"%s\"}]
";
        let source = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
        let launch = one(body, &["alpha"], &*source).unwrap();
        assert_eq!(
            launch
                .owned_env()
                .get(&GuestEnvName::parse("OPENAI_API_KEY").unwrap()),
            Some(&EnvDisposition::Unset)
        );
        let env = assemble(&launch, &BTreeMap::new());
        // No sentinel is
        // published - the name is genuinely unset. The launcher's other writers
        // are untouched.
        assert!(!contains_key(&env, "OPENAI_API_KEY"));
        assert_eq!(value_of(&env, "PATH"), Some("/image/bin"));
        assert_eq!(value_of(&env, "IS_SANDBOX"), Some("1"));
        assert_eq!(
            value_of(&env, "COPILOT_GITHUB_TOKEN"),
            Some("msb-copilot-placeholder-v2")
        );
    }

    #[test]
    fn proxy_managed_is_accepted_as_the_sentinel_alias_ac2() {
        // AC2/AC3: Docker's `proxyManaged` alias reaches the same decision.
        // (The load-time conflict/alias rules are pinned in
        // `credential_yaml::tests::rejects_conflicting_sentinel_env_and_proxy_managed`.)
        let body = "\
credentials:
  - service: alpha
    apiKey:
      name: ALPHA_KEY
      proxyManaged: true
      inject: [{domain: a.example, header: x-a, format: \"%s\"}]
";
        let source = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
        let launch = one(body, &["alpha"], &*source).unwrap();
        let env = assemble(&launch, &BTreeMap::new());
        assert_eq!(value_of(&env, "ALPHA_KEY"), Some("proxy-managed"));
    }

    #[test]
    fn a_tool_declared_env_colliding_with_an_owned_name_is_refused() {
        let source = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
        let launch = one(ALPHA, &["alpha"], &*source).unwrap();
        let tool_env: BTreeMap<String, String> =
            [("ALPHA_KEY".to_owned(), "tool-value".to_owned())].into();
        let error = launch
            .assemble_guest_env(GuestEnvSources {
                tool_env: &tool_env,
                path: None,
                identity: &[],
                always: &[],
                provider: &[],
            })
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("ALPHA_KEY"), "{text}");
        assert!(text.contains("credentials.yaml"), "{text}");
    }

    /// A `None` path means the OCI default supplies `PATH`: neither the
    /// launcher nor a tool-declared `env` may emit one. A `Some` path is the
    /// only writer, and it wins over a tool-declared `PATH` (the pre-#258
    /// precedence, now by omission rather than by last-wins).
    #[test]
    fn path_is_written_only_by_a_some_source() {
        let source = TestSource::new();
        let launch = one(ALPHA, &["alpha"], &*source).unwrap();
        let tool_env: BTreeMap<String, String> =
            [("PATH".to_owned(), "/tool/bin".to_owned())].into();

        let none = launch
            .assemble_guest_env(GuestEnvSources {
                tool_env: &tool_env,
                path: None,
                identity: &[],
                always: &[],
                provider: &[],
            })
            .unwrap();
        assert!(
            !contains_key(&none, "PATH"),
            "path=None must let the acquired OCI PATH stand; got {none:?}"
        );

        let some = launch
            .assemble_guest_env(GuestEnvSources {
                tool_env: &tool_env,
                path: Some("/image/bin".to_owned()),
                identity: &[],
                always: &[],
                provider: &[],
            })
            .unwrap();
        assert_eq!(value_of(&some, "PATH"), Some("/image/bin"));
    }

    #[test]
    fn a_withheld_optional_credential_leaves_its_variable_unset() {
        // Ownership survives withholding: an unavailable value cannot enable
        // another guest-env writer for the authorization's name (AC2).
        let body = "\
credentials:
  - service: alpha
    apiKey:
      name: OPENAI_API_KEY
      inject: [{domain: a.example, header: x-a, format: \"%s\"}]
";
        let source = TestSource::new(); // Missing
        let launch = one(body, &["alpha"], &*source).unwrap();
        assert!(launch.ready().is_empty());
        let env = assemble(&launch, &BTreeMap::new());
        assert!(!contains_key(&env, "OPENAI_API_KEY"));
    }

    /// The full AC2 matrix against **every** environment writer, ready and
    /// withheld, sentinel true and false, root and non-root. This is the test
    /// that would fail if any writer stopped consulting ownership.
    #[test]
    fn the_final_guest_environment_honours_ownership_for_every_writer() {
        let root_and_nonroot = |identity: bool| -> Vec<(&'static str, String)> {
            if identity {
                vec![
                    ("HOME", "/host/home".to_owned()),
                    ("USER", "hostuser".to_owned()),
                    ("LOGNAME", "hostuser".to_owned()),
                ]
            } else {
                Vec::new()
            }
        };
        // `OPENAI_API_KEY` is owned; `unused` names a provider variable.
        for (sentinel, owned_value) in [("true", Some("proxy-managed")), ("false", None)] {
            for identity in [false, true] {
                let body = format!(
                    "credentials:\n  - service: alpha\n    apiKey:\n      name: OPENAI_API_KEY\n      sentinelEnv: {sentinel}\n      inject: [{{domain: a.example, header: x-a, format: \"%s\"}}]\n"
                );
                // Ready ...
                let ready = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
                let launch = one(&body, &["alpha"], &*ready).unwrap();
                let env = launch
                    .assemble_guest_env(GuestEnvSources {
                        tool_env: &BTreeMap::new(),
                        path: Some("/image/bin".to_owned()),
                        identity: &root_and_nonroot(identity),
                        always: &[("IS_SANDBOX", "1"), ("LANG", "C.UTF-8")],
                        provider: &[("COPILOT_GITHUB_TOKEN", "msb-copilot")],
                    })
                    .unwrap();
                assert_eq!(
                    value_of(&env, "OPENAI_API_KEY"),
                    owned_value,
                    "{body} identity={identity}"
                );
                assert!(!format!("{env:?}").contains("host-openai"));
                // ... and withheld.
                let withheld = TestSource::new(); // Missing
                let launch = one(&body, &["alpha"], &*withheld).unwrap();
                assert!(launch.ready().is_empty());
                let env = launch
                    .assemble_guest_env(GuestEnvSources {
                        tool_env: &BTreeMap::new(),
                        path: Some("/image/bin".to_owned()),
                        identity: &root_and_nonroot(identity),
                        always: &[("IS_SANDBOX", "1"), ("LANG", "C.UTF-8")],
                        provider: &[("COPILOT_GITHUB_TOKEN", "msb-copilot")],
                    })
                    .unwrap();
                assert!(
                    !contains_key(&env, "OPENAI_API_KEY"),
                    "{body} identity={identity}"
                );
            }
        }
    }

    #[test]
    fn an_owned_provider_variable_is_suppressed() {
        // The provider-forwarded names are a second writer that must consult
        // ownership.
        let body = "\
credentials:
  - service: alpha
    apiKey:
      name: COPILOT_GITHUB_TOKEN
      inject: [{domain: a.example, header: x-a, format: \"%s\"}]
";
        let source = TestSource::new(); // Missing -> withheld, still owned
        let launch = one(body, &["alpha"], &*source).unwrap();
        let env = assemble(&launch, &BTreeMap::new());
        assert!(!contains_key(&env, "COPILOT_GITHUB_TOKEN"));
    }

    #[test]
    fn launcher_owned_names_cannot_be_owned_by_a_credential() {
        // AC2 fail-closed: names agent-vm itself must publish are refused at
        // load time, because "leave unset" cannot be honored for them.
        use std::os::unix::fs::PermissionsExt as _;
        for name in [
            "IS_SANDBOX",
            "LANG",
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "MSB_HOME",
        ] {
            let body = format!(
                "credentials:\n  - service: alpha\n    apiKey:\n      name: {name}\n      inject: [{{domain: a.example, header: x-a, format: \"%s\"}}]\n"
            );
            let home = tempfile::tempdir().unwrap();
            let dir = home.path().join(USER_CONFIG_DIR_RELATIVE);
            fs::create_dir_all(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let path = dir.join(credential_yaml::CREDENTIALS_FILE_NAME);
            fs::write(&path, &body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let error = credential_yaml::load(home.path()).unwrap_err();
            assert!(
                format!("{error:#}").contains("apiKey.name"),
                "{name}: {error:#}"
            );
        }
    }

    #[test]
    fn sentinel_env_false_colliding_with_an_image_env_is_caught_even_when_withheld() {
        // A `sentinelEnv: false` name must end up unset, but the SDK builder
        // cannot remove an image `ENV`. The collision must be caught from the
        // authorization even when the credential was withheld (no `ready`
        // entry), because the ownership rule does not depend on resolution.
        let body = "\
credentials:
  - service: alpha
    apiKey:
      name: IMAGE_OWNED
      inject: [{domain: a.example, header: x-a, format: \"%s\"}]
";
        let image_env: BTreeSet<String> =
            ["IMAGE_OWNED=1".to_owned(), "PATH=/bin".to_owned()].into();
        let owned = GuestEnvName::parse("IMAGE_OWNED").unwrap();

        // Both availability policies: an image-env collision is a security
        // boundary, so `--allow-missing-credentials` must not move it.
        for policy in [MissingCredentialPolicy::Fail, MissingCredentialPolicy::Warn] {
            let ready = TestSource::new().script("alpha", Scripted::Value("sk-REAL".into()));
            let launch = one_with_policy(body, &["alpha"], &*ready, policy).unwrap();
            assert_eq!(
                launch.unset_names_in_image_env(&image_env),
                vec![owned.clone()],
                "policy={policy:?}"
            );

            let withheld = TestSource::new(); // Missing
            let launch = one_with_policy(body, &["alpha"], &*withheld, policy).unwrap();
            assert!(launch.ready().is_empty());
            assert_eq!(
                launch.unset_names_in_image_env(&image_env),
                vec![owned.clone()],
                "policy={policy:?}"
            );

            // A *sentinel* credential is not a collision: the sentinel is
            // published last and overrides the image value.
            let sentinel_body =
                body.replace("      inject:", "      sentinelEnv: true\n      inject:");
            let launch = one_with_policy(&sentinel_body, &["alpha"], &*ready, policy).unwrap();
            assert!(
                launch.unset_names_in_image_env(&image_env).is_empty(),
                "policy={policy:?}"
            );
        }
    }

    #[test]
    fn parallel_launches_do_not_share_credential_state() {
        // Two launches, two services, different values: each resolver's
        // `allowed` set is its own, and neither sees the other's service.
        let source = TestSource::new()
            .script("alpha", Scripted::Value("first".into()))
            .script("beta", Scripted::Value("second".into()));
        let body = "\
credentials:
  - service: alpha
    apiKey:
      name: ALPHA_KEY
      inject: [{domain: a.example, header: x-a, format: \"%s\"}]
  - service: beta
    apiKey:
      name: BETA_KEY
      inject: [{domain: b.example, header: x-b, format: \"%s\"}]
";
        let (home, set) = authorizations(body);
        let first = resolve_launch(
            &names(&["alpha"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .unwrap();
        let second = resolve_launch(
            &names(&["beta"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .unwrap();
        let first = first.resolver(source.clone());
        let second = second.resolver(source.clone());
        assert_eq!(&*first.resolve("alpha").unwrap(), "first");
        assert_eq!(
            first.resolve("beta").unwrap_err(),
            microsandbox::CredentialResolveError::NotAuthorized
        );
        assert_eq!(&*second.resolve("beta").unwrap(), "second");
        assert_eq!(
            second.resolve("alpha").unwrap_err(),
            microsandbox::CredentialResolveError::NotAuthorized
        );
        drop(home);
    }
    /// A `source: secretspec` entry whose table is valid; the executable is an
    /// absent path so a real read fails fast and for a named reason.
    fn secretspec_authorizations(required: bool) -> (tempfile::TempDir, AuthorizationSet) {
        authorizations(&format!(
            "credentials:\n  - service: alpha\n    source: secretspec\n    required: {required}\n    \
             apiKey:\n      name: ALPHA_KEY\n      sentinelEnv: true\n      inject: [{{domain: \
             api.alpha.example, scheme: bearer}}]\n    secretspec:\n      executable: \
             /nonexistent/secretspec\n      manifest: /tmp/secretspec.toml\n      profile: default\n"
        ))
    }

    /// A source that answers for exactly the SecretSpec-sourced services, so the
    /// resolver's message families can be exercised without a child.
    fn secretspec_source(outcome: Scripted) -> Arc<TestSource> {
        TestSource::new().script("alpha", outcome)
    }

    /// R2: a missing SecretSpec value names the secret and the SecretSpec remedy,
    /// and never suggests the keychain (`agent-vm secret set`).
    #[test]
    fn a_missing_secretspec_value_names_the_secret_and_not_the_keychain() {
        let (_home, set) = secretspec_authorizations(false);
        let source = TestSource::new();
        let launch = resolve_launch(
            &names(&["alpha"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .expect("optional");
        let notice = launch.withheld()[0].notice();
        assert!(
            notice.contains("SecretSpec has no value for `ALPHA_KEY`"),
            "{notice}"
        );
        assert!(notice.contains("not declared in the manifest"), "{notice}");
        assert!(notice.contains("outside the session scope"), "{notice}");
        assert!(!notice.contains("agent-vm secret set"), "{notice}");
        assert!(!notice.contains("keychain"), "{notice}");
    }

    /// R3: the availability matrix is the keychain's, unchanged, for a SecretSpec
    /// failure too.
    #[test]
    fn secretspec_unavailability_follows_the_availability_matrix() {
        use crate::credential_secretspec::SecretspecFailure as F;
        for (required, policy) in [
            (true, MissingCredentialPolicy::Fail),
            (true, MissingCredentialPolicy::Warn),
            (false, MissingCredentialPolicy::Fail),
            (false, MissingCredentialPolicy::Warn),
        ] {
            let (_home, set) = secretspec_authorizations(required);
            let source = secretspec_source(Scripted::SecretspecUnavailable(F::ProviderFailed));
            let result = resolve_launch(&names(&["alpha"]), &set, &*source, policy);
            let rendered = match result {
                Err(error) => error.to_string(),
                Ok(launch) => {
                    assert!(launch.ready().is_empty());
                    launch.withheld()[0].notice()
                }
            };
            assert!(
                rendered.contains("SecretSpec could not resolve `alpha`"),
                "{rendered}"
            );
            assert!(rendered.contains("`source: secretspec`"), "{rendered}");
            let fatal = required && policy == MissingCredentialPolicy::Fail;
            let rescued = required && policy == MissingCredentialPolicy::Warn;
            assert_eq!(
                rendered.contains("continuing without it"),
                !fatal,
                "{rendered}"
            );
            assert_eq!(
                rendered.contains("because --allow-missing-credentials was passed"),
                rescued,
                "{rendered}"
            );
        }
    }

    /// R4: a rejected SecretSpec value is a hard error under both policies and
    /// both `required` values — the bytes are present and unusable, which is a
    /// configuration error, not an unavailable source.
    #[test]
    fn an_invalid_secretspec_value_is_a_hard_error_under_both_policies() {
        for required in [false, true] {
            for policy in [MissingCredentialPolicy::Fail, MissingCredentialPolicy::Warn] {
                let (_home, set) = secretspec_authorizations(required);
                let source = secretspec_source(Scripted::Invalid);
                let error = resolve_launch(&names(&["alpha"]), &set, &*source, policy)
                    .expect_err("a rejected value is fatal")
                    .to_string();
                assert!(error.contains("SecretSpec resolved for `alpha`"), "{error}");
                assert!(error.contains("secret `ALPHA_KEY`"), "{error}");
                assert!(error.contains("Fix it in SecretSpec"), "{error}");
                assert!(!error.contains("sk-CANARY"), "{error}");
            }
        }
    }

    /// R5: #162's replacement is unchanged — a same-named built-in is replaced,
    /// and an unavailable SecretSpec value does not fall back to it.
    #[test]
    fn a_secretspec_sourced_same_named_authorization_replaces_without_fallback() {
        use crate::credential_provider::CredentialProvider;
        let (_home, set) = authorizations(
            "credentials:\n  - service: anthropic\n    source: secretspec\n    apiKey:\n      name: \
             ANTHROPIC_API_KEY\n      inject: [{domain: api.anthropic.com, scheme: bearer}]\n    \
             secretspec:\n      executable: /nonexistent/secretspec\n      manifest: \
             /tmp/secretspec.toml\n      profile: default\n",
        );
        let source = TestSource::new().script(
            "anthropic",
            Scripted::SecretspecUnavailable(
                crate::credential_secretspec::SecretspecFailure::ProviderFailed,
            ),
        );
        let launch = resolve_launch(
            &names(&["anthropic"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .expect("optional by default");
        assert!(launch.ready().is_empty());
        assert!(
            launch.replaced().contains(CredentialProvider::Anthropic),
            "the built-in stays replaced even while the value is unavailable"
        );
        assert_eq!(source.lookups(), ["anthropic"]);
    }

    /// R6: phase 2 maps `missing` — and therefore `undeclared`, which is the same
    /// outcome — to `not_found`, and every failure to `failed`.
    #[test]
    fn phase_two_maps_undeclared_and_missing_to_not_found() {
        use crate::credential_secretspec::SecretspecFailure as F;
        // Phase 1 sees a value; phase 2 sees `Missing`, which is what
        // `undeclared` also is. The runtime must read that as `not_found`, not
        // as an authorization or a runtime failure.
        let (_home, set) = secretspec_authorizations(true);
        let source =
            TestSource::new().script("alpha", Scripted::ValueThenMissing("sk-once".into()));
        let launch = resolve_launch(
            &names(&["alpha"]),
            &set,
            &*source,
            MissingCredentialPolicy::Fail,
        )
        .expect("phase 1 saw a value");
        let resolver = launch.resolver(dyn_source(&source));
        assert_eq!(
            resolver.resolve("alpha").unwrap_err(),
            microsandbox::CredentialResolveError::NotFound
        );
        for failure in [F::ProviderFailed, F::ProtocolViolation, F::SessionLost] {
            let (_home, set) = secretspec_authorizations(true);
            let source = TestSource::new().script(
                "alpha",
                Scripted::ValueThenSecretspecUnavailable("sk-once".into(), failure),
            );
            let launch = resolve_launch(
                &names(&["alpha"]),
                &set,
                &*source,
                MissingCredentialPolicy::Fail,
            )
            .expect("phase 1 saw a value");
            let resolver = launch.resolver(dyn_source(&source));
            assert_eq!(
                resolver.resolve("alpha").unwrap_err(),
                microsandbox::CredentialResolveError::Failed,
                "{failure:?}"
            );
        }
    }

    /// R2's routing half: a secretspec-only launch reports the *SecretSpec*
    /// cause, and a keychain-sourced launch with the same file shape reports a
    /// keychain cause, so the two are distinguishable.
    ///
    /// This proves **routing**, not construction: it says which backend answers,
    /// not whether a keychain object was built. A keychain constructed and never
    /// read would pass it.
    /// `the_keychain_is_constructed_only_when_a_keychain_source_is_requested`
    /// observes the construction itself.
    #[test]
    fn a_secretspec_only_launch_needs_no_keychain() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(USER_CONFIG_DIR_RELATIVE);
        fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join(credential_yaml::CREDENTIALS_FILE_NAME);
        fs::write(
            &path,
            "credentials:\n  - service: alpha\n    source: secretspec\n    apiKey:\n      name: \
             ALPHA_KEY\n      inject: [{domain: api.alpha.example, scheme: bearer}]\n    \
             secretspec:\n      executable: /nonexistent/secretspec\n      manifest: \
             /tmp/secretspec.toml\n      profile: default\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut guard = crate::test_env::guard();
        guard.set_var("HOME", home.path());
        guard.remove_var("AGENT_VM_TEST_CREDENTIAL");
        let preflight = CredentialPreflight::capture(&names(&["alpha"]));
        let (launch, source, sessions) = preflight
            .resolve(MissingCredentialPolicy::Fail)
            .expect("an optional secretspec entry does not fail the launch");
        assert!(source.is_some());
        drop(sessions);
        assert!(launch.ready().is_empty());
        let notice = launch.withheld()[0].notice();
        assert!(
            notice.contains("`secretspec.executable` does not exist"),
            "the routing chose SecretSpec, not the keychain: {notice}"
        );
    }

    /// R2's construction half, which has no other observable: a keychain built
    /// and never read looks exactly like one never built.
    ///
    /// The count is incremented in the branch that builds it. The plan forbids
    /// extracting a `needs_keychain` helper, so construction is observed where
    /// it happens rather than through a new predicate.
    #[test]
    fn the_keychain_is_constructed_only_when_a_keychain_source_is_requested() {
        let secretspec_entry = "  - service: alpha\n    source: secretspec\n    apiKey:\n      \
                               name: ALPHA_KEY\n      inject: [{domain: api.alpha.example, \
                               scheme: bearer}]\n    secretspec:\n      executable: \
                               /nonexistent/secretspec\n      manifest: /tmp/secretspec.toml\n      \
                               profile: default\n";
        let env_entry = "  - service: alpha\n    source: env\n    apiKey:\n      name: \
                        ALPHA_KEY\n      inject: [{domain: api.alpha.example, scheme: bearer}]\n";
        let keychain_entry = "  - service: beta\n    apiKey:\n      name: BETA_KEY\n      \
                             inject: [{domain: api.beta.example, scheme: bearer}]\n";
        // The `HOME` a launch reads, and the delta the counter moved by.
        let constructions = |body: &str, services: &[&str]| -> usize {
            let home = tempfile::tempdir().unwrap();
            let dir = home.path().join(USER_CONFIG_DIR_RELATIVE);
            fs::create_dir_all(&dir).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let path = dir.join(credential_yaml::CREDENTIALS_FILE_NAME);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let mut guard = crate::test_env::guard();
            guard.set_var("HOME", home.path());
            guard.remove_var("AGENT_VM_TEST_CREDENTIAL");
            let before = keychain_built();
            // Either outcome is acceptable for the keychain case: what is under
            // test is whether a keychain was built, not whether this host has
            // one, and the counter moves before `system()` can fail.
            let _ = CredentialPreflight::capture(&names(services))
                .resolve(MissingCredentialPolicy::Fail);
            keychain_built() - before
        };
        let credentials = |entries: &[&str]| format!("credentials:\n{}\n", entries.concat());
        assert_eq!(
            constructions(&credentials(&[secretspec_entry]), &["alpha"]),
            0,
            "a secretspec-only launch must build no keychain"
        );
        assert_eq!(
            constructions(&credentials(&[env_entry]), &["alpha"]),
            0,
            "an env-only launch must build no keychain"
        );
        assert_eq!(
            constructions(
                &credentials(&[keychain_entry, secretspec_entry]),
                &["alpha", "beta"]
            ),
            1,
            "a keychain-sourced authorization must build exactly one keychain"
        );
    }

    fn env_authorizations(required: bool, sentinel: bool) -> (tempfile::TempDir, AuthorizationSet) {
        authorizations(&format!(
            "credentials:\n  - service: alpha\n    source: env\n    required: {required}\n    apiKey:\n      name: ALPHA_KEY\n      sentinelEnv: {sentinel}\n      inject: [{{domain: api.alpha.example, scheme: bearer}}]\n"
        ))
    }

    #[test]
    fn an_unset_env_source_never_falls_back_to_the_keychain() {
        for (required, policy) in [
            (false, MissingCredentialPolicy::Fail),
            (true, MissingCredentialPolicy::Fail),
            (true, MissingCredentialPolicy::Warn),
        ] {
            let (_home, set) = env_authorizations(required, true);
            let keychain =
                TestSource::new().script("alpha", Scripted::Value("sk-store-decoy".into()));
            let source = LaunchSource {
                keychain: Some(dyn_source(&keychain)),
                environment: EnvCapture::take_with(&names(&["alpha"]), &set, |_| None),
                secretspec: None,
            };
            let result = resolve_launch(&names(&["alpha"]), &set, &source, policy);
            let text = if required && policy == MissingCredentialPolicy::Fail {
                result.unwrap_err().to_string()
            } else {
                let launch = result.unwrap();
                assert!(launch.ready().is_empty());
                launch.withheld()[0].notice()
            };
            assert!(text.contains("ALPHA_KEY"));
            assert!(text.contains("unset or empty"));
            assert_eq!(
                text.contains("because --allow-missing-credentials"),
                required && policy == MissingCredentialPolicy::Warn
            );
            assert!(keychain.lookups().is_empty());
        }
    }

    #[test]
    fn each_service_reads_only_its_own_source() {
        let (_home, set) = authorizations(
            "credentials:\n  - service: alpha\n    source: env\n    apiKey:\n      name: ALPHA_KEY\n      sentinelEnv: true\n      inject: [{domain: api.alpha.example, scheme: bearer}]\n  - service: beta\n    apiKey:\n      name: BETA_KEY\n      inject: [{domain: api.beta.example, scheme: bearer}]\n",
        );
        let mut captured = Vec::new();
        let environment = EnvCapture::take_with(&names(&["alpha", "beta"]), &set, |name| {
            captured.push(name.as_str().to_owned());
            Some("sk-env".into())
        });
        let keychain = TestSource::new().script("beta", Scripted::Value("sk-store".into()));
        let source = LaunchSource {
            keychain: Some(dyn_source(&keychain)),
            environment,
            secretspec: None,
        };
        let launch = resolve_launch(
            &names(&["alpha", "beta"]),
            &set,
            &source,
            MissingCredentialPolicy::Fail,
        )
        .unwrap();
        assert_eq!(launch.ready().len(), 2);
        assert_eq!(captured, ["ALPHA_KEY"]);
        assert_eq!(keychain.lookups(), ["beta"]);
    }

    #[test]
    fn phase_two_resolves_an_env_service_from_the_capture() {
        let (_home, set) = env_authorizations(false, true);
        let source: Arc<dyn CredentialSource> = Arc::new(LaunchSource {
            keychain: None,
            environment: EnvCapture::take_with(&names(&["alpha"]), &set, |_| {
                Some("sk-phase-two".into())
            }),
            secretspec: None,
        });
        let launch = resolve_launch(
            &names(&["alpha"]),
            &set,
            source.as_ref(),
            MissingCredentialPolicy::Fail,
        )
        .unwrap();
        let resolver = launch.resolver(source);
        for _ in 0..2 {
            assert_eq!(&*resolver.resolve("alpha").unwrap(), "sk-phase-two");
        }
        assert!(resolver.resolve("beta").is_err());
    }

    #[test]
    fn an_invalid_env_value_is_a_hard_error_under_both_policies() {
        for policy in [MissingCredentialPolicy::Fail, MissingCredentialPolicy::Warn] {
            let (_home, set) = env_authorizations(false, false);
            let source = EnvCapture::take_with(&names(&["alpha"]), &set, |_| {
                Some(" sk-CANARY-invalid".into())
            });
            let error = resolve_launch(&names(&["alpha"]), &set, &source, policy)
                .unwrap_err()
                .to_string();
            assert!(error.contains("ALPHA_KEY"));
            assert!(error.contains("leading or trailing space"));
            assert!(!error.contains("sk-CANARY-invalid"));
        }
    }

    #[test]
    fn env_sentinel_true_publishes_only_the_sentinel_and_false_leaves_it_unset() {
        for sentinel in [true, false] {
            let (_home, set) = env_authorizations(false, sentinel);
            let source =
                EnvCapture::take_with(&names(&["alpha"]), &set, |_| Some("sk-sentinel".into()));
            let launch = resolve_launch(
                &names(&["alpha"]),
                &set,
                &source,
                MissingCredentialPolicy::Fail,
            )
            .unwrap();
            let env = assemble(&launch, &BTreeMap::new());
            assert_eq!(
                value_of(&env, "ALPHA_KEY"),
                if sentinel {
                    Some("proxy-managed")
                } else {
                    None
                }
            );
        }
    }

    #[test]
    fn an_env_sourced_value_is_injected_into_exactly_its_authorized_header() {
        use microsandbox_network::{
            secrets::{credential::ResolvedHeaderCredential, handler::SecretsHandler},
            shared::{ResolvedHostnameFamily, SharedState},
        };
        use std::{
            net::{IpAddr, SocketAddr},
            time::Duration,
        };
        let canary = "sk-CANARY-163-joined-header";
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let input = b"POST /v1 HTTP/1.1\r\nHost: api.alpha.example\r\nContent-Length: 5\r\nX-Trace: abc\r\n\r\nhello";
        let expected = format!(
            "POST /v1 HTTP/1.1\r\nHost: api.alpha.example\r\nContent-Length: 5\r\nX-Trace: abc\r\nauthorization: Bearer {canary}\r\n\r\nhello"
        );
        let mut positive_outputs = Vec::new();
        for sentinel in [true, false] {
            let (_home, set) = env_authorizations(false, sentinel);
            let source: Arc<dyn CredentialSource> = Arc::new(LaunchSource {
                keychain: None,
                environment: EnvCapture::take_with(&names(&["alpha"]), &set, |_| {
                    Some(canary.into())
                }),
                secretspec: None,
            });
            let launch = resolve_launch(
                &names(&["alpha"]),
                &set,
                source.as_ref(),
                MissingCredentialPolicy::Fail,
            )
            .unwrap();
            assert_eq!(launch.ready().len(), 1);
            assert_eq!(
                value_of(&assemble(&launch, &BTreeMap::new()), "ALPHA_KEY"),
                if sentinel {
                    Some("proxy-managed")
                } else {
                    None
                }
            );
            let state = tempfile::tempdir().unwrap();
            let config = durable_config(&launch, state.path());
            assert_eq!(config.secrets.header_credentials.len(), 1);
            assert_eq!(config.secrets.header_credentials[0].reference, "alpha");
            assert!(!serde_json::to_string(&config).unwrap().contains(canary));
            assert!(!format!("{config:?}").contains(canary));
            for (sni, pin, port, tls) in [
                ("api.alpha.example", "api.alpha.example", 443, true),
                ("other.example", "other.example", 443, true),
                ("api.alpha.example", "other.example", 443, true),
                ("api.alpha.example", "api.alpha.example", 8443, true),
                ("api.alpha.example", "api.alpha.example", 443, false),
            ] {
                let resolver = launch.resolver(Arc::clone(&source));
                let resolved = config
                    .secrets
                    .header_credentials
                    .iter()
                    .map(|def| {
                        ResolvedHeaderCredential::from_definition(
                            def,
                            resolver.resolve(&def.reference).unwrap(),
                        )
                    })
                    .collect();
                let shared = SharedState::new(16);
                shared.cache_resolved_hostname(
                    pin,
                    ResolvedHostnameFamily::Ipv4,
                    [ip],
                    Duration::from_secs(300),
                );
                let mut handler = if tls {
                    SecretsHandler::new_tls_intercepted(&config.secrets, sni, ip, &shared)
                } else {
                    SecretsHandler::new_plain_http(&config.secrets, sni, ip, &shared)
                }
                .with_header_credentials(resolved)
                .with_guest_dst(SocketAddr::new(ip, port));
                let request = String::from_utf8(input.to_vec())
                    .unwrap()
                    .replace("api.alpha.example", sni);
                let output = handler.substitute(request.as_bytes()).unwrap().into_owned();
                if sni == "api.alpha.example" && pin == sni && port == 443 && tls {
                    assert_eq!(output, expected.as_bytes());
                    assert_eq!(
                        String::from_utf8_lossy(&output)
                            .matches("authorization:")
                            .count(),
                        1
                    );
                    positive_outputs.push(output);
                } else {
                    assert_eq!(output, request.as_bytes());
                }
            }
        }
        assert_eq!(positive_outputs[0], positive_outputs[1]);
    }
}
