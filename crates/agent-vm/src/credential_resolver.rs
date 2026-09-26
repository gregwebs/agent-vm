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
//! [`KeychainCredentialResolver`], called by the runtime immediately before
//! `fork` on a value it never keeps. Splitting them means a locked or missing
//! keychain fails *before* a sandbox is created, rather than producing a
//! booted-but-uncredentialed sandbox.
//!
//! The cost is two keychain reads per launch — not per connection, which is
//! why per-connection reads were rejected. Rotation is therefore
//! launch-scoped: `agent-vm secret set` does not reach a running sandbox.
//!
//! [`LaunchCredentials::assemble_guest_env`] is the one ownership-aware guest
//! environment decision. Every writer whose contribution *could* carry a name a
//! credential owns is settled there: a tool-declared `env` key is refused, and
//! host-forwarded / provider-forwarded pairs are dropped (AC2). The launcher's
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
use zeroize::Zeroizing;

use crate::config::USER_CONFIG_DIR_RELATIVE;
use crate::credential_provider::{CredentialProvider, ProviderSet};
use crate::credential_yaml::{self, AuthorizationSet, GuestEnvName};
use crate::secret_store::{
    KeychainFailure, Resolved, SecretStore, ServiceName, SystemKeychain, system_store,
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
pub(crate) struct KeychainCredentialSource {
    store: Mutex<SecretStore<SystemKeychain>>,
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

/// A source that resolves nothing, for a launch whose requested names are
/// **all** built-in providers (or absent). Such a launch has no authorized
/// YAML credential, so [`resolve_launch`] never reaches its source; this
/// exists so that launch never constructs (or depends on) a keychain at all -
/// a host with no `$HOME`, or a Linux host with no Secret Service, must still
/// be able to run a built-in-only launch exactly as before.
pub(crate) struct NoKeychainSource;

impl CredentialSource for NoKeychainSource {
    fn resolve(&self, _service: &ServiceName) -> Resolved {
        Resolved::Missing
    }
}

/// Phase 2: the value the runtime's spawn path asks for, immediately before
/// `fork`.
///
/// `allowed` is exactly the services this launch authorized **and** requested.
/// The check is load-bearing (AC8): a durable config tampered with between
/// build and spawn cannot widen what is read, because a reference outside the
/// set is refused rather than resolved.
pub(crate) struct KeychainCredentialResolver {
    source: Arc<dyn CredentialSource>,
    allowed: BTreeSet<ServiceName>,
}

impl microsandbox::CredentialResolver for KeychainCredentialResolver {
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
            Resolved::Unavailable(_) | Resolved::InvalidValue(_) => {
                Err(microsandbox::CredentialResolveError::failed())
            }
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
/// override "cannot bypass malformed configuration, expand destinations,
/// forward raw values, or select a fallback source"
/// (docs/specs/credential-shielding.md line 233).
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
/// authorization, so agent-vm must actively suppress every other writer (raw
/// forwarding, a tool-declared `env` key) rather than merely declining to add
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
/// credential-relevant writers (`tool_env`, `forwarded`, `provider`) can only
/// be settled in one place (agent-vm #161 review, M1). The launcher-owned
/// writers (`path`, `identity`, `always`) are emitted unfiltered; their names
/// are already refused as credential-owned names at load time, so filtering
/// them here would be unreachable code.
pub(crate) struct GuestEnvSources<'a> {
    /// The launched tool's own config-declared `env` pairs.
    pub tool_env: &'a BTreeMap<String, String>,
    /// Host variables forwarded verbatim (e.g. `ANTHROPIC_API_KEY`), already
    /// filtered to those actually set and non-empty by the caller.
    pub forwarded: &'a [(&'static str, String)],
    /// The booted image's own `PATH` (or the launcher fallback).
    pub path: String,
    /// The non-root guest identity triple (`HOME`/`USER`/`LOGNAME`), empty in
    /// root mode.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WithheldCause {
    Missing,
    Unavailable(KeychainFailure),
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

impl Withheld {
    /// The full, renderable reason. Names the service (user-controlled
    /// metadata, already shown by `secret ls`) and, for `Unavailable`, the
    /// closed failure message, so "locked" never reads as "not stored".
    pub(crate) fn reason(&self) -> String {
        match self.cause {
            WithheldCause::Missing => format!(
                "no value is stored in the system keychain for `{}`; store it with `agent-vm secret set {}`",
                self.service, self.service
            ),
            WithheldCause::Unavailable(failure) => format!(
                "the system keychain could not be read for `{}`: {}",
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
        Arc::new(KeychainCredentialResolver {
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
    /// - `forwarded` and `provider` — an owned name is **dropped**.
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
    /// context. A forwarded or provider variable an authorization owns is
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
            env.push((key.clone(), value.clone()));
        }
        for (name, value) in sources.forwarded {
            if !self.owns_env(name) {
                env.push(((*name).to_owned(), value.clone()));
            }
        }
        env.push(("PATH".to_owned(), sources.path));
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

    for service in requested {
        let built_in = CredentialProvider::from_config_name(service.as_str());
        match (built_in, authorization.get(service)) {
            // AC1: the authorization wins outright. The built-in's credential
            // facets are suppressed through `replaced` (see `secrets.rs`); its
            // configuration and persistence facets are untouched (AC2). There
            // is deliberately no fallback arm: an unavailable authorized value
            // does not re-enable the built-in, because that would silently
            // downgrade a shielded credential to a guest-visible placeholder.
            (built_in, Some(credential)) => {
                if let Some(provider) = built_in {
                    launch.replaced = launch.replaced.union(ProviderSet::new([provider]));
                }
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
        Resolved::Missing | Resolved::Unavailable(_) => {
            let cause = match &resolved {
                Resolved::Unavailable(failure) => WithheldCause::Unavailable(*failure),
                _ => WithheldCause::Missing,
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
            // A hard error regardless of `required` and regardless of the
            // policy: the stored bytes are not a value this release will
            // inject, and treating that as merely withheld would hide a real
            // problem behind a warning.
            return Err(anyhow!(
                "the stored value for `{service}` cannot be used: {}. Remove and \
                 re-store it with `agent-vm secret set {service}`",
                rejection.message()
            ));
        }
    }
    Ok(())
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
        Invalid,
    }

    /// A plain `Send + Sync` source: a pre-seeded map behind a `Mutex`. The
    /// point of `CredentialSource` is that this never has to be the `!Sync`
    /// `FakeKeychain`.
    struct TestSource {
        scripted: Mutex<BTreeMap<String, Scripted>>,
        lookups: Mutex<Vec<String>>,
    }

    impl TestSource {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                scripted: Mutex::new(BTreeMap::new()),
                lookups: Mutex::new(Vec::new()),
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
            match self.scripted.lock().unwrap().get(service.as_str()).cloned() {
                Some(Scripted::Value(raw)) => {
                    Resolved::Value(SecretValue::parse(raw.into_bytes()).expect("acceptable"))
                }
                Some(Scripted::Unavailable(failure)) => Resolved::Unavailable(failure),
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
                forwarded: &[
                    ("ANTHROPIC_API_KEY", "host-anthropic".to_owned()),
                    ("OPENAI_API_KEY", "host-openai".to_owned()),
                ],
                path: "/image/bin".to_owned(),
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
        let source = TestSource::new()
            .script("alpha", Scripted::Missing)
            .script("beta", Scripted::Unavailable(KeychainFailure::AccessDenied));
        // Phase 1 refuses Missing/Unavailable for required, so build the
        // resolver through the type's own constructor instead.
        let resolver = KeychainCredentialResolver {
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
        // The host's real OPENAI_API_KEY is not forwarded, and no sentinel is
        // published - the name is genuinely unset. The launcher's other writers
        // are untouched.
        assert!(!contains_key(&env, "OPENAI_API_KEY"));
        assert_eq!(value_of(&env, "PATH"), Some("/image/bin"));
        assert_eq!(value_of(&env, "IS_SANDBOX"), Some("1"));
        assert_eq!(value_of(&env, "ANTHROPIC_API_KEY"), Some("host-anthropic"));
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
                forwarded: &[],
                path: String::new(),
                identity: &[],
                always: &[],
                provider: &[],
            })
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("ALPHA_KEY"), "{text}");
        assert!(text.contains("credentials.yaml"), "{text}");
    }

    #[test]
    fn withheld_optional_credential_still_suppresses_raw_forwarding() {
        // A host `OPENAI_API_KEY` must not leak when a YAML credential *owns*
        // the name, even though the keychain read came back `Missing` (so it is
        // withheld rather than ready). Suppression comes from the authorization,
        // not from resolution success (AC2).
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
        assert_eq!(value_of(&env, "ANTHROPIC_API_KEY"), Some("host-anthropic"));
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
                        forwarded: &[("OPENAI_API_KEY", "host-openai".to_owned())],
                        path: "/image/bin".to_owned(),
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
                        forwarded: &[("OPENAI_API_KEY", "host-openai".to_owned())],
                        path: "/image/bin".to_owned(),
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
        // ownership, exactly like the raw-forwarded list.
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
}
