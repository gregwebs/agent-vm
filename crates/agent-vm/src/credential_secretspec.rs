//! `source: secretspec` (agent-vm #202): the value comes from the user's
//! SecretSpec configuration, read on the host through one
//! `secretspec serve --read-only` session per pinned session key.
//!
//! Nothing here is an authorization: `~/.config/agent-vm/credentials.yaml`
//! stays the only thing that decides whether a service's value may leave the
//! host, and it decides *where* with `source:`. SecretSpec's manifest is
//! consulted for the value and never for permission.
//!
//! # The shape
//!
//! - [`config`] — the validated `secretspec:` table (`SecretspecSelection`,
//!   `SessionKey`). Pure, no I/O.
//! - [`protocol`] — the `secretspec.resolver/1` frames, the handshake gate and
//!   the outcome mapping. Pure.
//! - [`session`] — one child, its framing, its bounds and its process group.
//! - [`failure`] — the closed failure taxonomy and its remedies.
//! - `fake` — the debug-only endpoint the boot-free tests speak to.
//!
//! The module's external interface is a `CredentialSource` like any other, so
//! routing, the two phases and the availability policy are unchanged.
//!
//! # What is not claimed
//!
//! agent-vm never *emits* a resolved value: not into logs, `Debug`, argv, the
//! guest environment or files, the durable sandbox config, an error message, a
//! warning, or `doctor`; and it never newly *assigns* a value to the
//! environment of a child it spawns. A value the operator already placed in
//! agent-vm's environment and that a SecretSpec provider consumes as its own
//! input (an `env` provider's variable, `OP_*`, `VAULT_*`, `AWS_*`) is ambient
//! trusted input, not something this module emits — the same line
//! `credential_env` draws for `source: env`.

pub(crate) mod config;
pub(crate) mod failure;
#[cfg(any(test, debug_assertions))]
pub(crate) mod fake;
pub(crate) mod pool;
pub(crate) mod protocol;
pub(crate) mod session;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::credential_resolver::CredentialSource;
use crate::credential_yaml::{AuthorizationSet, SourceKind};
use crate::secret_store::{Resolved, ServiceName};

use config::{SecretspecSelection, SessionKey};
use pool::SessionPool;

#[cfg(test)]
mod tests;

pub(crate) use failure::SecretspecFailure;

use vstd::prelude::*;

verus! {

/// The Boolean selection decision for one credential: read from SecretSpec iff
/// the name is requested, it is authorized, and that authorization selects
/// `source: secretspec`. Same shape and scope as
/// `credential_env::env_source_selected`, and the same trusted adapter story:
/// only this decision is proved.
pub(crate) fn secretspec_source_selected(
    requested: bool,
    authorized: bool,
    secretspec_source: bool,
) -> (selected: bool)
    ensures
        selected == (requested && authorized && secretspec_source),
{
    requested && authorized && secretspec_source
}

/// The mandatory-capability half of the handshake gate: protocol v1 **and both**
/// required methods, `resolver.get` and `resolver.release`.
///
/// Requiring `resolver.release` is a capability check, not a path lease:
/// agent-vm never sends it, because a `value` get creates no lease. A server
/// that offers `get` alone is refused, which is why this is a separate kernel
/// from the read-only half — the two refusals carry different messages.
pub(crate) fn capability_satisfied(
    speaks_v1: bool,
    offers_get: bool,
    offers_release: bool,
) -> (ok: bool)
    ensures
        ok == (speaks_v1 && offers_get && offers_release),
        ok ==> offers_get && offers_release,
{
    speaks_v1 && offers_get && offers_release
}

/// The read-only half of the gate: an accepted session never advertised a write
/// method.
pub(crate) fn offers_no_write_method(offers_set: bool, offers_delete: bool) -> (ok: bool)
    ensures
        ok == (!offers_set && !offers_delete),
{
    !offers_set && !offers_delete
}

} // verus!

/// The SecretSpec reads one launch may make: exactly the requested, authorized
/// `source: secretspec` services, each pinned to its session key and secret
/// name. Constructing it does no I/O; children start on the first read that
/// needs them, so an unrequested SecretSpec authorization spawns nothing.
pub(crate) struct SecretspecSource {
    selected: BTreeMap<ServiceName, SecretspecSelection>,
    pool: SessionPool,
}

impl SecretspecSource {
    /// `None` when no requested authorization selects SecretSpec, so such a
    /// launch builds nothing at all.
    pub(crate) fn select(
        requested: &BTreeSet<ServiceName>,
        authorizations: &AuthorizationSet,
    ) -> Option<Self> {
        Self::build(requested, authorizations, SessionPool::production())
    }

    #[cfg(test)]
    pub(in crate::credential_secretspec) fn select_with(
        requested: &BTreeSet<ServiceName>,
        authorizations: &AuthorizationSet,
        bounds: session::Bounds,
    ) -> Option<Self> {
        Self::build(requested, authorizations, SessionPool::with_bounds(bounds))
    }

    #[cfg(test)]
    pub(in crate::credential_secretspec) fn select_with_starter(
        requested: &BTreeSet<ServiceName>,
        authorizations: &AuthorizationSet,
        bounds: session::Bounds,
        starter: pool::TestStarter,
    ) -> Option<Self> {
        Self::build(
            requested,
            authorizations,
            SessionPool::with_starter(bounds, starter),
        )
    }

    fn build(
        requested: &BTreeSet<ServiceName>,
        authorizations: &AuthorizationSet,
        pool: SessionPool,
    ) -> Option<Self> {
        let mut selected = BTreeMap::new();
        for service in requested {
            let Some(credential) = authorizations.get(service) else {
                continue;
            };
            // `requested` and `authorized` are true by construction here; the
            // kernel is what makes the third fact the only variable.
            if !secretspec_source_selected(
                true,
                true,
                credential.source() == SourceKind::Secretspec,
            ) {
                continue;
            }
            let crate::credential_yaml::SourceSelection::Secretspec(selection) =
                credential.selection()
            else {
                // Unreachable: `source()` is the tag of `selection()`.
                continue;
            };
            selected.insert(service.clone(), selection.clone());
        }
        if selected.is_empty() {
            return None;
        }
        Some(Self { selected, pool })
    }

    /// Whether this launch reads `service` from SecretSpec. True for every
    /// selected service, so the router never falls through to another source.
    pub(crate) fn selects(&self, service: &ServiceName) -> bool {
        self.selected.contains_key(service)
    }

    /// Shut every session down. Later reads fail with `SessionClosed` and spawn
    /// nothing.
    pub(crate) fn close(&self) {
        self.pool.close();
    }

    fn session_for(&self, service: &ServiceName) -> Option<(&SessionKey, &config::SecretspecName)> {
        self.selected
            .get(service)
            .map(|selection| (selection.session(), selection.name()))
    }
}

impl CredentialSource for SecretspecSource {
    fn resolve(&self, service: &ServiceName) -> Resolved {
        match self.session_for(service) {
            Some((key, name)) => self.pool.get(key, name, service),
            None => Resolved::Missing,
        }
    }
}

/// Service → secret name and profile only. The pool's slots and any frame text
/// are never rendered, and there is no value in this type to render.
impl fmt::Debug for SecretspecSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.selected.iter().map(|(service, selection)| {
                (
                    service,
                    format!("{} (profile {})", selection.name(), selection.profile()),
                )
            }))
            .finish()
    }
}
