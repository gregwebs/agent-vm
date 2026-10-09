//! The host credential store behind `agent-vm secret` (#160).
//!
//! agent-vm has always *read* credentials other tools wrote on the host and
//! handed the guest placeholders (`secrets.rs`, `credential_provider.rs`).
//! This module owns the second kind: a value the *user* gives agent-vm, kept in
//! the host OS credential store under agent-vm's own namespace. It is the
//! lifecycle plus exactly one authorized read. The one way a stored value
//! comes back out is [`SecretStore::resolve`], reachable only from the launch
//! credential resolver (`credential_resolver.rs`) for a service that the user's
//! `credentials.yaml` authorizes *and* the launch requests. `secret ls`,
//! `doctor` and every diagnostic still cannot read a value: the only
//! value-shaped things they can obtain are the two-valued [`Presence`] a probe
//! returns and the index/label-only refusals. Storing a value does not
//! authorize its use (`docs/specs/credential-shielding.md`, §Contract).
//!
//! # The awkward fact: the credential store is not enumerable
//!
//! `keyring` 3.6.3 can `set`, probe and `delete` one `(service, account)` pair
//! and exposes **no portable enumeration API** (its `src/lib.rs` exports
//! `Entry`, `set_default_credential_builder`, `credential` and `mock`; the
//! Secret Service backend has internal attribute matching, nothing public, and
//! the macOS backend has none at all). `secret ls` therefore cannot ask the OS
//! "what does agent-vm own?".
//!
//! So a non-secret **inventory** of names lives beside the values, and `ls`
//! probes the credential store once per name. The inventory holds **names only,
//! never bytes**, which is what makes `ls` structurally incapable of printing a
//! value: the only value-shaped thing anywhere in the listing is the two-valued
//! [`Presence`] a probe returns. See ADR-0024 for the alternatives considered.
//!
//! The guarantee is about *values*: agent-vm never reads a stored value back out
//! to render it. A name is different — it is user-controlled metadata that `ls`
//! and the success messages display by design, and under the case-folding rule a
//! realistic API key is a valid name. A key mistakenly typed into the name slot
//! is therefore **exposed** (argv, shell history, listings); see `secret.rs`'s
//! module docs and USAGE.md.
//!
//! # Scope: the inventory is user-scoped, not state-scoped
//!
//! The keychain namespace ([`KEYCHAIN_SERVICE`]) is **host-wide**: every
//! agent-vm process on the machine addresses the same entries regardless of
//! `AGENT_VM_STATE_DIR`. An inventory under the state dir would therefore be
//! wrong rather than inconvenient — CONTRIBUTING.md encourages a separate state
//! root per worktree, so one worktree could delete a value another worktree's
//! `ls` never mentions. `$HOME/.config/agent-vm/` is the user-scoped directory
//! this repo already owns (`config.rs`'s `USER_CONFIG_DIR_RELATIVE`, deliberately
//! not XDG-overridable) and is where #161's `credentials.yaml` will live, so the
//! inventory's scope matches the namespace's scope.
//!
//! ```
//! ~/.config/agent-vm/secret-inventory.json     0600   names only
//! ~/.config/agent-vm/.secret-inventory.lock    0600   flock(2) target
//! ~/.config/agent-vm/                          0700   created if absent
//! ```
//!
//! # Service names are case-folded
//!
//! A name is accepted as 1-64 bytes of `[a-zA-Z0-9._-]` starting with a letter
//! or digit, and then **ASCII-lowercased**: the canonical form is the keychain
//! account, the inventory key and what `ls` prints, so `Anthropic`,
//! `ANTHROPIC` and `anthropic` are one credential rather than three invisible
//! duplicates in a case-sensitive keychain. Both halves are machine-checked
//! (`service_name_is_valid_spec` and `service_name_canonical_bytes`; the spec
//! functions are erased under a plain build, so they are not rustdoc links), and
//! the latter's contract is what proves that folding an accepted name leaves it
//! accepted — so validation and canonicalization cannot disagree about what is
//! storable. #161 must fold a YAML `service:` the same way, or the two sides
//! can disagree about which credential a name selects.
//!
//! # The ordering invariant
//!
//! `set` writes the **inventory first, then the value**. The invariant is: *a
//! stored value is always listed*. The reverse drift (a listed name with no
//! value) is visible, truthful and repairable; the opposite ordering produces
//! the failure mode that actually hurts — a value sitting in the user's
//! keychain that `secret ls` never mentions. `remove` runs the other way and
//! **re-probes after the delete** before dropping the row (see `remove`),
//! because `keyring` 3.6.3's macOS backend reports a delete it did not verify.
//!
//! Every mutation — and `list`, so it never observes a half-published file —
//! runs under an exclusive `flock(2)` ([`InventoryLock`]). Two concurrent
//! `secret set` runs are realistic (`printf … | agent-vm secret set x` is
//! documented as scriptable), and a lost inventory row means a stored value
//! nobody can see.
//!
//! # No fallback, and no durability claim
//!
//! There is **no** file-backed store, no plaintext path, no env-var degradation.
//! If the platform credential store is unavailable the operation fails with a
//! classified message; `docs/specs/credential-shielding.md` ("Keychain source",
//! AC 10) requires that unavailability never creates plaintext storage.
//! Docker falls back to a plaintext file on headless Linux; agent-vm does not.
//!
//! # A read that never returns is abandoned, not waited on (#251)
//!
//! Every read this module serves calls the platform credential store
//! synchronously, and that call has **no bound of its own**: on macOS
//! `SecKeychainFindGenericPassword` waits on the system's unlock prompt when the
//! keychain is locked, and on Linux a Secret Service round-trip waits on the
//! keyring daemon. A launch inherits that wait, and holds
//! `~/.config/agent-vm/.secret-inventory.lock` for its duration, which wedges
//! every other agent-vm process; nothing above this module can tell a user who
//! is typing a password from a call that is wedged. So the bound lives here, at
//! the one boundary that knows it is calling a platform store:
//! [`BoundedKeychainReads`] abandons a read that outlives
//! [`keychain_read_bound`] and reports it as [`KeychainFailure::Unresponsive`],
//! which every caller already renders as a locked/unavailable keychain rather
//! than as a missing value.
//!
//! Only **reads** are bounded. An abandoned `set` or `delete` would keep
//! running and could still commit, turning a reported failure into a later lie
//! about what is stored — a worse outcome than the wait it avoids.
//!
//! Crash durability is **not** claimed: [`crate::host_paths::atomic_write`]
//! renames without `fsync`ing the file or its directory, so a power loss can
//! lose the most recent inventory update. The consequence is a listing drift,
//! never a lost value, and it is repairable by re-running `secret set`. See
//! ADR-0024.
//!
//! # The lock wait is bounded; a mutation under the lock is not (#291)
//!
//! `set` and `remove` hold the inventory lock across their platform call, and
//! that call stays unbounded for the #251 reason above. Bounding reads did
//! not bound the lock: a mutation parked on an unlock prompt held it
//! indefinitely, and every other agent-vm process on the host — every verb and
//! every credential-bearing launch — waited behind it in silence. The bound is
//! on the **waiter**: [`SecretStore::lock`] gives up after
//! [`inventory_lock_wait`], and the verbs name the lock file
//! ([`KeychainFailure::InventoryBusy`] for a launch). A waiter that gives up has
//! not begun its own read-modify-write, so its failure is true when reported
//! and stays true — the property that bounding the holder cannot have.

#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::IsTerminal as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use vstd::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::config;
use crate::host_paths::{
    FlockWait, atomic_write, flock_exclusive_within, read_bounded_regular_file,
};

verus! {

/// The longest accepted service name. Short enough that a keychain account
/// string is comfortably inside every backend's attribute limits, and long
/// enough for a reverse-DNS-ish provider identifier.
pub(crate) const MAX_SERVICE_NAME_LEN: usize = 64;

/// The longest accepted secret value. Bounds a runaway paste or a redirected
/// file; far above any real API key.
pub(crate) const MAX_SECRET_VALUE_LEN: usize = 4096;

/// Bytes an accepted service name may contain after its first byte: ASCII
/// letters (either case), digits, `.`, `_` and `-`.
///
/// The alphabet is deliberately one shape (`pi_credential_inspection::provider_id_byte_allowed`
/// plus letters' other case) so the codebase has **one** identifier shape.
/// Uppercase is *accepted and folded*, not rejected: see
/// [`service_name_lower_byte`].
pub(crate) open spec fn service_name_byte_allowed(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z')
        || (b'A' <= byte && byte <= b'Z')
        || (b'0' <= byte && byte <= b'9')
        || byte == b'.' || byte == b'_' || byte == b'-'
}

/// The first byte additionally may not be punctuation, so a name can never be
/// confused with a flag or a path fragment.
pub(crate) open spec fn service_name_first_byte_allowed(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z')
        || (b'A' <= byte && byte <= b'Z')
        || (b'0' <= byte && byte <= b'9')
}

/// The whole service-name decision: accepted iff the byte sequence is 1..=64
/// bytes, starts with an ASCII letter (either case) or digit, and every byte is
/// `[a-zA-Z0-9._-]`.
pub(crate) open spec fn service_name_is_valid_spec(bytes: Seq<u8>) -> bool {
    1 <= bytes.len() && bytes.len() <= MAX_SERVICE_NAME_LEN
        && service_name_first_byte_allowed(bytes[0])
        && forall|i: int| 0 <= i < bytes.len() ==> service_name_byte_allowed(bytes[i])
}

/// The ASCII-lowercase mapping the canonical service name is derived from.
///
/// Canonicalization is the *identity* of a stored name: the canonical form is
/// the keychain account, the inventory key, and what `ls` prints. Keychain
/// accounts are case-sensitive, so without folding `Anthropic` and `anthropic`
/// would be two invisible entries — the "silently approximated behavior" the
/// spec forbids. Folding (rather than rejecting uppercase) is the documented
/// rule, and #161 must fold a YAML `service:` the same way.
pub(crate) open spec fn service_name_lower_byte(byte: u8) -> u8 {
    // The `as u8` is Verus's u8 arithmetic: a spec expression computes in `int`,
    // while the exec body below is already a `u8`. The value is in `0x61..=0x7A`
    // in the taken branch, so the cast is the identity there.
    if b'A' <= byte && byte <= b'Z' {
        ((byte - b'A') + b'a') as u8
    } else {
        byte
    }
}

/// Bytes an accepted secret value may contain: printable ASCII `0x20..=0x7E`.
///
/// The value's destination (#161) is an HTTP request header, where CR/LF is a
/// header-injection primitive and non-ASCII needs an encoding decision nobody
/// has made, so rejecting at the point of storage is defence in depth one
/// ticket ahead of the injector. NUL is rejected as **application policy**, not
/// a platform limit — macOS explicitly supports NUL in a generic password — but
/// it cannot appear in a header value and is a classic truncation hazard.
pub(crate) open spec fn secret_value_byte_allowed(byte: u8) -> bool {
    b' ' <= byte && byte <= b'~'
}

/// The whole value-shape decision: accepted iff the byte sequence is 1..=4096
/// bytes, every byte is printable ASCII, and neither the first nor the last
/// byte is a space. A space is invisible, and shells and copy-paste add them;
/// rejecting is safer than trimming, which would silently store something other
/// than what the user supplied.
pub(crate) open spec fn secret_value_is_acceptable_spec(bytes: Seq<u8>) -> bool {
    1 <= bytes.len() && bytes.len() <= MAX_SECRET_VALUE_LEN
        && forall|i: int| 0 <= i < bytes.len() ==> secret_value_byte_allowed(bytes[i])
        && bytes[0] != b' '
        && bytes[bytes.len() - 1] != b' '
}

// The `<=` spelling (rather than clippy's suggested `(b'a'..=b'z').contains`)
// is kept so the exec bytes stay syntactically the predicate the `verus!` spec
// fn unfolds to.
#[allow(clippy::manual_range_contains)]
fn service_name_is_valid_bytes(bytes: &[u8]) -> (ok: bool)
    ensures ok == service_name_is_valid_spec(bytes@),
{
    let len = bytes.len();
    if len == 0 || len > MAX_SERVICE_NAME_LEN {
        return false;
    }
    let first = bytes[0];
    assert(service_name_first_byte_allowed(first) == (
        (b'a' <= first && first <= b'z')
            || (b'A' <= first && first <= b'Z')
            || (b'0' <= first && first <= b'9')
    ));
    if !((b'a' <= first && first <= b'z')
        || (b'A' <= first && first <= b'Z')
        || (b'0' <= first && first <= b'9'))
    {
        return false;
    }
    let mut i: usize = 0;
    while i < len
        invariant
            i <= len,
            len == bytes@.len(),
            1 <= len,
            len <= MAX_SERVICE_NAME_LEN,
            service_name_first_byte_allowed(bytes@[0]),
            forall|j: int| 0 <= j < i ==> service_name_byte_allowed(bytes@[j]),
        decreases len - i,
    {
        let byte = bytes[i];
        assert(service_name_byte_allowed(byte) == (
            (b'a' <= byte && byte <= b'z')
                || (b'A' <= byte && byte <= b'Z')
                || (b'0' <= byte && byte <= b'9')
                || byte == b'.' || byte == b'_' || byte == b'-'
        ));
        // The predicate is inlined, not called: a `spec fn` erases under a
        // plain build, so an exec call to it would not compile.
        if !((b'a' <= byte && byte <= b'z')
            || (b'A' <= byte && byte <= b'Z')
            || (b'0' <= byte && byte <= b'9')
            || byte == b'.'
            || byte == b'_'
            || byte == b'-')
        {
            return false;
        }
        i += 1;
    }
    true
}

/// Lowercasing neither adds nor removes an accepted byte, and neither adds nor
/// removes a valid first byte. Those two facts are what make "canonicalize,
/// then validate" and "validate, then canonicalize" the same decision, so a
/// second acceptance check on the canonical form is unnecessary.
proof fn lemma_lower_byte_is_allowed_both_ways(byte: u8)
    ensures service_name_byte_allowed(service_name_lower_byte(byte))
        == service_name_byte_allowed(byte),
{
}

proof fn lemma_lower_byte_is_first_allowed_both_ways(byte: u8)
    ensures service_name_first_byte_allowed(service_name_lower_byte(byte))
        == service_name_first_byte_allowed(byte),
{
}

/// The canonical (ASCII-lowercased) form of an accepted name — the value the
/// store actually keys on. A pure transform of the already-measured bytes, so
/// it carries a contract: the canonical form of a valid name is valid, which is
/// what lets [`ServiceName::parse`] store and print it without a second check.
#[allow(clippy::manual_range_contains)]
fn service_name_canonical_bytes(bytes: &[u8]) -> (out: Vec<u8>)
    requires service_name_is_valid_spec(bytes@),
    ensures
        out@.len() == bytes@.len(),
        service_name_is_valid_spec(out@),
{
    let len = bytes.len();
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < len
        invariant
            i <= len,
            len == bytes@.len(),
            // A loop body does not inherit the function's `requires`, so the
            // acceptance of the input bytes is restated here.
            service_name_is_valid_spec(bytes@),
            out@.len() == i,
            forall|j: int| 0 <= j < i ==> out@[j] == service_name_lower_byte(bytes@[j]),
            forall|j: int| 0 <= j < i ==> service_name_byte_allowed(out@[j]),
        decreases len - i,
    {
        let byte = bytes[i];
        assert(service_name_byte_allowed(bytes@[i as int]));
        // The `<=` spelling (and the inlining) matches `service_name_lower_byte`
        // exactly: a `spec fn` erases under a plain build, so the exec body
        // restates it, and the assert below ties the two together.
        let lower = if b'A' <= byte && byte <= b'Z' {
            (byte - b'A') + b'a'
        } else {
            byte
        };
        assert(lower == service_name_lower_byte(byte));
        proof { lemma_lower_byte_is_allowed_both_ways(byte); }
        assert(service_name_byte_allowed(lower));
        out.push(lower);
        assert(out@[i as int] == lower);
        i += 1;
    }
    // The first byte has to be checked separately: the loop's invariant only
    // covers bytes already behind the cursor.
    assert(service_name_first_byte_allowed(bytes@[0]));
    proof { lemma_lower_byte_is_first_allowed_both_ways(bytes@[0]); }
    assert(out@[0] == service_name_lower_byte(bytes@[0]));
    out
}

#[allow(clippy::manual_range_contains)]
fn secret_value_is_acceptable_bytes(bytes: &[u8]) -> (ok: bool)
    ensures ok == secret_value_is_acceptable_spec(bytes@),
{
    let len = bytes.len();
    if len == 0 || len > MAX_SECRET_VALUE_LEN {
        return false;
    }
    assert(secret_value_byte_allowed(bytes[0]) == (b' ' <= bytes[0] && bytes[0] <= b'~'));
    assert(secret_value_byte_allowed(bytes[len - 1]) == (
        b' ' <= bytes[len - 1] && bytes[len - 1] <= b'~'
    ));
    if bytes[0] == b' ' || bytes[len - 1] == b' ' {
        return false;
    }
    let mut i: usize = 0;
    while i < len
        invariant
            i <= len,
            len == bytes@.len(),
            1 <= len,
            len <= MAX_SECRET_VALUE_LEN,
            bytes@[0] != b' ',
            bytes@[len - 1] != b' ',
            forall|j: int| 0 <= j < i ==> secret_value_byte_allowed(bytes@[j]),
        decreases len - i,
    {
        let byte = bytes[i];
        assert(secret_value_byte_allowed(byte) == (b' ' <= byte && byte <= b'~'));
        if !(b' ' <= byte && byte <= b'~') {
            return false;
        }
        i += 1;
    }
    true
}

} // verus!

/// agent-vm's own namespace in the host credential store. Reverse-DNS, like
/// microsandbox's `dev.microsandbox.registry`, and deliberately unrelated to
/// Docker's `com.docker.sandboxes`: agent-vm neither reads nor writes Docker's
/// secrets (spec "Keychain source"). Changing this before any user stores a
/// value is free; afterwards it is a migration.
const KEYCHAIN_SERVICE: &str = "dev.agent-vm.credentials";

const INVENTORY_FILE_NAME: &str = "secret-inventory.json";
const LOCK_FILE_NAME: &str = ".secret-inventory.lock";
const INVENTORY_VERSION: u32 = 1;
const INVENTORY_FILE_MODE: u32 = 0o600;
const CONFIG_DIR_MODE: u32 = 0o700;

/// A names-only file a user will find and read. It exists so the file cannot be
/// mistaken for an authorization list: storing a value never authorizes its use
/// (spec §Contract, AC 7). Written always, ignored on read.
const INVENTORY_NOTE: &str = "service names only - this file is not an authorization list";

/// What every corrupt-inventory error ends with. The listing can always be
/// reset safely: deleting it loses only the row set, never a value, and `rm`
/// works by name against the credential store once the file is gone.
const INVENTORY_RECOVERY: &str = "delete this file to reset the listing; the stored values are \
                                  unaffected and `agent-vm secret rm NAME` still works by name";

/// Ceiling on the inventory read. A names-only file; a hostile or corrupt one
/// must not be able to make a listing unbounded.
const MAX_INVENTORY_BYTES: u64 = 1024 * 1024;

/// A service name, validated at the boundary by [`ServiceName::parse`] and
/// **canonicalized** to ASCII lowercase there.
///
/// The canonical form is the identity of a stored credential: it is the
/// keychain account, the inventory key, and what `ls` prints, so `Anthropic`,
/// `ANTHROPIC` and `anthropic` are one entry. Folding rather than rejecting is
/// deliberate — keychain accounts are case-sensitive, so rejecting would be
/// safer but hostile, and normalizing silently at some *later* layer is what
/// the spec forbids. #161 must fold a YAML `service:` the same way, or the two
/// sides can disagree.
///
/// Only a *validated* name is ever rendered: the argv shape
/// `agent-vm secret set sk-ant-REAL` (a user forgetting the name and typing the
/// key) puts a secret in the name position, so the rejected raw string is never
/// echoed and deliberately has no `Display`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ServiceName(String);

/// Shown for any rejected name. States the rule and does not echo the input, in
/// case a secret value was typed where a name belongs. `SERVICE` is the
/// argument name, not the user's text.
const SERVICE_NAME_RULE: &str = "'SERVICE' must be 1-64 characters from [a-zA-Z0-9._-] and start \
                                 with a letter or digit; letters are folded to lowercase. The \
                                 supplied name does not match and is not shown here, in case a \
                                 secret value was typed in its place";

impl ServiceName {
    /// The trusted adapter around the proved [`service_name_is_valid_bytes`]
    /// and [`service_name_canonical_bytes`]: the `&str` → bytes measurement and
    /// the `Vec<u8>` → `String` assembly are outside the proof (ADR-0018), and
    /// the two proof lemmas above are what make canonicalizing before keying
    /// equivalent to validating first.
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let bytes = raw.as_bytes();
        if !service_name_is_valid_bytes(bytes) {
            return Err(anyhow!(SERVICE_NAME_RULE));
        }
        let canonical = match String::from_utf8(service_name_canonical_bytes(bytes)) {
            Ok(name) => name,
            // Unreachable: every accepted byte is ASCII, hence valid UTF-8.
            Err(_) => return Err(anyhow!(SERVICE_NAME_RULE)),
        };
        Ok(Self(canonical))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A secret value, validated at the boundary by [`SecretValue::parse`].
///
/// Deliberately unprintable: no `Display`, no `Deref`, no public `as_str`. The
/// only ways out are [`Self::expose`], which is the single audited *write*
/// call site (`SystemKeychain::set`), and `credential_resolver.rs`'s read of an
/// authorized value into the runtime's resolver — the only two places a stored
/// value becomes a plain `&str`. The inner `String` is zeroized on drop as a
/// best-effort reduction of the plaintext window (it cannot cover the copies
/// listed in ADR-0025).
pub(crate) struct SecretValue(Zeroizing<String>);

impl SecretValue {
    /// The trusted adapter around the proved [`secret_value_is_acceptable_bytes`]:
    /// the byte measurement is outside the proof (ADR-0018). The proved
    /// predicate is the *decision*; [`value_rejection`] only labels which rule
    /// failed so the message is specific, and a test pins the two together.
    pub(crate) fn parse(bytes: Vec<u8>) -> Result<Self> {
        match Self::try_parse(bytes) {
            Ok(value) => Ok(value),
            Err(rejection) => Err(anyhow!(rejection.message())),
        }
    }

    /// The same decision as [`Self::parse`], with the label rather than a
    /// message. A read path must distinguish "the stored bytes are not an
    /// acceptable value" from "nothing is stored", so it takes this form.
    ///
    /// The buffer is zeroized on **every** path: a rejected value is wiped
    /// before the `Vec` is freed, so no plaintext copy is left in allocator
    /// memory (agent-vm #161 review, m2).
    pub(crate) fn try_parse(mut bytes: Vec<u8>) -> std::result::Result<Self, ValueRejection> {
        if !secret_value_is_acceptable_bytes(&bytes) {
            let rejection = value_rejection(&bytes).unwrap_or(ValueRejection::NonPrintable);
            bytes.zeroize();
            return Err(rejection);
        }
        match String::from_utf8(bytes) {
            Ok(value) => Ok(Self(Zeroizing::new(value))),
            // Unreachable: every byte that passes the predicate is printable
            // ASCII, hence valid UTF-8. The returned buffer is still wiped
            // rather than dropped un-zeroized.
            Err(error) => {
                let mut rejected = error.into_bytes();
                rejected.zeroize();
                Err(ValueRejection::NonPrintable)
            }
        }
    }

    /// Consume the value into the runtime's own resolver at handoff. This is
    /// the third and last audited path (write, phase-1 availability read, and
    /// this move into `microsandbox::CredentialResolver`), and it hands over
    /// the zeroizing buffer rather than a copy of its text.
    pub(crate) fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }

    /// The two audited paths from a stored value to a plain `&str`: a write
    /// into the platform credential store ([`SystemKeychain::set`]) and the
    /// launch resolver's read of a *previously authorized* value. Nothing else
    /// — not `secret ls`, not `doctor`, not any diagnostic — may call it.
    fn expose(&self) -> &str {
        &self.0
    }

    /// Test-only view of the stored bytes, so a test can assert acceptance
    /// without a credential store. Production has exactly two readers,
    /// [`Self::expose`].
    #[cfg(test)]
    pub(crate) fn expose_for_test(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// Why [`secret_value_is_acceptable_bytes`] rejected a value, for the message
/// only. Never carries any of the bytes.
///
/// `pub(crate)` because a *read* has to report "what is stored is not an
/// acceptable value" as a distinct outcome from "nothing is stored":
/// conflating the two would let a corrupt or truncated entry read as an
/// unconfigured credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueRejection {
    Empty,
    TooLong,
    EdgeSpace,
    NonPrintable,
}

impl ValueRejection {
    pub(crate) fn message(self) -> String {
        match self {
            Self::Empty => "no value was supplied".to_owned(),
            Self::TooLong => format!("the value is longer than {MAX_SECRET_VALUE_LEN} bytes"),
            Self::EdgeSpace => {
                "the value has a leading or trailing space; it was not stored".to_owned()
            }
            Self::NonPrintable => {
                "the value contains characters that are not printable ASCII; it was not stored"
                    .to_owned()
            }
        }
    }
}

/// The label-only classifier for a rejected value. `None` iff the verified
/// predicate accepts, which a test asserts over arbitrary byte strings.
fn value_rejection(bytes: &[u8]) -> Option<ValueRejection> {
    if bytes.is_empty() {
        return Some(ValueRejection::Empty);
    }
    if bytes.len() > MAX_SECRET_VALUE_LEN {
        return Some(ValueRejection::TooLong);
    }
    if bytes[0] == b' ' || bytes[bytes.len() - 1] == b' ' {
        return Some(ValueRejection::EdgeSpace);
    }
    if bytes.iter().any(|byte| !(b' ' <= *byte && *byte <= b'~')) {
        return Some(ValueRejection::NonPrintable);
    }
    None
}

/// Whether a value is in the credential store — the only value-shaped thing any
/// *diagnostic* operation here returns. (`SecretStore::resolve` also returns a
/// value, but only to an authorized launch; nothing that renders a listing,
/// `doctor`, or any error can reach a value.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    Present,
    Absent,
}

/// A **closed**, value-free classification of platform failures, and of the two
/// ways this process stops waiting for an answer.
///
/// `keyring::Error` is `#[non_exhaustive]`, derives `Debug`, and carries
/// `BadEncoding(Vec<u8>)` plus arbitrary boxed platform errors, so it must never
/// reach a message, a `source()` chain or a `tracing` field. The cost of
/// closing the mapping is a less specific message; the benefit is that no
/// future `keyring` variant can leak a value through agent-vm's stderr. A safe
/// platform detail (an OS status code) can be added later, one audited field at
/// a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeychainFailure {
    AccessDenied,
    Unavailable,
    Ambiguous,
    Rejected,
    /// The platform read outlived [`keychain_read_bound`] and was abandoned
    /// (#251). Distinct from [`Self::Ambiguous`] and [`Self::Rejected`] because
    /// the store never observed a result at all, and distinct from
    /// [`Self::Unavailable`] because the credential store may be perfectly
    /// reachable — it is this process that stopped waiting.
    Unresponsive,
    /// This process could not acquire the inventory lock within
    /// [`inventory_lock_wait`] (#291); no platform operation was started.
    /// In contrast, [`Self::Unresponsive`] means a platform read started but
    /// no read result was observed before this process stopped waiting.
    /// Polling does not identify a holder or prove continuous ownership.
    InventoryBusy,
    Unknown,
}

impl KeychainFailure {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::AccessDenied => {
                "the system keychain could not be accessed - it may be locked, or access was denied"
            }
            Self::Unavailable => {
                "the system keychain is unavailable (on Linux, a Secret Service such as \
                 gnome-keyring or KWallet must be running)"
            }
            Self::Ambiguous => {
                "more than one matching keychain item exists; remove the duplicates with \
                 Keychain Access / seahorse"
            }
            Self::Rejected => "the system keychain rejected the item",
            Self::Unresponsive => {
                "the system keychain did not respond before the read was abandoned - it may be \
                 waiting on a locked keychain or an unlock prompt; unlock the keychain and retry"
            }
            Self::InventoryBusy => {
                "could not acquire the secret inventory lock \
                 (~/.config/agent-vm/.secret-inventory.lock) within the wait; another process \
                 may be using it, possibly waiting on a keychain unlock prompt; unlock the \
                 keychain or let that command finish, and retry"
            }
            Self::Unknown => "the system keychain failed for an unrecognized reason",
        }
    }
}

/// The one boundary a `keyring::Error` crosses. The error value is **dropped**,
/// never stored as an `anyhow` source, never `Debug`-formatted, never logged.
///
/// `NoEntry` is not reachable here — the three callers turn it into
/// [`Presence::Absent`] before classifying — but it is matched explicitly rather
/// than left to the catch-all so a future `keyring` release that reshapes it
/// forces a look here.
fn classify(error: keyring::Error) -> KeychainFailure {
    match error {
        keyring::Error::NoStorageAccess(_) => KeychainFailure::AccessDenied,
        keyring::Error::PlatformFailure(_) => KeychainFailure::Unavailable,
        keyring::Error::Ambiguous(_) => KeychainFailure::Ambiguous,
        keyring::Error::TooLong(..)
        | keyring::Error::Invalid(..)
        | keyring::Error::BadEncoding(_) => KeychainFailure::Rejected,
        keyring::Error::NoEntry => KeychainFailure::Unknown,
        _ => KeychainFailure::Unknown,
    }
}

/// One `secret ls` row: a tracked name and what a probe found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SecretEntry {
    pub(crate) service: ServiceName,
    pub(crate) status: StorageStatus,
}

/// The storage status of a tracked name. `Missing` means the probe succeeded and
/// found nothing; `Unavailable` means the probe could not run. Conflating the
/// two is the most dangerous confusion this module can make, because "locked"
/// would then read as "not stored".
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StorageStatus {
    Stored,
    Missing,
    Unavailable(KeychainFailure),
}

/// The outcome of a removal, so the caller can distinguish "gone" from "there
/// was nothing to remove" without treating the second as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoveOutcome {
    Removed,
    NotStored,
}

/// Raw bytes as they came out of the platform store, **before** the
/// accepted-value predicate runs.
///
/// It exists so the read path can hand bytes across the `KeychainBackend` trait
/// without handing out a `Vec<u8>` a caller might print: there is no `Display`,
/// no `Deref`, and the `Debug` is redacting, and the bytes are zeroized on drop.
/// The only way to a usable value is [`Self::into_value`], which applies the
/// *same* predicate a write applies.
pub(crate) struct StoredSecret(Zeroizing<Vec<u8>>);

impl StoredSecret {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn into_value(self) -> std::result::Result<SecretValue, ValueRejection> {
        // `mem::take` leaves an empty Vec behind for `Zeroizing` to wipe, so the
        // bytes move into the (also zeroizing) `SecretValue` rather than being
        // copied.
        let mut inner = self.0;
        let bytes = std::mem::take(&mut *inner);
        SecretValue::try_parse(bytes)
    }
}

impl fmt::Debug for StoredSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredSecret(<redacted>)")
    }
}

/// The outcome of a read for one service. Four outcomes, not two, because the
/// caller's behaviour differs for each and every conflation is a failure mode:
/// `Missing` is "the probe worked and there is nothing there", `Unavailable`
/// is "the read could not run" (a locked keychain, no Secret Service), and
/// conflating those would let "locked" read as "not stored".
#[derive(Debug)]
pub(crate) enum Resolved {
    Value(SecretValue),
    Missing,
    Unavailable(KeychainFailure),
    /// A value *is* stored but its bytes fail the accepted-value predicate.
    /// Never `Missing`: silently treating a corrupt entry as absent would boot
    /// an uncredentialed sandbox that looks configured.
    InvalidValue(ValueRejection),
}

/// Everything the store needs from the platform credential store: four
/// methods and no logic. This is the untestable-in-CI surface, kept minimal.
pub(crate) trait KeychainBackend {
    fn set(&self, service: &ServiceName, value: &SecretValue) -> Result<(), KeychainFailure>;
    /// Presence only. No value crosses into agent-vm code.
    fn probe(&self, service: &ServiceName) -> Result<Presence, KeychainFailure>;
    fn delete(&self, service: &ServiceName) -> Result<Presence, KeychainFailure>;
    /// The one read path. Unreachable from any `agent-vm secret` verb: the
    /// only caller is [`SecretStore::resolve`], which itself is reachable only
    /// through launch resolution for an *authorized, requested* service
    /// (`credential_resolver.rs`). Nothing here may be wired into `ls`,
    /// `doctor`, or any diagnostic.
    fn get(&self, service: &ServiceName) -> Result<Option<StoredSecret>, KeychainFailure>;
    /// Whether this backend is the debug-only *test recording* seam, which stores
    /// nothing (only a length and SHA-256). The verb layer uses this to keep its
    /// success message honest when the seam is active (review finding R5).
    /// Production backends are `false`.
    fn is_test_recording(&self) -> bool {
        false
    }
}

/// The production backend: the host OS credential store through `keyring`.
pub(crate) struct SystemKeychain;

impl KeychainBackend for SystemKeychain {
    fn set(&self, service: &ServiceName, value: &SecretValue) -> Result<(), KeychainFailure> {
        entry(service)?
            .set_password(value.expose())
            .map_err(classify)
    }

    fn probe(&self, service: &ServiceName) -> Result<Presence, KeychainFailure> {
        // `get_attributes` is the presence probe on purpose: keyring's default
        // implementation calls `get_secret()` for effect and discards the bytes
        // inside the crate, and the Secret Service backend overrides it to query
        // attributes without fetching the secret at all. Either way no secret
        // byte crosses into agent-vm, and this returns an enum.
        match entry(service)?.get_attributes() {
            Ok(_) => Ok(Presence::Present),
            Err(keyring::Error::NoEntry) => Ok(Presence::Absent),
            Err(error) => Err(classify(error)),
        }
    }

    fn get(&self, service: &ServiceName) -> Result<Option<StoredSecret>, KeychainFailure> {
        // The only place agent-vm fetches a stored value. `get_secret` returns
        // the **raw bytes**; `get_password` would decode UTF-8 inside `keyring`
        // and surface invalid bytes as `BadEncoding`, which `classify` maps to
        // the non-fatal `Unavailable` class. Reading raw bytes instead routes a
        // malformed stored value through `StoredSecret`'s accepted-value
        // predicate, where it is `InvalidValue` - fatal regardless of
        // `required` (agent-vm #161 review, M3).
        read_stored_secret(entry(service)?.get_secret())
    }

    fn delete(&self, service: &ServiceName) -> Result<Presence, KeychainFailure> {
        match entry(service)?.delete_credential() {
            Ok(()) => Ok(Presence::Present),
            Err(keyring::Error::NoEntry) => Ok(Presence::Absent),
            Err(error) => Err(classify(error)),
        }
    }
}

/// The one place an entry is constructed. `entry_key` is pure so a test can
/// assert the `(service, account)` pair at this seam rather than only the
/// constant — that catches a future two-argument swap.
fn entry_key(service: &ServiceName) -> (&str, &str) {
    (KEYCHAIN_SERVICE, service.as_str())
}

fn entry(service: &ServiceName) -> Result<keyring::Entry, KeychainFailure> {
    let (service_name, account) = entry_key(service);
    keyring::Entry::new(service_name, account).map_err(classify)
}

/// The closed decision inside [`SystemKeychain::get`], split out so the
/// adapter boundary is testable without an OS keychain: raw bytes stay raw
/// (never decoded here, so invalid UTF-8 is not confused with an access
/// failure), `NoEntry` is absence, and every other failure is the closed
/// `Unavailable` class. The `keyring::Entry::get_secret` call that produces the
/// result is the trusted adapter; `keyring`'s own `mock` backend cannot model a
/// persistent store (it returns a fresh, independent credential per
/// `Entry::new`), so the raw read is not exercised against the OS store in CI.
fn read_stored_secret(
    read: std::result::Result<Vec<u8>, keyring::Error>,
) -> Result<Option<StoredSecret>, KeychainFailure> {
    match read {
        Ok(bytes) => Ok(Some(StoredSecret::new(bytes))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(classify(error)),
    }
}

/// How long a keychain **read** may take before the store abandons it (#251).
///
/// An *attended* process (stdin on a TTY: the launcher's own interactive signal,
/// see `run.rs`) may be sitting on a GUI unlock prompt the user is answering, so
/// it gets a long bound. An *unattended* one — a script, CI, a piped stdin — can
/// never answer a prompt, so it fails fast. Both are bounded: a healthy read is
/// a local call that takes microseconds, and no caller can distinguish slow from
/// wedged.
const KEYCHAIN_READ_BOUND_ATTENDED: Duration = Duration::from_secs(60);
const KEYCHAIN_READ_BOUND_UNATTENDED: Duration = Duration::from_secs(5);

/// The read bound for this process, chosen once at store construction.
fn keychain_read_bound() -> Duration {
    if std::io::stdin().is_terminal() {
        KEYCHAIN_READ_BOUND_ATTENDED
    } else {
        KEYCHAIN_READ_BOUND_UNATTENDED
    }
}

/// How long a verb waits for another process to release the inventory lock (#291).
///
/// The read bound, by design and not by coincidence: the holder this wait is
/// for may be parked on the same unlock prompt a read would be, and whether this
/// process's user can answer it is the question [`keychain_read_bound`] already
/// answers. Not longer: a longer wait would always outlast a holder's abandoned
/// read and then start a second one. See ADR-0024's #291 amendment.
fn inventory_lock_wait() -> Duration {
    keychain_read_bound()
}

/// The lock wait for tests that do not exercise contention: long enough that
/// healthy in-process contention (`concurrent_sets_do_not_lose_an_inventory_row`)
/// is expected to finish within it. Independent of the test runner's stdin mode;
/// not a fairness or scheduler guarantee.
#[cfg(test)]
pub(crate) const TEST_LOCK_WAIT: Duration = Duration::from_secs(5);

/// Bounds every **read** the wrapped backend serves (#251).
///
/// The platform read is a synchronous call into the OS credential store that can
/// block on an unlock prompt no layer above can answer (see the module docs).
/// Wrapping the backend — rather than timing out in `get`/`probe` — keeps the
/// bound out of reach of a caller that forgets it, and lets a test drive the
/// timeout with a backend that never answers, which the OS store cannot be made
/// to do in CI.
///
/// Writes pass straight through: see the module docs for why an abandoned
/// mutation is not a failure this store is allowed to report.
pub(crate) struct BoundedKeychainReads<B> {
    backend: Arc<B>,
    bound: Duration,
}

impl<B: KeychainBackend + Send + Sync + 'static> BoundedKeychainReads<B> {
    pub(crate) fn new(backend: B, bound: Duration) -> Self {
        Self {
            backend: Arc::new(backend),
            bound,
        }
    }

    /// Run `read` on its own thread and give up after the bound.
    ///
    /// The abandoned thread is deliberately not joined: the platform call cannot
    /// be cancelled, and waiting for it is the hang this exists to prevent. It
    /// holds none of this store's state — the inventory `flock` guard lives in
    /// the caller's frame — so abandoning it cannot wedge a later verb, and the
    /// value it eventually reads is dropped (and zeroized) on that thread when
    /// nothing is left to receive it.
    fn bounded<T: Send + 'static>(
        &self,
        read: impl FnOnce(&B) -> std::result::Result<T, KeychainFailure> + Send + 'static,
    ) -> std::result::Result<T, KeychainFailure> {
        let backend = Arc::clone(&self.backend);
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = tx.send(read(&backend));
        });
        match rx.recv_timeout(self.bound) {
            Ok(Ok(read)) => Ok(read),
            Ok(Err(failure)) => Err(failure),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(KeychainFailure::Unresponsive),
            // The reader thread panicked. That is a bug in agent-vm or in the
            // platform adapter, not a keychain state, and `Unknown` is where
            // this module already puts another thread's panic.
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(KeychainFailure::Unknown),
        }
    }
}

impl<B: KeychainBackend + Send + Sync + 'static> KeychainBackend for BoundedKeychainReads<B> {
    fn set(
        &self,
        service: &ServiceName,
        value: &SecretValue,
    ) -> std::result::Result<(), KeychainFailure> {
        self.backend.set(service, value)
    }

    fn probe(&self, service: &ServiceName) -> std::result::Result<Presence, KeychainFailure> {
        let service = service.clone();
        self.bounded(move |backend| backend.probe(&service))
    }

    fn get(
        &self,
        service: &ServiceName,
    ) -> std::result::Result<Option<StoredSecret>, KeychainFailure> {
        let service = service.clone();
        self.bounded(move |backend| backend.get(&service))
    }

    fn delete(&self, service: &ServiceName) -> std::result::Result<Presence, KeychainFailure> {
        self.backend.delete(service)
    }

    fn is_test_recording(&self) -> bool {
        self.backend.is_test_recording()
    }
}

/// The user-scoped inventory location. A directory plus two file names; kept as
/// one value so no caller can pair an inventory with a lock file from a
/// different scope.
#[derive(Debug, Clone)]
pub(crate) struct InventoryPaths {
    dir: PathBuf,
}

impl InventoryPaths {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn inventory_path(&self) -> PathBuf {
        self.dir.join(INVENTORY_FILE_NAME)
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE_NAME)
    }

    /// Create the config directory if it is absent. The mode is applied to a
    /// directory agent-vm creates; an *existing* directory is left as the user
    /// (or their umask) made it, because it may also hold #161's
    /// `credentials.yaml` and rewriting a user's `$HOME` layout is not this
    /// module's call. Nothing secret is at stake either way: the inventory file
    /// is always 0600 and the lock file carries nothing.
    fn ensure_dir(&self) -> Result<()> {
        let existed = self.dir.is_dir();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(CONFIG_DIR_MODE)
            .create(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        if !existed {
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(CONFIG_DIR_MODE))
                .with_context(|| format!("securing {}", self.dir.display()))?;
        }
        Ok(())
    }
}

/// Holds the exclusive `flock(2)` for as long as it is alive; the lock is
/// released when the file descriptor closes (or by the kernel on process death,
/// so a crashed process cannot wedge the store).
struct InventoryLock {
    _file: File,
}

/// Why [`SecretStore::lock`] returned without the lock. `Busy` is separate so
/// `resolve` can report it as its own closed class and the verbs can name the
/// lock; an I/O failure keeps its `anyhow` context.
enum LockRefusal {
    Busy,
    Failed(anyhow::Error),
}

/// The names-only inventory document, as written to disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct InventoryFile {
    version: u32,
    #[serde(default)]
    note: String,
    services: Vec<String>,
}

pub(crate) struct SecretStore<B: KeychainBackend> {
    backend: B,
    paths: InventoryPaths,
    /// Production shares the read bound; tests supply an explicit wait (#291).
    lock_wait: Duration,
    /// Test-only: when `Some`, the inventory write fails with this message. S16
    /// models "the delete succeeded, the listing write failed"; that cannot be
    /// provoked portably through the filesystem (a read-only directory is
    /// writable to root), so the fault is injected explicitly rather than
    /// faked with a permission trick that would silently pass as root. Every
    /// other failure in this module is the real one.
    #[cfg(test)]
    fail_inventory_write: Cell<Option<&'static str>>,
}

impl<B: KeychainBackend> SecretStore<B> {
    pub(crate) fn new(backend: B, paths: InventoryPaths, lock_wait: Duration) -> Self {
        Self {
            backend,
            paths,
            lock_wait,
            #[cfg(test)]
            fail_inventory_write: Cell::new(None),
        }
    }

    /// Whether the backend is the debug-only test recording seam, which stores
    /// nothing. The success message is qualified rather than lying when it is
    /// (review finding R5).
    pub(crate) fn is_test_recording(&self) -> bool {
        self.backend.is_test_recording()
    }

    /// Store or replace `value` for `service`.
    ///
    /// Inventory first, then the credential store, both under the lock (see the
    /// module docs for why that order and not the reverse). On a platform
    /// failure the name stays listed and the message says only that the value
    /// was not updated — **not** that nothing is stored, because a failed
    /// *replace* may leave the previous value in place.
    pub(crate) fn set(&self, service: &ServiceName, value: &SecretValue) -> Result<()> {
        let _lock = self.lock_for_verb()?;
        let mut names = self.load_inventory()?;
        if !names.contains(service) {
            names.insert(service.clone());
            self.write_inventory(&names)?;
        }
        self.backend
            .set(service, value)
            .map_err(|failure| anyhow!("the value was not updated: {}", failure.message()))
    }

    /// Every tracked name with its storage status, in name order.
    pub(crate) fn list(&self) -> Result<Vec<SecretEntry>> {
        let _lock = self.lock_for_verb()?;
        let names = self.load_inventory()?;
        let mut rows = Vec::with_capacity(names.len());
        for service in names {
            let status = match self.backend.probe(&service) {
                Ok(Presence::Present) => StorageStatus::Stored,
                Ok(Presence::Absent) => StorageStatus::Missing,
                Err(failure) => StorageStatus::Unavailable(failure),
            };
            rows.push(SecretEntry { service, status });
        }
        Ok(rows)
    }

    /// Remove the stored value for `service` and drop its inventory row.
    ///
    /// The re-probe after the delete is not paranoia: `keyring` 3.6.3's macOS
    /// backend calls `item.delete()` and returns `Ok(())` unconditionally, and
    /// `security-framework`'s `delete()` discards `SecKeychainItemDelete`'s
    /// status. Without the re-probe, `rm` could report a removal that did not
    /// happen *and* drop the row, leaving an invisible live credential. The
    /// extra probe costs one more keychain access; that is the right trade.
    pub(crate) fn remove(&self, service: &ServiceName) -> Result<RemoveOutcome> {
        let _lock = self.lock_for_verb()?;
        let mut names = self.load_inventory()?;
        let listed = names.contains(service);
        let deleted = self.backend.delete(service).map_err(|failure| {
            anyhow!("could not remove the stored value: {}", failure.message())
        })?;
        match self.backend.probe(service) {
            Ok(Presence::Absent) => {}
            Ok(Presence::Present) => {
                return Err(anyhow!(
                    "the keychain reported success but the entry is still present; the listing \
                     was left unchanged so the value stays discoverable"
                ));
            }
            Err(failure) => {
                return Err(anyhow!(
                    "could not confirm the removal: {}; the entry may still be present, so the \
                     listing was left unchanged",
                    failure.message()
                ));
            }
        }
        if listed {
            names.remove(service);
            self.write_inventory(&names).map_err(|error| {
                // Truthful about the half-done state: the value is gone, but
                // the listing was not updated, so `ls` may over-report. The
                // name is not interpolated: a failure diagnostic must not echo
                // a user-supplied identifier (review finding 3).
                anyhow!(
                    "removed the stored value, but failed to update {}: {error:#}",
                    self.paths.inventory_path().display()
                )
            })?;
        }
        // A name that drifted out of the inventory is still removable by name,
        // and a name that drifted in (listed, no value) is still removable.
        Ok(if listed || deleted == Presence::Present {
            RemoveOutcome::Removed
        } else {
            RemoveOutcome::NotStored
        })
    }

    /// The one authorized read: resolve `service` to its stored value.
    ///
    /// Reachable only from the launch credential resolver, and only for a
    /// service the *authorization file* names and the launch *requests*. It is
    /// deliberately not part of `list`/`doctor`: the value never leaves this
    /// module except through [`Self::resolve`].
    ///
    /// Runs under the same `flock` as the mutating verbs, so a resolution
    /// never races a `secret set`/`secret rm` on the same host. A failure to
    /// take the lock is reported as [`Resolved::Unavailable`]: from the
    /// caller's point of view the source "could not be read", which is the
    /// class that decides between warning and hard error. A peer that keeps the
    /// lock past the wait is [`KeychainFailure::InventoryBusy`]; other lock
    /// failures are `Unknown`.
    pub(crate) fn resolve(&self, service: &ServiceName) -> Resolved {
        let _lock = match self.lock() {
            Ok(lock) => lock,
            Err(LockRefusal::Busy) => return Resolved::Unavailable(KeychainFailure::InventoryBusy),
            Err(LockRefusal::Failed(_)) => return Resolved::Unavailable(KeychainFailure::Unknown),
        };
        match self.backend.get(service) {
            Ok(Some(stored)) => match stored.into_value() {
                Ok(value) => Resolved::Value(value),
                Err(rejection) => Resolved::InvalidValue(rejection),
            },
            Ok(None) => Resolved::Missing,
            Err(failure) => Resolved::Unavailable(failure),
        }
    }

    /// Take the exclusive inventory lock, creating the directory and lock file
    /// if needed, waiting at most `self.lock_wait` for a peer. Held until the
    /// returned guard is dropped. The `File` is dropped on every `Err`, so a
    /// waiter that gives up no longer has the lock file open.
    fn lock(&self) -> std::result::Result<InventoryLock, LockRefusal> {
        self.paths.ensure_dir().map_err(LockRefusal::Failed)?;
        let path = self.paths.lock_path();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(INVENTORY_FILE_MODE)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))
            .map_err(LockRefusal::Failed)?;
        match flock_exclusive_within(&file, self.lock_wait).map_err(LockRefusal::Failed)? {
            FlockWait::Acquired => Ok(InventoryLock { _file: file }),
            FlockWait::TimedOut => Err(LockRefusal::Busy),
        }
    }

    /// [`Self::lock`] for the verbs, which report through an `anyhow` chain.
    fn lock_for_verb(&self) -> Result<InventoryLock> {
        self.lock().map_err(|refusal| match refusal {
            LockRefusal::Busy => inventory_busy_error(&self.paths.lock_path(), self.lock_wait),
            LockRefusal::Failed(error) => error,
        })
    }

    /// The tracked names, or an empty set when the inventory file is absent
    /// (the normal state before the first `set`). A file that exists but cannot
    /// be read, parsed, or validated is a **hard error**: never a silent reset,
    /// never an unvalidated name, never a quoted byte.
    /// The tracked names, or an empty set when the inventory file is absent
    /// (the normal state before the first `set`). **Every other load failure
    /// names the path and the recovery**, so the one instruction the user needs
    /// is always present: a file that is unreadable, oversized, unparseable, of
    /// an unknown version, or carrying an invalid name. Never a silent reset,
    /// never an unvalidated name, never a quoted byte.
    fn load_inventory(&self) -> Result<BTreeSet<ServiceName>> {
        let path = self.paths.inventory_path();
        // Stat first, so "absent" is a fact rather than an inference from a
        // failed read, and so an oversized file gets the same recovery
        // instruction as a corrupt one instead of a bare size error.
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeSet::new());
            }
            Err(error) => {
                return Err(inventory_error(
                    &path,
                    &format!("could not be examined ({error})"),
                ));
            }
            Ok(metadata) if metadata.len() > MAX_INVENTORY_BYTES => {
                return Err(inventory_error(
                    &path,
                    &format!("is larger than {MAX_INVENTORY_BYTES} bytes"),
                ));
            }
            Ok(_) => {}
        }
        let bytes = read_bounded_regular_file(&path, MAX_INVENTORY_BYTES)
            .map_err(|error| inventory_error(&path, &format!("could not be read ({error:#})")))?;
        let file: InventoryFile = serde_json::from_slice(&bytes).map_err(|error| {
            // `serde_json::Error` is *not* value-free: a wrong JSON type carries
            // the offending string in its `Display` (`invalid type: string
            // "sk-…", expected u32`), so formatting it would print a value a
            // user pasted into the wrong field. Discard the `Display`/`source`
            // at this boundary — the same discipline `classify` applies to
            // `keyring::Error` — and keep only the numeric position, which is
            // safe because it is a line/column, never content.
            inventory_error(
                &path,
                &format!(
                    "is not valid JSON at line {} column {} (a schema or syntax error; the \
                     offending text is not shown)",
                    error.line(),
                    error.column()
                ),
            )
        })?;
        if file.version != INVENTORY_VERSION {
            return Err(inventory_error(
                &path,
                &format!(
                    "declares version {}, but this agent-vm understands only version \
                     {INVENTORY_VERSION}",
                    file.version
                ),
            ));
        }
        let mut names = BTreeSet::new();
        for raw in file.services {
            let name = ServiceName::parse(&raw).map_err(|_| {
                inventory_error(&path, "contains an entry that is not a valid service name")
            })?;
            // Duplicates collapse: the file records *which* names are tracked,
            // so a repeated row in a hand-edited file is the same fact twice,
            // not an error and not a second `ls` row.
            names.insert(name);
        }
        Ok(names)
    }

    fn write_inventory(&self, names: &BTreeSet<ServiceName>) -> Result<()> {
        #[cfg(test)]
        if let Some(message) = self.fail_inventory_write.get() {
            return Err(anyhow!("{message}"));
        }
        let file = InventoryFile {
            version: INVENTORY_VERSION,
            note: INVENTORY_NOTE.to_owned(),
            services: names.iter().map(|name| name.as_str().to_owned()).collect(),
        };
        let mut bytes =
            serde_json::to_vec_pretty(&file).context("serializing the secret inventory")?;
        bytes.push(b'\n');
        atomic_write(&self.paths.inventory_path(), &bytes, INVENTORY_FILE_MODE)
    }
}

/// Production construction: the user-scoped inventory paths and the host
/// credential store, with every read bounded (#251) and the inventory lock
/// wait bounded (#291).
///
/// Fails explicitly when `$HOME` is unusable, so no verb ever writes to a
/// relative or empty location.
pub(crate) fn system_store() -> Result<SecretStore<BoundedKeychainReads<SystemKeychain>>> {
    Ok(SecretStore::new(
        BoundedKeychainReads::new(SystemKeychain, keychain_read_bound()),
        inventory_paths()?,
        inventory_lock_wait(),
    ))
}

/// The user-scoped inventory paths, resolved through the shared `$HOME`
/// discipline. Shared by the production store and the debug-only test seam so
/// both honor the same location rules.
fn inventory_paths() -> Result<InventoryPaths> {
    let home = match config::host_home_dir() {
        Ok(Some(home)) => home,
        Ok(None) => {
            return Err(anyhow!(
                "$HOME is not set; cannot locate {}",
                config::quoted_str(crate::config::USER_CONFIG_DIR_RELATIVE)
            ));
        }
        Err(error) => {
            return Err(anyhow!(
                "{error}; cannot locate {}",
                config::quoted_str(crate::config::USER_CONFIG_DIR_RELATIVE)
            ));
        }
    };
    Ok(InventoryPaths::new(
        home.join(crate::config::USER_CONFIG_DIR_RELATIVE),
    ))
}

/// Debug-only credential-store fake used by the PTY integration tests.
///
/// When `AGENT_VM_TEST_SECRET_RECORD` names a path, `set` records only the
/// accepted value's **length and SHA-256** — never its bytes — to that file, so
/// `tests/secret_pty.rs` can assert the *exact* value the hidden reader
/// delivered without a real credential store (review finding N3). The inventory
/// paths still honor `$HOME`.
///
/// Gated on `any(test, debug_assertions)`: the `test` arm lets this type's unit
/// test compile and run under `--release` (where `debug_assertions` is off), and
/// `debug_assertions` is the arm [`test_recording_store`] exposes. `test` is
/// never set for a shipped binary, so a release binary still cannot be pointed
/// at a secret-recording backend.
#[cfg(any(test, debug_assertions))]
pub(crate) struct RecordingKeychain {
    path: PathBuf,
}

#[cfg(any(test, debug_assertions))]
impl KeychainBackend for RecordingKeychain {
    fn set(&self, _service: &ServiceName, value: &SecretValue) -> Result<(), KeychainFailure> {
        use sha2::{Digest as _, Sha256};
        use std::io::Write as _;
        let mut hasher = Sha256::new();
        hasher.update(value.expose().as_bytes());
        let line = format!("{} {:x}\n", value.expose().len(), hasher.finalize());
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(INVENTORY_FILE_MODE)
            .open(&self.path)
            .map_err(|_| KeychainFailure::Unavailable)?;
        file.write_all(line.as_bytes())
            .map_err(|_| KeychainFailure::Unavailable)
    }

    fn probe(&self, _service: &ServiceName) -> Result<Presence, KeychainFailure> {
        Ok(Presence::Absent)
    }

    /// **Not a value oracle.** This backend stores nothing (it writes a length
    /// and SHA-256), so it has nothing to return and must never become a way to
    /// read a value back out through the debug seam. `is_test_recording` stays
    /// honest alongside it.
    fn get(&self, _service: &ServiceName) -> Result<Option<StoredSecret>, KeychainFailure> {
        Ok(None)
    }

    fn delete(&self, _service: &ServiceName) -> Result<Presence, KeychainFailure> {
        Ok(Presence::Absent)
    }

    fn is_test_recording(&self) -> bool {
        true
    }
}

/// The debug-only test store, or `None` when the seam is not configured.
#[cfg(debug_assertions)]
pub(crate) fn test_recording_store() -> Result<Option<SecretStore<RecordingKeychain>>> {
    match std::env::var_os("AGENT_VM_TEST_SECRET_RECORD") {
        Some(path) if !path.is_empty() => Ok(Some(SecretStore::new(
            RecordingKeychain {
                path: PathBuf::from(path),
            },
            inventory_paths()?,
            inventory_lock_wait(),
        ))),
        _ => Ok(None),
    }
}

/// The verbs' contention error (#291). Names agent-vm's own lock file and the
/// wait, never a service name, and says nothing was changed: the lock is
/// acquired before any inventory/value mutation. Setup may create a directory
/// or lock file; "changed nothing" refers to inventory rows and secret values.
fn inventory_busy_error(path: &Path, waited: Duration) -> anyhow::Error {
    let path = path.display();
    anyhow!(
        "could not acquire the secret inventory lock {path} within {waited:?}; another process \
         may be using it, possibly waiting on a keychain unlock prompt. Unlock the keychain \
         or let that command finish, then retry; this command changed nothing. Use lsof to \
         inspect processes with this file open"
    )
}

/// Every inventory-load failure names the path (agent-vm's own) and the
/// recovery, and quotes no part of the file's contents.
fn inventory_error(path: &Path, reason: &str) -> anyhow::Error {
    anyhow!(
        "the secret inventory {} {reason}. {INVENTORY_RECOVERY}",
        path.display()
    )
}

#[cfg(test)]
pub(crate) mod fake {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    use super::{
        KeychainBackend, KeychainFailure, Presence, SecretValue, ServiceName, StoredSecret,
    };

    /// A stub for the three OS calls, **not** a mock of the logic under test:
    /// inventory handling, locking, drift repair, ordering, outcomes and
    /// rendering are all real code. `keyring`'s own `mock` backend is unusable
    /// here — it returns a fresh, independent credential per `Entry::new`, so it
    /// cannot model a store that remembers anything.
    #[derive(Default)]
    pub(crate) struct FakeKeychain {
        items: RefCell<BTreeMap<String, Vec<u8>>>,
        fail_set: Cell<Option<KeychainFailure>>,
        fail_probe: Cell<Option<KeychainFailure>>,
        fail_delete: Cell<Option<KeychainFailure>>,
        /// Models the macOS defect: `delete` returns `Ok` but the item survives.
        delete_is_a_lie: Cell<bool>,
    }

    impl FakeKeychain {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Put a value in the fake *without* an inventory row: the drift-out
        /// state S4/S5 exercise.
        pub(crate) fn seed(&self, service: &str, value: &str) {
            self.items
                .borrow_mut()
                .insert(service.to_owned(), value.as_bytes().to_vec());
        }

        /// Put **raw bytes** in the fake, including bytes a real `set` would
        /// have refused (e.g. invalid UTF-8). The read path must classify them
        /// through the accepted-value predicate, so a test can plant a
        /// malformed stored value the String-only `seed` cannot express.
        pub(crate) fn seed_bytes(&self, service: &str, bytes: Vec<u8>) {
            self.items.borrow_mut().insert(service.to_owned(), bytes);
        }

        pub(crate) fn stored(&self, service: &str) -> Option<String> {
            self.items
                .borrow()
                .get(service)
                .and_then(|bytes| String::from_utf8(bytes.clone()).ok())
        }

        pub(crate) fn fail_set(&self, failure: KeychainFailure) {
            self.fail_set.set(Some(failure));
        }

        pub(crate) fn fail_probe(&self, failure: KeychainFailure) {
            self.fail_probe.set(Some(failure));
        }

        pub(crate) fn fail_delete(&self, failure: KeychainFailure) {
            self.fail_delete.set(Some(failure));
        }

        pub(crate) fn delete_is_a_lie(&self) {
            self.delete_is_a_lie.set(true);
        }
    }

    impl KeychainBackend for FakeKeychain {
        fn set(&self, service: &ServiceName, value: &SecretValue) -> Result<(), KeychainFailure> {
            if let Some(failure) = self.fail_set.get() {
                return Err(failure);
            }
            self.items.borrow_mut().insert(
                service.as_str().to_owned(),
                value.expose().as_bytes().to_vec(),
            );
            Ok(())
        }

        fn probe(&self, service: &ServiceName) -> Result<Presence, KeychainFailure> {
            if let Some(failure) = self.fail_probe.get() {
                return Err(failure);
            }
            if self.items.borrow().contains_key(service.as_str()) {
                Ok(Presence::Present)
            } else {
                Ok(Presence::Absent)
            }
        }

        /// Raw bytes, deliberately **not** run through the value predicate:
        /// that the read path applies it is the property a test wants to
        /// exercise, so `seed`/`seed_bytes` can plant a value a real `set`
        /// would have refused.
        fn get(&self, service: &ServiceName) -> Result<Option<StoredSecret>, KeychainFailure> {
            if let Some(failure) = self.fail_probe.get() {
                return Err(failure);
            }
            Ok(self
                .items
                .borrow()
                .get(service.as_str())
                .map(|bytes| StoredSecret::new(bytes.clone())))
        }

        fn delete(&self, service: &ServiceName) -> Result<Presence, KeychainFailure> {
            if let Some(failure) = self.fail_delete.get() {
                return Err(failure);
            }
            if self.delete_is_a_lie.get() {
                return Ok(Presence::Present);
            }
            let removed = self.items.borrow_mut().remove(service.as_str());
            Ok(if removed.is_some() {
                Presence::Present
            } else {
                Presence::Absent
            })
        }
    }
}

/// Lets a test keep the fake and still hand the store an owned backend, so the
/// backend can be inspected after the store has run.
#[cfg(test)]
impl KeychainBackend for std::rc::Rc<fake::FakeKeychain> {
    fn set(&self, service: &ServiceName, value: &SecretValue) -> Result<(), KeychainFailure> {
        (**self).set(service, value)
    }

    fn probe(&self, service: &ServiceName) -> Result<Presence, KeychainFailure> {
        (**self).probe(service)
    }

    fn get(&self, service: &ServiceName) -> Result<Option<StoredSecret>, KeychainFailure> {
        (**self).get(service)
    }

    fn delete(&self, service: &ServiceName) -> Result<Presence, KeychainFailure> {
        (**self).delete(service)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::sync::{Arc, Barrier};
    use std::time::Instant;

    use proptest::prelude::*;
    use proptest::sample::Index;

    use super::fake::FakeKeychain;
    use super::*;
    use crate::test_env;

    fn name(raw: &str) -> ServiceName {
        ServiceName::parse(raw).expect("test name is valid")
    }

    fn value(raw: &str) -> SecretValue {
        SecretValue::parse(raw.as_bytes().to_vec()).expect("test value is acceptable")
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A temp config directory plus a fake backend, so a test can inspect the
    /// backend and the inventory it left behind after the store has moved on.
    struct Harness {
        dir: tempfile::TempDir,
        backend: Rc<FakeKeychain>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                backend: Rc::new(FakeKeychain::new()),
            }
        }

        fn paths(&self) -> InventoryPaths {
            InventoryPaths::new(self.dir.path().to_path_buf())
        }

        fn store(&self) -> SecretStore<Rc<FakeKeychain>> {
            SecretStore::new(Rc::clone(&self.backend), self.paths(), TEST_LOCK_WAIT)
        }

        fn inventory(&self) -> PathBuf {
            self.dir.path().join(INVENTORY_FILE_NAME)
        }

        fn write_inventory(&self, body: &str) {
            std::fs::write(self.inventory(), body).unwrap();
        }
    }

    fn contains_substring_of_len(haystack: &str, needle: &str, len: usize) -> bool {
        needle.as_bytes().windows(len).any(|window| {
            let window = std::str::from_utf8(window).expect("the needle is ASCII");
            haystack.contains(window)
        })
    }

    /// One leak check used by every test that has a value in play, so a leak
    /// shows up as a failure wherever it happens rather than only where the
    /// test author remembered to look.
    fn assert_no_leak(text: &str, needle: &str) {
        assert!(!text.contains(needle), "the whole value leaked: {text}");
        assert!(
            !contains_substring_of_len(text, needle, 4),
            "a 4+ character substring of the value leaked: {text}"
        );
    }

    // -- S13: the namespace seam -----------------------------------------

    #[test]
    fn the_keychain_namespace_is_agent_vms_own() {
        let service = name("anthropic");
        let (keychain_service, account) = entry_key(&service);
        assert_eq!(keychain_service, "dev.agent-vm.credentials");
        assert_eq!(account, "anthropic");
        // A rename onto a neighbour's namespace would address another tool's
        // entries, so both neighbour names are asserted explicitly.
        for foreign in ["com.docker.sandboxes", "dev.microsandbox.registry"] {
            assert_ne!(keychain_service, foreign);
        }
    }

    // -- S1/S2/S3: set, replace, and the write-ordering invariant --------

    #[test]
    fn set_lists_one_stored_row() {
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value("first")).unwrap();
        assert_eq!(
            store.list().unwrap(),
            vec![SecretEntry {
                service: name("anthropic"),
                status: StorageStatus::Stored,
            }]
        );
        assert_eq!(
            harness.backend.stored("anthropic").as_deref(),
            Some("first")
        );
    }

    #[test]
    fn set_twice_replaces_the_value_without_adding_a_row() {
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value("first")).unwrap();
        store.set(&name("anthropic"), &value("second")).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        assert_eq!(
            harness.backend.stored("anthropic").as_deref(),
            Some("second")
        );
    }

    #[test]
    fn a_failed_set_still_lists_the_name_and_never_claims_nothing_is_stored() {
        let harness = Harness::new();
        harness.backend.fail_set(KeychainFailure::AccessDenied);
        let store = harness.store();
        let error = store
            .set(&name("anthropic"), &value("sk-REAL"))
            .expect_err("the backend failed");
        let text = format!("{error:#}");
        assert!(text.contains("the value was not updated"), "{text}");
        // A failed *replace* may leave the previous value behind, so the
        // message must never assert the keychain is empty.
        assert!(!text.contains("nothing is stored"), "{text}");
        assert!(
            text.contains(KeychainFailure::AccessDenied.message()),
            "{text}"
        );

        let rows = store.list().unwrap();
        assert_eq!(rows.len(), 1, "the name must stay listed: {rows:?}");
        assert_eq!(rows[0].status, StorageStatus::Missing);
    }

    // -- S4/S5/S6/S7/S11: removal and drift -------------------------------

    #[test]
    fn rm_repairs_a_name_that_drifted_out_of_the_inventory() {
        let harness = Harness::new();
        harness.backend.seed("anthropic", "sk-REAL");
        let store = harness.store();
        assert_eq!(
            store.remove(&name("anthropic")).unwrap(),
            RemoveOutcome::Removed
        );
        assert_eq!(harness.backend.stored("anthropic"), None);
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn a_listed_name_with_no_value_reads_missing_and_is_still_removable() {
        let harness = Harness::new();
        harness.write_inventory(r#"{"version":1,"note":"","services":["anthropic"]}"#);
        let store = harness.store();
        let rows = store.list().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].status,
            StorageStatus::Missing,
            "a Stored row here would be a lie"
        );
        assert_eq!(
            store.remove(&name("anthropic")).unwrap(),
            RemoveOutcome::Removed
        );
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn rm_of_an_untracked_value_reports_not_stored() {
        let harness = Harness::new();
        let store = harness.store();
        assert_eq!(
            store.remove(&name("anthropic")).unwrap(),
            RemoveOutcome::NotStored
        );
    }

    /// Finding 3 — no `remove` failure path interpolates the identifier, in
    /// either the typed or the case-folded spelling.
    #[test]
    fn remove_failures_do_not_echo_the_service_name() {
        let typed = "Sk-Ant-API03-AbCdEf";
        let canonical = typed.to_ascii_lowercase();
        let assert_clean = |error: &anyhow::Error| {
            let text = format!("{error:#}");
            assert!(!text.contains(typed), "the typed name was echoed: {text}");
            assert!(
                !text.contains(&canonical),
                "the canonical name was echoed: {text}"
            );
        };

        // The post-delete re-probe fails.
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name(typed), &value("sk-REAL")).unwrap();
        harness.backend.fail_probe(KeychainFailure::Unavailable);
        assert_clean(&store.remove(&name(typed)).expect_err("probe failed"));

        // Delete reports success but the entry survives.
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name(typed), &value("sk-REAL")).unwrap();
        harness.backend.delete_is_a_lie();
        assert_clean(&store.remove(&name(typed)).expect_err("delete lied"));

        // The value is removed but the listing write fails.
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name(typed), &value("sk-REAL")).unwrap();
        store
            .fail_inventory_write
            .set(Some("injected listing failure"));
        assert_clean(
            &store
                .remove(&name(typed))
                .expect_err("listing write failed"),
        );
    }

    #[test]
    fn a_failed_delete_leaves_the_inventory_untouched() {
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value("sk-REAL")).unwrap();
        harness.backend.fail_delete(KeychainFailure::Unavailable);
        let error = store
            .remove(&name("anthropic"))
            .expect_err("the backend failed");
        let text = format!("{error:#}");
        assert!(text.contains("could not remove the stored value"), "{text}");
        let rows = store.list().unwrap();
        assert_eq!(rows.len(), 1, "a surviving value must stay discoverable");
        assert_eq!(rows[0].status, StorageStatus::Stored);
    }

    #[test]
    fn rm_removes_exactly_the_selected_entry() {
        let harness = Harness::new();
        let store = harness.store();
        for service in ["anthropic", "openai", "azure"] {
            store.set(&name(service), &value("sk-REAL")).unwrap();
        }
        assert_eq!(
            store.remove(&name("openai")).unwrap(),
            RemoveOutcome::Removed
        );
        let rows = store.list().unwrap();
        let kept: Vec<&str> = rows.iter().map(|row| row.service.as_str()).collect();
        assert_eq!(kept, ["anthropic", "azure"]);
        assert_eq!(harness.backend.stored("openai"), None);
        assert_eq!(
            harness.backend.stored("anthropic").as_deref(),
            Some("sk-REAL")
        );
        assert_eq!(harness.backend.stored("azure").as_deref(), Some("sk-REAL"));
    }

    // -- S8/S15/S16: probe failure, a lying delete, a failed listing write --

    #[test]
    fn a_probe_failure_is_unavailable_never_missing() {
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value("sk-REAL")).unwrap();
        harness.backend.fail_probe(KeychainFailure::AccessDenied);
        let rows = store.list().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].status,
            StorageStatus::Unavailable(KeychainFailure::AccessDenied),
            "a locked keychain must never read as 'not stored'"
        );
    }

    #[test]
    fn a_delete_that_lies_keeps_the_row_and_fails() {
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value("sk-REAL")).unwrap();
        harness.backend.delete_is_a_lie();
        let error = store
            .remove(&name("anthropic"))
            .expect_err("the re-probe must catch the lie");
        let text = format!("{error:#}");
        assert!(text.contains("reported success but the entry"), "{text}");
        let rows = store.list().unwrap();
        assert_eq!(rows.len(), 1, "the row must be kept: {rows:?}");
        assert_eq!(rows[0].status, StorageStatus::Stored);
        assert_eq!(
            harness.backend.stored("anthropic").as_deref(),
            Some("sk-REAL")
        );
    }

    #[test]
    fn a_delete_that_succeeds_with_a_failed_listing_write_is_reported_truthfully() {
        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value("sk-REAL")).unwrap();
        store
            .fail_inventory_write
            .set(Some("injected listing failure"));
        let error = store
            .remove(&name("anthropic"))
            .expect_err("the listing write failed");
        let text = format!("{error:#}");
        assert!(text.contains("removed the stored value"), "{text}");
        assert!(text.contains("failed to update"), "{text}");
        assert!(text.contains("secret-inventory.json"), "{text}");
        assert!(text.contains("injected listing failure"), "{text}");
        // The value really is gone; the listing over-reports, which is the
        // truthful direction and is repairable by re-running the verb.
        assert_eq!(harness.backend.stored("anthropic"), None);
        let rows = harness.store().list().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, StorageStatus::Missing);
    }

    // -- S9/S10: a corrupt inventory, and no plaintext fallback ------------

    #[test]
    fn a_corrupt_inventory_is_a_hard_error_on_every_verb_and_quotes_no_bytes() {
        // A distinctive string placed in the *wrong* JSON field: `serde_json`'s
        // `Display` embeds such a string (`invalid type: string "sk-…",
        // expected u32`), so these are the fixtures that prove the boundary
        // discards it rather than the earlier syntax-only ones (review finding
        // 2). `assert_no_leak` also forbids a 4+ character fragment.
        const NEEDLE: &str = "sk-Q7XZPLMN-4w9t-AbCdEf";
        let fixtures = [
            "{ this is not json".to_owned(),
            r#"{"version":2,"note":"","services":[]}"#.to_owned(),
            r#"{"version":1,"note":"","services":["Bad Name"]}"#.to_owned(),
            // Wrong type in `version` (a string where u32 is expected).
            format!(r#"{{"version":"{NEEDLE}","services":[]}}"#),
            // Wrong type in `services` (a string where a sequence is expected).
            format!(r#"{{"version":1,"services":"{NEEDLE}"}}"#),
            // Wrong type inside an element of `services`.
            format!(r#"{{"version":1,"services":[{{"value":"{NEEDLE}"}}]}}"#),
            // Wrong type in the optional `note` field.
            format!(r#"{{"version":1,"note":{{"value":"{NEEDLE}"}},"services":[]}}"#),
        ];
        for fixture in fixtures {
            let harness = Harness::new();
            harness.write_inventory(&fixture);
            let store = harness.store();
            let errors = [
                store
                    .set(&name("anthropic"), &value("sk-REAL"))
                    .expect_err("set must fail"),
                store.list().expect_err("list must fail"),
                store
                    .remove(&name("anthropic"))
                    .expect_err("remove must fail"),
            ];
            for error in errors {
                let text = format!("{error:#}");
                assert!(
                    text.contains(&harness.inventory().display().to_string()),
                    "the error must name the path: {text}"
                );
                assert!(
                    text.contains("delete this file to reset the listing"),
                    "the error must state the recovery: {text}"
                );
                assert!(
                    !text.contains("Bad Name"),
                    "the file content leaked: {text}"
                );
                assert_no_leak(&text, NEEDLE);
            }
        }
    }

    #[test]
    fn an_oversized_or_unreadable_inventory_states_the_path_and_the_recovery() {
        // Oversized: its own check fires, and it carries the *same* recovery as
        // a corrupt file rather than a bare size error.
        let harness = Harness::new();
        std::fs::write(
            harness.inventory(),
            "x".repeat((MAX_INVENTORY_BYTES + 1) as usize),
        )
        .unwrap();
        let store = harness.store();
        for error in [
            store.list().expect_err("list must fail"),
            store
                .set(&name("anthropic"), &value("sk-REAL"))
                .expect_err("set must fail"),
            store
                .remove(&name("anthropic"))
                .expect_err("remove must fail"),
        ] {
            let text = format!("{error:#}");
            assert!(text.contains("larger than"), "{text}");
            assert!(
                text.contains(&harness.inventory().display().to_string()),
                "{text}"
            );
            assert!(
                text.contains("delete this file to reset the listing"),
                "{text}"
            );
        }

        // A directory where the file belongs is not a readable inventory, and
        // gets the same instruction rather than a bare I/O error.
        let harness = Harness::new();
        std::fs::create_dir(harness.inventory()).unwrap();
        let store = harness.store();
        let text = format!("{:#}", store.list().expect_err("list must fail"));
        assert!(text.contains("could not be read"), "{text}");
        assert!(
            text.contains("delete this file to reset the listing"),
            "{text}"
        );
    }

    // -- S17: the one authorized read ------------------------------------

    /// The read path applies the *same* predicate a write does. A stored value
    /// that violates it is `InvalidValue`, never `Missing`: a corrupt or
    /// truncated entry must not silently read as an unconfigured credential.
    #[test]
    fn get_validates_reads_with_the_write_predicate() {
        let harness = Harness::new();
        let service = name("alpha");
        // `seed` writes straight into the fake, so it can plant bytes a real
        // `set` would have refused — which is exactly the corrupt-entry case.
        harness.backend.seed("alpha", "has a  newline\n");
        let store = harness.store();
        match store.resolve(&service) {
            Resolved::InvalidValue(rejection) => {
                assert_eq!(rejection, ValueRejection::NonPrintable)
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }

        // The accepted shapes still come back, and byte for byte.
        for acceptable in ["sk-REAL", "a", &"x".repeat(MAX_SECRET_VALUE_LEN)] {
            harness.backend.seed("alpha", acceptable);
            match store.resolve(&service) {
                Resolved::Value(resolved) => assert_eq!(resolved.expose_for_test(), acceptable),
                other => panic!("expected Value, got {other:?}"),
            }
        }

        // Too long, an edge space and empty are the other three labels.
        for (raw, expected) in [
            (
                "x".repeat(MAX_SECRET_VALUE_LEN + 1),
                ValueRejection::TooLong,
            ),
            (" sk".to_owned(), ValueRejection::EdgeSpace),
            (String::new(), ValueRejection::Empty),
        ] {
            harness.backend.seed("alpha", &raw);
            match store.resolve(&service) {
                Resolved::InvalidValue(rejection) => assert_eq!(rejection, expected),
                other => panic!("expected InvalidValue({expected:?}), got {other:?}"),
            }
        }

        // A value that is not a printable-ASCII string at all is not `Missing`
        // and its bytes never reach a rendering.
        harness.backend.seed("alpha", "\u{7f}");
        let rendered = format!("{:?}", store.resolve(&service));
        assert!(rendered.contains("InvalidValue"), "{rendered}");
        assert!(
            !rendered.contains("\u{7f}"),
            "the stored bytes leaked: {rendered}"
        );
    }

    /// A stored value that is not valid UTF-8 must be `InvalidValue`, never the
    /// non-fatal `Unavailable` class. `get_secret` (raw bytes) makes this
    /// distinguishable from a locked/absent keychain; `get_password` would have
    /// surfaced it as `BadEncoding` -> `Unavailable` (agent-vm #161 review, M3).
    #[test]
    fn invalid_utf8_stored_bytes_are_an_invalid_value_not_unavailable() {
        let harness = Harness::new();
        let service = name("alpha");
        harness.backend.seed_bytes("alpha", vec![0xff, 0xfe, b'x']);
        match harness.store().resolve(&service) {
            Resolved::InvalidValue(rejection) => {
                assert_eq!(rejection, ValueRejection::NonPrintable)
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
        // An access failure is still `Unavailable`, so the two outcomes remain
        // distinguishable at the adapter boundary.
        harness.backend.fail_probe(KeychainFailure::AccessDenied);
        match harness.store().resolve(&service) {
            Resolved::Unavailable(KeychainFailure::AccessDenied) => {}
            other => panic!("expected Unavailable(AccessDenied), got {other:?}"),
        }
    }

    /// The adapter boundary: raw bytes (including invalid UTF-8) stay raw and
    /// are classified by the accepted-value predicate, an access failure is the
    /// closed `Unavailable` class, and `NoEntry` is absence. This is the
    /// decision `SystemKeychain::get` makes around the trusted `get_secret`
    /// call (agent-vm #161 review, M3).
    #[test]
    fn read_stored_secret_keeps_raw_bytes_and_distinguishes_access_failure() {
        // Invalid UTF-8 arrives as raw bytes and becomes `InvalidValue`, not a
        // decode failure routed to `Unavailable`.
        let stored = read_stored_secret(Ok(vec![0xff, 0xfe, b'x']))
            .expect("a raw read succeeds")
            .expect("a value is present");
        assert_eq!(
            stored.into_value().unwrap_err(),
            ValueRejection::NonPrintable
        );
        // `NoEntry` is "nothing is stored", not a failure.
        assert!(
            read_stored_secret(Err(keyring::Error::NoEntry))
                .expect("absence is not a failure")
                .is_none()
        );
        // An access failure is the closed class, distinguishable from the above.
        let denied = read_stored_secret(Err(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("os detail"),
        ))))
        .unwrap_err();
        assert_eq!(denied, KeychainFailure::AccessDenied);
    }

    /// "Locked" must never read as "not stored".
    #[test]
    fn resolve_separates_missing_from_unavailable() {
        let harness = Harness::new();
        let store = harness.store();
        let service = name("alpha");
        assert!(matches!(store.resolve(&service), Resolved::Missing));

        harness.backend.fail_probe(KeychainFailure::AccessDenied);
        match store.resolve(&service) {
            Resolved::Unavailable(failure) => assert_eq!(failure, KeychainFailure::AccessDenied),
            other => panic!("expected Unavailable, got {other:?}"),
        }
        // The closed message says "locked or denied", never "not stored".
        assert!(KeychainFailure::AccessDenied.message().contains("locked"));

        // A backend with nothing to say still cannot be mistaken for absent
        // while it is failing.
        harness.backend.seed("alpha", "sk-REAL");
        harness.backend.fail_probe(KeychainFailure::Unavailable);
        assert!(matches!(
            store.resolve(&service),
            Resolved::Unavailable(KeychainFailure::Unavailable)
        ));
    }

    // -- agent-vm #251: a read that never returns is abandoned ---------------

    /// A `Send + Sync` backend with one value and a chosen read delay.
    /// [`DelayedKeychain::never`] models the platform call that blocks on a
    /// locked keychain's unlock prompt; it exists because `fake::FakeKeychain`
    /// cannot serve here — its fault-injection cells are deliberately `!Sync`,
    /// and a bounded read runs on another thread.
    struct DelayedKeychain {
        value: Vec<u8>,
        read_delay: Option<Duration>,
    }

    impl DelayedKeychain {
        fn never() -> Self {
            Self {
                value: b"sk-REAL".to_vec(),
                read_delay: None,
            }
        }

        fn immediately() -> Self {
            Self {
                value: b"sk-REAL".to_vec(),
                read_delay: Some(Duration::ZERO),
            }
        }

        fn read_delay(&self) {
            match self.read_delay {
                Some(delay) => std::thread::sleep(delay),
                None => loop {
                    std::thread::sleep(Duration::from_secs(3600));
                },
            }
        }
    }

    impl KeychainBackend for DelayedKeychain {
        fn set(&self, _: &ServiceName, _: &SecretValue) -> Result<(), KeychainFailure> {
            Ok(())
        }

        fn probe(&self, _: &ServiceName) -> Result<Presence, KeychainFailure> {
            self.read_delay();
            Ok(Presence::Present)
        }

        fn get(&self, _: &ServiceName) -> Result<Option<StoredSecret>, KeychainFailure> {
            self.read_delay();
            Ok(Some(StoredSecret::new(self.value.clone())))
        }

        fn delete(&self, _: &ServiceName) -> Result<Presence, KeychainFailure> {
            Ok(Presence::Absent)
        }
    }

    /// A store with the production read bound over `backend`, and the temp dir
    /// the store's inventory lives in.
    fn bounded_store(
        backend: DelayedKeychain,
        bound: Duration,
    ) -> (
        tempfile::TempDir,
        SecretStore<BoundedKeychainReads<DelayedKeychain>>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::new(
            BoundedKeychainReads::new(backend, bound),
            InventoryPaths::new(dir.path().to_path_buf()),
            TEST_LOCK_WAIT,
        );
        (dir, store)
    }

    /// The type is the assertion for the production wiring: if `system_store`
    /// goes back to returning the bare `SystemKeychain`, the bound silently
    /// stops applying to every verb and every launch, and this stops compiling.
    /// A runtime assertion is not available — CI cannot make the OS store block.
    #[test]
    fn the_production_store_is_wired_to_bounded_reads() {
        let _pin: fn() -> Result<SecretStore<BoundedKeychainReads<SystemKeychain>>> = system_store;
    }

    /// `store.resolve(&name("alpha"))`, run on its own thread so a regression
    /// to an unbounded read fails this test rather than stalling the suite. The
    /// store comes back with the outcome, so a caller can keep using it.
    fn resolve_within_deadline<B: KeychainBackend + Send + 'static>(
        store: SecretStore<B>,
    ) -> (SecretStore<B>, Resolved) {
        within_deadline("the keychain read", move || {
            let resolved = store.resolve(&name("alpha"));
            (store, resolved)
        })
    }

    /// A regression fails finitely rather than joining a stuck worker.
    fn within_deadline<T: Send + 'static>(
        what: &'static str,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(work());
        });
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(value) => value,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("{what} was not bounded: no result after 30s")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("{what} worker disconnected or panicked before returning a result")
            }
        }
    }
    // -- agent-vm #291: a bounded waiter, never an abandoned writer --------

    const SHORT: Duration = Duration::from_millis(200);
    const SHORT_UPPER: Duration = Duration::from_secs(2);

    fn assert_short(elapsed: Duration) {
        assert!(
            SHORT <= elapsed && elapsed < SHORT_UPPER,
            "elapsed: {elapsed:?}"
        );
    }

    fn hold_inventory_lock(dir: &Path) -> File {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(INVENTORY_FILE_MODE)
            .open(dir.join(LOCK_FILE_NAME))
            .unwrap();
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        file
    }

    #[test]
    fn every_verb_gives_up_on_a_held_inventory_lock() {
        let dir = tempfile::tempdir().unwrap();
        let _holder = hold_inventory_lock(dir.path());
        let store = SecretStore::new(
            FakeKeychain::new(),
            InventoryPaths::new(dir.path().to_path_buf()),
            SHORT,
        );
        within_deadline("all inventory verbs", move || {
            for verb in 0..3 {
                let started = Instant::now();
                let error = match verb {
                    0 => store.set(&name("alpha"), &value("v")).unwrap_err(),
                    1 => store.list().unwrap_err(),
                    _ => store.remove(&name("alpha")).unwrap_err(),
                };
                assert_short(started.elapsed());
                let text = format!("{error:#}");
                for expected in [
                    "could not acquire the secret inventory lock",
                    "200ms",
                    "changed nothing",
                ] {
                    assert!(text.contains(expected), "{text}");
                }
                assert!(
                    text.contains(&store.paths.lock_path().display().to_string()),
                    "{text}"
                );
                assert!(!text.contains("alpha"), "{text}");
            }
            let started = Instant::now();
            assert!(matches!(
                store.resolve(&name("alpha")),
                Resolved::Unavailable(KeychainFailure::InventoryBusy)
            ));
            assert_short(started.elapsed());
        });
    }

    #[test]
    fn a_set_that_gives_up_on_the_lock_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let _holder = hold_inventory_lock(dir.path());
        let store = SecretStore::new(
            FakeKeychain::new(),
            InventoryPaths::new(dir.path().to_path_buf()),
            SHORT,
        );
        let store = within_deadline("refused set", move || {
            let started = Instant::now();
            assert!(store.set(&name("alpha"), &value("v")).is_err());
            assert_short(started.elapsed());
            store
        });
        assert_eq!(store.backend.stored("alpha"), None);
        assert!(!dir.path().join(INVENTORY_FILE_NAME).exists());
    }

    #[test]
    fn a_lock_released_during_the_wait_lets_the_verb_proceed() {
        let dir = tempfile::tempdir().unwrap();
        let holder = hold_inventory_lock(dir.path());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(holder);
            let _ = tx.send(());
        });
        let store = SecretStore::new(
            FakeKeychain::new(),
            InventoryPaths::new(dir.path().to_path_buf()),
            TEST_LOCK_WAIT,
        );
        let store = within_deadline("released set", move || {
            store.set(&name("alpha"), &value("v")).unwrap();
            assert_eq!(store.backend.stored("alpha").as_deref(), Some("v"));
            store
        });
        rx.recv_timeout(Duration::from_secs(30)).unwrap();
        within_deadline("released listing", move || {
            let rows = store.list().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].service.as_str(), "alpha");
        });
    }

    /// A gate models a writer parked on a platform prompt. A disconnected gate
    /// fails without committing, so test failure does not strand the holder.
    struct GatedKeychain {
        entered: mpsc::SyncSender<()>,
        gate: std::sync::Mutex<mpsc::Receiver<()>>,
        committed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl KeychainBackend for GatedKeychain {
        fn set(&self, _: &ServiceName, _: &SecretValue) -> Result<(), KeychainFailure> {
            self.entered
                .send(())
                .map_err(|_| KeychainFailure::Unknown)?;
            self.gate
                .lock()
                .unwrap()
                .recv()
                .map_err(|_| KeychainFailure::Unknown)?;
            self.committed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn probe(&self, _: &ServiceName) -> Result<Presence, KeychainFailure> {
            Ok(Presence::Present)
        }
        fn get(&self, _: &ServiceName) -> Result<Option<StoredSecret>, KeychainFailure> {
            Ok(Some(StoredSecret::new(b"sk-REAL".to_vec())))
        }
        fn delete(&self, _: &ServiceName) -> Result<Presence, KeychainFailure> {
            Ok(Presence::Absent)
        }
    }

    #[test]
    fn a_write_holding_the_lock_is_not_abandoned_while_a_waiter_gives_up() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let paths = InventoryPaths::new(dir.path().to_path_buf());
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (gate_tx, gate_rx) = mpsc::channel();
        let committed = Arc::new(AtomicBool::new(false));
        let gated = GatedKeychain {
            entered: entered_tx,
            gate: std::sync::Mutex::new(gate_rx),
            committed: Arc::clone(&committed),
        };
        let holder = SecretStore::new(
            BoundedKeychainReads::new(gated, Duration::from_millis(100)),
            paths.clone(),
            TEST_LOCK_WAIT,
        );
        let (holder_tx, holder_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = holder_tx.send(holder.set(&name("alpha"), &value("v")));
        });
        entered_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        let waiter = SecretStore::new(FakeKeychain::new(), paths.clone(), SHORT);
        within_deadline("waiter behind writer", move || {
            let started = Instant::now();
            let error = waiter.set(&name("beta"), &value("v")).unwrap_err();
            assert!(format!("{error:#}").contains("secret inventory lock"));
            assert_short(started.elapsed());
            let started = Instant::now();
            assert!(matches!(
                waiter.resolve(&name("beta")),
                Resolved::Unavailable(KeychainFailure::InventoryBusy)
            ));
            assert_short(started.elapsed());
        });
        assert!(
            matches!(holder_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "holder's write was abandoned"
        );
        gate_tx.send(()).unwrap();
        holder_rx
            .recv_timeout(Duration::from_secs(30))
            .unwrap()
            .unwrap();
        assert!(committed.load(Ordering::SeqCst));
        within_deadline("listing after writer", move || {
            let store = SecretStore::new(FakeKeychain::new(), paths, TEST_LOCK_WAIT);
            let rows = store.list().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].service.as_str(), "alpha");
        });
    }

    #[test]
    fn the_busy_message_names_the_real_lock_path() {
        assert!(KeychainFailure::InventoryBusy.message().contains(&format!(
            "~/{}/{}",
            config::USER_CONFIG_DIR_RELATIVE,
            LOCK_FILE_NAME
        )));
    }

    /// The platform read cannot be cancelled, so the store abandons it and
    /// reports the closed `Unresponsive` class instead of waiting forever.
    #[test]
    fn a_read_that_outlives_the_bound_is_abandoned_and_reported() {
        let (_dir, store) = bounded_store(DelayedKeychain::never(), Duration::from_millis(200));
        let (_, resolved) = resolve_within_deadline(store);
        assert!(
            matches!(
                resolved,
                Resolved::Unavailable(KeychainFailure::Unresponsive)
            ),
            "expected Unavailable(Unresponsive), got {resolved:?}"
        );
    }

    /// Abandoning the read must release the inventory lock: the reported hang
    /// held `~/.config/agent-vm/.secret-inventory.lock` for as long as the
    /// platform call blocked, which wedged every other agent-vm process. `set`
    /// takes that same `flock`, so it returning is the lock being free.
    #[test]
    fn an_abandoned_read_releases_the_inventory_lock() {
        let (_dir, store) = bounded_store(DelayedKeychain::never(), Duration::from_millis(200));
        let (store, resolved) = resolve_within_deadline(store);
        assert!(matches!(
            resolved,
            Resolved::Unavailable(KeychainFailure::Unresponsive)
        ));
        store
            .set(&name("alpha"), &value("sk-REAL"))
            .expect("the inventory lock was released");
    }

    /// A probe is a read too: `secret ls` must report the wedged store rather
    /// than hang on it, and the listing must still list.
    #[test]
    fn a_listing_reports_a_wedged_read_instead_of_waiting_for_it() {
        let (_dir, store) = bounded_store(DelayedKeychain::never(), Duration::from_millis(200));
        store.set(&name("alpha"), &value("sk-REAL")).expect("set");
        assert_eq!(
            store.list().expect("a listing"),
            vec![SecretEntry {
                service: name("alpha"),
                status: StorageStatus::Unavailable(KeychainFailure::Unresponsive),
            }]
        );
    }

    /// The bound must not cost the fast path its value: a read inside the bound
    /// returns byte for byte, through both read verbs.
    #[test]
    fn a_read_inside_the_bound_returns_the_value_unchanged() {
        let (_dir, store) =
            bounded_store(DelayedKeychain::immediately(), Duration::from_millis(200));
        match store.resolve(&name("alpha")) {
            Resolved::Value(resolved) => assert_eq!(resolved.expose_for_test(), "sk-REAL"),
            other => panic!("expected Value, got {other:?}"),
        }
        store.set(&name("alpha"), &value("sk-REAL")).expect("set");
        assert_eq!(
            store.list().expect("a listing"),
            vec![SecretEntry {
                service: name("alpha"),
                status: StorageStatus::Stored,
            }]
        );
    }

    /// The debug-only recording seam records a length and a digest of what was
    /// set; it must never become a way to read that value back out.
    #[test]
    fn recording_keychain_is_not_a_value_oracle() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = dir.path().join("recorded.txt");
        let backend = RecordingKeychain {
            path: recorded.clone(),
        };
        let service = name("alpha");
        backend
            .set(&service, &value("sk-REAL"))
            .expect("the seam accepts a set");
        assert!(backend.is_test_recording());
        match backend.get(&service) {
            Ok(None) => {}
            other => panic!("the recording seam must never return a value: {other:?}"),
        }
        let recorded_bytes = std::fs::read_to_string(&recorded).unwrap();
        assert!(!recorded_bytes.contains("sk-REAL"));
    }

    #[test]
    fn a_failing_session_creates_no_plaintext_value_file() {
        let harness = Harness::new();
        harness.backend.fail_set(KeychainFailure::Unavailable);
        let store = harness.store();
        store
            .set(&name("anthropic"), &value("sk-REAL-LEAK"))
            .expect_err("the backend failed");
        // A name that was never involved: the failing `set` still listed
        // `anthropic` (the inventory-first ordering), so removing *that* would
        // correctly report `Removed`.
        assert_eq!(
            store.remove(&name("openai")).unwrap(),
            RemoveOutcome::NotStored
        );

        let mut entries: Vec<String> = std::fs::read_dir(harness.dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(entries, [LOCK_FILE_NAME, INVENTORY_FILE_NAME]);
        for file in [harness.inventory(), harness.dir.path().join(LOCK_FILE_NAME)] {
            let bytes = std::fs::read(&file).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("sk-REAL-LEAK"), "{} leaked", file.display());
        }
    }

    // -- S12: the value-carrying renderings disclose nothing ----------------

    /// S12 — every rendering that *could* carry the value is checked: the
    /// `Debug` of the value, entry and failures; the `set`/`remove`/probe error
    /// paths that interpolate a failure message; and the invalid-name error for
    /// a value typed in the name slot. That is the set of paths a value can
    /// reach, not a proof about "every error in the module" — the
    /// inventory-load errors are covered separately by S9, which asserts with a
    /// value-bearing needle.
    #[test]
    fn no_debug_or_error_rendering_carries_the_value() {
        const SECRET: &str = "SUPERSECRET-VALUE";

        assert_no_leak(&format!("{:?}", value(SECRET)), SECRET);
        let entry = SecretEntry {
            service: name("anthropic"),
            status: StorageStatus::Unavailable(KeychainFailure::Ambiguous),
        };
        assert_no_leak(&format!("{entry:?}"), SECRET);
        for failure in [
            KeychainFailure::AccessDenied,
            KeychainFailure::Unavailable,
            KeychainFailure::Ambiguous,
            KeychainFailure::Rejected,
            KeychainFailure::Unresponsive,
            KeychainFailure::InventoryBusy,
            KeychainFailure::Unknown,
        ] {
            assert_no_leak(&format!("{failure:?}"), SECRET);
            assert_no_leak(failure.message(), SECRET);
        }

        let mut rendered = Vec::new();

        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value(SECRET)).unwrap();
        harness.backend.fail_set(KeychainFailure::AccessDenied);
        rendered.push(format!(
            "{:#}",
            store
                .set(&name("anthropic"), &value(SECRET))
                .expect_err("set")
        ));
        harness.backend.fail_delete(KeychainFailure::Unavailable);
        rendered.push(format!(
            "{:#}",
            store.remove(&name("anthropic")).expect_err("remove")
        ));

        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value(SECRET)).unwrap();
        harness.backend.delete_is_a_lie();
        rendered.push(format!(
            "{:#}",
            store.remove(&name("anthropic")).expect_err("lying delete")
        ));

        let harness = Harness::new();
        let store = harness.store();
        store.set(&name("anthropic"), &value(SECRET)).unwrap();
        harness.backend.fail_probe(KeychainFailure::Ambiguous);
        let rows = store.list().unwrap();
        let row = rows.first().expect("one row");
        if let StorageStatus::Unavailable(failure) = &row.status {
            rendered.push(failure.message().to_owned());
        }

        // The invalid-name error must not echo a secret typed in the name slot.
        // The sample has a `/`, so it is still rejected under the O1 alphabet
        // (a key made only of letters, digits, `.`, `_` and `-` now *is* an
        // acceptable name -- see `a_key_shaped_name_is_accepted_after_o1`).
        let value_shaped_name = "sk-ant-api03-REAL/VALUE";
        rendered.push(format!(
            "{:#}",
            ServiceName::parse(value_shaped_name).expect_err("a value is not a name")
        ));

        for text in rendered {
            assert_no_leak(&text, SECRET);
        }
    }

    // -- S14: directory and file lifecycle -------------------------------

    #[test]
    fn first_set_creates_the_config_dir_and_the_inventory_with_narrow_modes() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(crate::config::USER_CONFIG_DIR_RELATIVE);
        assert!(!dir.exists(), "the fixture must start with no config dir");
        let store = SecretStore::new(
            FakeKeychain::new(),
            InventoryPaths::new(dir.clone()),
            TEST_LOCK_WAIT,
        );
        store.set(&name("anthropic"), &value("sk-REAL")).unwrap();
        assert_eq!(mode(&dir), CONFIG_DIR_MODE);
        assert_eq!(mode(&dir.join(INVENTORY_FILE_NAME)), INVENTORY_FILE_MODE);
        assert_eq!(mode(&dir.join(LOCK_FILE_NAME)), INVENTORY_FILE_MODE);
    }

    #[test]
    fn the_production_store_lives_under_home_and_listing_creates_only_the_directory() {
        let mut env = test_env::guard();
        let home = tempfile::tempdir().unwrap();
        env.set_var("HOME", home.path());
        let store = system_store().expect("a valid HOME resolves");
        assert_eq!(
            store.paths.inventory_path(),
            home.path()
                .join(crate::config::USER_CONFIG_DIR_RELATIVE)
                .join(INVENTORY_FILE_NAME)
        );
        // An empty inventory probes nothing, so this never touches the host
        // credential store -- which is what makes it safe on any machine.
        assert!(store.list().unwrap().is_empty());
        assert!(!store.paths.inventory_path().exists());
        assert_eq!(mode(&store.paths.dir), CONFIG_DIR_MODE);
    }

    // -- S17: the lock serializes the read-modify-write -------------------

    #[test]
    fn concurrent_sets_do_not_lose_an_inventory_row() {
        let dir = tempfile::tempdir().unwrap();
        let paths = InventoryPaths::new(dir.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(2));
        let deadline = Instant::now() + Duration::from_secs(30);
        let (tx, rx) = mpsc::channel();
        let handles: Vec<_> = ["alpha", "beta"]
            .into_iter()
            .map(|raw| {
                let paths = paths.clone();
                let barrier = Arc::clone(&barrier);
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let store = SecretStore::new(FakeKeychain::new(), paths, TEST_LOCK_WAIT);
                    let service = ServiceName::parse(raw).unwrap();
                    let value = SecretValue::parse(b"sk-REAL".to_vec()).unwrap();
                    barrier.wait();
                    for _ in 0..25 {
                        store.set(&service, &value).unwrap();
                    }
                    tx.send(()).unwrap();
                })
            })
            .collect();
        drop(tx);
        for _ in 0..2 {
            rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap();
        }
        for handle in handles {
            while !handle.is_finished() {
                assert!(Instant::now() < deadline, "worker did not finish");
                std::thread::sleep(Duration::from_millis(1));
            }
            handle.join().unwrap();
        }
        let rows = within_deadline("concurrent final listing", move || {
            SecretStore::new(FakeKeychain::new(), paths, TEST_LOCK_WAIT)
                .list()
                .unwrap()
        });
        let names: Vec<&str> = rows.iter().map(|row| row.service.as_str()).collect();
        assert_eq!(names, ["alpha", "beta"], "a lost row hides a stored value");
    }

    // -- S18: the $HOME discipline ----------------------------------------

    /// `SecretStore` deliberately has no `Debug` (there is nothing safe to
    /// print about it), so this renders the error from a `match` rather than
    /// `expect_err`.
    fn unusable_home_error() -> String {
        match system_store() {
            Ok(_) => panic!("an unusable $HOME must not resolve a store"),
            Err(error) => format!("{error:#}"),
        }
    }

    #[test]
    fn an_unusable_home_is_an_explicit_error() {
        let mut env = test_env::guard();

        env.remove_var("HOME");
        let text = unusable_home_error();
        assert!(text.contains("$HOME is not set"), "{text}");
        assert!(text.contains("cannot locate"), "{text}");

        env.set_var("HOME", "");
        let text = unusable_home_error();
        assert!(text.contains("$HOME is set but empty"), "{text}");

        env.set_var("HOME", "relative/path");
        let text = unusable_home_error();
        assert!(text.contains("is not absolute"), "{text}");
    }

    // -- the real adapter, by hand ----------------------------------------

    /// Mechanizes manual verification steps 1 and 2 (macOS Keychain / Linux
    /// Secret Service) against the **real** platform credential store, with a
    /// throwaway service name. Deliberately `#[ignore]`d: `ubuntu-latest` has
    /// no Secret Service, and touching a developer's keychain on every test run
    /// is rude.
    ///
    /// ```text
    /// cargo test -p agent-vm --bin agent-vm -- --ignored system_keychain_round_trip
    /// ```
    ///
    /// On macOS, confirm the item is gone afterwards with a metadata-only
    /// lookup — never pass `-w`, which prints the value:
    ///
    /// ```text
    /// security find-generic-password -s dev.agent-vm.credentials -a avm-manual-check
    /// ```
    #[test]
    #[ignore = "touches the host OS credential store; see the doc comment"]
    fn system_keychain_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::new(
            SystemKeychain,
            InventoryPaths::new(dir.path().to_path_buf()),
            TEST_LOCK_WAIT,
        );
        let service = name("avm-manual-check");
        let value = value("synthetic-manual-check-value");

        store.set(&service, &value).expect("set");
        assert_eq!(
            store.list().expect("list"),
            vec![SecretEntry {
                service: service.clone(),
                status: StorageStatus::Stored,
            }]
        );
        assert_eq!(
            store.remove(&service).expect("remove"),
            RemoveOutcome::Removed
        );
        assert!(store.list().expect("list").is_empty());
    }

    // -- C5: the closed error classification ------------------------------

    #[test]
    fn classify_maps_every_keyring_variant_without_carrying_bytes() {
        const NEEDLE: &str = "SUPERSECRET";
        let platform = keyring::Error::PlatformFailure(Box::new(std::io::Error::other(NEEDLE)));
        let access = keyring::Error::NoStorageAccess(Box::new(std::io::Error::other(NEEDLE)));
        let bad_encoding = keyring::Error::BadEncoding(NEEDLE.as_bytes().to_vec());
        let invalid = keyring::Error::Invalid("service".to_owned(), NEEDLE.to_owned());
        // Positive control: these `keyring::Error` values really do carry the
        // needle, which is exactly why the boundary drops them instead of
        // attaching them as an `anyhow` source.
        for error in [&platform, &access, &invalid] {
            assert!(
                format!("{error:?}").contains(NEEDLE),
                "the control error must carry the needle: {error:?}"
            );
        }
        // `BadEncoding` carries the raw bytes, so its `Debug` prints the byte
        // values rather than the text. The control is the same fact, spelled
        // the way the type spells it.
        let byte_list = NEEDLE
            .bytes()
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            format!("{bad_encoding:?}").contains(&byte_list),
            "the control error must carry the bytes: {bad_encoding:?}"
        );

        let cases: Vec<(keyring::Error, KeychainFailure)> = vec![
            (platform, KeychainFailure::Unavailable),
            (access, KeychainFailure::AccessDenied),
            (bad_encoding, KeychainFailure::Rejected),
            (
                keyring::Error::TooLong("service".to_owned(), 64),
                KeychainFailure::Rejected,
            ),
            (invalid, KeychainFailure::Rejected),
            (
                keyring::Error::Ambiguous(Vec::new()),
                KeychainFailure::Ambiguous,
            ),
            // Unreachable from the three callers, matched explicitly so a
            // reshaped variant forces a look here.
            (keyring::Error::NoEntry, KeychainFailure::Unknown),
        ];
        for (error, expected) in cases {
            let failure = classify(error);
            assert_eq!(failure, expected);
            assert_no_leak(failure.message(), NEEDLE);
            assert_no_leak(&format!("{failure:?}"), NEEDLE);
        }
    }

    // -- V1/V2: the boundary pairs ---------------------------------------

    #[test]
    fn service_name_boundaries_and_canonicalization() {
        // (accepted input, canonical form). The canonical form is the identity
        // of the stored credential.
        for (raw, canonical) in [
            ("a", "a"),
            ("a0", "a0"),
            ("x-y.z_w", "x-y.z_w"),
            ("Anthropic", "anthropic"),
            ("ANTHROPIC", "anthropic"),
            ("A0-b.C_d", "a0-b.c_d"),
        ] {
            let name = ServiceName::parse(raw).unwrap_or_else(|error| panic!("{raw}: {error:#}"));
            assert_eq!(name.as_str(), canonical, "{raw}");
            assert_eq!(name.to_string(), canonical, "{raw}");
            // Re-parsing the canonical form is a fixed point.
            assert_eq!(ServiceName::parse(canonical).unwrap(), name, "{raw}");
        }

        let longest = "a".repeat(MAX_SERVICE_NAME_LEN);
        assert!(ServiceName::parse(&longest).is_ok());
        // 64 uppercase bytes fold to 64 lowercase bytes: still inside the limit.
        assert_eq!(
            ServiceName::parse(&"A".repeat(MAX_SERVICE_NAME_LEN))
                .unwrap()
                .as_str(),
            longest
        );

        let mut rejected = vec![
            String::new(),
            "a".repeat(MAX_SERVICE_NAME_LEN + 1),
            "-lead".to_owned(),
            ".lead".to_owned(),
            "a b".to_owned(),
            "a/b".to_owned(),
            "a\0b".to_owned(),
            "añ".to_owned(),
        ];
        rejected.push("sk-ant-api03-REAL/VALUE".to_owned());
        for raw in rejected {
            let error = ServiceName::parse(&raw).expect_err("must be rejected");
            let text = format!("{error:#}");
            assert!(
                text.contains("1-64 characters from [a-zA-Z0-9._-]"),
                "{text}"
            );
            // The rule is stated and the input is never echoed: a user may have
            // typed a value in the name slot.
            if !raw.is_empty() {
                assert!(!text.contains(&raw), "the input was echoed: {text}");
            }
        }
    }

    /// The O1 trade-off, pinned deliberately rather than discovered later.
    ///
    /// Under the accepted alphabet (letters either case, digits, `.`, `_`, `-`)
    /// a realistic API key *is* a valid service name, so "a secret typed in the
    /// name slot" is no longer always rejected: it is folded and accepted, and
    /// `set` prints it as the service name (and the inventory records it). The
    /// original lowercase-only rule rejected such a name outright.
    ///
    /// This is a usability/defence-in-depth regression, not a guest-visible
    /// credential disclosure: the name goes to the user's own stderr and to a
    /// 0600 host file, and the *value* is never taken from argv. The mitigation
    /// to consider later is a warning when a name looks like a credential.
    #[test]
    fn a_key_shaped_name_is_accepted_after_o1() {
        let parsed = ServiceName::parse("sk-ant-API03-AbCdEf")
            .expect("a key-shaped name is a valid name under O1");
        assert_eq!(parsed.as_str(), "sk-ant-api03-abcdef");
    }

    /// O1: case folding is the identity rule, so three spellings are one entry
    /// -- an update, not three invisible duplicates in a case-sensitive
    /// keychain.
    #[test]
    fn case_spellings_of_a_name_are_one_entry() {
        let harness = Harness::new();
        let store = harness.store();

        store.set(&name("Anthropic"), &value("first")).unwrap();
        let rows = store.list().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].service.as_str(), "anthropic");

        store.set(&name("ANTHROPIC"), &value("second")).unwrap();
        assert_eq!(store.list().unwrap().len(), 1, "an update, not a duplicate");
        assert_eq!(
            harness.backend.stored("anthropic").as_deref(),
            Some("second")
        );
        assert_eq!(harness.backend.stored("Anthropic"), None);

        // `rm` by any spelling removes the one entry.
        assert_eq!(
            store.remove(&name("Anthropic")).unwrap(),
            RemoveOutcome::Removed
        );
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn secret_value_boundaries() {
        for accepted in [
            b"x".to_vec(),
            vec![b'a'; MAX_SECRET_VALUE_LEN],
            b"a b".to_vec(),
        ] {
            assert!(SecretValue::parse(accepted.clone()).is_ok(), "{accepted:?}");
        }
        let rejected: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![b'a'; MAX_SECRET_VALUE_LEN + 1],
            b" x".to_vec(),
            b"x ".to_vec(),
            b"a\tb".to_vec(),
            b"a\nb".to_vec(),
            b"a\rb".to_vec(),
            vec![0x7f],
            vec![0],
            vec![0xff, 0xfe],
        ];
        for raw in rejected {
            let error = SecretValue::parse(raw.clone()).expect_err("must be rejected");
            let text = format!("{error:#}");
            assert!(
                text.contains("not printable ASCII")
                    || text.contains("longer than")
                    || text.contains("leading or trailing space")
                    || text.contains("no value was supplied"),
                "{raw:?}: {text}"
            );
            assert!(
                !text.contains("UTF-8"),
                "{raw:?} must fail the shape rule: {text}"
            );
        }
    }

    // -- V5: the bidirectional oracle -----------------------------------

    fn valid_name_strategy() -> impl Strategy<Value = String> {
        let rest = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-".to_vec();
        (
            proptest::sample::select(
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_vec(),
            ),
            proptest::collection::vec(proptest::sample::select(rest), 0..=MAX_SERVICE_NAME_LEN - 1),
        )
            .prop_map(|(first, mut rest)| {
                let mut bytes = vec![first];
                bytes.append(&mut rest);
                String::from_utf8(bytes).expect("the strategy only emits ASCII")
            })
    }

    fn mutated_name_strategy() -> impl Strategy<Value = String> {
        let replacements: Vec<char> = "AaZz09 ._/ñ-".chars().collect();
        (
            valid_name_strategy(),
            proptest::sample::select(replacements),
            any::<Index>(),
        )
            .prop_map(|(name, replacement, index)| {
                let mut chars: Vec<char> = name.chars().collect();
                if chars.is_empty() {
                    chars.push(replacement);
                } else {
                    let position = index.index(chars.len());
                    chars[position] = replacement;
                }
                chars.into_iter().collect()
            })
    }

    fn valid_value_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(0x20u8..=0x7e, 1..=MAX_SECRET_VALUE_LEN).prop_map(|mut bytes| {
            bytes[0] = b'a';
            let last = bytes.len() - 1;
            bytes[last] = b'z';
            bytes
        })
    }

    fn value_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            valid_value_strategy(),
            (valid_value_strategy(), any::<u8>(), any::<Index>()).prop_map(
                |(mut bytes, replacement, index)| {
                    let position = index.index(bytes.len());
                    bytes[position] = replacement;
                    bytes
                }
            ),
            proptest::collection::vec(any::<u8>(), 0..=MAX_SECRET_VALUE_LEN + 1),
        ]
    }

    /// The oracle is written from the rule table, not from the implementation.
    fn service_name_oracle(bytes: &[u8]) -> bool {
        (1..=MAX_SERVICE_NAME_LEN).contains(&bytes.len())
            && matches!(bytes[0], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')
            && bytes.iter().all(|byte| {
                matches!(
                    byte,
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'
                )
            })
    }

    fn secret_value_oracle(bytes: &[u8]) -> bool {
        let last = bytes.len().saturating_sub(1);
        (1..=MAX_SECRET_VALUE_LEN).contains(&bytes.len())
            && bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
            && bytes.first() != Some(&b' ')
            && bytes.get(last) != Some(&b' ')
    }

    proptest! {
        /// Equivalence, not implication: a function that rejected everything
        /// would pass an implication.
        #[test]
        fn service_name_parse_matches_the_rule(
            raw in prop_oneof![valid_name_strategy(), mutated_name_strategy(), any::<String>()],
        ) {
            // Bidirectional: acceptance is exactly the oracle, the stored value
            // is exactly the ASCII-lowercased input, and folding is idempotent.
            let parsed = ServiceName::parse(&raw);
            prop_assert_eq!(parsed.is_ok(), service_name_oracle(raw.as_bytes()));
            if let Ok(name) = parsed {
                prop_assert_eq!(name.as_str().to_owned(), raw.to_ascii_lowercase());
                prop_assert_eq!(
                    ServiceName::parse(name.as_str()).unwrap().as_str().to_owned(),
                    name.as_str().to_owned()
                );
            }
        }

        #[test]
        fn secret_value_parse_matches_the_rule(raw in value_strategy()) {
            prop_assert_eq!(
                SecretValue::parse(raw.clone()).is_ok(),
                secret_value_oracle(&raw)
            );
        }

        /// The label-only classifier must never disagree with the verified
        /// predicate about whether something was rejected.
        #[test]
        fn value_rejection_matches_the_predicate(raw in value_strategy()) {
            prop_assert_eq!(
                value_rejection(&raw).is_none(),
                secret_value_is_acceptable_bytes(&raw)
            );
        }
    }
}
