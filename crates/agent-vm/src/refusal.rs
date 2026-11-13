//! What a sandbox refused, coalesced per session and entry key.
//!
//! One [`SessionRefusals`] holds one live session's list. It is pure: it takes
//! decoded runtime records ([`NetworkLogRecord`]) and produces the entries, the
//! counters and a revision. Everything that touches a file, a socket or a
//! runtime lives in [`log`] and [`feed`], so the coalescing rules — the ones a
//! reader will argue about — are testable without any of those.
//!
//! The module stores **wire strings**, never the SDK's enums. `RefusalSite`,
//! `RefusalLayer` and `NameSource` are `#[non_exhaustive]`, so a record from a
//! newer runtime carries a value this build cannot name; keeping the string it
//! arrived as means such a record is displayed as what the runtime said instead
//! of being dropped or collapsed into a catch-all variant.
//!
//! Slice 1 never decides whether an allowance covers an entry. Entries keep
//! `last_revision` so coverage filtering can be added without a second pass over
//! the runtime's records.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use microsandbox::logs::{
    NameSource, NetworkLogEvent, NetworkLogRecord, NetworkRefusal, PlaceholderLocation,
    RefusalLayer, RefusalSite,
};

/// At most this many entries per session. A hostile or broken guest can open
/// destinations forever; past this the session counts what it did not keep
/// instead of growing without bound (AC12).
pub(crate) const MAX_ENTRIES_PER_SESSION: usize = 512;

/// DNS allows 253 bytes of name. A longer one is guest text, not a name.
pub(crate) const MAX_NAME_BYTES: usize = 253;

/// Every other stored string (protocol, site, layer) is a short wire token.
const MAX_FIELD_BYTES: usize = 32;

/// The prefix of the ID hash input. Versioned so a later rule can change the
/// derivation without ever colliding with an ID from this one.
const ID_DOMAIN: &str = "agent-vm/refusal-id/v1";

/// One launch's identity, as the log and the control socket name it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SessionId(String);

/// Deserialized through [`SessionId::parse`], so the one accepted spelling holds
/// for a value read from the log and not only for one read from the command line.
/// `access` prints a session ID, and a forged log must not be able to put terminal
/// escapes in that column (AC5).
impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        SessionId::parse(&text)
            .ok_or_else(|| serde::de::Error::custom("a session ID is exactly 8 lowercase hex"))
    }
}

impl SessionId {
    /// A fresh reservation drawn from the kernel's CSPRNG: 8 lowercase hex.
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).expect("the kernel CSPRNG is available");
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Parse the one accepted spelling: exactly 8 lowercase hex digits.
    ///
    /// The strict spelling is what makes a session ID safe as a file name and a
    /// socket name: it is also what `discover` filters a directory listing by.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        (text.len() == 8
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| Self(text.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why nothing can be done about a refusal in this version (AC1's reason
/// column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    /// A tenant network denial an allowance would cover once grants exist.
    NetworkDenial,
    /// A rule of the engine or the deployment profile, which no allowance can
    /// lift.
    PolicyLock,
    /// The credential boundary, which is not an egress decision at all.
    CredentialRefusal,
}

impl Kind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NetworkDenial => "network denial",
            Self::PolicyLock => "policy lock",
            Self::CredentialRefusal => "credential refusal",
        }
    }

    /// The `Kind` as the coordinate of a key: stable wire text, never an enum
    /// discriminant, so the ID derivation survives a variant being added.
    fn key_name(self) -> &'static str {
        match self {
            Self::NetworkDenial => "network-denial",
            Self::PolicyLock => "policy-lock",
            Self::CredentialRefusal => "credential-refusal",
        }
    }
}

/// What an allowance would name, and therefore what coalesces.
///
/// The choice is §5's: the destination is the thing a grant would have to
/// mention. A DNS answer the guest's own resolver produced is not a destination
/// — the resolver address is — and a name the guest supplied over SNI or HTTP is
/// the destination, with the address kept as evidence.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "variant", rename_all = "kebab-case")]
pub(crate) enum Destination {
    /// No usable name evidence: the address the guest used.
    Address {
        protocol: String,
        ip: Option<IpAddr>,
        port: Option<u16>,
    },
    /// A guest-supplied name from SNI or an HTTP `Host`/`:authority`.
    Host {
        protocol: String,
        name: String,
        port: Option<u16>,
    },
    /// A name the guest asked the resolver for.
    DnsName { name: String },
}

impl Destination {
    fn variant_name(&self) -> &'static str {
        match self {
            Self::Address { .. } => "address",
            Self::Host { .. } => "host",
            Self::DnsName { .. } => "dns-name",
        }
    }

    fn protocol(&self) -> &str {
        match self {
            Self::Address { protocol, .. } | Self::Host { protocol, .. } => protocol,
            Self::DnsName { .. } => "",
        }
    }

    fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Address { ip, .. } => *ip,
            Self::Host { .. } | Self::DnsName { .. } => None,
        }
    }

    fn port(&self) -> Option<u16> {
        match self {
            Self::Address { port, .. } | Self::Host { port, .. } => *port,
            Self::DnsName { .. } => None,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Address { .. } => "",
            Self::Host { name, .. } | Self::DnsName { name } => name,
        }
    }
}

/// The coalescing key: one entry per kind, destination and — for a credential
/// refusal — credential. ADR-0064 records why the credential is a coordinate and
/// what it costs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct EntryKey {
    pub(crate) kind: Kind,
    pub(crate) destination: Destination,
    /// Set for [`Kind::CredentialRefusal`] and no other kind. Absent in a log
    /// written before this coordinate existed; decodes as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) credential: Option<String>,
}

/// The bytes an ID is derived from: one field per line, an absent field empty.
///
/// Canonical in exactly the way the entry is: the same refusal on the same
/// session always produces the same bytes, whatever spelling the runtime
/// reported the name in.
///
/// The six lines are fixed, and a credential refusal appends the credential as a
/// seventh. Conditional on purpose: every ID a log already holds was derived from
/// the six-line form, and no credential-free ID may move.
pub(crate) fn key_bytes(key: &EntryKey) -> Vec<u8> {
    let mut lines = vec![
        key.kind.key_name().to_owned(),
        key.destination.variant_name().to_owned(),
        key.destination.protocol().to_lowercase(),
        key.destination
            .ip()
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        key.destination
            .port()
            .map(|port| port.to_string())
            .unwrap_or_default(),
        key.destination.name().to_ascii_lowercase(),
    ];
    if key.kind == Kind::CredentialRefusal {
        lines.push(key.credential.clone().unwrap_or_default());
    }
    lines.join("\n").into_bytes()
}

/// A name the guest supplied, which is therefore text and never a fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GuestName {
    pub(crate) name: String,
    /// The runtime's own `name_source` wire value, e.g. `sni` or `dns-cache`.
    pub(crate) source: String,
    /// Whether the runtime's name was longer than [`MAX_NAME_BYTES`] and had to
    /// be cut. Displayed, because a truncated name is not a name.
    pub(crate) truncated: bool,
}

impl GuestName {
    fn new(name: &str, source: String) -> Self {
        let truncated = name.len() > MAX_NAME_BYTES;
        let mut name = if truncated {
            name[..floor_char_boundary(name, MAX_NAME_BYTES)].to_owned()
        } else {
            name.to_owned()
        };
        name.retain(|c| c != '\0');
        Self {
            name,
            source,
            truncated,
        }
    }
}

/// Cut `text` at or below `limit` without splitting a character.
fn floor_char_boundary(text: &str, limit: usize) -> usize {
    let mut end = limit.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// One coalesced refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RefusalEntry {
    pub(crate) id: String,
    pub(crate) key: EntryKey,
    /// The runtime's `layer` wire value for the latest refusal.
    pub(crate) layer: String,
    /// The runtime's `site` wire value for the latest refusal.
    pub(crate) last_site: String,
    /// The address of the latest refusal, when the key does not carry one.
    pub(crate) last_ip: Option<IpAddr>,
    pub(crate) name: Option<GuestName>,
    /// The runtime's `location` wire value for the latest refusal that stated
    /// one, so a later record that stayed silent cannot erase it. Absent in an
    /// older log, on the same terms as [`EntryKey::credential`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_location: Option<String>,
    /// The runtime's `reason` wire value, on the same terms as
    /// [`RefusalEntry::last_location`].
    ///
    /// Evidence rather than identity, unlike the credential: a reason is a
    /// diagnosis of the latest attempt, so a row keyed on it would leave two rows
    /// differing by a cause that has since been fixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_reason: Option<String>,
    /// The tenant policy revision in force for the latest refusal. Unused in
    /// slice 1 (it decides nothing); kept so coverage filtering can be added
    /// later without re-reading the runtime's log.
    pub(crate) last_revision: u64,
    pub(crate) count: u64,
    pub(crate) first_ms: i64,
    pub(crate) last_ms: i64,
}

impl RefusalEntry {
    /// The row's reason: what, if anything, could change this decision.
    ///
    /// The engine's own rules and the platform floor are not egress decisions an
    /// allowance reaches, so they say which rule locked them rather than
    /// offering an action that would not work.
    pub(crate) fn reason(&self) -> String {
        if self.layer == "platform" {
            return "can't be allowed: platform policy".to_owned();
        }
        match self.key.kind {
            Kind::NetworkDenial => {
                "no grant in this version; relaunch with --allow-egress".to_owned()
            }
            Kind::CredentialRefusal => self.credential_policy_reason(),
            // `last_site` is the runtime's wire value as a forged record may
            // carry it, so it is escaped here, where it becomes text a reader
            // prints.
            Kind::PolicyLock => format!(
                "can't be allowed: built-in rule {}",
                crate::config::escape_str(&self.last_site)
            ),
        }
    }

    /// The credential boundary, then the facts the runtime stated.
    ///
    /// A record that states none of them keeps the bare sentence: a missing field
    /// means the record did not say, never that nothing was refused, so the cell
    /// never prints "none" and never names a cause it was not given.
    fn credential_policy_reason(&self) -> String {
        let mut text = "can't be allowed here: credential policy".to_owned();
        let credential = self.key.credential.as_deref();
        let location = self.last_location.as_deref().and_then(location_phrase);
        if credential.is_none() && location.is_none() && self.last_reason.is_none() {
            return text;
        }
        let subject = match credential {
            // The name the configuration supplied is still text a record may have
            // forged, so it is escaped where it becomes something a reader prints.
            Some(credential) => crate::config::escape_str(credential),
            // The engine's own 403 says this when the name would itself carry a
            // placeholder.
            None => "a credential".to_owned(),
        };
        text.push_str(&format!("; {subject} was sent"));
        if let Some(phrase) = location {
            text.push_str(&format!(" in {phrase}"));
        }
        if let Some(reason) = self.last_reason.as_deref() {
            text.push_str(&format!(", and {}", reason_clause(reason)));
        }
        text
    }
}

/// Where the placeholder was found, as the engine's own phrase for its wire value
/// (`PlaceholderLocation::phrase()`).
///
/// The log holds a string, so it is decoded back through the engine's type rather
/// than copied into a second table here. `None` for a value this build cannot
/// name — a forged record, or one a later runtime adds — so the cell says nothing
/// about where instead of pushing text into a phrase it does not fit.
fn location_phrase(location: &str) -> Option<&'static str> {
    serde_json::from_value::<PlaceholderLocation>(serde_json::Value::String(location.into()))
        .ok()
        .map(PlaceholderLocation::phrase)
}

/// Why the secret could not serve the request, in words.
///
/// "Host" is never the noun: the destination is the API side and this computer is
/// "outside the sandbox". A value this build cannot name is displayed as what the
/// runtime said, escaped, because the cell must not invent a cause.
fn reason_clause(reason: &str) -> String {
    match reason {
        "host-not-covered" => "its secret does not cover the destination".to_owned(),
        "credential-unavailable" => {
            "the real value could not be read outside the sandbox".to_owned()
        }
        "destination-unverified" => "the destination could not be verified".to_owned(),
        other => format!("the runtime reported {}", crate::config::escape_str(other)),
    }
}

/// The session an entry belongs to. `socket` is whether a control socket was
/// bound; a session without one is still listable from the log, and says so.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionInfo {
    pub(crate) id: SessionId,
    pub(crate) pid: u32,
    pub(crate) started_ms: i64,
    pub(crate) socket: bool,
}

/// One session, whole. The same shape is the in-memory value, the log's record
/// and the `list` reply, so nothing has to be translated at a boundary and a
/// field cannot exist on one side only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionSnapshot {
    pub(crate) info: SessionInfo,
    /// Bumped by every change. Absolute updates carry it, so a subscriber can
    /// discard anything it already has without tracking which fields moved.
    pub(crate) rev: u64,
    pub(crate) ended_ms: Option<i64>,
    /// When the follower last read the runtime's log successfully. Only used for
    /// a session with no control socket, where it is the only liveness evidence.
    pub(crate) heartbeat_ms: Option<i64>,
    /// Refusals the runtime decided but did not write.
    pub(crate) suppressed: u64,
    /// Refusals this session could not keep: past [`MAX_ENTRIES_PER_SESSION`].
    pub(crate) lost: u64,
    /// Whether a gap in the runtime's log was observed. The number missed is
    /// unknown by construction, so it is a flag rather than a count.
    pub(crate) gap: bool,
    pub(crate) entries: Vec<RefusalEntry>,
}

impl SessionSnapshot {
    pub(crate) fn new(info: SessionInfo) -> Self {
        Self {
            info,
            rev: 0,
            ended_ms: None,
            heartbeat_ms: None,
            suppressed: 0,
            lost: 0,
            gap: false,
            entries: Vec::new(),
        }
    }

    /// The entry IDs of this session, for the "same ID in two sessions" footer.
    pub(crate) fn ids(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.id.as_str())
    }
}

/// One absolute change: the entry that moved (if any) and every counter.
///
/// Absolute rather than a delta, so a subscriber that misses nothing still needs
/// no state machine, and one that misses something can be corrected by the next
/// update instead of staying wrong.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Update {
    pub(crate) rev: u64,
    /// The entry that moved. Boxed so `session_control::Reply::Update` stays the
    /// size of its other variants (`clippy::large_enum_variant`); serde's `Box` is
    /// transparent, so the wire form is the entry itself.
    pub(crate) entry: Option<Box<RefusalEntry>>,
    pub(crate) suppressed: u64,
    pub(crate) lost: u64,
    pub(crate) gap: bool,
}

/// One live session's entries, counters and revision.
#[derive(Debug)]
pub(crate) struct SessionRefusals {
    snapshot: SessionSnapshot,
    index: HashMap<EntryKey, usize>,
}

impl SessionRefusals {
    pub(crate) fn new(info: SessionInfo) -> Self {
        Self {
            snapshot: SessionSnapshot::new(info),
            index: HashMap::new(),
        }
    }

    /// Resume from a snapshot read back from the log, rebuilding the index.
    ///
    /// A session ID is reserved once and never reused, so a snapshot is only ever
    /// handed back to the one process that reserved it.
    pub(crate) fn resume(snapshot: SessionSnapshot) -> Self {
        let index = snapshot
            .entries
            .iter()
            .enumerate()
            .map(|(position, entry)| (entry.key.clone(), position))
            .collect();
        Self { snapshot, index }
    }

    pub(crate) fn snapshot(&self) -> SessionSnapshot {
        self.snapshot.clone()
    }

    /// Fold one runtime record in. `None` when it changes nothing (a record from
    /// before this session started), so the caller does not notify or persist.
    pub(crate) fn ingest(&mut self, record: &NetworkLogRecord) -> Option<Update> {
        let at_ms = record.t.timestamp_millis();
        if at_ms < self.snapshot.info.started_ms {
            // The sandbox name carries the launcher PID, and a PID is reused. A
            // record older than this session belongs to the earlier launch that
            // owned the name; it is not this session's refusal.
            return None;
        }
        match &record.event {
            NetworkLogEvent::Refusal(refusal) => Some(self.ingest_refusal(refusal, at_ms)),
            NetworkLogEvent::Suppressed(suppressed) => {
                self.snapshot.suppressed =
                    self.snapshot.suppressed.saturating_add(suppressed.count);
                Some(self.bump(None))
            }
            // Required by `NetworkLogEvent`'s `#[non_exhaustive]`, and
            // unreachable for a record that decoded at all: an unknown `event`
            // tag fails the whole `NetworkLogRecord` decode before this point
            // (which [`super::feed::accept`] records as a gap). Nothing changes
            // here, not even the revision.
            _ => None,
        }
    }

    fn ingest_refusal(&mut self, refusal: &NetworkRefusal, at_ms: i64) -> Update {
        let layer = wire(refusal.layer);
        let kind = classify(refusal.site, refusal.layer);
        // The three refusal facts are set on a `secret-violation` record only, and
        // they are stored for that kind alone: a forged record must not widen a
        // row of another kind with fields its kind has no meaning for.
        let (credential, last_location, last_reason) = match kind {
            Kind::CredentialRefusal => (
                refusal
                    .credential
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .map(secret_name),
                refusal.location.map(|location| clip(&wire(location))),
                refusal.reason.map(|reason| clip(&wire(reason))),
            ),
            _ => (None, None, None),
        };
        let key = EntryKey {
            kind,
            destination: destination(refusal),
            credential,
        };
        let name = refusal
            .name
            .as_deref()
            .filter(|name| !name.is_empty())
            .map(|name| GuestName::new(name, wire(refusal.name_source)));
        if let Some(position) = self.index.get(&key).copied() {
            let entry = &mut self.snapshot.entries[position];
            entry.count = entry.count.saturating_add(1);
            entry.last_ms = at_ms;
            entry.last_ip = refusal.dst_ip;
            entry.last_site = wire(refusal.site);
            entry.layer = layer;
            entry.last_revision = refusal.revision;
            // Only a record that stated a field overwrites it: evidence a later
            // record stayed silent about is still what the runtime last said.
            if last_location.is_some() {
                entry.last_location = last_location;
            }
            if last_reason.is_some() {
                entry.last_reason = last_reason;
            }
            let entry = entry.clone();
            return self.bump(Some(entry));
        }
        if self.snapshot.entries.len() >= MAX_ENTRIES_PER_SESSION {
            // A guest can open destinations forever. Count what did not fit,
            // rather than evicting an entry a reader is already looking at.
            self.snapshot.lost = self.snapshot.lost.saturating_add(1);
            return self.bump(None);
        }
        let id = self.assign_id(&key);
        let entry = RefusalEntry {
            id,
            key: key.clone(),
            layer,
            last_site: wire(refusal.site),
            last_ip: refusal.dst_ip,
            name,
            last_location,
            last_reason,
            last_revision: refusal.revision,
            count: 1,
            first_ms: at_ms,
            last_ms: at_ms,
        };
        self.index.insert(key, self.snapshot.entries.len());
        self.snapshot.entries.push(entry.clone());
        self.bump(Some(entry))
    }

    /// The smallest `u8` that gives an ID this session has not used.
    ///
    /// Collisions are a property of the *session*, not of the hash: 8 hex is 32
    /// bits, and a session is bounded at [`MAX_ENTRIES_PER_SESSION`], so the
    /// birthday probability is small but not zero. Bumping `n` is deterministic,
    /// which is what makes an ID stable across a restart from the log.
    fn assign_id(&self, key: &EntryKey) -> String {
        let mut n: u8 = 0;
        loop {
            let id = refusal_id(self.snapshot.info.id.as_str(), key, n);
            if !self.snapshot.ids().any(|used| used == id) {
                return id;
            }
            n = n.saturating_add(1);
        }
    }

    /// Record a gap in the runtime's log. The number of records missed is not
    /// recoverable, so the flag is all the feed can honestly say.
    pub(crate) fn mark_gap(&mut self) -> Option<Update> {
        if self.snapshot.gap {
            return None;
        }
        self.snapshot.gap = true;
        Some(self.bump(None))
    }

    /// Record that the follower read the runtime's log at `now_ms`.
    ///
    /// Not a revision bump: a heartbeat is not a change to the list, and making
    /// it one would wake every subscriber every poll.
    pub(crate) fn beat(&mut self, now_ms: i64) {
        self.snapshot.heartbeat_ms = Some(now_ms);
    }

    /// Mark the session ended. Bumps the revision, because a subscriber's
    /// session label changes from `running` to `ended`.
    pub(crate) fn ended(&mut self, now_ms: i64) -> Update {
        self.snapshot.ended_ms.get_or_insert(now_ms);
        self.bump(None)
    }

    fn bump(&mut self, entry: Option<RefusalEntry>) -> Update {
        self.snapshot.rev = self.snapshot.rev.saturating_add(1);
        Update {
            rev: self.snapshot.rev,
            entry: entry.map(Box::new),
            suppressed: self.snapshot.suppressed,
            lost: self.snapshot.lost,
            gap: self.snapshot.gap,
        }
    }
}

/// `hex(sha256("agent-vm/refusal-id/v1" ‖ sid ‖ key ‖ n))[..8]`.
fn refusal_id(sid: &str, key: &EntryKey, n: u8) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ID_DOMAIN.as_bytes());
    hasher.update(b"\n");
    hasher.update(sid.as_bytes());
    hasher.update(b"\n");
    hasher.update(key_bytes(key));
    hasher.update(b"\n");
    hasher.update(n.to_string().as_bytes());
    let digest = hasher.finalize();
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// One SDK enum's wire value, as the record carried it.
fn wire<T: Serialize>(value: T) -> String {
    match serde_json::to_value(&value) {
        Ok(serde_json::Value::String(text)) => text,
        // An enum whose serialization is not a string is not a wire value this
        // module can name; a stable placeholder beats a panic in a follower.
        _ => "unknown".to_owned(),
    }
}

fn clip(text: &str) -> String {
    text.chars().take(MAX_FIELD_BYTES).collect()
}

/// The refused secret's name, bounded and cut on a character boundary.
///
/// It is a [`String`] field of an entry in a log that is bounded in bytes, so it
/// needs a bound; [`MAX_NAME_BYTES`] is the one this module already uses for a
/// name. A longer value is not an environment-variable name, and the reader still
/// needs no more of it than that to identify the credential. Unlike [`GuestName`]
/// a cut here is not marked: a built-in name is short, so only a forged log
/// reaches the cut.
fn secret_name(name: &str) -> String {
    name[..floor_char_boundary(name, MAX_NAME_BYTES)].to_owned()
}

/// The destination an allowance would have to name (§5).
fn destination(refusal: &NetworkRefusal) -> Destination {
    let protocol = clip(&wire(refusal.protocol));
    let name = refusal.name.as_deref().filter(|name| !name.is_empty());
    match (refusal.name_source, name) {
        (NameSource::DnsQuery, Some(name)) => Destination::DnsName {
            name: name.to_ascii_lowercase(),
        },
        (NameSource::Sni | NameSource::HttpHost, Some(name)) => Destination::Host {
            protocol,
            name: name.to_ascii_lowercase(),
            port: refusal.dst_port,
        },
        // `dns-cache`, `none`, and a newer source this build cannot name: the
        // address the guest actually used is the destination, and the name
        // stays evidence.
        _ => Destination::Address {
            protocol,
            ip: refusal.dst_ip,
            port: refusal.dst_port,
        },
    }
}

/// Which of the three kinds a `(site, layer)` pair is (§5).
///
/// Total with a wildcard arm, and the wildcard is the *common* path, not a
/// forward-compatibility formality: 15 of the runtime's 24 sites are not egress
/// decisions an allowance reaches, so they land there. Both enums are
/// `#[non_exhaustive]`, so the arm also gives a site or layer a later runtime
/// adds an answer instead of failing to compile. The fail-safe answer is
/// [`Kind::PolicyLock`], which offers no action — the wrong choice for a network
/// denial is an action that would not work, and the wrong choice for a policy
/// lock would be a promise this slice cannot keep.
pub(crate) fn classify(site: RefusalSite, layer: RefusalLayer) -> Kind {
    if matches!(layer, RefusalLayer::Platform) {
        return Kind::PolicyLock;
    }
    match site {
        RefusalSite::TcpSyn
        | RefusalSite::TcpHostname
        | RefusalSite::TlsSni
        | RefusalSite::Udp
        | RefusalSite::Icmp
        | RefusalSite::DnsQuery
        | RefusalSite::DnsResolver
        | RefusalSite::HttpAuthority => Kind::NetworkDenial,
        RefusalSite::SecretViolation => Kind::CredentialRefusal,
        _ => Kind::PolicyLock,
    }
}

pub(crate) mod feed;
pub(crate) mod log;

#[cfg(test)]
mod tests;
