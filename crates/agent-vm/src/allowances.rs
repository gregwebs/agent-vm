//! The project allowance record, read side: one facade over one authority file.
//!
//! `$HOME/.config/agent-vm/allowances.json` holds **project allowances** — egress
//! authority bound to one project's path identity (CONTEXT.md). This module is
//! its whole read side: the launch takes [`for_launch`]'s view into the one
//! policy computation, `agent-vm access` asks [`ProjectAllowances::covers`] which
//! refusals a record names, and `agent-vm doctor` prints [`doctor_section`].
//! PR 2's writer and runtime `apply` land behind this same facade.
//!
//! Three functions, one query and three accessors are the entire interface. That
//! is the deletion test: without this module the schema, the trust measurement,
//! the reopen rule, damage classification, the coverage table and all of the
//! wording would reappear in `run.rs`, `access_cmd.rs` and `doctor.rs`.
//!
//! # Three levels, kept apart (ADR-0065 P5)
//!
//! * **Recorded** — a usable record for this project names the entry's
//!   destination. This is [`ProjectAllowances::covers`]: pure, syntactic, and the
//!   only level this release computes.
//! * **Admissible** — the runtime's own evaluator would admit the flow under a
//!   policy containing that record. Never computed in production; it exists as
//!   the tests' oracle.
//! * **Applied** — this session's runtime had the record in force. Unknowable
//!   here, which is why the ACTION cell says "not confirmed for this session"
//!   rather than claiming the session allowed anything.
//!
//! `covers` errs towards *not recorded* wherever it cannot be exact, and every
//! conservative negative has a named test. It is deliberately not a mirror of
//! the runtime's destination predicate: it compares destinations only
//! like-for-like, which is what makes the claim shrink-only.
//!
//! # A broken store never fails a launch
//!
//! Every state other than `Absent` produces exactly one notice, and every one of
//! them leaves the launch with its configured authority. The two launch
//! refusals that exist are the guard's (ADR-0065 E1/E2), not this module's.

mod store;

use std::path::{Path, PathBuf};

use microsandbox_network::policy::{
    Action, Destination as RuleDestination, Direction, DomainName, NetworkPolicy, Protocol, Rule,
};

use crate::egress_grammar::AllowanceError;
use crate::egress_hostname::{HostnameAllowance, InterceptedPorts, domain_rules};
use crate::egress_policy::Allowance;
use crate::image_pin::ProjectId;
use crate::project::ProjectDir;
use crate::refusal::{Destination, Kind, RefusalEntry};

/// How many unusable destinations the one warning names before it counts the
/// rest. Three is enough to identify a typo or a stale spelling; the rest are a
/// number, because a hand-edited file can hold thousands (ADR-0065 §5.3).
const NAMED_UNUSABLE: usize = 3;

/// One usable record: a canonical destination and when it was recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProjectAllowance {
    destination: Allowance,
    recorded_ms: i64,
}

impl ProjectAllowance {
    pub(crate) fn destination(&self) -> &Allowance {
        &self.destination
    }

    pub(crate) fn recorded_ms(&self) -> i64 {
        self.recorded_ms
    }
}

/// One project's usable records, deduplicated by parsed value, in file order.
///
/// This is D7's set: the facade hands the policy computation a set and the
/// computation merges it, so neither side names the other's authority type.
#[derive(Debug, Default)]
pub(crate) struct ProjectAllowances {
    entries: Vec<ProjectAllowance>,
}

impl ProjectAllowances {
    pub(crate) fn destinations(&self) -> impl Iterator<Item = &Allowance> {
        self.entries.iter().map(ProjectAllowance::destination)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// ADR-0065 P5's *recorded* level: does a usable record for this project
    /// name this refusal's destination?
    ///
    /// The first matching record in file order wins, because that is the record
    /// the ACTION cell names. Every gate below is syntactic — protocol, port,
    /// CIDR membership, exact name, and the runtime's own site/name-source
    /// vocabulary — so the answer never depends on the launch policy, the DNS
    /// cache or any session state.
    pub(crate) fn covers(&self, entry: &RefusalEntry) -> Option<Coverage<'_>> {
        if entry.key.kind != Kind::NetworkDenial || entry.layer == "platform" {
            return None;
        }
        let ports = self.intercepted_ports();
        match &entry.key.destination {
            // A DNS query names no address, so only a name rule can answer, and
            // the runtime's own pure predicate is the probe (ADR-0065 §5.3).
            Destination::DnsName { name } => {
                if entry.last_site != "dns-query" {
                    return None;
                }
                let domain: DomainName = name.parse().ok()?;
                self.entries
                    .iter()
                    .find(|record| admits_dns_query(record, &domain, ports.as_ref()))
                    .map(Coverage::Recorded)
            }
            _ => {
                let probe = probe(entry)?;
                self.entries
                    .iter()
                    .find(|record| {
                        rules_of(record, ports.as_ref())
                            .iter()
                            .any(|rule| admits(rule, &probe))
                    })
                    .map(Coverage::Recorded)
            }
        }
    }

    /// A set built from spellings: the seam `network`'s and `access`'s tests
    /// use to hand the policy computation records without a file. Test-only,
    /// because a production caller must never assemble a set the schema did not
    /// check.
    #[cfg(test)]
    pub(crate) fn for_tests(spellings: &[&str]) -> Self {
        let mut entries: Vec<ProjectAllowance> = Vec::new();
        for text in spellings {
            let destination = Allowance::parse(text).expect(text);
            if !entries.iter().any(|held| held.destination == destination) {
                entries.push(ProjectAllowance {
                    destination,
                    recorded_ms: 0,
                });
            }
        }
        Self { entries }
    }

    /// The port set a hostname record's rules are built from: every recorded
    /// hostname contributes, exactly as the launch's own producer does, so a
    /// bare recorded name covers the ports a *recorded* `tcp://NAME:PORT` adds
    /// and no others (ADR-0065 §4.3).
    fn intercepted_ports(&self) -> Option<InterceptedPorts> {
        let names: Vec<HostnameAllowance> = self
            .entries
            .iter()
            .filter_map(|record| match &record.destination {
                Allowance::Address(_) => None,
                Allowance::Hostname(hostname) => Some(hostname.clone()),
            })
            .collect();
        InterceptedPorts::for_hostnames(&names)
    }
}

/// ADR-0065 P5's levels. This release can only know `Recorded`; PR 2 adds
/// `Applied { record, revision }` from the session's runtime. "Admissible" is
/// never a variant: it exists only as a test oracle.
pub(crate) enum Coverage<'a> {
    Recorded(&'a ProjectAllowance),
}

/// Everything one command learned about the store, ready to render.
///
/// The notice is part of the value rather than something the caller derives, so
/// no caller can reveal a store problem twice or in two words.
#[derive(Debug)]
pub(crate) struct ProjectView {
    file: Option<PathBuf>,
    allowances: ProjectAllowances,
    notice: Option<String>,
}

impl ProjectView {
    pub(crate) fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    pub(crate) fn allowances(&self) -> &ProjectAllowances {
        &self.allowances
    }

    /// Escaped, one line, with no `warning: ` prefix: the caller owns that
    /// framing, and it differs per command.
    pub(crate) fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            file: None,
            allowances: ProjectAllowances::default(),
            notice: None,
        }
    }
}

/// The launch's view: this project's recorded allowances, or why there are none.
pub(crate) fn for_launch(project: &ProjectDir) -> ProjectView {
    host_view(&ProjectId::of(project))
}

/// The same view for a command that has only the identity.
pub(crate) fn host_view(project: &ProjectId) -> ProjectView {
    let (store, host_error) = host_store();
    view(store.as_ref(), host_error, project)
}

fn host_store() -> (Option<store::Store>, Option<anyhow::Error>) {
    match store::Store::host() {
        Ok(store) => (store, None),
        Err(error) => (None, Some(error)),
    }
}

/// One read, one classification, one notice at most.
fn view(
    store: Option<&store::Store>,
    host_error: Option<anyhow::Error>,
    project: &ProjectId,
) -> ProjectView {
    let Some(store) = store else {
        // `$HOME` unset is not a problem to report: no user config is read at
        // all then (ADR-0038), so there is nothing to be wrong with.
        return ProjectView {
            file: None,
            allowances: ProjectAllowances::default(),
            notice: host_error.map(|error| {
                format!(
                    "project allowances not read: {}",
                    crate::one_line::text(&format!("{error:#}"))
                )
            }),
        };
    };
    from_read(store.read(), store.file(), project)
}

/// The classification turned into a view. Separate from [`view`] so a test can
/// drive every read state without a filesystem, which is what keeps the wording
/// and the selection testable on their own.
fn from_read(read: store::Read, file: PathBuf, project: &ProjectId) -> ProjectView {
    let (allowances, notice) = match read {
        store::Read::Absent => (ProjectAllowances::default(), None),
        store::Read::Current { records, .. } => {
            let (allowances, unusable) = select(&records, project);
            let notice = unusable_notice(&file, &unusable);
            (allowances, notice)
        }
        store::Read::Newer { v, .. } => (
            ProjectAllowances::default(),
            Some(format!(
                "project allowances not applied: {} was written by a newer agent-vm (version {v}); this version applies none of it",
                crate::one_line::quoted_path(&file)
            )),
        ),
        store::Read::NotUsed(problem) => (
            ProjectAllowances::default(),
            Some(problem_notice(&file, &problem)),
        ),
    };
    ProjectView {
        file: Some(file),
        allowances,
        notice,
    }
}

/// This project's usable records and the spellings that did not parse.
///
/// A record for another project is neither: it is not an error and not ours
/// (ADR-0065 P2), which is what makes a moved or copied project inherit nothing.
fn select(
    records: &[store::StoredRecord],
    project: &ProjectId,
) -> (ProjectAllowances, Vec<(String, AllowanceError)>) {
    let mut entries: Vec<ProjectAllowance> = Vec::new();
    let mut unusable: Vec<(String, AllowanceError)> = Vec::new();
    for record in records
        .iter()
        .filter(|record| record.project == project.as_str())
    {
        match Allowance::parse(&record.destination) {
            Ok(destination) => {
                // Canonical value, not text: `10.0.0.5` and `10.0.0.5/32` are
                // one allowance, exactly as `resolve` deduplicates them.
                if !entries.iter().any(|held| held.destination == destination) {
                    entries.push(ProjectAllowance {
                        destination,
                        recorded_ms: record.recorded_ms,
                    });
                }
            }
            Err(error) => {
                if !unusable.iter().any(|(text, _)| text == &record.destination) {
                    unusable.push((record.destination.clone(), error));
                }
            }
        }
    }
    (ProjectAllowances { entries }, unusable)
}

/// The one warning for records this build cannot parse.
fn unusable_notice(file: &Path, unusable: &[(String, AllowanceError)]) -> Option<String> {
    let (first, rest) = unusable.split_first()?;
    let named: Vec<String> = std::iter::once(first)
        .chain(rest.iter())
        .take(NAMED_UNUSABLE)
        .map(|(text, error)| format!("\"{}\" ({error})", crate::config::escape_str(text)))
        .collect();
    let mut sentence = format!(
        "{} project allowance(s) in {} not applied: {}",
        unusable.len(),
        crate::one_line::quoted_path(file),
        named.join(", ")
    );
    if unusable.len() > NAMED_UNUSABLE {
        sentence.push_str(&format!(" and {} more", unusable.len() - NAMED_UNUSABLE));
    }
    Some(sentence)
}

/// The one warning for a file that exists but is not in force (ADR-0065 §5.3).
fn problem_notice(file: &Path, problem: &store::Problem) -> String {
    let file = crate::one_line::quoted_path(file);
    match problem {
        store::Problem::Damaged(damage) => format!(
            "project allowances not applied: {file} could not be used ({}); this version does not repair it — move it aside to start over",
            damage.clause()
        ),
        store::Problem::Untrusted(refusal) => format!(
            "project allowances not applied: {file} {}; a guest or another account may have written it, so review it before removing it",
            refusal_clause(refusal)
        ),
        store::Problem::Unreadable(error) => {
            format!("project allowances not applied: {file} could not be read ({error})")
        }
        store::Problem::Unsettled => format!(
            "project allowances not applied: {file} changed while being read; the next launch reads it again"
        ),
    }
}

/// The kernel's verdict in this file's own words. One row per
/// `AuthorityRefusal`, so a new verdict fails to compile until it has a clause.
fn refusal_clause(refusal: &crate::config_authority::AuthorityRefusal) -> String {
    use crate::config_authority::AuthorityRefusal::*;
    match refusal {
        FileOwner => "is owned by another user".to_owned(),
        FileWritable => "is group- or other-writable".to_owned(),
        FileLinks(nlinks) => format!("has {nlinks} hard links"),
        ThroughSymlink => "is a symbolic link".to_owned(),
        DirOwner => "is in a directory owned by another user".to_owned(),
        DirWritable => "is in a group- or other-writable directory".to_owned(),
        DirNotDirectory => "is not in a directory".to_owned(),
    }
}

/// What one refusal entry would have to name, when it names something this
/// query can compare at all.
enum Target<'a> {
    Address(std::net::IpAddr),
    Name(&'a str),
}

struct Probe<'a> {
    protocol: Protocol,
    port: Option<u16>,
    target: Target<'a>,
}

/// The entry's destination as a comparable probe, or `None` when this release
/// never answers "recorded" for that shape (ADR-0065 §5.3's gated sites).
fn probe(entry: &RefusalEntry) -> Option<Probe<'_>> {
    match &entry.key.destination {
        Destination::Address {
            protocol,
            ip: Some(ip),
            port,
        } if matches!(entry.last_site.as_str(), "tcp-syn" | "udp" | "icmp") => Some(Probe {
            protocol: wire_protocol(protocol)?,
            port: *port,
            // `to_canonical` is the runtime's `normalize_ip_addr`: a v4-mapped
            // v6 address is the v4 address for a `Cidr` rule.
            target: Target::Address(ip.to_canonical()),
        }),
        Destination::Host {
            protocol,
            name,
            port: Some(port),
        } if protocol == "tcp"
            && matches!(entry.last_site.as_str(), "tls-sni" | "tcp-hostname")
            && entry.name.as_ref().is_some_and(|name| name.source == "sni") =>
        {
            Some(Probe {
                protocol: Protocol::Tcp,
                port: Some(*port),
                target: Target::Name(name),
            })
        }
        _ => None,
    }
}

/// The runtime's wire protocol value, for the four a rule can filter on.
fn wire_protocol(wire: &str) -> Option<Protocol> {
    match wire {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "icmpv4" => Some(Protocol::Icmpv4),
        "icmpv6" => Some(Protocol::Icmpv6),
        _ => None,
    }
}

/// One record's rules, from the launch's own producers.
///
/// Nothing here re-implements rule assembly: an address record's rule is
/// `EgressAllowance::rule`, and a hostname record's are `domain_rules` over the
/// recorded port set.
fn rules_of(record: &ProjectAllowance, ports: Option<&InterceptedPorts>) -> Vec<Rule> {
    match &record.destination {
        Allowance::Address(address) => vec![address.rule()],
        Allowance::Hostname(hostname) => match ports {
            Some(ports) => domain_rules(std::slice::from_ref(hostname), ports),
            None => Vec::new(),
        },
    }
}

/// The record-level syntactic test.
///
/// Destinations are compared only like-for-like — `Cidr` against an address,
/// `Domain` against a name — so a rule that the runtime would match through the
/// DNS cache, or a `Cidr` rule against a hostname probe, is *never* recorded.
/// That is the conservative direction: it can only refuse to claim coverage.
fn admits(rule: &Rule, probe: &Probe<'_>) -> bool {
    rule.action == Action::Allow
        && matches!(rule.direction, Direction::Egress | Direction::Any)
        && (rule.protocols.is_empty() || rule.protocols.contains(&probe.protocol))
        && match probe.port {
            None => rule.ports.is_empty(),
            Some(port) => {
                rule.ports.is_empty() || rule.ports.iter().any(|range| range.contains(port))
            }
        }
        && match (&rule.destination, &probe.target) {
            (RuleDestination::Cidr(network), Target::Address(address)) => {
                network.contains(*address)
            }
            (RuleDestination::Domain(domain), Target::Name(name)) => domain.as_str() == *name,
            _ => false,
        }
}

/// A DNS query answered by one record: the runtime's pure predicate over that
/// record's own rules, which is a probe of the grammar and not the launch policy.
fn admits_dns_query(
    record: &ProjectAllowance,
    name: &DomainName,
    ports: Option<&InterceptedPorts>,
) -> bool {
    let policy = NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: rules_of(record, ports),
    };
    policy.evaluate_dns_query(name, Protocol::Udp, 53) == Action::Allow
}

#[cfg(test)]
mod tests;
