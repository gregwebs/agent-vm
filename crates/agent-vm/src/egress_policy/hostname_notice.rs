//! The launch's hostname lines, collapsed (#631).
//!
//! Only the `==> Egress policy: allowing TLS to …` lines change: each egress
//! reference becomes `NAME (count)`, more than three bare names become a count,
//! `on ports 443` goes when 443 is the only intercepted port, and one pointer
//! line names the command that shows the whole table. Address, group, header, override, proxy and DNS lines are
//! untouched.

use super::EgressAuthority;
use super::view::{HostnameAttribution, written_index};
use crate::egress_reference::{EgressReference, EntryOrigin};

/// Bare names past this many are counted, not listed (#631).
const MAX_NAMED_BARE_HOSTS: usize = 3;
/// Printed once after the hostname lines when any of them hid a name.
const EGRESS_LIST_POINTER: &str = "==> list: agent-vm access egress";

/// Which tiers granted a line's names. Lines group by this, not by reference:
/// the references are now on the line itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tiers {
    user: bool,
    cli: bool,
    project: bool,
}

impl Tiers {
    fn of(attribution: &HostnameAttribution<'_>) -> Self {
        Self {
            user: granted(&attribution.user),
            cli: granted(&attribution.cli),
            project: attribution.recorded,
        }
    }

    /// `persisted grants`, `--allow-egress`, `project allowance`, joined
    /// " and "; `None` when it would say only `persisted grants`, which is
    /// every launch's default source and the noise this ticket removes.
    fn tag(self) -> Option<String> {
        let mut phrases = Vec::new();
        if self.user {
            phrases.push("persisted grants");
        }
        if self.cli {
            phrases.push("--allow-egress");
        }
        if self.project {
            phrases.push("project allowance");
        }
        match phrases.as_slice() {
            [] | ["persisted grants"] => None,
            _ => Some(phrases.join(" and ")),
        }
    }
}

fn granted(origin: &EntryOrigin<'_>) -> bool {
    origin.direct || !origin.via.is_empty()
}

impl EgressAuthority {
    pub(super) fn write_hostname_notices(
        &self,
        output: &mut impl std::io::Write,
    ) -> std::io::Result<()> {
        let Some(ports) = self.intercepted_ports() else {
            return Ok(());
        };
        // A non-443 intercepted port is TLS-only for every destination, so the
        // port text stays on every line the moment one exists.
        let show_ports = ports.to_vec() != [443];
        let show_sources = self.shows_sources();
        let order = self.reference_order();
        let attributions = self.hostname_attributions();
        // First-seen grouping keeps line order the rule traversal order;
        // hashing would reorder display.
        let mut groups: Vec<(Vec<u16>, Option<Tiers>, Vec<&HostnameAttribution<'_>>)> = Vec::new();
        for attribution in &attributions {
            let key = (
                attribution.ports.clone(),
                show_sources.then(|| Tiers::of(attribution)),
            );
            match groups.iter_mut().find(|(group_ports, group_tiers, _)| {
                *group_ports == key.0 && *group_tiers == key.1
            }) {
                Some((_, _, names)) => names.push(attribution),
                None => groups.push((key.0, key.1, vec![attribution])),
            }
        }
        let mut collapsed = false;
        for (group_ports, tiers, names) in &groups {
            let (list, hid) = line_items(names, &order);
            collapsed |= hid;
            let ports = if show_ports {
                format!(" on ports {}", joined_ports(group_ports))
            } else {
                String::new()
            };
            let tag = tiers
                .and_then(Tiers::tag)
                .map(|tag| format!(" ({tag})"))
                .unwrap_or_default();
            writeln!(
                output,
                "==> Egress policy: allowing TLS to {list}{ports}{tag}"
            )?;
        }
        if collapsed {
            writeln!(output, "{EGRESS_LIST_POINTER}")?;
        }
        Ok(())
    }
}

fn joined_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The comma list for one line, and whether it hid any name.
fn line_items<'a>(
    names: &[&HostnameAttribution<'a>],
    order: &[&'a EgressReference],
) -> (String, bool) {
    // A name granted by two references counts toward each, so this counts names
    // per reference rather than counting references per name.
    let mut counted: Vec<(usize, &EgressReference, usize)> = Vec::new();
    let mut bare: Vec<&str> = Vec::new();
    for attribution in names {
        let mut via: Vec<&EgressReference> = attribution.user.via.clone();
        for reference in &attribution.cli.via {
            if !via.contains(reference) {
                via.push(reference);
            }
        }
        if via.is_empty() {
            bare.push(attribution.name.as_str());
            continue;
        }
        for reference in via {
            match counted.iter_mut().find(|(_, seen, _)| *seen == reference) {
                Some((_, _, count)) => *count += 1,
                None => counted.push((written_index(order, reference), reference, 1)),
            }
        }
    }
    counted.sort_by_key(|(index, _, _)| *index);
    let mut items: Vec<String> = counted
        .iter()
        .map(|(_, reference, count)| format!("{} ({count})", reference.notice_label()))
        .collect();
    let hid = !items.is_empty() || bare.len() > MAX_NAMED_BARE_HOSTS;
    if bare.len() <= MAX_NAMED_BARE_HOSTS {
        items.extend(bare.iter().map(|name| (*name).to_owned()));
    } else if items.is_empty() {
        items.push(format!("{} hosts", bare.len()));
    } else {
        items.push(format!("and {} other hosts", bare.len()));
    }
    (items.join(", "), hid)
}
