//! Where a key sits in a config document — the one placement classifier beside
//! [`crate::config::RawConfig`] (#749 F2).
//!
//! TOML assigns a bare key to the most recent table header, so one spelling can
//! be a top-level key, a `[[tools]]` member, a `[[sources]]` member, a
//! `[network]` setting or a set definition depending only on where it appears.
//! Two policies ask this question and must answer it the same way:
//!
//! * the reader refuses a retired key at any readable site
//!   ([`crate::config::refuse_retired_keys`]), and
//! * the project-config writer (#737, ADR-0078) refuses a misplaced key only
//!   where its own narrow edit is concerned.
//!
//! This module answers *placement* and nothing else. It holds no policy, names
//! no field and never echoes a value: a caller decides what a site means.
//!
//! The walk is deliberately shallow. A tool's `mounts` array and its `env`
//! table are valid members with their own grammar, so a key nested one level
//! deeper (`env.allow_tools`, a mount declaration's text) is that grammar's
//! business and must never classify as misplaced. Only a *direct* member of the
//! six readable sites does.

/// One readable site in a config document.
///
/// `Tools`, `Sources`, `MountSet` and `EgressSet` carry the numeric declaration
/// the diagnostic names so two plantings in one file cannot be confused, and so
/// no tool name, alias or set name — config-chosen text — is ever echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Site {
    /// A key at the document root, before any table header.
    Root,
    /// A direct member of the `index`th `[[tools]]` declaration.
    Tool(usize),
    /// A direct member of the `index`th `[[sources]]` entry.
    Source(usize),
    /// A direct member of the `[network]` table.
    Network,
    /// A direct member of the `index`th `[mount_sets.*]` definition.
    MountSet(usize),
    /// A direct member of the `index`th `[egress_sets.*]` definition.
    EgressSet(usize),
}

impl Site {
    /// The value-safe spelling of this site, used as the diagnostic's prefix.
    pub(crate) fn label(self) -> String {
        match self {
            Self::Root => "root".to_owned(),
            Self::Tool(index) => format!("tools[{index}]"),
            Self::Source(index) => format!("sources[{index}]"),
            Self::Network => "[network]".to_owned(),
            Self::MountSet(index) => format!("[mount_sets] definition {index}"),
            Self::EgressSet(index) => format!("[egress_sets] definition {index}"),
        }
    }
}

/// The first site in a fixed walk order that directly declares `key`, or `None`.
///
/// The order is root, `[[tools]]`, `[[sources]]`, `[network]`, `[mount_sets]`,
/// `[egress_sets]`: a file that planted one key in several places reports the
/// root first and a tool before a set, so the diagnostic does not depend on map
/// iteration order.
///
/// Inline and dotted spellings need no separate case: `tools = [{ … }]`,
/// `network.allow_tools = 1` and `[mount_sets.NAME]` all produce the same
/// table-of-tables shape this reads, and a dotted key inside a declaration
/// (`allow_tools.x = 1`) is still a direct member of that declaration.
pub(crate) fn misplaced_key(document: &toml::Table, key: &str) -> Option<Site> {
    if document.contains_key(key) {
        return Some(Site::Root);
    }
    if let Some(index) = array_member_index(document.get("tools"), key) {
        return Some(Site::Tool(index));
    }
    if let Some(index) = array_member_index(document.get("sources"), key) {
        return Some(Site::Source(index));
    }
    if document
        .get("network")
        .and_then(toml::Value::as_table)
        .is_some_and(|network| network.contains_key(key))
    {
        return Some(Site::Network);
    }
    if let Some(index) = table_member_index(document.get("mount_sets"), key) {
        return Some(Site::MountSet(index));
    }
    if let Some(index) = table_member_index(document.get("egress_sets"), key) {
        return Some(Site::EgressSet(index));
    }
    None
}

/// The first declaration of a table that is normally an array of tables
/// (`[[tools]]`/`[[sources]]`) and directly declares `key`.
///
/// A dotted spelling (`sources.image = "x"`, `tools.allow_tools = []`) produces
/// one *table* rather than an array of tables; it is declaration 0, and the
/// caller's question — is the key a direct member of this site? — is the same
/// one, so it must classify rather than slip through as "absent".
fn array_member_index(value: Option<&toml::Value>, key: &str) -> Option<usize> {
    let value = value?;
    if let Some(entries) = value.as_array() {
        return entries.iter().position(|entry| {
            entry
                .as_table()
                .is_some_and(|table| table.contains_key(key))
        });
    }
    value
        .as_table()
        .is_some_and(|table| table.contains_key(key))
        .then_some(0)
}

/// The first definition table of a set table (`[mount_sets]`/`[egress_sets]`)
/// that directly declares `key` — or whose own name **is** `key`.
///
/// The name half matters for a retired key: a bare key written after the header
/// (`[egress_sets]` then `allow_tools = [...]`) does not sit inside a
/// definition, it *becomes* one, so a member-only walk accepted it as a legal
/// set name (#749 V3). A later bare key assigns to the most recent header, so
/// every set definition would have the same hole.
fn table_member_index(value: Option<&toml::Value>, key: &str) -> Option<usize> {
    value
        .and_then(toml::Value::as_table)
        .and_then(|definitions| {
            definitions.iter().position(|(name, definition)| {
                name == key
                    || definition
                        .as_table()
                        .is_some_and(|table| table.contains_key(key))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the body as a TOML document. Every case below is *valid* TOML:
    /// placement is classified from shape, never from a syntax error.
    fn document(body: &str) -> toml::Table {
        body.parse().expect("the case must be valid TOML")
    }

    #[test]
    fn the_root_is_its_own_site() {
        assert_eq!(
            misplaced_key(&document("allow_tools = [\"t\"]\n"), "allow_tools"),
            Some(Site::Root)
        );
        // A dotted root key creates the same table the plain spelling does.
        assert_eq!(
            misplaced_key(&document("allow_tools.x = 1\n"), "allow_tools"),
            Some(Site::Root)
        );
        // Empty is present: presence, not contents, is what is classified.
        assert_eq!(
            misplaced_key(&document("allow_tools = []\n"), "allow_tools"),
            Some(Site::Root)
        );
    }

    #[test]
    fn a_tool_declaration_is_its_own_site_in_every_spelling() {
        for body in [
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nallow_tools = [\"t\"]\n",
            "tools = [{ name = \"t\", command = \"t\", allow_tools = [\"t\"] }]\n",
            "[[tools]]\nname = \"t\"\ncommand = \"t\"\nallow_tools.x = 1\n",
        ] {
            assert_eq!(
                misplaced_key(&document(body), "allow_tools"),
                Some(Site::Tool(0)),
                "{body}"
            );
        }
        // The index is the declaration the key landed in, not the first one.
        let two = "[[tools]]\nname = \"a\"\ncommand = \"a\"\n\
                   [[tools]]\nname = \"b\"\ncommand = \"b\"\nallow_tools = []\n";
        assert_eq!(
            misplaced_key(&document(two), "allow_tools"),
            Some(Site::Tool(1))
        );
    }

    #[test]
    fn a_source_entry_is_its_own_site_in_every_spelling() {
        for body in [
            "[[sources]]\nname = \"repo\"\npath = \"x.toml\"\nallow_tools = []\n",
            "sources = [{ name = \"repo\", path = \"x.toml\", allow_tools = [] }]\n",
        ] {
            assert_eq!(
                misplaced_key(&document(body), "allow_tools"),
                Some(Site::Source(0)),
                "{body}"
            );
        }
    }

    #[test]
    fn the_network_table_is_its_own_site() {
        assert_eq!(
            misplaced_key(
                &document("[network]\nallow_lan = true\nallow_tools = []\n"),
                "allow_tools"
            ),
            Some(Site::Network)
        );
        // Dotted: `network.allow_tools` produces the same member.
        assert_eq!(
            misplaced_key(&document("network.allow_tools = []\n"), "allow_tools"),
            Some(Site::Network)
        );
        // A `[network]` setting that a tool declares is still not the root's.
        assert_eq!(
            misplaced_key(&document("[network]\npoison = 1\n"), "mounts"),
            None
        );
        // ... but a member of the table itself is this site, which is why a
        // caller asks only about keys it retires.
        assert_eq!(
            misplaced_key(&document("[network]\nallow_lan = true\n"), "allow_lan"),
            Some(Site::Network)
        );
    }

    #[test]
    fn both_set_tables_are_their_own_site() {
        assert_eq!(
            misplaced_key(
                &document("[mount_sets.tools]\nallow_tools = []\n"),
                "allow_tools"
            ),
            Some(Site::MountSet(0))
        );
        assert_eq!(
            misplaced_key(
                &document("mount_sets = { tools = { allow_tools = [] } }\n"),
                "allow_tools"
            ),
            Some(Site::MountSet(0))
        );
        assert_eq!(
            misplaced_key(
                &document("[egress_sets.proxy]\nallow_tools = []\n"),
                "allow_tools"
            ),
            Some(Site::EgressSet(0))
        );
        assert_eq!(
            misplaced_key(
                &document("egress_sets = { proxy = { allow_tools = [] } }\n"),
                "allow_tools"
            ),
            Some(Site::EgressSet(0))
        );
    }

    /// A dotted spelling of a normally-array site is still that site: TOML hands
    /// the walk a table instead of an array of tables, and the key is just as
    /// misplaced there as inside `[[tools]]`.
    #[test]
    fn a_dotted_array_site_is_its_own_site() {
        for (body, key, expected) in [
            ("sources.image = \"ref\"\n", "image", Site::Source(0)),
            ("tools.allow_tools = []\n", "allow_tools", Site::Tool(0)),
        ] {
            assert_eq!(
                misplaced_key(&document(body), key),
                Some(expected),
                "{body}"
            );
        }
        // The negative: a key one level below the dotted site stays that
        // grammar's, exactly as `[tools.env]` does.
        assert_eq!(
            misplaced_key(&document("sources.extra.image = \"ref\"\n"), "image"),
            None
        );
    }

    /// The pinned negatives: a tool's `mounts` and `env` are valid members whose
    /// own grammar owns whatever sits inside them, so neither one can make a
    /// retired key classify.
    #[test]
    fn a_tools_mounts_and_env_never_classify() {
        let body = "[[tools]]\nname = \"t\"\ncommand = \"t\"\n\
                    mounts = [\"/a:/b:ro\"]\n\
                    env = { allow_tools = \"not-a-key\", mounts = \"neither\" }\n";
        let document = document(body);
        assert_eq!(
            misplaced_key(&document, "allow_tools"),
            None,
            "a tool's own env is not a readable site for the key"
        );
        // The same spellings in a tool definition *are* valid there, which is
        // why a caller must ask this classifier about a retired key only.
        assert_eq!(misplaced_key(&document, "mounts"), Some(Site::Tool(0)));
        assert_eq!(misplaced_key(&document, "env"), Some(Site::Tool(0)));
    }

    /// Only a direct member classifies: a key one table deeper than any site —
    /// a tool's `env`, a `[network.foo]` sub-table, a set definition's own
    /// nested table — is that grammar's business, not a placement.
    #[test]
    fn keys_below_a_site_do_not_classify() {
        let document = document(
            "[network.foo]\nallow_tools = 1\n\
             [[tools]]\nname = \"t\"\ncommand = \"t\"\n\
             [tools.env]\nallow_tools = 1\n",
        );
        for key in ["allow_tools", "sources", "mounts"] {
            assert_eq!(misplaced_key(&document, key), None, "{key}");
        }
    }

    /// The walk order is fixed: a file that plants the key twice reports the
    /// root, then a tool, then a set — never a map-order coincidence.
    #[test]
    fn a_repeated_plant_reports_the_first_site_in_walk_order() {
        let everywhere = document(
            "allow_tools = []\n\
             [network]\nallow_tools = []\n\
             [[tools]]\nname = \"t\"\ncommand = \"t\"\nallow_tools = []\n",
        );
        assert_eq!(misplaced_key(&everywhere, "allow_tools"), Some(Site::Root));
        let network_before_tools = document(
            "[network]\nallow_tools = []\n\
             [mount_sets.one]\nallow_tools = []\n",
        );
        assert_eq!(
            misplaced_key(&network_before_tools, "allow_tools"),
            Some(Site::Network)
        );
    }

    #[test]
    fn labels_name_the_site_without_echoing_a_name() {
        assert_eq!(Site::Root.label(), "root");
        assert_eq!(Site::Tool(2).label(), "tools[2]");
        assert_eq!(Site::Source(1).label(), "sources[1]");
        assert_eq!(Site::Network.label(), "[network]");
        assert_eq!(Site::MountSet(0).label(), "[mount_sets] definition 0");
        assert_eq!(Site::EgressSet(0).label(), "[egress_sets] definition 0");
    }
}
