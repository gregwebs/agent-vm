//! Parsing for the top-level `allow_tools = [...]` authorization list (#735).
//!
//! A `[[tools]]` block is an inert **declaration**; `allow_tools` is what turns a
//! declaration into a launch verb. Splitting the two is what lets a sourced file
//! describe tools without granting them, and it is why this module exists on its
//! own: every rule here is a grammar rule over one TOML value, with no filesystem
//! access, so it is table-testable and #736/#739 can validate a project list
//! before opening a source.
//!
//! Two entry forms, one per scope:
//!
//! - **Unqualified** (`"pi"`) resolves against the `[[tools]]` of the file that
//!   wrote the entry. Legal in both scopes.
//! - **Qualified** (`"repo:app"`) resolves against the source bound to `repo`.
//!   Legal only in the project config, because only it declares `sources`
//!   (ADR-0074). `:` is therefore unambiguous: [`crate::config::tool_name_rejection`]
//!   refuses it in a tool name.
//!
//! Value safety (see `config`'s module docs): every message below names the file
//! and an `allow_tools[N]` index and never echoes the entry, the alias or the
//! name it refused.

use crate::config::ToolName;
use crate::config_sources::SourceAlias;
use std::path::Path;

/// Which file wrote the list. The only difference between the two scopes is
/// whether a qualified `<alias>:<name>` entry is legal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllowToolScope {
    /// Any sourced file: the default user config, or an `allow = true` source
    /// (ADR-0076 R4.4). Unqualified entries only — a sourced file can authorize
    /// its own `[[tools]]` and nothing else.
    SourceFile,
    /// `~/.config/agent-vm/projects/<id>/config.toml`: unqualified or qualified.
    ProjectConfig,
}

/// One authorized tool, before it is resolved against the loaded files.
///
/// Both variants hold a [`ToolName`], parsed here, so an `AllowToolEntry` can
/// never name a tool no declaration could have — and no consumer re-validates.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AllowToolEntry {
    Local(ToolName),
    Qualified { alias: SourceAlias, name: ToolName },
}

impl AllowToolEntry {
    /// The tool name, unqualified.
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Local(name) => name.as_str(),
            Self::Qualified { name, .. } => name.as_str(),
        }
    }

    /// The source alias a qualified entry names, or `None` for the same file.
    pub(crate) fn alias(&self) -> Option<&SourceAlias> {
        match self {
            Self::Local(_) => None,
            Self::Qualified { alias, .. } => Some(alias),
        }
    }
}

/// One `allow = true` source's own authorizations, admitted for inheritance
/// (ADR-0076 R4.4).
///
/// The private field is the point: [`Self::from_authorized`] is the only
/// constructor and it demands an [`AdoptedAuthority`] token, so a file's own
/// `allow_tools` can only reach a launch verb through a verified read (or, from
/// #736, approved bytes). A file whose `allow_tools` never made it into
/// `AuthorityTriggers` finds no token and is refused rather than silently
/// inheriting nothing.
#[derive(Debug)]
pub(crate) struct AdoptedAllowTools {
    file: std::path::PathBuf,
    entries: Vec<AllowToolEntry>,
}

impl AdoptedAllowTools {
    pub(crate) fn from_authorized(
        authority: &crate::config_authority::AdoptedAuthority<'_>,
        value: &toml::Value,
    ) -> anyhow::Result<Self> {
        let file = authority.file();
        let entries = parse(value, file, AllowToolScope::SourceFile)?;
        Ok(Self {
            file: file.to_path_buf(),
            entries,
        })
    }

    /// The entries as parsed, in the file's own order.
    pub(crate) fn entries(&self) -> &[AllowToolEntry] {
        &self.entries
    }

    pub(crate) fn file(&self) -> &Path {
        &self.file
    }
}

/// Parse a present `allow_tools` value. Pure: no filesystem access.
///
/// Presence is decided by the caller (`RawConfig::allow_tools` is an `Option`
/// precisely so an authority decision can be made before the schema is), so this
/// sees `[]`, a table and a number alike.
pub(crate) fn parse(
    value: &toml::Value,
    file: &Path,
    scope: AllowToolScope,
) -> anyhow::Result<Vec<AllowToolEntry>> {
    let Some(items) = value.as_array() else {
        return Err(prefix(file, None, "must be an array of strings"));
    };
    let mut entries = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        entries.push(parse_entry(item, file, scope, index)?);
    }
    Ok(entries)
}

fn parse_entry(
    item: &toml::Value,
    file: &Path,
    scope: AllowToolScope,
    index: usize,
) -> anyhow::Result<AllowToolEntry> {
    let Some(text) = item.as_str() else {
        return Err(prefix(file, Some(index), "must be a string"));
    };
    // Wildcards first, in both scopes: `home:*` in a user config is a wildcard
    // mistake, not a qualified-entry mistake, so it gets the wildcard sentence.
    if text.contains('*') {
        return Err(prefix(
            file,
            Some(index),
            "wildcards (\"*\") are not permitted in allow_tools; list each tool explicitly",
        ));
    }
    let Some((alias, name)) = text.split_once(':') else {
        return Ok(AllowToolEntry::Local(valid_name(file, index, text)?));
    };
    if scope == AllowToolScope::SourceFile {
        return Err(prefix(
            file,
            Some(index),
            "qualified <alias>:<tool> entries are only valid in the project config; a sourced \
             file can only authorize its own [[tools]]",
        ));
    }
    let Some(alias) = SourceAlias::parse(alias) else {
        return Err(prefix(
            file,
            Some(index),
            "names a source alias that is not a valid alias ([a-z][a-z0-9_-]{0,31})",
        ));
    };
    Ok(AllowToolEntry::Qualified {
        alias,
        name: valid_name(file, index, name)?,
    })
}

/// The one tool-name rule, shared with `[[tools]]` declarations: a name this
/// refuses is a name no declaration can have, so it is a syntax error here
/// rather than a resolution one.
fn valid_name(file: &Path, index: usize, raw: &str) -> anyhow::Result<ToolName> {
    ToolName::parse(raw).ok_or_else(|| {
        prefix(
            file,
            Some(index),
            "invalid tool name; a tool name must be a non-empty command token with no \
             whitespace, control characters, '/', or ':', not starting with '-', and not '.', \
             '..', '*' or a reserved subcommand",
        )
    })
}

/// `config: "<file>": allow_tools[N]: <message>`, or `allow_tools: <message>` for
/// a refusal about the whole list.
fn prefix(file: &Path, index: Option<usize>, message: &str) -> anyhow::Error {
    let field = match index {
        Some(index) => format!("allow_tools[{index}]"),
        None => "allow_tools".to_owned(),
    };
    anyhow::anyhow!(
        "config: {}: {field}: {message}",
        crate::one_line::quoted_path(file)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file() -> PathBuf {
        PathBuf::from("/home/u/.config/agent-vm/config.toml")
    }

    fn parse_user(text: &str) -> anyhow::Result<Vec<AllowToolEntry>> {
        parse(&toml_value(text), &file(), AllowToolScope::SourceFile)
    }

    fn parse_project(text: &str) -> anyhow::Result<Vec<AllowToolEntry>> {
        parse(&toml_value(text), &file(), AllowToolScope::ProjectConfig)
    }

    #[test]
    fn accepts_local_qualified_and_empty_lists() {
        assert_eq!(
            parse_user(r#"["pi", "claude"]"#).unwrap(),
            vec![
                AllowToolEntry::Local(ToolName::parse("pi").unwrap()),
                AllowToolEntry::Local(ToolName::parse("claude").unwrap()),
            ]
        );
        assert_eq!(
            parse_project(r#"["repo:app", "home:pi"]"#).unwrap(),
            vec![
                AllowToolEntry::Qualified {
                    alias: SourceAlias::for_test("repo"),
                    name: ToolName::parse("app").unwrap(),
                },
                AllowToolEntry::Qualified {
                    alias: SourceAlias::for_test("home"),
                    name: ToolName::parse("pi").unwrap(),
                },
            ]
        );
        assert_eq!(parse_user("[]").unwrap(), Vec::new());
        assert_eq!(parse_project("[]").unwrap(), Vec::new());
    }

    /// Every refusal is value-safe: the entry text never reaches the sentence, so
    /// a tool name that is a secret stays out of a diagnostic.
    #[test]
    fn refusals_never_echo_the_entry() {
        const SECRET: &str = "SECRET-735";
        for (text, scope, expected_field) in [
            (r#"["*"]"#, AllowToolScope::SourceFile, "allow_tools[0]"),
            (
                r#"["repo:*"]"#,
                AllowToolScope::ProjectConfig,
                "allow_tools[0]",
            ),
            (
                r#"["*:pi"]"#,
                AllowToolScope::ProjectConfig,
                "allow_tools[0]",
            ),
            (
                r#"["*:*"]"#,
                AllowToolScope::ProjectConfig,
                "allow_tools[0]",
            ),
            (
                r#"["repo:pi"]"#,
                AllowToolScope::SourceFile,
                "allow_tools[0]",
            ),
            (
                &format!(r#"["{}:{SECRET}"]"#, "R".repeat(33)),
                AllowToolScope::ProjectConfig,
                "allow_tools[0]",
            ),
            (
                &format!(r#"["repo:{SECRET}/x"]"#),
                AllowToolScope::ProjectConfig,
                "allow_tools[0]",
            ),
            (
                &format!(r#"["{SECRET}/x"]"#),
                AllowToolScope::ProjectConfig,
                "allow_tools[0]",
            ),
            ("123", AllowToolScope::SourceFile, "allow_tools"),
            ("[1]", AllowToolScope::SourceFile, "allow_tools[0]"),
        ] {
            let error = parse(&toml_value(text), &file(), scope)
                .unwrap_err()
                .to_string();
            assert!(
                error.starts_with(&format!(
                    "config: \"/home/u/.config/agent-vm/config.toml\": {expected_field}: "
                )),
                "{text}: {error}"
            );
            assert!(!error.contains(SECRET), "{text}: {error}");
            assert!(!error.contains("Rrr"), "{text}: {error}");
        }
    }

    fn toml_value(text: &str) -> toml::Value {
        let document: toml::Table = format!("v = {text}").parse().unwrap();
        document["v"].clone()
    }

    #[test]
    fn each_grammar_rule_has_a_sentence() {
        let message = |text: &str, scope| {
            parse(&toml_value(text), &file(), scope)
                .unwrap_err()
                .to_string()
        };
        assert!(
            message("123", AllowToolScope::SourceFile)
                .ends_with("allow_tools: must be an array of strings")
        );
        assert!(
            message("[1]", AllowToolScope::SourceFile)
                .ends_with("allow_tools[0]: must be a string")
        );
        assert!(message(r#"["*"]"#, AllowToolScope::SourceFile).ends_with(
            "allow_tools[0]: wildcards (\"*\") are not permitted in allow_tools; list each tool \
             explicitly"
        ));
        assert!(
            message(r#"["repo:pi"]"#, AllowToolScope::SourceFile).ends_with(
                "allow_tools[0]: qualified <alias>:<tool> entries are only valid in the project \
             config; a sourced file can only authorize its own [[tools]]"
            )
        );
        assert!(
            message(r#"["Repo:pi"]"#, AllowToolScope::ProjectConfig).ends_with(
                "allow_tools[0]: names a source alias that is not a valid alias \
                 ([a-z][a-z0-9_-]{0,31})"
            )
        );
        // `:` is forbidden in a tool name, so a second `:` cannot be a name.
        assert!(
            message(r#"["repo:a:b"]"#, AllowToolScope::ProjectConfig)
                .contains("allow_tools[0]: invalid tool name")
        );
        for reserved in ["help", "run", "doctor"] {
            assert!(
                message(&format!(r#"["{reserved}"]"#), AllowToolScope::SourceFile)
                    .contains("invalid tool name"),
                "{reserved}"
            );
        }
        // Names a declaration may hold are accepted verbatim.
        assert_eq!(
            parse_project(r#"["a-1", "repo:a.b"]"#).unwrap().len(),
            2,
            "a dot inside a name is not the `..` refusal"
        );
    }
}
